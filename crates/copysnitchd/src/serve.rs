//! Unix socket between the root daemon and one user-session UI.
//!
//! The serve thread is the only owner of the firewall. The submitter wakes it
//! through a pipe when a connection is ready to judge.

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, TryRecvError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use copysnitch_common::{
    Action, ClientMessage, Connection, MAX_LINE, ServerMessage, format_server_message,
    parse_client_message,
};

use crate::queue::{self, parse_queued, recv_queue, send_verdict, verdict_message};
use crate::{AnswerError, Because, Firewall, Step};

/// What the daemon reports to its operator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Decision {
        connection: Connection,
        action: Action,
        because: DecisionBecause,
    },
    PeerRejected,
    BusyRejected,
}

/// Why a connection was allowed or denied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecisionBecause {
    Rule(String),
    Answer {
        duration: copysnitch_common::Duration,
        name: Option<String>,
    },
    Timeout,
}

struct Submitter {
    tx: Sender<Connection>,
    wake: std::io::PipeWriter,
}

impl Submitter {
    fn submit(&mut self, connection: Connection) -> io::Result<()> {
        self.tx
            .send(connection)
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "daemon stopped"))?;
        match self.wake.write(&[1]) {
            Ok(_) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(()),
            Err(error) => Err(error),
        }
    }
}

/// A running daemon loop.
pub struct Running {
    submitter: Option<Submitter>,
    events: Receiver<Event>,
    thread: Option<JoinHandle<io::Result<()>>>,
}

impl Running {
    /// Listen on `socket`. `allowed_uid` is the only user who may connect.
    /// The parent directory must be owned by this process and not writable by group or other.
    pub fn start(
        firewall: Firewall,
        socket: &Path,
        allowed_uid: u32,
        prompt_timeout: Duration,
    ) -> io::Result<Self> {
        let listener = bind_listener(socket)?;
        let (wake_read, wake_write) = std::io::pipe()?;
        set_nonblocking(wake_read.as_raw_fd())?;
        set_nonblocking(wake_write.as_raw_fd())?;
        let (tx, rx) = mpsc::channel();
        let (events_tx, events_rx) = mpsc::channel();
        Self::spawn(
            firewall,
            listener,
            allowed_uid,
            prompt_timeout,
            tx,
            wake_write,
            events_rx,
            rx,
            events_tx,
            wake_read,
            None,
        )
    }

    /// Same as [`Running::start`], and also bind netfilter queue `queue_num`.
    /// This does not install nftables rules. The queue fails open if the process exits.
    pub fn start_with_queue(
        firewall: Firewall,
        socket: &Path,
        allowed_uid: u32,
        prompt_timeout: Duration,
        queue_num: u16,
    ) -> io::Result<Self> {
        let listener = bind_listener(socket)?;
        let (wake_read, wake_write) = std::io::pipe()?;
        set_nonblocking(wake_read.as_raw_fd())?;
        set_nonblocking(wake_write.as_raw_fd())?;
        let (tx, rx) = mpsc::channel();
        let (events_tx, events_rx) = mpsc::channel();
        let queue = queue::open_queue(queue_num)?;
        Self::spawn(
            firewall,
            listener,
            allowed_uid,
            prompt_timeout,
            tx,
            wake_write,
            events_rx,
            rx,
            events_tx,
            wake_read,
            Some((queue, queue_num)),
        )
    }

    fn spawn(
        firewall: Firewall,
        listener: UnixListener,
        allowed_uid: u32,
        prompt_timeout: Duration,
        tx: mpsc::Sender<Connection>,
        wake_write: std::io::PipeWriter,
        events_rx: Receiver<Event>,
        rx: Receiver<Connection>,
        events_tx: Sender<Event>,
        wake_read: std::io::PipeReader,
        queue: Option<(OwnedFd, u16)>,
    ) -> io::Result<Self> {
        let thread = thread::spawn(move || {
            serve(
                firewall,
                listener,
                allowed_uid,
                prompt_timeout,
                rx,
                events_tx,
                wake_read,
                queue,
            )
        });
        Ok(Running {
            submitter: Some(Submitter {
                tx,
                wake: wake_write,
            }),
            events: events_rx,
            thread: Some(thread),
        })
    }

    pub fn submit(&mut self, connection: Connection) -> io::Result<()> {
        self.submitter
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "daemon stopped"))?
            .submit(connection)
    }

    /// Move the submitter to another thread, such as the one reading stdin.
    pub fn take_submitter(&mut self) -> io::Result<SubmitHandle> {
        let submitter = self
            .submitter
            .take()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "daemon stopped"))?;
        Ok(SubmitHandle { submitter })
    }

    pub fn recv(&self) -> io::Result<Event> {
        self.events
            .recv()
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "daemon stopped"))
    }

    pub fn recv_timeout(&self, timeout: Duration) -> io::Result<Event> {
        match self.events.recv_timeout(timeout) {
            Ok(event) => Ok(event),
            Err(RecvTimeoutError::Timeout) => {
                Err(io::Error::new(io::ErrorKind::TimedOut, "no event"))
            }
            Err(RecvTimeoutError::Disconnected) => {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "daemon stopped"))
            }
        }
    }

    pub fn shutdown(mut self) -> io::Result<()> {
        self.submitter.take();
        match self.thread.take() {
            Some(thread) => match thread.join() {
                Ok(result) => result,
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::Other,
                    "daemon thread panicked",
                )),
            },
            None => Ok(()),
        }
    }
}

/// Stdin side of a running daemon. Dropping it asks the daemon to exit.
pub struct SubmitHandle {
    submitter: Submitter,
}

impl SubmitHandle {
    pub fn submit(&mut self, connection: Connection) -> io::Result<()> {
        self.submitter.submit(connection)
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.submitter.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn bind_listener(path: &Path) -> io::Result<UnixListener> {
    let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "socket path has no parent",
        ));
    };
    super::private_directory(parent)?;
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => std::fs::remove_file(path)?,
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "socket path exists and is not a socket",
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let listener = UnixListener::bind(path)?;
    listener.set_nonblocking(true)?;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o666);
    std::fs::set_permissions(path, perms)?;
    Ok(listener)
}

struct Waiting {
    id: u64,
    connection: Connection,
    deadline: Instant,
    sent: bool,
    packet_id: Option<u32>,
}

struct Work {
    connection: Connection,
    packet_id: Option<u32>,
}

fn serve(
    firewall: Firewall,
    listener: UnixListener,
    allowed_uid: u32,
    prompt_timeout: Duration,
    rx: Receiver<Connection>,
    events: Sender<Event>,
    mut wake: std::io::PipeReader,
    queue: Option<(OwnedFd, u16)>,
) -> io::Result<()> {
    let (queue, queue_num) = match queue {
        Some((fd, number)) => (Some(fd), number),
        None => (None, 0),
    };
    let mut state = Loop {
        firewall,
        listener,
        allowed_uid,
        prompt_timeout,
        rx,
        events,
        wake: &mut wake,
        client: None,
        buf: Vec::new(),
        incoming: VecDeque::new(),
        inbox: VecDeque::new(),
        waiting: None,
        stop: false,
        queue,
        queue_num,
    };
    state.run()
}

struct Loop<'a> {
    firewall: Firewall,
    listener: UnixListener,
    allowed_uid: u32,
    prompt_timeout: Duration,
    rx: Receiver<Connection>,
    events: Sender<Event>,
    wake: &'a mut std::io::PipeReader,
    client: Option<UnixStream>,
    buf: Vec<u8>,
    incoming: VecDeque<Result<ClientMessage, ()>>,
    inbox: VecDeque<Work>,
    waiting: Option<Waiting>,
    stop: bool,
    queue: Option<OwnedFd>,
    queue_num: u16,
}

impl Loop<'_> {
    fn run(&mut self) -> io::Result<()> {
        loop {
            self.progress()?;
            if self.stop && self.waiting.is_none() {
                return Ok(());
            }
            let client_fd = self
                .client
                .as_ref()
                .map(|client| client.as_raw_fd())
                .unwrap_or(-1);
            let queue_fd = if self.waiting.is_none() {
                self.queue
                    .as_ref()
                    .map(|queue| queue.as_raw_fd())
                    .unwrap_or(-1)
            } else {
                -1
            };
            let mut fds = [
                libc::pollfd {
                    fd: self.listener.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: self.wake.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: client_fd,
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: queue_fd,
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            let timeout_ms = self.poll_timeout();
            poll_wait(&mut fds, timeout_ms)?;
            if fds[1].revents != 0 {
                self.drain_wake()?;
            }
            if fds[0].revents & libc::POLLIN != 0 {
                self.accept_ready()?;
            }
            if client_fd >= 0 && fds[2].revents != 0 {
                self.read_client()?;
            }
            if queue_fd >= 0 && fds[3].revents & libc::POLLIN != 0 {
                self.read_queue()?;
            }
        }
    }

    fn poll_timeout(&self) -> i32 {
        if let Some(waiting) = &self.waiting {
            let millis = waiting
                .deadline
                .saturating_duration_since(Instant::now())
                .as_millis();
            i32::try_from(millis).unwrap_or(i32::MAX)
        } else if self.stop || !self.inbox.is_empty() {
            0
        } else {
            -1
        }
    }

    fn progress(&mut self) -> io::Result<()> {
        self.apply_incoming()?;
        self.expire()?;
        self.decide_next()?;
        self.send_prompt()?;
        Ok(())
    }

    fn apply_incoming(&mut self) -> io::Result<()> {
        while let Some(item) = self.incoming.pop_front() {
            match item {
                Err(()) => self.write_message(&ServerMessage::BadRequest)?,
                Ok(ClientMessage::Answer {
                    id,
                    action,
                    duration,
                    scope,
                }) => {
                    self.apply_answer(id, action, duration, scope)?;
                }
                Ok(ClientMessage::List) => {
                    for rule in self.firewall.list() {
                        self.write_message(&ServerMessage::Rule {
                            name: rule.name,
                            summary: rule.summary,
                        })?;
                    }
                    self.write_message(&ServerMessage::RulesEnd)?;
                }
                Ok(ClientMessage::Forget { name }) => match self.firewall.forget(&name) {
                    Ok(()) => self.write_message(&ServerMessage::Forgotten)?,
                    Err(_) => self.write_message(&ServerMessage::Rejected)?,
                },
            }
        }
        Ok(())
    }

    fn apply_answer(
        &mut self,
        id: u64,
        action: Action,
        duration: copysnitch_common::Duration,
        scope: copysnitch_common::Scope,
    ) -> io::Result<()> {
        let Some(waiting) = self.waiting.take() else {
            return self.write_message(&ServerMessage::BadRequest);
        };
        if waiting.id != id {
            self.waiting = Some(waiting);
            return self.write_message(&ServerMessage::BadRequest);
        }
        match self
            .firewall
            .answer(id, &waiting.connection, action, duration, scope)
        {
            Ok(name) => {
                if let Some(name) = name.clone() {
                    self.write_message(&ServerMessage::Stored { name })?;
                }
                self.finish(
                    waiting.connection,
                    action,
                    DecisionBecause::Answer { duration, name },
                    waiting.packet_id,
                )
            }
            Err(AnswerError::UnknownPrompt) => {
                self.waiting = Some(waiting);
                self.write_message(&ServerMessage::BadRequest)
            }
            Err(
                AnswerError::Unstorable
                | AnswerError::Conflict
                | AnswerError::Store
                | AnswerError::UnknownRule,
            ) => {
                self.waiting = Some(waiting);
                self.write_message(&ServerMessage::Rejected)
            }
        }
    }

    fn expire(&mut self) -> io::Result<()> {
        let timed_out = self
            .waiting
            .as_ref()
            .is_some_and(|waiting| self.stop || Instant::now() >= waiting.deadline);
        if !timed_out {
            return Ok(());
        }
        let Some(waiting) = self.waiting.take() else {
            return Ok(());
        };
        self.firewall.timeout(waiting.id).ok();
        self.finish(
            waiting.connection,
            Action::Deny,
            DecisionBecause::Timeout,
            waiting.packet_id,
        )
    }

    fn decide_next(&mut self) -> io::Result<()> {
        if self.stop || self.waiting.is_some() {
            return Ok(());
        }
        let Some(work) = self.inbox.pop_front() else {
            return Ok(());
        };
        match self.firewall.decide(&work.connection) {
            Step::Decided { action, because } => {
                let because = match because {
                    Because::Rule(name) => DecisionBecause::Rule(name),
                };
                self.finish(work.connection, action, because, work.packet_id)
            }
            Step::Ask { id } => {
                self.waiting = Some(Waiting {
                    id,
                    connection: work.connection,
                    deadline: Instant::now() + self.prompt_timeout,
                    sent: false,
                    packet_id: work.packet_id,
                });
                Ok(())
            }
            Step::Busy => {
                self.inbox.push_front(work);
                Ok(())
            }
        }
    }

    fn send_prompt(&mut self) -> io::Result<()> {
        let should_send = self
            .waiting
            .as_ref()
            .is_some_and(|waiting| !waiting.sent && self.client.is_some());
        if !should_send {
            return Ok(());
        }
        let Some(waiting) = self.waiting.as_ref() else {
            return Ok(());
        };
        let message = ServerMessage::Prompt {
            id: waiting.id,
            connection: waiting.connection.clone(),
        };
        // The prompt line and the pending record both carry the connection.
        match format_server_message(&message) {
            Ok(line) => {
                let failed = self
                    .client
                    .as_mut()
                    .map(|client| write_all_nb(client, line.as_bytes()))
                    .is_some_and(|result| result.is_err());
                if failed {
                    self.client = None;
                    self.buf.clear();
                    return Ok(());
                }
                if let Some(waiting) = self.waiting.as_mut() {
                    waiting.sent = true;
                    waiting.deadline = Instant::now() + self.prompt_timeout;
                }
                Ok(())
            }
            Err(_) => {
                let Some(waiting) = self.waiting.take() else {
                    return Ok(());
                };
                self.firewall.timeout(waiting.id).ok();
                self.finish(
                    waiting.connection,
                    Action::Deny,
                    DecisionBecause::Timeout,
                    waiting.packet_id,
                )
            }
        }
    }

    fn finish(
        &mut self,
        connection: Connection,
        action: Action,
        because: DecisionBecause,
        packet_id: Option<u32>,
    ) -> io::Result<()> {
        if let (Some(packet_id), Some(queue)) = (packet_id, self.queue.as_ref()) {
            let message = verdict_message(self.queue_num, packet_id, action == Action::Allow);
            if send_verdict(queue.as_raw_fd(), &message).is_err() {
                self.queue = None;
            }
        }
        let _ = self.write_message(&decision_message(&connection, action, &because));
        self.emit(Event::Decision {
            connection,
            action,
            because,
        })
    }

    fn read_queue(&mut self) -> io::Result<()> {
        let Some(fd) = self.queue.as_ref().map(|queue| queue.as_raw_fd()) else {
            return Ok(());
        };
        let mut buf = vec![0u8; 128 * 1024];
        loop {
            let n = match recv_queue(fd, &mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => {
                    self.queue = None;
                    break;
                }
            };
            let Ok(queued) = parse_queued(&buf[..n]) else {
                continue;
            };
            let Some(direction) = queue::direction_from_hook(queued.hook) else {
                let message = verdict_message(self.queue_num, queued.packet_id, false);
                if send_verdict(fd, &message).is_err() {
                    self.queue = None;
                    break;
                }
                continue;
            };
            match crate::observe::name_packet(&queued.payload, Path::new("/proc"), direction) {
                Ok(connection) => self.inbox.push_back(Work {
                    connection,
                    packet_id: Some(queued.packet_id),
                }),
                Err(_) => {
                    let message = verdict_message(self.queue_num, queued.packet_id, false);
                    if send_verdict(fd, &message).is_err() {
                        self.queue = None;
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    fn drain_wake(&mut self) -> io::Result<()> {
        let mut tmp = [0u8; 64];
        loop {
            match self.wake.read(&mut tmp) {
                Ok(0) => {
                    self.stop = true;
                    break;
                }
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        loop {
            match self.rx.try_recv() {
                Ok(connection) => self.inbox.push_back(Work {
                    connection,
                    packet_id: None,
                }),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    self.stop = true;
                    break;
                }
            }
        }
        Ok(())
    }

    fn accept_ready(&mut self) -> io::Result<()> {
        loop {
            match self.listener.accept() {
                Ok((stream, _)) => self.greet(stream)?,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
    }

    fn greet(&mut self, mut stream: UnixStream) -> io::Result<()> {
        let uid = peer_uid(stream.as_raw_fd()).ok();
        if uid != Some(self.allowed_uid) {
            let _ = stream.write_all(b"error\tdenied\n");
            return self.emit(Event::PeerRejected);
        }
        if self.client.is_some() {
            let _ = stream.write_all(b"error\tbusy\n");
            return self.emit(Event::BusyRejected);
        }
        set_nonblocking(stream.as_raw_fd())?;
        self.client = Some(stream);
        Ok(())
    }

    fn read_client(&mut self) -> io::Result<()> {
        let mut tmp = [0u8; 512];
        let outcome = loop {
            let Some(client) = self.client.as_mut() else {
                return Ok(());
            };
            match client.read(&mut tmp) {
                Ok(0) => break ReadOutcome::Closed,
                Ok(n) => break ReadOutcome::Data(n),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break ReadOutcome::Idle,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => break ReadOutcome::Closed,
            }
        };
        match outcome {
            ReadOutcome::Idle => Ok(()),
            ReadOutcome::Closed => {
                self.drop_client();
                Ok(())
            }
            ReadOutcome::Data(n) => {
                self.buf.extend_from_slice(&tmp[..n]);
                self.extract_lines();
                if self.buf.len() > MAX_LINE {
                    self.drop_client();
                }
                Ok(())
            }
        }
    }

    fn extract_lines(&mut self) {
        while let Some(pos) = self.buf.iter().position(|byte| *byte == b'\n') {
            let raw: Vec<u8> = self.buf.drain(..=pos).collect();
            if raw.len() > MAX_LINE {
                self.incoming.push_back(Err(()));
                continue;
            }
            let Ok(text) = std::str::from_utf8(&raw[..raw.len() - 1]) else {
                self.incoming.push_back(Err(()));
                continue;
            };
            let text = text.strip_suffix('\r').unwrap_or(text);
            match parse_client_message(text) {
                Ok(message) => self.incoming.push_back(Ok(message)),
                Err(_) => self.incoming.push_back(Err(())),
            }
        }
    }

    fn drop_client(&mut self) {
        self.client = None;
        self.buf.clear();
        self.incoming.clear();
    }

    fn write_message(&mut self, message: &ServerMessage) -> io::Result<()> {
        let Ok(line) = format_server_message(message) else {
            self.client = None;
            return Ok(());
        };
        let failed = self
            .client
            .as_mut()
            .map(|client| write_all_nb(client, line.as_bytes()))
            .is_some_and(|result| result.is_err());
        if failed {
            self.client = None;
            self.buf.clear();
        }
        Ok(())
    }

    fn emit(&self, event: Event) -> io::Result<()> {
        self.events
            .send(event)
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "listener dropped"))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReadOutcome {
    Idle,
    Closed,
    Data(usize),
}

fn write_all_nb(stream: &mut UnixStream, bytes: &[u8]) -> io::Result<()> {
    let mut rest = bytes;
    while !rest.is_empty() {
        match stream.write(rest) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::WriteZero, "closed")),
            Ok(n) => rest = &rest[n..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn peer_uid(fd: RawFd) -> io::Result<u32> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: getsockopt SO_PEERCRED writes one ucred into `cred` for a unix socket
    // this process accepted. `len` is the size of that struct. A negative return
    // leaves `cred` unread.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(cred.uid)
}

fn decision_message(
    connection: &Connection,
    action: Action,
    because: &DecisionBecause,
) -> ServerMessage {
    let because = match because {
        DecisionBecause::Rule(name) => format!("rule {name}"),
        DecisionBecause::Answer { duration, name } => {
            let duration = match duration {
                copysnitch_common::Duration::Once => "once",
                copysnitch_common::Duration::Session => "session",
                copysnitch_common::Duration::Always => "always",
            };
            match name {
                Some(name) => format!("{duration} {name}"),
                None => duration.to_string(),
            }
        }
        DecisionBecause::Timeout => "timeout".to_string(),
    };
    let direction = match connection.direction {
        copysnitch_common::Direction::Inbound => "inbound",
        copysnitch_common::Direction::Outbound => "outbound",
    };
    let protocol = match connection.protocol {
        copysnitch_common::Protocol::Icmp => "icmp",
        copysnitch_common::Protocol::Tcp => "tcp",
        copysnitch_common::Protocol::Udp => "udp",
    };
    let zone = match copysnitch_common::zone_of(connection.dest_ip) {
        copysnitch_common::Zone::Internet => "internet",
        copysnitch_common::Zone::Trusted => "trusted",
    };
    ServerMessage::Decision {
        action,
        because,
        path: connection.process_path.clone(),
        detail: format!(
            "{direction} {protocol} {zone} {}:{port}",
            connection.dest_ip,
            port = connection.dest_port
        ),
        command: connection.cmdline.clone(),
    }
}

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: F_GETFL and F_SETFL apply to an fd this process owns. A negative
    // return is an error code, and the flags word is only passed back to fcntl.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn poll_wait(fds: &mut [libc::pollfd], timeout_ms: i32) -> io::Result<()> {
    // SAFETY: fds is a live slice, the length matches, and timeout_ms is in poll's range.
    let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout_ms) };
    if rc < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            return Ok(());
        }
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Scratch(std::path::PathBuf);

    impl Scratch {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let mut path = std::env::temp_dir();
            path.push(format!(
                "copysnitch-sock-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            let mut perms = std::fs::metadata(&path).unwrap().permissions();
            perms.set_mode(0o700);
            std::fs::set_permissions(&path, perms).unwrap();
            Scratch(path)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    impl std::ops::Deref for Scratch {
        type Target = std::path::Path;
        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    fn connection(path: &str) -> Connection {
        Connection {
            process_path: path.to_string(),
            cmdline: "curl https://example.com".to_string(),
            uid: 1000,
            protocol: copysnitch_common::Protocol::Tcp,
            dest_host: "example.com".to_string(),
            dest_ip: "93.184.216.34".parse().unwrap(),
            dest_port: 443,
            direction: copysnitch_common::Direction::Outbound,
            sha256: String::new(),
        }
    }

    fn euid() -> u32 {
        // SAFETY: geteuid has no preconditions.
        unsafe { libc::geteuid() }
    }

    #[test]
    fn the_ui_can_allow_a_program_and_another_uid_cannot() {
        let rules = Scratch::new();
        let socks = Scratch::new();
        let socket = socks.join("copysnitch.sock");
        let firewall = Firewall::load(&rules).unwrap();
        let mut running = Running::start(firewall, &socket, euid(), Duration::from_secs(2))
            .expect("daemon listens");
        let mut client = UnixStream::connect(&socket).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        running.submit(connection("/usr/bin/curl")).unwrap();

        let mut prompt = String::new();
        io::BufReader::new(client.try_clone().unwrap())
            .read_line(&mut prompt)
            .unwrap();
        let message =
            copysnitch_common::parse_server_message(prompt.trim_end_matches('\n')).expect("prompt");
        let copysnitch_common::ServerMessage::Prompt {
            id,
            connection: prompted,
        } = message
        else {
            panic!("expected a prompt, got {prompt}");
        };
        assert_eq!(prompted.process_path, "/usr/bin/curl");
        assert_eq!(prompted.direction, copysnitch_common::Direction::Outbound);
        assert_eq!(
            copysnitch_common::zone_of(prompted.dest_ip),
            copysnitch_common::Zone::Internet
        );
        writeln!(client, "answer\t{id}\tallow\talways").unwrap();

        let mut stored = String::new();
        let mut event_line = String::new();
        let mut reader = io::BufReader::new(client.try_clone().unwrap());
        reader.read_line(&mut stored).unwrap();
        reader.read_line(&mut event_line).unwrap();
        assert!(stored.starts_with("ok\trule\t"), "{stored}");
        match copysnitch_common::parse_server_message(event_line.trim_end_matches('\n'))
            .expect("decision line")
        {
            ServerMessage::Decision {
                action: Action::Allow,
                path,
                detail,
                ..
            } => {
                assert_eq!(path, "/usr/bin/curl");
                assert!(detail.contains("internet"), "{detail}");
            }
            other => panic!("expected a decision, got {other:?} from {event_line}"),
        }

        let event = running.recv_timeout(Duration::from_secs(2)).unwrap();
        match event {
            Event::Decision {
                action: Action::Allow,
                because:
                    DecisionBecause::Answer {
                        duration: copysnitch_common::Duration::Always,
                        name: _,
                    },
                ..
            } => {}
            other => panic!("expected an allow answer, got {other:?}"),
        }
        let mut reloaded = Firewall::load(&rules).unwrap();
        assert!(matches!(
            reloaded.decide(&connection("/usr/bin/curl")),
            crate::Step::Decided {
                action: Action::Allow,
                ..
            }
        ));
        let mut inbound = connection("/usr/bin/curl");
        inbound.direction = copysnitch_common::Direction::Inbound;
        assert!(matches!(reloaded.decide(&inbound), crate::Step::Ask { .. }));

        let other = if euid() == 1 { 2 } else { 1 };
        let intruder_dir = Scratch::new();
        let intruder_rules = Scratch::new();
        let intruder_socket = intruder_dir.join("copysnitch.sock");
        let intruder = Running::start(
            Firewall::load(&intruder_rules).unwrap(),
            &intruder_socket,
            other,
            Duration::from_millis(200),
        )
        .unwrap();
        let mut stranger = UnixStream::connect(&intruder_socket).unwrap();
        stranger
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut line = String::new();
        io::BufReader::new(&mut stranger)
            .read_line(&mut line)
            .unwrap();
        assert_eq!(line, "error\tdenied\n");
        // The rejected socket cannot allow the program. With no UI, the ask times out closed.
        let mut running = intruder;
        running.submit(connection("/usr/bin/curl")).unwrap();
        let mut saw_reject = false;
        let mut saw_timeout = false;
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline && !(saw_reject && saw_timeout) {
            match running.recv_timeout(Duration::from_millis(400)) {
                Ok(Event::PeerRejected) => saw_reject = true,
                Ok(Event::Decision {
                    action: Action::Deny,
                    because: DecisionBecause::Timeout,
                    ..
                }) => saw_timeout = true,
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::TimedOut => {}
                Err(error) => panic!("{error}"),
            }
        }
        assert!(saw_reject, "the other uid was not rejected");
        assert!(saw_timeout, "the ask did not fail closed");
        assert_eq!(std::fs::read_dir(&*intruder_rules).unwrap().count(), 0);
        running.shutdown().unwrap();
    }

    #[test]
    fn a_world_writable_socket_directory_is_refused_and_a_regular_file_is_left_alone() {
        let rules = Scratch::new();
        let socks = Scratch::new();
        let mut perms = std::fs::metadata(&*socks).unwrap().permissions();
        perms.set_mode(0o777);
        std::fs::set_permissions(&*socks, perms).unwrap();
        let error = Running::start(
            Firewall::load(&rules).unwrap(),
            &socks.join("copysnitch.sock"),
            euid(),
            Duration::from_millis(50),
        );
        assert!(error.is_err());

        let socks = Scratch::new();
        let socket = socks.join("copysnitch.sock");
        std::fs::write(&socket, b"keep").unwrap();
        let error = Running::start(
            Firewall::load(&rules).unwrap(),
            &socket,
            euid(),
            Duration::from_millis(50),
        );
        assert!(error.is_err());
        assert_eq!(std::fs::read(&socket).unwrap(), b"keep");
    }
}
