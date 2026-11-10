//! Netfilter queue messages.
//!
//! The daemon binds a queue only when `--queue` is set. Tests never bind one,
//! and nothing in this crate installs nftables rules.

use std::io::{self, ErrorKind};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;

use copysnitch_common::{Action, Connection, Direction};

use crate::observe::name_packet;
use crate::{Firewall, Step};

const MAX_MESSAGE: usize = 128 * 1024;
const MAX_PAYLOAD: usize = 65535;
const COPY_LEN: u32 = 65535;

/// A packet the kernel is holding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Queued {
    pub packet_id: u32,
    pub payload: Vec<u8>,
    /// Netfilter hook. 1 is local in, 3 is local out.
    pub hook: Option<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueueError {
    Malformed,
}

/// What to do with one queued packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Judgement {
    /// Send these bytes back to the kernel.
    Verdict(Vec<u8>),
    /// Ask the person. The kernel keeps the packet until a verdict is sent.
    Hold {
        packet_id: u32,
        prompt_id: u64,
        connection: Connection,
    },
    /// A prompt is already in progress. Keep the netlink message and try again.
    Busy,
}

/// Drop or accept packet `packet_id` on `queue`.
pub fn verdict_message(queue: u16, packet_id: u32, accept: bool) -> Vec<u8> {
    let verdict: u32 = if accept { 1 } else { 0 };
    let mut payload = Vec::with_capacity(8);
    payload.extend(verdict.to_be_bytes());
    payload.extend(packet_id.to_be_bytes());
    let mut attrs = Vec::new();
    put_attr(&mut attrs, 2, &payload);
    finish_message(1, queue, &attrs)
}

/// Messages that bind `queue`, ask for packet bytes, and fail open if we exit.
pub fn setup_messages(queue: u16) -> [Vec<u8>; 3] {
    let mut bind = Vec::new();
    put_attr(&mut bind, 1, &[1, 0, 0, 0]);
    let mut copy = Vec::new();
    let mut params = COPY_LEN.to_be_bytes().to_vec();
    params.push(2);
    put_attr(&mut copy, 2, &params);
    let mut flags = Vec::new();
    put_attr(&mut flags, 4, &1u32.to_ne_bytes());
    put_attr(&mut flags, 5, &1u32.to_ne_bytes());
    put_attr(&mut flags, 3, &128u32.to_ne_bytes());
    [
        finish_message(2, queue, &bind),
        finish_message(2, queue, &copy),
        finish_message(2, queue, &flags),
    ]
}

/// Read one kernel packet message. A truncated or huge attribute is refused.
pub fn parse_queued(message: &[u8]) -> Result<Queued, QueueError> {
    if message.len() < 20 || message.len() > MAX_MESSAGE {
        return Err(QueueError::Malformed);
    }
    let nl_len = u32::from_ne_bytes(message[0..4].try_into().unwrap()) as usize;
    if nl_len < 20 || nl_len > message.len() {
        return Err(QueueError::Malformed);
    }
    let msg_type = u16::from_ne_bytes(message[4..6].try_into().unwrap());
    if msg_type >> 8 != 3 || msg_type & 0xff != 0 {
        return Err(QueueError::Malformed);
    }
    let mut offset = 20;
    let mut packet_id = None;
    let mut payload = None;
    let mut hook = None;
    while offset + 4 <= nl_len {
        let nla_len = u16::from_ne_bytes(message[offset..offset + 2].try_into().unwrap()) as usize;
        let nla_type =
            u16::from_ne_bytes(message[offset + 2..offset + 4].try_into().unwrap()) & 0x3fff;
        if nla_len < 4 || offset + nla_len > nl_len {
            return Err(QueueError::Malformed);
        }
        let data = &message[offset + 4..offset + nla_len];
        match nla_type {
            1 => {
                if data.len() < 4 {
                    return Err(QueueError::Malformed);
                }
                packet_id = Some(u32::from_be_bytes(data[0..4].try_into().unwrap()));
                if data.len() >= 7 {
                    hook = Some(data[6]);
                }
            }
            10 => {
                if data.len() > MAX_PAYLOAD {
                    return Err(QueueError::Malformed);
                }
                payload = Some(data.to_vec());
            }
            _ => {}
        }
        let step = align4(nla_len);
        if offset + nla_len == nl_len {
            break;
        }
        if offset + step > nl_len {
            return Err(QueueError::Malformed);
        }
        offset += step;
    }
    match (packet_id, payload) {
        (Some(packet_id), Some(payload)) => Ok(Queued {
            packet_id,
            payload,
            hook,
        }),
        _ => Err(QueueError::Malformed),
    }
}

/// Decide a queued packet. An unreadable payload is a drop verdict.
pub fn judge_packet(
    firewall: &mut Firewall,
    message: &[u8],
    proc_root: &Path,
    queue: u16,
) -> Result<Judgement, QueueError> {
    let queued = parse_queued(message)?;
    let Some(direction) = direction_from_hook(queued.hook) else {
        return Ok(Judgement::Verdict(verdict_message(
            queue,
            queued.packet_id,
            false,
        )));
    };
    let connection = match name_packet(&queued.payload, proc_root, direction) {
        Ok(connection) => connection,
        Err(_) => {
            return Ok(Judgement::Verdict(verdict_message(
                queue,
                queued.packet_id,
                false,
            )));
        }
    };
    match firewall.decide(&connection) {
        Step::Decided { action, .. } => Ok(Judgement::Verdict(verdict_message(
            queue,
            queued.packet_id,
            action == Action::Allow,
        ))),
        Step::Ask { id } => Ok(Judgement::Hold {
            packet_id: queued.packet_id,
            prompt_id: id,
            connection,
        }),
        Step::Busy => Ok(Judgement::Busy),
    }
}

/// Open the netfilter queue and ask the kernel to copy packets.
/// The socket fails open when this process exits.
pub fn open_queue(queue: u16) -> io::Result<OwnedFd> {
    // SAFETY: socket() with these constants creates a netlink socket or returns -1.
    // The fd is wrapped in OwnedFd, which closes it.
    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_NETFILTER) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut addr = [0u8; 12];
    addr[0..2].copy_from_slice(&libc::AF_NETLINK.to_ne_bytes()[..2]);
    // SAFETY: bind on the socket we just opened, with a sockaddr_nl of 12 bytes.
    let rc = unsafe {
        libc::bind(
            owned.as_raw_fd(),
            addr.as_ptr().cast(),
            addr.len() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    set_nonblocking(owned.as_raw_fd())?;
    for message in setup_messages(queue) {
        send_all(owned.as_raw_fd(), &message)?;
    }
    Ok(owned)
}

pub fn send_verdict(fd: std::os::fd::RawFd, message: &[u8]) -> io::Result<()> {
    send_all(fd, message)
}

fn send_all(fd: std::os::fd::RawFd, message: &[u8]) -> io::Result<()> {
    let mut sent = 0;
    while sent < message.len() {
        // SAFETY: send on a netlink fd we own. The slice is the unsent tail.
        let rc =
            unsafe { libc::send(fd, message[sent..].as_ptr().cast(), message.len() - sent, 0) };
        if rc < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        sent += rc as usize;
    }
    Ok(())
}

pub fn recv_queue(fd: std::os::fd::RawFd, buf: &mut [u8]) -> io::Result<usize> {
    // SAFETY: recv into the caller buffer on a netlink fd we own.
    let rc = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(rc as usize)
}

fn finish_message(kind: u8, queue: u16, attrs: &[u8]) -> Vec<u8> {
    let total = 20 + attrs.len();
    let mut out = Vec::with_capacity(total);
    out.extend((total as u32).to_ne_bytes());
    let msg_type = (3u16 << 8) | u16::from(kind);
    out.extend(msg_type.to_ne_bytes());
    out.extend(1u16.to_ne_bytes());
    out.extend(0u32.to_ne_bytes());
    out.extend(0u32.to_ne_bytes());
    out.push(0);
    out.push(0);
    out.extend(queue.to_be_bytes());
    out.extend(attrs);
    out
}

fn put_attr(out: &mut Vec<u8>, kind: u16, payload: &[u8]) {
    let nla_len = 4 + payload.len();
    out.extend((nla_len as u16).to_ne_bytes());
    out.extend(kind.to_ne_bytes());
    out.extend(payload);
    while out.len() % 4 != 0 {
        out.push(0);
    }
}

pub(crate) fn direction_from_hook(hook: Option<u8>) -> Option<Direction> {
    match hook {
        Some(1) => Some(Direction::Inbound),
        Some(3) => Some(Direction::Outbound),
        _ => None,
    }
}

fn align4(len: usize) -> usize {
    len.div_ceil(4) * 4
}

fn set_nonblocking(fd: std::os::fd::RawFd) -> io::Result<()> {
    // SAFETY: fcntl on an fd this process owns. A negative return is an error.
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn a_drop_verdict_names_the_packet() {
        assert_eq!(
            verdict_message(0, 7, false),
            [
                0x20, 0x00, 0x00, 0x00, 0x01, 0x03, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x07,
            ]
        );
    }

    #[test]
    fn an_accept_verdict_uses_nf_accept() {
        let bytes = verdict_message(0, 7, true);
        assert_eq!(&bytes[24..28], &[0, 0, 0, 1]);
        assert_eq!(&bytes[28..32], &[0, 0, 0, 7]);
    }

    #[test]
    fn a_queued_message_yields_its_payload_and_a_lie_is_rejected() {
        let message = [
            0x4c, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07,
            0x08, 0x00, 0x03, 0x00, 0x2c, 0x00, 0x0a, 0x00, 0x45, 0x00, 0x00, 0x28, 0x00, 0x00,
            0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x02, 0x5d, 0xb8, 0xd8, 0x22,
            0xd4, 0x31, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let queued = parse_queued(&message).expect("queued packet");
        assert_eq!(queued.packet_id, 7);
        assert_eq!(queued.payload.len(), 40);
        assert_eq!(&queued.payload[..4], &[0x45, 0x00, 0x00, 0x28]);
        assert_eq!(queued.payload[16], 93);
        assert!(parse_queued(&[0x10, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());
        let mut lying = message;
        lying[32] = 0xff;
        lying[33] = 0xff;
        assert!(parse_queued(&lying).is_err());
    }

    #[test]
    fn an_unreadable_payload_is_dropped_and_a_saved_rule_accepts() {
        let junk = [
            0x28, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07,
            0x08, 0x00, 0x03, 0x00, 0x08, 0x00, 0x0a, 0x00, 0x01, 0x02, 0x03, 0x04,
        ];
        let dir = private_dir();
        let mut firewall = Firewall::load(&dir).unwrap();
        match judge_packet(&mut firewall, &junk, Path::new("/no/such/proc"), 0).unwrap() {
            Judgement::Verdict(bytes) => assert_eq!(bytes, verdict_message(0, 7, false)),
            other => panic!("junk payload should drop, got {other:?}"),
        }

        let root = private_dir();
        std::fs::create_dir_all(root.join("net")).unwrap();
        std::fs::write(
            root.join("net/tcp"),
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0200000A:D431 22D8B85D:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 4242 1 0000000000000000 100 0 0 10 0\n",
        )
        .unwrap();
        std::fs::create_dir_all(root.join("42/fd")).unwrap();
        std::os::unix::fs::symlink("socket:[4242]", root.join("42/fd/3")).unwrap();
        std::fs::write(root.join("42/cmdline"), b"curl\0https://example.com\0").unwrap();
        std::os::unix::fs::symlink("/usr/bin/curl", root.join("42/exe")).unwrap();
        std::fs::write(
            dir.join("curl"),
            "action allow\nduration always\ndirection outbound\nprocess.path /usr/bin/curl\n",
        )
        .unwrap();
        let mut firewall = Firewall::load(&dir).unwrap();
        let message = [
            0x4c, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07,
            0x08, 0x00, 0x03, 0x00, 0x2c, 0x00, 0x0a, 0x00, 0x45, 0x00, 0x00, 0x28, 0x00, 0x00,
            0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x02, 0x5d, 0xb8, 0xd8, 0x22,
            0xd4, 0x31, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        match judge_packet(&mut firewall, &message, &root, 0).unwrap() {
            Judgement::Verdict(bytes) => {
                assert_eq!(&bytes[24..32], &[0, 0, 0, 1, 0, 0, 0, 7]);
            }
            other => panic!("saved rule should accept, got {other:?}"),
        }
        let mut forwarded = message;
        forwarded[30] = 2;
        match judge_packet(&mut firewall, &forwarded, &root, 0).unwrap() {
            Judgement::Verdict(bytes) => assert_eq!(&bytes[24..28], &[0, 0, 0, 0]),
            other => panic!("a forwarded packet should drop, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(dir);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn the_bind_message_joins_queue_zero() {
        let [bind, copy, flags] = setup_messages(0);
        assert_eq!(
            bind,
            [
                0x1c, 0x00, 0x00, 0x00, 0x02, 0x03, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
            ]
        );
        assert_eq!(copy[20], 9);
        assert_eq!(&copy[24..29], &[0, 0, 0xff, 0xff, 2]);
        assert!(flags.len() > 20);
        let _ = copy;
    }

    fn private_dir() -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "copysnitch-queue-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&path).unwrap();
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o700);
        std::fs::set_permissions(&path, perms).unwrap();
        path
    }
}
