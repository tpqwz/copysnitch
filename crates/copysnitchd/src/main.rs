use std::env;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::thread;
use std::time::Duration;

use std::path::Path;

use copysnitch_common::{Action, Direction, Zone, zone_of};
use copysnitchd::{
    DecisionBecause, Event, Firewall, Running, connection_from_line, output_queue_ruleset,
};

fn main() -> ExitCode {
    match run(env::args().skip(1)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("copysnitchd: {error}");
            ExitCode::from(1)
        }
    }
}

struct Opts {
    rules: PathBuf,
    socket: PathBuf,
    allow_uid: u32,
    timeout: Duration,
    queue: Option<u16>,
}

fn run(args: impl Iterator<Item = String>) -> io::Result<()> {
    let args: Vec<String> = args.collect();
    if args.iter().any(|arg| arg == "--print-ruleset") {
        println!("{}", output_queue_ruleset());
        return Ok(());
    }
    let opts = parse_args(args.into_iter())?;
    let firewall = Firewall::load(&opts.rules)?;
    let mut running = if let Some(queue) = opts.queue {
        Running::start_with_queue(firewall, &opts.socket, opts.allow_uid, opts.timeout, queue)?
    } else {
        Running::start(firewall, &opts.socket, opts.allow_uid, opts.timeout)?
    };
    let mut submitter = running.take_submitter()?;
    thread::spawn(move || {
        let stdin = io::stdin();
        for line in stdin.lock().lines() {
            let Ok(line) = line else {
                break;
            };
            if line.is_empty() {
                continue;
            }
            match connection_from_line(&line, Path::new("/proc")) {
                Ok(connection) => {
                    if submitter.submit(connection).is_err() {
                        break;
                    }
                }
                Err(_) => eprintln!("copysnitchd: ignored a connection line"),
            }
        }
    });
    let stdout = io::stdout();
    let mut output = stdout.lock();
    loop {
        match running.recv() {
            Ok(event) => write_event(&mut output, &event)?,
            Err(_) => break,
        }
    }
    if let Err(error) = running.shutdown() {
        eprintln!("copysnitchd: {error}");
        std::process::exit(1);
    }
    Ok(())
}

fn write_event(output: &mut impl Write, event: &Event) -> io::Result<()> {
    match event {
        Event::Decision {
            connection,
            action,
            because,
        } => {
            let action = match action {
                Action::Allow => "allow",
                Action::Deny => "deny",
            };
            let because = match because {
                DecisionBecause::Rule(name) => format!("rule {name}"),
                DecisionBecause::Answer { duration, name } => {
                    let duration = format!("{duration:?}").to_lowercase();
                    match name {
                        Some(name) => format!("{duration} {name}"),
                        None => duration,
                    }
                }
                DecisionBecause::Timeout => "timeout".to_string(),
            };
            let direction = match connection.direction {
                Direction::Inbound => "inbound",
                Direction::Outbound => "outbound",
            };
            let zone = match zone_of(connection.dest_ip) {
                Zone::Internet => "internet",
                Zone::Trusted => "trusted",
            };
            writeln!(
                output,
                "{action} {because} {path} {direction} {zone} {ip}:{port}",
                path = connection.process_path,
                ip = connection.dest_ip,
                port = connection.dest_port,
            )
        }
        Event::PeerRejected => writeln!(output, "peer rejected"),
        Event::BusyRejected => writeln!(output, "busy"),
    }
}

fn parse_args(args: impl Iterator<Item = String>) -> io::Result<Opts> {
    let mut rules = None;
    let mut socket = None;
    let mut allow_uid = None;
    let mut timeout = Duration::from_secs(30);
    let mut queue = None;
    let mut args = args;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--rules" => rules = Some(PathBuf::from(next_value("--rules", &mut args)?)),
            "--socket" => socket = Some(PathBuf::from(next_value("--socket", &mut args)?)),
            "--allow-uid" => {
                let text = next_value("--allow-uid", &mut args)?;
                allow_uid = Some(text.parse::<u32>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "allow-uid is not a number")
                })?);
            }
            "--queue" => {
                let text = next_value("--queue", &mut args)?;
                queue = Some(text.parse::<u16>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "queue is not a number")
                })?);
            }
            "--timeout-secs" => {
                let text = next_value("--timeout-secs", &mut args)?;
                let secs = text.parse::<u64>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "timeout-secs is not a number")
                })?;
                timeout = Duration::from_secs(secs);
            }
            "--help" | "-h" => {
                println!("{}", usage());
                std::process::exit(0);
            }
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unknown argument {other}\n{}", usage()),
                ));
            }
        }
    }
    let Some(rules) = rules else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("missing --rules\n{}", usage()),
        ));
    };
    let Some(socket) = socket else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("missing --socket\n{}", usage()),
        ));
    };
    // SAFETY: geteuid has no preconditions. It is the default user allowed to answer.
    let allow_uid = allow_uid.unwrap_or_else(|| unsafe { libc::geteuid() });
    Ok(Opts {
        rules,
        socket,
        allow_uid,
        timeout,
        queue,
    })
}

fn next_value(name: &str, args: &mut impl Iterator<Item = String>) -> io::Result<String> {
    args.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("missing value for {name}"),
        )
    })
}

fn usage() -> &'static str {
    "\
usage: copysnitchd --rules DIR --socket PATH [--allow-uid UID] [--timeout-secs N] [--queue N]
       copysnitchd --print-ruleset

DIR holds rule files and must be owned by this process, mode 0755 or stricter.
PATH's parent directory has the same requirement. The socket is mode 0666;
only --allow-uid may speak on it. The default uid is this process.

Each stdin line is one connection, fields separated by tabs:
  process-path  command  uid  tcp|udp|icmp  host  ip  port  inbound|outbound
or a packet named from /proc:
  packet [in|out] <hex>

No answer within the timeout denies the connection. Ctrl-D stops the daemon.
--queue N binds that netfilter queue. It does not install nftables rules.
The queue fails open if this process exits."
}
