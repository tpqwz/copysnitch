//! The user-session window. It does not run as root and it cannot submit connections.

use std::io::{self, BufRead, Write};
use std::os::unix::net::UnixStream;

use copysnitch_common::{
    Action, ClientMessage, Connection, Direction, Duration, Protocol, Scope, ServerMessage, Zone,
    format_client_message, parse_server_message, zone_of,
};

/// `allow once`, `deny session`, `allow always`, or `allow always zone`.
/// `zone` limits a session or always answer to the zone shown in the prompt.
pub fn parse_operator_line(line: &str) -> Option<(Action, Duration, Scope)> {
    let mut parts = line.trim().split(' ');
    let action = match parts.next() {
        Some("allow") => Action::Allow,
        Some("deny") => Action::Deny,
        _ => return None,
    };
    let duration = match parts.next() {
        Some("once") => Duration::Once,
        Some("session") => Duration::Session,
        Some("always") => Duration::Always,
        _ => return None,
    };
    let scope = match parts.next() {
        None => Scope::Program,
        Some("zone") if duration != Duration::Once => Scope::Zone,
        Some("command") if duration != Duration::Once => Scope::Command,
        _ => return None,
    };
    if parts.next().is_some() {
        return None;
    }
    Some((action, duration, scope))
}

/// The window's Allow or Deny button. `once` cannot carry a zone or a command.
pub fn window_answer(allow: bool, duration: Duration, scope: Scope) -> (Action, Duration, Scope) {
    let action = if allow { Action::Allow } else { Action::Deny };
    let scope = if duration == Duration::Once {
        Scope::Program
    } else {
        scope
    };
    (action, duration, scope)
}

/// File name shown for a process path. A path with no slash is itself.
pub fn program_name(path: &str) -> &str {
    match path.rsplit_once('/') {
        Some((_, name)) if !name.is_empty() => name,
        _ => path,
    }
}

/// Zone word from a decision detail, `outbound tcp internet 1.2.3.4:443`.
pub fn decision_zone(detail: &str) -> Option<&str> {
    let mut words = detail.split(' ');
    let _direction = words.next()?;
    let _protocol = words.next()?;
    let zone = words.next()?;
    matches!(zone, "internet" | "trusted").then_some(zone)
}

/// Words the prompt shows for one connection.
pub fn prompt_text(connection: &Connection) -> String {
    let zone = match zone_of(connection.dest_ip) {
        Zone::Internet => "the internet",
        Zone::Trusted => "the trusted network",
    };
    let (direction, relation) = match connection.direction {
        Direction::Inbound => ("accept", "from"),
        Direction::Outbound => ("open", "to"),
    };
    let protocol = match connection.protocol {
        Protocol::Icmp => "icmp",
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
    };
    let host = if connection.dest_host.is_empty() {
        String::new()
    } else {
        format!("{} ", connection.dest_host)
    };
    format!(
        "{path} wants to {direction} {protocol} {relation} {zone}\n  {host}{ip}:{port}\n  command: {command}\n  uid: {uid}\nChoose once, session, or always. Add zone or command for a narrower rule.\n",
        path = connection.process_path,
        ip = connection.dest_ip,
        port = connection.dest_port,
        command = connection.cmdline,
        uid = connection.uid,
    )
}

/// Read prompts from `stream`, show them on `output`, and send the operator's answers.
pub fn converse(
    stream: &UnixStream,
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> io::Result<()> {
    let mut reader = io::BufReader::new(stream.try_clone()?);
    let mut writer = stream.try_clone()?;
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            return Ok(());
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        match parse_server_message(trimmed) {
            Ok(ServerMessage::Prompt { id, connection }) => {
                output.write_all(prompt_text(&connection).as_bytes())?;
                output.flush()?;
                let Some((action, duration, scope)) =
                    read_answer(input, output, &mut reader, &mut writer)?
                else {
                    return Ok(());
                };
                let encoded = format_client_message(&ClientMessage::Answer {
                    id,
                    action,
                    duration,
                    scope,
                })
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "answer"))?;
                writer.write_all(encoded.as_bytes())?;
            }
            Ok(ServerMessage::Denied) => writeln!(output, "daemon refused this user")?,
            Ok(ServerMessage::Busy) => writeln!(output, "another prompt is already connected")?,
            Ok(ServerMessage::BadRequest) => writeln!(output, "daemon rejected that answer")?,
            Ok(ServerMessage::Rejected) => writeln!(output, "that answer was not stored")?,
            Ok(ServerMessage::Forgotten) => writeln!(output, "rule removed")?,
            Ok(ServerMessage::Stored { name }) => writeln!(output, "saved {name}")?,
            Ok(ServerMessage::Rule { name, summary }) => writeln!(output, "{name} {summary}")?,
            Ok(ServerMessage::RulesEnd) => writeln!(output, "end of rules")?,
            Ok(ServerMessage::Decision {
                action,
                because,
                path,
                detail,
                command,
            }) => {
                let action = match action {
                    Action::Allow => "allow",
                    Action::Deny => "deny",
                };
                writeln!(output, "{action} {path} {detail} {because} {command}")?
            }
            Err(_) => writeln!(output, "ignored a daemon line")?,
        }
    }
}

fn read_answer(
    input: &mut impl BufRead,
    output: &mut impl Write,
    daemon: &mut impl BufRead,
    writer: &mut impl Write,
) -> io::Result<Option<(Action, Duration, Scope)>> {
    let mut line = String::new();
    loop {
        line.clear();
        if input.read_line(&mut line)? == 0 {
            return Ok(None);
        }
        if line.trim() == "rules" {
            let encoded = format_client_message(&ClientMessage::List)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "list"))?;
            writer.write_all(encoded.as_bytes())?;
            let mut ack = String::new();
            loop {
                ack.clear();
                if daemon.read_line(&mut ack)? == 0 {
                    break;
                }
                match parse_server_message(ack.trim_end_matches(['\r', '\n'])) {
                    Ok(ServerMessage::Rule { name, summary }) => {
                        writeln!(output, "{name} {summary}")?
                    }
                    Ok(ServerMessage::RulesEnd) => break,
                    _ => writeln!(output, "ignored a daemon line")?,
                }
            }
            output.flush()?;
            continue;
        }
        if let Some(name) = line.trim().strip_prefix("forget ") {
            let encoded = format_client_message(&ClientMessage::Forget {
                name: name.to_string(),
            });
            if let Ok(encoded) = encoded {
                writer.write_all(encoded.as_bytes())?;
                let mut ack = String::new();
                daemon.read_line(&mut ack)?;
                match parse_server_message(ack.trim_end_matches(['\r', '\n'])) {
                    Ok(ServerMessage::Forgotten) => writeln!(output, "rule removed")?,
                    _ => writeln!(output, "that rule was not removed")?,
                }
            } else {
                writeln!(output, "expected: forget name")?;
            }
            output.flush()?;
            continue;
        }
        if let Some(answer) = parse_operator_line(&line) {
            return Ok(Some(answer));
        }
        writeln!(output, "expected: allow once")?;
        output.flush()?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};
    use std::thread;

    #[test]
    fn the_operator_line_is_an_allowlist() {
        assert_eq!(
            parse_operator_line("allow session\n"),
            Some((Action::Allow, Duration::Session, Scope::Program))
        );
        assert_eq!(
            parse_operator_line("deny always"),
            Some((Action::Deny, Duration::Always, Scope::Program))
        );
        assert_eq!(
            parse_operator_line("allow always zone"),
            Some((Action::Allow, Duration::Always, Scope::Zone))
        );
        assert_eq!(
            parse_operator_line("allow session command"),
            Some((Action::Allow, Duration::Session, Scope::Command))
        );
        assert_eq!(parse_operator_line("allow once command"), None);
        assert_eq!(parse_operator_line("allow once zone"), None);
        assert_eq!(parse_operator_line("allow forever"), None);
        assert_eq!(parse_operator_line("allow once extra"), None);
        assert_eq!(
            window_answer(true, Duration::Once, Scope::Zone),
            (Action::Allow, Duration::Once, Scope::Program)
        );
        assert_eq!(
            window_answer(false, Duration::Always, Scope::Command),
            (Action::Deny, Duration::Always, Scope::Command)
        );
        assert_eq!(program_name("/usr/bin/curl"), "curl");
        assert_eq!(program_name("curl"), "curl");
        assert_eq!(
            decision_zone("outbound tcp internet 1.2.3.4:443"),
            Some("internet")
        );
        assert_eq!(
            decision_zone("inbound tcp trusted 192.168.1.40:22"),
            Some("trusted")
        );
        assert_eq!(decision_zone("outbound tcp"), None);
    }

    #[test]
    fn a_prompt_is_shown_with_its_zone_and_the_answer_is_sent() {
        let (ui_side, mut daemon_side) = UnixStream::pair().unwrap();
        let connection = Connection {
            process_path: "/usr/sbin/sshd".to_string(),
            cmdline: "sshd: listener".to_string(),
            uid: 0,
            protocol: Protocol::Tcp,
            dest_host: String::new(),
            dest_ip: "192.168.1.40".parse().unwrap(),
            dest_port: 22,
            direction: Direction::Inbound,
            sha256: String::new(),
        };
        let prompt =
            copysnitch_common::format_server_message(&ServerMessage::Prompt { id: 4, connection })
                .unwrap();
        let server = thread::spawn(move || {
            daemon_side.write_all(prompt.as_bytes()).unwrap();
            let mut reader = io::BufReader::new(daemon_side.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            drop(reader);
            drop(daemon_side);
            line
        });
        let mut output = Vec::new();
        converse(
            &ui_side,
            &mut Cursor::new(b"nope\ndeny once\n"),
            &mut output,
        )
        .unwrap();
        let answer = server.join().unwrap();
        assert_eq!(answer, "answer\t4\tdeny\tonce\n");
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("/usr/sbin/sshd"), "{text}");
        assert!(
            text.contains("accept tcp from the trusted network"),
            "{text}"
        );
        assert!(text.contains("192.168.1.40:22"), "{text}");
        assert!(text.contains("expected: allow once"), "{text}");
    }
}
