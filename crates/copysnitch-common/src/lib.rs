//! Types shared by the root daemon and the user-session UI.
//!
//! The daemon decides whether a connection proceeds. The UI asks the person.
//! A prompt does not run as root.

use std::net::IpAddr;

/// Whether a connection may proceed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Allow,
    Deny,
}

/// How long an answer stays in force.
///
/// `Once` covers the single connection that was asked about. `Session` lasts
/// until the daemon exits. `Always` is written to the rules directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Duration {
    Once,
    Session,
    Always,
}

/// Transport of an intercepted connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Protocol {
    Icmp,
    Tcp,
    Udp,
}

/// Where the address sits. Trusted is the machine and the local network.
/// Internet is everything else, in the sense ZoneAlarm used zones.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Zone {
    Internet,
    Trusted,
}

/// Outbound is a client connection. Inbound is a program accepting one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Direction {
    Inbound,
    Outbound,
}

/// How wide a remembered answer is.
///
/// `Program` is the path and the direction, in every zone. `Zone` adds the
/// zone of that connection, so a LAN allow does not cover the internet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    Program,
    Zone,
    /// The process path, the direction, and the exact command line.
    Command,
}

/// One attempt the daemon can name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Connection {
    pub process_path: String,
    pub cmdline: String,
    pub uid: u32,
    pub protocol: Protocol,
    pub dest_host: String,
    pub dest_ip: IpAddr,
    pub dest_port: u16,
    pub direction: Direction,
    /// Lowercase hex SHA-256 of the program file. Empty when the file was not hashed.
    pub sha256: String,
}

/// Zone of `ip`. Loopback, RFC1918, link-local, and IPv6 unique-local are trusted.
/// Carrier-grade NAT and public addresses are the internet.
pub fn zone_of(ip: IpAddr) -> Zone {
    match ip.to_canonical() {
        IpAddr::V4(ip) => {
            if ip.is_loopback() || ip.is_private() || ip.is_link_local() || ip.is_unspecified() {
                Zone::Trusted
            } else {
                Zone::Internet
            }
        }
        IpAddr::V6(ip) => {
            if ip.is_loopback()
                || ip.is_unicast_link_local()
                || ip.is_unique_local()
                || ip.is_unspecified()
            {
                Zone::Trusted
            } else {
                Zone::Internet
            }
        }
    }
}

/// One predicate inside a rule. Every predicate on a rule must match.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Field {
    DestHost(String),
    DestIp(IpAddr),
    DestPort(u16),
    Cmdline(String),
    Direction(Direction),
    ProcessPath(String),
    Protocol(Protocol),
    Sha256(String),
    Uid(u32),
    Zone(Zone),
}

/// A named allow or deny. Conditions are a conjunction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub name: String,
    pub action: Action,
    pub duration: Duration,
    pub when: Vec<Field>,
}

/// The rule that answers `conn`, if any.
///
/// The rule with the most conditions wins. A tie in size fails closed: deny
/// beats allow. Two rules with the same size and the same action resolve to
/// the lexicographically smaller name.
pub fn pick<'a, I>(rules: I, conn: &Connection) -> Option<&'a Rule>
where
    I: IntoIterator<Item = &'a Rule>,
{
    let mut best: Option<&Rule> = None;
    for rule in rules {
        if !rule.when.iter().all(|field| field.matches(conn)) {
            continue;
        }
        best = Some(match best {
            None => rule,
            Some(current) => prefer(current, rule),
        });
    }
    best
}

fn prefer<'a>(current: &'a Rule, candidate: &'a Rule) -> &'a Rule {
    use std::cmp::Ordering;
    match candidate.when.len().cmp(&current.when.len()) {
        Ordering::Greater => candidate,
        Ordering::Less => current,
        Ordering::Equal => match (current.action, candidate.action) {
            (Action::Allow, Action::Deny) => candidate,
            (Action::Deny, Action::Allow) => current,
            _ => {
                if candidate.name < current.name {
                    candidate
                } else {
                    current
                }
            }
        },
    }
}

/// Why a rule file was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleParseError {
    /// The file name is not a single safe path component.
    Name,
    /// The body is missing a required line, has an unknown key, or names `once` or `session`.
    Syntax,
}

/// `name` is the file name, not a path. It may contain ASCII letters, digits, `.`, `_`, and `-`, and it must start with a letter or digit. The maximum length is 64 bytes.
pub fn rule_name_ok(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > 64 {
        return false;
    }
    let [first, rest @ ..] = bytes else {
        return false;
    };
    first.is_ascii_alphanumeric()
        && rest
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

/// Parse a rule file body. Stored rules are `duration always` and have at least one condition.
pub fn parse_rule(name: &str, text: &str) -> Result<Rule, RuleParseError> {
    if !rule_name_ok(name) {
        return Err(RuleParseError::Name);
    }
    if text.len() > 64 * 1024 {
        return Err(RuleParseError::Syntax);
    }
    let mut action = None;
    let mut duration = None;
    let mut when = Vec::new();
    for raw in text.lines() {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once(' ') else {
            return Err(RuleParseError::Syntax);
        };
        if !value_ok(value) {
            return Err(RuleParseError::Syntax);
        }
        let field = match key {
            "action" => {
                if action.is_some() {
                    return Err(RuleParseError::Syntax);
                }
                action = Some(match value {
                    "allow" => Action::Allow,
                    "deny" => Action::Deny,
                    _ => return Err(RuleParseError::Syntax),
                });
                continue;
            }
            "duration" => {
                if duration.is_some() || value != "always" {
                    return Err(RuleParseError::Syntax);
                }
                duration = Some(Duration::Always);
                continue;
            }
            "process.command" => Field::Cmdline(value.to_string()),
            "process.path" => Field::ProcessPath(value.to_string()),
            "process.sha256" => {
                if value.len() != 64
                    || !value
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                {
                    return Err(RuleParseError::Syntax);
                }
                Field::Sha256(value.to_string())
            }
            "dest.host" => Field::DestHost(value.to_string()),
            "dest.ip" => Field::DestIp(value.parse().map_err(|_| RuleParseError::Syntax)?),
            "dest.port" => Field::DestPort(value.parse().map_err(|_| RuleParseError::Syntax)?),
            "protocol" => Field::Protocol(match value {
                "icmp" => Protocol::Icmp,
                "tcp" => Protocol::Tcp,
                "udp" => Protocol::Udp,
                _ => return Err(RuleParseError::Syntax),
            }),
            "user.uid" => Field::Uid(value.parse().map_err(|_| RuleParseError::Syntax)?),
            "direction" => Field::Direction(parse_direction_rule(value)?),
            "zone" => Field::Zone(parse_zone_rule(value)?),
            _ => return Err(RuleParseError::Syntax),
        };
        if when
            .iter()
            .any(|existing| std::mem::discriminant(existing) == std::mem::discriminant(&field))
        {
            return Err(RuleParseError::Syntax);
        }
        when.push(field);
    }
    if when.is_empty() || when.len() > 16 {
        return Err(RuleParseError::Syntax);
    }
    Ok(Rule {
        name: name.to_string(),
        action: action.ok_or(RuleParseError::Syntax)?,
        duration: duration.ok_or(RuleParseError::Syntax)?,
        when,
    })
}

/// Canonical rule file body. Keys are in a fixed order and the text ends with a newline.
pub fn format_rule(rule: &Rule) -> String {
    let mut lines = vec![
        match rule.action {
            Action::Allow => "action allow".to_string(),
            Action::Deny => "action deny".to_string(),
        },
        match rule.duration {
            Duration::Always => "duration always".to_string(),
            Duration::Once => "duration once".to_string(),
            Duration::Session => "duration session".to_string(),
        },
    ];
    let mut when = rule.when.clone();
    when.sort();
    for field in when {
        lines.push(match field {
            Field::DestHost(value) => format!("dest.host {value}"),
            Field::DestIp(value) => format!("dest.ip {value}"),
            Field::DestPort(value) => format!("dest.port {value}"),
            Field::Cmdline(value) => format!("process.command {value}"),
            Field::Direction(Direction::Inbound) => "direction inbound".to_string(),
            Field::Direction(Direction::Outbound) => "direction outbound".to_string(),
            Field::ProcessPath(value) => format!("process.path {value}"),
            Field::Sha256(value) => format!("process.sha256 {value}"),
            Field::Protocol(Protocol::Icmp) => "protocol icmp".to_string(),
            Field::Protocol(Protocol::Tcp) => "protocol tcp".to_string(),
            Field::Protocol(Protocol::Udp) => "protocol udp".to_string(),
            Field::Uid(value) => format!("user.uid {value}"),
            Field::Zone(Zone::Internet) => "zone internet".to_string(),
            Field::Zone(Zone::Trusted) => "zone trusted".to_string(),
        });
    }
    lines.push(String::new());
    lines.join("\n")
}

fn value_ok(value: &str) -> bool {
    !value.is_empty() && value.len() <= 4096 && value.chars().all(|c| c >= ' ' && c != '\u{7f}')
}

/// Maximum length of one socket message, including the trailing newline.
pub const MAX_LINE: usize = 4096;

/// A line the UI sends to the daemon. The line has no trailing newline.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientMessage {
    Answer {
        id: u64,
        action: Action,
        duration: Duration,
        scope: Scope,
    },
    Forget {
        name: String,
    },
    List,
}

/// A line the daemon sends to the UI. The line has no trailing newline.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerMessage {
    Prompt { id: u64, connection: Connection },
    Denied,
    Busy,
    BadRequest,
    Rejected,
    Forgotten,
    Stored { name: String },
    Rule { name: String, summary: String },
    RulesEnd,
}

/// The socket line was not in the allowlist, or a field could not be represented.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireError {
    Syntax,
    Unrepresentable,
}

/// A connection submitted by the operator, not by the UI.
///
/// Fields, separated by tabs: process path, command line, uid, protocol,
/// destination host, destination IP, destination port, direction.
/// The zone is derived from the IP.
pub fn parse_connection_line(line: &str) -> Result<Connection, WireError> {
    if line.len() >= MAX_LINE {
        return Err(WireError::Syntax);
    }
    let fields: Vec<&str> = line.split('\t').collect();
    match fields.as_slice() {
        [path, cmdline, uid, protocol, host, ip, port, direction] => {
            if !wire_text_ok(path) || !wire_text_ok(cmdline) || !wire_text_ok(host) {
                return Err(WireError::Syntax);
            }
            Ok(Connection {
                process_path: (*path).to_string(),
                cmdline: (*cmdline).to_string(),
                uid: parse_u32(uid)?,
                protocol: parse_protocol(protocol)?,
                dest_host: (*host).to_string(),
                dest_ip: ip.parse().map_err(|_| WireError::Syntax)?,
                dest_port: parse_u16(port)?,
                direction: parse_direction_wire(direction)?,
                sha256: String::new(),
            })
        }
        _ => Err(WireError::Syntax),
    }
}

pub fn parse_client_message(line: &str) -> Result<ClientMessage, WireError> {
    if line.len() >= MAX_LINE {
        return Err(WireError::Syntax);
    }
    let fields: Vec<&str> = line.split('\t').collect();
    match fields.as_slice() {
        ["answer", id, action, duration] => Ok(ClientMessage::Answer {
            id: parse_id(id)?,
            action: parse_action(action)?,
            duration: parse_duration(duration)?,
            scope: Scope::Program,
        }),
        ["answer", id, action, duration, scope] => Ok(ClientMessage::Answer {
            id: parse_id(id)?,
            action: parse_action(action)?,
            duration: parse_duration(duration)?,
            scope: parse_scope(scope)?,
        }),
        ["forget", name] if rule_name_ok(name) => Ok(ClientMessage::Forget {
            name: (*name).to_string(),
        }),
        ["list"] => Ok(ClientMessage::List),
        _ => Err(WireError::Syntax),
    }
}

pub fn parse_server_message(line: &str) -> Result<ServerMessage, WireError> {
    if line.len() >= MAX_LINE {
        return Err(WireError::Syntax);
    }
    let fields: Vec<&str> = line.split('\t').collect();
    match fields.as_slice() {
        [
            "prompt",
            id,
            path,
            cmdline,
            uid,
            protocol,
            host,
            ip,
            port,
            direction,
            zone,
        ] => {
            if !wire_text_ok(path) || !wire_text_ok(cmdline) || !wire_text_ok(host) {
                return Err(WireError::Syntax);
            }
            let dest_ip: IpAddr = ip.parse().map_err(|_| WireError::Syntax)?;
            let parsed_zone = parse_zone_wire(zone)?;
            if parsed_zone != zone_of(dest_ip) {
                return Err(WireError::Syntax);
            }
            Ok(ServerMessage::Prompt {
                id: parse_id(id)?,
                connection: Connection {
                    process_path: (*path).to_string(),
                    cmdline: (*cmdline).to_string(),
                    uid: parse_u32(uid)?,
                    protocol: parse_protocol(protocol)?,
                    dest_host: (*host).to_string(),
                    dest_ip,
                    dest_port: parse_u16(port)?,
                    direction: parse_direction_wire(direction)?,
                    sha256: String::new(),
                },
            })
        }
        ["error", "denied"] => Ok(ServerMessage::Denied),
        ["error", "busy"] => Ok(ServerMessage::Busy),
        ["error", "bad request"] => Ok(ServerMessage::BadRequest),
        ["error", "rejected"] => Ok(ServerMessage::Rejected),
        ["ok", "forgotten"] => Ok(ServerMessage::Forgotten),
        ["ok", "rule", name] if rule_name_ok(name) => Ok(ServerMessage::Stored {
            name: (*name).to_string(),
        }),
        ["rule", name, summary] if rule_name_ok(name) && !summary.contains('\n') => {
            Ok(ServerMessage::Rule {
                name: (*name).to_string(),
                summary: (*summary).to_string(),
            })
        }
        ["ok", "rules"] => Ok(ServerMessage::RulesEnd),
        _ => Err(WireError::Syntax),
    }
}

pub fn format_client_message(message: &ClientMessage) -> Result<String, WireError> {
    let body = match message {
        ClientMessage::Answer {
            id,
            action,
            duration,
            scope,
        } => {
            let body = format!(
                "answer\t{id}\t{}\t{}",
                action_token(*action),
                duration_token(*duration)
            );
            match scope {
                Scope::Program => body,
                Scope::Zone => format!("{body}\tzone"),
                Scope::Command => format!("{body}\tcommand"),
            }
        }
        ClientMessage::Forget { name } => {
            if !rule_name_ok(name) {
                return Err(WireError::Syntax);
            }
            format!("forget\t{name}")
        }
        ClientMessage::List => "list".to_string(),
    };
    finish_line(body)
}

pub fn format_server_message(message: &ServerMessage) -> Result<String, WireError> {
    let body = match message {
        ServerMessage::Prompt { id, connection } => {
            if !wire_text_ok(&connection.process_path)
                || !wire_text_ok(&connection.cmdline)
                || !wire_text_ok(&connection.dest_host)
            {
                return Err(WireError::Unrepresentable);
            }
            format!(
                "prompt\t{id}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                connection.process_path,
                connection.cmdline,
                connection.uid,
                protocol_token(connection.protocol),
                connection.dest_host,
                connection.dest_ip,
                connection.dest_port,
                direction_token(connection.direction),
                zone_token(zone_of(connection.dest_ip))
            )
        }
        ServerMessage::Denied => "error\tdenied".to_string(),
        ServerMessage::Busy => "error\tbusy".to_string(),
        ServerMessage::BadRequest => "error\tbad request".to_string(),
        ServerMessage::Rejected => "error\trejected".to_string(),
        ServerMessage::Forgotten => "ok\tforgotten".to_string(),
        ServerMessage::Stored { name } => {
            if !rule_name_ok(name) {
                return Err(WireError::Unrepresentable);
            }
            format!("ok\trule\t{name}")
        }
        ServerMessage::Rule { name, summary } => {
            if !rule_name_ok(name) || summary.contains('\t') || summary.contains('\n') {
                return Err(WireError::Unrepresentable);
            }
            format!("rule\t{name}\t{summary}")
        }
        ServerMessage::RulesEnd => "ok\trules".to_string(),
    };
    finish_line(body)
}

fn finish_line(body: String) -> Result<String, WireError> {
    if body.len() + 1 > MAX_LINE {
        return Err(WireError::Unrepresentable);
    }
    Ok(format!("{body}\n"))
}

fn wire_text_ok(value: &str) -> bool {
    value.len() <= 4096 && value.chars().all(|c| c >= ' ' && c != '\u{7f}')
}

fn parse_id(value: &str) -> Result<u64, WireError> {
    if value.is_empty() || value.len() > 20 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(WireError::Syntax);
    }
    value.parse().map_err(|_| WireError::Syntax)
}

fn parse_u32(value: &str) -> Result<u32, WireError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(WireError::Syntax);
    }
    value.parse().map_err(|_| WireError::Syntax)
}

fn parse_u16(value: &str) -> Result<u16, WireError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(WireError::Syntax);
    }
    value.parse().map_err(|_| WireError::Syntax)
}

fn parse_action(value: &str) -> Result<Action, WireError> {
    match value {
        "allow" => Ok(Action::Allow),
        "deny" => Ok(Action::Deny),
        _ => Err(WireError::Syntax),
    }
}

fn parse_duration(value: &str) -> Result<Duration, WireError> {
    match value {
        "once" => Ok(Duration::Once),
        "session" => Ok(Duration::Session),
        "always" => Ok(Duration::Always),
        _ => Err(WireError::Syntax),
    }
}

fn parse_protocol(value: &str) -> Result<Protocol, WireError> {
    match value {
        "icmp" => Ok(Protocol::Icmp),
        "tcp" => Ok(Protocol::Tcp),
        "udp" => Ok(Protocol::Udp),
        _ => Err(WireError::Syntax),
    }
}

fn action_token(action: Action) -> &'static str {
    match action {
        Action::Allow => "allow",
        Action::Deny => "deny",
    }
}

fn duration_token(duration: Duration) -> &'static str {
    match duration {
        Duration::Once => "once",
        Duration::Session => "session",
        Duration::Always => "always",
    }
}

fn protocol_token(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Icmp => "icmp",
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
    }
}

fn direction_token(direction: Direction) -> &'static str {
    match direction {
        Direction::Inbound => "inbound",
        Direction::Outbound => "outbound",
    }
}

fn zone_token(zone: Zone) -> &'static str {
    match zone {
        Zone::Internet => "internet",
        Zone::Trusted => "trusted",
    }
}

fn parse_direction_wire(value: &str) -> Result<Direction, WireError> {
    match value {
        "inbound" => Ok(Direction::Inbound),
        "outbound" => Ok(Direction::Outbound),
        _ => Err(WireError::Syntax),
    }
}

fn parse_scope(value: &str) -> Result<Scope, WireError> {
    match value {
        "program" => Ok(Scope::Program),
        "zone" => Ok(Scope::Zone),
        "command" => Ok(Scope::Command),
        _ => Err(WireError::Syntax),
    }
}

fn parse_zone_wire(value: &str) -> Result<Zone, WireError> {
    match value {
        "internet" => Ok(Zone::Internet),
        "trusted" => Ok(Zone::Trusted),
        _ => Err(WireError::Syntax),
    }
}

fn parse_direction_rule(value: &str) -> Result<Direction, RuleParseError> {
    match value {
        "inbound" => Ok(Direction::Inbound),
        "outbound" => Ok(Direction::Outbound),
        _ => Err(RuleParseError::Syntax),
    }
}

fn parse_zone_rule(value: &str) -> Result<Zone, RuleParseError> {
    match value {
        "internet" => Ok(Zone::Internet),
        "trusted" => Ok(Zone::Trusted),
        _ => Err(RuleParseError::Syntax),
    }
}

impl Field {
    fn matches(&self, conn: &Connection) -> bool {
        match self {
            Field::DestHost(host) => host == &conn.dest_host,
            Field::DestIp(ip) => ip == &conn.dest_ip,
            Field::DestPort(port) => *port == conn.dest_port,
            Field::Cmdline(cmdline) => cmdline == &conn.cmdline,
            Field::Direction(direction) => *direction == conn.direction,
            Field::ProcessPath(path) => path == &conn.process_path,
            Field::Sha256(hash) => !hash.is_empty() && hash == &conn.sha256,
            Field::Protocol(protocol) => *protocol == conn.protocol,
            Field::Uid(uid) => *uid == conn.uid,
            Field::Zone(zone) => *zone == zone_of(conn.dest_ip),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn conn(path: &str, port: u16) -> Connection {
        Connection {
            process_path: path.to_string(),
            cmdline: String::new(),
            uid: 1000,
            protocol: Protocol::Tcp,
            dest_host: String::new(),
            dest_ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            dest_port: port,
            direction: Direction::Outbound,
            sha256: String::new(),
        }
    }

    fn path_rule(name: &str, action: Action, path: &str) -> Rule {
        Rule {
            name: name.to_string(),
            action,
            duration: Duration::Always,
            when: vec![Field::ProcessPath(path.to_string())],
        }
    }

    #[test]
    fn a_more_specific_rule_beats_a_broader_one() {
        let broad = path_rule("broad", Action::Allow, "/usr/bin/curl");
        let mut narrow = path_rule("narrow", Action::Deny, "/usr/bin/curl");
        narrow.when.push(Field::DestPort(22));
        let rules = [broad, narrow];

        let chosen = pick(rules.iter(), &conn("/usr/bin/curl", 22)).expect("a rule matches");
        assert_eq!(chosen.name, "narrow");
        assert_eq!(chosen.action, Action::Deny);

        let chosen =
            pick(rules.iter(), &conn("/usr/bin/curl", 443)).expect("the broad rule matches");
        assert_eq!(chosen.name, "broad");
        assert_eq!(chosen.action, Action::Allow);

        assert!(pick(rules.iter(), &conn("/usr/bin/wget", 22)).is_none());
    }

    #[test]
    fn a_tie_in_specificity_fails_closed() {
        let rules = [
            path_rule("a-allow", Action::Allow, "/bin/x"),
            path_rule("b-deny", Action::Deny, "/bin/x"),
        ];
        let chosen = pick(rules.iter(), &conn("/bin/x", 443)).expect("both rules match");
        assert_eq!(chosen.name, "b-deny");
        assert_eq!(chosen.action, Action::Deny);
    }

    #[test]
    fn the_same_action_at_the_same_specificity_uses_the_smaller_name() {
        let rules = [
            path_rule("b", Action::Allow, "/bin/x"),
            path_rule("a", Action::Allow, "/bin/x"),
        ];
        let chosen = pick(rules.iter(), &conn("/bin/x", 1)).expect("both rules match");
        assert_eq!(chosen.name, "a");
    }

    #[test]
    fn every_condition_on_a_rule_must_match() {
        let rules = [Rule {
            name: "ssh".to_string(),
            action: Action::Deny,
            duration: Duration::Always,
            when: vec![Field::DestPort(22)],
        }];
        assert!(pick(rules.iter(), &conn("/bin/anything", 22)).is_some());
        assert!(pick(rules.iter(), &conn("/bin/anything", 80)).is_none());
    }

    #[test]
    fn a_rule_file_roundtrips_through_the_canonical_text() {
        let text = "\
action allow
duration always
process.path /usr/bin/curl
";
        let rule = parse_rule("curl", text).expect("rule file parses");
        assert_eq!(rule.action, Action::Allow);
        assert_eq!(rule.duration, Duration::Always);
        assert_eq!(
            rule.when,
            vec![Field::ProcessPath("/usr/bin/curl".to_string())]
        );
        assert_eq!(format_rule(&rule), text);
    }

    #[test]
    fn a_rule_file_rejects_a_path_name_an_unknown_key_and_a_match_all() {
        let ok = "\
action deny
duration always
dest.port 22
";
        assert_eq!(parse_rule("../outside", ok), Err(RuleParseError::Name));
        assert_eq!(parse_rule("a/b", ok), Err(RuleParseError::Name));
        assert_eq!(parse_rule(&"n".repeat(65), ok), Err(RuleParseError::Name));

        let unknown = "\
action deny
duration always
process.user root
";
        assert_eq!(parse_rule("ssh", unknown), Err(RuleParseError::Syntax));

        let once = "\
action deny
duration once
dest.port 22
";
        assert_eq!(parse_rule("ssh", once), Err(RuleParseError::Syntax));

        let bare = "\
action deny
duration always
";
        assert_eq!(parse_rule("ssh", bare), Err(RuleParseError::Syntax));
    }

    #[test]
    fn an_operator_line_names_one_connection() {
        let line = "/usr/bin/curl\tcurl https://example.com\t1000\ttcp\texample.com\t93.184.216.34\t443\toutbound";
        let connection = parse_connection_line(line).expect("connection line");
        assert_eq!(connection.process_path, "/usr/bin/curl");
        assert_eq!(connection.cmdline, "curl https://example.com");
        assert_eq!(connection.uid, 1000);
        assert_eq!(connection.protocol, Protocol::Tcp);
        assert_eq!(connection.dest_host, "example.com");
        assert_eq!(
            connection.dest_ip,
            "93.184.216.34".parse::<IpAddr>().unwrap()
        );
        assert_eq!(connection.dest_port, 443);
        assert_eq!(connection.direction, Direction::Outbound);
        assert_eq!(zone_of(connection.dest_ip), Zone::Internet);
        assert_eq!(
            parse_connection_line("/bin/x\t\t1\ttcp\t\t10.0.0.2\t80"),
            Err(WireError::Syntax)
        );
    }

    #[test]
    fn a_prompt_and_an_answer_roundtrip_as_tab_separated_lines() {
        let connection = Connection {
            process_path: "/usr/bin/curl".to_string(),
            cmdline: "curl https://example.com".to_string(),
            uid: 1000,
            protocol: Protocol::Tcp,
            dest_host: "example.com".to_string(),
            dest_ip: "93.184.216.34".parse().unwrap(),
            dest_port: 443,
            direction: Direction::Outbound,
            sha256: String::new(),
        };
        let prompt = ServerMessage::Prompt {
            id: 7,
            connection: connection.clone(),
        };
        let line = format_server_message(&prompt).expect("prompt formats");
        assert_eq!(
            line,
            "prompt\t7\t/usr/bin/curl\tcurl https://example.com\t1000\ttcp\texample.com\t93.184.216.34\t443\toutbound\tinternet\n"
        );
        assert_eq!(
            parse_server_message(line.trim_end_matches('\n')).expect("prompt parses"),
            prompt
        );

        let answer = ClientMessage::Answer {
            id: 7,
            action: Action::Allow,
            duration: Duration::Once,
            scope: Scope::Program,
        };
        let line = format_client_message(&answer).expect("answer formats");
        assert_eq!(line, "answer\t7\tallow\tonce\n");
        assert_eq!(
            parse_client_message(line.trim_end_matches('\n')).expect("answer parses"),
            answer
        );
    }

    #[test]
    fn the_socket_allowlist_rejects_extra_fields_and_unsafe_text() {
        assert_eq!(
            parse_client_message("answer\t7\tallow\tonce\textra"),
            Err(WireError::Syntax)
        );
        let zoned = ClientMessage::Answer {
            id: 7,
            action: Action::Allow,
            duration: Duration::Always,
            scope: Scope::Zone,
        };
        let line = format_client_message(&zoned).expect("zoned answer");
        assert_eq!(line, "answer\t7\tallow\talways\tzone\n");
        assert_eq!(
            parse_client_message(line.trim_end_matches('\n')).expect("zoned answer parses"),
            zoned
        );
        assert_eq!(
            parse_client_message("answer\t7\tallow\tforever"),
            Err(WireError::Syntax)
        );
        assert_eq!(
            parse_client_message("forget\tcurl"),
            Ok(ClientMessage::Forget {
                name: "curl".to_string()
            })
        );
        assert_eq!(
            parse_client_message("forget\t../outside"),
            Err(WireError::Syntax)
        );
        assert_eq!(
            parse_server_message("error\tdenied"),
            Ok(ServerMessage::Denied)
        );
        let connection = Connection {
            process_path: "/bin/x\tsecret".to_string(),
            cmdline: String::new(),
            uid: 1,
            protocol: Protocol::Tcp,
            dest_host: String::new(),
            dest_ip: "127.0.0.1".parse().unwrap(),
            dest_port: 80,
            direction: Direction::Outbound,
            sha256: String::new(),
        };
        assert_eq!(
            format_server_message(&ServerMessage::Prompt { id: 1, connection }),
            Err(WireError::Unrepresentable)
        );
    }

    #[test]
    fn lan_and_loopback_are_trusted_and_public_addresses_are_the_internet() {
        let trusted = [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.1",
            "192.168.1.20",
            "169.254.1.1",
            "0.0.0.0",
            "::1",
            "fe80::1",
            "fd00::1",
            "::ffff:192.168.0.1",
        ];
        for ip in trusted {
            assert_eq!(zone_of(ip.parse().unwrap()), Zone::Trusted, "{ip}");
        }
        let internet = [
            "8.8.8.8",
            "172.32.0.1",
            "100.64.0.1",
            "2001:db8::1",
            "224.0.0.1",
        ];
        for ip in internet {
            assert_eq!(zone_of(ip.parse().unwrap()), Zone::Internet, "{ip}");
        }

        let rule = Rule {
            name: "net".to_string(),
            action: Action::Allow,
            duration: Duration::Always,
            when: vec![Field::Zone(Zone::Internet)],
        };
        let mut public = conn("/usr/bin/curl", 443);
        public.dest_ip = "8.8.8.8".parse().unwrap();
        assert_eq!(
            pick(std::iter::once(&rule), &public).map(|rule| rule.name.as_str()),
            Some("net")
        );
        public.dest_ip = "192.168.1.1".parse().unwrap();
        assert!(pick(std::iter::once(&rule), &public).is_none());
    }
}
