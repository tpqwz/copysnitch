//! Name a connection from a packet and a proc tree.
//!
//! The queue itself is not installed here. Applying the ruleset is for the guest.
//! shortcut: scanning proc for the socket inode, replace with eBPF when the guest has BTF.

use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use copysnitch_common::{Connection, Direction, Protocol, WireError, parse_connection_line};

/// Why a packet could not be named.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObserveError {
    Truncated,
    Unsupported,
}

/// Ruleset text for the guest. `bypass` keeps the machine working if the daemon is not running.
/// The chain accepts unless a running daemon returns a verdict.
pub fn output_queue_ruleset() -> &'static str {
    "\
table inet copysnitch {
    chain input {
        type filter hook input priority filter; policy accept;
        ct state new queue num 0 bypass
    }
    chain output {
        type filter hook output priority filter; policy accept;
        ct state new queue num 0 bypass
    }
}
"
}

/// Build the outbound connection a queued packet belongs to.
///
/// `proc_root` is a directory shaped like `/proc`. An unknown socket still
/// returns a connection; its process path is empty.
/// A stdin line is either the tab-separated connection text or `packet ` plus hex.
/// Hex is decoded and named from `proc_root`. The development host does not install nftables.
pub fn connection_from_line(line: &str, proc_root: &Path) -> Result<Connection, WireError> {
    let Some(hex) = line.strip_prefix("packet ") else {
        return parse_connection_line(line);
    };
    let bytes = decode_hex(hex.trim()).map_err(|_| WireError::Syntax)?;
    name_outbound(&bytes, proc_root).map_err(|_| WireError::Syntax)
}

fn decode_hex(text: &str) -> Result<Vec<u8>, ()> {
    if text.is_empty() || text.len() % 2 != 0 || text.len() > 8192 {
        return Err(());
    }
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).map_err(|_| ()))
        .collect()
}

/// Name a packet as outbound or inbound.
///
/// For inbound, `dest_ip` is the peer and `dest_port` is the local service port.
pub fn name_packet(
    packet: &[u8],
    proc_root: &Path,
    direction: Direction,
) -> Result<Connection, ObserveError> {
    let endpoints = parse_packet(packet)?;
    let mut rows = Vec::new();
    for name in ["net/tcp", "net/tcp6", "net/udp", "net/udp6"] {
        if let Ok(text) = fs::read_to_string(proc_root.join(name)) {
            rows.extend(parse_proc_net(&text));
        }
    }
    let matched = rows.iter().find(|row| match direction {
        Direction::Outbound => {
            row.local_ip == endpoints.src
                && row.local_port == endpoints.src_port
                && row.remote_ip == endpoints.dst
                && row.remote_port == endpoints.dst_port
        }
        Direction::Inbound => {
            row.local_ip == endpoints.dst
                && row.local_port == endpoints.dst_port
                && row.remote_ip == endpoints.src
                && row.remote_port == endpoints.src_port
        }
    });
    let (path, cmdline, uid) = if let Some(row) = matched {
        let (path, cmdline) = program_for_inode(proc_root, row.inode).unwrap_or_default();
        (path, cmdline, row.uid)
    } else {
        (String::new(), String::new(), 0)
    };
    let (dest_ip, dest_port) = match direction {
        Direction::Outbound => (endpoints.dst, endpoints.dst_port),
        Direction::Inbound => (endpoints.src, endpoints.dst_port),
    };
    Ok(Connection {
        process_path: path,
        cmdline,
        uid,
        protocol: endpoints.protocol,
        dest_host: String::new(),
        dest_ip,
        dest_port,
        direction,
        sha256: String::new(),
    })
}

pub fn name_outbound(packet: &[u8], proc_root: &Path) -> Result<Connection, ObserveError> {
    name_packet(packet, proc_root, Direction::Outbound)
}

struct Endpoints {
    src: IpAddr,
    src_port: u16,
    dst: IpAddr,
    dst_port: u16,
    protocol: Protocol,
}

fn parse_packet(packet: &[u8]) -> Result<Endpoints, ObserveError> {
    if packet.is_empty() {
        return Err(ObserveError::Truncated);
    }
    match packet[0] >> 4 {
        4 => parse_v4(packet),
        6 => parse_v6(packet),
        _ => Err(ObserveError::Unsupported),
    }
}

fn parse_v4(packet: &[u8]) -> Result<Endpoints, ObserveError> {
    if packet.len() < 20 {
        return Err(ObserveError::Truncated);
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < 20 || packet.len() < header_len {
        return Err(ObserveError::Truncated);
    }
    let protocol = ip_protocol(packet[9])?;
    let src = IpAddr::V4(Ipv4Addr::new(
        packet[12], packet[13], packet[14], packet[15],
    ));
    let dst = IpAddr::V4(Ipv4Addr::new(
        packet[16], packet[17], packet[18], packet[19],
    ));
    let (src_port, dst_port) = ports(protocol, &packet[header_len..])?;
    Ok(Endpoints {
        src,
        src_port,
        dst,
        dst_port,
        protocol,
    })
}

fn parse_v6(packet: &[u8]) -> Result<Endpoints, ObserveError> {
    if packet.len() < 40 {
        return Err(ObserveError::Truncated);
    }
    // Extension headers are not peeled. Misreading one would name the wrong ports.
    let protocol = match packet[6] {
        6 => Protocol::Tcp,
        17 => Protocol::Udp,
        58 => Protocol::Icmp,
        _ => return Err(ObserveError::Unsupported),
    };
    let src_bytes: [u8; 16] = packet[8..24]
        .try_into()
        .map_err(|_| ObserveError::Truncated)?;
    let dst_bytes: [u8; 16] = packet[24..40]
        .try_into()
        .map_err(|_| ObserveError::Truncated)?;
    let (src_port, dst_port) = ports(protocol, &packet[40..])?;
    Ok(Endpoints {
        src: IpAddr::V6(Ipv6Addr::from(src_bytes)),
        src_port,
        dst: IpAddr::V6(Ipv6Addr::from(dst_bytes)),
        dst_port,
        protocol,
    })
}

fn ip_protocol(number: u8) -> Result<Protocol, ObserveError> {
    match number {
        1 => Ok(Protocol::Icmp),
        6 => Ok(Protocol::Tcp),
        17 => Ok(Protocol::Udp),
        _ => Err(ObserveError::Unsupported),
    }
}

fn ports(protocol: Protocol, rest: &[u8]) -> Result<(u16, u16), ObserveError> {
    if protocol == Protocol::Icmp {
        return Ok((0, 0));
    }
    if rest.len() < 4 {
        return Err(ObserveError::Truncated);
    }
    Ok((
        u16::from_be_bytes([rest[0], rest[1]]),
        u16::from_be_bytes([rest[2], rest[3]]),
    ))
}

struct Row {
    local_ip: IpAddr,
    local_port: u16,
    remote_ip: IpAddr,
    remote_port: u16,
    uid: u32,
    inode: u64,
}

fn parse_proc_net(text: &str) -> Vec<Row> {
    text.lines().skip(1).filter_map(parse_proc_row).collect()
}

fn parse_proc_row(line: &str) -> Option<Row> {
    let mut parts = line.split_whitespace();
    let _index = parts.next()?;
    let local = parts.next()?;
    let remote = parts.next()?;
    let _state = parts.next()?;
    let _queues = parts.next()?;
    let _timer = parts.next()?;
    let _retrans = parts.next()?;
    let uid = parts.next()?.parse().ok()?;
    let _timeout = parts.next()?;
    let inode = parts.next()?.parse().ok()?;
    let (local_ip, local_port) = parse_proc_addr(local)?;
    let (remote_ip, remote_port) = parse_proc_addr(remote)?;
    Some(Row {
        local_ip,
        local_port,
        remote_ip,
        remote_port,
        uid,
        inode,
    })
}

fn parse_proc_addr(text: &str) -> Option<(IpAddr, u16)> {
    let (ip_hex, port_hex) = text.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    let ip = if ip_hex.len() == 8 {
        IpAddr::V4(parse_proc_v4(ip_hex)?)
    } else if ip_hex.len() == 32 {
        IpAddr::V6(parse_proc_v6(ip_hex)?)
    } else {
        return None;
    };
    Some((ip, port))
}

fn parse_proc_v4(hex: &str) -> Option<Ipv4Addr> {
    let raw = u32::from_str_radix(hex, 16).ok()?;
    let bytes = raw.to_le_bytes();
    Some(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
}

fn parse_proc_v6(hex: &str) -> Option<Ipv6Addr> {
    if hex.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for index in 0..4 {
        let start = index * 8;
        let word = u32::from_str_radix(&hex[start..start + 8], 16).ok()?;
        bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    Some(Ipv6Addr::from(bytes))
}

fn program_for_inode(proc_root: &Path, inode: u64) -> Option<(String, String)> {
    let needle = format!("socket:[{inode}]");
    let mut entries = fs::read_dir(proc_root).ok()?.flatten().collect::<Vec<_>>();
    entries.sort_by(|left, right| left.file_name().cmp(&right.file_name()));
    for entry in entries {
        let Some(name) = entry.file_name().into_string().ok() else {
            continue;
        };
        if name.is_empty() || !name.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        let Ok(fds) = fs::read_dir(entry.path().join("fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            let Ok(target) = fs::read_link(fd.path()) else {
                continue;
            };
            if target.as_os_str() != std::ffi::OsStr::new(&needle) {
                continue;
            }
            let path = fs::read_link(entry.path().join("exe"))
                .map(|target| target.to_string_lossy().into_owned())
                .unwrap_or_default();
            let cmdline = read_cmdline(&entry.path().join("cmdline"));
            return Some((path, cmdline));
        }
    }
    None
}

fn read_cmdline(path: &Path) -> String {
    let Ok(bytes) = fs::read(path) else {
        return String::new();
    };
    let bytes = if bytes.len() > 4096 {
        &bytes[..4096]
    } else {
        &bytes[..]
    };
    String::from_utf8_lossy(bytes)
        .trim_end_matches('\0')
        .replace('\0', " ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use copysnitch_common::{Action, Direction as Way};
    use std::os::unix::fs::PermissionsExt;

    fn private_dir() -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "copysnitch-observe-{}-{}",
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

    #[test]
    fn a_queued_packet_is_named_after_the_socket_owner() {
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

        // IPv4 TCP from 10.0.0.2:54321 to 93.184.216.34:443.
        let packet = [
            0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 10, 0, 0, 2,
            93, 184, 216, 34, 0xd4, 0x31, 0x01, 0xbb, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0x02, 0, 0, 0,
            0, 0, 0,
        ];
        let connection = name_outbound(&packet, &root).expect("named connection");
        assert_eq!(connection.process_path, "/usr/bin/curl");
        assert_eq!(connection.cmdline, "curl https://example.com");
        assert_eq!(connection.uid, 1000);
        assert_eq!(connection.protocol, Protocol::Tcp);
        assert_eq!(
            connection.dest_ip,
            "93.184.216.34".parse::<IpAddr>().unwrap()
        );
        assert_eq!(connection.dest_port, 443);
        assert_eq!(connection.direction, Way::Outbound);

        let rules = private_dir();
        std::fs::write(
            rules.join("curl"),
            "action allow\nduration always\ndirection outbound\nprocess.path /usr/bin/curl\n",
        )
        .unwrap();
        let mut firewall = crate::Firewall::load(&rules).unwrap();
        match firewall.decide(&connection) {
            crate::Step::Decided {
                action: Action::Allow,
                ..
            } => {}
            other => panic!("the saved rule should allow the named program, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_dir_all(rules);
    }

    #[test]
    fn an_inbound_packet_is_named_after_the_listener() {
        let root = private_dir();
        std::fs::create_dir_all(root.join("net")).unwrap();
        std::fs::write(
            root.join("net/tcp"),
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0200000A:0016 22D8B85D:D431 01 00000000:00000000 00:00000000 00000000     0        0 99 1 0000000000000000 100 0 0 10 0\n",
        )
        .unwrap();
        std::fs::create_dir_all(root.join("7/fd")).unwrap();
        std::os::unix::fs::symlink("socket:[99]", root.join("7/fd/4")).unwrap();
        std::fs::write(root.join("7/cmdline"), b"sshd:\0listener\0").unwrap();
        std::os::unix::fs::symlink("/usr/sbin/sshd", root.join("7/exe")).unwrap();
        // Client 93.184.216.34:54321 to local 10.0.0.2:22.
        let packet = [
            0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 93, 184, 216,
            34, 10, 0, 0, 2, 0xd4, 0x31, 0x00, 0x16, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0x02, 0, 0, 0,
            0, 0, 0,
        ];
        let connection = name_packet(&packet, &root, Direction::Inbound).expect("listener");
        assert_eq!(connection.process_path, "/usr/sbin/sshd");
        assert_eq!(connection.cmdline, "sshd: listener");
        assert_eq!(connection.direction, Direction::Inbound);
        assert_eq!(
            connection.dest_ip,
            "93.184.216.34".parse::<std::net::IpAddr>().unwrap()
        );
        assert_eq!(connection.dest_port, 22);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_short_packet_is_rejected_and_a_missing_socket_has_no_program() {
        assert_eq!(
            name_outbound(&[0x45, 0, 0, 0], Path::new("/no/such/proc")),
            Err(ObserveError::Truncated)
        );
        let packet = [
            0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 10, 0, 0, 2,
            93, 184, 216, 34, 0xd4, 0x31, 0x01, 0xbb, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0x02, 0, 0, 0,
            0, 0, 0,
        ];
        let root = private_dir();
        let connection = name_outbound(&packet, &root).expect("tuple without a program");
        assert_eq!(connection.process_path, "");
        assert_eq!(connection.dest_port, 443);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn the_guest_ruleset_queues_new_output_and_fails_open_when_the_daemon_is_absent() {
        let ruleset = output_queue_ruleset();
        assert!(ruleset.contains("hook output"), "{ruleset}");
        assert!(ruleset.contains("hook input"), "{ruleset}");
        assert!(ruleset.contains("policy accept"), "{ruleset}");
        assert!(ruleset.contains("ct state new"), "{ruleset}");
        assert!(ruleset.contains("queue num 0 bypass"), "{ruleset}");
        assert!(!ruleset.contains("policy drop"), "{ruleset}");
    }

    #[test]
    fn a_packet_hex_line_names_the_socket_owner() {
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
        let line = "packet 4500002800004000400600000a0000025db8d822d43101bb00000000000000005002000000000000";
        let connection = connection_from_line(line, &root).expect("hex packet");
        assert_eq!(connection.process_path, "/usr/bin/curl");
        assert_eq!(connection.dest_port, 443);
        assert_eq!(
            connection_from_line("packet zz", &root),
            Err(WireError::Syntax)
        );
        let _ = std::fs::remove_dir_all(root);
    }
}
