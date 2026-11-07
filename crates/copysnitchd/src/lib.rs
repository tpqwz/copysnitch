//! The root daemon: load rules, decide a connection, and remember an answer.

mod observe;
mod queue;
mod serve;

pub use observe::{connection_from_line, name_outbound, output_queue_ruleset};
pub use queue::{Judgement, judge_packet};

pub use serve::{DecisionBecause, Event, Running};

use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use copysnitch_common::{
    Action, Connection, Duration, Field, Rule, format_rule, parse_rule, pick, rule_name_ok,
};

/// What the daemon did with one connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    Decided {
        action: Action,
        because: Because,
    },
    Ask {
        id: u64,
    },
    /// A prompt is already waiting for an answer.
    Busy,
}

/// Why a connection was allowed or denied without a new prompt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Because {
    Rule(String),
}

/// The answer did not change the rule set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnswerError {
    UnknownPrompt,
    /// The process path is empty or cannot be stored in a rule file.
    Unstorable,
    /// A rule with the same conditions and a different action is already stored.
    Conflict,
    /// The rules directory could not be updated. The prompt is still pending.
    Store,
    /// No saved or session rule has that name.
    UnknownRule,
}

/// One rule as shown to the operator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListedRule {
    pub name: String,
    pub summary: String,
}

/// Saved rules plus the one prompt currently waiting for a person.
#[derive(Debug)]
pub struct Firewall {
    root: PathBuf,
    saved: Vec<Rule>,
    session: Vec<Rule>,
    pending: Option<u64>,
    next_id: u64,
}

impl Firewall {
    /// Load `dir`. The directory must be owned by this process and not writable by group or other.
    pub fn load(dir: &Path) -> io::Result<Self> {
        let root = private_directory(dir)?;
        let mut saved = Vec::new();
        for entry in fs::read_dir(&root)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                return Err(invalid("rule name is not utf-8"));
            };
            if !rule_name_ok(name) {
                return Err(invalid("rule name is not a single safe component"));
            }
            let path = root.join(name);
            let text = read_rule_file(&path)?;
            let rule = parse_rule(name, &text).map_err(|_| invalid("rule file is invalid"))?;
            saved.push(rule);
        }
        saved.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(Firewall {
            root,
            saved,
            session: Vec::new(),
            pending: None,
            next_id: 1,
        })
    }

    pub fn decide(&mut self, conn: &Connection) -> Step {
        if self.pending.is_some() {
            return Step::Busy;
        }
        let hashed;
        let conn = if conn.sha256.is_empty() {
            if let Some(hash) = file_sha256(&conn.process_path) {
                hashed = Connection {
                    sha256: hash,
                    ..conn.clone()
                };
                &hashed
            } else {
                conn
            }
        } else {
            conn
        };
        if let Some(rule) = pick(self.saved.iter().chain(self.session.iter()), conn) {
            return Step::Decided {
                action: rule.action,
                because: Because::Rule(rule.name.clone()),
            };
        }
        let id = self.next_id;
        self.next_id += 1;
        self.pending = Some(id);
        Step::Ask { id }
    }

    /// Record the person's answer for the pending prompt `id`.
    ///
    /// `Session` and `Always` store a rule on the process path and the direction.
    /// An outbound allow does not become a server right. `Scope::Zone` also
    /// stores the zone of this connection.
    pub fn answer(
        &mut self,
        id: u64,
        conn: &Connection,
        action: Action,
        duration: Duration,
        scope: copysnitch_common::Scope,
    ) -> Result<Option<String>, AnswerError> {
        if self.pending != Some(id) {
            return Err(AnswerError::UnknownPrompt);
        }
        if duration == Duration::Once {
            self.pending = None;
            return Ok(None);
        }
        if !storable_path(&conn.process_path) {
            return Err(AnswerError::Unstorable);
        }
        let zone = copysnitch_common::zone_of(conn.dest_ip);
        let mut when = vec![
            Field::ProcessPath(conn.process_path.clone()),
            Field::Direction(conn.direction),
        ];
        if scope == copysnitch_common::Scope::Zone {
            when.push(Field::Zone(zone));
        }
        if let Some(hash) = file_sha256(&conn.process_path) {
            when.push(Field::Sha256(hash));
        }
        let rule = Rule {
            name: stored_rule_name(action, &conn.process_path, conn.direction, scope, zone),
            action,
            duration,
            when,
        };
        if let Some(existing) = self
            .saved
            .iter()
            .chain(self.session.iter())
            .find(|existing| same_conditions(existing, &rule))
        {
            if existing.action != rule.action {
                return Err(AnswerError::Conflict);
            }
            if duration == Duration::Always {
                save_rule(&self.root, &rule)?;
            }
            self.pending = None;
            let name = existing.name.clone();
            return Ok(Some(name));
        }
        let name = rule.name.clone();
        if duration == Duration::Always {
            save_rule(&self.root, &rule)?;
            self.saved.retain(|saved| saved.name != name);
            self.saved.push(rule);
        } else {
            self.session.push(rule);
        }
        self.pending = None;
        Ok(Some(name))
    }

    /// Saved and session rules. The summary has no tabs.
    pub fn list(&self) -> Vec<ListedRule> {
        let mut listed: Vec<ListedRule> = self
            .saved
            .iter()
            .chain(self.session.iter())
            .map(|rule| ListedRule {
                name: rule.name.clone(),
                summary: summarize(rule),
            })
            .collect();
        listed.sort_by(|left, right| left.name.cmp(&right.name));
        listed
    }

    /// Remove a saved or session rule. A symlink is left in place.
    pub fn forget(&mut self, name: &str) -> Result<(), AnswerError> {
        if !rule_name_ok(name) {
            return Err(AnswerError::Unstorable);
        }
        let path = self.root.join(name);
        if path.parent() != Some(self.root.as_path()) {
            return Err(AnswerError::Unstorable);
        }
        let on_disk = match fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_symlink() || !meta.is_file() => {
                return Err(AnswerError::Conflict);
            }
            Ok(_) => true,
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(_) => return Err(AnswerError::Store),
        };
        let in_memory = self.saved.iter().any(|rule| rule.name == name)
            || self.session.iter().any(|rule| rule.name == name);
        if !in_memory && !on_disk {
            return Err(AnswerError::UnknownRule);
        }
        if on_disk {
            fs::remove_file(&path).map_err(|_| AnswerError::Store)?;
        }
        self.saved.retain(|rule| rule.name != name);
        self.session.retain(|rule| rule.name != name);
        Ok(())
    }

    pub fn timeout(&mut self, id: u64) -> Result<(), AnswerError> {
        if self.pending != Some(id) {
            return Err(AnswerError::UnknownPrompt);
        }
        self.pending = None;
        Ok(())
    }
}

fn private_directory(dir: &Path) -> io::Result<PathBuf> {
    let root = dir.canonicalize()?;
    let meta = fs::metadata(&root)?;
    if !meta.is_dir() {
        return Err(invalid("path is not a directory"));
    }
    if meta.permissions().mode() & 0o022 != 0 {
        return Err(invalid("directory is writable by group or other"));
    }
    // SAFETY: geteuid has no preconditions. It returns this process's effective user id.
    let euid = unsafe { libc::geteuid() };
    if meta.uid() != euid {
        return Err(invalid("directory is owned by another user"));
    }
    Ok(root)
}

fn read_rule_file(path: &Path) -> io::Result<String> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.file_type().is_file() {
        return Err(invalid("rule entry is not a regular file"));
    }
    if meta.len() > 64 * 1024 {
        return Err(invalid("rule file is too large"));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let mut text = String::new();
    file.read_to_string(&mut text)?;
    Ok(text)
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn file_sha256(path: &str) -> Option<String> {
    if !storable_path(path) {
        return None;
    }
    let mut file = fs::File::open(path).ok()?;
    let meta = file.metadata().ok()?;
    // shortcut: files larger than 32MiB are not hashed, raise this when a program we care about is bigger.
    if !meta.is_file() || meta.len() > 32 * 1024 * 1024 {
        return None;
    }
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buf[..n]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return None,
        }
    }
    Some(format!("{:x}", hasher.finalize()))
}

fn storable_path(path: &str) -> bool {
    !path.is_empty() && path.len() <= 4096 && path.chars().all(|ch| ch >= ' ' && ch != '\u{7f}')
}

fn stored_rule_name(
    action: Action,
    process_path: &str,
    direction: copysnitch_common::Direction,
    scope: copysnitch_common::Scope,
    zone: copysnitch_common::Zone,
) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    let action_tag = match action {
        Action::Allow => 1u8,
        Action::Deny => 2u8,
    };
    let direction_tag = match direction {
        copysnitch_common::Direction::Inbound => 3u8,
        copysnitch_common::Direction::Outbound => 4u8,
    };
    let scope_tag = match scope {
        copysnitch_common::Scope::Program => 5u8,
        copysnitch_common::Scope::Zone => 6u8,
    };
    let mut bytes = vec![action_tag, direction_tag, scope_tag];
    if scope == copysnitch_common::Scope::Zone {
        bytes.push(match zone {
            copysnitch_common::Zone::Internet => 7,
            copysnitch_common::Zone::Trusted => 8,
        });
    }
    bytes.extend(process_path.bytes());
    for byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("r{hash:016x}")
}

fn same_program(existing: &str, new_rule: &Rule) -> bool {
    let Ok(old) = parse_rule(&new_rule.name, existing) else {
        return false;
    };
    if old.action != new_rule.action {
        return false;
    }
    process_path(&old) == process_path(new_rule) && process_path(new_rule).is_some()
}

fn process_path(rule: &Rule) -> Option<&str> {
    rule.when.iter().find_map(|field| match field {
        Field::ProcessPath(path) => Some(path.as_str()),
        _ => None,
    })
}

fn replace_rule(path: &Path, body: &str) -> Result<(), AnswerError> {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return Err(AnswerError::Store);
    };
    let tmp = path.with_file_name(format!("{name}.tmp"));
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp)
        .map_err(|_| AnswerError::Store)?;
    if file.write_all(body.as_bytes()).is_err() {
        let _ = fs::remove_file(&tmp);
        return Err(AnswerError::Store);
    }
    fs::rename(&tmp, path).map_err(|_| {
        let _ = fs::remove_file(&tmp);
        AnswerError::Store
    })
}

fn summarize(rule: &Rule) -> String {
    let action = match rule.action {
        Action::Allow => "allow",
        Action::Deny => "deny",
    };
    let path = rule
        .when
        .iter()
        .find_map(|field| match field {
            Field::ProcessPath(path) => Some(path.as_str()),
            _ => None,
        })
        .unwrap_or("");
    let direction = rule.when.iter().find_map(|field| match field {
        Field::Direction(copysnitch_common::Direction::Inbound) => Some("inbound"),
        Field::Direction(copysnitch_common::Direction::Outbound) => Some("outbound"),
        _ => None,
    });
    let zone = rule.when.iter().find_map(|field| match field {
        Field::Zone(copysnitch_common::Zone::Internet) => Some("internet"),
        Field::Zone(copysnitch_common::Zone::Trusted) => Some("trusted"),
        _ => None,
    });
    let mut summary = format!("{action}");
    if let Some(direction) = direction {
        summary.push(' ');
        summary.push_str(direction);
    }
    if let Some(zone) = zone {
        summary.push(' ');
        summary.push_str(zone);
    }
    if !path.is_empty() {
        summary.push(' ');
        summary.push_str(path);
    }
    summary
}

fn same_conditions(left: &Rule, right: &Rule) -> bool {
    let mut left_fields = left.when.clone();
    let mut right_fields = right.when.clone();
    left_fields.sort();
    right_fields.sort();
    left_fields == right_fields
}

fn save_rule(root: &Path, rule: &Rule) -> Result<(), AnswerError> {
    if !rule_name_ok(&rule.name) {
        return Err(AnswerError::Store);
    }
    let path = root.join(&rule.name);
    if path.parent() != Some(root) {
        return Err(AnswerError::Store);
    }
    let body = format_rule(rule);
    match fs::symlink_metadata(&path) {
        Ok(meta) if meta.file_type().is_symlink() || !meta.is_file() => {
            return Err(AnswerError::Conflict);
        }
        Ok(meta) if meta.len() > 64 * 1024 => return Err(AnswerError::Conflict),
        Ok(_) => {
            let existing = read_rule_file(&path).map_err(|_| AnswerError::Store)?;
            if existing == body {
                return Ok(());
            }
            if !same_program(&existing, rule) {
                return Err(AnswerError::Conflict);
            }
            return replace_rule(&path, &body);
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err(AnswerError::Store),
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .map_err(|_| AnswerError::Store)?;
    if let Err(error) = file.write_all(body.as_bytes()) {
        let _ = fs::remove_file(&path);
        let _ = error;
        return Err(AnswerError::Store);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use copysnitch_common::Protocol;
    use std::net::IpAddr;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn private_dir() -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let mut path = std::env::temp_dir();
        path.push(format!(
            "copysnitch-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        let mut perms = fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o700);
        fs::set_permissions(&path, perms).unwrap();
        path
    }

    fn conn(path: &str) -> Connection {
        Connection {
            process_path: path.to_string(),
            cmdline: String::new(),
            uid: 1000,
            protocol: Protocol::Tcp,
            dest_host: String::new(),
            dest_ip: "1.2.3.4".parse::<IpAddr>().unwrap(),
            dest_port: 443,
            direction: copysnitch_common::Direction::Outbound,
            sha256: String::new(),
        }
    }

    #[test]
    fn a_saved_rule_allows_the_program_and_an_unknown_program_asks() {
        let dir = private_dir();
        fs::write(
            dir.join("curl"),
            "action allow\nduration always\nprocess.path /usr/bin/curl\n",
        )
        .unwrap();
        let mut fw = Firewall::load(&dir).unwrap();
        match fw.decide(&conn("/usr/bin/curl")) {
            Step::Decided { action, because } => {
                assert_eq!(action, Action::Allow);
                assert_eq!(because, Because::Rule("curl".to_string()));
            }
            other => panic!("expected an allow rule, got {other:?}"),
        }
        assert!(matches!(
            fw.decide(&conn("/usr/bin/wget")),
            Step::Ask { id: 1 }
        ));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn forgetting_a_saved_rule_asks_again_and_does_not_remove_a_symlink() {
        let dir = private_dir();
        fs::write(
            dir.join("curl"),
            "action allow\nduration always\ndirection outbound\nprocess.path /usr/bin/curl\n",
        )
        .unwrap();
        let mut fw = Firewall::load(&dir).unwrap();
        fw.forget("curl").expect("the saved rule is removed");
        assert!(matches!(
            fw.decide(&conn("/usr/bin/curl")),
            Step::Ask { .. }
        ));
        assert!(!dir.join("curl").exists());
        assert_eq!(fw.forget("../outside"), Err(AnswerError::Unstorable));
        std::os::unix::fs::symlink("/etc/passwd", dir.join("link")).unwrap();
        assert_eq!(fw.forget("link"), Err(AnswerError::Conflict));
        assert!(dir.join("link").is_symlink());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_session_answer_allows_that_program_until_the_daemon_exits() {
        let dir = private_dir();
        let mut fw = Firewall::load(&dir).unwrap();
        let Step::Ask { id } = fw.decide(&conn("/usr/bin/curl")) else {
            panic!("unknown program should ask");
        };
        fw.answer(
            id,
            &conn("/usr/bin/curl"),
            Action::Allow,
            Duration::Session,
            copysnitch_common::Scope::Program,
        )
        .unwrap();
        match fw.decide(&conn("/usr/bin/curl")) {
            Step::Decided {
                action: Action::Allow,
                because: Because::Rule(_),
            } => {}
            other => panic!("session answer should allow the next connection, got {other:?}"),
        }
        let mut inbound = conn("/usr/bin/curl");
        inbound.direction = copysnitch_common::Direction::Inbound;
        let Step::Ask { id } = fw.decide(&inbound) else {
            panic!("an outbound answer does not grant a server right");
        };
        fw.timeout(id).unwrap();
        assert!(matches!(
            fw.decide(&conn("/usr/bin/wget")),
            Step::Ask { .. }
        ));
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 0);
        let mut reloaded = Firewall::load(&dir).unwrap();
        assert!(matches!(
            reloaded.decide(&conn("/usr/bin/curl")),
            Step::Ask { .. }
        ));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_zone_answer_stays_in_that_zone() {
        let dir = private_dir();
        let mut fw = Firewall::load(&dir).unwrap();
        let mut internet = conn("/usr/bin/curl");
        internet.dest_ip = "8.8.8.8".parse().unwrap();
        let Step::Ask { id } = fw.decide(&internet) else {
            panic!("ask");
        };
        fw.answer(
            id,
            &internet,
            Action::Allow,
            Duration::Session,
            copysnitch_common::Scope::Zone,
        )
        .unwrap();
        internet.dest_port = 80;
        match fw.decide(&internet) {
            Step::Decided {
                action: Action::Allow,
                ..
            } => {}
            other => panic!("the same zone should be allowed, got {other:?}"),
        }
        let mut lan = conn("/usr/bin/curl");
        lan.dest_ip = "192.168.1.20".parse().unwrap();
        assert!(
            matches!(fw.decide(&lan), Step::Ask { .. }),
            "a trusted-network connection is outside an internet answer"
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_replaced_program_does_not_keep_an_always_allow() {
        let rules = private_dir();
        let files = private_dir();
        let program = files.join("tool");
        fs::write(&program, b"version-one").unwrap();
        let sample = conn(program.to_str().unwrap());
        let mut fw = Firewall::load(&rules).unwrap();
        let Step::Ask { id } = fw.decide(&sample) else {
            panic!("ask");
        };
        fw.answer(
            id,
            &sample,
            Action::Allow,
            Duration::Always,
            copysnitch_common::Scope::Program,
        )
        .unwrap();
        match fw.decide(&sample) {
            Step::Decided {
                action: Action::Allow,
                ..
            } => {}
            other => panic!("the same bytes should stay allowed, got {other:?}"),
        }
        fs::write(&program, b"version-two").unwrap();
        let Step::Ask { id } = fw.decide(&sample) else {
            panic!("a replaced program must be asked again");
        };
        fw.answer(
            id,
            &sample,
            Action::Allow,
            Duration::Always,
            copysnitch_common::Scope::Program,
        )
        .unwrap();
        match fw.decide(&sample) {
            Step::Decided {
                action: Action::Allow,
                ..
            } => {}
            other => panic!("the new bytes should be allowed, got {other:?}"),
        }
        let _ = fs::remove_dir_all(rules);
        let _ = fs::remove_dir_all(files);
    }

    #[test]
    fn an_always_answer_names_the_rule_it_stored() {
        let rules = private_dir();
        let files = private_dir();
        let program = files.join("tool");
        fs::write(&program, b"one").unwrap();
        let sample = conn(program.to_str().unwrap());
        let mut fw = Firewall::load(&rules).unwrap();
        let Step::Ask { id } = fw.decide(&sample) else {
            panic!("ask");
        };
        let name = fw
            .answer(
                id,
                &sample,
                Action::Allow,
                Duration::Always,
                copysnitch_common::Scope::Program,
            )
            .unwrap()
            .expect("stored rule name");
        assert!(
            rules.join(&name).is_file(),
            "the named file was not written"
        );
        assert!(
            fw.list()
                .iter()
                .any(|rule| rule.name == name && rule.summary.contains("tool")),
            "the list should show the program"
        );
        let _ = fs::remove_dir_all(rules);
        let _ = fs::remove_dir_all(files);
    }

    #[test]
    fn once_does_not_stick_and_always_is_reloaded() {
        let dir = private_dir();
        let mut fw = Firewall::load(&dir).unwrap();
        let Step::Ask { id } = fw.decide(&conn("/usr/bin/curl")) else {
            panic!("ask");
        };
        fw.answer(
            id,
            &conn("/usr/bin/curl"),
            Action::Allow,
            Duration::Once,
            copysnitch_common::Scope::Program,
        )
        .unwrap();
        let Step::Ask { id } = fw.decide(&conn("/usr/bin/curl")) else {
            panic!("once should ask again");
        };
        fw.timeout(id).unwrap();
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 0);

        let Step::Ask { id } = fw.decide(&conn("/no/such/copysnitch-wget")) else {
            panic!("ask");
        };
        fw.answer(
            id,
            &conn("/no/such/copysnitch-wget"),
            Action::Deny,
            Duration::Always,
            copysnitch_common::Scope::Program,
        )
        .unwrap();
        assert_eq!(
            fw.answer(
                id,
                &conn("/no/such/copysnitch-wget"),
                Action::Allow,
                Duration::Always,
                copysnitch_common::Scope::Program
            ),
            Err(AnswerError::UnknownPrompt)
        );
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);

        let mut reloaded = Firewall::load(&dir).unwrap();
        match reloaded.decide(&conn("/no/such/copysnitch-wget")) {
            Step::Decided {
                action: Action::Deny,
                because: Because::Rule(name),
            } => {
                let body = fs::read_to_string(dir.join(name)).unwrap();
                assert_eq!(
                    body,
                    "action deny\nduration always\ndirection outbound\nprocess.path /no/such/copysnitch-wget\n"
                );
            }
            other => panic!("reloaded rule should deny wget, got {other:?}"),
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_different_rule_body_is_not_overwritten_and_a_symlink_is_not_followed() {
        let dir = private_dir();
        let name = stored_rule_name(
            Action::Allow,
            "/usr/bin/curl",
            copysnitch_common::Direction::Outbound,
            copysnitch_common::Scope::Program,
            copysnitch_common::Zone::Internet,
        );
        fs::write(
            dir.join(&name),
            "action allow\nduration always\nprocess.path /bin/other\n",
        )
        .unwrap();
        let mut fw = Firewall::load(&dir).unwrap();
        let Step::Ask { id } = fw.decide(&conn("/usr/bin/curl")) else {
            panic!("planted rule is for another path");
        };
        assert_eq!(
            fw.answer(
                id,
                &conn("/usr/bin/curl"),
                Action::Allow,
                Duration::Always,
                copysnitch_common::Scope::Program
            ),
            Err(AnswerError::Conflict)
        );
        assert_eq!(
            fs::read_to_string(dir.join(&name)).unwrap(),
            "action allow\nduration always\nprocess.path /bin/other\n"
        );
        fw.answer(
            id,
            &conn("/usr/bin/curl"),
            Action::Deny,
            Duration::Once,
            copysnitch_common::Scope::Program,
        )
        .unwrap();

        let empty = private_dir();
        let mut fw = Firewall::load(&empty).unwrap();
        let target = empty.join("outside");
        std::os::unix::fs::symlink(
            &target,
            empty.join(stored_rule_name(
                Action::Allow,
                "/bin/x",
                copysnitch_common::Direction::Outbound,
                copysnitch_common::Scope::Program,
                copysnitch_common::Zone::Internet,
            )),
        )
        .unwrap();
        let Step::Ask { id } = fw.decide(&conn("/bin/x")) else {
            panic!("ask");
        };
        assert_eq!(
            fw.answer(
                id,
                &conn("/bin/x"),
                Action::Allow,
                Duration::Always,
                copysnitch_common::Scope::Program
            ),
            Err(AnswerError::Conflict)
        );
        assert!(!target.exists());
        let _ = fs::remove_dir_all(dir);
        let _ = fs::remove_dir_all(empty);
    }

    #[test]
    fn an_empty_path_cannot_be_stored_and_a_busy_prompt_is_not_replaced() {
        let dir = private_dir();
        let mut fw = Firewall::load(&dir).unwrap();
        let Step::Ask { id } = fw.decide(&conn("")) else {
            panic!("ask");
        };
        assert_eq!(
            fw.answer(
                id,
                &conn(""),
                Action::Allow,
                Duration::Always,
                copysnitch_common::Scope::Program
            ),
            Err(AnswerError::Unstorable)
        );
        assert!(matches!(fw.decide(&conn("/bin/y")), Step::Busy));
        fw.answer(
            id,
            &conn(""),
            Action::Deny,
            Duration::Once,
            copysnitch_common::Scope::Program,
        )
        .unwrap();
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 0);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_group_writable_directory_or_a_symlink_rule_is_refused() {
        let dir = private_dir();
        let mut perms = fs::metadata(&dir).unwrap().permissions();
        perms.set_mode(0o775);
        fs::set_permissions(&dir, perms).unwrap();
        assert_eq!(
            Firewall::load(&dir).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        let _ = fs::remove_dir_all(&dir);

        let dir = private_dir();
        std::os::unix::fs::symlink("anywhere", dir.join("curl")).unwrap();
        assert_eq!(
            Firewall::load(&dir).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        let _ = fs::remove_dir_all(dir);
    }
}
