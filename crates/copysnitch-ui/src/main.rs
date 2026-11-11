use std::cell::RefCell;
use std::env;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::process::ExitCode;
use std::rc::Rc;

use copysnitch_common::{
    ClientMessage, Duration, Scope, ServerMessage, format_client_message, parse_server_message,
};
use copysnitch_ui::{decision_zone, program_name, prompt_text, window_answer};
use gtk4::prelude::*;
use gtk4::{
    Application, ApplicationWindow, Box, Button, CheckButton, Label, ListBox, Orientation,
    ScrolledWindow,
};

const LOG_LIMIT: usize = 400;

fn main() -> ExitCode {
    match run(env::args().skip(1)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("copysnitch-ui: {error}");
            ExitCode::from(1)
        }
    }
}

fn run(args: impl Iterator<Item = String>) -> io::Result<()> {
    let socket = socket_path(args)?;
    let stream = UnixStream::connect(&socket)?;
    let app = Application::builder()
        .application_id("com.github.tpqwz.copysnitch")
        .build();
    app.connect_activate(move |app| {
        let hold = app.hold();
        if let Err(error) = attach(app.clone(), hold, stream.try_clone().expect("socket")) {
            eprintln!("copysnitch-ui: {error}");
            app.quit();
        }
    });
    app.run_with_args::<&str>(&[]);
    Ok(())
}

fn socket_path(args: impl Iterator<Item = String>) -> io::Result<String> {
    let mut socket = None;
    let mut args = args;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--socket" => {
                socket = Some(args.next().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "missing value for --socket")
                })?);
            }
            "--help" | "-h" => {
                println!("usage: copysnitch-ui --socket PATH");
                std::process::exit(0);
            }
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unknown argument {other}"),
                ));
            }
        }
    }
    socket.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: copysnitch-ui --socket PATH",
        )
    })
}

struct Logged {
    action: String,
    because: String,
    path: String,
    detail: String,
    command: String,
}

struct Session {
    read: UnixStream,
    write: UnixStream,
    buf: Vec<u8>,
    app: Application,
    window: ApplicationWindow,
    events: ListBox,
    programs: ListBox,
    zones: ListBox,
    rules: ListBox,
    log: Vec<Logged>,
    rule_count: usize,
    asking: Label,
    status: Label,
    _hold: gtk4::gio::ApplicationHoldGuard,
}

struct Shell {
    window: ApplicationWindow,
    events: ListBox,
    programs: ListBox,
    zones: ListBox,
    rules: ListBox,
    asking: Label,
    status: Label,
}

fn attach(
    app: Application,
    hold: gtk4::gio::ApplicationHoldGuard,
    stream: UnixStream,
) -> io::Result<()> {
    let read = stream.try_clone()?;
    read.set_nonblocking(true)?;
    let shell = main_window(&app, stream.try_clone()?);
    let session = Rc::new(RefCell::new(Session {
        read,
        write: stream,
        buf: Vec::new(),
        app: app.clone(),
        window: shell.window,
        events: shell.events,
        programs: shell.programs,
        zones: shell.zones,
        rules: shell.rules,
        log: Vec::new(),
        rule_count: 0,
        asking: shell.asking,
        status: shell.status,
        _hold: hold,
    }));
    refresh_rules(&mut session.borrow_mut())?;
    let fd = session.borrow().read.as_raw_fd();
    let session_for_fd = session.clone();
    gtk4::glib::unix_fd_add_local(
        fd,
        gtk4::glib::IOCondition::IN | gtk4::glib::IOCondition::HUP,
        move |_fd, condition| {
            let mut session = session_for_fd.borrow_mut();
            if condition.contains(gtk4::glib::IOCondition::HUP)
                && !condition.contains(gtk4::glib::IOCondition::IN)
            {
                session.app.quit();
                return gtk4::glib::ControlFlow::Break;
            }
            match pump(&mut session) {
                Ok(true) => gtk4::glib::ControlFlow::Continue,
                Ok(false) => {
                    session.app.quit();
                    gtk4::glib::ControlFlow::Break
                }
                Err(error) => {
                    eprintln!("copysnitch-ui: {error}");
                    session.app.quit();
                    gtk4::glib::ControlFlow::Break
                }
            }
        },
    );
    Ok(())
}

/// Returns false when the daemon hangs up.
fn pump(session: &mut Session) -> io::Result<bool> {
    let mut tmp = [0u8; 1024];
    loop {
        match session.read.read(&mut tmp) {
            Ok(0) => return Ok(false),
            Ok(n) => session.buf.extend_from_slice(&tmp[..n]),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    while let Some(pos) = session.buf.iter().position(|byte| *byte == b'\n') {
        let raw: Vec<u8> = session.buf.drain(..=pos).collect();
        let Ok(text) = std::str::from_utf8(&raw[..raw.len() - 1]) else {
            eprintln!("copysnitch-ui: ignored a daemon line");
            continue;
        };
        handle_line(session, text.trim_end_matches('\r'))?;
    }
    Ok(true)
}

fn handle_line(session: &mut Session, line: &str) -> io::Result<()> {
    match parse_server_message(line) {
        Ok(ServerMessage::Prompt { id, connection }) => {
            let text = prompt_text(&connection);
            let first = text.lines().next().unwrap_or("A program is waiting");
            session.asking.set_text(&format!("Asking now — {first}"));
            session.asking.set_visible(true);
            let writer = session.write.try_clone()?;
            present(&session.app, &session.window, writer, id, text);
        }
        Ok(ServerMessage::Denied) => eprintln!("copysnitch-ui: daemon refused this user"),
        Ok(ServerMessage::Busy) => eprintln!("copysnitch-ui: another prompt is already connected"),
        Ok(ServerMessage::BadRequest) => eprintln!("copysnitch-ui: daemon rejected that answer"),
        Ok(ServerMessage::Rejected) => eprintln!("copysnitch-ui: that answer was not stored"),
        Ok(ServerMessage::Forgotten) | Ok(ServerMessage::Stored { .. }) => {
            refresh_rules(session)?;
        }
        Ok(ServerMessage::Rule { name, summary }) => {
            add_rule_row(&session.rules, &name, &summary);
            session.rule_count += 1;
        }
        Ok(ServerMessage::RulesEnd) => {
            if session.rule_count == 0 {
                add_note(
                    &session.rules,
                    "No rules yet. Choose always on a prompt to keep one.",
                );
            }
            paint_status(session);
        }
        Ok(ServerMessage::Decision {
            action,
            because,
            path,
            detail,
            command,
        }) => {
            session.asking.set_visible(false);
            let action = match action {
                copysnitch_common::Action::Allow => "allow",
                copysnitch_common::Action::Deny => "deny",
            };
            session.log.insert(
                0,
                Logged {
                    action: action.to_string(),
                    because,
                    path,
                    detail,
                    command,
                },
            );
            if session.log.len() > LOG_LIMIT {
                session.log.truncate(LOG_LIMIT);
            }
            refill_events(&session.events, &session.log);
            refill_programs(&session.programs, &session.log);
            refill_zones(&session.zones, &session.log);
            paint_status(session);
        }
        Err(_) => eprintln!("copysnitch-ui: ignored a daemon line"),
    }
    Ok(())
}

fn main_window(app: &Application, writer: UnixStream) -> Shell {
    install_css();
    let window = ApplicationWindow::builder()
        .application(app)
        .title("copysnitch")
        .default_width(960)
        .default_height(640)
        .build();

    let title = Label::new(Some("copysnitch"));
    title.add_css_class("title");
    let subtitle = Label::new(Some("Application firewall"));
    subtitle.add_css_class("subtitle");
    subtitle.add_css_class("dim");
    let titles = Box::new(Orientation::Vertical, 0);
    titles.append(&title);
    titles.append(&subtitle);
    let bar = gtk4::HeaderBar::new();
    bar.set_title_widget(Some(&titles));
    window.set_titlebar(Some(&bar));

    let root = Box::new(Orientation::Vertical, 8);
    root.set_margin_top(12);
    root.set_margin_bottom(12);
    root.set_margin_start(12);
    root.set_margin_end(12);

    let blurb = Label::new(Some(
        "New programs ask first. Once covers that connection. Session lasts until the daemon exits. Always is saved as a rule. Trusted is the local network. Everything else is the internet.",
    ));
    blurb.set_xalign(0.0);
    blurb.set_wrap(true);
    blurb.add_css_class("dim");
    root.append(&blurb);

    let asking = Label::new(None);
    asking.set_xalign(0.0);
    asking.set_wrap(true);
    asking.add_css_class("decision-ask");
    asking.set_visible(false);
    root.append(&asking);

    let events = list_box(false);
    let programs = list_box(false);
    let zones = list_box(false);
    let rules = list_box(true);

    let events_scroll = scroll(&events);
    let connections = page("Newest decision first.", &events_scroll);
    let intro = connections
        .first_child()
        .expect("the page intro is the first child");
    connections.insert_child_after(&column_head(), Some(&intro));
    let programs_page = page(
        "Each program that has been allowed or denied in this session.",
        &scroll(&programs),
    );
    let zones_page = page(
        "Trusted is loopback, private LAN, and link-local. Other addresses are the internet.",
        &scroll(&zones),
    );
    let rules_page = page(
        "Saved and session rules. Remove deletes the selected rule. A symlink is left in place.",
        &scroll(&rules),
    );
    let remove = Button::with_label("Remove selected rule");
    remove.add_css_class("destructive-action");
    rules_page.append(&remove);

    let notebook = gtk4::Notebook::new();
    notebook.set_vexpand(true);
    notebook.append_page(
        &connections,
        Some(&tab("network-transmit-symbolic", "Connections")),
    );
    notebook.append_page(
        &programs_page,
        Some(&tab("application-x-executable-symbolic", "Programs")),
    );
    notebook.append_page(
        &zones_page,
        Some(&tab("network-workgroup-symbolic", "Zones")),
    );
    notebook.append_page(&rules_page, Some(&tab("security-high-symbolic", "Rules")));
    root.append(&notebook);

    let status = Label::new(Some("Connected. Waiting for the rule list."));
    status.set_xalign(0.0);
    status.add_css_class("dim");
    root.append(&status);
    window.set_child(Some(&root));

    refill_events(&events, &[]);
    refill_programs(&programs, &[]);
    refill_zones(&zones, &[]);

    let rules_for_button = rules.clone();
    let writer = Rc::new(RefCell::new(writer));
    remove.connect_clicked(move |_| {
        let Some(row) = rules_for_button.selected_row() else {
            return;
        };
        let Some(name) = row.tooltip_text() else {
            return;
        };
        if let Ok(encoded) = format_client_message(&ClientMessage::Forget {
            name: name.to_string(),
        }) {
            let _ = writer.borrow_mut().write_all(encoded.as_bytes());
        }
    });

    window.present();
    Shell {
        window,
        events,
        programs,
        zones,
        rules,
        asking,
        status,
    }
}

fn install_css() {
    let Some(display) = gtk4::gdk::Display::default() else {
        return;
    };
    let provider = gtk4::CssProvider::new();
    provider.load_from_data(
        "label.decision-allow { color: #1a7f37; font-weight: 700; }
         label.decision-deny { color: #c41a16; font-weight: 700; }
         label.decision-ask { color: #9a6700; font-weight: 700; }
         label.dim { opacity: 0.72; }",
    );
    gtk4::style_context_add_provider_for_display(
        &display,
        &provider,
        gtk4::STYLE_PROVIDER_PRIORITY_APPLICATION,
    );
}

fn tab(icon: &str, text: &str) -> Box {
    let row = Box::new(Orientation::Horizontal, 6);
    row.append(&gtk4::Image::from_icon_name(icon));
    row.append(&Label::new(Some(text)));
    row
}

fn list_box(selectable: bool) -> ListBox {
    let list = ListBox::new();
    list.set_vexpand(true);
    list.set_show_separators(true);
    list.set_selection_mode(if selectable {
        gtk4::SelectionMode::Single
    } else {
        gtk4::SelectionMode::None
    });
    list
}

fn scroll(child: &ListBox) -> ScrolledWindow {
    let scrolled = ScrolledWindow::new();
    scrolled.set_child(Some(child));
    scrolled.set_vexpand(true);
    scrolled.set_min_content_height(280);
    scrolled.set_policy(gtk4::PolicyType::Never, gtk4::PolicyType::Automatic);
    scrolled
}

fn page(intro: &str, body: &ScrolledWindow) -> Box {
    let page = Box::new(Orientation::Vertical, 8);
    page.set_margin_top(8);
    let label = Label::new(Some(intro));
    label.set_xalign(0.0);
    label.set_wrap(true);
    label.add_css_class("dim");
    page.append(&label);
    page.append(body);
    page
}

fn column_head() -> Box {
    let row = Box::new(Orientation::Horizontal, 12);
    row.set_margin_start(8);
    row.set_margin_end(8);
    for (text, width) in [("action", 8), ("program", 16), ("destination", 0)] {
        let label = Label::new(Some(text));
        label.add_css_class("dim");
        label.set_xalign(0.0);
        if width > 0 {
            label.set_width_chars(width);
        } else {
            label.set_hexpand(true);
        }
        row.append(&label);
    }
    row
}

fn clear_list(list: &ListBox) {
    while let Some(child) = list.first_child() {
        list.remove(&child);
    }
}

fn add_note(list: &ListBox, text: &str) {
    let label = Label::new(Some(text));
    label.set_xalign(0.0);
    label.set_wrap(true);
    label.add_css_class("dim");
    label.set_margin_top(8);
    label.set_margin_bottom(8);
    label.set_margin_start(8);
    label.set_margin_end(8);
    list.append(&label);
}

fn refill_events(list: &ListBox, log: &[Logged]) {
    clear_list(list);
    if log.is_empty() {
        add_note(list, "No connection has been decided yet.");
        return;
    }
    for event in log {
        list.append(&event_row(event));
    }
}

fn event_row(event: &Logged) -> gtk4::ListBoxRow {
    let top = Box::new(Orientation::Horizontal, 12);
    let action = Label::new(Some(&event.action));
    action.add_css_class(if event.action == "allow" {
        "decision-allow"
    } else {
        "decision-deny"
    });
    action.set_width_chars(8);
    action.set_xalign(0.0);
    let program = Label::new(Some(program_name(&event.path)));
    program.add_css_class("heading");
    program.set_width_chars(16);
    program.set_xalign(0.0);
    program.set_ellipsize(gtk4::pango::EllipsizeMode::End);
    let detail = Label::new(Some(&event.detail));
    detail.set_xalign(0.0);
    detail.set_hexpand(true);
    detail.set_ellipsize(gtk4::pango::EllipsizeMode::Start);
    top.append(&action);
    top.append(&program);
    top.append(&detail);

    let meta = if event.command.is_empty() {
        format!("{}    {}", event.path, event.because)
    } else {
        format!("{}    {}    {}", event.path, event.because, event.command)
    };
    let below = Label::new(Some(&meta));
    below.set_xalign(0.0);
    below.add_css_class("dim");
    below.set_wrap(true);

    let body = Box::new(Orientation::Vertical, 2);
    body.set_margin_top(6);
    body.set_margin_bottom(6);
    body.set_margin_start(8);
    body.set_margin_end(8);
    body.append(&top);
    body.append(&below);
    let row = gtk4::ListBoxRow::new();
    row.set_child(Some(&body));
    row
}

fn refill_programs(list: &ListBox, log: &[Logged]) {
    clear_list(list);
    if log.is_empty() {
        add_note(list, "No program has been decided yet.");
        return;
    }
    let mut seen: Vec<&str> = Vec::new();
    for event in log {
        if !seen.contains(&event.path.as_str()) {
            seen.push(event.path.as_str());
        }
    }
    seen.sort_by(|left, right| {
        let count = |path: &str| log.iter().filter(|event| event.path == path).count();
        count(right).cmp(&count(left)).then(left.cmp(right))
    });
    for path in seen {
        let allowed = log
            .iter()
            .filter(|event| event.path == path && event.action == "allow")
            .count();
        let denied = log
            .iter()
            .filter(|event| event.path == path && event.action == "deny")
            .count();
        let last = log
            .iter()
            .find(|event| event.path == path)
            .map(|event| event.detail.as_str())
            .unwrap_or("");
        list.append(&program_row(path, allowed, denied, last));
    }
}

fn program_row(path: &str, allowed: usize, denied: usize, last: &str) -> gtk4::ListBoxRow {
    let name = Label::new(Some(program_name(path)));
    name.add_css_class("heading");
    name.set_xalign(0.0);
    name.set_hexpand(true);
    let counts = Label::new(Some(&format!("{allowed} allowed · {denied} denied")));
    counts.set_xalign(1.0);
    let top = Box::new(Orientation::Horizontal, 12);
    top.append(&name);
    top.append(&counts);
    let below = Label::new(Some(&format!("{path}    last {last}")));
    below.set_xalign(0.0);
    below.set_wrap(true);
    below.add_css_class("dim");
    let body = Box::new(Orientation::Vertical, 2);
    body.set_margin_top(6);
    body.set_margin_bottom(6);
    body.set_margin_start(8);
    body.set_margin_end(8);
    body.append(&top);
    body.append(&below);
    let row = gtk4::ListBoxRow::new();
    row.set_child(Some(&body));
    row
}

fn refill_zones(list: &ListBox, log: &[Logged]) {
    clear_list(list);
    for zone in ["internet", "trusted"] {
        let heading = Label::new(Some(zone));
        heading.add_css_class("heading");
        heading.set_xalign(0.0);
        heading.set_margin_top(8);
        heading.set_margin_start(8);
        list.append(&heading);
        let mut any = false;
        for event in log {
            if decision_zone(&event.detail) == Some(zone) {
                list.append(&event_row(event));
                any = true;
            }
        }
        if !any {
            add_note(
                list,
                if zone == "internet" {
                    "No internet decision yet."
                } else {
                    "No trusted-network decision yet."
                },
            );
        }
    }
    let other: Vec<&Logged> = log
        .iter()
        .filter(|event| decision_zone(&event.detail).is_none())
        .collect();
    if !other.is_empty() {
        let heading = Label::new(Some("unparsed"));
        heading.add_css_class("heading");
        heading.set_xalign(0.0);
        heading.set_margin_top(8);
        heading.set_margin_start(8);
        list.append(&heading);
        for event in other {
            list.append(&event_row(event));
        }
    }
}

fn add_rule_row(list: &ListBox, name: &str, summary: &str) {
    let title = Label::new(Some(name));
    title.add_css_class("heading");
    title.set_xalign(0.0);
    let detail = Label::new(Some(summary));
    detail.set_xalign(0.0);
    detail.set_wrap(true);
    detail.add_css_class("dim");
    let body = Box::new(Orientation::Vertical, 2);
    body.set_margin_top(6);
    body.set_margin_bottom(6);
    body.set_margin_start(8);
    body.set_margin_end(8);
    body.append(&title);
    body.append(&detail);
    let row = gtk4::ListBoxRow::new();
    row.set_child(Some(&body));
    row.set_tooltip_text(Some(name));
    list.append(&row);
}

fn refresh_rules(session: &mut Session) -> io::Result<()> {
    clear_list(&session.rules);
    session.rule_count = 0;
    let encoded = format_client_message(&ClientMessage::List)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "list"))?;
    session.write.write_all(encoded.as_bytes())?;
    Ok(())
}

fn paint_status(session: &Session) {
    let allowed = session
        .log
        .iter()
        .filter(|event| event.action == "allow")
        .count();
    let denied = session
        .log
        .iter()
        .filter(|event| event.action == "deny")
        .count();
    let mut programs: Vec<&str> = Vec::new();
    for event in &session.log {
        if !programs.contains(&event.path.as_str()) {
            programs.push(event.path.as_str());
        }
    }
    session.status.set_text(&format!(
        "{} decisions · {allowed} allowed · {denied} denied · {} programs · {} rules",
        session.log.len(),
        programs.len(),
        session.rule_count,
    ));
}

fn present(
    app: &Application,
    parent: &ApplicationWindow,
    writer: UnixStream,
    id: u64,
    text: String,
) {
    let window = ApplicationWindow::builder()
        .application(app)
        .title("Allow this connection?")
        .default_width(520)
        .build();
    window.set_transient_for(Some(parent));
    window.set_modal(true);
    window.set_destroy_with_parent(true);

    let root = Box::new(Orientation::Vertical, 8);
    root.set_margin_top(12);
    root.set_margin_bottom(12);
    root.set_margin_start(12);
    root.set_margin_end(12);

    let heading = Label::new(Some("A program wants to use the network"));
    heading.add_css_class("title-2");
    heading.set_xalign(0.0);
    heading.set_wrap(true);
    root.append(&heading);

    let label = Label::new(Some(&text));
    label.set_wrap(true);
    label.set_xalign(0.0);
    label.set_selectable(true);
    root.append(&label);

    let once = CheckButton::with_label("once");
    once.set_active(true);
    let session = CheckButton::with_label("session");
    session.set_group(Some(&once));
    let always = CheckButton::with_label("always");
    always.set_group(Some(&once));
    let durations = Box::new(Orientation::Horizontal, 8);
    durations.append(&once);
    durations.append(&session);
    durations.append(&always);
    root.append(&durations);

    let program = CheckButton::with_label("this program");
    program.set_active(true);
    let zone = CheckButton::with_label("this zone");
    zone.set_group(Some(&program));
    let command = CheckButton::with_label("this command");
    command.set_group(Some(&program));
    let scopes = Box::new(Orientation::Horizontal, 8);
    scopes.append(&program);
    scopes.append(&zone);
    scopes.append(&command);
    root.append(&scopes);

    let zone_toggle = zone.clone();
    let command_toggle = command.clone();
    let program_toggle = program.clone();
    once.connect_toggled(move |button| {
        let wider = !button.is_active();
        zone_toggle.set_sensitive(wider);
        command_toggle.set_sensitive(wider);
        if button.is_active() {
            program_toggle.set_active(true);
        }
    });

    let buttons = Box::new(Orientation::Horizontal, 8);
    buttons.set_halign(gtk4::Align::End);
    let allow = Button::with_label("Allow");
    allow.add_css_class("suggested-action");
    let deny = Button::with_label("Deny");
    deny.add_css_class("destructive-action");
    buttons.append(&deny);
    buttons.append(&allow);
    root.append(&buttons);
    window.set_child(Some(&root));
    window.set_default_widget(Some(&allow));

    let send = {
        let once = once.clone();
        let session = session.clone();
        let zone = zone.clone();
        let command = command.clone();
        let window = window.clone();
        let writer = Rc::new(RefCell::new(writer));
        move |allow_it: bool| {
            let duration = if session.is_active() {
                Duration::Session
            } else if once.is_active() {
                Duration::Once
            } else {
                Duration::Always
            };
            let scope = if command.is_active() {
                Scope::Command
            } else if zone.is_active() {
                Scope::Zone
            } else {
                Scope::Program
            };
            let (action, duration, scope) = window_answer(allow_it, duration, scope);
            if let Ok(encoded) = format_client_message(&ClientMessage::Answer {
                id,
                action,
                duration,
                scope,
            }) {
                let _ = writer.borrow_mut().write_all(encoded.as_bytes());
            }
            window.close();
        }
    };
    let allow_send = send.clone();
    allow.connect_clicked(move |_| allow_send(true));
    deny.connect_clicked(move |_| send(false));
    window.present();
}
