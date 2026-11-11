# copysnitch

A Linux application firewall, alpha `0.1.0-alpha.3`. When a program opens an outbound connection, name that program and ask whether to allow it.

Linux x86_64. MIT license. A release build produces `copysnitchd` and `copysnitch-ui`.

A push and a pull request build those two programs. A GitHub release attaches `copysnitchd-linux-x86_64` and `copysnitch-ui-linux-x86_64`. The UI executable needs the system GTK 4 library.

[OpenSnitch](https://github.com/evilsocket/opensnitch) is the existing tool in this category. Its daemon is Go, its interface is Python and PyQt6, and its process monitor is eBPF. copysnitch is a new implementation of that job, in one systems language, with no Node and no Python.

## Language

Rust.

The daemon runs as root and parses kernel events. That path has to be memory-safe.

One language covers the three places the program has to reach:

- nftables and netlink, for the queue that holds a new connection until a rule answers
- eBPF, for tying a socket to a process, written and loaded with [aya](https://github.com/aya-rs/aya)
- the desktop prompt, written with gtk4-rs against the system GTK 4 library

GTK is a system library, in the same class as libc. The prompt should look like a desktop dialog.

C stays available for an eBPF probe when a helper is only exposed that way. The daemon, the rule engine, and the UI stay in Rust. The bpf target and bpf-linker are compilers used at build time.

C++ and Qt would match a KDE desktop more closely, and would leave the root daemon without a borrow checker. Go is the language OpenSnitch's daemon is already written in, and the Python UI is the runtime this project leaves behind. Zig's eBPF and desktop libraries are too thin for this job.

The UI crate is the piece to replace if the GTK prompt is wrong on a given desktop. The daemon stays Rust.

## Layout

| Crate | Role |
| --- | --- |
| `crates/copysnitchd` | Root daemon. Owns interception and the decision. |
| `crates/copysnitch-ui` | User session. Main window and the allow or deny prompt. |
| `crates/copysnitch-common` | Rule types and the socket messages both sides share. |

The UI talks to the daemon on a Unix socket. The daemon checks the peer credentials of that socket. The prompt process does not run as root.

The shape of the decision comes from the small application firewalls: simplewall's per-program allow list and default deny, ZoneAlarm's split between the local network and the internet and between a client and a server, and the learning prompt those tools shared with Tiny Firewall. An answer remembers the program and the direction. A rule file can also name the zone. An outbound allow is not a server right.

OpenSnitch is GPL-3. Keep its sources out of this tree. This is a clean implementation of the same kind of tool.

## Run

Rust 1.85 or newer (edition 2024).

```sh
mkdir -m 0700 -p "${XDG_RUNTIME_DIR:-$HOME/.cache}/copysnitch" "$HOME/.config/copysnitch/rules"
cargo run -p copysnitchd -- \
  --rules "$HOME/.config/copysnitch/rules" \
  --socket "${XDG_RUNTIME_DIR:-$HOME/.cache}/copysnitch/copysnitch.sock"
```

In another terminal the GTK window opens. It lists connections, programs, zones, and rules. A prompt opens on top when a program needs an answer:

```sh
cargo run -p copysnitch-ui -- \
  --socket "${XDG_RUNTIME_DIR:-$HOME/.cache}/copysnitch/copysnitch.sock"
```

The rules directory and the socket's parent must be owned by the daemon's user and not writable by group or other. The socket itself is mode 0666. Only `--allow-uid` (the daemon's own uid, unless you set it) may connect. A root daemon that should prompt a desktop user needs a directory such as `/run/copysnitch` mode 0755 and `--allow-uid` set to that user.

Paste a connection on the daemon's stdin. A line may be tab-separated fields, or `packet in` / `packet out` and the hex of an IP packet, which is named from `/proc` on that machine. Bare `packet` is outbound:

```text
/usr/bin/curl	curl https://example.com	1000	tcp	example.com	93.184.216.34	443	outbound
```

The UI prints the program, the direction, and the zone. Answer with `allow once`, `deny session`, or `allow always`. Add `zone` (`allow always zone`) to remember only that zone: an internet allow does not cover the LAN. Add `command` (`allow session command`) to remember the exact command line, so one Python script does not allow another. A stored answer also remembers the user id and the protocol from the prompt, so one user's allow does not cover another user, and a TCP allow does not cover UDP. Type `forget curl` to remove a saved rule by its file name. A symlink is not removed. An answer that stores a rule prints `saved` and that file name. Type `rules` to list them. `once` covers that connection. `session` lasts until the daemon exits. `always` is written under the rules directory. No answer before `--timeout-secs` (default 30) denies it. Ctrl-D stops the daemon.

A rule file is one safe file name per rule:

```text
action allow
duration always
direction outbound
process.path /usr/bin/curl
zone trusted
```

`zone trusted` is loopback, private LAN, link-local, and IPv6 unique-local. Other addresses are `internet`. `direction inbound` is a program accepting a connection.

`copysnitchd --print-ruleset` prints the nftables ruleset for a guest. It queues new inbound and outbound connections and accepts them if the daemon is not running, so a stopped daemon does not black-hole the machine. An inbound packet is named after the listening program. Its peer address is the other end, and the port is the local service port. `--queue N` binds that queue and answers it. It does not install the ruleset. The queue fails open if the daemon exits. Neither is applied on the development host. Real interception belongs in the guest.

An `always` or `session` answer records the SHA-256 of the program file when that file can be read. If the file changes, the rule no longer matches and the program is asked again.

A queued packet is named from its headers and from a proc tree: the socket inode in `net/tcp` is matched to `/proc/<pid>/fd`. The development daemon still takes those connections from stdin. There is no eBPF attribution and no system tray. The window is the connection list, the program counts, the trusted and internet zones, and the rules.
