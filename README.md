# copysnitch

A Linux application firewall. When a program opens an outbound connection, name that program and ask whether to allow it.

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
| `crates/copysnitch-ui` | User session. Tray icon and the allow or deny prompt. |
| `crates/copysnitch-common` | Rule types and the socket messages both sides share. |

The UI talks to the daemon on a Unix socket. The daemon checks the peer credentials of that socket. The prompt process does not run as root.

OpenSnitch is GPL-3. Keep its sources out of this tree. This is a clean implementation of the same kind of tool.

## Build

Rust 1.85 or newer (edition 2024).

```sh
cargo build
```

Nothing intercepts traffic yet. The crates record the language choice and the split between the root daemon and the user session.
