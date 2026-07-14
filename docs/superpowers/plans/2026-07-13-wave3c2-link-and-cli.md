# Wave 3c-2: pause/resume ServerLink + live CLI smoke - Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development or superpowers:executing-plans. Steps use `- [ ]`.

**Goal:** Add the `ServerLink` lifecycle manager (connect / pause / resume over a real socket, honest state events) and a `mule-cli` harness that logs into a live eD2k server. This is the first time padMule's code touches the real network.

**Architecture:** `ServerLink` in `mule-engine` owns the current `FramedStream<TcpStream>` and drives connect/pause/resume, emitting `ServerEvent::State`. Tested against a local `TcpListener` mock server (real socket path, deterministic). `mule-cli` is a bin crate that runs `ServerLink` (or raw connect+handshake) against a given server or every server in a `server.met`.

**Tech Stack:** Rust 1.96, `mule-engine`, `mule-files`, `mule-proto`, `tokio`.

**Grounding:** [[lifecycle-and-reactivation]] (pause = drop socket -> PausedForBackground; resume = reconnect + re-handshake, idempotent). server.met IP is a u32 with the FIRST octet in the LOW byte ([[protocol-understanding]] 5.0): `Ipv4Addr::new(ip as u8, (ip>>8) as u8, (ip>>16) as u8, (ip>>24) as u8)` - NOT `Ipv4Addr::from(ip)` (that is big-endian).

**Toolchain:** `source "$HOME/.cargo/env"` before every cargo call.

---

## File structure

- Create: `crates/mule-engine/src/link.rs` - `ServerLink`.
- Modify: `crates/mule-engine/src/lib.rs` - `pub mod link;` + re-export.
- Modify: `Cargo.toml` (workspace) - add `crates/mule-cli`.
- Create: `crates/mule-cli/Cargo.toml`, `crates/mule-cli/src/main.rs`.

## Tasks (TDD + a live run)

### Task 1: ServerLink
- Fields: `addr`, `login`, `events: mpsc::Sender<ServerEvent>`, `conn: Option<FramedStream<TcpStream>>`, `state: ServerState`.
- `connect()`/`resume()` -> `establish()`: emit State(Connecting); `connect_server` + `login_handshake`; store the stream; on error emit State(Disconnected) and return Err.
- `pause()`: drop `conn` (closes the socket), emit State(PausedForBackground).
- `disconnect()`: drop `conn`, emit State(Disconnected).
- `state()`, `is_connected()`.
- Test (local `TcpListener` mock server that answers login with IDCHANGE HighID for EACH accepted connection): `connect()` -> Connected + conn.is_some(); `pause()` -> PausedForBackground + conn.is_none(); `resume()` -> Connected again; the event log is `[Connecting, Connected, PausedForBackground, Connecting, Connected]` (State events).
- Gate: `cargo test -p mule-engine`, clippy, `cargo fmt --check`.

### Task 2: mule-cli
- Bin `mule-cli` with subcommands:
  - `login <host> <port>` - resolve, `ServerLink::connect`, print state events + final result; then `pause`/`resume` once to demonstrate the lifecycle.
  - `login-any <server.met path>` - parse via `mule_files::read_server_met`, try each server with a per-server `timeout` (~8s) until one reaches Connected; print progress.
- Uses a fixed demo userhash with the eMule markers (byte[5]=14, byte[14]=111), nick "padMule", port 4662, DEFAULT_SERVER_FLAGS.
- Gate: `cargo build -p mule-cli`, clippy, fmt.

### Task 3: live run (manual, reported)
- Fetch a real `server.met` (curl to scratchpad). Run `mule-cli login-any <that file>`. Report the outcome (Connected HighID/LowID + server message/status, or all-unreachable). NOT part of the automated gate - servers are volatile and it needs outbound network.

## Self-review checklist
- Spec coverage: the pause/resume lifecycle manager + a live handshake harness (Wave 3c remainder).
- Placeholder scan: implement fully.
- Type consistency: `ServerLink::new(SocketAddr, LoginRequest, Sender<ServerEvent>)`, `connect/resume -> Result<ServerState, FrameError>`, `pause/disconnect -> ()`.
- server.met IP decode uses LE-octet construction, not `Ipv4Addr::from(u32)`.
