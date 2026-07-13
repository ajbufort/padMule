# Wave 2a: mule-files crate + byte-compatible server.met - Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development or superpowers:executing-plans. Steps use `- [ ]`.

**Goal:** Create the `mule-files` crate and a byte-compatible `server.met` reader/writer, proving the on-disk-format approach (round-trip through the `mule-proto` tag codec) end to end.

**Architecture:** New workspace crate `mule-files` depending on `mule-proto`. First module `server_met` parses and re-emits the eD2k server list. Records preserve exactly what was read (header byte, IP u32, port, tag list) so a read-then-write round-trips bit-for-bit.

**Tech Stack:** Rust 1.96, `mule-proto` (Reader/Writer/Tag), `hex` (dev).

**Grounding** (`docs/raw/amule-upstream-reference-2026-07-12.md` section 5, ServerList.cpp:94-197 load / 689-825 save):
- Header: `u8` = 0xE0 on write; load accepts 0xE0 OR 0x0E. Then `u32` server count. Per server: `u32` IP (stored verbatim, eMule byte convention - keep opaque), `u16` port, `u32` tagcount, then `tagcount` MET-format tags.
- Server tag ids (ServerTags.h): ST_SERVERNAME=0x01, ST_DESCRIPTION=0x0B, ST_PING=0x0C, ST_FAIL=0x0D, ST_PREFERENCE=0x0E, ST_DYNIP=0x85, ST_LASTPING=0x90, ST_VERSION=0x91, etc. (We preserve tags generically; ids are for callers.)
- Round-trip note: to be bit-identical we preserve the header byte AS READ (aMule always writes 0xE0 but accepts 0x0E). Archive unwrapping (server.met can arrive gzip/zip-wrapped from a URL, ServerList.cpp:106-111) is a SEPARATE higher-layer concern, not part of the raw-format codec.

**Toolchain:** `source "$HOME/.cargo/env"` before every cargo call.

---

## File structure

- Modify: `Cargo.toml` (workspace) - add `crates/mule-files` to members.
- Create: `crates/mule-files/Cargo.toml`.
- Create: `crates/mule-files/src/lib.rs` - crate root, re-exports.
- Create: `crates/mule-files/src/server_met.rs` - `Server`, `ServerMet`, `read_server_met`, `write_server_met`.

## Data model

```rust
pub struct Server { pub ip: u32, pub port: u16, pub tags: Vec<Tag> }
pub struct ServerMet { pub header: u8, pub servers: Vec<Server> }
```

## Tasks (TDD; each ends green + committed)

### Task 1: Crate skeleton
- Add `mule-files` to workspace members; crate manifest depends on `mule-proto` (path) and `hex` (dev).
- `lib.rs` declares `pub mod server_met;` and re-exports the public items.
- Gate: `cargo build` compiles the empty crate.

### Task 2: read_server_met
- `read_server_met(bytes: &[u8]) -> Result<ServerMet, IoError>`: read `u8` header (error `IoError::BadTag(h)` if not 0xE0/0x0E), `u32` count, then count servers (u32 ip, u16 port, u32 tagcount, tagcount `read_tag`).
- Tests: parse a hand-built golden byte vector (1 server, 1 ST_SERVERNAME string tag); assert the parsed struct and full consumption; a header-validation error test.
- Gate: `cargo test -p mule-files read_`.

### Task 3: write_server_met + round-trip
- `write_server_met(m: &ServerMet) -> Vec<u8>`: write header, u32 count, per server (ip, port, u32 tagcount, each `write_tag`).
- Tests: the golden vector writes back bit-identically; round-trip a 2-server list (one with several tags incl. a UINT32 and a string) and an empty list; confirm header byte preserved (build one with 0x0E, assert it round-trips as 0x0E).
- Gate: `cargo test -p mule-files` all green, `cargo clippy -p mule-files --all-targets -- -D warnings`, `cargo fmt --check`.

## Golden vector (Task 2/3)

```
E0                          header
01 00 00 00                 server count = 1
04 03 02 01                 ip   = 0x01020304 (stored verbatim)
35 12                       port = 0x1235
01 00 00 00                 tagcount = 1
02 01 00 01 04 00 65 44 32 4B   tag: STRING id=0x01 "eD2K"
```
Parsed: `ServerMet{ header:0xE0, servers:[ Server{ ip:0x01020304, port:0x1235,
tags:[ Tag::id(0x01, TagValue::Str(b"eD2K")) ] } ] }`.

## Self-review checklist
- Spec coverage: the server.met slice of Wave 2 (spec 10.2). known.met and part.met are follow-on plans (2b, 2c).
- Placeholder scan: implement fully.
- Type consistency: `read_server_met(&[u8]) -> Result<ServerMet, IoError>`, `write_server_met(&ServerMet) -> Vec<u8>`.
- Divergence: header byte preserved on round-trip (fidelity) rather than forced to 0xE0; archive unwrapping out of scope for the raw codec.
