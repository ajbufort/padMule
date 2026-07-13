# Wave 3b: mule-engine login-handshake message codecs - Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development or superpowers:executing-plans. Steps use `- [ ]`.

**Goal:** Create the `mule-engine` crate and the PURE (no-networking) codecs for the server login handshake: build `OP_LOGINREQUEST`, parse `OP_IDCHANGE`, `OP_SERVERMESSAGE`, `OP_SERVERSTATUS`. Testable entirely offline with golden bytes before any socket (Wave 3c adds tokio).

**Architecture:** New workspace crate `mule-engine` depending on `mule-proto`. Module `server_messages` holds message structs + `build_*`/`parse_*` functions over `mule_proto::{Packet, Reader, Writer, write_tag, Tag}`. No tokio yet.

**Tech Stack:** Rust 1.96, `mule-proto`, `hex` (dev).

**Grounding** (ServerConnect.cpp:210-259 login; ServerSocket.cpp:228-320 IDCHANGE; [[protocol-understanding]] Part 1):
- `OP_LOGINREQUEST` = 0x01, protocol 0xE3. Payload: `userhash(16)`, `clientID u32` (0 at login), `TCP port u16`, `tagcount u32 = 4`, then 4 tags in verbose (WriteTagToFile) form:
  - CT_NAME (0x01) STRING = nick
  - CT_VERSION (0x11) UINT32 = EDONKEYVERSION 0x3C
  - CT_SERVER_FLAGS (0x20) UINT32 = capability bitmask
  - CT_EMULE_VERSION (0xFB) UINT32 = (SO_AMULE<<24) | make_full_ed2k_version(3,0,1)
- Constants: SRVCAP_ZLIB 0x0001, SRVCAP_AUXPORT 0x0004, SRVCAP_NEWTAGS 0x0008, SRVCAP_UNICODE 0x0010, SRVCAP_LARGEFILES 0x0100 (crypt bits SUPPORT 0x0200 / REQUEST 0x0400 / REQUIRE 0x0800 - OFF for the v1 baseline, obfuscation is Wave 5). SO_AMULE=3. `make_full_ed2k_version(a,b,c) = (a<<17)|(b<<10)|(c<<7)`. So default flags (no crypt) = 0x011D; CT_EMULE_VERSION value = (3<<24)|((3<<17)|(0<<10)|(1<<7)) = 0x03060080.
- `OP_IDCHANGE` = 0x40. Size-tiered payload: `new_id u32` (required); if size>=8 `tcp_flags u32`; if size>=12 `standard_port u32`; if size>=20 `reported_ip u32` + `obfuscation_tcp_port u32`. `new_id == 0` means the server REJECTED the login (disconnect). `IsLowID(id) = id < 16777216`.
- `OP_SERVERMESSAGE` = 0x38: `u16 len + text bytes` (UTF-8 or Latin-1).
- `OP_SERVERSTATUS` = 0x34: `u32 users`, `u32 files`.

**padMule note:** the tags use the verbose form -> `mule_proto::write_tag` (which emits exactly that). Never advertise VBT (per [[protocol-understanding]]); we simply do not set that bit anywhere.

**Toolchain:** `source "$HOME/.cargo/env"` before every cargo call.

---

## File structure

- Modify: `Cargo.toml` (workspace) - add `crates/mule-engine` to members.
- Create: `crates/mule-engine/Cargo.toml` (dep mule-proto; dev hex).
- Create: `crates/mule-engine/src/lib.rs` (re-exports).
- Create: `crates/mule-engine/src/server_messages.rs`.

## Data model

```rust
pub struct LoginRequest { pub user_hash: [u8;16], pub client_id: u32, pub tcp_port: u16, pub nick: String, pub server_flags: u32 }
pub struct IdChange { pub new_id: u32, pub tcp_flags: Option<u32>, pub standard_port: Option<u32>, pub reported_ip: Option<u32>, pub obfuscation_tcp_port: Option<u32> }
// consts: OP_LOGINREQUEST 0x01, OP_IDCHANGE 0x40, OP_SERVERMESSAGE 0x38, OP_SERVERSTATUS 0x34,
//         CT_NAME 0x01, CT_VERSION 0x11, CT_SERVER_FLAGS 0x20, CT_EMULE_VERSION 0xFB,
//         EDONKEYVERSION 0x3C, EMULE_VERSION_TAG 0x03060080, DEFAULT_SERVER_FLAGS 0x011D,
//         SRVCAP_* bits, HIGHEST_LOWID 16_777_216
```

## Tasks (TDD)

### Task 1: crate skeleton + build_login_request
- Add `mule-engine` to the workspace; crate depends on `mule-proto`.
- `build_login_request(req: &LoginRequest) -> Packet`: write userhash, client_id (u32), tcp_port (u16), tagcount (u32=4), then the 4 tags via `write_tag`; wrap in `Packet::new(PROT_EDONKEY, OP_LOGINREQUEST, payload)`.
- `is_low_id(id: u32) -> bool = id < HIGHEST_LOWID`.
- Tests: a golden login (fixed userhash, nick "a", port 4662, id 0, flags DEFAULT_SERVER_FLAGS) produces the exact payload bytes (spell them out); the packet protocol/opcode are correct; `build -> write_packet -> read_packet` round-trips to an equal Packet; assert EMULE_VERSION_TAG == 0x03060080 and DEFAULT_SERVER_FLAGS == 0x011D.

### Task 2: parse_id_change + parse_server_message + parse_server_status
- `parse_id_change(payload: &[u8]) -> Result<IdChange, IoError>`: new_id required; optional fields by length tier (8/12/20); shorter-than-4 -> UnexpectedEof.
- `IdChange::is_rejected(&self) -> bool` (new_id == 0); `IdChange::is_low_id(&self) -> bool`.
- `parse_server_message(payload) -> Result<String, IoError>` (u16 len + bytes, from_utf8_lossy).
- `parse_server_status(payload) -> Result<(u32,u32), IoError>` (users, files).
- Tests: IDCHANGE with just new_id (4 bytes) -> only new_id set; full 20-byte IDCHANGE -> all fields; a HighID (>=16M) and a LowID (<16M) classify correctly; new_id=0 -> is_rejected; server message golden; server status golden; a truncated IDCHANGE (<4) -> Err.
- Gate: `cargo test -p mule-engine`, clippy, `cargo fmt --check`.

## Golden login payload (Task 1)

```
<userhash 16 bytes: 00..0F>
00 00 00 00                    client_id = 0
36 12                          tcp_port = 4662 (0x1236)
04 00 00 00                    tagcount = 4
02 01 00 01 01 00 61           CT_NAME(0x01) STRING "a"
03 01 00 11 3C 00 00 00        CT_VERSION(0x11) UINT32 0x3C
03 01 00 20 1D 01 00 00        CT_SERVER_FLAGS(0x20) UINT32 0x011D
03 01 00 FB 80 00 06 03        CT_EMULE_VERSION(0xFB) UINT32 0x03060080
```

## Self-review checklist
- Spec coverage: the login-handshake slice of Wave 3b. Search (OP_SEARCHREQUEST + expression) and OP_SERVERIDENT/OP_SERVERLIST are follow-on slices.
- Placeholder scan: implement fully.
- Type consistency: `build_login_request(&LoginRequest)->Packet`, `parse_id_change(&[u8])->Result<IdChange,IoError>`, `parse_server_message(&[u8])->Result<String,IoError>`, `parse_server_status(&[u8])->Result<(u32,u32),IoError>`.
- Baseline choice: crypt OFF (DEFAULT_SERVER_FLAGS 0x011D) until Wave 5; VBT never advertised.
