# Wave 3a: mule-proto packet framing (+zlib) - Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development or superpowers:executing-plans. Steps use `- [ ]`.

**Goal:** Add eD2k/eMule TCP packet framing to `mule-proto`: a streaming frame reader/writer and zlib pack/unpack. This is the last codec piece before the networked engine (Wave 3b+).

**Architecture:** New module `packet` in `mule-proto`. A `Packet` is `{protocol, opcode, payload}`. `read_packet` is a STREAMING parser (returns `Ok(None)` when the buffer holds an incomplete frame, so a socket read loop can call it repeatedly). `write_packet` serializes. `compress`/`decompress` handle the zlib-packed protocol variants. No I/O and no networking - pure codec.

**Tech Stack:** Rust 1.96, `flate2` (default miniz_oxide backend - pure Rust, iOS-safe), `hex` (dev).

**Grounding** (reference section 1-4; EMSocket.cpp, Packet.cpp:80-307, Protocols.h):
- 6-byte header: `[protocol u8][packetlength u32 LE][opcode u8][payload]`. `packetlength = 1 + payload_size` (includes the opcode byte). Total wire = 6 + payload_size.
- Valid protocol bytes: OP_EDONKEYPROT 0xE3, OP_EMULEPROT 0xC5, OP_PACKEDPROT 0xD4, OP_ED2KV2HEADER 0xF4, OP_ED2KV2PACKEDPROT 0xF5 (also 0xE4/0xE5 for Kad TCP-style, accepted). Unknown -> ERR_WRONGHEADER.
- `packetlength < 1` invalid; `payload_size > MAX_PACKET_SIZE (2_000_000)` -> ERR_TOOBIG.
- ZLIB pack (Packet.cpp:247-307): compress ONLY the payload (level 9); if the result is smaller, set protocol to OP_PACKEDPROT (0xD4), or OP_KADEMLIAPACKEDPROT (0xE5) if it was 0xE4, or OP_ED2KV2PACKEDPROT (0xF5) if 0xF4; else keep uncompressed. Unpack: valid only for 0xD4/0xF5/0xE5; inflate payload; protocol becomes 0xC5 (0xD4/0xF5 -> eMule-ext on a client link) or 0xE4 (0xE5 -> Kad). Decompress buffer cap = size*10+300, capped at a caller max (default 50000; server 250000).
- SPLIT packets are NOT real fragmentation - a "splitted" buffer is just concatenated frames; a reimplementation handles arbitrarily large single packets up to MAX_PACKET_SIZE and never emits multi-fragment packets.

**Toolchain:** `source "$HOME/.cargo/env"` before every cargo call.

---

## File structure

- Modify: `Cargo.toml` (workspace) - add `flate2 = "1"` to `[workspace.dependencies]`.
- Modify: `crates/mule-proto/Cargo.toml` - depend on `flate2`.
- Modify: `crates/mule-proto/src/io.rs` - add `IoError` variants `BadHeader(u8)`, `TooBig`, `Decompress`.
- Create: `crates/mule-proto/src/packet.rs`.
- Modify: `crates/mule-proto/src/lib.rs` - `pub mod packet;` + re-exports.

## Data model

```rust
pub struct Packet { pub protocol: u8, pub opcode: u8, pub payload: Vec<u8> }
// protocol consts: PROT_EDONKEY 0xE3, PROT_EMULE 0xC5, PROT_PACKED 0xD4,
//                  PROT_KAD 0xE4, PROT_KAD_PACKED 0xE5, PROT_ED2KV2 0xF4, PROT_ED2KV2_PACKED 0xF5
// pub const MAX_PACKET_SIZE: usize = 2_000_000;
```

## Tasks (TDD)

### Task 1: IoError variants + write_packet + protocol consts
- Add `BadHeader(u8)`, `TooBig`, `Decompress` to `IoError` (+ Display arms).
- `write_packet(p: &Packet) -> Vec<u8>`: `[protocol][u32 LE (1+payload.len())][opcode][payload]`.
- Tests: golden `Packet{0xE3, 0x01, [0xAA,0xBB]}` -> `[E3, 03 00 00 00, 01, AA BB]`.

### Task 2: streaming read_packet
- `read_packet(buf: &[u8]) -> Result<Option<(Packet, usize)>, IoError>`:
  - `buf.len() < 6` -> `Ok(None)`.
  - Read protocol; if not a known protocol byte -> `Err(BadHeader(protocol))`.
  - Read packetlength (LE u32); `packetlength < 1` -> `Err(BadHeader)`; `payload_size = packetlength-1`; `payload_size > MAX_PACKET_SIZE` -> `Err(TooBig)`.
  - `buf.len() < 6 + payload_size` -> `Ok(None)`.
  - Else return `Ok(Some((Packet{protocol,opcode,payload}, 6+payload_size)))`.
- Tests: full single packet -> Some + consumed; a 5-byte and a header-only-but-short-payload buffer -> None; two concatenated packets -> first Some with correct consumed, then second parses from the remainder; bad protocol byte -> BadHeader; payload_size > MAX -> TooBig.

### Task 3: compress / decompress
- `compress(p: &Packet) -> Packet`: zlib-deflate the payload (level 9); if smaller AND protocol is a packable base (0xC5/0xE4/0xF4 or 0xE3 -> maps to 0xD4), return a new Packet with the packed protocol byte and compressed payload; else return `p.clone()`. Mapping: 0xE4->0xE5, 0xF4->0xF5, else->0xD4.
- `decompress(p: &Packet, max_size: usize) -> Result<Packet, IoError>`: only for 0xD4/0xF5/0xE5 (else `Err(BadHeader)`); inflate payload, bounding output to `max_size` (`Err(TooBig)` if exceeded, `Err(Decompress)` on zlib error); protocol becomes 0xE4 for 0xE5 else 0xC5.
- Tests: compress a highly-compressible 2000-byte payload then decompress -> original Packet payload, and protocol mapping 0xC5->0xD4->(decompress)->0xC5; compress an incompressible tiny payload returns it unchanged (still 0xC5); decompress on a non-packed protocol -> BadHeader; decompress with a tiny max_size -> TooBig.
- Gate: `cargo test -p mule-proto`, clippy, `cargo fmt --check`.

## Self-review checklist
- Spec coverage: TCP framing + zlib (reference sections 1-4). Kad UDP framing (0xE4/0xE5 with the RC4 obfuscation layer) is a Wave-6 concern; the protocol-byte consts are shared.
- Placeholder scan: implement fully.
- Type consistency: `Packet{protocol,opcode,payload}`, `read_packet(&[u8]) -> Result<Option<(Packet,usize)>, IoError>`, `write_packet(&Packet)->Vec<u8>`, `compress(&Packet)->Packet`, `decompress(&Packet,usize)->Result<Packet,IoError>`.
- Divergence: no split-packet emission (matches aMule); decompress protocol remap targets the client-link interpretation (0xD4/0xF5 -> 0xC5), matching ClientTCPSocket (server code overrides to 0xE3, an engine-side detail for later).
