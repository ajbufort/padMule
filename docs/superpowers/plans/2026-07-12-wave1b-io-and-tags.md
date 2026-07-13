# Wave 1b: mule-proto byte I/O + eD2k tag system - Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development or superpowers:executing-plans. Steps use `- [ ]`.

**Goal:** Add little-endian byte I/O primitives and a byte-compatible eD2k tag reader/writer to `mule-proto`, the foundation `mule-files` and the engine build on.

**Architecture:** Two new modules in `crates/mule-proto`: `io` (a bounds-checked LE cursor reader + a Vec-backed writer, mirroring aMule's CFileDataIO/SafeFile primitives) and `tag` (the MET-format tag: type byte, name, typed value). Values preserve exact on-disk bytes so writing round-trips bit-identically.

**Tech Stack:** Rust 1.96, no new deps (thiserror optional; use a hand-rolled error enum to stay dep-light).

**Grounding** (`docs/raw/amule-upstream-reference-2026-07-12.md`):
- All eD2k integers little-endian; strings = u16 length prefix + bytes, no NUL (SafeFile.cpp:330-405).
- MET tag (SafeFile.cpp:513-570; Tag.cpp:85-189): `u8 type`; name = `u16 namelen` then, if namelen==1, one `u8` numeric id, else `namelen` Latin-1 bytes. Read side ALSO accepts the compact form `(type|0x80)` + `u8` id, but file writers never emit it. Payloads: HASH16 0x01 =16B; STRING 0x02 = u16 len+bytes; UINT32 0x03 =4B LE; FLOAT32 0x04 =4B; BLOB 0x07 = u32 len+bytes; UINT16 0x08 =2B LE; UINT8 0x09 =1B; BSOB 0x0A = u8 len+bytes; UINT64 0x0B =8B LE; STR1..STR16 0x11..0x20 = inline fixed string, len=type-0x11+1 (read only).
- MET ints are written at the DECLARED width, never shrunk (Tag.h:112-155) - so value types must be preserved on read, not promoted.
- Strings written utf8strRaw (no BOM); readers must accept a leading BOM (eMule). Preserve raw bytes for fidelity.

**Toolchain:** `source "$HOME/.cargo/env"` before every cargo call.

---

## File structure

- Create: `crates/mule-proto/src/io.rs` - `Reader`, `Writer`, `IoError`.
- Create: `crates/mule-proto/src/tag.rs` - `TagName`, `TagValue`, `Tag`, `read_tag`, `write_tag`.
- Modify: `crates/mule-proto/src/lib.rs` - add `pub mod io; pub mod tag;` and re-exports.

## Tasks (TDD; each ends green + committed)

### Task 1: `io::Reader` / `io::Writer` LE primitives
- Reader over `&[u8]` with position; `read_u8/u16/u32/u64` (LE), `read_bytes(n)`, `read_string_u16` (u16 len + raw bytes), `remaining`. Underrun -> `IoError::UnexpectedEof`.
- Writer over `Vec<u8>`; `write_u8/u16/u32/u64` (LE), `write_bytes`, `write_string_u16`, `into_inner`.
- Tests: round-trip each width; a golden byte check (`write_u32(0x12345678)` -> `[0x78,0x56,0x34,0x12]`); underrun errors.
- Gate: `cargo test -p mule-proto io::`.

### Task 2: `tag` types + `read_tag`/`write_tag`
- `TagName { Id(u8), Str(Vec<u8>) }`; `TagValue { U8, U16, U32, U64, F32, Hash([u8;16]), Str(Vec<u8>), Blob(Vec<u8>), Bsob(Vec<u8>) }`; `Tag { name, value }`.
- `read_tag`: read `u8` raw type; if `& 0x80`, name = `Id(read_u8)` and type = `raw & 0x7f`; else `namelen=read_u16`, name = `Id(read_u8)` if namelen==1 else `Str(read_bytes(namelen))`; then value by type (incl. STR1..16 -> `Str`). Unknown type -> `IoError::BadTag`.
- `write_tag`: write `u8 type`; name -> `Id(id)`: `write_u16(1); write_u8(id)`; `Str(b)`: `write_u16(len); write_bytes(b)`; then value at DECLARED width. (Emit the non-compact MET form, matching aMule file writers.)
- Tests:
  - Golden UINT32 tag id 0x01 value 0x12345678 -> `[0x03, 0x01,0x00, 0x01, 0x78,0x56,0x34,0x12]`, read and write both.
  - Golden STRING tag id 0x01 value "abc" -> `[0x02, 0x01,0x00, 0x01, 0x03,0x00, 'a','b','c']`.
  - Round-trip a HASH16 tag and a string-named tag.
  - Read the compact form `(0x03|0x80), 0x10, <4 LE bytes>` -> `Id(0x10)` U32, and confirm re-writing yields the NON-compact form (documented divergence).
  - STR3 (0x13) inline read -> `Str` of 3 bytes.
- Gate: `cargo test -p mule-proto` (all green), `cargo clippy -p mule-proto --all-targets -- -D warnings`.

## Self-review checklist
- Spec coverage: the "tags" slice of Wave 1 (spec 10.1) and the SafeFile/Tag byte layout. Framing (protocol byte + opcode + size + split/packed) is deferred to the engine wave; `.met` files need tags, not packet framing.
- Placeholder scan: implement fully; no TODO.
- Type consistency: `read_tag(&mut Reader) -> Result<Tag, IoError>`, `write_tag(&mut Writer, &Tag)`; `TagValue` variants stable.
- Divergence noted: writer never emits the compact `0x80` form or STR1..16 (write-side uses STRING 0x02); both are read-only compatibility paths, matching aMule.
