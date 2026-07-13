# Wave 2b: byte-compatible known.met - Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development or superpowers:executing-plans. Steps use `- [ ]`.

**Goal:** Add a byte-compatible `known.met` reader/writer to `mule-files` (the shared/known-files database).

**Architecture:** New module `known_met` in the existing `mule-files` crate. A `known.met` is a header byte + `u32` record count + records; each record is a date, file hash, part-hash list, and tag list. Fields are preserved verbatim so read-then-write round-trips bit-for-bit, and the 0x0E vs 0x0F (large-file) header is handled uniformly because tags (incl. UINT64 sizes) are preserved as-is.

**Tech Stack:** Rust 1.96, `mule-proto`, `hex` (dev).

**Grounding** (reference section 3; KnownFile.cpp:723-858, KnownFileList.cpp):
- Header `u8` = 0x0E, or 0x0F if any record has size > OLD_MAX_FILE_SIZE (MET_HEADER / MET_HEADER_WITH_LARGEFILES, DataFileVersion.h:43-46). Then `u32` record count.
- Record: `u32` date (mtime at hash time); `16B` file MD4 hash; `u16` part-hash count; that many `16B` part hashes (equals ED2KPartHashCount, includes the empty-MD4 sentinel for exact multiples, 0 for sub-part files); `u32` tag count; that many MET-format tags.
- We preserve every field as read (tags kept generic); we do NOT interpret or reorder tags, so both 0x0E and 0x0F round-trip. Header byte preserved.

**Toolchain:** `source "$HOME/.cargo/env"` before every cargo call.

---

## File structure

- Create: `crates/mule-files/src/known_met.rs`.
- Modify: `crates/mule-files/src/lib.rs` - add `pub mod known_met;` and re-exports.

## Data model

```rust
pub struct KnownFileEntry {
    pub date: u32,
    pub file_hash: [u8; 16],
    pub part_hashes: Vec<[u8; 16]>, // u16 count on the wire
    pub tags: Vec<Tag>,             // u32 count on the wire
}
pub struct KnownMet { pub header: u8, pub entries: Vec<KnownFileEntry> }
```

## Tasks (TDD)

### Task 1: read_known_met
- `read_known_met(&[u8]) -> Result<KnownMet, IoError>`: header `u8` (error `BadTag` if not 0x0E/0x0F), `u32` count, then per entry: `u32` date, `16B` hash, `u16` phcount, phcount*`16B`, `u32` tagcount, tagcount `read_tag`.
- Tests: parse a golden vector (1 entry, 0 part hashes, 1 FT_FILESIZE tag); a golden with 2 part hashes; bad-header error.

### Task 2: write_known_met + round-trip
- `write_known_met(&KnownMet) -> Vec<u8>`: reverse of read, preserving header.
- Tests: golden writes byte-identically; round-trip a multi-entry file (mix of 0-part and 2-part entries, several tag types incl. a UINT64 size); a 0x0F header preserved; empty file `[0x0E, 0,0,0,0]`.
- Gate: `cargo test -p mule-files`, clippy, `cargo fmt --check`.

## Golden vector (1 entry, no part hashes, one UINT32 FT_FILESIZE=3 tag)

```
0E                                header (MET_HEADER)
01 00 00 00                       record count = 1
00 00 00 5F                       date = 0x5F000000
00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F   file hash (16B)
00 00                             part-hash count = 0
01 00 00 00                       tag count = 1
03 01 00 02 03 00 00 00           tag UINT32 id=0x02 (FT_FILESIZE) = 3
```

## Self-review checklist
- Spec coverage: known.met slice of Wave 2. part.met (gaps, 64-bit) is Wave 2c.
- Placeholder scan: implement fully.
- Type consistency: `read_known_met(&[u8]) -> Result<KnownMet, IoError>`, `write_known_met(&KnownMet) -> Vec<u8>`; entry fields fixed.
- Divergence: header preserved (fidelity). aMule's read-side u8/u16 tag promotion is NOT replicated (we preserve widths, per the mule-proto decision) - so re-serialization of foreign narrow-int tags is more faithful to the source than aMule's own re-save.
