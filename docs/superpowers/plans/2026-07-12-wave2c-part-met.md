# Wave 2c: byte-compatible part.met + gap list - Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development or superpowers:executing-plans. Steps use `- [ ]`.

**Goal:** Add a byte-compatible `part.met` reader/writer to `mule-files`, plus helpers to extract and build the gap list (the still-missing byte ranges) with correct inclusive-start / exclusive-end semantics.

**Architecture:** New module `part_met` in `mule-files`. A `part.met` describes ONE partial download: version byte, date, file hash, part-hash list, tag list. The gap list is carried as ordinary tags whose string names are a `\x09`(FT_GAPSTART)/`\x0A`(FT_GAPEND) byte followed by the ASCII-decimal gap index; the generic tag codec round-trips them, and `gaps()`/`gap_tags()` translate to/from `(start, end)` ranges.

**Tech Stack:** Rust 1.96, `mule-proto`, `hex` (dev), `std::collections::BTreeMap`.

**Grounding** (reference section 4; PartFile.cpp:820-1053 save, 384-817 load):
- `u8` version = 0xE0 (PARTFILE_VERSION) or 0xE2 (PARTFILE_VERSION_LARGEFILE, size > OLD_MAX_FILE_SIZE). 0xE1 is edonkey-import, accepted on read only.
- `u32` date (mtime of the .part data file). `16B` file hash. `u16` part-hash count + that many `16B` part hashes (may be 0 before the hashset is fetched; includes the sentinel for exact multiples). `u32` tag count + that many MET tags (fixed tags + gap tags + extras, all flat).
- GAP LIST (part of the tag list): per gap `i` (ascending), two string-named tags: name = `[0x09]` + ASCII-decimal(i) for GAPSTART, `[0x0A]` + ASCII-decimal(i) for GAPEND. Values UINT32, or UINT64 iff large file. Semantics: GAPSTART = first missing byte (INCLUSIVE); GAPEND = first byte NOT missing (EXCLUSIVE). A fresh download of an N-byte file is one gap: GAPSTART 0, GAPEND N. Gaps are the ranges still MISSING.
- Load tolerance: gap tags are paired by their decimal index (a map), so order/duplication is tolerated. We replicate that: pair by parsed index, keep only indices that have both a start and an end.

**Toolchain:** `source "$HOME/.cargo/env"` before every cargo call.

---

## File structure

- Create: `crates/mule-files/src/part_met.rs`.
- Modify: `crates/mule-files/src/lib.rs` - add `pub mod part_met;` + re-exports.

## Data model

```rust
pub struct PartMet {
    pub version: u8,               // 0xE0 or 0xE2 (read also 0xE1)
    pub date: u32,
    pub file_hash: [u8; 16],
    pub part_hashes: Vec<[u8; 16]>,
    pub tags: Vec<Tag>,            // fixed + gap + extra tags, flat
}
pub struct Gap { pub start: u64, pub end: u64 } // end is EXCLUSIVE
```

## Tasks (TDD)

### Task 1: read/write part.met round-trip
- `read_part_met(&[u8]) -> Result<PartMet, IoError>`: `u8` version (accept 0xE0/0xE1/0xE2 else `BadTag`), `u32` date, `16B` hash, `u16` phcount + hashes, `u32` tagcount + tags.
- `write_part_met(&PartMet) -> Vec<u8>`: reverse, preserving version.
- Tests: golden vector (version 0xE0, 0 part hashes, one FT_FILESIZE tag + a gap pair for a fresh 500-byte file) reads and writes byte-identically; bad-version error; round-trip a 0xE2 large-file part.met with UINT64 gap values.

### Task 2: gaps() extractor + gap_tags() builder
- `pub const FT_GAPSTART: u8 = 0x09; pub const FT_GAPEND: u8 = 0x0A;`
- `gaps(pm: &PartMet) -> Vec<Gap>`: scan tags for string names beginning 0x09/0x0A, parse the decimal index, read the value as u64 (from U32 or U64; ignore other types), pair start+end by index, return sorted by `start`. Malformed/unpaired entries are skipped (aMule tolerates).
- `gap_tags(gaps: &[Gap], large: bool) -> Vec<Tag>`: for each gap `i`, emit the GAPSTART and GAPEND string-named tags; values `U64` if `large` else `U32`.
- Tests: a fresh 500-byte download -> one gap `Gap{0,500}` from `[start=0,end=500]` tags (locks the inclusive/exclusive semantics); `gap_tags` then `gaps` round-trips `[Gap{0,100}, Gap{200,300}]`; large=true emits UINT64 and round-trips a >4GiB gap; out-of-order/duplicate gap tags still pair correctly by index.
- Gate: `cargo test -p mule-files`, clippy, `cargo fmt --check`.

## Golden vector (Task 1): fresh 500-byte download, version 0xE0

```
E0                                version
11 22 33 44                       date
<16B file hash 00..0F>            file hash
00 00                             part-hash count = 0
03 00 00 00                       tag count = 3
03 01 00 02  F4 01 00 00          FT_FILESIZE(0x02) UINT32 = 500
03 02 00 09 30  00 00 00 00       GAPSTART gap0: name [0x09,'0'], UINT32 0
03 02 00 0A 30  F4 01 00 00       GAPEND   gap0: name [0x0A,'0'], UINT32 500
```
(String-named UINT32 tag = type 0x03, u16 namelen=2, 2 name bytes, 4 LE value bytes.)

## Self-review checklist
- Spec coverage: part.met + gap semantics (Wave 2 remainder). nodes.dat moved to Wave 6 (Kad) where its 128-bit id is interpreted.
- Placeholder scan: implement fully.
- Type consistency: `read_part_met`/`write_part_met`, `gaps(&PartMet)->Vec<Gap>`, `gap_tags(&[Gap],bool)->Vec<Tag>`, `Gap{start,end}` end-exclusive.
- Divergence: version byte preserved on round-trip. gaps() returns end-EXCLUSIVE (the on-disk GAPEND value), matching a resume calculation; aMule stores inclusive internally but writes exclusive.
