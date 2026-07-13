# Wave 3b-2: search codec + server list/ident - Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development or superpowers:executing-plans. Steps use `- [ ]`.

**Goal:** Add the eD2k server-search codecs to `mule-engine`: build `OP_SEARCHREQUEST` (the search expression), parse `OP_SEARCHRESULT`, and parse the remaining login-burst packets `OP_SERVERLIST` and `OP_SERVERIDENT`. Pure; no networking.

**Architecture:** New module `search` (request builder + result parser); extend `server_messages` with the two server-info parsers. Built on `mule-proto` (Reader/Writer/Packet/read_tag/write_tag). Network parsers do NOT pre-allocate from an untrusted count.

**Tech Stack:** Rust 1.96, `mule-proto`, `hex` (dev).

**Grounding** (SearchList.cpp:156-257 CSearchExprTarget, :714-830 CreateSearchData; TCP.h opcodes; Constants.h ED2K_SEARCH_OP_*; FileTags.h):
- `OP_SEARCHREQUEST` = 0x16, protocol 0xE3. Payload = the search expression (Query_Tree), nothing before it.
- Expression tokens (CSearchExprTarget):
  - Boolean op: `u8 0x00` (param type) + `u8 op` (AND=0x00, OR=0x01, NOT=0x02).
  - Keyword string term: `u8 0x01` + `WriteString` (u16 len + UTF-8 no BOM).
  - String metadata param: `u8 0x02` + `WriteString(value)` + `u16 1` (tag-id length) + `u8 tagId`. (ASCII variant writes the value as Latin-1; for ASCII file-type strings this is byte-identical.)
  - Numeric metadata param: `u8 0x03` + `u32 value` + `u8 operator` + `u16 1` + `u8 tagId`. (Large-file 64-bit variant is `u8 0x08` + `u64`; the baseline clamps to u32 = aMule's non-64bit path.)
- Common-case assembly (SearchList.cpp:776-829, the `m_aExpr.GetCount() <= 1` branch): count the parameters; write a boolean AND before every parameter EXCEPT the last (`if (++i < count) WriteAND` before each), producing `AND p0 AND p1 ... p(n-1)`. A single keyword -> just the keyword term, no AND.
  - Parameter order: keyword, file_type (FT_FILETYPE 0x03, ASCII), min_size (FT_FILESIZE 0x02, OP_GREATER), max_size (FT_FILESIZE, OP_LESS), extension (FT_FILEFORMAT 0x04).
- Ops (Constants.h): EQUAL=0, GREATER=1, LESS=2, GREATER_EQUAL=3, LESS_EQUAL=4, NOTEQUAL=5. Tags: FT_FILENAME 0x01, FT_FILESIZE 0x02, FT_FILETYPE 0x03, FT_FILEFORMAT 0x04.
- `OP_SEARCHRESULT` = 0x33: `u32 count`, then per file: `hash(16)`, `id(u32)`, `port(u16)`, `u32 tagcount`, tags (generic MET/new tags - our read_tag handles both, incl. compact and width-varying ints).
- `OP_SERVERLIST` = 0x32: `u8 count`, then `count * (u32 IP, u16 port)`.
- `OP_SERVERIDENT` = 0x41: `hash(16)`, `IP(u32)`, `port(u16)`, `u32 tagcount`, tags.

**Toolchain:** `source "$HOME/.cargo/env"` before every cargo call.

---

## File structure

- Create: `crates/mule-engine/src/search.rs`.
- Modify: `crates/mule-engine/src/server_messages.rs` - add `ServerIdent`, `parse_server_ident`, `parse_server_list`, opcode consts `OP_SEARCHREQUEST`/`OP_SEARCHRESULT`/`OP_SERVERLIST`/`OP_SERVERIDENT`.
- Modify: `crates/mule-engine/src/lib.rs` - `pub mod search;` + re-exports.

## Data model

```rust
pub struct SearchParams { pub keyword: String, pub file_type: Option<String>, pub min_size: Option<u32>, pub max_size: Option<u32>, pub extension: Option<String> }
pub struct SearchResultFile { pub hash: [u8;16], pub id: u32, pub port: u16, pub tags: Vec<Tag> }
pub struct ServerIdent { pub hash: [u8;16], pub ip: u32, pub port: u16, pub tags: Vec<Tag> }
```

## Tasks (TDD)

### Task 1: search-expression primitives + build_search_request
- Private writers: `write_and(w)`, `write_keyword(w, &str)`, `write_string_meta(w, tag_id, &str)`, `write_numeric_meta(w, tag_id, op, u32)`.
- `build_search_request(p: &SearchParams) -> Packet`: collect the present terms in order; emit AND before all but the last; wrap in `Packet::new(PROT_EDONKEY, OP_SEARCHREQUEST, payload)`.
- Tests: single keyword "movie" -> `[01][05 00 "movie"]` (no AND); keyword + min_size 1000 -> `[00 00][01][05 00 "movie"][03][E8 03 00 00][01][01 00][02]` (AND, keyword, numeric FT_FILESIZE GREATER); keyword + type "Video" + min + max + extension "avi" -> the full ANDed golden; framing round-trip.

### Task 2: parse_search_result + parse_server_list + parse_server_ident
- `parse_search_result(&[u8]) -> Result<Vec<SearchResultFile>, IoError>` - `Vec::new()` (no prealloc from the untrusted u32 count); each file = hash/id/port/tagcount/tags via read_tag.
- `parse_server_list(&[u8]) -> Result<Vec<(u32,u16)>, IoError>` - u8 count (safe to prealloc) + entries.
- `parse_server_ident(&[u8]) -> Result<ServerIdent, IoError>`.
- Tests: a golden 1-file search result (with an FT_FILENAME string + FT_FILESIZE u32 tag) parses to the expected struct; a 2-server OP_SERVERLIST; an OP_SERVERIDENT with a name tag; a truncated result -> Err.
- Gate: `cargo test -p mule-engine`, clippy, `cargo fmt --check`.

## Self-review checklist
- Spec coverage: the search slice of Wave 3. Global (UDP) search, OP_FOUNDSOURCES, and the full boolean-tree (OR/NOT, parenthesized) parser are deferred - the ANDed-terms form is the common case and what aMule sends for simple searches; note the deferral.
- Placeholder scan: implement fully.
- Type consistency: `build_search_request(&SearchParams)->Packet`, `parse_search_result(&[u8])->Result<Vec<SearchResultFile>,IoError>`, `parse_server_list`, `parse_server_ident`.
- Safety: network parsers use `Vec::new()` (not `with_capacity(count)`) for the untrusted u32 count, so a hostile count cannot force a huge allocation; read_tag/Reader already bound-check.
