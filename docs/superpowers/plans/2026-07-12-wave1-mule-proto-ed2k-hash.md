# Wave 1: mule-proto workspace + eD2k file hashing - Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up the padMule Cargo workspace and the `mule-proto` crate, delivering a verified eD2k file-hash function (`ed2k_hash`) that matches aMule's rule, including the exact-multiple-of-PARTSIZE edge case.

**Architecture:** A Cargo workspace at the repo root. First crate `mule-proto` is pure, no-I/O codec/crypto. This plan implements the MD4-based eD2k file hash: split the file into 9,728,000-byte parts, MD4 each part, and combine. Single-part files use the part hash directly; multi-part files hash the concatenation of part hashes; a file whose size is an exact multiple of PARTSIZE gets a trailing empty part (part count = floor(size/PARTSIZE) + 1), matching aMule/eMule (NOT the old eDonkey rule).

**Tech Stack:** Rust 1.96 (edition 2021), `md4` crate, `hex` crate (tests).

**Grounding:** `docs/wiki/protocol-reference.md` and `docs/raw/amule-upstream-reference-2026-07-12.md` (PARTSIZE = 9,728,000; part count = floor(size/PARTSIZE)+1; file hash = MD4 over parts then MD4 of concatenated part hashes; single-part file hash IS the part hash). MD4 known-answer values are from RFC 1320.

**Toolchain note:** every `cargo` command must be preceded by `source "$HOME/.cargo/env"` in a fresh shell (cargo is not on the default PATH on this box). Commit authoring uses `git -c user.name='Anthony J. (Tony) Bufort' -c user.email='ajbufort@ajbconsulting.us'`.

---

## File structure

- Create: `Cargo.toml` (workspace manifest)
- Create: `crates/mule-proto/Cargo.toml`
- Create: `crates/mule-proto/src/lib.rs` (crate root; re-exports)
- Create: `crates/mule-proto/src/hash.rs` (PARTSIZE, part_count, ed2k_hash, MD4 helper)
- Test: unit tests inline in `hash.rs` under `#[cfg(test)]`

Rationale: hashing is one responsibility in its own module. Later Wave-1 plans add sibling modules (`framing.rs`, `tag.rs`, `aich.rs`, `search_expr.rs`) to the same crate.

---

### Task 1: Workspace + empty mule-proto crate

**Files:**
- Create: `Cargo.toml`
- Create: `crates/mule-proto/Cargo.toml`
- Create: `crates/mule-proto/src/lib.rs`

- [ ] **Step 1: Create the workspace manifest**

Create `Cargo.toml`:

```toml
[workspace]
resolver = "2"
members = ["crates/mule-proto"]

[workspace.package]
edition = "2021"
license = "GPL-2.0-or-later"
rust-version = "1.96"

[workspace.dependencies]
md4 = "0.10"
hex = "0.4"
```

- [ ] **Step 2: Create the crate manifest**

Create `crates/mule-proto/Cargo.toml`:

```toml
[package]
name = "mule-proto"
version = "0.0.0"
edition.workspace = true
license.workspace = true
rust-version.workspace = true

[dependencies]
md4 = { workspace = true }

[dev-dependencies]
hex = { workspace = true }
```

- [ ] **Step 3: Create a placeholder crate root**

Create `crates/mule-proto/src/lib.rs`:

```rust
//! mule-proto: pure eD2k/Kad codec and crypto primitives for padMule.
//! No I/O. See docs/wiki/protocol-reference.md.

pub mod hash;
```

- [ ] **Step 4: Create an empty hash module so it compiles**

Create `crates/mule-proto/src/hash.rs`:

```rust
//! eD2k/MD4 file hashing. See docs/wiki/protocol-reference.md.
```

- [ ] **Step 5: Verify the workspace builds**

Run: `source "$HOME/.cargo/env" && cargo build`
Expected: compiles clean (a warning-free empty crate).

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock crates/mule-proto
git -c user.name='Anthony J. (Tony) Bufort' -c user.email='ajbufort@ajbconsulting.us' \
  commit -m "feat(proto): scaffold cargo workspace and mule-proto crate"
```

---

### Task 2: MD4 helper with RFC 1320 known-answer tests

**Files:**
- Modify: `crates/mule-proto/src/hash.rs`

- [ ] **Step 1: Write the failing test**

Append to `crates/mule-proto/src/hash.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    // RFC 1320 MD4 test vectors.
    #[test]
    fn md4_rfc1320_vectors() {
        assert_eq!(hex::encode(md4(b"")), "31d6cfe0d16ae931b73c59d7e0c089c0");
        assert_eq!(hex::encode(md4(b"a")), "bde52cb31de33e46245e05fbdbd6fb24");
        assert_eq!(hex::encode(md4(b"abc")), "a448017aaf21d8525fc10ae87aa6729d");
        assert_eq!(
            hex::encode(md4(b"message digest")),
            "d9130a8164549fe818874806e1c7014b"
        );
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `source "$HOME/.cargo/env" && cargo test -p mule-proto md4_rfc1320_vectors`
Expected: FAIL - `md4` function not found (does not compile).

- [ ] **Step 3: Write minimal implementation**

Insert at the TOP of `crates/mule-proto/src/hash.rs` (above the test module):

```rust
use md4::{Digest, Md4};

/// Raw MD4 digest of `data`.
pub fn md4(data: &[u8]) -> [u8; 16] {
    let mut hasher = Md4::new();
    hasher.update(data);
    hasher.finalize().into()
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `source "$HOME/.cargo/env" && cargo test -p mule-proto md4_rfc1320_vectors`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/mule-proto/src/hash.rs
git -c user.name='Anthony J. (Tony) Bufort' -c user.email='ajbufort@ajbconsulting.us' \
  commit -m "feat(proto): MD4 helper verified against RFC 1320 vectors"
```

---

### Task 3: PARTSIZE and part_count (the floor+1 rule)

**Files:**
- Modify: `crates/mule-proto/src/hash.rs`

- [ ] **Step 1: Write the failing test**

Add these test functions inside the existing `mod tests { ... }` block in `crates/mule-proto/src/hash.rs`:

```rust
    #[test]
    fn part_count_rule() {
        // aMule: part count = floor(size / PARTSIZE) + 1. An exact multiple
        // gets a trailing (empty) part. See protocol-reference.md.
        assert_eq!(part_count(0), 1);
        assert_eq!(part_count(1), 1);
        assert_eq!(part_count(PARTSIZE - 1), 1);
        assert_eq!(part_count(PARTSIZE), 2);
        assert_eq!(part_count(PARTSIZE + 1), 2);
        assert_eq!(part_count(2 * PARTSIZE), 3);
        assert_eq!(part_count(2 * PARTSIZE + 1), 3);
    }

    #[test]
    fn partsize_value() {
        assert_eq!(PARTSIZE, 9_728_000);
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `source "$HOME/.cargo/env" && cargo test -p mule-proto part_count`
Expected: FAIL - `PARTSIZE` / `part_count` not found (does not compile).

- [ ] **Step 3: Write minimal implementation**

Add below the `md4` function in `crates/mule-proto/src/hash.rs`:

```rust
/// eD2k part size in bytes (aMule PARTSIZE).
pub const PARTSIZE: u64 = 9_728_000;

/// Number of eD2k parts for a file of `size` bytes: floor(size/PARTSIZE) + 1.
/// A size that is an exact multiple of PARTSIZE yields a trailing empty part.
pub fn part_count(size: u64) -> u64 {
    size / PARTSIZE + 1
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `source "$HOME/.cargo/env" && cargo test -p mule-proto part_count && cargo test -p mule-proto partsize_value`
Expected: PASS (both).

- [ ] **Step 5: Commit**

```bash
git add crates/mule-proto/src/hash.rs
git -c user.name='Anthony J. (Tony) Bufort' -c user.email='ajbufort@ajbconsulting.us' \
  commit -m "feat(proto): PARTSIZE and part_count (floor+1 rule)"
```

---

### Task 4: ed2k_hash - single-part, multi-part, and exact-multiple

**Files:**
- Modify: `crates/mule-proto/src/hash.rs`

- [ ] **Step 1: Write the failing tests**

Add inside `mod tests { ... }` in `crates/mule-proto/src/hash.rs`:

```rust
    #[test]
    fn ed2k_empty_file_is_md4_empty() {
        // One (empty) part -> hash is that part's MD4 directly.
        assert_eq!(
            hex::encode(ed2k_hash(b"")),
            "31d6cfe0d16ae931b73c59d7e0c089c0"
        );
    }

    #[test]
    fn ed2k_single_part_is_md4_of_contents() {
        // Sub-PARTSIZE file: single part, file hash IS the part MD4.
        let data = b"abc";
        assert_eq!(ed2k_hash(data), md4(data));
        assert_eq!(
            hex::encode(ed2k_hash(data)),
            "a448017aaf21d8525fc10ae87aa6729d"
        );
    }

    #[test]
    fn ed2k_two_parts_hashes_concat_of_part_hashes() {
        // Slightly over one part -> 2 parts: [PARTSIZE bytes][remainder].
        // Expected = MD4( MD4(part0) || MD4(part1) ), built from the
        // RFC-verified md4() primitive.
        let mut data = vec![0xABu8; PARTSIZE as usize];
        data.extend_from_slice(b"tail");
        let part0 = md4(&data[..PARTSIZE as usize]);
        let part1 = md4(&data[PARTSIZE as usize..]);
        let mut concat = Vec::new();
        concat.extend_from_slice(&part0);
        concat.extend_from_slice(&part1);
        let expected = md4(&concat);
        assert_eq!(ed2k_hash(&data), expected);
    }

    #[test]
    fn ed2k_exact_multiple_appends_empty_trailing_part() {
        // Exactly PARTSIZE bytes -> 2 parts: [PARTSIZE bytes][empty].
        // aMule includes the trailing empty part's MD4 in the combination.
        let data = vec![0xCDu8; PARTSIZE as usize];
        let part0 = md4(&data);
        let part1 = md4(b""); // trailing empty part
        let mut concat = Vec::new();
        concat.extend_from_slice(&part0);
        concat.extend_from_slice(&part1);
        let expected = md4(&concat);
        assert_eq!(ed2k_hash(&data), expected);
        // And it must NOT equal the naive single-part MD4 of the whole file.
        assert_ne!(ed2k_hash(&data), md4(&data));
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `source "$HOME/.cargo/env" && cargo test -p mule-proto ed2k_`
Expected: FAIL - `ed2k_hash` not found (does not compile).

- [ ] **Step 3: Write minimal implementation**

Add below `part_count` in `crates/mule-proto/src/hash.rs`:

```rust
/// eD2k file hash of an in-memory file `data`, per the aMule rule.
///
/// - Split into PARTSIZE-byte parts; if `data.len()` is an exact multiple of
///   PARTSIZE (including 0), a trailing empty part is appended, so part count
///   is always floor(len/PARTSIZE)+1.
/// - Each part is MD4-hashed.
/// - If there is exactly one part, the file hash is that part's MD4.
/// - Otherwise the file hash is MD4 of the concatenated 16-byte part hashes.
pub fn ed2k_hash(data: &[u8]) -> [u8; 16] {
    let n = part_count(data.len() as u64) as usize;
    if n == 1 {
        return md4(data);
    }
    let mut concat = Vec::with_capacity(n * 16);
    for i in 0..n {
        let start = i * PARTSIZE as usize;
        let end = core::cmp::min(start + PARTSIZE as usize, data.len());
        // For the trailing empty part on an exact multiple, start == end == len.
        concat.extend_from_slice(&md4(&data[start..end]));
    }
    md4(&concat)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `source "$HOME/.cargo/env" && cargo test -p mule-proto`
Expected: PASS (all hash tests: MD4 vectors, part_count, partsize, and the four ed2k_ tests).

- [ ] **Step 5: Re-export from the crate root**

In `crates/mule-proto/src/lib.rs`, add below the `pub mod hash;` line:

```rust
pub use hash::{ed2k_hash, md4, part_count, PARTSIZE};
```

- [ ] **Step 6: Verify clippy is clean**

Run: `source "$HOME/.cargo/env" && cargo clippy -p mule-proto --all-targets -- -D warnings`
Expected: no warnings.

- [ ] **Step 7: Commit**

```bash
git add crates/mule-proto/src/hash.rs crates/mule-proto/src/lib.rs
git -c user.name='Anthony J. (Tony) Bufort' -c user.email='ajbufort@ajbconsulting.us' \
  commit -m "feat(proto): ed2k_hash with single/multi-part and exact-multiple rule"
```

---

## Self-review

- **Spec coverage:** implements the Wave-1 hashing slice from spec section 10 item 1 and the PARTSIZE / part-count / exact-multiple facts from protocol-reference.md. Framing, tags, AICH, and search-expr are explicitly deferred to follow-on Wave-1 plans (they are additional modules in the same crate and do not change these interfaces).
- **Placeholder scan:** none - every step has concrete code and exact commands.
- **Type consistency:** `md4 -> [u8;16]`, `part_count(u64) -> u64`, `PARTSIZE: u64`, `ed2k_hash(&[u8]) -> [u8;16]` are used consistently across tasks and the re-export.
- **Known limitation to carry forward:** `ed2k_hash` takes an in-memory slice. The engine will hash multi-GB files from disk in streaming fashion; a streaming `Ed2kHasher` (feed parts incrementally) is a follow-on task in the `mule-files`/engine wave. This in-memory version is the verified reference the streaming one must match.
