# Build Progress

Updated: 2026-07-12

Wave-by-wave status of the padMule Rust engine (waves defined in
`docs/superpowers/specs/2026-07-12-padmule-design.md` section 10). Each wave
ends at a differential/round-trip gate.

## Status

| Wave | Scope | Plan | State |
|------|-------|------|-------|
| 1 | `mule-proto` foundation: eD2k/MD4 file hashing | `plans/2026-07-12-wave1-mule-proto-ed2k-hash.md` | eD2k hash DONE (7 tests, clippy clean). Framing, tags, AICH, search-expr: follow-on Wave-1 plans, not yet written. |
| 2 | `mule-files` byte-compatible .met/.part | - | not started |
| 3 | `mule-engine` eD2k core: login/search/single-source download | - | not started |
| 4 | multi-source + upload + queue + credits + SX + corruption | - | not started |
| 5 | obfuscation + secure ident | - | not started |
| 6 | `mule-kad` | - | not started |
| 7 | `mule-ec` + `mule-cli` parity (IP filter, UPnP, categories) | - | not started |
| 8 | `mule-ffi` + `ios/padMule` SwiftUI shell + lifecycle + sideload | - | not started |
| 9 | (v1.1) seedbox mode | - | not started |

## Wave 1 notes

- Workspace at repo root; first crate `crates/mule-proto` (pure, no I/O).
- `ed2k_hash(&[u8]) -> [u8;16]` is an in-memory reference implementation. The
  engine will need a STREAMING `Ed2kHasher` (feed parts from disk) for multi-GB
  files; that lands with `mule-files`/engine and must match this reference.
- Toolchain: Rust 1.96.1; `source "$HOME/.cargo/env"` before every cargo call
  (cargo not on default PATH). No aarch64-apple-ios target installed here (iOS
  builds happen on CI macOS per [[ipados-constraints]]).

## Remaining Wave-1 slices (next plans)

1. LE byte reader/writer primitives + packet framing (protocol byte, u32 size,
   opcode, split packets, packed/zlib). See [[protocol-reference]].
2. Tag system (types, special short-name compressed tags, read/write).
3. AICH SHA-1 hash tree (180 KiB blocks, master hash, recovery packet).
4. Search-expression encoding (boolean AND/OR/NOT + parameter terms).

## Test fixtures / live data (from [[ref-ecosystem]])

emule-security.org provides real `nodes.dat` (Wave-2 round-trip + Wave-6 Kad
bootstrap) and `ipfilter.dat` (Wave-7 IP filter). Fetch at the relevant wave;
do not vendor. For known.met/part.met/clients.met round-trips, generate golden
files by building/running amuled from `amule-3.0.1/`, or hand-construct from the
verified byte layouts in [[protocol-reference]] / docs/raw.

## Related

- [[protocol-reference]]
- [[ref-ecosystem]]
- [[arch-upstream-amule]]
- [[decisions-and-lessons]]
