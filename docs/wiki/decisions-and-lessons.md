# Decisions and Lessons

Updated: 2026-07-12

Locked decisions, rejected approaches, gotchas, measured facts. One dated
bullet each; newest first.

## Locked decisions

- 2026-07-12 **v1 scope: full amuled parity.** Anthony chose full parity over
  a download-focused v1 or a minimal-first-transfer MVP: eD2k servers + Kad,
  search, multi-source transfers with AICH recovery, uploads + credits,
  source exchange, obfuscation, IP filter, UPnP, categories, EC remote
  control, and .met/.part file-format compatibility with upstream. All
  foreground-first on iPadOS (the OS suspends backgrounded P2P regardless).

- 2026-07-12 **Deploy path: no Mac.** Anthony has only the iPad (plus this
  Windows/WSL2 box). Plan is engine-first on Linux; the SwiftUI shell builds
  on CI macOS runners (GitHub Actions); device installs via AltStore or
  Sideloadly from Windows with a free Apple ID (7-day re-sign, 3-app cap,
  AltServer auto-refresh on same Wi-Fi). A local/rented Mac can upgrade this
  later without changing the architecture.
- 2026-07-12 **Engine strategy: Rust rewrite.** Anthony chose a new Rust
  eD2k/Kad engine crate over porting the C++ amuled or a hybrid. Rationale:
  aarch64-apple-ios is a supported Rust target (engine develops/tests fully on
  WSL2, iOS is just a compile target); Rust core + SwiftUI shell over
  UniFFI-style glue is a proven production pattern; he is already a Rust shop
  (FinalWord). Cost accepted: the protocol is rebuilt from spec - no mature
  Rust eD2k/Kad implementation exists. Upstream `amule-3.0.1/` C++ becomes the
  behavioral REFERENCE ORACLE (differential testing against amuled on Linux),
  not the working tree. Rejected: C++ port of amuled (wxWidgets pervades the
  engine; zero upstream iOS support), hybrid C++-then-Rust (pays both costs).

## Related

- [[arch-upstream-amule]]
- [[ref-ecosystem]]
