# Decisions and Lessons

Updated: 2026-07-12

Locked decisions, rejected approaches, gotchas, measured facts. One dated
bullet each; newest first.

## Locked decisions

- 2026-07-13 **"Modified tree" caveat RETIRED; our tree is faithful aMule.**
  Cross-checked `amule-3.0.1/` against pristine aMule mainline
  (`refs/amule-master`) and canonical eMule 0.50a/0.70b (`refs/emule-0.50a`,
  `refs/emule-0.70b`). The items the recon called "local modifications"
  (GetMaxSlots N_FLOOR=20, ALPHA_QUERY=5, the cascade heuristic) are aMule
  design, byte-identical in aMule master - aMule-vs-eMule POLICY differences,
  wire-neutral. New rule: eMule 0.50a is the de-facto WIRE/FORMAT authority
  (most of the network runs eMule); match aMule for wire-neutral policy. Wire
  landmines (userhash markers, Kad crypt 16B, MAGICVALUE_UDP_SYNC, SetValueBE)
  CONFIRMED identical in eMule 0.50a. See [[ref-source-trees]].

- 2026-07-12 **Deliberate tag-codec divergences from aMule (do NOT "fix").**
  Surfaced by the review pass; each is intentional for byte-compat fidelity.
  (1) `mule-proto` PRESERVES UINT8/UINT16 tag widths; aMule's reader promotes
  them to UINT32 (Tag.cpp:123-131) and thus re-writes them wider, so preserving
  is strictly more faithful to the source file and aMule reads them back fine.
  (2) `write_tag` emits only the non-compact MET form (never the `type|0x80`
  short form or inline STR1..16), matching aMule's file writers; those are
  read-only. (3) A `TagName::Str` of length 1 is unrepresentable (the format
  reserves name-length==1 for numeric ids) and reads back as `TagName::Id` -
  inherent to eD2k. (4) BOOL/BOOLARRAY are accepted for robustness though no
  aMule .met writer emits them. See [[protocol-reference]], [[build-progress]].
- 2026-07-12 **Byte-compatible .met/.part.** padMule reads and writes upstream
  binary formats (known.met, part.met incl. 64-bit variant + gap lists,
  server.met, nodes.dat, prefs, clients.met, ipfilter.dat) so downloads move
  between padMule and desktop aMule/eMule. Doubles as a differential test
  (load upstream file, re-emit, diff bytes). See [[protocol-reference]].
- 2026-07-12 **Seeding: foreground-only v1, seedbox toggle in v1.1.** Given the
  ~30s background suspension ([[ipados-constraints]]), v1 is honestly
  foreground-only (transfers pause on background, resume + Kad re-bootstrap on
  foreground). A supported "seedbox mode" (Auto-Lock=Never, plugged in, screen
  on) lands as a v1.1 toggle. Rejected the fragile silent-audio/location
  keepalive (unreliable, battery-heavy, memory-capped) for v1.
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
