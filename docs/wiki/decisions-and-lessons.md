# Decisions and Lessons

Updated: 2026-07-12

Locked decisions, rejected approaches, gotchas, measured facts. One dated
bullet each; newest first.

## Locked decisions

- 2026-07-13 **LIVE-VALIDATED: padMule logged into a real eD2k server.**
  Against 45.87.41.16:6262 (emule-security.org list) - LowID assigned (NATed
  box), full connect/pause/resume/reconnect lifecycle worked. Proves Wave 3a-3c
  end-to-end against real server software; the exact login tags/flags/version
  interoperated first try. LESSON: the WSL2 env does NOT block P2P ports
  (arbitrary outbound + UDP work); earlier all-fail runs were STALE server
  lists. Always use a current trusted list: `http://upd.emule-security.org/
  server.met`. See [[build-progress]], [[ref-ecosystem]].

- 2026-07-13 **Background pause is avoidable best-effort, not always-on.** The
  ~30s suspend is the only OS-GUARANTEED behavior, but sideloading unlocks the
  audio/location keepalive (App-Store-review-blocked, but we are not reviewed)
  for hours of best-effort screen-off running - killable by jetsam, needs
  <100MB bg memory + battery warning. Fully-supported always-on = foreground
  "seedbox mode" (Auto-Lock=Never, plugged in). iPadOS 26
  BGContinuedProcessingTask = legitimate "finish this file." A supported
  always-on screen-off P2P daemon is impossible (background URLSession is
  HTTP-only). Plan: v1 foreground-only + clean pause/resume; background
  persistence is a later OPT-IN tiered feature; clean pause/resume stays
  REQUIRED as the always-correct fallback. See [[lifecycle-and-reactivation]].

- 2026-07-13 **Replicate first, then improve (standing principle).** Replicate
  standard eD2k/Kad behavior faithfully before proposing improvements; Anthony
  invited improvements past that baseline (perf, correctness, memory, UX). The
  boundary: WIRE + FILE FORMATS stay byte-faithful to eMule/aMule (improving
  them = breaking interop); WIRE-NEUTRAL POLICY and IMPLEMENTATION INTERNALS are
  fair game. Flag any post-baseline deviation explicitly with rationale (like
  the tag-codec divergences below) and prefer it be measurable. iPad constraints
  ([[ipados-constraints]]) are a legitimate driver.

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

## Lessons

- 2026-07-14 **Agent-derived constants are a HYPOTHESIS until a test pins them
  against real bytes.** The Wave-4d research pass reported the source-exchange
  record sizes as 14/30/31. They are 12/28/29 - upstream's own size checks are
  literally `nCount*(4+2+4+2)[+16][+1]`. The agent's FIELD LIST was right and its
  SIZE COLUMN was wrong, and the two contradicted each other in the same table.
  Because SX1 resolves the record version BY PACKET SIZE, shipping the wrong
  numbers would have made padMule silently reject every real source-exchange
  answer on the network - a bug that would have looked like "source exchange just
  does not work" and been miserable to trace. A byte-exact test caught it in
  minutes, because the test asserted the LAYOUT (offsets and total length), not
  just that a round-trip succeeded. Rule: for any wire/file format, assert the
  actual byte offsets and sizes - a round-trip test alone would have passed here,
  since our writer and reader were consistently wrong together.
- 2026-07-14 **Upstream is a reference, not an authority.** Wave 4d found four
  genuine aMule 3.0.1 bugs in the subsystems it touched (see [[build-progress]]).
  Replicate-then-improve means replicating the WIRE, not the mistakes: where aMule
  and eMule disagree and eMule is right, follow eMule. Every such divergence is
  documented at its call site so it is never "fixed" back into a bug.
- 2026-07-14 **eMule 0.50a is the wire source of truth; CONFIRM every wire fix
  against it, not just aMule.** (Anthony reinforced this mid-Wave-4d.) padMule is
  an aMule PORT, so LOCAL POLICY (queue-score curves, credit thresholds, slot
  counts) follows aMule deliberately. But the WIRE - opcodes, byte layouts,
  guards, constants that other clients observe - is defined by eMule; aMule is
  just one implementation of it, and a buggy one in places. Workflow: derive a
  fix from whichever tree is clearest, then grep the OTHER tree to confirm the
  bytes match before banking it. Doing this on the 6 Wave-4d review fixes upgraded
  them from "cited aMule, probably fine" to "verified identical in eMule"
  (bounds guard, compressed opcodes + inflate, the 4_290_048_000 boundary). Note
  eMule's .cpp files have high-bit bytes - use `grep -a` or you get silent
  zero-hit false negatives.
- 2026-07-14 **A duplicated code path is a duplicated bug.** The Wave-4d review
  found the SAME panic and hang in BOTH download loops (transfer_session and
  multi_source) because the receive logic was copy-pasted. The fix extracted one
  hardened `BlockReceiver` both route through. When two places implement the same
  wire behaviour, factor it - or the next reviewer files the same finding twice.

## Related

- [[arch-upstream-amule]]
- [[ref-ecosystem]]
- [[build-progress]]
