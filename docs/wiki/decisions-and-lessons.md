# Decisions and Lessons

Updated: 2026-07-19

Locked decisions, rejected approaches, gotchas, measured facts. One dated
bullet each; Locked decisions newest first, Lessons in the order learned.

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
  (AS SHIPPED, 2026-07-18 revision: EC was deferred entirely - the iPad seam
  is in-process FFI, see [[build-progress]] wave 7. AICH recovery, IP filter,
  and categories did not make the shipped v1 either; they are open backlog,
  recorded here so the trim is explicit rather than silent.)

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
- 2026-07-14 **Advertise no capability you do not honour on the wire.** The
  amuled differential test caught, in its first successful run, a bug all 166
  padMule-to-padMule tests missed: we advertised `ExtendedRequestsVersion=2` in
  the hello but sent a bare `OP_REQUESTFILENAME`. aMule disconnects a client that
  claims extended requests then omits the payload (ProcessExtendedInfo,
  UploadClient.cpp:193). A SYMMETRIC peer (our own serve()) ignored the mismatch,
  so only the real implementation punished it. Two lessons: (1) capabilities and
  behaviour must be coherent - the receiver enforces what you advertise; (2) the
  differential test against the real client is not optional polish, it is the
  only oracle that catches mistakes we make identically on both ends (same class
  as the SX record-size error). Diagnosis tip: when the real client's own debug
  logging won't cooperate, trace the wire from our side (`mule-cli peer-probe`) -
  the packet sequence + close point localises the fault faster than the source.
- 2026-07-16 **On eD2k, completion is a source-availability hunt, not a protocol
  problem.** Once the wire was proven (Wave 4 differential vs amuled), getting
  three real files to finish was entirely about HOW we pick files and spend time -
  all client-side, zero wire change. Five things mattered, each learned from a
  failed run: (1) earn HighID (bind a listener during login) - it is the key that
  unlocks the whole LowID source pool via OP_CALLBACKREQUEST; 2 of our 3 files came
  from firewalled LowID peers dialing us back. (2) Fast-bail an upload queue
  (OP_QUEUERANKING -> `TransferError::Queued`) - sitting in a queue is dead time
  for a hunt; a real background client would wait, we move on. (3) A keyword can be
  SATURATED by one sharer's collection (200 "wav" results from a single IP), so
  sweep DISTINCT sharers (skip files whose only source is an already-stalled IP)
  and use `min_size` to filter a collection out of the result cap. (4) NEVER
  abandon an in-flight callback: wait while bytes are still arriving, and give each
  candidate its own part directory - a fixed short wait + shared `001.part` once
  delivered a full 5.9 MB file and then clobbered it. (5) Size-adaptive per-peer
  timeouts (tiny files sweep fast, larger files pull sustained). The reusable
  principle, consistent with replicate-wire/improve-internals: the wire stays
  stock; the intelligence is in selection and scheduling. See [[build-progress]]
  three-file milestone.
- 2026-07-16 **The differential test catches your OWN optimizations, not just
  missing features.** Building the padMule enhancement channel, the amuled
  differential test flagged a regression I had introduced earlier: my queue
  fast-bail (`TransferError::Queued` on OP_QUEUERANKING) was UNCONDITIONAL, so the
  single-source `peer-download` aborted the moment amuled rationed its upload slot
  - the 2nd and 3rd files failed while the 1st (served immediately) passed. A
  padMule-to-padMule test never sees this because our own `serve()` grants a slot
  at once; only a real client that RATIONS uploads exposes it - the same class as
  the Wave-4d extended-requests bug. Fix: make fast-bail a policy - the
  multi-source hunt bails (it has other sources), a single dedicated source waits
  in the queue like a normal client (`download_from_peer(.., bail_on_queue)`).
  Lesson: an optimization that helps one caller can silently break another that
  shares the code path; re-run the real-peer differential gate after ANY transfer
  change, not just feature work. See [[padmule-enhancement-channel]].
- 2026-07-16 **DECISION: build Layer 1 of the enhancement channel, DEFER Layer 2 +
  NAT traversal until there is an install base.** Every enhancement the channel
  could carry works ONLY padMule<->padMule, so its value is 100% gated on padMule
  adoption; on today's ~all-stock network a padMule user almost always talks to a
  stock peer where Layer 1 returns None and Layer 2 never fires. Goal is mass
  adoption (Anthony, 2026-07-16), which is a chicken-and-egg: no value from
  peer-to-peer features until padMule HAS peers, and you get peers by shipping a
  good client - so building Layer 2/NAT traversal now is a speculative feature
  (violates the CLAUDE.md "no speculative features" rule). What we KEEP: Layer 1
  detection (tiny, safe, done - deploys the recognition marker early so capability
  accrues across the install base for free) and the research (cheap; de-risks
  Layer 2 + NAT traversal to a few days of ready work - [[padmule-enhancement-channel]],
  [[nat-traversal-design]]). NEAR-TERM PRIORITY REDIRECTED to adoption drivers,
  all single-user-valuable on day one: the iPad app (Wave 8 - the entire value
  prop, there is no aMule on iPad), on-device HighID (UPnP/NAT-PMP -
  [[net-highid-and-port-forwarding]]), and the already-landing fetch/search/trust
  quality. Revisit Layer 2 when real padMule<->padMule traffic exists.
- 2026-07-18 **DECISION: upload queueing is scoped to the held connection, not a
  desktop-style persistent queue.** At capacity padMule now queues a leecher and
  sends OP_QUEUERANKING, granting a freed slot IN PLACE on the connection it
  already holds open. It deliberately does NOT implement eMule's cross-connection
  queue persistence, slot-grant dial-out (uploader connects back to an idled
  HighID downloader), or UDP OP_REASKFILEPING refresh. Those exist because a
  desktop client is always-on and a queued peer idles its TCP out after 40s;
  padMule is FOREGROUND-ONLY ([[ipados-constraints]]) - its sockets and the app
  itself die on background - so a long-lived queue would be dishonest. Holding
  the connection and granting in place is faithful on the wire (correct opcode +
  12-byte payload) and fits the platform. Rank is FIFO; eMule's score-ordering
  ([[build-progress]] upload_queue.rs scoring) is wire-neutral policy for later.
- 2026-07-18 **LESSON: re-review any change that reshapes a hot path; "moved the
  check" == "removed the check" until proven otherwise.** The same-day adversarial
  review of the code-fix round found 8 real bugs the 383-test suite AND the amuled
  differential test both missed - several REGRESSIONS. The worst: moving the upload
  slot check out of connection-admission (old `serve_inbound`) into the
  OP_STARTUPLOADREQ arm silently left the OP_REQUESTPARTS path ungated, so a peer
  that skipped the upload request streamed full-file data past the 8-slot cap and
  the whole queue; and the same move left idle pre-upload sessions unbounded. Both
  are "I relocated a guard and didn't re-establish it on every path it used to
  cover." The differential test could not catch them because it exercises the
  DOWNLOAD direction, not serve. Rules: (1) when you move a check, enumerate every
  code path the old placement covered and confirm the new one still does; (2) a
  feature that reshapes a hot path (the serve loop, the fetch manager) earns an
  adversarial review even when the test suite is green - the tests encode the paths
  you thought of, the review hunts the ones you didn't; (3) a green oracle that only
  drives one direction is not coverage of the other.
- 2026-07-18 **LESSON: verify a "hardening" idea against the wire authority BEFORE
  writing it - replicate-then-improve cuts both ways.** The 2026-07-18 lint flagged
  two "candidate hardening" items (sanitize a peer's crypt bits so requires implies
  supports; buffer a secure-ident signature that arrives before the pubkey).
  Checking eMule 0.50a first showed BOTH padMule behaviors were ALREADY faithful and
  the "fix" would have DIVERGED from the wire: eMule reads the crypt bits raw
  (SetConnectOptions, BaseClient.cpp:3190-3192) with reject/obfuscate predicates
  byte-identical to ours (:1437/:1647), and it DROPS a signature that arrives before
  the pubkey (ProcessSignaturePacket, BaseClient.cpp:2133, returns when
  GetSecIDKeyLen()==0). The lint's own doc comments (written the same day) had
  mis-framed faithful behavior as bugs. Rule: for anything a peer observes, a
  proposed improvement is a HYPOTHESIS until checked against eMule - "more robust"
  and "interoperable" are not the same, and diverging silently breaks interop the
  way the SX/extended-requests bugs did, just in the other direction. Same spirit as
  the "agent-derived constants are a hypothesis" lesson above.
- 2026-07-19 **LESSON: never ship an interop feature validated only by a mock that
  plays the WRONG role - a false-positive test is worse than no test.** The
  "verified-identity" secure-ident feature shipped GREEN (its unit test passed) and
  was REVERTED the next commit after an adversarial review found a HIGH deadlock.
  Root cause: padMule ran secure-ident as a post-transfer INITIATOR while advertising
  sec_ident=0, so a real uploader never initiated and padMule hung the full 8s
  timeout on EVERY delivering source (never verifying, delaying completion). The unit
  test passed only because BOTH mock ends called `run_secure_ident` as initiators - a
  synthetic exchange no real serve peer performs. The original instinct to DEFER (it
  could not be integration-tested) was correct and was overridden by a
  green-but-synthetic test. Redone correctly (advertise sec_ident so the uploader
  initiates; RESPOND inline; never wait - #4/#32) and validated the RIGHT way: a mock
  uploader that INITIATES, plus the amuled differential proving "verified: true"
  against real aMule. Rules: (1) test an interop feature against a FAITHFUL
  other-side - the real peer (the amuled/eMule/eserver oracles) or a mock that plays
  the peer's ACTUAL role, NEVER both-ends-same-role; (2) if no faithful test is
  possible, DEFER and say so - do not ship on a false positive; (3) the reverted
  commit is far cheaper than the shipped bug. Cross-session memory:
  interop-test-fidelity. Enabled by the [[build-progress]] oracle set (amuled peer,
  real eMule peer [[emule-peer-oracle]], real eserver server [[ed2k-server-oracle]]).

## Related

- [[arch-upstream-amule]]
- [[ref-ecosystem]]
- [[build-progress]]
