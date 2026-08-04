# HANDOFF - start here next session

Updated: 2026-08-03 (one very long session: reanalysis -> doc-drift round ->
OP_GETSERVERLIST -> the RECURSIVE UDP CRAWL -> server names -> the SEVEN-BUG
USAGE-FEEDBACK ROUND -> VPN readiness -> on-glass fixes. Everything below is
verified, not assumed, and what is NOT verified says so.)

Living doc: replace it wholesale next time. Full narrative in [[build-progress]]
rows 8av-8bi + the [[log]] entries for 2026-08-03.

## State of the tree

- All work committed AND pushed; tree clean; branch even with origin/main at
  **d7d555a**.
- **Gate**: 564 Rust tests, clippy WARNING-FREE, fmt clean, ASCII clean.
- CI: all three workflows GREEN on the last code commit.
- ALL FOUR ORACLES re-run and PASS after the serve-path change: amuled
  differential (byte-for-byte, 3 files), the REVERSE oracle (real amuled
  downloads FROM padMule + serve-side secure-ident), the isolated eserver
  login, and the Kad verify oracle.
- [[security-model]] scorecard unchanged: **23 OPERATIONAL / 1 PARTIAL / 2
  documented opt-outs**. The PARTIAL is AICH block recovery (wave 11).
- Latest build staged for install:
  `C:\Users\ajbuf\Downloads\padMule-INSTALL-THIS-unsigned-d7d555a.ipa`.

## THE HARD DEADLINE

**The free signing cert + provisioning profiles EXPIRE 2026-08-10.** After
that, no new build installs until renewed via Sideloadly (Apple ID auth, App
ID + device registration, cert issuance), then re-pull the profile with
`ideviceprovision copy`.

## Where things actually stand

**The app is in daily-driver shape.** Anthony's first extended usage session
produced 18 items; four parallel investigations turned them into SEVEN
confirmed bugs (8bb), all fixed TDD-first and mutation-checked, plus the whole
UI batch (8bg). Two findings are worth carrying forward as lessons:

1. **Resume was broken - and ONLY when Kad was HEALTHY.** `find_sources` joins
   its server and Kad arms so it returns in max(), and the Kad arm carries a
   15s budget; `resume_fetches` wrapped the call in a 4s timeout that DISCARDED
   everything, including server sources that had already arrived. `add_download`
   calls the same function with no outer timeout, which is why adding worked and
   resuming did not. Now bounded per-arm so partial results always survive.
2. **Phantom shared files** - a file deleted in the Files app was still
   announced, answered "COMPLETE" to peers, given an upload slot, then dropped
   the connection. Verified at the serve path plus a 60s prune.

**VPN readiness is complete but UNPROVEN.** Anthony is moving padMule behind
AirVPN. Ports are configurable (listen vs ADVERTISED - they differ under
remote-to-local forwarding), UPnP can be switched off, and a public-address
CHANGE pauses sharing and warns loudly, since stock iOS has no kill switch.
See [[net-highid-and-port-forwarding]] for the AirVPN specifics, including
that **port 4662 is NOT obtainable** (another subscriber holds it), which is
what turned the port override from a nicety into a prerequisite.

## Open tasks (ranked)

1. **Prove the VPN path on device.** The AirVPN side is DONE: port 5999
   reserved, TCP+UDP, All devices, "Local" cleared for same-port forwarding,
   and the app now DEFAULTS all three ports to 5999. Remaining: UPnP off,
   RESTART padMule (ports bind when the listener starts). Then AirVPN's Test open (only meaningful
   with padMule running) and Status -> HighID. Expect the public-address guard
   to fire once as the tunnel comes up; that is correct.
   KNOWN LIMIT: the advertised/listen split covers the TCP port only - Kad's
   UDP port is a single value used for both bind and advertise, so a
   remote-to-local REMAP would break Kad's inbound reachability. Same-port
   forwarding sidesteps it. Add a fourth field only if a remap becomes
   necessary.
2. **Device-verify what the photos have not shown**: the resume fix (needs a
   background/foreground cycle with an active download - the headline fix of
   the whole session), the Downloaded tab's QuickLook Open, and the
   metered-sharing pause (needs a cellular link).
3. **Get blocking engine calls OFF the one serial queue** - the biggest
   remaining structural risk. "Reconnecting..." still cannot render; pause()
   starvation is MITIGATED (background-task assertion + refresh in-flight
   guard) but not eliminated; a ~10s crawl and ~20s search still freeze the UI.
   The periodic re-drive and share-verify were both kept deliberately small for
   exactly this reason.
4. **Remaining Tier 2** ([[portability-audit]]): NAT-PMP is dead code in the
   engine; the 4s offer_files timeout silently drops uploads on a slow link; no
   bandwidth limiting anywhere.
5. **Settings Tier 1/2 engine work** - nickname (hardcoded "padMule"),
   obfuscation policy tri-state, ipfilter controls, upload slots, bandwidth
   caps (`upload_queue.rs` holds dead kbps logic to revive-or-delete),
   See-My-Shared-Files.
6. **AICH block recovery** (wave 11, the last scorecard PARTIAL).
7. **Continuous block-request top-up** - padMule is stop-and-wait per 3-block
   batch, shallower than both authorities; no wire change, big win at cellular
   RTT. (Also why keep-awake watches a WINDOW of rate samples: a batch boundary
   legitimately reads zero.)
8. **Smaller open items**: harvest queue lost if the server.met write fails; no
   thin-file guard on nodes.dat writes (aMule refuses < 25 contacts); the
   related-search fallback pollutes Recent Searches; Settings accepts https://
   list URLs the engine rejects (http-only); the kick alert may not surface
   while a sheet is open; `hash-file` exits 0 on failure and two oracle scripts
   consume it without `-e`; MSRV declared but unenforced in CI.

## Discipline reminders that earned their keep THIS session

- **User testing finds what tests cannot.** One real session produced seven
  bugs that a green 550-test suite, clean clippy and four passing oracles had
  all missed - including a resume path that only worked when Kad was BROKEN.
- **A test can reach the right CALLER and still not exercise the MECHANISM.**
  Two resume tests passed with the fix deleted. MUTATION-CHECK anything
  load-bearing; if it stays green it is decoration. Now standard practice.
- **A fake fixture hides a missing check.** Nine serve tests used
  `/does/not/matter` as a shared-file path; adding the correct disk check broke
  all nine, which WAS the check working. They now write real files.
- **Verify the RENDERED result, not the source.** The title-bar literal decoded
  correctly as a Swift string and still rendered wrong, because
  `.navigationTitle` reinterprets a literal as a LocalizedStringKey. Read the
  compiled binary, or the screen.
- **Ordering bugs are invisible to CI.** The port override shipped INERT
  because `boot()` applied settings after `start()`; it compiled, the suite
  stayed green, and only reading the call sequence caught it.
- **Attach global UI at the root.** The Stop confirmation lived on the Status
  screen, so the new toolbar button would have silently done nothing anywhere
  else.

## Related

- [[net-highid-and-port-forwarding]] - HighID, the AirVPN setup, the kill-switch gap.
- [[portability-audit]] - Tier 2/3 open work.
- [[ipad-usb-tooling]] - device runbook; NB `unbind` (not `detach`) frees the
  iPad for Sideloadly on this box.
- [[build-progress]] / [[security-model]] / [[log]] / [[feature-server-hunter]].
