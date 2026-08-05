# HANDOFF - start here next session

Updated: 2026-08-05, after the reanalysis + serve-side rotation pass.

Living doc - replace it wholesale next time. Full narrative: [[build-progress]]
rows 8bt-8by and the [[log]] entries for 2026-08-04 and 2026-08-05.

## State of the tree

- **Gate**: 622 Rust tests, clippy `-D warnings` clean, fmt clean, ASCII clean.
- **YOU ARE ON BRANCH `fetch-funnel`, NOT main**, and nothing is merged. Decide
  that first. History is LINEAR across 390+ commits and must stay that way
  (`gh pr merge --rebase`). Do not trust prose for counts - run
  `git log --oneline main..HEAD` and `git log --oneline origin/main..main`.
- Oracles: differential AND reverse both re-run GREEN 2026-08-05. Kad-verify not
  re-run. NOTE what the reverse oracle does NOT cover: `mule-cli serve-file`
  passes no upload gate and its fixture is 300KB with one downloader, so it
  never drives the slot rotation (8by). A green oracle proves only the path it
  drives - the third time that has mattered.
- **Latest IPA delivered: `d24e88d`** (2026-08-05, CI run 30979781242), current
  with the branch. iPadOS 26.6. Cert lapses ~2026-08-12.
- **The device can now name its own build.** CI stamps the git short sha into
  `CFBundleVersion`, and Settings > This device > **Build** reads
  "1.0 (d24e88d)", selectable. Verified in the delivered artifact. Confirm an
  install by READING that row, not by spotting a UI change.
- Both iOS workflows re-run green on this branch: the .ipa build and the Swift
  simulator tests (21 tests). The Swift tests are the ONLY type-check available
  from this box - dispatch `ios-test.yml` after any Swift edit.
- IPAs go to `/mnt/c/Users/ajbuf/Downloads/` as
  `padMule-INSTALL-THIS-unsigned-<sha>.ipa` ([[padmule-ipa-delivery]]).

## THE POINT OF THIS SESSION: instruments, not guesses

Three rounds of theory had failed on "downloads stall". Building the instrument
took under an hour and answered it in one run. **Read these before theorising.**

**1. The fetch funnel** (`mule_engine::stats`; Stats -> Fetch diagnostics, with
Copy report and Reset counters; also printed by the stress harness). Cumulative
per-stage counts of how far each PEER SESSION got. The DROP between two adjacent
stages is the loss at that stage - **including a loss to a TIMEOUT, which no
error value can report.** Both FFI methods are LOCK-FREE by design: a stall is
exactly when the engine is busy. Counters are cumulative since launch, so the
workflow is **reset -> reproduce -> read**.

**2. "N parts missing from all M sources"** on each transfer row. Parts still
needed that not one sampled peer offered. Separates a SLOW tail from an
IMPOSSIBLE one - identical on a row reading "90%, 86 sources, not moving".
Gated at 4 sampled statuses; the sample size is in the text on purpose.

**3. `skipped: source BANNED`** - the in-memory gate a RESTART clears, and the
standing lead (see open item 1). Its sibling `skipped: fetch already running`
was CORRECTED 2026-08-05: it sat behind callers that already filter
`!is_fetching()`, so it read 0 in exactly the stuck-flag case it was built for.
It is now labelled `spawn raced a live fetch`, and the durable state is read
instead from the **`fetches in flight` GAUGE** under `STATE (not reset)`.

**4. The dial-time histogram**, split by whether the handshake succeeded - but
it is now CENSORED by the 10s cap its own reading justified. Every bucket above
10s is structurally dead; "20-45s: 0" is the cap talking, not the network.
Re-measuring on another path means raising `fetch::CONNECT_TIMEOUT` first.

## Shipped

1. **`OP_OUTOFPARTREQS` (0x57) had no handler** - the ordinary end of every
   upload slot (10MB or 1h; eMule UploadClient.cpp:722-725/:767-782, aMule
   UploadClient.cpp:463-466, UploadQueue.cpp:609-616). padMule waited out the
   45s per-peer timeout holding 1 of only 4 workers.
2. **Slots asked of peers holding nothing we need** - eMule sets
   DS_NONEEDEDPARTS and swaps away without asking (DownloadClient.cpp:634-641).
3. **The empty Servers tab was a bootstrap bug**: `ensure`'s guard was
   `exists && len > 0`, and LENGTH IS NOT USABILITY. Reachable normally - prune
   the last dead server and that is the file you get.
4. **The dial got its own 10s deadline** (was sharing the 45s session budget).
5. **`Get` was a flat ~15s**, now ~200ms when the server answers.
6. **The funnel counted two entry paths as one**, reporting more file statuses
   than handshakes - impossible. Inbound (called-back) sessions now counted
   separately.
7. **UI round**: banners at **#000066** and FLAT (see below), ALL banners
   closeable, server list on APP open, finish BEEP (typed `Finished` event, not
   a match on prose), full-width rate chart, Stop first in the toolbar,
   "Name (ip:port)" on the Servers tab.
8. **The banner colour took three attempts, and the value was never the
   problem.** `.gradient` lightens the top of whatever tint it is given, so the
   colour named at the call site was never the colour on the glass. Removing it
   - which is what `banner`'s doc had always claimed it did - fixed what two
   rounds of re-picking the shade could not. **When a value is repeatedly
   "wrong", check for a TRANSFORM between declaration and render before picking
   another value.**
9. **(2026-08-05) The SERVE side rotates its slot** - was open item 6, and it
   was the mirror of shipped fix 1. padMule held a granted slot for the whole
   connection, so the first peer to win one kept it and everybody else timed out
   at `QUEUE_WAIT` and was closed. Now kicked at 10MB/1h **only when somebody is
   waiting** (eMule's anti-churn rule; aMule has none - divergence recorded both
   sides), and the rotation clears the re-send dedup because upstream does and
   because otherwise padMule's own downloader hangs for 45s. Row 8by.
10. **(2026-08-05) Two instrument corrections** - `skipped: fetch already
    running` could not observe a stuck flag (see instrument 3 above), and the
    parts badge said "sources" for a count of SESSIONS. Row 8by.

## OPEN - named as open, not explained

1. **The stall whose blocker a RESTART clears - now NARROWED to the ban set.**
   Anthony's clue: a file sat at 85%, the app was restarted, it finished. That
   rules out disk, network and the swarm and leaves in-memory state. Of the two
   candidate gates, the per-download **ban set** is the live hypothesis: a plain
   `HashSet<IpAddr>`, extended on corruption, **never lifted anywhere in the
   code** and never persisted, consulted BEFORE dialing - so a download that
   banned its handful of sources makes ZERO dials while still listing them.
   `skipped: source BANNED` is correctly placed to catch it. The **`fetching`
   flag** is the weaker candidate on two counts: `FetchGuard` releases it on any
   task exit including unwind and `download_file` is bounded on every axis, so a
   stuck flag should be unreachable - and that is an ARGUMENT, which is why the
   `fetches in flight` gauge now exists to refute it. Do not read `spawn raced a
   live fetch` as evidence either way. A restart clears the ban set too, so the
   counter needs a FRESH stall to develop before it means anything.
2. **"No completions" is PARTLY answered, and the answer was the swarm** - the
   two non-moving files were exactly the two carrying the parts-missing badge,
   one at Zero KB with 24 parts, another capped near 50% by 13 parts (~120MB).
   padMule was correct. This does NOT close item 1.
3. **Device and dev box DIVERGE** on the same server at the same minute; the
   difference is the VPN path. Measure with the on-device funnel.
4. **`slot REVOKED (0x57)` has never fired live** - a many-source file gives
   each peer ~2MB, far under the 10MB kick. Test-proven only; needs a file with
   few, fast sources.
5. **Nothing evicts a proven-dead source** from `download_file`'s pool -
   `PeerScoreboard` only re-ORDERS - so a dead peer is re-dialed 8x per sweep
   and again per retry.
6. ~~padMule's serve side never rotates an upload slot.~~ **CLOSED 2026-08-05,
   row 8by** - see shipped item 9. Note the follow-on: the rotation has never
   run live either, for the same reason item 4 has not.
7. Kad gave ZERO sources across 25 dev-box downloads but DID on device. **Partly
   self-inflicted, and unmeasured:** since the Get fix, `find_sources` returns on
   the first NON-EMPTY server answer, so the Kad arm is skipped entirely whenever
   the server names even one source (all three callers pass
   `stop_when_server_answers = true`). The ~15s -> ~200ms win is measured; the
   narrower source pool is NOT, and it sits directly against "downloads run short
   of live sources". A count threshold, or letting the Kad arm land into the
   mid-sweep `take_sx_sources` channel that already exists, would keep both.
8. Status scalars lag behind `Engine::search`'s ~20s `&mut self`; Portability
   Tier 2; Settings Tier 1/2.
9. **Housekeeping, verified safe 2026-08-05:** ELEVEN remote branches (not ten)
   are fully merged - `git cherry main origin/<b>` reports every commit
   patch-equivalent for all of them, including `worktree-wave11-aich` - so they
   and the locked worktree at `.claude/worktrees/wave11-aich` can be deleted.
   `main` is also 4 commits ahead of `origin/main`, unpushed.

## Discipline this session actually paid for

- **When two theories have failed, stop and build the instrument.** It refuted
  my own fresh hypotheses THREE times: the 0x57 handler was genuinely missing
  yet SECONDARY; the small-file reservation theory was half wrong; and the
  needed-parts gate looked like a regression until the control cleared it.
  **Citing the upstream source line proves the code is wrong, not that it is
  what is hurting you.**
- **A zero-result test is not a failing test until the CONTROL runs.**
- **An instrument's first duty is to measure itself.** The funnel's own
  arithmetic was impossible (396 statuses from 315 handshakes), and the parts
  badge shipped OVERSTATING its evidence - a real measurement inflated into a
  claim about the network, from a sample of one.
- **A threshold tuned on one network is a hypothesis about the others.** "A 5s
  connect cap is free" was true on the dev box (75 of 76 handshakes under 1s)
  and false over the VPN, which had a real tail: of 315 successful handshakes,
  one landed at 5-10s and TWO at 20-45s. 10s keeps 313 of 315. padMule ships on
  the VPN path. [CORRECTED 2026-08-05: this line used to read "real connections
  land at 20-45s", which says the BULK do - and read that way the shipped 10s
  cap looks like a serious regression. It was chased as one before [[log]]
  2026-08-04 refuted it. The measurement was right; the compression was not, in
  the one document the next session reads first. **A summary that overstates its
  own evidence costs the next session real time.**]
- **Reasoning is not measurement, even when it is mine.** `Get`'s 15s and the
  queue-bail "root cause" were both argued rather than measured, and both wrong.
- **Sampling too early is not a failed fix** - the Servers tab read 0 three
  times because `start()` still held the engine lock.
- **A green oracle proves only the path it drives.** The differential test moves
  15MB, past the 10MB kick, and still never saw 0x57 - loopback is faster than
  amuled's timer. Third instance 2026-08-05: the REVERSE oracle went green over
  the new slot rotation without executing one line of it, because `mule-cli
  serve-file` passes no upload gate and the fixture is 300KB with one downloader.
  **Before citing an oracle as proof, name the path it drove.**
- **(2026-08-05) An instrument can be placed where it cannot see.** `skipped:
  fetch already running` was correct code counting a real event at a point every
  caller had already filtered past - so it read 0 in exactly the case it was
  built to name. Being lock-free, cheap and correct is not the same as being
  OBSERVABLE. Check the call graph ABOVE a new counter, not just the line it
  sits on.
- **(2026-08-05) The same overstatement twice in one instrument.** The parts
  badge was corrected on 2026-08-04 for inflating a one-peer sample into a claim
  about the swarm, and the correction then called its sample "sources" when it
  counts SESSIONS. A fix aimed at honesty is not automatically honest.
- **DEVICE: only session-free reads are safe during a live run.**
  `GET /source` and `pymobiledevice3 developer dvt screenshot` disturb nothing;
  creating ANY WebDriverAgent session - even with empty capabilities -
  backgrounds padMule and pauses every transfer. Learned by doing it.
- **Swift type-checks ONLY in CI here.** Verify a new binding with
  `uniffi-bindgen` against the compiled cdylib BEFORE pushing, and expect the
  type-checker to give up on a view with five conditional branches.
- **`strings` on the .ipa can FALSE-NEGATIVE** - Swift stores <=15-byte strings
  inline. Pick longer markers.
- **The WDA search field CONCATENATES**: the clear "x" is an 18pt button at the
  RIGHT EDGE of the field, and typing must go through `element/{id}/value`.
  Read the field back before searching.

## Related

- [[build-progress]] / [[security-model]] / [[log]] / [[decisions-and-lessons]]
- [[padmule-ipa-delivery]] - the build-and-deliver loop.
- [[ipad-usb-tooling]] - device runbook, incl. the read-only rule above.
- [[net-highid-and-port-forwarding]] - the AirVPN Local-port trap.
- [[lifecycle-and-reactivation]] - foreground-only, permanent.
