# HANDOFF - start here next session

Updated: 2026-08-04, close of the instrumentation session.

Living doc - replace it wholesale next time. Full narrative: [[build-progress]]
rows 8bt-8bx and the [[log]] entries for 2026-08-04.

## State of the tree

- **Gate**: 618 Rust tests, clippy `-D warnings` clean, fmt clean, ASCII clean.
- **YOU ARE ON BRANCH `fetch-funnel`, NOT main**, and nothing is merged. Decide
  that first. History is LINEAR across 390+ commits and must stay that way
  (`gh pr merge --rebase`). Do not trust prose for counts - run
  `git log --oneline main..HEAD` and `git log --oneline origin/main..main`.
- Oracles: amuled differential re-run GREEN after every transfer-path change
  today. REVERSE / eserver / Kad-verify not re-run this session.
- **Installed on the iPad: `f82ee7e`.** iPadOS 26.6. Cert lapses ~2026-08-11.
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

**3. `skipped: source BANNED` / `skipped: fetch already running`** - the two
in-memory gates a RESTART clears (see open item 1).

**4. The dial-time histogram**, split by whether the handshake succeeded.

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
7. **UI round**: dark `Color.bannerBlue`, ALL banners closeable, server list on
   APP open, finish BEEP (typed `Finished` event, not a match on prose),
   full-width rate chart, Stop first in the toolbar, "Name (ip:port)" on the
   Servers tab.

## OPEN - named as open, not explained

1. **The stall whose blocker a RESTART clears.** Anthony's clue and the best
   lead of the day: a file sat at 85%, the app was restarted, it finished. That
   rules out disk, network and the swarm, and leaves exactly two in-memory gates
   - the per-download **ban set** (a HashSet, never persisted, consulted BEFORE
   dialing, so a download that banned its handful of sources makes ZERO dials
   while still listing them) and the **`fetching` flag** (the retry sweep skips
   any download holding it). BOTH ARE NOW COUNTED. The next stall should name
   itself; do not guess between them. NOTE a restart also CLEARS both, so the
   counters need a fresh stall to develop before they mean anything.
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
6. **padMule's serve side never rotates an upload slot**: `should_kick()` and
   `build_out_of_part_reqs()` are BOTH dead code. Mirror image of shipped fix 1.
7. Kad gave ZERO sources across 25 dev-box downloads but DID on device.
8. Status scalars lag behind `Engine::search`'s ~20s `&mut self`; Portability
   Tier 2; Settings Tier 1/2; ten merged branches still on origin plus a stale
   worktree at `.claude/worktrees/wave11-aich`.

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
  connect cap is free" was true on the dev box and false over the VPN, where
  real connections land at 20-45s. padMule ships on the VPN path.
- **Reasoning is not measurement, even when it is mine.** `Get`'s 15s and the
  queue-bail "root cause" were both argued rather than measured, and both wrong.
- **Sampling too early is not a failed fix** - the Servers tab read 0 three
  times because `start()` still held the engine lock.
- **A green oracle proves only the path it drives.** The differential test moves
  15MB, past the 10MB kick, and still never saw 0x57 - loopback is faster than
  amuled's timer.
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
