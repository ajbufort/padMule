# HANDOFF - start here next session

Updated: 2026-08-04, close of the instrumentation + on-glass session.

Living doc - replace it wholesale next time. Full narrative: [[build-progress]]
rows 8bj-8bw and the [[log]] entries for 2026-08-03/04.

## State of the tree

- **Gate**: 617 Rust tests, clippy `-D warnings` clean, fmt clean, ASCII clean.
- **YOU ARE ON BRANCH `fetch-funnel`, NOT main.** Ten commits ahead of main, all
  pushed. `main` itself is still 4 commits ahead of `origin/main` from the
  previous session. Nothing has been merged - decide that first
  (`gh pr merge --rebase`, history is LINEAR across 390+ commits and must stay
  that way). Do not trust prose for commit counts; run
  `git log --oneline main..HEAD` and `git log --oneline origin/main..main`.
- [[security-model]]: **24 OPERATIONAL / 0 PARTIAL / 2 documented opt-outs**.
- Oracles: amuled differential re-run GREEN after the transfer-path changes
  (3 files byte-for-byte, incl. the 15MB multipart). REVERSE / eserver / Kad
  verify not re-run this session.
- **Latest IPA delivered: `d1f058f`** (branch head). Device on iPadOS
  **26.6**. Cert re-signed 2026-08-04, lapses about **2026-08-11**.
- IPAs are delivered to `/mnt/c/Users/ajbuf/Downloads/` as
  `padMule-INSTALL-THIS-unsigned-<sha>.ipa` ([[padmule-ipa-delivery]]).

## THE FETCH FUNNEL - now on the device. Use it before theorising.

`mule_engine::stats` counts how far down the eD2k request sequence each PEER
SESSION got, plus every opcode read out of turn and a dial-duration histogram.
The DROP between two adjacent stages is the loss at that stage - **including a
loss to the per-peer TIMEOUT, which no error value can report.** That is why
this gap survived three rounds of reasoning.

- **On the device**: Stats -> Fetch diagnostics, with **Copy report** and
  **Reset counters**. Counters are cumulative since launch, so the workflow is
  **reset -> reproduce -> read**, then Copy and paste the block.
- **On this box**: `cargo run --release -p mule-ffi --example stress -- /tmp/cfg /tmp/dl linux 12 300`
- Both FFI methods are LOCK-FREE by design (process-global atomics, never the
  engine lock) - a stall is exactly when the engine is busy.

## Fixed this session

1. **`OP_OUTOFPARTREQS` (0x57) had no handler.** The ordinary end of every
   upload slot - both authorities send it when `CheckForTimeOver()` trips at
   10 MB or 1 hour (eMule 0.50a UploadClient.cpp:722-725/:767-782, aMule master
   UploadClient.cpp:463-466, UploadQueue.cpp:609-616). padMule waited out the
   caller's 45s timeout holding 1 of only 4 workers.
2. **Asking a slot of peers holding nothing we need.** eMule sets
   DS_NONEEDEDPARTS and swaps away without asking (DownloadClient.cpp:634-641).
3. **The empty Servers tab was a bootstrap bug.** `ensure`'s guard was
   `exists && len > 0` - length is not usability, so a `server.met` that parsed
   to ZERO servers was "already present" forever. Reachable normally: prune the
   last dead server and that is the file you get.
4. **The funnel counted two entry paths as one**, so it reported more file
   statuses than handshakes - impossible. A called-back source dials US and
   never passes `fetch_one`. Inbound sessions are now counted separately.
5. **The dial got its own 10s deadline** (see MEASURED below).
6. **On-glass UI round** (row 8bw): dark `Color.bannerBlue`, ALL banners
   closeable, server list on APP open, a finish BEEP (typed `Finished` event,
   not a match on prose), a full-width rate chart, Stop first in the toolbar,
   and "Name (ip:port)" on the Servers tab via a shared `serverLabel()`.

Items 1-3 test-first with RED observed, 2 of them mutation-checked.

## MEASURED - and one number that CHANGED once the device spoke

**The dial now has its own 10s deadline (SHIPPED).** The dev box argued for far
less: of 76 successful handshakes, 75 landed under 1s and one at 1-2s, with NOT
ONE connecting after 2s, while 57 dials burned the full 45s and all failed. So
"a 5s cap is free" looked safe.

**The iPad refuted the word "free".** Over the VPN the slow tail is REAL - one
connection at 5-10s and TWO at 20-45s, out of 315:

```
              dev box            iPad (VPN)
0-1s          75 ok / 166 fail   274 ok / 239 fail
1-2s           1 / 5              31 / 25
2-5s           0 / 22              7 / 5
5-10s          -                   1 / 14
20-45s         0                   2 / 0     <- real, and a 5s cap kills them
>=45s          0 / 57              0 / 63
```

Settled at **10s**: keeps 313 of 315 (99.4%) and still kills the 63 dials that
each burned 45s. LESSON: a threshold tuned on one network is a hypothesis about
the others; padMule ships on the VPN path, so that is the one that decides.

**Still true and still unfixed: nothing ever evicts a proven-dead source** from
`download_file`'s pool - `PeerScoreboard` only re-ORDERS - so a dead peer is
re-dialed 8x per sweep and again on every retry.

## OPEN - and named as open, not explained

0. **"Much download activity but NO completions" (Anthony, on the fixed build).**
   Leading candidate is the TAIL, and the funnel already points at it:
   `accepted, no block to take` was **84 of 194** granted slots (43%). Four
   workers x 3 blocks x 184320 = **2.11MB** can be under reservation at once,
   while `ENDGAME_LIMIT` only races the last **737KB** - so a nearly-finished
   file can have its whole remainder held by a few workers while every OTHER
   source that wins a slot is turned away with nothing to do. If those holders
   are slow or die, the tail never lands. NOT confirmed. The on-device funnel
   settles it: let a download get near the end, then Copy report and look at
   whether `accepted, no block to take` climbs while nothing completes. The
   likely fix is widening the endgame window so the tail is RACED, not hoarded.
1. **The device and this box DIVERGE on the same server at the same minute.**
   Dev box: 7 of 12 downloads receiving, one at 147MB, 42 delivering sessions.
   iPad at the same time: two files crossed 10MB then froze for 9 minutes with
   **ZERO sources**, and three 2-2.4GB ISOs (6-7 full srcs claimed) never
   registered at all - while Connected/HighID/Kad-138 the whole time. The
   difference between the two is the **VPN path**. MEASURE IT with the on-device
   funnel now that it exists; do not assume.
2. **`slot REVOKED (0x57) = 0` in all three runs.** No source has yet fed
   padMule 10MB in one session, so that fix is TEST-proven only. Hunting it
   needs large, genuinely well-seeded content (and note the documented trap:
   Blender open movies are not on eD2k at all).
3. **Kad contributed ZERO sources across 25 dev-box downloads** - but DID
   contribute on the device. Possibly dev-box-specific.
4. **`accepted, no block to take`** was 6-of-7 pre-fix and 0 in the control, but
   12-of-17 in one run. The reservation arithmetic (4 workers x 3 blocks x
   184320 = 2.11MB) is REAL but the band is only 737KB-2.11MB, because below
   ENDGAME_LIMIT `take_blocks` races the reservations - a test proved that after
   the obvious version of the theory failed.
5. **padMule's serve side never rotates an upload slot.** `should_kick()` and
   `build_out_of_part_reqs()` are both DEAD CODE, so a peer holding a padMule
   slot holds it for the whole session. Mirror image of fix 1; NOT covered by
   the UploadGate's foreground-only scoping, since rotation is on the held
   connection.
6. Status scalars lag behind `Engine::search`'s ~20s `&mut self`; Portability
   Tier 2; Settings Tier 1/2; ten merged branches still on origin plus a stale
   worktree at `.claude/worktrees/wave11-aich`.

## Discipline that keeps earning its keep

- **When two theories have failed, stop and build the instrument.** The funnel
  took under an hour and answered in one run what three rounds of reasoning had
  not - and then refuted my OWN fresh hypothesis, twice: the 0x57 handler was
  genuinely missing yet SECONDARY, and the small-file reservation theory was
  half wrong. **Citing the upstream source line proves the code is wrong, not
  that it is what is hurting you.**
- **A zero-result test is not a failing test until the CONTROL runs.** The
  device showed 0 bytes and looked exactly like a regression from my own gate;
  the control on this box showed `(holds nothing we need) = 0` across 70
  file-status reads and 42 delivering sessions. The fixes were innocent.
- **Sampling too early is not a failed fix.** The Servers tab read 0 three times
  because `start()` still held the engine lock; a fourth read said 10.
- **A green oracle proves only the path it drives.** The differential test moves
  15MB - past the 10MB kick - and still never saw 0x57, because loopback is
  faster than amuled's kick timer.
- **A tidy causal story is a HYPOTHESIS** ([[verify-before-reporting]]).
- **MUTATION-CHECK anything load-bearing**; **bugs invisible at N=1**;
  **"an event is not state"** ([[an-event-is-not-state]]).
- **Swift type-checks ONLY in CI here** - verify a new binding by running
  `uniffi-bindgen` against the compiled cdylib BEFORE pushing.
- **`strings` on the .ipa can FALSE-NEGATIVE**: Swift stores <=15-byte strings
  inline. Pick longer markers.
- **The WDA search field CONCATENATES**: tapping it places a cursor, it does not
  select, and `/clear` does not take. The clear "x" is an 18pt button at the
  RIGHT EDGE of the field (x~1160), and typing must go through
  `element/{id}/value`. Read the field back before searching.
- **Attaching a WDA session RELAUNCHES the app** - it will end whatever run is
  in flight.

## Related

- [[build-progress]] / [[security-model]] / [[log]] / [[decisions-and-lessons]]
- [[padmule-ipa-delivery]] - the build-and-deliver loop.
- [[net-highid-and-port-forwarding]] - the AirVPN Local-port trap.
- [[ipad-usb-tooling]] - device runbook; the DDI unmounts on reboot.
- [[lifecycle-and-reactivation]] - foreground-only, permanent.
