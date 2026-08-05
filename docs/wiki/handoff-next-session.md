# HANDOFF - start here next session

Updated: 2026-08-04, close of the instrumentation session.

Living doc - replace it wholesale next time. Full narrative: [[build-progress]]
rows 8bj-8bu and the [[log]] entries for 2026-08-03/04.

## State of the tree

- **Gate**: 616 Rust tests, clippy `-D warnings` clean, fmt clean, ASCII clean.
- **YOU ARE ON BRANCH `fetch-funnel`, NOT main.** Six commits ahead of main, all
  pushed. `main` itself is still 4 commits ahead of `origin/main` from the
  previous session. Nothing has been merged - decide that first
  (`gh pr merge --rebase`, history is LINEAR across 390+ commits and must stay
  that way). Do not trust prose for commit counts; run
  `git log --oneline main..HEAD` and `git log --oneline origin/main..main`.
- [[security-model]]: **24 OPERATIONAL / 0 PARTIAL / 2 documented opt-outs**.
- Oracles: amuled differential re-run GREEN after the transfer-path changes
  (3 files byte-for-byte, incl. the 15MB multipart). REVERSE / eserver / Kad
  verify not re-run this session.
- **Installed on the iPad: `a980fba`** (current branch head). Device on iPadOS
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
4. **Strip order**: Servers, Status, Search, **Transfers, Downloads**, Shared,
   Stats.

All test-first with RED observed, and 1/2 mutation-checked.

## MEASURED - act on these

**The dial deadline is the biggest cheap win, and it is now evidence-backed.**
Of 76 successful handshakes in a 5-minute run, 75 landed under 1s and ONE
between 1-2s. **Not one dial connected after 2s.** Meanwhile 57 dials burned the
FULL 45s and every one failed:

```
0-1s    75 connected / 166 failed
1-2s     1 / 5
2-5s     0 / 22
>=45s    0 / 57
```

A ~5s CONNECT deadline (separate from the session budget) would lose zero real
sources and reclaim ~43 minutes of worker time from a 5-minute run. The "widen
the worker pool instead" branch is refuted. **Nothing ever evicts a proven-dead
source from `download_file`'s pool either** - `PeerScoreboard` only re-ORDERS -
so a dead peer is re-dialed 8x per sweep and again on every retry.

## OPEN - and named as open, not explained

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
