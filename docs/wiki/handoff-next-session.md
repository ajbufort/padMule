# HANDOFF - start here next session

Updated: 2026-08-04 (second session of the day: the fetch path was INSTRUMENTED,
and the measurement replaced three rounds of theory).

Living doc - replace it wholesale next time. Full narrative: [[build-progress]]
rows 8bj-8bt and the [[log]] entries for 2026-08-03/04.

## State of the tree

- **Gate**: 614 Rust tests, clippy `-D warnings` clean, fmt clean, ASCII clean.
- History LINEAR across 390+ commits - zero merge commits, ever. Keep it that
  way (`gh pr merge --rebase`).
- **UNPUSHED COMMITS** - check `git log origin/main..HEAD` before judging device
  behaviour. (The previous handoff said "three" and named three; there were
  FOUR. The commit that writes the handoff cannot list itself - use the command,
  not the prose.)
- [[security-model]]: **24 OPERATIONAL / 0 PARTIAL / 2 documented opt-outs**.
- All four oracles pass: amuled differential, REVERSE, isolated eserver, Kad
  verify.
- Installed on the iPad: **8068a71** (stale). Device on iPadOS **26.6**.
- **Cert re-signed 2026-08-04**, lapses about **2026-08-11**.

## THE FETCH FUNNEL - build it, then read it

The previous handoff said the next step was "a MEASUREMENT, not another theory".
That instrument now exists and is the most important thing in this file.

`mule_engine::stats` holds cumulative per-stage counters, bumped one line at a
time through `run_peer`/`fetch_one`, plus a tally of every opcode read out of
turn and a dial-duration histogram. `mule_ffi::fetch_report()` prints it; the
stress harness prints it every 30s. The DROP between two adjacent stages is the
loss at that stage - **including a loss to the per-peer TIMEOUT, which no error
value can report.** That is precisely why the gap had stayed invisible.

Baseline, 480s, 25 downloads, HighID, a 41k-user server:

```
dialed                         1583      <- includes re-dials across the sweep
connected                        74      <- 4.7%
got filestatus                   65
asked for a slot                 65
  slot ACCEPTED                   7      <- 11% of peers reached
  queued (bailed)                50
accepted, no block to take        6      <- 86% of the slots WON were useless
requested blocks                  1
DELIVERED bytes                   1      <- ONE session moved a byte
```

23 of 25 downloads reached `0/0/0` connected sources against a Search claim of
8-22. **Kad contributed ZERO sources to any download** - unexplained, worth a
look.

## What that found, and what it did NOT

**FIXED - `OP_OUTOFPARTREQS` (0x57) had no handler.** Not an edge case: it is
how every upload slot ends. Both authorities send it the instant
`CheckForTimeOver()` trips, at 10 MB uploaded or one hour (eMule 0.50a
UploadClient.cpp:722-725 + :767-782, aMule master UploadClient.cpp:463-466,
UploadQueue.cpp:609-616 - the same 10 MB padMule already encodes as
`SESSION_MAX_BYTES`). `BlockReceiver::accept` yields no writes for a non-data
opcode, so the block loop waited for bytes that were never coming until the
caller's **45s** timeout, holding one of only FOUR workers. The one download that
moved in the baseline froze at exactly 18.6MB. *The differential test's 15MB file
does cross 10MB, but on loopback it finishes before amuled's kick timer ticks.*

**FIXED - padMule asked for a slot from peers holding nothing it needed.** eMule
sets DS_NONEEDEDPARTS on the file status and swaps away WITHOUT asking
(DownloadClient.cpp:634-641). Fast-bail SELECTS for these peers: a client that
just started downloading has a free upload slot precisely because it has nothing
to give. That was the 6-of-7 line.

## REPRODUCED ON THE DEVICE - and here is the re-test to run

2026-08-04, agent-driven over WebDriverAgent, on the STALE 8068a71 build with
Anthony's real config on the VPN. Connected to eMule Sunrise HighID, searched
(375 hits), queued four. One download went 20MB -> 35.3 -> 64.8 -> **65 MB /
67.5 MB (96%), then froze for over ten minutes while its source count climbed
20 -> 30 -> 33 -> 42 ed2k**. More sources, zero bytes. A sibling download
progressed normally the whole time (2MB -> 41.2MB), so the engine was not
wedged - the stall is PER-DOWNLOAD and it struck at the TAIL, which is exactly
where the two fixes compound (about 2.5MB left, near the 2.11MB four workers can
hold reserved, and a worker hung on the missing 0x57 handler keeps its
reservations for the full 45s).

**THE RE-TEST, once a fixed build is installed:** connect to a big server, queue
3-4 files of 50MB+, and watch for a row that pins at high percent while its
source count keeps growing. That signature - frozen bytes, climbing sources - is
the bug. If it is gone, the fixes did it.

**Installing needs Anthony.** CI builds an UNSIGNED .ipa (verified: no
`_CodeSignature`, no `embedded.mobileprovision`), so Sideloadly on the Windows
host must re-sign it. Everything else in this loop is agent-drivable: WDA is
installed, `pymobiledevice3 developer dvt xcuitest ...` plus the 8100 forward
gives full touch control, and `GET /source?format=json` reads the transfer rows
as text.

**Also seen on-device, unexplained:** the Servers screen read "No server list on
disk" / Servers (0) on a device that had been downloading overnight; one
"Refresh server list" tap restored 10. And Kad DID supply sources on the device
(2 kad, 1 kad) where the dev-box stress runs got zero from it - so the
zero-Kad finding below may be dev-box-specific.

**THE LIVE A/B IS INCONCLUSIVE - do not cite it as validation.** A second 480s
run with both fixes: `1676 dialed -> 33 connected -> 24 slot asks -> 17 ACCEPTED
-> 12 no-block-to-take -> 5 DELIVERED`, 2 of 25 receiving, 22.6MB. Every number
moved the right way and none of it is attributable - `connected` fell 74 -> 33 on
a similar dial count, so the runs sampled very different source populations, and
an 11% -> 71% slot-accept swing is far too large for a gate that removed six
asks. **Both fixes are established OFFLINE**, by deterministic loopback tests
with mutation checks. Note `slot REVOKED (0x57) = 0` across the whole second run:
no source fed padMule 10MB in one session, so the revocation fix was never
exercised live. Proven by test, not by that run.

**OPEN - `accepted, no block to take` did not fall; it rose to 12 of 17.** Part
of the mechanism is proven and part was REFUTED. The arithmetic (4 workers x 3
blocks x 184320 = 2.11MB reservable at once) says a small file is fully spoken
for by its own workers - but a test written to prove that failed first, because
below ENDGAME_LIMIT (737KB) `take_blocks` enters endgame and races the
reservations. The real band is 737KB < still-missing < 2.11MB, plus any peer
holding only already-reserved parts. Real, kept as a test, too narrow to explain
12 of 17.

**NOT EXPLAINED - the first stage, which is the biggest loss.** 95% of dials
never complete a handshake, and neither fix touches it. Two known contributors,
neither measured apart yet:

1. Nothing ever removes a proven-dead source from `download_file`'s pool.
   `PeerScoreboard` only re-ORDERS; one dead peer costs 8 dials per sweep and
   again on every retry, so 1583 dials is far fewer distinct peers.
2. The connect shares the 45s per-peer budget. Both authorities do use
   CONNECTION_TIMEOUT = 40s (eMule opcodes.h:62, aMule Constants.h:33-35), but
   eMule multiplexes hundreds of sockets so a stalled one costs it nothing;
   padMule's four-worker pool turns the same number into a throughput cap.

**The dial-duration histogram exists to settle #2 with data** - it splits dial
times by whether the handshake SUCCEEDED. If successful handshakes all land in
the first seconds, everything past that is dead air and a shorter CONNECT
deadline is free. If they are spread out, cutting it would discard real sources
and the honest answer is to widen the worker pool instead. **Run it and read it
before changing either number.**

**Reproduce anything here:**
`cargo run --release -p mule-ffi --example stress -- /tmp/cfg /tmp/dl linux 25 480`

## Open work (ranked)

0. **Run the funnel several times before trusting any A/B on it.** One pair of
   runs cannot separate a fix from source-population variance on this network;
   the STAGE RATIOS are the signal, and even those need repetition.
1. **The dial stage** - read the histogram, then decide: dead-source eviction,
   a shorter connect deadline, a wider worker pool, or some of each.
1b. **`accepted, no block to take`, 12 of 17** - the biggest loss among slots we
   actually win, and unexplained past the narrow reservation band above.
2. **Kad found zero sources across 25 downloads.** Server-only discovery is a
   single point of failure, and this was not true earlier in the project.
3. **padMule's serve side never rotates an upload slot.** `should_kick()` and
   `build_out_of_part_reqs()` are both DEAD CODE, so a peer holding a padMule
   slot holds it for the whole session and better-scored waiters never get in.
   The `UploadGate` doc scopes out cross-connection queue persistence, but
   rotation happens on the HELD connection, so this is not covered by that
   decision. Mirror image of the bug above - padMule neither sent nor understood
   slot rotation.
4. **Status scalars lag during a long search** (`state`/`server_info`/
   `kad_contacts` stall behind `Engine::search`'s ~20s `&mut self`). 34 use
   sites, new lock-ordering surface, NOT required for a responsive UI.
5. **Device-verify what shipped unseen**: Downloaded sort, the Open handoff,
   alphanumeric search sort, the amber row.
6. **Portability Tier 2**: NAT-PMP dead code; the 4s `offer_files` timeout drops
   uploads on a slow link; no bandwidth limiting.
7. **Settings Tier 1/2**: nickname (hardcoded), obfuscation tri-state, ipfilter
   controls, upload slots, bandwidth caps, See-My-Shared-Files.
8. **Smaller items**: harvest queue lost if the server.met write fails; no
   thin-file guard on nodes.dat; related-search pollutes Recent Searches;
   Settings accepts `https://` URLs the engine rejects; kick alert may not
   surface over a sheet; `hash-file` exits 0 on failure; MSRV unenforced. Ten
   merged feature branches still exist locally and on origin, plus a stale
   worktree at `.claude/worktrees/wave11-aich`.

## Discipline that keeps earning its keep

- **When two theories have already failed, stop and build the instrument.** The
  funnel took under an hour and answered in one run what three rounds of
  reasoning had not. It also refuted my OWN fresh hypothesis on the spot: the
  0x57 handler was traced to real upstream source lines and was genuinely
  missing, and the funnel still showed the block loop nearly unreachable, so it
  was real but SECONDARY. **Citing the upstream line proves the code is wrong,
  not that it is what is hurting you.**
- **A tidy causal story is a HYPOTHESIS.** See [[verify-before-reporting]] - the
  queue-bail "root cause" was documented before it was tested and measured four
  times worse.
- **User testing finds what tests cannot.** Eight bugs in the previous session,
  zero caught by the gate.
- **A green oracle proves only the path it drives**, and says nothing about COST.
  The differential test transfers 15MB - past upstream's 10MB kick threshold -
  and still never saw the revocation, because loopback is too fast for the
  timer.
- **MUTATION-CHECK anything load-bearing** - break the fix, watch the right test
  go red. Both fixes here: red at 5.02s/5.19s `Elapsed`, green at 0.03s/0.23s.
- **Bugs invisible at N=1.** A stable sort plus `.first()` looks fair until the
  key ties.
- **"An event is not state"** - FOUR occurrences ([[an-event-is-not-state]]).
- **Swift type-checks ONLY in CI on this box.**
- **`strings` on the .ipa can FALSE-NEGATIVE**: Swift stores <=15-byte strings
  inline. Pick longer markers.
- **Two agents in one worktree is a data-loss shape** -
  [[parallel-sessions-one-worktree]].

## Related

- [[build-progress]] / [[security-model]] / [[log]] / [[decisions-and-lessons]]
- [[net-highid-and-port-forwarding]] - the AirVPN Local-port trap: the "Local
  port" field cannot be left blank, and `Connection refused (111)` rather than a
  TIMEOUT is what proves the packet crossed the tunnel.
- [[ipad-usb-tooling]] - device runbook. `usbipd bind` is NOT needed;
  pymobiledevice3 reaches the iPad through Windows' own Apple service. NB the
  DDI unmounts on reboot and WebDriverAgent needs a remount before it will run.
- [[lifecycle-and-reactivation]] - foreground-only, now permanent.
