# HANDOFF - start here next session

Updated: 2026-08-04, written fresh at the close of a very long session.
Everything below is verified; anything NOT verified says so, and the one claim
that was asserted without evidence is marked REFUTED rather than deleted.

Living doc - replace it wholesale next time. Full narrative: [[build-progress]]
rows 8bj-8bs and the [[log]] entries for 2026-08-03/04.

## State of the tree

- **Gate**: 610 Rust tests, clippy `-D warnings` clean, fmt clean, ASCII clean.
- History LINEAR across 390+ commits - zero merge commits, ever. Keep it that
  way (`gh pr merge --rebase`).
- **THREE COMMITS ARE UNPUSHED** (`b02017f`, `678dbb3`, `a3c6da1`) and the iPad
  build predates them. Push and rebuild before judging behaviour on device.
- [[security-model]]: **24 OPERATIONAL / 0 PARTIAL / 2 documented opt-outs**.
- All four oracles pass: amuled differential, REVERSE, isolated eserver, Kad
  verify.
- Installed on the iPad: **8068a71** (stale). Device on iPadOS **26.6**.
- **Cert re-signed 2026-08-04**, lapses about **2026-08-11**.

## THE OPEN PROBLEM: downloads stall, cause NOT identified

Anthony ran padMule overnight: "many files partially download and then either
stop or slow to a crawl". Three real bugs were found and fixed. The symptom is
better but NOT solved, and the obvious explanation has been disproved.

**What is measured and true:**

- Retries are cheap (~195ms, was 6.001s) and fair (was: one download got every
  retry, forever).
- 15 of 17 source lookups find **2-7 usable sources**, plus LowID peers.
- Yet only ~**5 of 20** downloads ever receive a byte.
- **Sources are found; data does not follow.** Nobody has looked inside that gap.

**What is REFUTED**, and this is the useful part. `bail_on_queue` makes padMule
abandon a peer the instant it queues us. eD2k rations upload slots, so "a client
that never queues can never be served" looked like the answer - and it was
written into the docs as the root cause before being tested. The A/B, with queue
policy as the only variable:

| policy | downloads receiving | bytes in 243s |
|---|---|---|
| BAIL (current) | 5 of 20 | 53.7 MB |
| WAIT (the "fix") | 1 of 21 | **0.0 MB** |

Four times worse. The manager runs ~4 concurrent peers per download, so waiting
parks all of them in hopeless queues instead of cycling to whoever has a FREE
slot. Fast-bail is doing real work, exactly as the three-file milestone claimed.
Reverted.

**The next step is a MEASUREMENT, not another theory:** instrument what happens
after a source is handed to the fetch task - connect success, handshake outcome,
slot verdict per peer - because the gap between "found 5 sources" and "0 bytes"
has never been observed directly.

**Untested candidate** (do not write it up as the cause until measured): bail
while UNTRIED sources remain, wait only once every known source has queued us.

**Reproduce anything here with the stress harness:**
`cargo run --release -p mule-ffi --example stress -- /tmp/cfg /tmp/dl linux 25 480`

## What landed this session

Wave 11 AICH merged, then eleven PRs. The headline is that **eight real bugs
were found by USING the app, none caught by the gate**:

1. The serve side sent every block up to THREE times (both oracles blind to it -
   duplicate bytes still verify, so a pass/fail harness cannot see a BANDWIDTH
   defect).
2. The AICH serve answer was unreachable on the path real clients use.
3. Called-back sources were tracked nowhere.
4. A second corruption round blamed the first round's source (a false ban).
5. Live servers shown dead on one lost UDP datagram.
6. The idle-retry sweep starved every download but one (stable sort + `.first()`
   - invisible at N=1, which is every test).
7. Retry budget was a floor not a ceiling: `find_sources` waited on both arms, so
   every retry cost the maximum even when the server answered in 195ms.
8. The Transfers badge counted every source EVER contacted (99 vs Search's 12).

Also: continuous block-request top-up, the source-origin badge, the amber
"receiving now" row, the Kad advertised-vs-bound port split, UPnP defaulting
OFF, the Files button, real Open, sortable Downloaded/Servers, alphanumeric
search sort, the floating Top button, and UI polls off the engine lock.

## HighID over AirVPN - SOLVED, and the cause is a trap

padMule is HighID on the VPN, device-proven. AirVPN's **"Local port" field
cannot be left blank** - the form refuses to save an empty value and silently
keeps the previous one, so the rule kept forwarding 5999 to an old 4662.

**The diagnostic is worth more than the fix:** `Connection refused (111)` rather
than a TIMEOUT proves the packet crossed the tunnel and reached the device,
which answered "nothing listening". Tunnel, keepalive and routing were never
suspects - only the port. Setup that works: one port, TCP+UDP, Local port set to
the SAME number, all four padMule port fields that number, UPnP OFF.

## Scope decisions

- **Wave 9 seedbox mode: DROPPED** (2026-08-04). Foreground-only is PERMANENT,
  so the honest pause/resume, readiness-gated splash, keep-screen-awake and
  Stop-releases-the-port are the FINAL design. Do not promise an always-on mode.

## Open work (ranked)

1. **The stall above** - measure the found-sources-to-no-bytes gap.
2. **Status scalars lag during a long search.** UI polls are off the engine lock
   now, but `state`/`server_info`/`kad_contacts` live in the engine and stall
   behind `Engine::search`'s ~20s `&mut self`. Needs `server`/`kad` made
   independently shareable - 34 use sites, new lock-ordering surface, NOT
   required for a responsive UI.
3. **Device-verify what shipped unseen**: Downloaded sort, the Open handoff,
   alphanumeric search sort, the amber row.
4. **Portability Tier 2**: NAT-PMP dead code; the 4s `offer_files` timeout drops
   uploads on a slow link; no bandwidth limiting.
5. **Settings Tier 1/2**: nickname (hardcoded), obfuscation tri-state, ipfilter
   controls, upload slots, bandwidth caps, See-My-Shared-Files.
6. **Smaller items**: harvest queue lost if the server.met write fails; no
   thin-file guard on nodes.dat; related-search pollutes Recent Searches;
   Settings accepts `https://` URLs the engine rejects; kick alert may not
   surface over a sheet; `hash-file` exits 0 on failure; MSRV unenforced.

## Discipline that keeps earning its keep

- **User testing finds what tests cannot.** Eight bugs this session, zero caught
  by the gate.
- **A tidy causal story is a HYPOTHESIS.** The queue-bail "root cause" was
  written into the docs before it was tested, and measurement said four times
  worse. A wrong diagnosis is costlier than a wrong fix, because it gets
  believed. When reverting someone's deliberate decision, first find the
  measurement that made them choose it. See [[verify-before-reporting]].
- **A budget that is ALWAYS fully consumed is not a budget, it is a cost.** Ask
  whether the fast path really finishes early or something in the join burns it.
- **A zero-result test is not a failing test until you run the CONTROL.** The
  video run moved 0 bytes; the control proved the build fine and the content
  absent (Blender open movies live on blender.org, not eD2k).
- **Bugs invisible at N=1.** A stable sort plus `.first()` looks fair until the
  key ties. Ask what a selection does when keys tie, and whether the test
  exercises N>1.
- **MUTATION-CHECK anything load-bearing** - break the fix, watch the right test
  go red.
- **"An event is not state"** - FOUR occurrences ([[an-event-is-not-state]]).
- **A green oracle proves only the path it drives**, and says nothing about COST.
- **Swift type-checks ONLY in CI on this box.**
- **`strings` on the .ipa can FALSE-NEGATIVE**: Swift stores <=15-byte strings
  inline. Pick longer markers.
- **Two agents in one worktree is a data-loss shape** -
  [[parallel-sessions-one-worktree]].

## Related

- [[build-progress]] / [[security-model]] / [[log]] / [[decisions-and-lessons]]
- [[net-highid-and-port-forwarding]] - the AirVPN Local-port trap.
- [[ipad-usb-tooling]] - device runbook. `usbipd bind` is NOT needed;
  pymobiledevice3 reaches the iPad through Windows' own Apple service. NB the
  DDI unmounts on reboot and WebDriverAgent needs a remount before it will run.
- [[lifecycle-and-reactivation]] - foreground-only, now permanent.
