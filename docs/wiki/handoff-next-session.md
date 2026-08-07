# HANDOFF - start here next session

Updated: 2026-08-07, after the slow-operations session. Living doc - replace
wholesale.

Full narrative: [[build-progress]] rows 8cf-8ch and the [[log]] entries for
2026-08-06 and 2026-08-07.

## THE ONE-LINE SUMMARY

The GUI freeze (8cg) and the operation slowness (8ch) are both fixed in code and
**neither the slowness fix nor the freeze fix has been measured on device** -
8cg's own re-measurement was inconclusive and 8ch is structural-plus-tests only.
**A device timing pass is the top action.**

## State of the tree

- **Gate**: 644 Rust tests, 24 Swift simulator tests, clippy `-D warnings`,
  fmt + ASCII clean.
- **BRANCH `fetch-funnel`, nothing merged.** Do not trust prose for counts - run
  `git log --oneline main..HEAD` and `git log --oneline origin/main..main`.
  History is LINEAR and must stay that way (`gh pr merge --rebase`).
- **`rust.yml` only fires on push to `main` and on PRs**, so the branch commits
  have NOT been through the CI Rust gate. The local gate is the only one.
- **Installed on device: `f946e02`** - which is BEFORE this session's work.
  Confirm any install by reading Settings > This device > **Build**, not by
  spotting a UI change.

## THE INSTALL PATH - read this before touching Sideloadly

**zsign + `pymobiledevice3` is the default. Sideloadly is for RENEWALS ONLY.**

    # Anthony runs this (his key, and it stays his):
    /home/ajbufort/padmule-resign/zsign -k <sideloadly>/key.pem \
      -c /home/ajbufort/padmule-resign/cert.pem \
      -m /home/ajbufort/padmule-resign/padmule.mobileprovision \
      -b us.ajbconsulting.padMule.Q444CHAF2Z \
      -o padmule-signed.ipa padmule-unsigned.ipa
    # then the agent installs, ~30 seconds:
    pymobiledevice3 apps install padmule-signed.ipa

Kits stay staged at `/home/ajbufort/padmule-resign/` and
`/home/ajbufort/wda-resign/`. **Every Sideloadly round re-signs WebDriverAgent
without signing its nested `.xctest` and breaks the automation.**

**PROFILE EXPIRIES (the 7-day clock is the PROFILE; the cert runs to 2027):**
WebDriverAgent **2026-08-10**, padMule **2026-08-14**. WDA is the binding one -
when it lapses, agent-driven device testing stops until a Sideloadly renewal.

## Shipped this session (8ch)

1. **Kad's alpha queries actually go out together.** `resolve_keyword` ran
   `for node in &batch { find_node(node).await }` - alpha is a CONCURRENCY
   parameter and padMule used it as a batch SIZE. Structurally 12 rounds x 3 x
   750ms = 27s of lookup before the keyword phase, capped at `KAD_SEARCH_WAIT`,
   so **the cap was the cost** and that is the 10.3s search. `request_batch` is
   one receive loop owning the whole batch. Wire-identical.
2. **`server_info()` was the fifth status reader 8cg never made lock-free** -
   so `refreshFast()`, and the event drain sharing its queue, still stalled for
   every search. Now published through `StatusPub`.
3. **`heartbeat()` took the engine lock once for eight duties** (up to ~10s).
   One lock per duty now.
4. **The server probe always spent its full 6s budget.** Stops when everyone has
   answered, or 2s after the last answer.
5. **Stats -> "Longest poll gap"**, because the 8cg counters cannot answer their
   own question (below).

## THE TOP NEXT ACTION - MEASURE 8cg AND 8ch ON DEVICE

Nothing in either row has a device number behind it. Build, install, and take
three readings:

| Reading | Before | Expect |
|---|---|---|
| search submit-to-results | 10.3s | materially lower; the Kad arm no longer sets the pace |
| "Refresh server list" idle | 7.5-9.3s | lower - the probe stops when answers are in |
| Stats -> **Longest poll gap** after a search | (new) | near 1s. Anything near the search length means something on that queue takes the engine lock again |

The gap row is the honest instrument. **The tick COUNTS cannot answer this** -
see below. If the search is still ~10s, the Kad arm is not the pace-setter and
the next suspect is the server arm or `ranked_to_hits` (which calls
`hit_status` per result, ~143 times, under the lock).

## HOW TO MEASURE ANYTHING ON THIS DEVICE - read before you measure

**`GET /source` is NOT a passive read.** It walks the whole view hierarchy on the
MAIN THREAD at 1.4-2.4s per call. Polling it once a second STARVES main-thread
work and will manufacture the freeze you are trying to measure. On 2026-08-07 it
produced a reading that refuted a correct fix.

**Take the measurement OUT of the window: record, leave, record once.**

**THE 8cg TICK COUNTERS CANNOT SUPPORT THE READING TAKEN FROM THEM.**
`uiPollTicks` / `heartbeatTicks` are cumulative, and their `eventQueue` is
SERIAL - so a poll that blocks does not LOSE its ticks, the timer keeps queueing
work items and they all run the instant the block clears. Over any window that
outlasts the stall, "stalled 10s then burst" and "never stalled" give the SAME
total. The 2026-08-07 table below is therefore not evidence that the poll kept
running, and finding (2) above makes the burst the likelier explanation:

| path | idle | during a search | what it actually shows |
|---|---|---|---|
| status polls | ~1.2/s | 0.94/s | a total, which a burst reproduces |
| heartbeats | ~1.2/s | 0.69/s | a real stall (it does take the lock) |

Read **Longest poll gap** instead. It is the one statistic a burst cannot hide.

**The WDA search field CONCATENATES.** The helper now clears, sets and READS THE
FIELD BACK, aborting on mismatch. A re-run once silently searched
`ministerminister`, which returns nothing fast and therefore produced a
measurement that looked clean *because* it was meaningless.

## OPEN

1. **Track 2 - concurrency under load. NOT STARTED.** Anthony's complaint:
   padMule handles numerous concurrent downloads badly. There is **NO cap at all**
   on concurrent downloads - each gets ~4 workers, so 20 downloads is ~80
   concurrent dials. Use HIS shared files as the controlled set (eMule on the
   Acer, port 5998, HighID, on eMule Sunrise); a known swarm beats a public one,
   whose variance has made every prior measurement ambiguous.
2. **Per-file pause/resume: DOES NOT EXIST.** Verified - no engine API, no FFI
   method, no per-download state. `pause()`/`resume()` are whole-engine lifecycle.
   Anthony asked for it plus a clear per-file state. **A build, not a bug.**
3. **A settable max-active download cap with the rest QUEUED**, per-file status
   like eMule. Anthony suggested 20 active. Same feature family as (2).
4. **padMule PUBLISHES NOTHING to Kad.** Opcodes 0x43-0x45 undefined, no call
   site; its shares are invisible to every client searching Kad. Payloads decoded
   and banked in [[kad-routing-lifecycle]]. Deliberately NOT half-built.
5. **Kad gaps still open** (8ce): no contact expiry or liveness ping (eMule's
   `OnSmallTimer` half), near-biased nodes.dat sample, no bootstrap retry, and
   `KadNode::add_contact` has no Kad-version gate so a peer can put a v1 contact
   in the table over the wire.
6. **The probe still runs UNDER THE ENGINE LOCK**, now for ~2s instead of 6s.
   Taking it off the lock was considered and NOT done: `persist_server_names`
   writes server.met, and the lock is the only thing serialising that against
   `update_server_list` and `merge_discovered_servers`. Doing it properly means
   snapshotting inputs under the lock, fanning out without it, then re-acquiring
   to fold health and persist names. Worth it only if 2s still shows up on a
   device reading.
7. **The pause teardown does not finish before iOS suspends** - 465ms to
   suspension, 30.5s to completion. `pause()` now logs whether the background
   assertion was GRANTED/REFUSED and how long the work waited. One background
   round trip on a current build answers it. Do not theorise first.
8. Housekeeping: eleven remote branches fully merged and deletable; `main` is
   ahead of `origin/main`, unpushed.

## STANDING DIRECTIVE (2026-08-06)

**eMule 0.70b is the authority for GUI, Settings and per-file behaviour**
(Anthony). Third row in the authority table in `CLAUDE.md`; 0.50a still decides
the wire. Check 0.70b BEFORE designing a screen or a download state, and diverge
only deliberately.

## What this session actually taught

- **A fix's own commit message is a claim, not a record.** 8cg said "all five are
  now lock-free" and converted four; the fifth kept taking the lock for a day.
  The test that pinned the property named four readers, so it could not see it.
  **A test that pins "these callers" has to name every one of them.**
- **A cumulative counter cannot measure a stall on a serial queue.** Ticks are
  not lost, they are deferred, and the total comes out the same. The 8cg
  instrument was built to carry its own control and does not; a max GAP does.
- **A constant that is always reached is not a bound, it is the cost.**
  `KAD_SEARCH_WAIT` looked like a safety cap and was the actual duration of every
  search, because the work under it was structurally 27s.
- **Alpha is a concurrency parameter.** The name of the constant said so
  (`ALPHA_QUERY`, "concurrent queries in flight") and the code batched three and
  then blocked on each. The doc comment was right and unread for a month.
- **Check an instrument can FAIL before believing it** - applied to five new
  tests this session, and two of them were vacuous on the first attempt.

## Related

- [[build-progress]] / [[kad-routing-lifecycle]] / [[log]] / [[decisions-and-lessons]]
- [[ipad-usb-tooling]] - install path, WDA runbook, the measurement rules above.
- [[padmule-ipa-delivery]] - the build-and-deliver loop (memory).
- [[net-highid-and-port-forwarding]] - the AirVPN setup; eMule on 5998, HighID.
