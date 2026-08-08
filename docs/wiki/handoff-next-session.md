# HANDOFF - start here next session

Updated: 2026-08-07, after the slow-operations session. Living doc - replace
wholesale.

Full narrative: [[build-progress]] rows 8cf-8ch and the [[log]] entries for
2026-08-06 and 2026-08-07.

## THE ONE-LINE SUMMARY

**padMule now keeps SHARING after it leaves the screen** (row 8cj, built
2026-08-07, NOT yet device-verified) - and the agent runs a closed
build-sign-install loop, because Anthony granted the signing key. Earlier the
same day: the GUI freeze (8cg) and the operation slowness (8ch) were fixed and
device-measured - search 10.3s -> 4.6-6.4s, Refresh 7.5-9.3s -> 2.83s, Longest
poll gap 1.1s.

## State of the tree

- **Gate**: 647 Rust tests, 24 Swift simulator tests, clippy `-D warnings`,
  fmt + ASCII clean.
- **BRANCH `fetch-funnel`, nothing merged.** Do not trust prose for counts - run
  `git log --oneline main..HEAD` and `git log --oneline origin/main..main`.
  History is LINEAR and must stay that way (`gh pr merge --rebase`).
- **`rust.yml` only fires on push to `main` and on PRs**, so branch commits do
  not get the CI Rust gate automatically. It DOES take `workflow_dispatch`
  though - `gh workflow run "Rust unit gate" --ref <branch>` - which is worth
  doing per commit on this branch rather than trusting the local gate alone.
  Done for `7d1b349` and `19d06d0`: both PASSED, as did the iOS builds.
- **Installed on device: `48b5128`** (branch HEAD), confirmed by reading
  Settings > This device > **Build** (`1.0 (48b5128)`) - which is how to confirm
  any install, never by spotting a UI change. The VPN badge was then verified by
  SCREENSHOT, reading `ON VPN`: its accessibility label was correct even while it
  rendered as ". . .   . . .", so the tree cannot witness that fix and only a
  picture can.

## THE INSTALL PATH - THE AGENT NOW HAS THE KEY

**ANTHONY GRANTED THE SIGNING KEY TO THE AGENT, 2026-08-07**, reversing the
"Anthony runs zsign himself" rule that [[ipad-usb-tooling]] and
[[padmule-ipa-delivery]] still describe. `scripts/ship.sh` is the closed loop:
commit -> CI -> verify sha AND `CFBundleVersion` from a FRESH extraction -> sign
-> install -> confirm WDA survived. Every guard in it is traceable to a session
it already cost. Its tail also lists the KB/handoff duties and the
run-reanalyze-after-a-compact rule, because Anthony asked for those to be part of
the loop rather than a chore after it.

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

## MEASURED (2026-08-07, build 7d1b349, eMule Sunrise, HighID)

| Reading | Before | Now | n |
|---|---|---|---|
| search submit-to-results | 10.3s | **4.58-6.38s** | 9 |
| "Refresh server list" idle | 7.5-9.31s | **2.82-2.86s** | 3 |
| Stats -> Longest poll gap | (unmeasurable) | **1.1s** | - |
| connect to a server | - | 2.6s, HighID | 1 |

Kad still contributes - rows read `server + kad`, and "hedda hopper" split 2 kad
/ 2 server - so the search did not get faster by dropping an arm.

**THE SEARCH A/B WAS SETTLED OFF-DEVICE, which is the better experiment.**
`mule-cli kad-keyword` calls `resolve_keyword` directly, so old binary vs new,
alternating against the live network, measures the function with no probe, no UI
and no server arm: 6.12->3.42, 6.73->5.02, 8.17->6.11. New won all three pairs;
median **-25%**, NOT the 3x the worst-case arithmetic implies - most queried
nodes ANSWER, so batching saves round trips rather than timeouts. Quote it as a
quarter to a half. The device A/B against f946e02 was therefore dropped.

Refresh is mechanism-matched (2s quiet period plus the send fan-out predicts
~2.8s) and the poll gap is measured INSIDE the app, so neither depends on the
probe.

**THAT "12 rounds x RTT matches the residual" CLAIM WAS WRONG - deleted rather
than softened.** The `stats::kad_report` panel added in 19d06d0 measured 5-6
rounds per lookup, not 12: the `0..12` bound is a safety cap the frontier never
reaches. The agreement was a coincidence between two wrong numbers.

**WHAT THE PANEL ACTUALLY SAYS (on device, over AirVPN, per_query 750ms):** 62%
of rounds and 87% of value windows are held open by a peer that never answers,
and the average round burns 633ms of its 750ms cap (84%). The answer rate is 67%
on device against 85% on the dev box. **So the barrier IS the remaining cost**,
and eMule's event-driven `CSearch` - no rounds, value requests interleaved -
is worth roughly 2-3x on the Kad arm. See [[kad-routing-lifecycle]].

## THE TOP NEXT ACTION - VERIFY BACKGROUND SEEDING ON DEVICE

Row 8cj ships untested on glass. The build is offline-verified (650 tests,
mutation-checked) and the memory gate is measured (30.8MB against ~100MB), but
the thing that actually matters has NOT been observed: **does padMule keep
serving after the home button, and for how long?**

The check: turn Settings -> "Keep sharing in the background" ON, start an upload
from the Acer (see the `controlled-swarm-acer` memory - and DO NOT search for
personal or family video, those are not shared), background padMule, and watch
whether bytes keep moving. Then leave it overnight and see whether the process
is still alive in the morning - `pymobiledevice3 developer dvt sysmon process
single` shows `physFootprint` and whether it is running at all.

Jetsam is what will end it, not suspension. If it dies, the number to look at is
the footprint at the time, not the elapsed hours.

## THEN - a DECISION is pending, not work

Anthony asked for the **event-driven `CSearch` rewrite, designed together with
the Kad serve loop** (not after it - they need the same restructure, and doing
them separately means doing it twice). Serve scope is DECIDED: **routing answers
only** - HELLO, PING, KADEMLIA2_REQ and the v8 verification handshake; no index,
no storage. The reason is padMule's foreground-only posture: answering routing
queries is stateless and a node that vanishes is what eviction already handles,
whereas STORING published data would take other clients' keywords and sources and
then disappear on a background, which is worse for the network than not storing.

What is NOT decided is the sequencing, and three options were put:

- **A** - one change, both halves together. Fewest moving parts, but it rewrites
  the layer verified today and the serve loop confounds any search regression.
- **B (recommended)** - serve loop FIRST (the owning read loop plus the inbound
  handler, keeping today's batched lookup on top of it), then the event-driven
  lookup as a pure policy change. Front-loads the structural risk into the step
  with an unambiguous success test - does a real eMule keep padMule in its
  routing table? - and leaves the perf change measurable by the Kad panel that
  already exists.
- **C** - lookup first, serve second: the "restructure twice" outcome.

**The main correctness surface either way:** an owning read loop means the
routing table is READ by the handler and WRITTEN by lookups, so it moves behind a
lock or into the actor. That is where the tests belong.

After that: Track 2 (below), concurrency under load, still never started.

**REOPENED 2026-08-07 - always-on background running.** Anthony wants padMule,
and Kad in particular, running in the background rather than foreground-only.
The 2026-08-04 "permanent posture" decision is back on the table. **The research
is already complete** in [[lifecycle-and-reactivation]] and does not need
redoing: the mechanism is the `audio` `UIBackgroundModes` key, which a FREE team
may set, blocked only by App Store review 2.5.4 - which never applies to a
sideloaded build. There is no backdoor to find; the ordinary mechanism is
already available.

What is missing is MEASUREMENT, not research:
1. **Background memory under ~100MB** - jetsam TERMINATION, not suspension, is
   the overnight failure mode, and padMule's background memory has never been
   measured on any build.
2. **Keepalive longevity overnight** on the M4 iPad Pro, and whether
   `BGContinuedProcessingTask` is eligible under iPadOS 26 there. Both were open
   questions against the OLD A12Z target and were never re-asked.
3. **Move the 1s heartbeat clock out of the UI first.** It is a `Timer` on the
   main runloop (`EngineModel.startPolling`) driving seven duties that fail
   SILENTLY if it stops. It would still fire under audio keepalive, but a
   background posture resting on the UI's runloop is fragile - the clock belongs
   in Rust as a tokio interval. Found 2026-08-07.

Clean pause/resume stays REQUIRED regardless: every keepalive can be revoked or
jetsam-killed, so the app must always degrade back to it.

## HOW TO MEASURE ANYTHING ON THIS DEVICE - read before you measure

**`GET /source` is NOT a passive read.** It walks the whole view hierarchy on the
MAIN THREAD at 1.4-2.4s per call. Polling it once a second STARVES main-thread
work and will manufacture the freeze you are trying to measure. On 2026-08-07 it
produced a reading that refuted a correct fix.

**Take the measurement OUT of the window: record, leave, record once.**

**MEASURE THE PROBES BEFORE TRUSTING THEM.** Timed on device 2026-08-07:
`/source` **1.70s**, a single element query **0.53s**, `dvt screenshot`
**2.13s**. Use the element query; `/source` is three times the cost and is what
starved the app and refuted a correct fix.

**THREE PROBES WERE WRONG BEFORE THEY WERE RIGHT on 2026-08-07, each producing a
plausible number first.** (1) The results list is NOT cleared between searches,
so a probe polling for result rows finds the PREVIOUS run's at t=0 and reports
1.3-1.5s - probe latency wearing a search time's clothes. **Do NOT solve this
with the Clear button:** `Clear search` is the field's own affordance and exists
only while the field holds text AND has focus, and clearing the FIELD does not
empty the results list - only the X button's `clearSearch()` does. Both cost a
run on 2026-08-07. Detect by CONTENT instead - poll for a distinctive token of
the query - which works with stale rows on screen and needs no control at all.
Re-find the search field every run, too: a cached element id goes stale when the
hierarchy is rebuilt. (2) A probe matching `srcs`
reported NO RESULTS by 46s while four results sat on screen, because a
single-source row reads **`1 src`**. Match **`Get`** instead - exactly one per
row, regardless of source count. (3) See the probe costs above.

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

Read **Longest poll gap** instead. It is the one statistic a burst cannot hide,
and on 2026-08-07 it read **1.1s** across nine searches and three probe rounds.

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
4. **padMule is a PURE CLIENT on Kad - it neither publishes nor answers.**
   Confirmed 2026-08-07 by reading the socket's call sites: three in production,
   and the only `recv_from` is inside `request_batch`'s reply collection. No
   listener, no inbound dispatch, no request opcode handled anywhere. So it
   stores nothing for anyone (Anthony's eMule on the Acer carries 7,700+ indexed
   entries the same day), answers no FIND_NODE/HELLO/PING, and publishes no
   shares (0x43-0x45 undefined). It therefore AGES OUT of other clients' routing
   tables - eMule's `OnSmallTimer` pings and evicts what stays silent - which
   costs findability now and breaks any future buddy/rendezvous scheme.
   Payloads decoded and banked in [[kad-routing-lifecycle]]. **The serve loop and
   the event-driven `CSearch` design need the SAME restructure** (one owning read
   loop routing datagrams to either a waiting request or a handler), so design
   them together rather than in sequence.
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
