# HANDOFF - start here next session

Updated: 2026-08-07, after the reanalysis pass that followed the background-seeding
session. Living doc - replace wholesale.

Full narrative: [[build-progress]] rows 8cf-8cj and the [[log]] entries for
2026-08-06 and 2026-08-07.

## THE ONE-LINE SUMMARY

**padMule keeps SHARING after it leaves the screen** (row 8cj, device-verified
2026-08-07) and a soak is proving longevity. **The next piece of work is not a
decision - it is DECIDED and PLANNED**: the Kad routing serve loop, step 1 of
`docs/superpowers/specs/2026-08-07-kad-owning-read-loop-design.md`, with a
task-by-task plan at `docs/superpowers/plans/2026-08-07-kad-serve-loop.md`.

## State of the tree

- **Gate**: **650** Rust tests, 24 Swift simulator tests, clippy `-D warnings`,
  fmt + ASCII clean. (Three docs disagreed about this number - CLAUDE.md said
  628, this handoff said 647, build-progress said 650. 650 is right; CLAUDE.md
  is still wrong and is on the fix list below.)
- **BRANCH `fetch-funnel`, nothing merged - 66 commits ahead of `main`, and
  `main` is 4 ahead of `origin/main`, unpushed.** Do not trust prose for counts -
  run `git log --oneline main..HEAD`. History is LINEAR and must stay that way
  (`gh pr merge --rebase`).
- **`rust.yml` only fires on push to `main` and on PRs**, so branch commits do
  not get the CI Rust gate automatically. It DOES take `workflow_dispatch` -
  `gh workflow run "Rust unit gate" --ref <branch>`.
- **Installed on device: `48b5128`**, confirmed by reading Settings > This
  device > **Build** - which is how to confirm any install, never by spotting a
  UI change.

## BACKGROUND SEEDING - the open item, and it is RUNNING RIGHT NOW

**Do not install anything on the device without checking this first.** A soak
(`$CLAUDE_JOB_DIR/tmp/soak.sh`, log beside it) samples `physFootprint` and CPU
every ~70s for 60 samples. Started 21:18 on 2026-08-07; an install would end it
and waste the run.

**What it says so far (34 minutes, 29 samples):**

| Reading | Value |
|---|---|
| Alive | every sample |
| `physFootprint` | **32.2MB -> 32.1MB, flat** (jetsam budget ~100MB) |
| CPU | **bimodal: ~0.1% or ~6-11%, alternating** |

The footprint is the number that decides survival and it is not moving. The
memory objection to background running is answered.

**THE CPU IS THE REMAINING QUESTION, and the bimodality is the clue.** A
continuously-playing audio session would show a steady floor, not an alternation
between 0.1% and 10%. That pattern is a periodic BURST being caught or missed by
the sampler, which points at padMule's own 1s poll rather than at the keepalive:

- `EngineModel.startPolling` is a 1 Hz `Timer` that is **not state-aware**. In
  `.seeding` it still runs `refreshFast()` - marshalling the whole downloads
  list, the whole shared library, transfer stats, the port-mapping flag and five
  scalars across the FFI - and `refresh()` -> `heartbeat()`, which takes and
  releases the engine mutex **nine times a second** to run maintainers that in
  Seeding mostly early-return. All of it publishes to a UI nobody is looking at.

**The cheap experiment, before anything is redesigned:** gate the poll on
`state != .seeding` (or drop it to ~5s there, keeping only `heartbeat()`) and
re-soak. That separates "the audio session costs 7%" from "our own 1 Hz loop
costs 7%". It also folds into the clock move below, since a Rust-side interval
can key its cadence off `EngineState` directly.

**HOW TO BACKGROUND AN APP FOR A TEST - this cost a false verdict.** Use
`pymobiledevice3 developer dvt launch <other.bundle>`. Do NOT create a WDA
session for another bundle: that TERMINATES the app that was running, which
produced four "DEAD" samples that read exactly like the feature failing.

## THE TOP NEXT ACTION - decided, planned, not started

**Kad routing serve loop, step 1.** padMule answers NOTHING on Kad: the socket
has three production call sites (`request_batch`'s `send_to` and its single
`recv_from`, plus `send_hello_res_ack`), so it reads the socket only while
awaiting its own reply and never answers a HELLO, PING or FIND_NODE. eMule's
`OnSmallTimer` pings the oldest contact per bin and evicts what stays silent, so
**padMule ages out of every routing table that learns it.** Verified by reading
the call sites, 2026-08-07.

**This was written up as an open A/B/C decision in the previous handoff. It is
not.** The spec records it under "Decisions taken before this spec":

- **Serve scope: ROUTING ANSWERS ONLY** - HELLO, PING, KADEMLIA2_REQ, the v8
  verification handshake. No index, no storage, no publish. Foreground-only makes
  stateless answering a pure win, while storing other clients' data and then
  vanishing is worse for the network than not storing.
- **Sequencing: serve loop FIRST, event-driven `CSearch` SECOND.** Step 1 carries
  the structural risk and has an unambiguous external success test; step 2 is then
  a pure policy change on proven plumbing.

The implementation plan is `docs/superpowers/plans/2026-08-07-kad-serve-loop.md`
(task-by-task, failing tests written out). **It was committed in `6963447` and
referenced from nowhere** - not index.md, not log.md, not this handoff - which is
how a session came to be told to re-decide a settled question. Now indexed.

**The main correctness surface:** an owning read loop means the routing table is
READ by the handler and WRITTEN by lookups, so it moves behind
`Arc<Mutex<RoutingTable>>`. That is where the tests belong, and the plan puts
them there.

**The external success test, which is the real one:** extend
[[kad-verify-oracle]] to show a real amuled KEEPS padMule in its routing table
across a ping cycle - a fact about another implementation, not our code agreeing
with itself ([[interop-test-fidelity]]).

## WHAT THE 2026-08-07 REANALYSIS FOUND

**FIXED in this pass: twelve doc comments were attached to the wrong item.** A
new item inserted immediately after an existing doc block orphaned the block onto
itself, leaving nine significant items undocumented - `Engine`, `EngineHandles`,
`resume()`, `maintain_checkpoint`, `maintain_share_verify`,
`download_from_peer_at`, `source_origins`, `MuleEngine`, and Swift's
`refresh()`/`refreshFast()`. The worst put `maintain_checkpoint`'s deliberate
deviation from both authorities on `nodes.dat` timer writes - with eMule/aMule
line citations - onto `maintain_resume_fetches`. In a project where the doc
comment IS the record of why, a misfiled one is worse than none. All twelve
moved; gate re-run green.

**STILL OPEN - doc drift, none of it fixed yet:**

1. **`ship.sh` does not check the Rust gate it dispatches.** Its header states
   guard 1 as "CI must be GREEN for the exact sha", but the body resolves and
   polls only the iOS run; `"Rust unit gate"`'s conclusion is never read, so a
   red workspace ships. It also never dispatches `"iOS unit tests (simulator)"`,
   so the 24 Swift tests never run on a shipped sha - which matters now that CI
   RENDERS the VPN badge as the guard for a bug class assertions cannot see.
2. **CLAUDE.md says 628 tests.** Actual 650.
3. **CLAUDE.md and README still say foreground-only.** Row 8cj superseded that
   for the serve side on 2026-08-07;
   [[lifecycle-and-reactivation]] and index.md were annotated, these two were not.
   CLAUDE.md is loaded into every session as an instruction, so it is the one
   that matters.
4. **[[security-model]] contradicts its own scorecard.** Header and tally say
   24/0/2 with no PARTIALs and the AICH row reads OPERATIONAL, but the "Release
   blockers" section still says "What is left is AICH block recovery" - 2026-08-02
   text superseded by wave 11 the next day and never annotated in place.
5. **`MARKETING_VERSION: "0.1"` in `ios/project.yml` is inert.** XcodeGen writes a
   literal `CFBundleShortVersionString`, so the device reports `1.0 (<sha>)` - as
   `SettingsView.buildId`'s own doc example and the 48b5128 screenshot both show.
   Fix is one line in `info.properties`.
6. **`MuleEngine::heartbeat`'s doc says "all seven stop SILENTLY"; there are
   eight maintainers.** `maintain_kad` is the one the count forgets.
7. **`for _round in 0..12` is a bare literal** in `kad_live.rs` (twice), and
   `KAD_SEARCH_WAIT`'s doc computes its budget from it. The maintenance path made
   `REFRESH_ROUNDS` `pub(crate)` precisely so a test could pin that arithmetic
   (`engine.rs`, `a_kad_maintenance_round_fits_inside_its_deadline`); the search
   path has no constant and no test, so changing the 12 silently falsifies the doc.
8. **`BackgroundKeepAlive.start()` can leave an audio session activated** when
   `setActive(true)` succeeds and `player.play()` then returns false: it returns
   false without deactivating and without setting `isRunning`, so `stop()` guards
   out. The engine correctly falls back to `pause()`, so nothing on screen is
   dishonest - it just holds a session nobody uses.
9. **`ContentView` is 1759 lines in one type**, 77 subviews deep.

**Verified CORRECT, so nobody re-derives them:** the "eleven remote branches are
merged and deletable" claim (they were rebase-merged, so `--merged` hides them and
`git cherry` confirms 0 unmerged patches); no contact eviction anywhere in
`RoutingTable`; `add_contact` has no Kad-version gate, so a peer's KADEMLIA2_RES
can insert a v1 contact even though the nodes.dat path gates `version > 1`; no cap
on concurrent downloads; no per-file pause. The inbound classifier's AICH opcodes
are mutation-checked - removing `OP_AICHFILEHASHREQ` turns
`an_aich_ask_opens_a_serve_session_through_the_real_classifier` red.

## THE INSTALL PATH - THE AGENT HAS THE KEY

**ANTHONY GRANTED THE SIGNING KEY TO THE AGENT, 2026-08-07.** `scripts/ship.sh`
is the loop: commit -> CI -> verify sha AND `CFBundleVersion` from a FRESH
extraction -> sign -> install -> confirm WDA survived. Every guard in it is
traceable to a session it already cost - except the Rust-gate hole above.

**zsign + `pymobiledevice3` is the default. Sideloadly is for RENEWALS ONLY**, and
every Sideloadly round re-signs WebDriverAgent without signing its nested
`.xctest` and breaks the automation. Kits stay staged at
`/home/ajbufort/padmule-resign/` and `/home/ajbufort/wda-resign/`.

**ONE SHIP AT A TIME** - `ship.sh` takes an flock. Two overlapping runs on
2026-08-07 both reached the install and both LOST it ("Coordinator superseded").

**PROFILE EXPIRIES (the 7-day clock is the PROFILE; the cert runs to 2027):**
WebDriverAgent **2026-08-10**, padMule **2026-08-14**. WDA is the binding one -
when it lapses, agent-driven device testing stops until a Sideloadly renewal.

## HOW TO MEASURE ANYTHING ON THIS DEVICE - read before you measure

**`GET /source` is NOT a passive read.** It walks the whole view hierarchy on the
MAIN THREAD at 1.4-2.4s per call. Polling it once a second STARVES main-thread
work and will manufacture the freeze you are trying to measure. On 2026-08-07 it
produced a reading that refuted a correct fix.

**Take the measurement OUT of the window: record, leave, record once.**

**MEASURE THE PROBES BEFORE TRUSTING THEM.** Timed on device 2026-08-07:
`/source` **1.70s**, a single element query **0.53s**, `dvt screenshot` **2.13s**.
Use the element query.

**THREE PROBES WERE WRONG BEFORE THEY WERE RIGHT on 2026-08-07.** (1) The results
list is NOT cleared between searches, so a probe polling for result rows finds the
PREVIOUS run's at t=0 and reports probe latency wearing a search time's clothes.
Do NOT solve this with the Clear button - `Clear search` exists only while the
field holds text AND has focus, and clearing the FIELD does not empty the results
list. Detect by CONTENT instead: poll for a distinctive token of the query.
Re-find the search field every run, too - a cached element id goes stale when the
hierarchy is rebuilt. (2) A probe matching `srcs` reported NO RESULTS by 46s while
four results sat on screen, because a single-source row reads **`1 src`**. Match
**`Get`** instead - exactly one per row. (3) The costs above.

**THE 8cg TICK COUNTERS CANNOT SUPPORT A READING TAKEN FROM THEM.**
`uiPollTicks`/`heartbeatTicks` are cumulative and their `eventQueue` is SERIAL, so
a poll that blocks does not LOSE its ticks - the timer keeps queueing work items
and they all run the instant the block clears. Over any window that outlasts the
stall, "stalled 10s then burst" and "never stalled" give the SAME total. Read
**Longest poll gap** instead: the one statistic a burst cannot hide. It read
**1.1s** across nine searches and three probe rounds.

**The WDA search field CONCATENATES.** The helper now clears, sets and READS THE
FIELD BACK, aborting on mismatch. A re-run once silently searched
`ministerminister`, which returns nothing fast and therefore produced a
measurement that looked clean *because* it was meaningless.

## MEASURED (2026-08-07, build 7d1b349, eMule Sunrise, HighID)

| Reading | Before | Now | n |
|---|---|---|---|
| search submit-to-results | 10.3s | **4.58-6.38s** | 9 |
| "Refresh server list" idle | 7.5-9.31s | **2.82-2.86s** | 3 |
| Stats -> Longest poll gap | (unmeasurable) | **1.1s** | - |
| connect to a server | - | 2.6s, HighID | 1 |

**THE SEARCH A/B WAS SETTLED OFF-DEVICE, which is the better experiment.**
`mule-cli kad-keyword` calls `resolve_keyword` directly, so old binary vs new,
alternating against the live network, measures the function with no probe, no UI
and no server arm: 6.12->3.42, 6.73->5.02, 8.17->6.11. Median **-25%**, NOT the 3x
the worst-case arithmetic implies - most queried nodes ANSWER, so batching saves
round trips rather than timeouts. Quote it as a quarter to a half.

**WHAT THE KAD PANEL SAYS (on device, over AirVPN, per_query 750ms):** 62% of
rounds and 87% of value windows are held open by a peer that never answers, and
the average round burns 633ms of its 750ms cap (84%). The answer rate is 67% on
device against 85% on the dev box. **So the barrier IS the remaining cost**, and
eMule's event-driven `CSearch` is worth roughly 2-3x on the Kad arm. That is step
2 of the spec. See [[kad-routing-lifecycle]].

## OPEN (beyond the doc drift above)

1. **Track 2 - concurrency under load. NOT STARTED.** Anthony's complaint:
   padMule handles numerous concurrent downloads badly. There is **NO cap at all**
   on concurrent downloads - each gets ~4 workers, so 20 downloads is ~80
   concurrent dials. Use HIS shared files as the controlled set (eMule on the
   Acer, port 5998, HighID); a known swarm beats a public one, whose variance has
   made every prior measurement ambiguous.
2. **Per-file pause/resume: DOES NOT EXIST.** Verified - no engine API, no FFI
   method, no per-download state. `pause()`/`resume()` are whole-engine lifecycle.
   Anthony asked for it plus a clear per-file state. **A build, not a bug.**
3. **A settable max-active download cap with the rest QUEUED**, per-file status
   like eMule. Anthony suggested 20 active. Same feature family as (2).
4. **Move the 1s heartbeat clock out of the UI.** It is a `Timer` on the main
   runloop (`EngineModel.startPolling`) driving eight duties that fail SILENTLY if
   it stops. It fires fine under the audio keepalive, but a background posture
   resting on the UI's runloop is fragile - the clock belongs in Rust as a tokio
   interval, keyed off `EngineState`. Ties directly to the seeding CPU question.
5. **Kad gaps still open** (8ce): no contact expiry or liveness ping (eMule's
   `OnSmallTimer` half), near-biased nodes.dat sample, no bootstrap retry, and
   `KadNode::add_contact` has no Kad-version gate so a peer can put a v1 contact
   in the table over the wire. The serve loop closes the "we never answer" half of
   this; expiry stays open.
6. **The server probe still runs UNDER THE ENGINE LOCK**, now for ~2s instead of
   6s. Taking it off was considered and NOT done: `persist_server_names` writes
   server.met and the lock is the only thing serialising that against
   `update_server_list` and `merge_discovered_servers`. Worth it only if 2s still
   shows up on a device reading.
7. **The pause teardown does not finish before iOS suspends** - 465ms to
   suspension, 30.5s to completion. `pause()` now logs whether the background
   assertion was GRANTED/REFUSED and how long the work waited. One background
   round trip on a current build answers it, and several background rounds have
   happened since without anyone reading the log. Do not theorise first.
8. Housekeeping: eleven remote branches fully merged and deletable; `main` is
   ahead of `origin/main`, unpushed; 66 commits on `fetch-funnel` unmerged.

## STANDING DIRECTIVE (2026-08-06)

**eMule 0.70b is the authority for GUI, Settings and per-file behaviour**
(Anthony). Third row in the authority table in `CLAUDE.md`; 0.50a still decides
the wire. Check 0.70b BEFORE designing a screen or a download state, and diverge
only deliberately.

## What these sessions actually taught

- **A doc comment can be filed against the wrong function and stay true.** Twelve
  did. Nothing catches this - not clippy, not tests, not review - because each
  block reads correctly on its own. The tell is an item with NO doc sitting next
  to one carrying two summaries.
- **A plan nobody links to does not exist.** A 1042-line committed plan for the
  top next action was invisible from index.md, log.md and the handoff, so the
  handoff asked for a decision the spec had already recorded.
- **A fix's own commit message is a claim, not a record.** 8cg said "all five are
  now lock-free" and converted four. **A test that pins "these callers" has to
  name every one of them.**
- **A cumulative counter cannot measure a stall on a serial queue.** Ticks are
  deferred, not lost; a max GAP is what measures it.
- **A constant that is always reached is not a bound, it is the cost.**
- **Alpha is a concurrency parameter.** The doc comment said so and was unread for
  a month.
- **Check an instrument can FAIL before believing it.**

## Related

- [[build-progress]] / [[kad-routing-lifecycle]] / [[log]] / [[decisions-and-lessons]]
- [[ipad-usb-tooling]] - install path, WDA runbook, the measurement rules above.
- [[padmule-ipa-delivery]] - the build-and-deliver loop (memory).
- [[net-highid-and-port-forwarding]] - the AirVPN setup; eMule on 5998, HighID.
