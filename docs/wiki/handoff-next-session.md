# HANDOFF - start here next session

Updated: 2026-08-06, after the full-tree reanalysis pass (row 8ce).

Living doc - replace it wholesale next time. Full narrative: [[build-progress]]
rows 8bt-8ce and the [[log]] entries for 2026-08-04 through 2026-08-06.

**READ THIS FIRST if you were about to go read Kad numbers off the device.** The
2026-08-06 reanalysis found that the "Kad contacts" reading this handoff
nominated as the verdict on row 8cd **could not fall on any build**, and that
8cd's resume fix named the wrong table. Open leads 2 and 3 are rewritten
accordingly; the mechanism is [[kad-routing-lifecycle]].

**THREE OF THE SIX FINDINGS ARE ALREADY FIXED (row 8ce, same day):** the live Kad
table is now SEEDED from what we already know instead of from one bootstrap
response; "Kad contacts" reports one quantity (the live table) instead of two;
and `maintain_kad` has a real 3s deadline instead of a 9s structural bound held
under the engine lock. **So the number is now worth reading again** - but only on
a build carrying this, which as of writing is NOT the delivered `2186e48`.
Findings 4-6 (contact expiry + liveness ping, the near-biased nodes.dat sample,
the missing bootstrap retry) are open by choice - see items 11-12.

## State of the tree

- **Gate**: 628 Rust tests + 24 Swift simulator tests, clippy `-D warnings`
  clean, fmt clean, ASCII clean. Re-verified locally 2026-08-06.
- **YOU ARE ON BRANCH `fetch-funnel`, NOT main**, and nothing is merged. Decide
  that first. History is LINEAR across 447 commits and must stay that way
  (`gh pr merge --rebase`). Do not trust prose for counts - run
  `git log --oneline main..HEAD` and `git log --oneline origin/main..main`.
  Measured 2026-08-06: **33 ahead of local `main`**, and local `main` is 4 ahead
  of `origin/main`. (This line said "17 ahead" for a while, which is exactly why
  it tells you to run the command.)
- **`rust.yml` only fires on push to `main` and on PRs**, so none of the 33
  branch commits have been through the CI Rust gate. The LOCAL gate is the only
  one that has run on this work.
- Oracles: differential AND reverse both re-run GREEN 2026-08-05. Kad-verify not
  re-run. NOTE what the reverse oracle does NOT cover: `mule-cli serve-file`
  passes no upload gate and its fixture is 300KB with one downloader, so it
  never drives the slot rotation (8by). A green oracle proves only the path it
  drives - the third time that has mattered.
- **Latest IPA delivered: `2186e48`** (2026-08-05, CI run 30988060927), current
  with the branch. Carries the reservation-leak fix (8cb) AND the Kad
  maintenance + reseed fixes (8cd). Verified by reading the plist out of the
  delivered artifact, not from the CI log. iPadOS 26.6. Cert lapses ~2026-08-12.
- **The device can now name its own build.** CI stamps the git short sha into
  `CFBundleVersion`, and Settings > This device > **Build** reads
  "1.0 (short-sha)", selectable - so on the delivered build it should read
  **"1.0 (2186e48)"**. Confirm an install by READING that row, not by spotting a
  UI change. (This line used to quote `d24e88d`, the build BEFORE the delivered
  one, which is the wrong thing to check an install against.)
- Both iOS workflows re-run green on this branch: the .ipa build and the Swift
  simulator tests (24 tests). The Swift tests are the ONLY type-check available
  from this box - dispatch `ios-test.yml` after any Swift edit, and **verify
  `gh run view --json headSha` matches local HEAD**: a dispatch once raced the
  push and reported success for the PREVIOUS commit (row 8cc).
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

**2. "N parts missing from all M peer reports"** on each transfer row. Parts still
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
13. **(2026-08-05) Kad got its first routing maintenance** (`maintain_kad`, a
    random-target lookup every 120s) - it had NONE, which was both the low
    contact count and the thin keyword results. And resume stopped throwing the
    table away: it re-seeded from nodes.dat only, discarding what `pause()` had
    just folded into memory (138 -> 21 in one round trip). Row 8cd.
14. **(2026-08-05) The probe stopped calling every server dead on a cold start**
    - "checking..." until three real misses, plus an auto re-probe 6s after
    boot. Row 8cd.
11. **(2026-08-05) An idle row now says WHICH kind of nothing it is** - "no
    sources found" vs "0 of 3 connected, 12 awaiting callback". Found by Anthony
    on glass, not by a code read. Row 8bz.
12. **(2026-08-05) Kad is no longer skipped on a useless server answer**, plus
    **Dark Mode** (Appearance, first in Settings, light unless chosen) and a
    provider-agnostic **VPN badge + drop warning**. Row 8bz.

## OPEN - named as open, not explained

1. **[LIKELY CLOSED 2026-08-05, row 8cb] The stall whose blocker a RESTART
   clears - it was the BLOCK-RESERVATION LEAK.** A cancelled peer session never
   released its reserved blocks (`timeout` drops the future; the release was
   trailing code), so `reserved` grew monotonically and a restart forgot it.
   That is a third in-memory gate, and it fits the 85%-then-restart-finished
   report better than either enumerated candidate. Fixed. Confirm on the next
   build by watching whether a near-complete download still goes quiet.
   **THE BAN-SET NARROWING WAS REFUTED BY MEASUREMENT, and it was mine.** This entry said the per-download ban
   set was the live hypothesis, on the strength of a code read: a HashSet never
   lifted anywhere, never persisted, consulted before dialing. The device funnel
   then read **`skipped: source BANNED` = 0** across 2719 dials and ~1235
   sessions. It never fired. The reasoning was clean and the answer was still
   no - which is exactly why the counter was placed there. Do not re-adopt the
   ban set without new evidence. `spawn raced a live fetch` = 0 too, as expected
   (see instrument 3). **What the same reading DID surface: `fetches in flight`
   = 3 against SIX queued downloads**, so three downloads had no live fetch task
   at all. That is the live lead now - a download whose fetch task has ended and
   which the retry sweep is not re-driving. Row 8ca.
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
7. ~~Kad gave ZERO sources...~~ **CONFIRMED then FIXED 2026-08-05 (row 8bz).**
   It was partly self-inflicted: `find_sources` skipped the Kad arm on ANY
   non-empty server answer, and a mostly-LowID swarm answers with a healthy
   count that yields almost nothing dialable. Confirmed live first - six
   downloads across two samples, every badge `ed2k` or `sx`, not one `kad`. The
   gate is now on DIALABLE sources with the threshold tied by test to the Normal
   worker-pool width. STILL OPEN: whether Kad now actually contributes on
   device. Watch for a `kad` badge on the next build.
8. **[MEASURED then HALF-FIXED 2026-08-07 - Track 1, row 8cg] The GUI slowness
   is real, it has TWO stacked causes, and the status-freeze half is now fixed
   (UNVERIFIED ON DEVICE - re-run the refresh-during-search timing below).** On device: search **10.3s**; server refresh alone
   **7.5-9.3s**; the same refresh tapped 1.9s into a search **20.62s**. So an
   action issued during a search waits ~12s extra.
   - **Cause 1**, the Rust engine mutex: 25 of 42 FFI methods take it, and the
     1s poll takes it five times.
   - **Cause 2, and it changes the fix**: `EngineModel.swift:376` declares a
     **SERIAL** `DispatchQueue`, and every engine call goes through
     `work.async` - so it serialises even the LOCK-FREE Rust methods. The
     lock-free work already done (8bq, the funnel's `fetch_report`) is partly
     defeated on the Swift side. **Making more Rust methods lock-free would NOT
     fix this on its own** - which is the fix a code read alone would pick.
   - The two cannot be separated from outside the app; either alone produces the
     measurement. The Swift queue being serial is provable from the declaration.
   - **FIXED (8cg):** the four scalars are now lock-free atomics published
     through `EngineHandles`, and on the Swift side they moved out of
     `refresh()` (which sat behind `heartbeat()` on the serial queue) into
     `refreshFast()`. Pinned by a test that HOLDS the engine mutex for 3s and
     asserts the readers answer in 500ms - it fails by TIMING, which is the only
     way this regression is catchable, since re-adding a lock breaks nothing
     functionally.
   - **STILL OPEN, and separable: the operations are individually slow.**
     `SEARCH_WAIT` 20s (both arms awaited), `PROBE_COLLECT_BUDGET` 6s held under
     the lock. A search still takes ~10s; it just no longer freezes the UI.
     Two problems, one fixed.
   Portability Tier 2; Settings Tier 1/2.
9. **THE KAD FINDINGS FROM THE 2026-08-06 REANALYSIS (row 8ce)** are items
   10-12, plus the two corrections already folded into open leads 2-3 below and
   into [[kad-routing-lifecycle]]. None is a regression; all are pre-existing,
   and most are 8cd's own new code read against what it actually does.
10. ~~`maintain_kad` is the only Kad call with no deadline.~~ **CLOSED
    2026-08-06, row 8ce** - `KAD_MAINTENANCE_BUDGET` (3s), pinned by test to be
    strictly under `refresh_routing`'s 9s structural worst case so the cap
    actually binds. Partial work is kept and the gain is measured from the table,
    so a cancelled round still reports what it learned.
11. **(2026-08-06, row 8ce) STILL OPEN: only eMule's `OnBigTimer` half of Kad
    maintenance exists.** No contact expiry, no liveness ping, no eviction -
    `Contact` has no timestamp and `RoutingTable` has no removal path. So dead
    contacts accumulate in a monotonic table and get written into nodes.dat,
    where the truncation to 200 is ALSO near-biased (padMule takes the first 200
    in tree order; eMule takes a deliberately SPREAD sample via `TopDepth(4)`).
    And `KAD_TABLE_TARGET`'s comment "Refresh resumes if the table shrinks"
    describes something that cannot happen.
12. **(2026-08-06, row 8ce) STILL OPEN, but much narrower: a failed Kad bootstrap
    is unrecoverable in-session.** `start_kad` runs only from
    `start()`/`resume()`. The seeding fix means a failed bootstrap now leaves a
    POPULATED table, so `maintain_kad`'s `contacts_known() == 0` guard no longer
    locks Kad off for the session - maintenance can carry it. What is still
    missing is a bootstrap RETRY. Also unfixed and separate: `KadNode::add_contact`
    has no Kad-version gate, so a peer that NAMES a v1 contact over the wire gets
    it into the table and a lookup can spend `KAD_PER_QUERY` on a node the
    protocol cannot speak to. The seeding path is safe (`gate_loaded_nodes`
    filters version > 1); the wire paths are not.
13. **Housekeeping, verified safe 2026-08-05 and re-verified 2026-08-06:** ELEVEN remote branches (not ten)
   are fully merged - `git cherry main origin/<b>` reports every commit
   patch-equivalent for all of them, including `worktree-wave11-aich` - so they
   and the locked worktree at `.claude/worktrees/wave11-aich` can be deleted.
   `main` is also 4 commits ahead of `origin/main`, unpushed.

## LIVE STATE at close (2026-08-05, build d24e88d on the iPad)

- **Best throughput padMule has ever shown: ~990 MB in 23 minutes across six
  downloads, ~718 KB/s sustained** (measured from timestamped screenshots, not
  the Stats screen). Against 106 KB/s on the 2026-08-04 device run.
- **THE FUNNEL WAS CAPTURED, and it names the bottleneck (row 8ca):**

      slot ACCEPTED              959
      accepted, no block to take 722     <- 75% of every slot we win
      requested blocks           237
      DELIVERED bytes            222

  padMule wins an upload slot - the scarcest thing on eD2k - and has nothing to
  ask for three times in four. The arithmetic closes exactly (722+237=959), and
  every OTHER stage is healthy: 42% of dials handshake (vs 5% in the 8bt
  baseline), 78% of slot asks are accepted, 94% of block requests deliver. There
  is now exactly ONE lossy stage and it is on padMule's side of the wire.
  **THE NEXT PIECE OF WORK IS HERE**, not in the swarm.
- Also live at close: an ebook stuck at 23.2/25.9 MB (89%) for 23 minutes with 4
  handshaked sources and no parts-missing badge - 2.7 MB remaining against the
  2.11 MB that four workers x three blocks can hold reserved.
- `100.avi` sat at Zero KB throughout with 15 server-advertised sources. Row
  8bz's badge should now say whether they are unreachable or LowID-only; that
  needs the next build to answer.

## DEVICE TOOLING NOTE

A WebDriverAgent runner and a `usbmux forward 8100 8100` were left RUNNING on
purpose. **Starting a session is the disruptive act, not holding one** - reuse
the live one rather than cycling it. Session-free reads (`pymobiledevice3
developer dvt screenshot`, `GET /source`) disturb nothing and are what the whole
2026-08-05 observation session ran on.

## OPEN LEADS FROM THE 2026-08-05 DEVICE SESSION

1. **The pause teardown does not finish before iOS suspends.** Captured: 465ms
   from `pause (backgrounded)` to `Suspending`, and `state -> paused` only 30.5s
   later, on the way back IN. So the "clean, honest pause/resume" that
   [[lifecycle-and-reactivation]] calls a HARD requirement is not what actually
   happens - the process is frozen mid-teardown and its sockets reclaimed. Two
   mechanisms fit and the log cannot separate them: the background-task
   assertion was refused, or `e.pause()` queued behind something long on the
   SERIAL work queue (the 6s server probe is a candidate). **`pause()` now logs
   both** - assertion GRANTED/REFUSED, and how long the work waited before it
   STARTED. Capture a background round trip on build 2186e48 and the answer is
   in those two lines. Do not theorise first.
2. ~~**Kad recovery baseline, for comparing the fixes.** The table was watched
   going 21 -> 223 organically...~~ **THIS TEST CANNOT WORK, AND THE REANALYSIS
   SAYS WHY (2026-08-06, row 8ce).** The "Kad contacts" number on screen is
   `Engine::routing.len()` - the PERSISTED table - and `RoutingTable` has no
   removal path anywhere, so **it is monotonic and cannot fall on any build**.
   It climbed before `maintain_kad` existed and it will climb after; the reading
   is not evidence about it either way. Worse, the same UI field is ALSO written
   by the `Kad` event, which carries the PERSISTED count from `start()` but the
   **LIVE node's** count from `start_kad` and `maintain_kad` - so the field
   alternates between two different quantities at 1s resolution. **The 21 in the
   "21 -> 223" baseline is not a damaged table; it is a freshly-bootstrapped
   LIVE node**, which is what `start_kad` produces every single time.
   Do NOT spend a device session on this reading until the two quantities are
   separated. See [[kad-routing-lifecycle]].
3. **Whether `maintain_kad` lifts the LIVE table, which is the only one lookups
   read.** Still the right question; it just needs an instrument that can answer
   it. Note what 8ce found underneath it: the live table is rebuilt from ONE
   bootstrap response (~21 contacts, of which exactly ONE is verified and
   therefore visible to `closest_to`) on every start AND every resume, because
   `bind_with_identity` constructs an empty table and nothing seeds it from
   `Engine::routing`. The 8cd union improved the bootstrap DIAL LIST, not the
   table. Kad keyword-search quality tracks the LIVE table, so that is the thing
   to fix and then measure.

## THE TOP NEXT ACTION

**RE-READ `accepted, no block to take` ON THE NEXT BUILD.** It was 722 of 959,
and the cause was found and fixed the same day (row 8cb): a CANCELLED session
never ran the release of its block reservations, because `timeout` drops the
future and a dropped future skips trailing code - so every timed-out peer
stranded 3 blocks permanently, and `reserved` only ever grew. Fixed with a
destructor; RED-first and mutation-checked; both oracles green.

**That fix is a hypothesis about the LIVE number until the funnel says so.**
What remains possible underneath it is the narrower contention band row 8bt
proved: `ENDGAME_LIMIT` is 4 blocks where four workers can hold 12, so a
download with 737KB < missing < 2.11MB is fully reserved by its own workers.
Real, unmeasured, and deliberately not bundled - widening endgame costs
duplicate tail traffic. If the line is still high, that band is next.

Note also this closes open item 1 differently than expected: **the leak is the
restart-clearable gate**, not the ban set (which measured 0).

## Discipline this session actually paid for

- **When two theories have failed, stop and build the instrument.** It refuted
  my own fresh hypotheses THREE times: the 0x57 handler was genuinely missing
  yet SECONDARY; the small-file reservation theory was half wrong; and the
  needed-parts gate looked like a regression until the control cleared it.
  **Citing the upstream source line proves the code is wrong, not that it is
  what is hurting you.**
- **A zero-result test is not a failing test until the CONTROL runs.**
- **(2026-08-06) A NUMBER THAT CANNOT FALL CANNOT BE A VERDICT.** This handoff
  nominated "watch Kad contacts climb" as the test of a fix, against a counter
  that is monotonic by construction - and the same UI field is fed by two
  different quantities depending on which code path last wrote it. Before
  nominating a reading as the judge of a change, ask what it does when the change
  DOESN'T work. If the answer is "the same thing", it is not an instrument.
  This is [[an-event-is-not-state]] instance 7, inverted: durable state
  OVERWRITTEN by an event carrying a different measurement.
- **(2026-08-06) A fix can be right and its stated cause still wrong.** 8cd's
  resume union is a genuine improvement to the bootstrap dial list. Its commit
  message explains it as recovering a table that was never lost. The mechanism
  gets written into the wiki alongside the fix and is what the NEXT session
  reasons from - so an unverified cause attached to a working fix is more
  durable than an ordinary mistake, not less.
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
- [[kad-routing-lifecycle]] - the two routing tables, and why the Kad readings
  in this doc had to be rewritten.
- [[padmule-ipa-delivery]] - the build-and-deliver loop.
- [[ipad-usb-tooling]] - device runbook, incl. the read-only rule above.
- [[net-highid-and-port-forwarding]] - the AirVPN Local-port trap.
- [[lifecycle-and-reactivation]] - foreground-only, permanent.
