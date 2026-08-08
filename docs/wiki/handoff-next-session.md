# HANDOFF - the state of the tree

Updated: 2026-08-08 by the row-8cp reanalysis pass, after the event-driven
CSearch landed AND was device-verified. Living doc - replace wholesale.

**[[handoff-for-fable]] IS THE AUTHORITY** (Anthony, 2026-08-08). It says what to
do next and how this project judges work. THIS entry is the companion: what is
true of the tree right now, and what is proven versus assumed. Where the two
disagree, the Fable handoff wins and this one is stale - say so and fix it.

Full narrative: [[build-progress]] rows 8ck-8cp and the [[log]] entries for
2026-08-07 and 2026-08-08.

## THE ONE-LINE SUMMARY

**padMule ANSWERS on Kad and its lookup is event-driven - BOTH steps of the
owning-read-loop spec are now built AND device-verified.** Search time on the
iPad halved (6.79s -> 3.32s) with the poll gap unchanged at 1.1s, and the
FIND_NODE answer rate was the same in both arms, so the win is structural.

## State of the tree - VERIFIED 2026-08-08, not remembered

- **Gate**: **711** Rust tests (0 failed, 2 ignored - both documented
  live-network tests); `clippy --workspace --all-targets -- -D warnings` clean,
  `fmt --check` clean, ASCII clean. It read 700 until 8cp added 5 tests, and 705
  until 8cq added 5 more, and 8cr added 1.
  **ONE KNOWN FLAKE, measured rather than waved off:**
  `request_reports_a_valid_receiver_key_when_the_peer_echoes_our_sender_key`
  failed once in six full-suite runs and passes 15/15 in ISOLATION - a
  pre-existing 2s-deadline loopback test that is sensitive to machine load, the
  same family as the fixed-port flake row 8ck found. Run a failing test ALONE
  before believing it is about your change.
  **The Swift suite has NOT been run for the 8cq change** - there is no Apple
  toolchain on this box, so `ios-test.yml` in CI is the only thing that compiles
  and runs it. The sharing-decision fix is UNPROVEN until that is green.
- **MERGED TO `main` 2026-08-08.** `kad-csearch` was fast-forwarded into `main`
  (8 commits, `--ff-only`, so history stays LINEAR - still 0 merge commits), the
  gate was re-run on the merged `main` ITSELF at 700 tests, and `main` is pushed.
  `kad-csearch` has since been DELETED (local and remote), as has `fetch-funnel`.
- **The last CODE commit is `9d9a031` plus the uncommitted 8cr round in the tree** (the 8cp/8cq fix round: the Kad answer
  count, the upload block bound, the table sender-key rule, the Kad1 gate, the
  flood-map bound, server-list vetting + the byte-reversed blocklist, the
  saturating `finds_inflight`, the UPnP honesty fix and the iOS sharing
  decision). **The device is therefore running OLDER code than `main`** - the
  build on it is `c656555`, so a reship is needed before any on-glass claim
  about this round. Previously `9b3402b` (the CSearch rewrite). Nothing under
  `crates/`, `ios/` or the manifests has changed since `c656555`, so **the build
  installed on the device IS `main`'s current shipped code** - a doc-only tip does
  not need a reship. **Check `git log` for the tip rather than trusting a sha
  written here** - a "state of the tree" line that names its own HEAD is stale the
  moment it is committed, which is exactly how row 8cn came to say "NOT
  committed" in the commit that committed it.
- **PUSHED, and all three CI workflows are GREEN for `c656555`** (dispatched by
  `ship.sh`, artifact verified, signed and installed). The branch-only CI hole
  below is therefore closed for THIS sha specifically - it is not closed in
  general.
- **`fetch-funnel` and `kad-csearch` are DELETED (2026-08-08), local and
  remote.** Tips are in `/home/ajbufort/padmule-deleted-branches-2026-08-08.txt`
  outside the repo, recoverable with `git push origin <sha>:refs/heads/<name>`.
  **Both were cleared by PATCH-ID (`git cherry`), never ancestry** - for
  `fetch-funnel` ancestry claimed 89 commits would be lost and patch-id found an
  equivalent in `main` for all 89, because a rebase changes every SHA. Keep that
  rule; it is the only thing standing between a tidy branch list and lost work.
- `worktree-wave11-aich` is a LOCKED worktree (10 ahead / 131 behind), and its
  remote is already gone with its tip already recorded. Its 10 commits are all in
  `main` by patch-id, so nothing is at risk by leaving it. A lock is a deliberate
  signal; do not override it.
- CI: `c656555` was dispatched explicitly by `ship.sh` and went green on all
  three. The push to `main` then fired all three AGAIN for the merged tip, which
  is the first time this work has had automatic CI coverage - branch tips never
  do. See the CI hole below.
- **Installed on device: `c656555`** - confirmed by `CFBundleVersion` read back
  off the device AND, more decisively, by the Stats panel's own text ("Every
  request races its own deadline now - no rounds"), which exists only in this
  build. A version string proves what was INSTALLED; a panel proves what is
  EXECUTING.
- **THE DEVICE IS WARM AGAIN, and this line used to say the opposite.** It was
  a fresh install for row 8cm (Anthony deleted the app mid-session), but it has
  since run: server.met carries 10 servers and nodes.dat is populated, verified
  on glass 2026-08-08 in both arms of the 8co pass. **An install over the top
  PRESERVES the data container**, so shipping a build does not reset it - only
  deleting the app does. Share library and downloads are still empty.

## THE CI HOLE, stated correctly

**All THREE workflows** (`rust.yml`, `ios-build.yml`, `ios-test.yml`) fire only
on `push` to `main`, on pull requests, and on `workflow_dispatch`. **A branch-only
workflow never runs any of them.**

The 2026-08-08 handoff recorded this against `ios-test.yml` alone, which invites
the assumption that the Rust gate at least covers branch work. It does not. What
made `ios-test.yml` uniquely dangerous was different: `ship.sh` dispatched the
other two and never dispatched or checked it, so the Swift bundle stayed
un-compiled for three builds while everything looked green. `ship.sh` now
requires all three green for the exact sha.

Practical consequence: on a branch, the LOCAL gate is the only gate. Run it.

## READ THIS BEFORE TRUSTING ANY GREEN

**THE SWIFT SUITE WAS RED FOR THREE BUILDS AND NOBODY KNEW (2026-08-08).**
`SettingsTests` called `Settings.register()`; no such type exists (it is
`SettingsDefaults`), so the ENTIRE padMuleTests bundle failed to COMPILE from
e3ed990 onward. Row 8cj cites that very test as its evidence. **A test you never
SAW run is not a test - green is evidence, absent is not, and a suite that cannot
compile reports nothing at all.** Fixed.

## THE SHIP LOOP - repaired, and its guards earn their keep

`scripts/ship.sh` = commit -> push -> CI(x3) -> verify -> sign -> install ->
confirm. **Anthony granted the signing key 2026-08-07**, so this is closed.

Guards, each paid for by a session it already cost:
1. **ALL THREE workflows green for the exact sha** (was: only the iOS build).
2. **`origin/<branch>` must already be at HEAD** - `gh workflow run --ref`
   builds the REMOTE ref. 12 local commits once sent CI to build a tip from
   before them; guard 3 caught it but reported the useless "no run found".
   **A guard that fires correctly can still fail the reader.**
3. The run's headSha must equal local HEAD.
4. `CFBundleVersion` read from a FRESH extraction of the downloaded ipa.
5. The installed build read back off the device.
6. `flock` - ONE ship at a time. Two overlapping runs both reached the install
   and both LOST it ("Coordinator superseded").

**PROFILE EXPIRIES: WebDriverAgent 2026-08-10 02:29:05 UTC, padMule 2026-08-14.**
WDA is the binding one - when it lapses, agent-driven UI testing stops until a
Sideloadly renewal (which breaks WDA's nested `.xctest` every time; budget a
re-sign). `pymobiledevice3` (install, syslog, sysmon, dvt launch, screenshot)
keeps working past it. Only Anthony can renew. Runbook in [[ipad-usb-tooling]].

## MEASURING ON THIS DEVICE - every session has produced a probe that lied

Budget for it. Never let a first reading into the record. Full runbook in
[[ipad-usb-tooling]]; the ones that have actually bitten:

- **The WDA session is fatal at BOTH ends, and the mechanism is now MEASURED:
  creating one RELAUNCHES the app** (padMule pid 2092 -> 2132 across a
  `POST /session`), so every in-app counter resets while nodes.dat and server.met
  survive; `DELETE /session` TERMINATES the app under test. Anything you want off
  a long-running session must be read before you open one, and opening one is the
  only way to read it - know you are making that trade. Background with
  `pymobiledevice3 developer dvt launch <other.bundle>` and leave the session
  open, or relaunch after closing.
- **An active XCUITest session BLOCKS `apps install` INDEFINITELY.** Ten minutes
  at ZERO CPU in `do_epoll_wait`, released instantly by `DELETE /session`. Close
  the session BEFORE installing, and never trust the install's exit - read
  `CFBundleVersion` back off the device.
- **A `pgrep -f "<string>"` waiter matches its own command line** and so never
  terminates. Poll the OBSERVABLE (the installed version), not the process.
- **Stop inferring - the app logs which branch it took.** `keepalive: STARTED` /
  `entering background SEEDING` / `the keepalive did not start - pausing
  instead`. One capture ends the argument.
- **`idevicesyslog` NO LONGER WORKS here** (old usbmuxd path vs an iOS 17+
  tunnel). Use `pymobiledevice3 syslog live -m padMule`. Older entries that say
  otherwise are stale.
- **WDA `partial link text` is CASE-SENSITIVE**, and the results list is NOT
  cleared between searches. A token must survive capitalisation AND be
  distinctive against the PREVIOUS query, or you get stale rows at t=0 and a
  ~1.2s reading that is probe latency wearing a search time's clothes.
- **A SwiftUI Toggle's element is the whole ROW.** Tap
  `x = rect.x + rect.width - 30` and READ THE VALUE BACK.
- The search field is an `XCUIElementTypeTextField`, not a `SearchField`.
- `GET /source` costs 1.70s ON THE MAIN THREAD - polling it manufactures the
  freeze you are measuring. One element query is 0.53s.
- Read **Longest poll gap**, never the cumulative tick counters: they are
  deferred, not lost, so a burst reproduces the same total.

## MEASURED

**Device, build `cadace2`, FRESH install, over AirVPN (row 8cm) - this is the
BEFORE-figure for the CSearch A/B:**

| Reading | Value | Note |
|---|---|---|
| Longest poll gap | **1.1s** | unchanged from 2026-08-07 - the serve loop cost the UI nothing |
| connect (HighID) | 6.5s | cold; 2.6s warm the day before |
| search submit-to-results | 9.57 / 3.28 / 8.40 / 7.41 / 4.97s | fresh table; NOT comparable to the warm 4.58-6.38 (n=9) |
| Kad FIND_NODE rounds | 57, 57% with a silent peer, 73% answered, avg 601ms | the round barrier WAS the cost |
| Kad value windows | 18, 44% silent, 75% answered, avg 560ms | |

Every Kad figure is modestly better than 2026-08-07's, **and none of it is
attributed to the serve loop** - different hour, different contact mix, fresh
table. These figures are preserved verbatim in `stats.rs`, the FFI doc and
[[build-progress]], because the panel that produced them no longer exists.

**THE CSEARCH DEVICE PASS, 2026-08-08 (row 8co) - build `c656555` IS ON THE
iPAD.** Both arms warm-disk / fresh-counters / foreground / HighID to the same
eMule Sunrise over AirVPN.

| Reading | before (`cadace2`, rounds) | after (`c656555`, CSearch) |
|---|---|---|
| search submit-to-first-results (n=5) | median **6.79s** | median **3.32s** (**-51%**) |
| `Longest poll gap` | 1.0s | **1.1s** - bar met |
| FIND_NODE answered | 71/138 = **51%** | 40/77 = **52%** |
| Kad time-to-first-result | no such field | **1939 ms**, 5 of 5 lookups |

**The equal answer rate is the control** - the swarm behaved the same in both
arms, so the halved search is structural, not a good hour. It matters because the
device arms were SEQUENTIAL, not alternating. **-51% is the JOINED server+Kad
number** (one `tokio::join!`, so the server arm floors it); the Kad arm's own
figure is the TTFR. n=5 per arm, one query, one server, one session.

**THE CSEARCH A/B, off-device, 2026-08-08.** Old (`main` @ `54384f2`) vs new
(`kad-csearch` @ `eb7ee3c`), alternating against the live network, same seed
nodes.dat, CLI `per_query` 1400ms both arms. Bootstrap is unchanged code and so a
CONTROL; it tracked within ~1s inside every pair.

| keyword | hits | old median search | new median search | delta | pairs won by new |
|---|---|---|---|---|---|
| "yes prime minister" | 50-55 | 8.26s | **2.56s** | **-69%** | 5 of 5 |
| "hedda hopper" | 4 | 9.12s | **5.64s** | **-38%** | 4 of 4 |

9 of 9 pairs won, result counts identical in both arms. **Quote it as "1.6x when
the lookup must run to exhaustion, 3.2x when it can stop early", never a flat
multiplier** - the spread is caused by which termination leg fires, and the
pre-build 2-3x estimate only counted the round barrier and missed that killing
the value PHASE is the bigger win. **This predicts nothing about the device**
(750ms + AirVPN + a 67% answer rate there, against 1400ms + no VPN + 85% here).
Detail and caveats in [[kad-routing-lifecycle]]; raw logs under
`$CLAUDE_JOB_DIR/tmp/ab-*.log`.

**Background seeding, 2026-08-07 soak:** 60 samples, ~70 minutes, ZERO deaths,
`physFootprint` flat at 32.1-32.2MB against a ~100MB jetsam budget.

**Background-seeding CPU: SETTLED 2026-08-08, and the hypothesis was WRONG.**
Re-soak with ONE variable changed (`shouldRunFastPoll` throttles the UI snapshot
to 1 tick in 5 while `.seeding`): 30 samples, 15 above 5% CPU / 15 below, zero
deaths, footprint flat. Against the baseline's 27-of-58 that is the SAME
distribution at a fifth the poll rate. **padMule's poll is not the cost; the
audio keepalive is.** Do not re-open it as posed, and do not let any write-up
claim the clock move buys CPU. The open battery question is a NEW one: what the
audio session itself spends.

## WHAT TO DO NEXT

**See [[handoff-for-fable]] - it is the authority and it carries the task list**,
including the 8cp findings ledger (twelve verified items found and deliberately
not fixed, ranked).
In one line: **the Kad spec is FINISHED - both steps built, oracle- and
device-verified (see MEASURED) - so the next round starts at Kad PUBLISHING**,
with concurrency-under-load behind it. The WDA profile expires 2026-08-10, which
is the deadline on anything needing UI driving.
[This section said "what is left is the DEVICE pass" until 2026-08-08, a day
after row 8co ran it - the same stale-status shape row 8cn hit.]

## STILL OPEN ON KAD

- Contact expiry and the liveness ping (eMule's `OnSmallTimer` half) do not exist
  on OUR side - nothing evicts a contact anywhere. We ANSWER other nodes' pings;
  we never send our own.
- `KadNode::add_contact` has **no Kad-version gate**, so a peer's answer can
  insert a v1 contact even though the nodes.dat path gates `version > 1`.
  `CSearch::add` rejects `version <= 1` for the FRONTIER only, and
  `absorb_find_answer` feeds the TABLE first - so the gap is real, not closed by
  the rewrite.
- `request_batch` still carries the stale-slot hazard on its OWN cancellation
  path (bootstrap/hello only). The lookup path was guarded by `SlotGuard`.
- Near-biased nodes.dat sample. No bootstrap retry.
- padMule PUBLISHES NOTHING (0x43-0x45). Payloads decoded and banked in
  [[kad-routing-lifecycle]]; deliberately not half-built.

## STANDING DIRECTIVES

- **[[handoff-for-fable]] is the authority for what to do next** (Anthony,
  2026-08-08).
- **eMule 0.70b is the authority for GUI, Settings and per-file behaviour**
  (Anthony, 2026-08-06). 0.50a still decides the wire.
- **Where the authorities conflict, follow eMule** - with citations on both sides.
- Keep the KB current as part of the work, not after it.

## What these sessions actually taught

- **The spec lost to the source four times in two days** - the empty
  `SEARCH_RES` (eMule stays silent), the missing ACK solicitation gate, the
  `OnSmallTimer` probe being a HELLO_REQ rather than a PING, and the
  frontier/table split. Check the authority DURING implementation.
- **A reported mutation table is a claim like any other**, and two first attempts
  came back falsely GREEN because the MUTANT DID NOT COMPILE. **A mutation check
  needs its own sanity check.**
- **A test whose fixture derives its bound from the constant it asserts against
  is tautological** - and the vacuity was hiding a real defect underneath.
- **A guard that fires correctly can still fail the reader.**
- **Doc comments drift onto the wrong item** when a new item is inserted after an
  existing block. Twelve had.
- **A status line written from a pre-commit draft outlives the commit.** Row 8cn
  said "NOT committed" in the commit that committed it.

## Related

- [[handoff-for-fable]] - THE AUTHORITY: what to do, and how work is judged.
- [[build-progress]] / [[kad-routing-lifecycle]] / [[kad-verify-oracle]] / [[log]]
- [[ipad-usb-tooling]] - install path, WDA runbook, every probe trap above.
- [[decisions-and-lessons]] / [[interop-test-fidelity]] (memory)
