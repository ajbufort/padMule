# HANDOFF - start here next session

Updated: 2026-08-08, after the Kad serve loop shipped and was device-verified.
Living doc - replace wholesale.

Full narrative: [[build-progress]] rows 8ck-8cm and the [[log]] entries for
2026-08-07 and 2026-08-08.

## THE ONE-LINE SUMMARY

**padMule ANSWERS on Kad now** - step 1 of the owning-read-loop spec is built,
oracle-proven against a real amuled, and on the device with no UI regression.
A real amuled EVICTED a silent control padMule and KEPT the answering one in the
same sweep.

## State of the tree

- **Gate**: **678** Rust tests, clippy `-D warnings`, fmt + ASCII clean. Swift
  suite is **6 files and GREEN AGAIN** - see the warning below.
- **BRANCH `fetch-funnel`, 83 commits ahead of `main`, nothing merged.**
  `main` is 4 ahead of `origin/main`, unpushed. **HEAD is currently UNPUSHED** -
  push before shipping (see the ship loop).
- **Installed on device: `cadace2`**, confirmed by reading Settings > This
  device > **Build**. The version string now reads **`0.1`** - it read `1.0` on
  every prior build because `MARKETING_VERSION` never reached the bundle.
- **THE DEVICE IS A FRESH INSTALL** (the app was deleted mid-session): no
  nodes.dat, no server.met, regenerated identity, EMPTY share library, no
  downloads. Any measurement that assumes warm state is not comparable to
  2026-08-07's.

## WHAT JUST SHIPPED (rows 8ck / 8cl / 8cm)

**One task owns the Kad socket.** padMule answers PING, HELLO, FIND_NODE and
BOOTSTRAP, plus the inbound HELLO_RES_ACK. Before this it answered NOTHING and
aged out of every routing table that learned it.

**The oracle proof is the strongest this project has produced.**
`scripts/kad-verify-oracle.sh` is an A/B inside ONE real amuled's routing table:
a CONTROL running the old one-shot `kad-bootstrap` (silence - literally what
padMule used to be) beside a SERVE node running the new `mule-cli kad-serve`.
Same sweep, same second: `EVICTED contact (77.77.0.8)` and
`REFRESH contact (77.77.0.9) type=2`. The counterfactual OBSERVED, not argued.
Reproduced on an independent second run. No timer was shortened.

**Device pass: the bar was no regression and it is met.** `Longest poll gap`
1.1s, identical to 2026-08-07.

**Flood limiter live** with eMule's exact budgets (BOOTSTRAP 2/min, HELLO 3,
KADEMLIA2_REQ 10, PING 2; ignore over, ban over 5x). `FloodTracker` had been
written and unused since there was no inbound path.

## READ THIS BEFORE TRUSTING ANY GREEN

**THE SWIFT SUITE WAS RED FOR THREE BUILDS AND NOBODY KNEW (2026-08-08).**
`SettingsTests` called `Settings.register()`; no such type exists (it is
`SettingsDefaults`), so the ENTIRE padMuleTests bundle failed to COMPILE from
e3ed990 onward. Two gaps let it run: `ios-test.yml` only fires on push to `main`
and on PRs, and `ship.sh` neither dispatched nor checked it. Row 8cj cites that
very test as its evidence. **A test you never SAW run is not a test - green is
evidence, absent is not, and a suite that cannot compile reports nothing at
all.** Fixed; `ship.sh` now requires all three workflows green.

## THE SHIP LOOP - repaired, and its guards now earn their keep

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

**PROFILE EXPIRIES: WebDriverAgent 2026-08-10, padMule 2026-08-14.** WDA is the
binding one - when it lapses, agent-driven device testing stops until a
Sideloadly renewal (which breaks WDA's nested `.xctest` every time; budget a
re-sign).

## MEASURING ON THIS DEVICE - every session so far has produced a probe that lied

Budget for it. Never let a first reading into the record. Full runbook in
[[ipad-usb-tooling]]; the ones that have actually bitten:

- **The WDA session is fatal at BOTH ends.** Creating one (any bundle) disturbs
  or kills the app; `DELETE /session` TERMINATES the app under test. That
  produced a fifth false "DEAD" for background seeding on 2026-08-08. Background
  with `pymobiledevice3 developer dvt launch <other.bundle>` and leave the
  session open, or relaunch after closing.
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
- **A SwiftUI Toggle's element is the whole ROW.** Clicking it, or its rect
  centre, hits the label and does nothing. Tap `x = rect.x + rect.width - 30`
  and READ THE VALUE BACK.
- The search field is an `XCUIElementTypeTextField`, not a `SearchField`.
- `GET /source` costs 1.70s ON THE MAIN THREAD - polling it manufactures the
  freeze you are measuring. One element query is 0.53s.
- Read **Longest poll gap**, never the cumulative tick counters: they are
  deferred, not lost, so a burst reproduces the same total.

## MEASURED

**Device, build cadace2, FRESH install, over AirVPN:**

| Reading | Value | Note |
|---|---|---|
| Longest poll gap | **1.1s** | unchanged from 2026-08-07 - no regression |
| connect (HighID) | 6.5s | cold; 2.6s warm yesterday |
| search submit-to-results | 9.57 / 3.28 / 8.40 / 7.41 / 4.97s | fresh table; NOT comparable to yesterday's warm 4.58-6.38 (n=9) |
| Kad FIND_NODE rounds | 57, 57% with a silent peer, 73% answered, avg 601ms | |
| Kad value windows | 18, 44% silent, 75% answered, avg 560ms | |

Every Kad figure is modestly better than 2026-08-07's, **and none of it is
attributed to the serve loop** - different hour, different contact mix, fresh
table. What it establishes: the barrier is still the dominant cost, so **step
2's case is unchanged**.

**Background seeding, 2026-08-07 soak:** 60 samples, ~70 minutes, ZERO deaths,
`physFootprint` flat at 32.1-32.2MB against a ~100MB jetsam budget. Survival is
settled. CPU was NOT: samples split almost exactly evenly above/below 5% (27/58)
against 0.1% foreground-idle.

## THE TOP NEXT ACTION

**Finish the seeding-CPU experiment.** A re-soak is running as of 2026-08-08
with the ONE variable changed: `EngineModel.shouldRunFastPoll` throttles the
full UI snapshot to 1 tick in 5 while `.seeding`. Compare the above/below-5%
split against 27/58. **If the split survives, the audio keepalive owns the cost
and padMule's own poll is exonerated** - which is worth knowing before anyone
redesigns the clock. The obvious "it is our poll" hypothesis has a hole: a 1 Hz
signal would be caught by nearly any sampling window, not half of them.
Log: `$CLAUDE_JOB_DIR/tmp/soak2.log`, script beside it.

## THEN

1. **Step 2 of the Kad spec: the event-driven `CSearch`.** Now unblocked - step
   1 is device-verified, which was the stated precondition. Worth ~2-3x on the
   Kad arm. `docs/superpowers/specs/2026-08-07-kad-owning-read-loop-design.md`.
   **The instrument must change with it**: `stats::kad_report` counts ROUNDS,
   which stop existing. Take a final old-panel reading first.
2. **Kad PUBLISHING (task #2).** padMule publishes nothing, so its shares are
   invisible to anyone searching Kad - findable only via the server index and
   source exchange. That sits badly against turning seeding on to "be a good
   neighbor". Settle first, do not assume: is a foreground-only publisher a net
   positive, given it vanishes and leaves stale source records? Read eMule's
   real republish/expiry intervals before building.
3. **Track 2 - concurrency under load. NOT STARTED.** No cap at all on
   concurrent downloads; each gets ~4 workers, so 20 downloads is ~80 dials.
   Use the Acer as the controlled swarm.
4. **Per-file pause/resume DOES NOT EXIST**, nor a max-active cap with the rest
   queued. Anthony asked for both. A build, not a bug.
5. **Move the 1s clock out of the UI runloop** into Rust as a tokio interval
   keyed off `EngineState`. Eight duties fail SILENTLY if it stops.
6. Housekeeping: eleven remote branches fully merged and deletable; `main`
   unpushed; **83 commits on `fetch-funnel` unmerged and never PR'd**.

## STILL OPEN ON KAD

Contact expiry and the liveness ping (eMule's `OnSmallTimer` half) still do not
exist on OUR side - nothing evicts a contact anywhere. Near-biased nodes.dat
sample. No bootstrap retry. `KadNode::add_contact` has no Kad-version gate, so a
peer's answer can still insert a v1 contact even though the nodes.dat path gates
`version > 1`.

## STANDING DIRECTIVES

- **eMule 0.70b is the authority for GUI, Settings and per-file behaviour**
  (Anthony, 2026-08-06). 0.50a still decides the wire.
- **Where the authorities conflict, follow eMule** - and say so with citations
  on both sides.
- Keep the KB current as part of the work, not after it.

## What these sessions actually taught

- **The spec lost to the source three times in one day** - the empty
  `SEARCH_RES` (eMule stays silent), the missing ACK solicitation gate, and the
  `OnSmallTimer` probe being a HELLO_REQ rather than a PING. Check the authority
  during implementation, not before it.
- **A reported mutation table is a claim like any other.** Re-running a
  sub-agent's checks found a real gap (`Drop { read_loop.abort() }` covered by
  no test) - and two of my own first attempts came back falsely GREEN because
  the MUTANT DID NOT COMPILE. **A mutation check needs its own sanity check.**
- **A test whose fixture derives its bound from the constant it asserts against
  is tautological** - and the vacuity was hiding a real defect underneath.
- **A guard that fires correctly can still fail the reader.**
- **Doc comments drift onto the wrong item** when a new item is inserted after
  an existing block. Twelve had. The tell: an item with NO doc beside one
  carrying two summaries.

## Related

- [[build-progress]] / [[kad-routing-lifecycle]] / [[kad-verify-oracle]] / [[log]]
- [[ipad-usb-tooling]] - install path, WDA runbook, every probe trap above.
- [[decisions-and-lessons]] / [[interop-test-fidelity]] (memory)
