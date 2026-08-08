# HANDOFF TO FABLE 5 - padMule, next round

Written 2026-08-08 by the Opus session that shipped the Kad serve loop and the
event-driven CSearch. This is a briefing for an agent picking up the next round,
not a status report. Start at [[handoff-next-session]] for general state; this
entry says what to do and how this project judges it.

## READ THESE FIRST, IN THIS ORDER

1. `/CLAUDE.md` - binding house rules. ASCII only, `->` and `-` never arrows or
   dashes. Never modify `amule-3.0.1/` or `refs/`: a modified oracle proves
   nothing.
2. [[handoff-next-session]] - current state, what is proven vs assumed.
3. The authority table in CLAUDE.md. **eMule 0.50a decides the WIRE and file
   formats; aMule is the runnable oracle and decides wire-neutral policy; eMule
   0.70b decides GUI, Settings and per-file behaviour.** Where they conflict,
   follow eMule and say so with citations on both sides.

## HOW THIS PROJECT JUDGES WORK - non-negotiable

- **Check the AUTHORITY, not the summary.** In this session the spec lost to the
  eMule source FOUR times: the empty `SEARCH_RES` (eMule stays silent), a
  missing ACK solicitation gate, the `OnSmallTimer` probe being a HELLO_REQ not
  a PING, and the frontier/table split. A design doc is a hypothesis.
- **MUTATION-CHECK every load-bearing assertion.** Break the rule, confirm the
  NAMED test goes red, restore. **And confirm the mutant COMPILED** - a mutation
  that fails to build reads as a false green, which happened twice here. A
  mutation check that cannot fail is worse than none.
- **A test whose fixture derives its bound from the constant it asserts against
  is tautological.** Two cap tests in `kad_serve` were vacuous exactly that way,
  and the vacuity was hiding a real defect underneath.
- **Verify a FAILURE the same way you verify a success.** Five "the process is
  DEAD" readings this week were bad instruments, not bad features.
- **Report what you OBSERVED.** Quote log lines. Say what you could not prove.
  An honestly reported partial beats a confident overstatement - the second gets
  written into the KB and believed.
- **Gate before claiming done:** `cargo test --workspace` (700 pass on
  `kad-csearch` now; none may regress), `cargo clippy --workspace --all-targets
  -- -D warnings`, `cargo fmt --all -- --check`, changed files ASCII-only. Run
  the full suite 3x - this codebase has had parallelism flakes from fixed-port
  binds; use ephemeral ports (0) in tests.
- Do NOT commit unless asked. Leave work in the tree and report its state.

## THE IMMEDIATE NEXT ACTION

**Device-verify the CSearch rewrite** (branch `kad-csearch`, commit `9b3402b`).
It is offline-green and has never run on hardware.

The A/B is already set up for you. The BEFORE figures, taken on device
2026-08-08 with the old round-based lookup (build-progress row 8cm), are
preserved verbatim in `stats.rs`, the FFI doc and build-progress:

| | before (rounds) |
|---|---|
| FIND_NODE rounds | 57, 57% with a silent peer, 73% answered, avg 601ms |
| value windows | 18, 44% silent, 75% answered, avg 560ms |
| search submit-to-results | 9.57 / 3.28 / 8.40 / 7.41 / 4.97s (FRESH install) |
| Longest poll gap | 1.1s |

**The cleanest experiment is OFF the device**: `mule-cli kad-keyword` calls
`resolve_keyword` directly, so old binary vs new, alternating against the live
network, measures the function with no probe, no UI and no server arm. That is
how the last Kad win was settled (median -25%, quoted honestly as "a quarter to
a half" rather than the 3x the arithmetic implied). Do that FIRST; the device
pass then only has to show no regression.

**The bar on device is: `Longest poll gap` stays ~1.1s**, and time-to-first-result
from the new panel. Expected win 2-3x on the Kad arm - **do not assert it, measure
it, and if it is smaller say the smaller number.**

## MEASURING ON THE DEVICE - read before you touch it

Every measurement session so far has produced at least one probe that was
confidently wrong before it was right. Budget for it; never let a first reading
into the record. Full runbook in [[ipad-usb-tooling]]. The ones that have bitten:

- **The WDA session is fatal at BOTH ends.** Creating one (any bundle) disturbs
  or kills the app; `DELETE /session` TERMINATES the app under test. Background
  with `pymobiledevice3 developer dvt launch <other.bundle>` and leave the
  session open.
- **`idevicesyslog` does not work here** (old usbmuxd path vs an iOS 17+
  tunnel). Use `pymobiledevice3 syslog live -m padMule`. The app logs its own
  lifecycle decisions - read them instead of inferring.
- **WDA `partial link text` is CASE-SENSITIVE**, and the results list is NOT
  cleared between searches. A content token must survive capitalisation AND be
  distinctive against the PREVIOUS query, or you time stale rows at t=0.
- **A SwiftUI Toggle's element is the whole ROW** - tap `x = rect.x + rect.width
  - 30` and READ THE VALUE BACK.
- `GET /source` costs 1.70s on the MAIN THREAD; polling it manufactures the
  freeze you are measuring.

**HARD DEADLINE: the WebDriverAgent profile expires 2026-08-10 02:29:05 UTC.**
After that, UI DRIVING stops - `pymobiledevice3` (install, syslog, sysmon, dvt
launch, screenshot) keeps working. Only Anthony can renew it; the runbook is in
[[ipad-usb-tooling]]. **So do the off-device A/B first** - it does not depend on
WDA at all.

## THEN, IN PRIORITY ORDER

1. **Kad PUBLISHING** (opcodes 0x43-0x45). padMule publishes NOTHING, so its
   shares are invisible to anyone searching Kad - findable only via the server
   index and source exchange. That sits badly against a user turning seeding on
   to be a good neighbour. **Settle this before building, do not assume:**
   padMule is foreground-only and drops Kad on background, so a publisher that
   vanishes leaves stale source records pointing at nobody. Read eMule's real
   republish and expiry intervals out of `refs/emule-0.50a` and decide whether a
   foreground-only publisher is a net positive. Payloads are already decoded and
   banked in [[kad-routing-lifecycle]].
2. **Track 2 - concurrency under load. NEVER STARTED.** There is NO cap at all
   on concurrent downloads; each gets ~4 workers, so 20 downloads is ~80
   concurrent dials. Anthony's complaint is that padMule handles many downloads
   badly. Use his eMule on the Acer as a CONTROLLED swarm (port 5998, HighID) -
   a known other side beats a public one, whose variance has made every prior
   measurement ambiguous. **HARD RULE from the `controlled-swarm-acer` memory:
   never search for personal or family video, and confirm a hit by name AND
   location.**
3. **Per-file pause/resume, and a settable max-active cap with the rest QUEUED.**
   Neither exists - `pause()`/`resume()` are whole-engine lifecycle. Anthony
   asked for both plus a clear per-file state. eMule 0.70b is the authority for
   what the states are and what the row says. A build, not a bug.
4. **Move the 1s heartbeat clock out of the UI runloop** into Rust as a tokio
   interval keyed off `EngineState`. Eight duties fail SILENTLY if it stops.
   **This buys NO CPU** - that hypothesis was tested and refuted 2026-08-08. Do
   it for robustness and say so.

## THE TRACKED TASK LIST, as it stands 2026-08-08

The session task list is ephemeral - it does not survive into your context, so
it is written out here. Two items, one closed and one open.

**#1 - Separate the background-seeding CPU cost: keepalive vs padMule's own 1 Hz
poll. COMPLETED 2026-08-08, AND THE HYPOTHESIS WAS WRONG.** Same conditions as
the 2026-08-07 baseline with ONE variable changed (`shouldRunFastPoll` throttles
the UI snapshot to 1 tick in 5 while `.seeding`): 30 samples, **15 above 5% CPU,
15 below, zero deaths**, footprint flat. Against the baseline's 27-of-58 that is
the SAME distribution at a fifth the poll rate. **padMule's poll is not the cost;
the audio keepalive is.** Do not re-open it as posed, and do not let any
write-up claim the clock move buys CPU. The remaining battery question is a NEW
one: what the audio session itself spends, and whether it can be made cheaper.

**#2 - Publish padMule's shares to Kad (Store File + Store Keyword, 0x43-0x45).
OPEN.** This is item 1 of the priority list above; the full statement of the
problem and the question to settle FIRST are there. Short version: padMule
publishes nothing, so its shares are invisible to anyone searching Kad -
findable only through the connected server's index and source exchange. Observed
on Anthony's own eMule the same week: 13,326 Kad operations in one session
publishing his shares as `Store File` and `Store Keyword`, one publish per WORD
carved out of each filename. padMule does none of it.

If you add tasks, restate them here on the way out. An agent handoff that
depends on a list the next agent cannot see is not a handoff.

## KNOWN CARRIED HAZARDS - inherit these knowingly

- **`request_batch` still has the stale-slot hazard on its OWN cancellation
  path** (bootstrap/hello only now). The lookup path was guarded; this one was
  outside that change's blast radius and is recorded rather than fixed.
- **Kad contact expiry and the liveness ping do not exist on our side** -
  nothing evicts a contact anywhere. We now ANSWER other nodes' pings, but we do
  not send our own.
- **`KadNode::add_contact` has no Kad-version gate**, so a peer's answer can
  insert a v1 contact even though the nodes.dat path gates `version > 1`.
- **`ios-test.yml` only fires on push to `main` and on PRs.** A branch-only
  workflow never runs it. That is how the Swift suite stayed broken for three
  builds.

## Related

- [[handoff-next-session]] / [[build-progress]] / [[kad-routing-lifecycle]]
- [[ipad-usb-tooling]] - the install path and every probe trap.
- [[kad-verify-oracle]] - the A/B oracle that proved the serve loop.
- [[interop-test-fidelity]] (memory) - why a green test can be worthless.
