# HANDOFF TO FABLE 5 - padMule, next round

Rewritten 2026-08-08 by the Opus session that shipped the Kad serve loop, the
event-driven CSearch, and the device pass that verified both. **This entry is THE
AUTHORITY** (Anthony, 2026-08-08): it says what to do and how this project judges
it. [[handoff-next-session]] is the companion that records the verified state of
the tree; where the two disagree, this one wins and that one is stale.

## READ THESE FIRST, IN THIS ORDER

1. `/CLAUDE.md` - binding house rules. ASCII only, `->` and `-`, never arrows or
   dashes. Never modify `amule-3.0.1/` or `refs/`: a modified oracle proves
   nothing.
2. [[handoff-next-session]] - branch, gate, what CI has and has not run, what is
   proven vs assumed.
3. The authority table in CLAUDE.md. **eMule 0.50a decides the WIRE and file
   formats; aMule is the runnable oracle and decides wire-neutral policy; eMule
   0.70b decides GUI, Settings and per-file behaviour.** Where they conflict,
   follow eMule and say so with citations on BOTH sides.

## HOW THIS PROJECT JUDGES WORK - non-negotiable

- **Check the AUTHORITY, not the summary.** The spec lost to the eMule source
  FOUR times in two days: the empty `SEARCH_RES` (eMule stays silent), a missing
  ACK solicitation gate, the `OnSmallTimer` probe being a HELLO_REQ not a PING,
  and the frontier/table split. A design doc is a hypothesis.
- **MUTATION-CHECK every load-bearing assertion.** Break the rule, confirm the
  NAMED test goes red, restore - **and confirm the mutant COMPILED.** A mutation
  that fails to build reads as a false green; that happened twice here.
- **A test whose fixture derives its bound from the constant it asserts against
  is tautological.** Two cap tests in `kad_serve` were vacuous exactly that way,
  and the vacuity hid a real defect underneath.
- **Verify a FAILURE the way you verify a success.** Six bad readings this week
  were bad instruments, not bad features - including `ideviceinfo` answering "No
  device found" for a device that was plainly there.
- **A HARNESS THAT ENCODES THE RULES STILL HAS TO BE RUN.** `device-timing.sh`
  had been correct for a UI that changed underneath it and could not produce a
  number at all. Run your instrument before you trust its output.
- **Prefer a CONTROL over a bigger sample.** The device A/B had to be sequential,
  so drift was uncontrolled; the FIND_NODE answer rate matching across arms (51%
  vs 52%) is what made the result attributable. Find the quantity that should NOT
  change and show it did not.
- **Report what you OBSERVED.** Quote log lines. Say what you could not prove. An
  honestly reported partial beats a confident overstatement - the second gets
  written into the KB and believed.
- **Gate before claiming done:** `cargo test --workspace` (**700** pass on
  `kad-csearch`; none may regress), `cargo clippy --workspace --all-targets --
  -D warnings`, `cargo fmt --all -- --check`, changed files ASCII-only. Run the
  suite 3x - this codebase has had parallelism flakes from fixed-port binds; use
  ephemeral ports (0) in tests.
- **On a branch, the LOCAL gate is the only gate.** All three workflows fire only
  on push-to-`main`, PRs and `workflow_dispatch`; `ship.sh` dispatches them
  explicitly.
- Do NOT commit unless asked. Leave work in the tree and report its state.

## WHERE THINGS STAND

**The Kad owning-read-loop spec is FINISHED - both steps built, both verified.**

- Step 1, the serve loop (rows 8ck/8cl/8cm): padMule ANSWERS PING, HELLO,
  FIND_NODE, BOOTSTRAP and the inbound HELLO_RES_ACK, with eMule's exact flood
  budgets. Proven by an A/B inside ONE real amuled that EVICTED a silent control
  padMule and KEPT the answering one in the same sweep.
- Step 2, the event-driven CSearch (rows 8cn/8co): per-request deadlines, alpha
  kept in flight, value asks interleaved, no value phase. Off-device A/B: **-38%
  on a rare keyword, -69% on an abundant one** (9 of 9 alternating pairs). On the
  iPad: **search 6.79s -> 3.32s (-51%)**, `Longest poll gap` unchanged at 1.1s,
  Kad **TTFR 1939ms**, with the FIND_NODE answer rate the same in both arms.
  **Say "1.6x to exhaustion, 3.2x when it can stop early", never a flat
  multiplier**, and remember the device -51% is the JOINED server+Kad number -
  the Kad arm's own figure is the TTFR.

Detail: [[build-progress]] rows 8ck-8co, [[kad-routing-lifecycle]] for the
mechanism and every measurement.

## THE TRACKED TASK LIST, as it stands 2026-08-08

The session task list is ephemeral - it does not survive into your context, so it
lives here. **If you add tasks, restate them here on the way out.** An agent
handoff that depends on a list the next agent cannot see is not a handoff.

**#1 - Separate the background-seeding CPU cost: keepalive vs padMule's own 1 Hz
poll. CLOSED 2026-08-08, AND THE HYPOTHESIS WAS WRONG.** Same conditions as the
2026-08-07 baseline with ONE variable changed (`shouldRunFastPoll` throttles the
UI snapshot to 1 tick in 5 while `.seeding`): 30 samples, **15 above 5% CPU, 15
below, zero deaths**, footprint flat. Against the baseline's 27-of-58 that is the
SAME distribution at a fifth the poll rate. **padMule's poll is not the cost; the
audio keepalive is.** Do not re-open it as posed, and **do not let any write-up
claim the clock move buys CPU.** The remaining battery question is a NEW one:
what the audio session itself spends, and whether it can be made cheaper.

**#2 - Publish padMule's shares to Kad (Store File + Store Keyword, 0x43-0x45).
OPEN.** Item 1 below.

**#3 - Device-verify the CSearch rewrite. CLOSED 2026-08-08** (row 8co).

## THEN, IN PRIORITY ORDER

1. **Kad PUBLISHING (0x43-0x45).** padMule publishes NOTHING, so its shares are
   invisible to anyone searching Kad - findable only via the connected server's
   index and source exchange. That sits badly against a user turning seeding on to
   be a good neighbour. Observed on Anthony's own eMule the same week: 13,326 Kad
   operations in one session publishing his shares, one publish per WORD carved
   out of each filename. **Settle this before building, do not assume:** padMule
   is foreground-only and drops Kad on background, so a publisher that vanishes
   leaves stale source records pointing at nobody. Read eMule's real republish and
   expiry intervals out of `refs/emule-0.50a` (banked: sources 5h, keywords and
   notes 24h) and decide whether a foreground-only publisher is a net positive.
   Payloads are already decoded in [[kad-routing-lifecycle]]. It needs codecs AND
   a publish driver AND a scheduler together - codecs alone would be dead code,
   which is the row-8by mistake.
2. **Track 2 - concurrency under load. NEVER STARTED.** There is NO cap at all on
   concurrent downloads; each gets ~4 workers (`parallel_for_priority`), so 20
   downloads is ~80 concurrent dials. Anthony's complaint is that padMule handles
   many downloads badly. Use his eMule on the Acer as a CONTROLLED swarm (port
   5998, HighID) - a known other side beats a public one, whose variance has made
   every prior measurement ambiguous. **HARD RULE from the
   `controlled-swarm-acer` memory: never search for personal or family video, and
   confirm a hit by name AND location.**
3. **Per-file pause/resume, and a settable max-active cap with the rest QUEUED.**
   Neither exists - `pause()`/`resume()` are whole-engine lifecycle. Anthony asked
   for both plus a clear per-file state. eMule 0.70b is the authority for what the
   states are and what the row says. A build, not a bug.
4. **Move the 1s heartbeat clock out of the UI runloop** into Rust as a tokio
   interval keyed off `EngineState`. Eight duties fail SILENTLY if it stops.
   **This buys NO CPU** - refuted 2026-08-08. Do it for robustness and say so.
5. **Housekeeping: DONE 2026-08-08.** `kad-csearch` was fast-forwarded into
   `main` (`--ff-only`, history still LINEAR at 0 merge commits), the gate was
   re-run on the merged `main` itself, all three workflows went green for the
   merged tip, and both `kad-csearch` and `fetch-funnel` are DELETED, local and
   remote. Tips recorded in `/home/ajbufort/padmule-deleted-branches-2026-08-08.txt`
   (outside the repo), recoverable with
   `git push origin <sha>:refs/heads/<name>`. **`worktree-wave11-aich` was left
   alone deliberately** - its remote is already gone and its tip already recorded,
   but the local branch is held by a LOCKED worktree, and a lock is a deliberate
   signal. Its content is in `main` either way.
   **THE RULE THAT MADE THIS SAFE, keep it:** check merged-ness by **patch-id
   (`git cherry`), not ancestry.** For `fetch-funnel` ancestry claimed 89 commits
   would be lost; patch-id found an equivalent in `main` for all 89.

## MEASURING ON THE DEVICE - read before you touch it

Every session so far has produced at least one probe that was confidently wrong
before it was right. Budget for it; never let a first reading into the record.
Full runbook in [[ipad-usb-tooling]]; `scripts/device-timing.sh` now encodes the
search timing correctly. The ones that have bitten:

- **`ideviceinfo` / `idevice_id` / `idevicesyslog` DO NOT WORK here** - the iPad
  is "Not shared" to WSL by design and `pymobiledevice3` talks to Windows' Apple
  Mobile Device Service instead. "No device found" is the documented trap, not a
  missing device. Use `pymobiledevice3 usbmux list` and `syslog live -m padMule`.
- **Creating a WDA session RELAUNCHES the app** (measured: pid 2092 -> 2132), so
  every in-app counter resets while nodes.dat and server.met survive. Anything you
  want off a long-running session must be read BEFORE you open one, and opening
  one is the only way to read it - know you are making that trade. It also makes
  "warm disk, fresh counters, foreground" a REPRODUCIBLE A/B state.
- **An active XCUITest session BLOCKS `apps install` indefinitely** - ten minutes
  at ZERO CPU in `do_epoll_wait`, released instantly by `DELETE /session`. Close
  the session BEFORE installing, and never trust the install's exit: read
  `CFBundleVersion` back off the device.
- **An install over the top PRESERVES the data container.** Only deleting the app
  resets nodes.dat / server.met.
- **The results list is NOT cleared between searches.** Tap **Clear search** and
  assert ZERO rows before any clock starts. Match `Get` (one per row), never
  `srcs` - a single-source row reads `1 src`.
- **The search field CONCATENATES**, is an `XCUIElementTypeTextField` (find it by
  CLASS - "Search the eD2k network" is its PLACEHOLDER, and `label=Search` matches
  the Search TAB), and **`/wda/keyboard/return` does not exist** in WDA 16.1.1 -
  tap the keyboard's `search` key element. `curl` exits 0 on an error BODY, so
  both failures are SILENT.
- **A SwiftUI Toggle's element is the whole ROW** - tap
  `x = rect.x + rect.width - 30` and READ THE VALUE BACK.
- `GET /source` costs 1.70s ON THE MAIN THREAD; one `elements` query is ~0.18s.
  Poll with the cheap one, read `/source` once at the end.
- **A `pgrep -f "<string>"` waiter matches its own command line.** Poll the
  OBSERVABLE, not the process.

**HARD DEADLINE: the WebDriverAgent profile expires 2026-08-10 02:29:05 UTC.**
After that, UI DRIVING stops; `pymobiledevice3` (install, syslog, sysmon, dvt
launch, screenshot) keeps working. padMule's own profile runs to 2026-08-14. Only
Anthony can renew; the runbook is in [[ipad-usb-tooling]], and **step 3 (zsign
re-signing the nested `.xctest`) is not optional** - Sideloadly does not sign it
and iOS then refuses to load it.

## KNOWN CARRIED HAZARDS - inherit these knowingly

- **`request_batch` still has the stale-slot hazard on its OWN cancellation
  path** (bootstrap/hello only now). The lookup path is guarded by `SlotGuard`.
- **Kad contact expiry and the liveness ping do not exist on our side** - nothing
  evicts a contact anywhere. We ANSWER other nodes' pings; we never send our own.
  This is eMule's whole `OnSmallTimer` half.
- **`KadNode::add_contact` has no Kad-version gate**, so a peer's answer can
  insert a v1 contact even though the nodes.dat path gates `version > 1`.
  `CSearch::add` rejects `version <= 1` for the FRONTIER only, and
  `absorb_find_answer` feeds the TABLE first - so the gap is real and the rewrite
  did not close it.
- **`KAD_MAINTENANCE_BUDGET` (3s) exactly equals `REFRESH_DEADLINE_QUERIES` x
  `KAD_PER_QUERY`** (4 x 750ms), so for a full-length refresh the outer timeout
  and the lookup's own deadline fire together and cancellation is the NORMAL path.
  `SlotGuard` is load-bearing there, not a belt-and-braces extra.
- **`drive_lookup` dispatches BEFORE it checks `results >= want`**, so the value
  response that satisfies a search triggers one more harvest-and-refill batch
  whose replies are discarded. Wasted datagrams on the success path; not a
  correctness bug, never measured.
- Near-biased nodes.dat sample. No bootstrap retry within a foreground session.

## Related

- [[handoff-next-session]] - the verified state of the tree.
- [[build-progress]] rows 8ck-8co / [[kad-routing-lifecycle]] / [[log]]
- [[ipad-usb-tooling]] - the install path and every probe trap.
- [[kad-verify-oracle]] - the A/B oracle that proved the serve loop.
- [[interop-test-fidelity]] (memory) - why a green test can be worthless.
