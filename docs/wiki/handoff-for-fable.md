# HANDOFF TO FABLE 5 - padMule, next round

Updated: 2026-08-08 (rows 8cp + 8cq + 8cr - the reanalysis and the two fix
rounds that followed it. Nine defects fixed and COMMITTED as `9d9a031`; the ledger below
records what is CLOSED and what is still open, and two findings that named the
WRONG remedy until the eMule source was read.)

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
- **Gate before claiming done:** `cargo test --workspace` (**711** pass as of the
  8cr round - 700 before 8cp, 705 after it, 710 after 8cq; none may regress), `cargo clippy
  --workspace --all-targets -- -D warnings`, `cargo fmt --all -- --check`,
  changed files ASCII-only. Run the suite 3x - this codebase has had parallelism
  flakes from fixed-port binds; use ephemeral ports (0) in tests.
- **A test that HANGS on regression is a defective test**, not a slow one. The
  8cp boundary mutation took 60s to fail because a refused request produces no
  packet and the read loop had no timeout - and a hang reads as an
  infrastructure problem rather than the defect it just caught, which is how a
  real regression gets waved off as a flake. Bound every wire read in a test.
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

## WHAT THE REANALYSIS FOUND (2026-08-08, rows 8cp/8cq) - the carried ledger

Two defects were FIXED (see [[build-progress]] 8cp): the Kad answer ignored the
contact COUNT the requester asked for, so every value lookup we answered was
discarded wholesale by the asker; and the upload serve path had no block-size
bound, so one packet could make us allocate the whole shared file. Both
eMule-grounded, test-first, mutation-checked.

**CLOSED by the follow-up round, same day** (all TDD, all mutation-checked
except where noted; the Swift one is CI-verified only, see below):

- ~~1. The CSearch split lost the anti-hijack refusal on the routing table.~~
  **CLOSED - and the finding NAMED THE WRONG REMEDY, which is the part worth
  keeping.** Reading eMule rather than the report: the frontier/table split IS
  faithful - `Process_KADEMLIA2_RES` feeds the table via `AddUnfiltered` and
  applies `IsAcceptableContact` only to what the SEARCH sees
  (KademliaUDPListener.cpp:848). Applying the frontier filter to the table, as
  the finding proposed, would have STARVED the table - the exact regression
  Anthony caught mid-build in 8cn. What eMule's table path really carries is a
  SENDER-KEY check: an entry holding a key may only be updated by a packet
  carrying the same key, and an empty key explicitly fails ("Sent Empty: Yes",
  RoutingZone.cpp:525-533) - which is precisely what a third party's RES payload
  is. Implemented in `Zone::add`, narrowed to the ADDRESS CHANGE because
  padMule records keys out of band so `add` never carries one.
- ~~2. The Kad flood maps have no pruner.~~ **CLOSED.** `MAX_TRACKED_IPS` (4096)
  now lives in `hardening.rs` and `FloodTracker::record` prunes then refuses to
  grow, fail-open, bounding every user of the type rather than one call site.
- ~~4. Two UDP fan-outs skip the SSRF gate.~~ **CLOSED, AT A DIFFERENT PLACE
  THAN PROPOSED.** Gating the fan-outs would have broken a supported setup -
  padMule's own eserver oracle runs on 127.0.0.1, and a LAN server the user
  added is legitimate. The actual hole was upstream: `update_server_list`
  fetches a server.met over PLAIN HTTP from a user-configured URL and merged it
  with NO vetting, so a hostile or MITM'd list could inject loopback/LAN entries
  that later became UDP targets. Vetting now happens at INGESTION
  (`vet_downloaded_servers`), matching where the crawl is gated.
  **AND IT UNCOVERED A LIVE BUG NOBODY HAD FILED:** the crawl's blocklist check
  passed the raw met-u32 to `is_blocked_u32`, which wants HOST order - the two
  are byte-reversed, so **the user's IP blocklist has never actually filtered a
  discovered server.** Verified empirically before fixing (85.17.116.222 reads
  unblocked as the met u32, blocked as the host-order one), fixed at both sites,
  and pinned by a case in `harvested_servers_are_filtered_and_merged`.
- ~~5. iOS: the cellular toggle cancels the public-address pause.~~ **CLOSED.**
  The rule is now the pure `EngineModel.sharingDecision(...)`, which returns
  `nil` ("push nothing") when an ON decision would clear a pause the user did
  not lift; only `setSharing` passes `userInitiated: true`. The OFF direction is
  never gated. `SettingsTests` now calls the REAL rule instead of re-stating it,
  which is what let this hide. **NOT LOCALLY VERIFIED - there is no Apple
  toolchain on this box, so the Swift half compiles and runs in CI only
  (`ios-test.yml`). Treat it as unproven until that goes green.**
- ~~6. A failed UPnP refresh leaves `public_ip` stale.~~ **CLOSED for the `Err`
  arm**, which now clears it, so `has_port_mapping()` stops claiming a mapping
  it just failed to confirm - the contract that field documents for itself.
  **UNTESTED: it needs a real IGD to exercise; the change rests on the
  documented contract, not on a green test.** The `Remapped` arm still cannot
  refresh the address because `RefreshOutcome` does not carry one - left alone.
- ~~Carried hazard: `finds_inflight` underflow.~~ **CLOSED**, made saturating,
  so the worst case is one over-parallel round instead of a wedged lookup.
- ~~12. PUBLIC-REPO privacy (the IP half).~~ **CLOSED.** The captured peer
  addresses are gone from `fetch.rs`, `kad_live.rs` and `log.md` (redacted there
  with the `<peer-ip>` convention the wiki already uses). Replacements are
  SYNTHETIC but keep each test's property: routable, because
  `is_routable_public_v4` rejects the RFC5737 ranges, and for the byte-order
  test one that still reverses into reserved space, which is how the original
  bug announced itself.

**STILL OPEN - verified in code, deliberately NOT fixed.** Ranked. **If you
close one, strike it here.**

~~1. The serve loop answers before checking the source address.~~ **SPLIT AND
   SETTLED 2026-08-08 - half implemented, half REFUTED, and the refuted half is
   the point.** Checking `ProcessPacket` (KademliaUDPListener.cpp:236-256)
   rather than trusting the spec: eMule gates an inbound Kad datagram on exactly
   TWO things before dispatch - the port-53 unencrypted guard and
   `InTrackListIsAllowedPacket` - and reaches for the ipfilter only when
   INSERTING contacts (`:835`). **So "never answer a request whose source is
   unroutable or private" is an aspiration the spec author wrote and the source
   does not support** - the FIFTH time the spec has lost to eMule. Implementing
   it would also have broken the loopback mock-peer shape the spec's OWN Testing
   section prescribes, and the namespaced amuled oracle. NOT DONE, deliberately,
   and the test that "pinned the permissive behaviour" turns out to be correct.
   **What WAS done, as a documented divergence:** padMule now refuses to ANSWER
   an address the user blocklisted, because a blocklist is an explicit "do not
   talk to these people" and a reply is talking - it confirms we exist, at this
   address, running Kad. Interop-safe by construction (it can only cut off peers
   the user chose to cut off) and fail-open with no filter loaded. eMule would
   answer; we do not, and the code says why.
~~2. `related_search` poisons "Load more".~~ **CLOSED 2026-08-08.** It issued a
   fresh server query without resetting `search_session`, and
   `OP_QUERY_MORE_RESULT` is BODILESS - it continues whatever query the SERVER
   last received - so a later `search_more()` passed its own staleness check and
   spliced page 2 of the RELATED query into the KEYWORD result set, silently.
   The session is now dropped, which turns "Load more" off; that is honest,
   since the related result already reports `more_available: false`. **NOT
   UNIT-TESTED - the seam needs a connected related-search-capable server, so no
   test in that file can reach it; the eserver oracle is where it is provable.**
3. **The 2-worker FFI runtime writes every received block synchronously.**
   `part_store` uses `File::write_all` from `Download::add_block` with no
   `spawn_blocking`, the one uninsulated blocking call in an engine that
   otherwise wraps hashing and verification carefully - on a `worker_threads(2)`
   runtime, with ~4 workers per download and NO cap on concurrent downloads.
   **A live suspect for "concurrency under load" below; measure it before
   assuming a download cap is the whole story.**
~~4. The stress harness corrupts the two numbers it exists to produce.~~
   **CLOSED 2026-08-08.** It now counts what the engine ACCEPTED
   (`AddOutcome::Started`) rather than what it was offered, so a hit refused for
   NoSources/NotConnected no longer inflates the `queued` denominator; and it
   CLEARS the config and download dirs on start, so `resume_downloads` cannot
   put a previous run's part-files into `ever_received` at tick one without a
   byte arriving - the starvation signal the harness exists to produce, and the
   one number that had to be trustworthy. `STRESS_KEEP_CONFIG=1` opts out when
   resume behaviour is deliberately the subject. Three stale comment blocks
   fixed with it (a promised Blender keyword list that was never there, and a
   size cap explained by three mutually inconsistent rationales naming numbers
   the code never used).
5. **Format fidelity, low severity**: `read_part_met` accepts the eDonkey
   `0xE1` version but parses it with the `0xE0` layout (aMule switches layouts,
   PartFile.cpp:432-456) - and its test only flips the version byte on an
   `0xE0` golden, so it is tautological; `write_tag` can emit `TAGTYPE_BSOB`
   into a MET file, which aMule's MET reader throws on; `is_expired` uses `>=`
   where aMule uses strict `>`; nodes.dat v0 is parsed where aMule refuses it.
6. **`ship.sh` guard 4 does not exist.** The `GUARD 4` label sits on a WDA
   `/status` ping and the run ends by telling a human to check Settings, so the
   "closed loop" is open at its last link - though `device-timing.sh` already
   reads the build off the device. Also: a zsign failure is swallowed by
   `|| true` (a stale signed ipa could install), the run-picker can lock onto an
   older FAILED run for the same sha, and the CI wait loop has no timeout while
   holding the `flock`.
7. **PUBLIC-REPO privacy, the remaining half, for Anthony to decide:** the Apple
   Team ID `Q444CHAF2Z` is committed in `ship.sh` and `device-timing.sh`. Left
   alone on purpose - it is the installed bundle id's suffix, so changing it
   risks breaking the proven install path for a personal-identifier concern that
   is real but weaker than the captured-peer one. Parameterising it via an env
   var would close it without touching the flow.

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
  did not close it. **The 8cp reanalysis found this is the SAME asymmetry as
  ledger item 1 above** (the anti-hijack refusal also filters only the frontier)
  and that it starts one layer lower: `read_nodes_dat` parses a v0 file that
  aMule refuses outright, and `routing::load_nodes` does not drop `version <= 1`
  at load the way aMule does. Fix them together - it is one seam, not three.
- **`KAD_MAINTENANCE_BUDGET` (3s) exactly equals `REFRESH_DEADLINE_QUERIES` x
  `KAD_PER_QUERY`** (4 x 750ms), so for a full-length refresh the outer timeout
  and the lookup's own deadline fire together and cancellation is the NORMAL path.
  `SlotGuard` is load-bearing there, not a belt-and-braces extra.
- **`drive_lookup` dispatches BEFORE it checks `results >= want`**, so the value
  response that satisfies a search triggers one more harvest-and-refill batch
  whose replies are discarded. Wasted datagrams on the success path; not a
  correctness bug, never measured. (Re-confirmed by the 8cp reanalysis.)
- **`finds_inflight` can UNDERFLOW and wedge a lookup** (found 8cp): the
  JoinSet-error arm decrements unconditionally, including when the failed task
  was a `ReqKind::Value`, while the normal arm decrements non-saturating. One
  panicking value task therefore wraps the counter in release, after which
  `ALPHA_QUERY.saturating_sub(finds_inflight)` is 0 and no FIND_NODE dispatches
  again until the overall deadline. Latent - it needs a task panic first.
- **There is NO contact eviction anywhere**: `RoutingTable` exposes no removal
  API at all, `Zone::add` drops the NEW contact when a bin is full rather than
  probing the oldest, and `CSearch::on_timeout` never feeds failure back to the
  table. Dead verified contacts persist as lookup seeds for the node's life.
  This is the other half of eMule's `OnSmallTimer` named above, stated as the
  code shape rather than the behaviour.
- Near-biased nodes.dat sample. No bootstrap retry within a foreground session.

## Related

- [[handoff-next-session]] - the verified state of the tree.
- [[build-progress]] rows 8ck-8co / [[kad-routing-lifecycle]] / [[log]]
- [[ipad-usb-tooling]] - the install path and every probe trap.
- [[kad-verify-oracle]] - the A/B oracle that proved the serve loop.
- [[interop-test-fidelity]] (memory) - why a green test can be worthless.
