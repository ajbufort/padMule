# HANDOFF - start here next session

Updated: 2026-08-04 (wave 11 finished, then INDEPENDENTLY SWEPT - see the
next section). Everything below is verified, not assumed; anything NOT verified
says so explicitly.

Living doc - replace it wholesale next time. Full narrative:
[[build-progress]] rows 8av-8bk and the [[log]] entries for 2026-08-03/04.

## THE SWEEP FOUND A HOLE THE BRANCH'S OWN GATE COULD NOT SEE (row 8bk)

An independent reanalysis of the FINISHED wave-11 branch - read as an outsider,
not as its author - found the serve-side AICH answer was **unreachable on the
path real clients use**: `is_upload_request` omitted 0x9B/0x9E, so
`classify_inbound` returned `Other` and the listener dropped exactly the
connections eMule opens to ask (`SendAICHRequest` ->
`SafeConnectAndSendPacket`, BaseClient.cpp:2402-2414; the source is picked at
RANDOM from `srclist` with no connection filter, PartFile.cpp:6087-6106). It
also found a SECOND corruption round blaming the FIRST round's source, breaking
the sole-contributor no-false-positive rule. Both fixed, mutation-checked, and
both oracles re-run green. **Take the lesson forward: the branch had 601 green
tests, warning-free clippy and three passing oracles, and every AICH serve test
called `serve_shared` directly - so not one of them could discover that the
connection dies before reaching it. That is the 8ad/8ae shape for the third
time.** Gate now 603 tests.

NOTE FOR NEXT TIME: a PARALLEL session was finishing the same task in the same
worktree while this sweep began. Two agents in one worktree is a data-loss
shape - check `git worktree list` against the running session transcripts under
`~/.claude/projects/` before writing.

## RESOLVED: the AICH worktree is FINISHED, rebased, and up for review

[SUPERSEDES the previous "unmerged work in a worktree" note, which was written
while this build was mid-flight.] `.claude/worktrees/wave11-aich` (branch
`worktree-wave11-aich`) now holds **wave 11 COMPLETE** - AICH block recovery,
the last PARTIAL on the security scorecard - as [[build-progress]] row 8bj.
Nothing is uncommitted, and the branch has been REBASED onto main (it was 12
commits behind; main's 13 new commits are all `ios/` + `docs/`, so the rebase
was clean and the gate was re-run green on top of it).

What it contains: the materialized AICH tree, a `known2_met.rs` codec + a
file-backed store with aMule master's root->offset index, the 0x9B/0x9C/0x9D/
0x9E packet codecs, serve-side root + recovery answers, download-side recovery
with per-BLOCK corruption attribution, and three terminal proofs - padMule's
known2_64.met ENTRY bytes are byte-identical to real amuled's, `mule-cli
aich-probe` verifies real amuled's recovery data live, and a padMule wire loop
repairs a poisoned block re-sending only a fraction of the part. A 3-lens
adversarial review confirmed 9 findings (incl. a FALSE BAN of the source
repairing the file, and a poisoned root that could livelock a download); all
are fixed and the two headline guards are mutation-checked.

Its state: 601 tests, clippy warning-free, fmt/ASCII clean, all three peer
oracles PASS. NOT device-verified - nothing about it is visible in the UI (the
repair is engine-internal). Next step is review + merge of its PR.

## State of the tree (main)

- Tree clean, all pushed. HEAD **0e65157**; last CODE commit **d7d555a**.
- **Gate**: 564 Rust tests, clippy WARNING-FREE, fmt clean, ASCII clean.
- **CI**: all three workflows green on d7d555a.
- **All four oracles re-run and PASS** after this session's serve-path change:
  amuled differential (byte-for-byte, 3 files), the REVERSE oracle (real
  amuled downloads FROM padMule + serve-side secure-ident), the isolated
  eserver login, and the Kad verify oracle.
- [[security-model]]: **24 OPERATIONAL / 0 PARTIAL / 2 documented opt-outs**
  once the AICH branch merges (the last PARTIAL closed 2026-08-03; see the
  worktree note above). On main alone it still reads 23/1/2.
- Build staged for install:
  `C:\Users\ajbuf\Downloads\padMule-INSTALL-THIS-unsigned-d7d555a.ipa`.

## THE HARD DEADLINE

**The free signing cert + provisioning profiles EXPIRE 2026-08-10** - about
six days out. After that, no new build installs until renewed through
Sideloadly (Apple ID auth, App ID + device registration, cert issuance), then
re-pull the profile with `ideviceprovision copy`. Renew early rather than
discovering it mid-debug.

## Where the project actually is

padMule is a **daily driver**, not a demo: search (server + Kad merged),
hash-verified downloads, uploads with credits and secure identity, four ways
of discovering servers, and an honest iPadOS lifecycle. This session added:

- **A usage-feedback round that found SEVEN real bugs** (8bb) which a green
  550-test suite, clean clippy and four passing oracles had all missed.
- **Server discovery completed** (8az/8ba): the OP_GETSERVERLIST ask plus the
  recursive UDP crawl. Device-verified: 10 seeds -> 35 servers, 32 named.
- **VPN readiness** (8bd/8be): configurable ports with ADVERTISED separate
  from LISTEN, a UPnP toggle, and a public-address-change guard that pauses
  sharing because stock iOS has no kill switch.
- **A large UI batch** (8bf-8bi) driven entirely by Anthony using the app.

The two engine bugs worth carrying forward:

1. **Resume was broken - and ONLY when Kad was HEALTHY.** `find_sources`
   joins its server and Kad arms so it returns in max(), and the Kad arm
   carries a 15s budget; `resume_fetches` wrapped the call in a 4s timeout
   that DISCARDED everything, including server sources that had already
   arrived. `add_download` calls the same function with no outer timeout -
   which is exactly why adding a file worked and resuming the identical file
   did not. Now bounded per-arm so partial results always survive.
2. **Phantom shared files.** A file deleted in the Files app was still
   announced via OP_OFFERFILES, answered "COMPLETE" to a requesting peer,
   given an upload slot, then dropped the connection when the read failed.
   Now refused at the serve path (honest FNF) plus a 60s prune.

## DEVICE-VERIFIED vs not

**Verified on glass** (2026-08-03 photos + an agent-driven WebDriverAgent
pass): the function strip in its new order; Status reading Connected /
HighID / 146 Kad contacts against a real Lugdunum server; the two-network
health panel green on both; the gossip crawl ("Discovered 24 servers", table
10 -> 35); server NAMES on discovered rows; Settings and its toggles; Stop
releasing the router port and Start reclaiming it.

**NOT verified on device**:
- **The resume fix** (needs a background/foreground cycle with an active
  download). Headline fix of the session; only the device can show it.
- **The whole VPN path** - unprovable until the tunnel is up.
- The Downloaded tab's QuickLook **Open**, the toolbar **Stop/Start**, the
  **help** screen, the rewritten **port fields**, the banner changes, and the
  **Servers** landing tab - all shipped after the last device pass.
- The **metered-sharing pause** (needs a cellular link; rests on its unit
  truth-table).

## Open tasks (ranked)

1. **Finish and prove the VPN path.** AirVPN side is DONE: port **5999**
   reserved, TCP+UDP, All devices, "Local" cleared so it forwards same-port;
   the app now DEFAULTS all three port fields to 5999. Remaining on device:
   **UPnP off**, **restart padMule** (ports bind when the listener starts),
   then AirVPN's **Test open** (only meaningful with padMule running) and
   Status -> **HighID**. Expect the public-address guard to fire once as the
   tunnel comes up and pause sharing - that is correct; re-enable after
   confirming HighID.
   KNOWN LIMIT: the advertised/listen split covers the **TCP** port only.
   Kad's UDP port is one value used for both bind and advertise, so a
   remote-to-local REMAP would break Kad's inbound reachability. Same-port
   forwarding sidesteps it; add a fourth field only if a remap is needed.
2. **Device-verify the unproven list above**, starting with resume.
3. **Review + merge the AICH branch** (see the top): it is finished, rebased
   onto main and green, with a draft PR open. Merging it is what actually
   moves the scorecard to 24/0/2.
4. **Get blocking engine calls OFF the one serial queue** - the biggest
   remaining structural risk. "Reconnecting..." still cannot render;
   `pause()` starvation is MITIGATED (background-task assertion + refresh
   in-flight guard) but not eliminated; a ~10s crawl and ~20s search still
   freeze the UI. The periodic re-drive and share-verify were both kept
   deliberately small as workarounds for exactly this.
5. **Remaining portability Tier 2** ([[portability-audit]]): NAT-PMP is dead
   code in the engine; the 4s `offer_files` timeout silently drops uploads on
   a slow link; no bandwidth limiting anywhere.
6. **Settings Tier 1/2 engine work**: nickname (hardcoded "padMule"),
   obfuscation policy tri-state, ipfilter controls, upload slots, bandwidth
   caps (`upload_queue.rs` holds dead kbps logic to revive-or-delete),
   See-My-Shared-Files.
7. **Continuous block-request top-up** - padMule is stop-and-wait per 3-block
   batch, shallower than both authorities. No wire change, big win at
   cellular RTT. (Also why keep-awake watches a WINDOW of rate samples: a
   batch boundary legitimately reads zero.)
8. **Smaller open items**: the harvest queue is lost if the server.met write
   fails; no thin-file guard on nodes.dat writes (aMule refuses < 25
   contacts, and padMule now writes every 300s); the related-search fallback
   pollutes Recent Searches; Settings accepts `https://` list URLs the engine
   rejects (http-only); the kick alert may not surface while a sheet is open;
   `hash-file` exits 0 on failure and two oracle scripts consume it without
   `-e`; MSRV declared but unenforced in CI.

## Discipline that earned its keep, and should survive this session

- **User testing finds what tests cannot.** One real usage session produced
  seven confirmed bugs the whole automated gate had missed. Green measures
  what you thought to check.
- **MUTATION-CHECK anything load-bearing.** Two resume tests PASSED with the
  fix deleted - one asserted a value false for other reasons, the other never
  exercised the Kad arm. A test can reach the right CALLER and still miss the
  MECHANISM. If breaking the fix leaves it green, it is decoration.
- **A fake fixture hides a missing check.** Nine serve tests used
  `/does/not/matter` as a shared-file path; adding the correct disk check
  broke all nine, which was the check WORKING. They write real files now.
- **Verify the RENDERED result, not the source.** The title-bar literal
  decoded correctly as a Swift string and still rendered wrong, because
  `.navigationTitle` reinterprets a literal as a `LocalizedStringKey`. Read
  the compiled binary, or the screen.
- **Swift type-checks ONLY in CI on this box.** Three separate breakages this
  session survived a careful grep-and-read pass. Wait for the iOS BUILD and
  TEST workflows before calling a Swift change good.
- **Ordering bugs are invisible to CI.** The port override shipped INERT
  because `boot()` applied settings after `start()`. It compiled, the suite
  stayed green; only reading the call sequence caught it.
- **A silent path must still speak.** Twice this session a durable UI row
  went stale because the code feeding it began early-returning (UPnP
  disabled; a mapping that never existed).
- **Attach global UI at the root.** A confirmationDialog on one screen is
  dead from a toolbar button on every other.

## Related

- [[net-highid-and-port-forwarding]] - HighID, the AirVPN setup, the iOS
  kill-switch gap and padMule's guard.
- [[feature-server-hunter]] - all four discovery parts, shipped.
- [[portability-audit]] - Tier 2/3 open work.
- [[ipad-usb-tooling]] - device runbook. NB on this box `usbipd unbind` (not
  `detach`) is what frees the iPad for Sideloadly.
- [[build-progress]] / [[security-model]] / [[log]] / [[decisions-and-lessons]].
