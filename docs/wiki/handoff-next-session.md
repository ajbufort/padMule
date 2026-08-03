# HANDOFF - start here next session

Updated: 2026-08-03 (second session that day: full reanalysis -> doc-drift fix
round -> OP_GETSERVERLIST shipped + live-proven -> two-bug fix round. Everything
below is verified, not assumed, and what is NOT verified says so.)

Living doc: replace it wholesale next time. Full narrative in [[build-progress]]
rows 8av-8az + the [[log]] entries for 2026-08-03 + [[feature-server-hunter]].

## State of the tree

- All work committed AND pushed; tree clean; branch even with origin/main at
  **fff31dc**. Session commits: 37eeac4 (doc-drift round), 4949f25
  (OP_GETSERVERLIST), fff31dc (magnet + Kad-gate fixes).
- **Gate**: 539 tests, clippy WARNING-FREE, fmt clean, ASCII clean.
- CI: Rust gate + iOS build GREEN on 4949f25 (the .ipa with the new Settings
  toggle built, so the Swift + regenerated FFI binding compile); the iOS
  simulator tests were still in flight at handoff time, as are all three runs
  for fff31dc - CONFIRM green before installing.
- [[security-model]] scorecard unchanged: **23 OPERATIONAL / 1 PARTIAL / 2
  documented opt-outs**. The PARTIAL is AICH block recovery (wave 11).

## THE HARD DEADLINE

**The free signing cert + provisioning profiles EXPIRE 2026-08-10** (now days
away). After that, no new build installs until renewed via Sideloadly (Apple ID
auth, App ID + device registration, cert issuance), then re-pull the profile
with `ideviceprovision copy`. Plan a build/install pass before then, or renew
early.

## FIRST THINGS TO DO

1. **Install the LATEST build.** The device still runs e7c38d0, now FIVE
   commits behind. Download the fff31dc `padMule-ipa` artifact once CI is
   green, put the UNSIGNED .ipa in `C:\Users\ajbuf\Downloads\`, and hand it to
   Sideloadly (never a pre-signed one - the double-suffix trap is in
   [[ipad-usb-tooling]]).
2. **Device-verify the batch** (see the list below). The headline check: on a
   real-server connect the notice stream should now show "N servers known" /
   "Discovered N server(s) from the network", and the Servers screen should
   grow rows that came from no published list.

## THE HEADLINE: the gossip harvest is LIVE (OP_GETSERVERLIST shipped)

The 8ay device pass proved modern servers do NOT volunteer OP_SERVERLIST; the
ask now ships (row 8az): a fresh login sends the bodiless 0x14 right after the
shares offer - BOTH authorities' send site - on connect AND resume, gated on
eMule's AddServersFromServer pref (Settings toggle "Ask connected servers for
more servers"; both authorities default OFF, padMule defaults ON as a
documented deviation). **LIVE-PROVEN from the dev box**: the isolated eserver
oracle accepts the ask through a full lifecycle, and a real public server
(85.17.116.222:6082, HighID, 3210 users) answered `[serverlist] 33 servers`
via `mule-cli login`. Ride-along fix: the event forwarder stashes a ServerList
BEFORE its flood limiter, so a connect-burst answer cannot be dropped.

## What else landed this session (all pushed)

- **Full reanalysis** (5 parallel area explorers + gate run): code sound, every
  prior-handoff claim verified; findings folded into the wiki + the list below.
- **Doc-drift fix round** (37eeac4): portability-audit Tier-1 items annotated
  FIXED; wave-10 row marked COMPLETE; build-progress rows 8av-8ay added; index
  caught up (log.md now listed); security-model tally chain joined; AltStore
  marked SUPERSEDED everywhere; six stale Updated: headers; four misattached
  code doc comments.
- **Magnet-link fix** (fff31dc): a flag-style parameter or trailing `&` no
  longer aborts the whole parse (it skipped-not-fatal, like the ed2k path).
- **Kad bootstrap gate** (fff31dc): the dial list now passes gate_loaded_nodes
  (ipfilter/routability/port-53/Kad1) exactly like the table load - a poisoned
  nodes.dat can no longer aim the bootstrap sweep at loopback/LAN/DNS.

## NOT yet device-verified (CI-green / live-CLI-proven only)

Everything since e7c38d0, on the fff31dc install: the connected-line server
NAME (26cc9f8), the gossip ask + harvest merge ON DEVICE (the ask itself is
live-proven from the dev box), the new Settings toggle, the metered-sharing
pause (needs a cellular/hotspot link; rests on its unit truth-table),
keep-screen-awake, and the multi-URL merge RESULT. NB the name shows in the
STATUS row only: `ServerInfoFfi` has no `name` field yet, so the Servers-screen
header and the Status "Server" row still show the bare IP (open task below).

## Open tasks (ranked)

1. **Recursive UDP server crawl** - the fuller "hidden servers" discovery
   (harvest from servers we are NOT connected to via UDP OP_GLOBSERVSTATREQ /
   server-list req, verify, recurse). Whole-net scanning stays OUT of scope
   ([[feature-server-hunter]]).
2. **Portability Tier 2** ([[portability-audit]]) plus the reanalysis findings
   that belong with it: "Reconnecting..." can never render (events drain behind
   the blocking call on one serial queue; a second drain queue fixes it) AND
   its dangerous sibling - **pause() can be LOST on backgrounding** behind a
   long call on that same queue (no beginBackgroundTask anywhere; the 300s
   checkpoint is the only mitigation); **a failed initial UPnP map permanently
   disables refresh/release** (both early-return on public_ip=None - a
   transient SSDP failure at start means LowID all session with no retry);
   NAT-PMP is dead code in the engine; the 4s offer_files timeout silently
   drops uploads on a slow link; RESUME_PER_DL(4s) < SOURCES_WAIT(10s).
3. **FFI/UI catch-up slice**: thread `name` into ServerInfoFfi (finish
   26cc9f8); Settings accepts https:// list URLs the engine rejects
   (update_server_list is http-only - either fetch https or validate
   consistently); the old single-URL field on the Servers screen bypasses the
   persisted multi-URL model; the related-search fallback pollutes Recent
   Searches.
4. **Settings Tier 1/2 engine work** - nickname (hardcoded "padMule"),
   obfuscation policy tri-state, ipfilter controls, UPnP toggle, upload slots;
   then bandwidth caps (eMule's anti-leech up/down coupling
   `Preferences.cpp:758-770`; `upload_queue.rs` holds dead kbps logic to
   revive-or-delete), port override, See-My-Shared-Files.
5. **AICH block recovery** (wave 11, the last scorecard PARTIAL). Do NOT port
   the vendored racy `known2_64.met` orphan-prune; route `localize_corruption`
   into block recovery; ship the AICH rate limit + O(1) index together.
6. **Continuous block-request top-up** - padMule is stop-and-wait per 3-block
   batch, shallower than both authorities; no wire change, big win at cellular
   RTT.
7. **Smaller reanalysis findings** (recorded in [[log]] 2026-08-03): harvest
   queue lost if the server.met write fails (mem::take before write); no
   thin-file guard on nodes.dat writes (aMule refuses < 25 contacts,
   RoutingZone.cpp:304 - and padMule now writes every 300s); `hash-file` exits
   0 on failure and two oracle scripts consume it without `-e`; MSRV declared
   (1.96) but unenforced in CI; request_callbacks has no cap/pacing; ipfilter
   drops a 2-field line aMule accepts; resume() failure emits no ServerDropped.

## Discipline reminders that earned their keep THIS session

- **Fix the payload path before the ask.** The flood limiter would have eaten
  the OP_SERVERLIST answer the new ask solicits - found by reanalysis BEFORE
  the send existed, fixed in the same commit, RED-first.
- **A single-server universe cannot prove a list answer.** The isolated
  eserver accepted the ask but advertises nothing (it knows no other servers);
  only the live public server could show `[serverlist] 33`. Match the oracle
  to the claim.
- **A test that exercises a HELPER is not evidence about the CALLER** (again).
  The Kad dial-gate RED was driven through start_kad itself: 3.6s of doomed
  dialing before the fix, a 0.02s honest bail after.
- **Both authorities default AddServersFromServer OFF; padMule ships ON.**
  Deviations are fine when wire-identical, justified, and written down with
  citations on both sides - that is the replicate-then-improve boundary.
- **Live servers churn.** The server the 8ay device pass used now refuses
  logins from this box entirely; the live check had to find a fresh one via
  login-any. Never hardcode a "known good" server into a test or doc.

## Related

- [[feature-server-hunter]] - the now-LIVE gossip crawl; the recursive-crawl
  next step.
- [[ipad-usb-tooling]] - device runbook, touch control, signing, the traps.
- [[portability-audit]] - Tier 2/3 open work.
- [[build-progress]] / [[security-model]] / [[log]].
