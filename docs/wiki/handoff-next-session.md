# HANDOFF - start here next session

Updated: 2026-08-03 (end of a very long session; everything below is verified,
not assumed, and what is NOT verified says so)

Living doc: replace it wholesale next time. Full narrative in [[build-progress]]
rows 8as-8au + [[portability-audit]] + the [[log]] entries for 2026-08-02/03.

## State of the tree

- All work committed AND pushed; tree clean; branch even with origin/main at
  **26cc9f8**. CI green on all three workflows for every push.
- **Gate**: 532 tests, clippy WARNING-FREE, fmt clean, ASCII clean.
- [[security-model]] scorecard unchanged: **23 OPERATIONAL / 1 PARTIAL / 2
  documented opt-outs**. The PARTIAL is AICH block recovery (wave 11).

## THE HARD DEADLINE

**The free signing cert + provisioning profiles EXPIRE 2026-08-10** (a week out).
After that, no new build installs until renewed via Sideloadly (Apple ID auth,
App ID + device registration, cert issuance), then re-pull the profile with
`ideviceprovision copy`. Plan a build/install pass before then, or renew early.

## FIRST TWO THINGS TO DO

1. **Install the latest build** so the device is current:
   `C:\Users\ajbuf\Downloads\padMule-INSTALL-THIS-unsigned-26cc9f8.ipa` (UNSIGNED,
   for Sideloadly - hand it the unsigned artifact, never a pre-signed one; the
   double-suffix trap is in [[ipad-usb-tooling]]). The device currently runs
   e7c38d0, which is MISSING the connected-line server-name change.

2. **Build the gossip `OP_GETSERVERLIST` send** - the device pass PROVED it is
   required, not optional: connecting HighID to a real Lugdunum server delivered
   NO OP_SERVERLIST (modern servers do not volunteer their list; you must ASK).
   The harvest-on-connect merge already works ([[feature-server-hunter]] part 3);
   this is the small "ask" step that makes it actually populate the list. eMule
   gates it on an "update list when connecting" pref (PPgServer). Verify live
   against a real server + the isolated eserver oracle.

## The device is now AGENT-DRIVABLE (major capability, this session)

Touch control works: WebDriverAgent via pymobiledevice3 - taps, typing,
screenshots, the accessibility tree, and reading engine os_log. Full runbook +
the traps in [[ipad-usb-tooling]]. The one that bites: **pymobiledevice3 defaults
to the WINDOWS usbmuxd (127.0.0.1:27015)** under WSL mirrored networking; set
`USBMUXD_SOCKET_ADDRESS=/var/run/usbmuxd` or it drives the wrong transport and
goes blind when the iPad's address changes. Also: `strings` on the .ipa only
finds Swift literals LONGER than 15 bytes (small-string optimization), so
grepping the binary for a short new string gives a false negative.

## What landed this session (all pushed, CI green)

- **Agent-driven device control** (WebDriverAgent) - see above.
- **UPnP stale-mapping** root cause (only the owning address may delete a mapping)
  + three fixes: verify-then-reopen refresh on resume and on a LowID answer, a
  conflict message that NAMES the holder, and release-on-Stop. Device-verified:
  Stop releases the port (confirmed at the router), Start re-claims it.
- **Status line stale-after-connect** (8as) - device-verified fixed.
- **Kad checkpoint gap** - mid-session contacts + verify keys were discarded;
  fixed and made structural via `set_kad`; plus a **periodic checkpoint** (300s)
  so a suspend-kill cannot cost the session (8at/8au).
- **Explicit Stop action** - the honest analogue of eMule's Exit; device-verified.
- **os_log** - the engine now logs to `idevicesyslog -p padMule -m
  padMule.engine`; device-verified (21 app lines across a launch/suspend/stop).
- **Portability audit** ([[portability-audit]]) - what breaks for users NOT on
  the dev's fast/UPnP/unblocked network. Tiered.
- **Tier 1 portability slice** - UDP-blocked networks no longer grey out every
  server (rows stay selectable; probe is UDP, login is TCP); splash waits for
  READINESS not a fixed 7s; a disconnected user is told THEY are not connected,
  not that the file is gone.
- **Settings screen (Tier 0)** - padMule's first. Persisted Leech Mode
  (device-verified: survives relaunch - was a live bug), "pause sharing on
  cellular/metered" (default ON - the one finding that can cost money),
  multi-URL server lists (eMule addresses.dat model, merged), default priority,
  remembered search filters, keep-screen-awake.
- **gzip/zip-wrapped server lists** - transparently unwrapped in the fetch path,
  bounded against a bomb.
- **Gossip crawl first cut** (harvest-on-connect) - correct, but device-proven
  INERT until the OP_GETSERVERLIST send lands (see FIRST THINGS TO DO #2).
- **Connected line shows the server NAME** with the address in parens (26cc9f8).

## NOT yet device-verified (CI-green only)

The connected-line name change (26cc9f8), the metered-sharing pause (needs a
cellular/hotspot link; this is Wi-Fi), keep-screen-awake, and the multi-URL merge
RESULT. Confirm these on the 26cc9f8 install. The metered pause rests on its unit
test (the truth table) since it cannot be produced on the dev Wi-Fi.

## Open tasks (ranked)

1. **Gossip `OP_GETSERVERLIST` send** - required, see above.
2. **Recursive UDP server crawl** - the fuller "hidden servers" discovery
   (harvest from servers we are NOT connected to, verify, recurse). Whole-net
   scanning stays OUT of scope ([[feature-server-hunter]]).
3. **Portability Tier 2** ([[portability-audit]]) - NAT-PMP is dead code in the
   engine (routers that speak it get needless LowID); "Reconnecting..." can never
   render (events drain behind the blocking call on one serial queue - up to ~20s
   frozen UI per foreground return); the 4s `offer_files` timeout silently
   disables uploads on a slow link; `RESUME_PER_DL`(4s) < `SOURCES_WAIT`(10s).
4. **Settings Tier 1/2 engine work** - nickname (hardcoded "padMule"), obfuscation
   policy tri-state (default to eMule's, cite both), ipfilter controls, UPnP
   toggle, upload slots; then bandwidth caps (the big one - eMule's anti-leech
   up/down coupling `Preferences.cpp:758-770` + the min-upload floor; `upload_queue.rs`
   holds dead kbps logic to revive-or-delete), port override, See-My-Shared-Files.
5. **AICH block recovery** (wave 11, the last scorecard PARTIAL). Do NOT port the
   vendored 3.0.1 racy `known2_64.met` orphan-prune; route `localize_corruption`
   into block recovery; ship the AICH rate limit + O(1) index together.
6. **Continuous block-request top-up** - padMule is stop-and-wait per 3-block
   batch, shallower than both authorities; no wire change, big win at cellular RTT.
7. **Smaller reanalysis findings** - `link.rs:96` aborts a whole magnet parse on a
   flag-style parameter; the Kad bootstrap dial list bypasses the ipfilter/
   routability gate; `ios/project.yml:56-61` names NAT-PMP where the shipped path
   is unicast-SSDP UPnP; the related-search fallback pollutes Recent Searches.

## Discipline reminders that earned their keep THIS session

- **A dev network that never fails is not a test environment for failure
  handling.** The whole portability audit exists because every degraded path
  (UDP-blocked, metered, no-UPnP, slow) is INVISIBLE from the dev box. Several
  Tier-1 fixes cannot be fully device-verified here for the same reason - say so,
  do not fudge it.
- **A test that exercises a HELPER is not evidence about the CALLER.** The first
  Kad checkpoint fix passed its test and did NOTHING on the pause path (the node
  was dropped before the checkpoint). When a fix is about ORDERING, drive the
  ordering. Mutation-check the regression test.
- **"The authorities surely do X" is a hypothesis - check first.** Killed the
  UPnP finite-lease plan (nobody uses one) and the periodic-nodes.dat-save
  precedent (both authorities write only from a destructor) with one grep each.
- **Only the device could prove the gossip harvest is inert** - the unit test
  proved the merge, not that real servers stay silent. Verify features against
  the real other side, not just a mock.
- **Verify before reporting.** An on-screen mojibake filename was baked into the
  wire name, not a decode bug. "The UPnP fix regressed" was a port conflict that
  PROVED the fix works.

## Related

- [[ipad-usb-tooling]] - device runbook, touch control, signing, the traps.
- [[portability-audit]] - the Tier 1/2/3 findings; open work.
- [[feature-server-hunter]] - the gossip crawl, its first cut, and the required
  OP_GETSERVERLIST next step.
- [[build-progress]] / [[security-model]].
