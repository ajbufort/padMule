# Portability audit: usable for people who are NOT on the dev's network

Updated: 2026-08-03 (first pass; Tier-1 items 1-4 fixed same day and annotated
below)

Anthony asked: "have we handled all such cases - making the product usable for
those who do not have my setup but meet minimum requirements?" The answer is NO,
and the findings share one shape: **the dev box has fast unmetered broadband, a
working UPnP IGD, a /24 LAN and no blocked ports, so every degraded path is
structurally invisible from here.** Two parallel audits (network/environment and
first-run/failure UX) plus hand-verification produced the list below.

Trigger for the audit: the Stop footer claimed the router port was handed back
even for users who never had a mapping ([[net-highid-and-port-forwarding]]),
which Anthony caught. That one bug was the visible tip.

## TIER 1 - the app is unusable or can cost the user money

1. [FIXED 2026-08-03] **~~A UDP-blocked network greys out EVERY server, with no
   escape hatch~~.** The `.disabled` condition no longer includes `!srv.alive`:
   it is now `srv.connected || model.connectingTo != nil`
   (ContentView.swift:682), so every row stays SELECTABLE even when the UDP
   status probe got no answer - the probe is UDP, the login is TCP, and plenty
   of networks pass one and block the other. The dead-server label changed from
   implying "offline" to the honest "no reply" (ContentView.swift:665), and
   tapping a no-reply row dials it exactly like a live one, now with a spinner
   and an honest failure report where the connect boolean used to be discarded.
   There is still no manual server-address field - that part of the finding
   remains open - but the escape hatch that shipped is "every server is
   tappable," which is what actually made hotel/corporate/carrier networks
   usable again. Device-verified 2026-08-03 (build 44ba972, [[log]]): the
   connect path itself was seen live end to end, but the "no reply" state could
   not be reproduced from the dev network (all ten configured servers answered
   the UDP probe there), so that specific render rests on its unit test rather
   than an on-glass repro.
2. [FIXED 2026-08-03] **~~The splash clears long before the engine is ready,
   and every control then silently no-ops~~.** The fixed 7s delay is gone.
   PadMuleApp.swift:40-62 now polls a new `model.ready` flag every 150ms,
   bounded on both sides: a 2.5s MINIMUM so the brand does not flash past on a
   warm start, and a 20s CEILING so a hung or failed boot can never trap the
   user behind the splash. Past either the ready flag or `bootError` becoming
   non-nil (once the minimum has elapsed), the splash yields to the app, and a
   new "Starting padMule... searching and downloading will work in a moment."
   banner (ContentView.swift:128-129, gated on `!model.ready && model.bootError
   == nil`) covers the remaining wait instead of a live-looking but inert UI.
   Device-verified 2026-08-03 (build 44ba972, [[log]]): boot completed in ~1s
   on the dev network, so the 2.5s splash minimum correctly covered the whole
   boot and the "Starting padMule..." banner never had to render there - that
   render, and the 20s-ceiling failure path, are proven by unit test rather
   than on-glass, since this network cannot produce a slow or hung boot to
   trigger them. The audit's own "12-17s warm / 25s+ cold" estimate was
   corrected in the same pass: it was the sum of the timeouts, not a
   measurement - warm boot with lists already on disk is closer to ~1s, though
   the finding still holds for a cold, slow, or blocked network where those
   timeouts actually elapse.
3. [FIXED 2026-08-03] **~~A disconnected user is always told the FILE is
   unavailable~~.** `AddResult::NoServer` is gone; it is now `NotConnected`
   (engine.rs:761-777), and it is REACHABLE: `add_download` checks
   `self.offline || !self.can_discover()` (engine.rs:2514, `can_discover` = a
   server OR a populated Kad table) and returns `NotConnected` BEFORE spending
   the 10s source-lookup budget, since with no channel there is nobody to ask -
   the honest answer is about the connection, not the file. The regression
   guard that the original bug's cause could have broken -
   `add_download_without_a_server_still_tries_kad`, which pins Kad-only clients
   never being refused for lacking a server - was updated to check BOTH halves:
   bail when there is no channel at all, and do NOT bail when Kad alone could
   still answer. Device-verified 2026-08-03 (build 44ba972, [[log]]): not
   directly reproducible from the dev network, since it requires no server AND
   zero Kad contacts, a state the app leaves within seconds there - it rests on
   its unit test (`add_download_refuses_what_it_cannot_do_instead_of_
   pretending`) instead.
4. [FIXED 2026-08-03] **~~No cellular / metered awareness, sharing ON by
   default~~.** Landed in the Tier-0 Settings slice: a `NetworkWatcher`
   (`NWPathMonitor` -> `isExpensive || isConstrained`) drives a
   "Pause sharing on cellular / metered networks" setting that DEFAULTS ON, so a
   fresh install protects a data plan without being configured. It pauses
   SHARING only (uploads); pausing downloads on a metered link is Tier 2, since
   there is no per-transfer pause yet, only cancel. Also fixed here: Leech Mode
   was initialised ON in the engine and NEVER PERSISTED, so turning it off
   silently turned itself back on every launch - now stored and re-applied.

## FIXED 2026-08-03 by the usage-feedback round (build-progress 8bb)

Anthony's first extended on-device session found what the audit's static reading
had not. Closed here, each TDD + mutation-checked:

- Item 17 below (the README never states minimum requirements) is still open,
  but the related "no way to get at a finished file" gap is CLOSED: the
  Downloaded tab lists finished files from disk, tapping one opens it in
  QuickLook, and a ShareLink hands it to another app. NB iOS refuses a
  `file://` URL to `UIApplication.open`, so those two are the ONLY routes.
- Item 6 below (RESUME_PER_DL < SOURCES_WAIT) was WORSE than recorded: the two
  source arms are JOINED, so the call returns in max(), and the 4s outer timeout
  DISCARDED the server sources that had already arrived. Resume therefore worked
  only when Kad was BROKEN. The budget is now a parameter bounding each arm, so
  partial results always survive; the whole-pass cap (2 downloads) is raised and
  a periodic re-drive fixes the total absence of any retry.
- Item 9's sibling: a finished file the user DELETED was still advertised and
  still answered "COMPLETE" to peers. Verified at the serve path now, plus a 60s
  prune of the library and known.met.
- The server-DROP path never emitted Status, so the Status row kept claiming a
  connection after a kick (the 8as bug's mirror).
- Search rows never refreshed: a completed file never showed "Have", and a file
  just tapped reverted to "Get" and could be started twice.
- Every silent long operation now shows progress ("Discover more servers" had
  none at all for ~12s), and the two FALSE UI claims (transfers "resume when you
  come back", keep-awake "only while actually transferring") are now true
  statements with the code changed to match.

STILL OPEN from Tier 2 below: the serial-queue freeze itself (items 10 and the
pause() starvation risk are mitigated, not eliminated - the real fix is getting
blocking engine calls off the one queue), NAT-PMP dead code, the 4s offer_files
timeout, and bandwidth limiting.

## TIER 2 - silently degrades, no diagnostic

5. **Uploads are never announced on a slow link.** `maintain_shares` wraps
   `offer_files` in a 4s timeout and DISCARDS the result (engine.rs:1994-1998).
   The 4s is a considered tradeoff (it runs under the engine lock on the 1s
   heartbeat, and iPadOS grants ~5s to background) - the defect is the silence.
6. **Resumed downloads get less time than a source lookup needs.**
   `RESUME_PER_DL` = 4s (engine.rs:274) wraps `find_sources` (engine.rs:2598),
   but `SOURCES_WAIT` = 10s (engine.rs:168). On a slow link a resumed download
   can never find sources.
7. **NAT-PMP is dead code in the engine.** `portmap.rs` implements it and its own
   module doc says "a real client tries both", but `Engine::map_port` only tries
   UPnP multicast then unicast; the sole caller of `portmap::map_port` is
   mule-cli. Routers that speak NAT-PMP but not UPnP get LowID for no reason.
8. **A first-run bootstrap failure is silent and not retried in-session.**
   `bootstrap::ensure`'s `Fetched::Failed` is discarded (engine.rs:1304-1318).
   NB the agent's harsher claim was REJECTED on inspection: a captive-portal HTML
   page is NOT written, because `ensure` writes only when the validator passes
   (bootstrap.rs:149-158, regression test at :214). So the damage is limited to
   an empty, unexplained app until relaunch.
9. **No bandwidth limiting anywhere in the live path.** Both authorities treat
   upload/download caps as core features. The kbps logic exists in
   `upload_queue.rs`, which is still DEAD (share.rs's `UploadGate` is the live
   path). padMule will saturate a shared uplink.
10. **"Reconnecting..." can never render.** The engine emits it before the work
    and the final status after (engine.rs:2788/:2842), but events are only
    drained by `refresh()`, which queues BEHIND the blocking `resume()` on the
    same serial queue - so both arrive in one drain and the flag flips true then
    false without a frame. The user gets up to ~20s of frozen-looking UI on every
    foreground return, which is what [[lifecycle-and-reactivation]] exists to
    prevent.

## TIER 3 - narrower

11. Gateway inference tries only `.1` and `.254` of the device's own /24
    (upnp.rs:364-371) - wrong on a /16 or /8 LAN, and on iOS unicast is the only
    route so there is no multicast fallback to save it.
12. LowID is shown as a bare orange word and never explained - the permanent
    state for cellular/CGNAT/hotel users.
13. The Local Network permission prompt fires while the splash still covers the
    screen, so it is answered with zero app context; denying it kills UPnP
    forever with no mention of Settings.
14. Accessibility: only 5 accessibility labels in the whole app; `.font(.system(
    size: 19))` and fixed frames do not scale with Dynamic Type; the "0 sources"
    state is conveyed by RED TEXT ALONE.
15. Split View / Slide Over are enabled but nothing adapts (no size classes); the
    six-item strip truncates at ~320pt.
16. Min-size > Max-size is accepted and silently returns nothing.
17. The README never states the minimum requirements: iPad ONLY
    (`TARGETED_DEVICE_FAMILY: "2"` - iPhone cannot install), iPadOS 16+,
    sideload-only, 7-day re-sign on a free Apple ID.
18. Timeouts calibrated to a fast link: server connect and resume 12s
    (engine.rs:1682/:2798), per-peer attempt 45s TOTAL rather than idle
    (engine.rs:2536), Kad verify 2s/1500ms (engine.rs:2124) - below one satellite
    RTT. Tokio is pinned to 2 worker threads (mule-ffi/src/lib.rs:400).

## What was CHECKED AND CLEARED

- Captive-portal HTML is never persisted as server.met/nodes.dat (validator +
  regression test), and the next launch retries cleanly.
- `Movie.mkv` vs `movie.mkv` does not overwrite: `unique_dest` checks `exists()`,
  which is case-insensitive on APFS, so the second lands as `Movie (2).mkv`.
- `MAX_CONTACTS_PER_IP = 1` hurts CGNAT users but is SPEC-FAITHFUL (eMule
  RoutingBin.cpp) - an inherited constraint, not a padMule bug.

## Related

- [[net-highid-and-port-forwarding]] - the Stop-footer bug that triggered this.
- [[lifecycle-and-reactivation]] - the honest-status requirement several of these
  violate.
- [[ipados-constraints]] - platform limits that are legitimate, vs these, which
  are not.
- [[build-progress]] - where fixes will be recorded.
