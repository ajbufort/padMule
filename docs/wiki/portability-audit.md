# Portability audit: usable for people who are NOT on the dev's network

Updated: 2026-08-03 (first pass)

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

1. **A UDP-blocked network greys out EVERY server, with no escape hatch.**
   `probe_server_list` marks a server `alive` only if it answers
   `OP_GLOBSERVSTATREQ` on UDP port+4 (engine.rs:1767-1808); the UI then does
   `.disabled(!srv.alive || srv.connected)` (ContentView.swift:645). CONNECTING
   is TCP, so a hotel/corporate/school/carrier network that blocks outbound UDP
   makes every row unselectable even though the TCP login would likely succeed.
   There is NO manual server-address field anywhere - verified, the only
   TextFields are Name / Search / Filter / Server-list-URL. The user sees "pick a
   live server below" above a list with no live server.
2. **The splash clears long before the engine is ready, and every control then
   silently no-ops.** The splash is a fixed 7s (PadMuleApp.swift:26-30) while
   `boot()` publishes `engine` only after `start()` returns - two HTTP fetches,
   the always-failing multicast SSDP attempt, then unicast + SOAP, then Kad -
   roughly 12-17s warm and 25s+ cold. In that window Search, Get, and even
   "Start padMule" hit `guard let e = engine else { return }` and do NOTHING with
   no feedback, and the Servers screen reads "No server list on disk", which is
   false. There is no engine-ready flag on the model for any view to show.
3. **A disconnected user is always told the FILE is unavailable.**
   `AddResult::NoServer` is returned ONLY under `self.offline` (engine.rs:2387)
   and `set_offline` is never exported over the FFI - so the Swift branch
   "Not connected to a server." is DEAD, and the real path yields
   "No one online has \"X\" right now." That sends a new user hunting for another
   file when the fix is to connect. Verified by hand.
4. [FIXED 2026-08-03] **~~No cellular / metered awareness, sharing ON by
   default~~.** Landed in the Tier-0 Settings slice: a `NetworkWatcher`
   (`NWPathMonitor` -> `isExpensive || isConstrained`) drives a
   "Pause sharing on cellular / metered networks" setting that DEFAULTS ON, so a
   fresh install protects a data plan without being configured. It pauses
   SHARING only (uploads); pausing downloads on a metered link is Tier 2, since
   there is no per-transfer pause yet, only cancel. Also fixed here: Leech Mode
   was initialised ON in the engine and NEVER PERSISTED, so turning it off
   silently turned itself back on every launch - now stored and re-applied.

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
