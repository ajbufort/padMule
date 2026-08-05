# On-device test checklist

Updated: 2026-08-05 (steps 15-20 added for the 8bv-8by on-glass work: the fetch
diagnostics panel, the parts badge, closeable banners, the finish beep, the
rate chart, and the strip reorder. Earlier: 2026-08-03, Launch splash corrected
to readiness-gated; Lifecycle corrected to drop the unrenderable
Reconnecting-banner claim)

What to tap through on the iPad after a fresh Sideloadly install, to verify the
whole app in hand. The engine side of every item is also exercisable without a
device via the hands-on FFI simulation (`scripts/simulate.sh`, [[ed2k-server-oracle]],
and [[padmule-live-downloads]]); this list is the human, on-glass pass.

Install: fetch the CI `.ipa` (`gh run download <run-id> -R ajbufort/padMule -n
padMule-ipa`), stage it in the Windows Downloads with the run id in the name,
DELETE the old app off the iPad first, then Sideloadly. See [[padmule-ios-app-path]].

## Pass

1. **Launch** - splash holds until the engine reports ready (minimum ~2.5s,
   hard ceiling 20s, after which a "Starting padMule..." banner takes over),
   then the main screen. No crash. [SUPERSEDED: previously read "3s splash
   (mascot)" - it became 7s on 2026-07-18, then readiness-gated on 2026-08-03.]
2. **Status** (gauge tab) - within ~15s: "Connected to <server> (HighID|LowID)"
   or an honest "Offline"; Kad contacts climb. HighID needs the BE9700 UPnP
   ([[padmule-dev-box-networking]]); LowID is fine.
3. **Search** - type a keyword, Search. Rich result rows: type icon, size,
   sources (+complete), media metadata, a status dot (New/Downloading/Have),
   a Fake flag on rating-1. Sort + filter chips work.
4. **Boolean search** - `linux NOT windows` or `(ubuntu OR debian) iso`. Needs a
   connected SERVER (the server parses the AND/OR/NOT tree; a Kad-only search
   matches the literal string, so it returns little).
5. **Global search** - flip "Search all servers (global)" on, search again -
   more/other results (slower).
6. **Get** - tap a result -> detail sheet (ed2k link copy, Download, Search
   related). Download -> it appears under Transfers with progress. NOTE: with all
   servers down but Kad up, Get now still works via Kad (the sim caught this).
7. **Search related** - in the detail sheet; real results only if the server
   advertises related-search (else it falls back to a filename search).
8. **Preview** (media download) - long-press an incomplete .mp4/.mov/.mp3 ->
   Preview -> AVPlayer plays the downloaded head. A non-faststart/moov-at-end file
   shows an honest "not enough downloaded yet" instead of a black screen.
9. **Statistics** (chart tab) - live down/up rate chart, session totals, up:down
   ratio, updating each second while a transfer runs.
10. **Priority** - long-press a transfer -> Priority -> High (row glyph updates).
11. **Leech Mode** - toggle "Share uploads" off then on (Status/Sharing).
12. **Lifecycle** - background the app, wait, foreground: the Status row
    returns to the connected line and transfers resume. (Transfers honestly
    pause while away.) [SUPERSEDED: previously instructed checking for a
    "Reconnecting..." banner on foreground - that banner provably CANNOT
    render (portability-audit item 10: events drain behind the blocking resume
    on one serial queue), so do not instruct a tester to look for it; it is a
    known open Tier-2 defect - see [[portability-audit]].]
13. **Cancel** - swipe a transfer to Remove; it disappears.
14. **Finished file** - a completed download opens in Files (On My iPad >
    padMule), hash-verified.

## Pass - the 2026-08-04/05 diagnostics and on-glass round

The strip order changed with this batch: Servers, Status, Search, **Transfers,
Downloads**, Shared, Stats. Seeing Transfers before Downloads is the quickest
confirmation that a NEW build actually installed (nothing shows a build sha -
`CFBundleVersion` is `1` in every build).

15. **Fetch diagnostics** (Stats, bottom) - the funnel renders in monospace with
    **Copy report** and **Reset counters**. The workflow is **reset ->
    reproduce -> read**: counters are cumulative since launch, so before
    investigating a stall, Reset first or the healthy minutes dominate. Copy
    report puts it on the clipboard so the numbers leave the device instead of
    being retyped off a photograph. Read `skipped: source BANNED` first - it is
    the one restart-clearable gate that can actually fire ([[build-progress]]
    8by). `STATE / fetches in flight` is a gauge and is NOT cleared by Reset.
16. **Parts badge** - a stalled transfer with >= 4 sampled statuses shows
    "N parts missing from all M peer reports". It separates a slow tail from an
    impossible one; both look identical on a row reading "90%, 86 sources, not
    moving". Absence of the badge is information too.
17. **Banners close** - every banner has an "x". Dismissing means "I have read
    this", not "never warn me again": a state-driven banner (reconnecting,
    sharing-paused, starting) RE-ARMS when its condition next changes. Banners
    are flat **#000066** navy, not a gradient.
18. **Finish beep** - Settings > Device, default ON, follows the silent switch.
    Toggling it ON plays the sound immediately, so the choice is auditioned
    rather than trusted. Then let a download finish and hear it.
19. **Rate chart** - full width, scrolling newest-to-the-right over a fixed
    60-point span, not squeezed into a sliver at the left.
20. **Servers on open** - the server list loads at APP open (not tab open), and
    the Status/Servers screens both name a connected server "Name (ip:port)".
    Stop is the FIRST trailing toolbar icon.

## Related

- [[padmule-ios-app-path]] - the sideload route + the "screen is the debugger" rules.
- [[padmule-live-downloads]] - the FFI simulation harness + Kad-only download.
- [[build-progress]] - what each feature is and where it lives.
