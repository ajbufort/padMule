# On-device test checklist

Updated: 2026-07-19

What to tap through on the iPad after a fresh Sideloadly install, to verify the
whole app in hand. The engine side of every item is also exercisable without a
device via the hands-on FFI simulation (`scripts/simulate.sh`, [[ed2k-server-oracle]],
and [[padmule-live-downloads]]); this list is the human, on-glass pass.

Install: fetch the CI `.ipa` (`gh run download <run-id> -R ajbufort/padMule -n
padMule-ipa`), stage it in the Windows Downloads with the run id in the name,
DELETE the old app off the iPad first, then Sideloadly. See [[padmule-ios-app-path]].

## Pass

1. **Launch** - 3s splash (mascot), then the main screen. No crash.
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
12. **Lifecycle** - background the app, wait, foreground: a "Reconnecting..."
    banner, then it resumes and reconnects. (Transfers honestly pause while away.)
13. **Cancel** - swipe a transfer to Remove; it disappears.
14. **Finished file** - a completed download opens in Files (On My iPad >
    padMule), hash-verified.

## Related

- [[padmule-ios-app-path]] - the sideload route + the "screen is the debugger" rules.
- [[padmule-live-downloads]] - the FFI simulation harness + Kad-only download.
- [[build-progress]] - what each feature is and where it lives.
