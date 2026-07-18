# padMule: Search-Result Richness + Launch Splash - Design Spec

Date: 2026-07-17
Status: implemented + merged to main 2026-07-18 (build-progress row 8d)

As-built divergence (2026-07-18 note): media fields (artist/album/title/codec)
use first-non-empty-wins in catalog.rs, not the most-common-value rule this
spec describes for name/size. An unplanned addition also rode along: the app
icon (mascot, corners flood-filled opaque - iOS icons cannot have alpha).

## Goal

Bring padMule's search experience up to the FUNCTIONALITY of eMule's search
panel (not its desktop look): richer per-result information, sort by any factor,
filter the fetched set, a per-result detail view with actions, and eMule-style
"do I already have this?" state - rendered as touch-native iPad patterns rather
than a 15-column grid. Plus a 3-second branded launch splash.

Reference oracle: `refs/emule-0.50a/.../srchybrid/SearchListCtrl.cpp` (its 15
columns, header-click sort, color states, filter, and context menu are the
functional target).

## Scope

IN (this spec):
- Engine surfaces the richer fields eMule shows, from tags it ALREADY receives.
- FFI `SearchHit` expanded to carry them + a New/Downloading/Have status.
- Search UI: rich result rows, a Sort control, a Filter bar, a detail sheet with
  actions (copy ed2k link, download, search-related), and status indicators.
- A launch splash: `images/splash.png` (with a baked 2px black stroke) centered
  for 3 seconds, then the main UI.

OUT (explicitly deferred - separate cycles):
- eMule's OTHER panels (Downloads detail, Uploads, Servers, Kad, Shared Files,
  Statistics, Messages/IRC). Each is its own future spec.
- "Download (paused)" per file - padMule's pause is engine-wide, not per-download;
  per-file paused-add is a separate feature.
- Expandable per-source child rows - `catalog` already dedupes to one row per
  unique file and aggregates sources, which is the grouped view eMule builds at
  runtime. No work needed.
- File "Comments/rating", "Preview", "Mark as spam" from eMule's context menu -
  not core to "more info + sortability"; revisit later if wanted.

## Architecture

The engine enriches each result and flags whether we already have it; the UI does
ALL sorting, filtering, and detail over the already-fetched `[SearchHit]`. No
re-search, no engine round-trip for sort/filter. Rationale: a search yields a
bounded set (a few hundred results at most), so client-side sort/filter is
instant and survives the server connection dropping; pushing it into the FFI
would only add blocking calls and coupling for no benefit.

No protocol or wire changes. `parse_search_result` already returns every tag on
each `SearchResultFile`; this work reads more of those tags and presents them.

## Component 1 - Engine: richer results (`catalog.rs`, `engine.rs`)

`RankedFile` (in `catalog.rs`, a pure client-side distillation) gains fields, all
read from tags already present on the results:

- `complete_sources: u32` - from `FT_COMPLETE_SOURCES` (0x30), already read for
  trust; now also surfaced.
- `file_type: String` - from the `FT_FILETYPE` tag when present; else inferred
  from the filename extension via a small extension->category map
  (Video/Audio/Archive/Document/Image/Program/Other).
- Media (empty string / 0 when the tag is absent): `artist`, `album`, `title`,
  `length_secs: u32`, `bitrate: u32`, `codec`.

`catalog()` already walks each result's tags for name/size/sources; it starts
also reading the type + media tags into these fields (taking the most-common
value across a hash's duplicates, same as it does for name/size). Exact tag
IDs/encoding for `FT_FILETYPE` and `FT_MEDIA_*` are pinned from
`refs/emule-0.50a/opcodes.h` + the tag codec during implementation - a bounded
lookup; the data itself is already parsed and preserved on `SearchResultFile`.

Result STATUS is engine state, not catalog data (catalog stays pure). The engine
gains `pub async fn hit_status(&self, hash: [u8;16]) -> HitStatus` returning:
- `Downloading` if an INCOMPLETE download with that hash is in the registry,
- `Have` if a COMPLETE download or a shared-library entry has that hash,
- `New` otherwise.

Limitation (documented, acceptable for v1): "Have" is best-effort - it knows
files finished THIS session (shared library) + active downloads, not files sitting
in Documents from a prior run. Cross-session "Have" needs a persistent known-files
index (a later cycle). This mirrors the existing session-scoped shared library.

## Component 2 - FFI: expanded `SearchHit` (`mule-ffi/src/lib.rs`)

`SearchHit` (uniffi Record) keeps `hash, name, size, sources, trusted, warning`
and adds: `complete_sources: u32`, `file_type: String`, `artist/album/title:
String`, `length_secs: u32`, `bitrate: u32`, `codec: String`, and
`status: HitStatusFfi` (a uniffi Enum: `New | Downloading | Have`).

`MuleEngine::search()` maps each enriched `RankedFile` to a `SearchHit`, calling
`hit_status(hash)` per result on the engine's runtime (same blocking-on-work-queue
pattern the UI already uses). The ed2k link is NOT added to the FFI - the UI
builds it from `name/size/hash` (see below).

## Component 3 - Search UI (`ios/padMule/Sources/`)

All new UI logic operates on the `[SearchHit]` the model already holds. Sort and
filter are pure Swift transforms; factor them into a small, testable
`func present(_ hits: [SearchHit], sort:, ascending:, filter:) -> [SearchHit]`
so the ordering/predicate logic is unit-checkable independent of SwiftUI.

Result row (rich but scannable):
- Filename (<=2 lines) + a STATUS dot: New (grey) / Downloading (orange) / Have
  (green check).
- A metadata line, shown only when the fields are present: type; for media,
  length (m:ss) and bitrate; artist/title fold in for music.
- A stats line: size - "N sources (M complete)" - a trust flag if suspect.
- Trailing "Get" button (one-tap download, as today); tapping the row body opens
  the detail sheet. (Two tap targets: borderless Get button + row `onTapGesture`.)

Sort control - a `Sort` menu above the list: Sources, Complete sources, Size,
Name, Type, Length, Bitrate, plus an ascending/descending toggle. Default:
sources-descending (matches today's ranking / "best available first").

Filter bar - a filter TextField (substring match on filename) + a Type menu
(All/Video/Audio/Archive/Document/Image/Program) + two toggles: "Trusted only"
and "Hide ones I have" (status == Have). Filters the already-fetched set live.

Detail sheet (`.sheet` on row tap) - every field; the `ed2k://|file|NAME|SIZE|
HASH|/` link with a Copy button (UIPasteboard); and actions: Download (->
`model.download`), Search related (-> `model.search` on the filename's base name,
extension stripped), and the plain status.

## Component 4 - Launch splash (`ios/`)

- Bake the stroke: `convert images/splash.png -bordercolor black -border 2
  ios/padMule/Resources/splash.png` (447x258 -> 451x262, a crisp 2-real-pixel
  black frame). The stroked PNG is committed and bundled.
- Bundle it: add the resource path to `ios/project.yml` so it lands in the app
  bundle and loads via `UIImage(named:)` / a bundle URL.
- `SplashView`: the framed image centered on a clean neutral background.
- Wiring: in `PadMuleApp` / the root view, a `ZStack { ContentView(); if
  showSplash { SplashView() } }`; a `.task` waits 3 seconds then sets
  `showSplash = false` with a short fade. The engine boots underneath, so the 3s
  is not dead time.

## Testing

- Engine (Rust, in CI): unit tests that (a) `catalog` extracts type + media +
  complete-sources from a `SearchResultFile` carrying those tags into
  `RankedFile`; (b) `file_type` inference maps extensions correctly and the
  `FT_FILETYPE` tag wins when present; (c) `hit_status` returns Downloading for an
  incomplete registered download, Have for a shared/complete one, New otherwise.
- FFI: `SearchHit` carries the new fields (compile + a mapping test).
- Swift `present(...)` sort/filter transform: pure function; add a small Swift
  test if a test target exists, else verify via the on-device build (CI has no
  Swift test target today - noted).
- UI + splash: verified by the CI arm64 build + on-device (rows render the fields,
  sort/filter behave, detail sheet opens, splash shows centered ~3s then clears).
  Verify the new strings are present in the built binary as we do for each ipa.

## Success criteria

A search returns rich rows (type, complete-sources, media info when present, a
have/downloading indicator), sortable by 7 factors ascending/descending,
filterable by name/type/trusted/have, each tappable to a detail sheet that copies
the ed2k link and offers Download + Search-related. On launch, the stroked splash
is centered on screen for ~3 seconds, then the main UI appears. All Rust tests
green, clippy/fmt/ASCII clean, CI ipa verified.

## Deliberate trims / limitations

- Per-download "paused", preview, comments, spam-marking: out of scope (above).
- "Have" is session-scoped best-effort until a persistent known-files index lands.
- Media fields appear only when the result carries the tags (server- and
  file-type-dependent); the UI shows only what is present.

## Related

- Reference: `refs/emule-0.50a/.../SearchListCtrl.cpp`, `opcodes.h`.
- Touches: `crates/mule-engine/src/catalog.rs`, `engine.rs`;
  `crates/mule-ffi/src/lib.rs`; `ios/padMule/Sources/*`, `ios/project.yml`.
- Prior art in-repo: the existing search wiring (`docs/wiki/log.md`), the
  swipe-action pattern (transfers cancel), the polled-snapshot model discipline.
