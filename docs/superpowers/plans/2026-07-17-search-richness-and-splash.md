# Search-Result Richness + Launch Splash Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring padMule's search to eMule's functionality - rich, sortable, filterable results with a per-result detail sheet + actions and have/downloading status - plus a 3-second branded launch splash.

**Architecture:** The engine reads the type/media/complete-sources tags it already receives into `RankedFile` and exposes a per-hash `HitStatus`; the FFI's `SearchHit` carries them; the SwiftUI layer does all sort/filter/detail client-side over the fetched `[SearchHit]`. The splash is a `ZStack` overlay dismissed after 3s. No eD2k wire changes.

**Tech Stack:** Rust (mule-engine, mule-ffi), UniFFI 0.28, SwiftUI, XcodeGen, ImageMagick (asset prep).

**Project constraint (read first):** iOS code cannot be compiled on this WSL box (no Xcode). Rust tasks are full TDD via `cargo test` locally. Swift tasks are written + committed here and verified by the GitHub Actions arm64 build (compile) plus on-device behavior; there is no Swift test runner in CI. Task 8 does the consolidated iOS build + verification.

---

## File Structure

- `crates/mule-engine/src/catalog.rs` (modify) - `RankedFile` gains type/media/complete fields; `catalog()` reads them; `infer_type` + `file_type_of` helpers. Owns result distillation.
- `crates/mule-engine/src/engine.rs` (modify) - add `HitStatus` enum + `hit_status()` method. Owns runtime state (downloads, shared).
- `crates/mule-ffi/src/lib.rs` (modify) - `SearchHit` expanded, `HitStatusFfi` enum, `search()` maps status. The Swift-facing shape.
- `ios/padMule/Sources/SearchPresentation.swift` (create) - pure `SortKey` enum + `present()` transform (sort/filter). Isolated, self-contained.
- `ios/padMule/Sources/EngineModel.swift` (modify) - sort/filter `@Published` state; expose `presentedResults`.
- `ios/padMule/Sources/ContentView.swift` (modify) - rich `resultRow`, sort menu, filter bar; wire the detail sheet.
- `ios/padMule/Sources/SearchDetailView.swift` (create) - the detail sheet (all fields, ed2k link + copy, Download, Search related).
- `ios/padMule/Sources/SplashView.swift` (create) - centered framed splash image.
- `ios/padMule/Sources/PadMuleApp.swift` (modify) - `ZStack` + 3s dismiss.
- `ios/padMule/Resources/splash.png` (create, generated) - the 2px-stroked splash.
- `ios/project.yml` (modify) - bundle the splash resource.

---

## Task 1: Engine - enrich RankedFile from result tags

**Files:**
- Modify: `crates/mule-engine/src/catalog.rs`

- [ ] **Step 1: Write the failing test**

Add to the `tests` module in `crates/mule-engine/src/catalog.rs`:

```rust
    fn media_result(hash: [u8; 16], name: &str, size: u64, sources: u32) -> SearchResultFile {
        SearchResultFile {
            hash,
            id: 0,
            port: 0,
            tags: vec![
                Tag { name: TagName::Id(FT_FILENAME), value: TagValue::Str(name.as_bytes().to_vec()) },
                Tag { name: TagName::Id(FT_FILESIZE), value: TagValue::U32(size as u32) },
                Tag { name: TagName::Id(FT_SOURCES), value: TagValue::U32(sources) },
                Tag { name: TagName::Id(FT_COMPLETE_SOURCES), value: TagValue::U32(7) },
                Tag { name: TagName::Id(FT_FILETYPE), value: TagValue::Str(b"Audio".to_vec()) },
                Tag { name: TagName::Id(FT_MEDIA_ARTIST), value: TagValue::Str(b"Some Artist".to_vec()) },
                Tag { name: TagName::Id(FT_MEDIA_ALBUM), value: TagValue::Str(b"Some Album".to_vec()) },
                Tag { name: TagName::Id(FT_MEDIA_TITLE), value: TagValue::Str(b"Some Title".to_vec()) },
                Tag { name: TagName::Id(FT_MEDIA_LENGTH), value: TagValue::U32(225) },
                Tag { name: TagName::Id(FT_MEDIA_BITRATE), value: TagValue::U32(192) },
                Tag { name: TagName::Id(FT_MEDIA_CODEC), value: TagValue::Str(b"mp3".to_vec()) },
            ],
        }
    }

    #[test]
    fn catalog_surfaces_type_media_and_complete_sources() {
        let cat = catalog(&[media_result([9u8; 16], "song.mp3", 5_000_000, 40)]);
        assert_eq!(cat.len(), 1);
        let f = &cat[0];
        assert_eq!(f.complete_sources, 7);
        assert_eq!(f.file_type, "Audio");
        assert_eq!(f.artist, "Some Artist");
        assert_eq!(f.album, "Some Album");
        assert_eq!(f.title, "Some Title");
        assert_eq!(f.length_secs, 225);
        assert_eq!(f.bitrate, 192);
        assert_eq!(f.codec, "mp3");
    }

    #[test]
    fn file_type_is_inferred_from_extension_when_no_tag() {
        // No FT_FILETYPE tag -> inferred from ".avi".
        let r = result([1u8; 16], "movie.avi", 700_000_000, 3);
        let cat = catalog(&[r]);
        assert_eq!(cat[0].file_type, "Video");
        assert_eq!(cat[0].complete_sources, 0); // absent -> 0
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p mule-engine -- catalog_surfaces_type_media file_type_is_inferred`
Expected: FAIL - `no field complete_sources on RankedFile`, and `FT_MEDIA_ARTIST` etc. undefined.

- [ ] **Step 3: Add the tag constants**

In `crates/mule-engine/src/catalog.rs`, after the existing `const FT_COMPLETE_SOURCES: u8 = 0x30;` line, add (IDs from `refs/emule-0.50a/.../opcodes.h`):

```rust
const FT_FILETYPE: u8 = 0x03;
const FT_MEDIA_ARTIST: u8 = 0xD0;
const FT_MEDIA_ALBUM: u8 = 0xD1;
const FT_MEDIA_TITLE: u8 = 0xD2;
const FT_MEDIA_LENGTH: u8 = 0xD3;
const FT_MEDIA_BITRATE: u8 = 0xD4;
const FT_MEDIA_CODEC: u8 = 0xD5;
```

- [ ] **Step 4: Add fields to RankedFile**

In the `RankedFile` struct, after `pub trust: Trust,` add:

```rust
    /// Full-file copies advertised (FT_COMPLETE_SOURCES); 0 if none advertised.
    pub complete_sources: u32,
    /// Display category (from FT_FILETYPE, else inferred from the extension).
    pub file_type: String,
    /// Media metadata, empty/0 when the result did not carry the tag.
    pub artist: String,
    pub album: String,
    pub title: String,
    pub length_secs: u32,
    pub bitrate: u32,
    pub codec: String,
```

- [ ] **Step 5: Add the type helpers**

Add near the other free helpers in `catalog.rs`:

```rust
/// Map a filename extension to a display category. eMule's FT_FILETYPE tag is
/// preferred when present; this is the fallback.
fn infer_type(name: &str) -> &'static str {
    let ext = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "avi" | "mkv" | "mp4" | "mov" | "mpg" | "mpeg" | "wmv" | "flv" | "m4v" | "webm"
        | "vob" | "ogm" | "rm" | "rmvb" => "Video",
        "mp3" | "flac" | "wav" | "aac" | "ogg" | "m4a" | "wma" | "ac3" | "ape" | "mpc" => "Audio",
        "zip" | "rar" | "7z" | "gz" | "tar" | "bz2" | "iso" | "img" | "nrg" => "Archive",
        "pdf" | "doc" | "docx" | "txt" | "epub" | "rtf" | "odt" | "chm" => "Document",
        "jpg" | "jpeg" | "png" | "gif" | "bmp" | "webp" | "tif" | "tiff" => "Image",
        "exe" | "msi" | "dmg" | "apk" | "deb" | "rpm" => "Program",
        _ => "Other",
    }
}

/// eMule sends FT_FILETYPE as short codes ("Audio","Video","Pro","Doc","Image",
/// "Arc","Iso"). Normalize to our display categories; unknown values pass through.
fn normalize_type(tag: &str) -> String {
    match tag {
        "Audio" => "Audio",
        "Video" => "Video",
        "Pro" => "Program",
        "Doc" => "Document",
        "Image" => "Image",
        "Arc" => "Archive",
        "Iso" => "Archive",
        other => other,
    }
    .to_string()
}
```

- [ ] **Step 6: Extend Group and read the tags in catalog()**

Add fields to the `Group` struct:

```rust
    complete: u32,
    types: BTreeMap<String, u32>, // FT_FILETYPE values seen
    artist: String,
    album: String,
    title: String,
    length: u32,
    bitrate: u32,
    codec: String,
```

In `catalog()`'s per-result loop (where it already reads name/size/sources), add after the `g.sources = g.sources.max(src);` line:

```rust
        g.complete = g.complete.max(
            tag_u64(&f.tags, FT_COMPLETE_SOURCES).unwrap_or(0) as u32,
        );
        if let Some(t) = tag_str(&f.tags, FT_FILETYPE) {
            if !t.is_empty() {
                *g.types.entry(t).or_default() += 1;
            }
        }
        // First non-empty media value wins (duplicates agree, or the tag is absent).
        let set_if_empty = |dst: &mut String, v: Option<String>| {
            if dst.is_empty() {
                if let Some(v) = v {
                    if !v.is_empty() {
                        *dst = v;
                    }
                }
            }
        };
        set_if_empty(&mut g.artist, tag_str(&f.tags, FT_MEDIA_ARTIST));
        set_if_empty(&mut g.album, tag_str(&f.tags, FT_MEDIA_ALBUM));
        set_if_empty(&mut g.title, tag_str(&f.tags, FT_MEDIA_TITLE));
        set_if_empty(&mut g.codec, tag_str(&f.tags, FT_MEDIA_CODEC));
        if g.length == 0 {
            g.length = tag_u64(&f.tags, FT_MEDIA_LENGTH).unwrap_or(0) as u32;
        }
        if g.bitrate == 0 {
            g.bitrate = tag_u64(&f.tags, FT_MEDIA_BITRATE).unwrap_or(0) as u32;
        }
```

In the `groups.into_iter().map(...)` closure that builds each `RankedFile`, compute the type and add the new fields. After the existing `name`/`name_variants`/`trust` computation, and before constructing `RankedFile { ... }`, add:

```rust
            let file_type = g
                .types
                .iter()
                .max_by_key(|(_, c)| **c)
                .map(|(t, _)| normalize_type(t))
                .unwrap_or_else(|| infer_type(&name).to_string());
```

and extend the `RankedFile { ... }` literal with:

```rust
                complete_sources: g.complete,
                file_type,
                artist: g.artist,
                album: g.album,
                title: g.title,
                length_secs: g.length,
                bitrate: g.bitrate,
                codec: g.codec,
```

Note: `g.artist` etc. are moved out of the group; this is the last use of `g`, so a move is fine.

- [ ] **Step 7: Run tests to verify they pass**

Run: `cargo test -p mule-engine -- catalog`
Expected: PASS (both new tests + the existing catalog tests).

- [ ] **Step 8: Format, lint, commit**

```bash
cargo fmt && cargo clippy -p mule-engine --all-targets 2>&1 | grep -E "warning|error" || true
git add crates/mule-engine/src/catalog.rs
git commit -m "feat(engine): surface type, media, and complete-sources on search results"
```

---

## Task 2: Engine - per-hash HitStatus

**Files:**
- Modify: `crates/mule-engine/src/engine.rs`

- [ ] **Step 1: Write the failing test**

Add to the `tests` module in `engine.rs`:

```rust
    #[tokio::test]
    async fn hit_status_reports_downloading_have_and_new() {
        let dir = tmp("hitstatus");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (mut engine, _rx) = Engine::new(&dir).unwrap();

        // An in-progress (incomplete) download -> Downloading.
        let store = PartStore::create(&dir, 1, [0xAA; 16], 1000, b"a.bin").unwrap();
        engine.downloads.lock().await.push(Download::new(store));
        assert_eq!(engine.hit_status([0xAA; 16]).await, HitStatus::Downloading);

        // A shared (finished) file -> Have.
        engine.shared.lock().await.push(SharedFile {
            hash: [0xBB; 16],
            size: 10,
            name: b"b.bin".to_vec(),
            part_hashes: vec![],
            path: dir.join("b.bin"),
        });
        assert_eq!(engine.hit_status([0xBB; 16]).await, HitStatus::Have);

        // Anything else -> New.
        assert_eq!(engine.hit_status([0xCC; 16]).await, HitStatus::New);

        std::fs::remove_dir_all(&dir).ok();
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p mule-engine -- hit_status_reports`
Expected: FAIL - `HitStatus` undefined, `hit_status` not found.

- [ ] **Step 3: Add the HitStatus enum**

In `engine.rs`, near the other public enums (e.g. after `AddResult`):

```rust
/// Whether a search hit is something we already have, are fetching, or is new.
/// Mirrors eMule's colored result states. "Have" is best-effort: it knows files
/// finished this session (shared library) + complete downloads, not files sitting
/// in the downloads directory from a prior run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HitStatus {
    New,
    Downloading,
    Have,
}
```

- [ ] **Step 4: Add the hit_status method**

In `impl Engine`, near `search`:

```rust
    /// Classify a search hit's hash against our downloads + shared files.
    pub async fn hit_status(&self, hash: [u8; 16]) -> HitStatus {
        for dl in self.downloads.lock().await.iter() {
            if dl.hash().await == hash {
                return if dl.is_complete().await {
                    HitStatus::Have
                } else {
                    HitStatus::Downloading
                };
            }
        }
        if self.shared.lock().await.iter().any(|s| s.hash == hash) {
            return HitStatus::Have;
        }
        HitStatus::New
    }
```

- [ ] **Step 5: Export HitStatus**

In `crates/mule-engine/src/lib.rs`, add `HitStatus` to the engine re-export line:

```rust
pub use engine::{AddResult, Engine, EngineEvent, EngineState, HitStatus, ServerInfo};
```

- [ ] **Step 6: Run test to verify it passes**

Run: `cargo test -p mule-engine -- hit_status_reports`
Expected: PASS

- [ ] **Step 7: Format, lint, commit**

```bash
cargo fmt && cargo clippy -p mule-engine --all-targets 2>&1 | grep -E "warning|error" || true
git add crates/mule-engine/src/engine.rs crates/mule-engine/src/lib.rs
git commit -m "feat(engine): hit_status classifies a hash as New/Downloading/Have"
```

---

## Task 3: FFI - expand SearchHit with the rich fields + status

**Files:**
- Modify: `crates/mule-ffi/src/lib.rs`

- [ ] **Step 1: Write the failing test**

Add to the `tests` module in `mule-ffi/src/lib.rs`:

```rust
    #[test]
    fn search_hit_has_the_rich_fields() {
        // Compile-level guarantee that the record carries the new shape.
        let h = SearchHit {
            hash: "00".to_string(),
            name: "x".to_string(),
            size: 1,
            sources: 2,
            complete_sources: 1,
            file_type: "Audio".to_string(),
            artist: "a".to_string(),
            album: "b".to_string(),
            title: "c".to_string(),
            length_secs: 10,
            bitrate: 128,
            codec: "mp3".to_string(),
            trusted: true,
            warning: String::new(),
            status: HitStatusFfi::New,
        };
        assert_eq!(h.file_type, "Audio");
        assert_eq!(h.status, HitStatusFfi::New);
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p mule-ffi -- search_hit_has_the_rich_fields`
Expected: FAIL - unknown fields / `HitStatusFfi` undefined.

- [ ] **Step 3: Add the status enum + its From**

In `mule-ffi/src/lib.rs`, add (and add `HitStatus` to the `use mule_engine::{...}` import):

```rust
/// A search hit's local state (already have / fetching / new).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum HitStatusFfi {
    New,
    Downloading,
    Have,
}

impl From<HitStatus> for HitStatusFfi {
    fn from(s: HitStatus) -> Self {
        match s {
            HitStatus::New => HitStatusFfi::New,
            HitStatus::Downloading => HitStatusFfi::Downloading,
            HitStatus::Have => HitStatusFfi::Have,
        }
    }
}
```

- [ ] **Step 4: Expand the SearchHit record**

Replace the `SearchHit` struct with (keep the existing doc comments on the kept fields):

```rust
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SearchHit {
    pub hash: String,
    pub name: String,
    pub size: u64,
    pub sources: u32,
    /// Full-file copies advertised; 0 if none.
    pub complete_sources: u32,
    /// Display category (Video/Audio/Archive/Document/Image/Program/Other).
    pub file_type: String,
    /// Media metadata, empty/0 when the result did not carry it.
    pub artist: String,
    pub album: String,
    pub title: String,
    pub length_secs: u32,
    pub bitrate: u32,
    pub codec: String,
    pub trusted: bool,
    pub warning: String,
    /// Whether we already have it, are fetching it, or it is new.
    pub status: HitStatusFfi,
}
```

- [ ] **Step 5: Fill the new fields in search()**

In `MuleEngine::search`, the mapping closure currently builds `SearchHit { hash, name, size, sources, trusted, warning }`. It must also compute status (an async engine call) - so restructure to look up status inside the locked block. Replace the body of `search` with:

```rust
    pub fn search(&self, keyword: String) -> Vec<SearchHit> {
        self.rt.block_on(async {
            let mut g = self.inner.lock().await;
            let ranked = g.search(&keyword).await;
            let mut out = Vec::with_capacity(ranked.len());
            for r in ranked {
                let status = g.hit_status(r.hash).await.into();
                let trusted = r.is_trusted();
                let warning = match r.trust {
                    Trust::Ok => String::new(),
                    Trust::Suspect(why) => why.to_string(),
                };
                out.push(SearchHit {
                    hash: hex::encode(r.hash),
                    name: r.name,
                    size: r.size,
                    sources: r.sources,
                    complete_sources: r.complete_sources,
                    file_type: r.file_type,
                    artist: r.artist,
                    album: r.album,
                    title: r.title,
                    length_secs: r.length_secs,
                    bitrate: r.bitrate,
                    codec: r.codec,
                    trusted,
                    warning,
                    status,
                });
            }
            out
        })
    }
```

(Note: `search(&mut self)` and `hit_status(&self)` both borrow the same guard `g`; `search` takes `&mut`, `hit_status` takes `&`. Call `g.search(...)` first, drop no borrows, then `g.hit_status(...)` - the mutable borrow from `search` has ended by the time we call `hit_status`, since its returned `Vec` is owned. This compiles.)

- [ ] **Step 6: Run test + build to verify**

Run: `cargo test -p mule-ffi -- search_hit_has_the_rich_fields && cargo build -p mule-ffi`
Expected: PASS + clean build.

- [ ] **Step 7: Regenerate + sanity-check Swift bindings compile-shape (optional local)**

The Swift bindings are generated in CI; no local action required. Proceed.

- [ ] **Step 8: Format, lint, commit**

```bash
cargo fmt && cargo clippy -p mule-ffi --all-targets 2>&1 | grep -E "warning|error" || true
git add crates/mule-ffi/src/lib.rs
git commit -m "feat(ffi): SearchHit carries type, media, complete-sources, and status"
```

---

## Task 4: Swift - the sort/filter transform

**Files:**
- Create: `ios/padMule/Sources/SearchPresentation.swift`

- [ ] **Step 1: Write the transform (no local test runner; keep it self-evidently correct)**

Create `ios/padMule/Sources/SearchPresentation.swift`:

```swift
import Foundation

/// The factors a user can sort search results by. Raw values are the menu labels.
enum SortKey: String, CaseIterable, Identifiable {
    case sources = "Sources"
    case completeSources = "Complete"
    case size = "Size"
    case name = "Name"
    case type = "Type"
    case length = "Length"
    case bitrate = "Bitrate"
    var id: String { rawValue }
}

/// A pure, order-preserving filter over the fetched hits, then a stable sort.
/// UI holds the inputs; this has no SwiftUI or engine dependency, so its behavior
/// is obvious from reading it.
func present(
    _ hits: [SearchHit],
    sort: SortKey,
    ascending: Bool,
    nameFilter: String,
    typeFilter: String?,     // nil = all
    trustedOnly: Bool,
    hideHave: Bool
) -> [SearchHit] {
    let needle = nameFilter.trimmingCharacters(in: .whitespaces).lowercased()
    var xs = hits.filter { h in
        (needle.isEmpty || h.name.lowercased().contains(needle))
            && (typeFilter == nil || h.fileType == typeFilter)
            && (!trustedOnly || h.trusted)
            && (!hideHave || h.status != .have)
    }
    xs.sort { a, b in
        let asc: Bool
        switch sort {
        case .sources:         asc = a.sources < b.sources
        case .completeSources: asc = a.completeSources < b.completeSources
        case .size:            asc = a.size < b.size
        case .name:            asc = a.name.localizedCaseInsensitiveCompare(b.name) == .orderedAscending
        case .type:            asc = a.fileType < b.fileType
        case .length:          asc = a.lengthSecs < b.lengthSecs
        case .bitrate:         asc = a.bitrate < b.bitrate
        }
        return ascending ? asc : !asc
    }
    return xs
}
```

(Note: UniFFI generates Swift property names in camelCase: `fileType`, `completeSources`, `lengthSecs`, and the enum `HitStatusFfi` with cases `.new`/`.downloading`/`.have`.)

- [ ] **Step 2: Commit**

```bash
git add ios/padMule/Sources/SearchPresentation.swift
git commit -m "feat(ui): pure sort/filter transform for search results"
```

---

## Task 5: Swift - EngineModel sort/filter state + rich rows

**Files:**
- Modify: `ios/padMule/Sources/EngineModel.swift`
- Modify: `ios/padMule/Sources/ContentView.swift`

- [ ] **Step 1: Add sort/filter state + presented results to EngineModel**

In `EngineModel`, after the `results` published property, add:

```swift
    // Sort / filter inputs (UI-owned; applied client-side over `results`).
    @Published var sortKey: SortKey = .sources
    @Published var sortAscending: Bool = false
    @Published var nameFilter: String = ""
    @Published var typeFilter: String? = nil
    @Published var trustedOnly: Bool = false
    @Published var hideHave: Bool = false

    /// The results after the current sort + filter. Recomputed on demand (cheap:
    /// a few hundred rows) so any input change reorders instantly.
    var presentedResults: [SearchHit] {
        present(results, sort: sortKey, ascending: sortAscending,
                nameFilter: nameFilter, typeFilter: typeFilter,
                trustedOnly: trustedOnly, hideHave: hideHave)
    }
```

- [ ] **Step 2: Replace resultRow + the results ForEach in ContentView**

In `ContentView.swift`, change the results `ForEach` to iterate `model.presentedResults`, and replace `resultRow(_:)` with the rich version + a status dot + tap-for-detail. Replace the `ForEach(model.results ...)` block inside the Search section with:

```swift
                        ForEach(model.presentedResults, id: \.hash) { hit in
                            resultRow(hit)
                                .contentShape(Rectangle())
                                .onTapGesture { detail = hit }
                        }
```

Replace `resultRow(_ hit: SearchHit)` with:

```swift
    private func resultRow(_ hit: SearchHit) -> some View {
        HStack(alignment: .top, spacing: 8) {
            statusDot(hit.status)
                .padding(.top, 5)
            VStack(alignment: .leading, spacing: 2) {
                Text(hit.name).lineLimit(2)
                if let meta = metaLine(hit) {
                    Text(meta).font(.caption).foregroundStyle(.secondary)
                }
                HStack(spacing: 6) {
                    Text(bytes(hit.size))
                    Text("-")
                    Text("\(hit.sources) src\(hit.sources == 1 ? "" : "s")"
                         + (hit.completeSources > 0 ? " (\(hit.completeSources) full)" : ""))
                    if !hit.trusted {
                        Text("- ").foregroundStyle(.orange) + Text(hit.warning).foregroundStyle(.orange)
                    }
                }
                .font(.caption)
                .foregroundStyle(.secondary)
            }
            Spacer()
            if model.adding.contains(hit.hash) {
                ProgressView()
            } else {
                Button("Get") { model.download(hit) }
                    .buttonStyle(.borderless)
            }
        }
    }

    /// Type + media summary, only when there is something to show.
    private func metaLine(_ hit: SearchHit) -> String? {
        var parts: [String] = []
        if !hit.fileType.isEmpty && hit.fileType != "Other" { parts.append(hit.fileType) }
        if hit.lengthSecs > 0 { parts.append(duration(hit.lengthSecs)) }
        if hit.bitrate > 0 { parts.append("\(hit.bitrate) kbps") }
        if !hit.artist.isEmpty { parts.append(hit.artist) }
        return parts.isEmpty ? nil : parts.joined(separator: "  -  ")
    }

    private func statusDot(_ s: HitStatusFfi) -> some View {
        switch s {
        case .have:        return Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
        case .downloading: return Image(systemName: "arrow.down.circle.fill").foregroundStyle(.orange)
        case .new:         return Image(systemName: "circle").foregroundStyle(.secondary)
        }
    }

    private func duration(_ secs: UInt32) -> String {
        let s = Int(secs)
        let h = s / 3600, m = (s % 3600) / 60, sec = s % 60
        return h > 0 ? String(format: "%d:%02d:%02d", h, m, sec)
                     : String(format: "%d:%02d", m, sec)
    }
```

- [ ] **Step 3: Add the `detail` sheet state**

At the top of `ContentView` with the other `@State`, add:

```swift
    @State private var detail: SearchHit?
```

And attach the sheet to the `List` (add after `.navigationTitle("padMule")`):

```swift
            .sheet(item: Binding(get: { detail.map { IdentifiedHit($0) } },
                                 set: { detail = $0?.hit })) { ih in
                SearchDetailView(hit: ih.hit).environmentObject(model)
            }
```

Because `SearchHit` is not `Identifiable`, add this tiny wrapper at file scope in `ContentView.swift`:

```swift
private struct IdentifiedHit: Identifiable { let hit: SearchHit; var id: String { hit.hash }
    init(_ h: SearchHit) { hit = h } }
```

- [ ] **Step 4: Commit**

```bash
git add ios/padMule/Sources/EngineModel.swift ios/padMule/Sources/ContentView.swift
git commit -m "feat(ui): rich search rows with status, metadata, and complete sources"
```

---

## Task 6: Swift - sort menu, filter bar, and detail sheet

**Files:**
- Modify: `ios/padMule/Sources/ContentView.swift`
- Create: `ios/padMule/Sources/SearchDetailView.swift`

- [ ] **Step 1: Add the sort menu + filter bar above the results**

In the `Section("Search")`, right after the search `TextField`/`HStack` and before the results `ForEach`, insert (shown only once a search has run):

```swift
                        if model.searched && !model.results.isEmpty {
                            HStack {
                                Menu {
                                    Picker("Sort", selection: $model.sortKey) {
                                        ForEach(SortKey.allCases) { Text($0.rawValue).tag($0) }
                                    }
                                    Toggle("Ascending", isOn: $model.sortAscending)
                                } label: {
                                    Label("Sort: \(model.sortKey.rawValue)", systemImage: "arrow.up.arrow.down")
                                        .font(.caption)
                                }
                                Spacer()
                                Menu {
                                    Button("All types") { model.typeFilter = nil }
                                    ForEach(["Video","Audio","Archive","Document","Image","Program"], id: \.self) { t in
                                        Button(t) { model.typeFilter = t }
                                    }
                                } label: {
                                    Label(model.typeFilter ?? "All types", systemImage: "line.3.horizontal.decrease.circle")
                                        .font(.caption)
                                }
                            }
                            HStack {
                                Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                                TextField("Filter these results", text: $model.nameFilter)
                                    .textInputAutocapitalization(.never)
                                    .disableAutocorrection(true)
                            }
                            .font(.caption)
                            HStack {
                                Toggle("Trusted only", isOn: $model.trustedOnly)
                                Toggle("Hide ones I have", isOn: $model.hideHave)
                            }
                            .font(.caption)
                            .toggleStyle(.switch)
                        }
```

- [ ] **Step 2: Create the detail sheet**

Create `ios/padMule/Sources/SearchDetailView.swift`:

```swift
import SwiftUI

/// Full detail for one search hit: every field, the ed2k link, and actions.
struct SearchDetailView: View {
    @EnvironmentObject var model: EngineModel
    @Environment(\.dismiss) private var dismiss
    let hit: SearchHit

    private var ed2kLink: String {
        "ed2k://|file|\(hit.name)|\(hit.size)|\(hit.hash)|/"
    }

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Text(hit.name).font(.headline)
                    row("Type", hit.fileType)
                    row("Size", ByteCountFormatter.string(fromByteCount: Int64(hit.size), countStyle: .file))
                    row("Sources", "\(hit.sources)" + (hit.completeSources > 0 ? " (\(hit.completeSources) complete)" : ""))
                    if hit.lengthSecs > 0 { row("Length", "\(hit.lengthSecs)s") }
                    if hit.bitrate > 0 { row("Bitrate", "\(hit.bitrate) kbps") }
                    if !hit.codec.isEmpty { row("Codec", hit.codec) }
                    if !hit.artist.isEmpty { row("Artist", hit.artist) }
                    if !hit.album.isEmpty { row("Album", hit.album) }
                    if !hit.title.isEmpty { row("Title", hit.title) }
                    row("Hash", hit.hash)
                    if !hit.trusted {
                        Label(hit.warning, systemImage: "exclamationmark.triangle")
                            .foregroundStyle(.orange).font(.caption)
                    }
                }
                Section {
                    Button {
                        UIPasteboard.general.string = ed2kLink
                    } label: { Label("Copy ed2k link", systemImage: "doc.on.doc") }
                    Button {
                        model.download(hit); dismiss()
                    } label: { Label("Download", systemImage: "arrow.down.circle") }
                    Button {
                        let base = (hit.name as NSString).deletingPathExtension
                        model.search(base); dismiss()
                    } label: { Label("Search related", systemImage: "magnifyingglass") }
                }
            }
            .navigationTitle("Details")
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } } }
        }
    }

    private func row(_ k: String, _ v: String) -> some View {
        HStack { Text(k).foregroundStyle(.secondary); Spacer(); Text(v).multilineTextAlignment(.trailing) }
            .font(.callout)
    }
}
```

- [ ] **Step 3: Commit**

```bash
git add ios/padMule/Sources/ContentView.swift ios/padMule/Sources/SearchDetailView.swift
git commit -m "feat(ui): sort menu, filter bar, and search-result detail sheet"
```

---

## Task 7: Launch splash

**Files:**
- Create (generated): `ios/padMule/Resources/splash.png`
- Create: `ios/padMule/Sources/SplashView.swift`
- Modify: `ios/padMule/Sources/PadMuleApp.swift`
- Modify: `ios/project.yml`

- [ ] **Step 1: Bake the 2px black stroke into the bundled asset**

```bash
mkdir -p ios/padMule/Resources
convert images/splash.png -bordercolor black -border 2 ios/padMule/Resources/splash.png
identify ios/padMule/Resources/splash.png   # expect 451x262
```

Expected: `... PNG 451x262 ...` (447x258 + 2px each side).

- [ ] **Step 2: Bundle the resource in project.yml**

In `ios/project.yml`, under `targets: padMule: sources:`, add an entry:

```yaml
      - path: padMule/Resources/splash.png
        type: file
```

- [ ] **Step 3: Create SplashView**

Create `ios/padMule/Sources/SplashView.swift`:

```swift
import SwiftUI

/// The launch splash: the pre-stroked padMule image centered on a clean field.
struct SplashView: View {
    var body: some View {
        ZStack {
            Color(.systemBackground).ignoresSafeArea()
            if let ui = UIImage(named: "splash") {
                Image(uiImage: ui)
                    .resizable()
                    .scaledToFit()
                    .frame(maxWidth: 360)
            }
        }
    }
}
```

- [ ] **Step 4: Show it for 3 seconds over the app**

In `PadMuleApp.swift`, wrap the root content in a `ZStack` with a timed dismiss. Replace the `ContentView()` in the `WindowGroup` with:

```swift
            ZStack {
                ContentView().environmentObject(model)
                if showSplash {
                    SplashView().transition(.opacity)
                }
            }
            .task {
                try? await Task.sleep(nanoseconds: 3_000_000_000)
                withAnimation(.easeOut(duration: 0.35)) { showSplash = false }
            }
```

Add the state to the `App` struct: `@State private var showSplash = true` (and keep the existing `model` / `EngineModel` however it is currently declared; if `model` is created in `ContentView`, move the `.environmentObject` to match the existing pattern - check `PadMuleApp.swift` first and follow it).

- [ ] **Step 5: Commit**

```bash
git add ios/padMule/Resources/splash.png ios/padMule/Sources/SplashView.swift ios/padMule/Sources/PadMuleApp.swift ios/project.yml
git commit -m "feat(ui): 3-second launch splash with a 2px-stroked padMule image"
```

---

## Task 8: Consolidated verification (workspace + CI + on-device)

**Files:** none (verification only)

- [ ] **Step 1: Full Rust gate**

```bash
cargo fmt --check && cargo test --workspace 2>&1 | grep -E "test result: FAILED|FAILED" || echo "all green"
cargo clippy --workspace --all-targets 2>&1 | grep -E "^warning|^error" || echo "clippy clean"
```

Expected: all green, clippy clean.

- [ ] **Step 2: ASCII check on every changed file**

```bash
for f in $(git diff --name-only HEAD~7); do LC_ALL=C grep -qP '[^\x00-\x7F]' "$f" 2>/dev/null && echo "NON-ASCII: $f"; done; echo "ascii checked"
```

Expected: no NON-ASCII lines (the splash PNG is binary; skip binary or ignore).

- [ ] **Step 3: Push and let CI build the ipa**

```bash
git push origin main
```

Then watch the run to green (the `.github/workflows/ios-build.yml` triggers on `ios/**`, `crates/**`).

- [ ] **Step 4: Verify the ipa carries the new UI + bindings**

Download the artifact and check the Mach-O for the new strings (as done for prior builds):

```bash
# in a scratch dir, unzip the artifact, then:
for s in "Search related" "Copy ed2k link" "Filter these results" "Hide ones I have" "muleengine_search"; do
  strings -a Payload/padMule.app/padMule | grep -c -- "$s"; done
ls Payload/padMule.app/ | grep -i splash   # the bundled resource
```

Expected: non-zero counts; the splash resource present in the bundle.

- [ ] **Step 5: On-device acceptance (sideload + check)**

- Splash: on launch, the framed padMule image is centered ~3s, then the app fades in.
- Search: run a query; rows show type/media/complete-sources and a status dot; the Sort menu reorders; the filter bar narrows; a green check appears on any file already downloaded.
- Detail: tapping a row opens the sheet; Copy ed2k link, Download, and Search related all work.

- [ ] **Step 6: Update the KB**

Append a `docs/wiki/log.md` entry and update `docs/wiki/build-progress.md` + memory noting the search-richness + splash landed; commit.

---

## Self-Review

**Spec coverage:** Every spec section maps to a task - engine enrichment (T1), status (T2), FFI (T3), sort/filter transform (T4), rich rows (T5), sort/filter UI + detail sheet (T6), splash (T7), verification + KB (T8). Out-of-scope items (per-download pause, preview, spam, source grouping) are absent by design.

**Placeholder scan:** No TBD/TODO. All code blocks are complete; tag IDs are pinned from opcodes.h; the one runtime caveat (the `search`/`hit_status` borrow ordering) is explained in T3 Step 5.

**Type consistency:** `HitStatus` (engine) -> `HitStatusFfi` (ffi) -> Swift `.new/.downloading/.have`. `RankedFile` fields (`complete_sources`, `file_type`, `length_secs`, ...) match the `SearchHit` fields and the Swift camelCase (`completeSources`, `fileType`, `lengthSecs`). `present(...)` signature matches its EngineModel call. `SortKey` used consistently.

**Known adaptation:** Swift tasks (T4-T7) cannot run local tests (no Xcode on WSL); they are verified by the CI compile + on-device acceptance in T8, which is called out in the plan header.
