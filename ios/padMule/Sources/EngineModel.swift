// The SwiftUI-facing wrapper around the Rust engine's FFI facade (MuleEngine,
// from crates/mule-ffi via uniffi). Every MuleEngine call is synchronous and
// blocks (the facade drives the async engine on its own tokio runtime), so all
// of them run on a background queue and only results hop back to the main actor.
//
// Events are POLLED via drainEvents() - the MVP shape of the seam; a uniffi
// callback interface is the later upgrade. See docs/wiki/padmule-enhancement-channel.md
// ... and docs/wiki/lifecycle-and-reactivation.md for why pause/resume is honest.

import Foundation
import SwiftUI

// File-scope, NOT static members: a stored-property initializer cannot reference
// `Self.` (covariant Self), so the recents key/cap live here where the
// `recentSearches` default can read them directly.
private let recentsKey = "padMule.recentSearches"
private let recentsCap = 12

@MainActor
final class EngineModel: ObservableObject {
    @Published private(set) var state: EngineStateFfi = .stopped
    @Published private(set) var status: String = "Idle"
    @Published private(set) var reconnecting: Bool = false
    @Published private(set) var downloads: [DownloadInfo] = []
    /// The files we are serving to peers (the persisted + session shared library).
    @Published private(set) var sharedFiles: [SharedFileInfo] = []
    @Published private(set) var kadContacts: UInt32 = 0
    /// How many IP-blocklist ranges are loaded (0 = no ipfilter placed).
    @Published private(set) var ipFilterRanges: UInt32 = 0
    @Published private(set) var identity: IdentityInfo?
    @Published private(set) var bootError: String?
    /// The live login. Polled as a SNAPSHOT rather than tracked from events:
    /// start() emits Server(...) then Status(...) into the same drain, so an
    /// event-derived ID is overwritten in the same frame it arrives.
    @Published private(set) var server: ServerInfoFfi?

    // Servers screen: the probed server.met list, a loading flag, and the
    // kick/drop banner (settable so the alert can clear it). padMule does NOT
    // auto-connect; the user picks a live server here.
    @Published private(set) var servers: [ServerEntryFfi] = []
    @Published private(set) var loadingServers = false
    @Published var serverKick: String?

    @Published private(set) var results: [SearchHit] = []

    // The incomplete-file preview currently open (drives the AVPlayer sheet).
    // Settable so the sheet can clear it on dismiss.
    @Published var preview: PreviewItem?

    // Session transfer stats. `totalDown`/`totalUp` are the engine's monotonic
    // byte totals; `rateHistory` is a rolling 60s window of per-second deltas the
    // stats screen charts. All derived on the main thread from the 1s poll.
    @Published private(set) var totalDown: UInt64 = 0
    @Published private(set) var totalUp: UInt64 = 0
    @Published private(set) var rateHistory: [RatePoint] = []
    private var lastSampleDown: UInt64 = 0
    private var lastSampleUp: UInt64 = 0
    private var lastSampleTime = Date()
    private var sampleIndex = 0
    private var statsPrimed = false
    private let rateHistoryCap = 60
    // Pre-search WIRE filters (sent to the server so it pre-filters the capped
    // result set), distinct from the client-side sort/filter chips below which
    // refine what came back. `mb` values are megabytes; 0 = no bound.
    @Published var wireCompleteOnly = false
    @Published var wireMinSizeMb: UInt64 = 0
    @Published var wireMaxSizeMb: UInt64 = 0
    /// Query the whole serverlist over UDP (global search), not just the
    /// connected server. Off by default (slower + noisier).
    @Published var wireGlobal = false

    // Sort / filter inputs (UI-owned; applied client-side over `results`).
    @Published var sortKey: SortKey = .sources
    @Published var sortAscending: Bool = false
    @Published var nameFilter: String = ""
    @Published var typeFilter: String?
    @Published var trustedOnly: Bool = false
    @Published var hideHave: Bool = false

    /// The results after the current sort + filter. Recomputed on demand (cheap:
    /// a few hundred rows) so any input change reorders instantly.
    var presentedResults: [SearchHit] {
        present(results, sort: sortKey, ascending: sortAscending,
                nameFilter: nameFilter, typeFilter: typeFilter,
                trustedOnly: trustedOnly, hideHave: hideHave)
    }

    /// Recent search queries, most-recent first, persisted across launches so a
    /// touch user can re-run a query without retyping on the soft keyboard.
    @Published private(set) var recentSearches: [String] =
        UserDefaults.standard.stringArray(forKey: recentsKey) ?? []

    // Categories: a client-side organization layer over the transfer list
    // (definitions + a hash -> category-id map, both in UserDefaults).
    @Published private(set) var categories: [Category] = CategoryStore.loadCategories()
    @Published private(set) var categoryOf: [String: String] = CategoryStore.loadAssignment()
    /// The active category filter on the Transfers screen; nil = show all.
    @Published var categoryFilter: String?

    @Published private(set) var searching = false
    /// True once a search has actually run, so "no results" is only ever shown
    /// about a real search - never about a box the user has not used yet.
    @Published private(set) var searched = false
    /// Hashes with an add_download call in flight (its source lookup blocks).
    @Published private(set) var adding: Set<String> = []
    /// A transient line reporting what just happened.
    @Published var notice: String?
    /// The last port-mapping (UPnP) result - durable, so the "Connected" line
    /// can't clobber it. This is our only window into why HighID did or didn't
    /// happen on a device with no debugger.
    @Published private(set) var upnpStatus: String?
    /// Whether padMule serves files to peers. Off is "Leech Mode". Polled as a
    /// SNAPSHOT, like the server login: the engine owns the truth, the UI mirrors
    /// it. Defaults to true so the switch reads correctly before the first poll.
    @Published private(set) var sharing = true

    private var engine: MuleEngine?
    private var timer: Timer?
    private let work = DispatchQueue(label: "us.ajbconsulting.padMule.engine")

    /// Create the engine and start it. Idempotent - safe to call from onAppear.
    ///
    /// Two directories, deliberately: working state (identity, part files, Kad
    /// contacts) lives in Application Support, which is invisible to the user
    /// and excluded from their view; FINISHED files land in Documents, which the
    /// Files app can see. A download the user cannot open is not a download.
    func boot() {
        guard engine == nil, bootError == nil else { return }
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        let dir = base.appendingPathComponent("padMule", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]

        let path = dir.path
        let docsPath = docs.path
        work.async { [weak self] in
            do {
                let e = try MuleEngine(configDir: path, downloadsDir: docsPath)
                let ident = e.identity()
                e.start()
                DispatchQueue.main.async {
                    guard let self else { return }
                    self.engine = e
                    self.identity = ident
                    self.startPolling()
                    self.refresh()
                }
            } catch {
                DispatchQueue.main.async { self?.bootError = "\(error)" }
            }
        }
    }

    /// Search the connected server. The FFI call BLOCKS for up to ~20s waiting
    /// on the server, so it runs on the work queue and only the result hops back.
    func search(_ keyword: String) {
        let q = keyword.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let e = engine, !q.isEmpty, !searching else { return }
        recordRecent(q)
        searching = true
        notice = nil
        let mb: UInt64 = 1_048_576
        let filters = SearchFilters(
            completeOnly: wireCompleteOnly,
            minSize: wireMinSizeMb * mb,
            maxSize: wireMaxSizeMb * mb,
            global: wireGlobal
        )
        work.async { [weak self] in
            let hits = e.search(keyword: q, filters: filters)
            DispatchQueue.main.async {
                guard let self else { return }
                self.searching = false
                self.results = hits
                self.searched = true
                if hits.isEmpty {
                    self.notice = "No results for \"\(q)\"."
                }
            }
        }
    }

    /// True eD2k "related files" search: ask the connected server for the files
    /// its index associates with this hit's hash. Only servers advertising
    /// related-search support answer it, so when the server lacks support we fall
    /// back to a filename keyword search - the action still does something useful
    /// (eMule just greys the button out; padMule degrades gracefully instead).
    func relatedSearch(_ hit: SearchHit) {
        guard let e = engine, !searching else { return }
        guard server?.relatedSearch == true else {
            // Fallback: keyword search on the base filename.
            search((hit.name as NSString).deletingPathExtension)
            return
        }
        searching = true
        notice = nil
        let hash = hit.hash
        let name = hit.name
        work.async { [weak self] in
            let hits = e.relatedSearch(hash: hash)
            DispatchQueue.main.async {
                guard let self else { return }
                self.searching = false
                self.results = hits
                self.searched = true
                if hits.isEmpty {
                    self.notice = "No files related to \"\(name)\"."
                }
            }
        }
    }

    func clearSearch() {
        results = []
        searched = false
        notice = nil
    }

    /// AVPlayer-friendly media containers, so we only offer Preview for files it
    /// can actually open (avi/mkv/wmv are not natively supported - skip those).
    private static let previewableExtensions: Set<String> = [
        "mp4", "m4v", "mov", "m4a", "mp3", "aac", "wav", "caf", "aif", "aiff",
    ]

    func isPreviewable(_ name: String) -> Bool {
        Self.previewableExtensions.contains((name as NSString).pathExtension.lowercased())
    }

    /// Preview an incomplete download: switch it to preview block-bias (so the
    /// file grows contiguously from the start), snapshot the contiguous prefix to
    /// a temp file, and play it. A too-small prefix just turns preview mode on and
    /// asks the user to try again shortly - the bias makes the head arrive first.
    func startPreview(_ dl: DownloadInfo) {
        guard let e = engine else { return }
        let hash = dl.hash
        let name = dl.name
        let ext = (name as NSString).pathExtension
        let dest = FileManager.default.temporaryDirectory
            .appendingPathComponent("preview-\(hash).\(ext.isEmpty ? "mp4" : ext)")
        work.async { [weak self] in
            _ = e.setPreview(hash: hash, on: true)
            let n = e.previewSnapshot(hash: hash, destPath: dest.path)
            DispatchQueue.main.async {
                guard let self else { return }
                if n > 0 {
                    self.preview = PreviewItem(url: dest, name: name, hash: hash)
                } else {
                    self.notice = "Not enough of \"\(name)\" yet - preview mode is on, "
                        + "try again shortly."
                }
            }
        }
    }

    /// Turn preview mode back off (reverting to rarest-first). Called when the
    /// preview sheet is dismissed, so previewing once does not latch off
    /// rarest-first block selection for the rest of the session.
    func stopPreview(_ hash: String) {
        guard let e = engine else { return }
        work.async { _ = e.setPreview(hash: hash, on: false) }
    }

    /// Record a query at the front of the recents (case-insensitive de-dupe,
    /// capped), and persist. Called on every real search.
    private func recordRecent(_ q: String) {
        var list = recentSearches.filter { $0.caseInsensitiveCompare(q) != .orderedSame }
        list.insert(q, at: 0)
        if list.count > recentsCap { list = Array(list.prefix(recentsCap)) }
        recentSearches = list
        UserDefaults.standard.set(list, forKey: recentsKey)
    }

    /// Remove one recent query (swipe-to-delete).
    func removeRecent(_ q: String) {
        recentSearches.removeAll { $0 == q }
        UserDefaults.standard.set(recentSearches, forKey: recentsKey)
    }

    /// Toggle uploading. Off is "Leech Mode": padMule keeps downloading but stops
    /// serving files to peers. Optimistic - the 1s poll timer's refresh()
    /// reconciles from the engine.
    func setSharing(_ on: Bool) {
        guard let e = engine else { return }
        sharing = on
        work.async { e.setSharing(on: on) }
    }

    /// Start downloading a hit. Blocks briefly (asking the server for sources),
    /// so it too goes through the work queue.
    func download(_ hit: SearchHit) {
        guard let e = engine else { return }
        adding.insert(hit.hash)
        work.async { [weak self] in
            let outcome = e.addDownload(hash: hit.hash, size: hit.size, name: hit.name)
            DispatchQueue.main.async {
                guard let self else { return }
                self.adding.remove(hit.hash)
                switch outcome {
                case .started:
                    self.notice = "Downloading \"\(hit.name)\"."
                case .alreadyAdded:
                    self.notice = "\"\(hit.name)\" is already downloading."
                case .noSources:
                    // Not an error: nobody who is online right now has it.
                    self.notice = "No one online has \"\(hit.name)\" right now."
                case .noServer:
                    self.notice = "Not connected to a server."
                case .rejected(let reason):
                    self.notice = "Cannot download: \(reason)"
                }
                self.refresh()
            }
        }
    }

    /// Cancel and remove an in-progress download, deleting its part files. The
    /// engine owns the truth; refresh() pulls the updated list right after.
    func cancel(_ hash: String) {
        guard let e = engine else { return }
        work.async { [weak self] in
            _ = e.cancelDownload(hash: hash)
            DispatchQueue.main.async { self?.refresh() }
        }
    }

    // MARK: - Categories

    /// Downloads in the currently-selected category (all when no filter).
    var filteredDownloads: [DownloadInfo] {
        guard let f = categoryFilter else { return downloads }
        return downloads.filter { categoryOf[$0.hash] == f }
    }

    /// The category assigned to a hash, if any.
    func category(for hash: String) -> Category? {
        guard let id = categoryOf[hash] else { return nil }
        return categories.first { $0.id == id }
    }

    /// Add a category with the next palette color. No-op on a blank/dupe name.
    func addCategory(_ name: String) {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty,
              !categories.contains(where: { $0.name.caseInsensitiveCompare(trimmed) == .orderedSame })
        else { return }
        let cat = Category(id: UUID().uuidString, name: trimmed, colorIndex: categories.count)
        categories.append(cat)
        CategoryStore.saveCategories(categories)
    }

    /// Delete a category and clear it from any downloads assigned to it.
    func removeCategory(_ id: String) {
        categories.removeAll { $0.id == id }
        categoryOf = categoryOf.filter { $0.value != id }
        if categoryFilter == id { categoryFilter = nil }
        CategoryStore.saveCategories(categories)
        CategoryStore.saveAssignment(categoryOf)
    }

    /// Assign (or clear, with nil) a hash's category.
    func assignCategory(_ id: String?, to hash: String) {
        if let id { categoryOf[hash] = id } else { categoryOf.removeValue(forKey: hash) }
        CategoryStore.saveAssignment(categoryOf)
    }

    /// Fetch the connected sources for one download (a snapshot; the FFI call
    /// blocks, so it runs off the main thread and hands the result back on it).
    func sources(for hash: String, completion: @escaping ([SourceInfoFfi]) -> Void) {
        guard let e = engine else { completion([]); return }
        work.async {
            let s = e.downloadSources(hash: hash)
            DispatchQueue.main.async { completion(s) }
        }
    }

    /// Stop sharing one file (keeps the file on disk). refresh() pulls the
    /// updated library right after.
    func unshare(_ hash: String) {
        guard let e = engine else { return }
        work.async { [weak self] in
            _ = e.unshareFile(hash: hash)
            DispatchQueue.main.async { self?.refresh() }
        }
    }

    /// Set the local user's own rating (0-5, 0 = none) and comment on a shared
    /// file. Persisted and served to downloaders via OP_FILEDESC. refresh() pulls
    /// the updated library right after.
    func setFileRating(_ hash: String, rating: UInt8, comment: String) {
        guard let e = engine else { return }
        work.async { [weak self] in
            _ = e.setFileRating(hash: hash, rating: rating, comment: comment)
            DispatchQueue.main.async { self?.refresh() }
        }
    }

    /// Set a download's priority: 0 = Low, 1 = Normal, 2 = High. Persisted to
    /// part.met and honored by the running fetch. refresh() pulls the update.
    func setPriority(_ hash: String, priority: UInt8) {
        guard let e = engine else { return }
        work.async { [weak self] in
            _ = e.setDownloadPriority(hash: hash, priority: priority)
            DispatchQueue.main.async { self?.refresh() }
        }
    }

    /// App backgrounded: checkpoint + release sockets. iPadOS would reclaim them
    /// anyway - doing it explicitly is what makes resume honest.
    func pause() { run { $0.pause() } }

    /// App foregrounded: rebuild + reconnect.
    func resume() { run { $0.resume() } }

    func shutdown() { run { $0.shutdown() } }

    private func run(_ body: @escaping (MuleEngine) -> Void) {
        guard let e = engine else { return }
        work.async { [weak self] in
            body(e)
            DispatchQueue.main.async { self?.refresh() }
        }
    }

    private func startPolling() {
        timer?.invalidate()
        let t = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.refresh() }
        }
        RunLoop.main.add(t, forMode: .common)
        timer = t
    }

    /// Pull a fresh snapshot + drain queued events, all off the main thread.
    private func refresh() {
        guard let e = engine else { return }
        work.async { [weak self] in
            let st = e.state()
            let dls = e.downloads()
            let shf = e.sharedFiles()
            let kad = e.kadContacts()
            let ipf = e.ipFilterRanges()
            let srv = e.serverInfo()
            let shr = e.isSharing()
            let stats = e.transferStats()
            let evs = e.drainEvents()
            DispatchQueue.main.async {
                guard let self else { return }
                self.state = st
                self.downloads = dls
                self.sharedFiles = shf
                self.kadContacts = kad
                self.ipFilterRanges = ipf
                self.server = srv
                self.sharing = shr
                self.sampleStats(stats)
                for ev in evs { self.apply(ev) }
            }
        }
    }

    /// Fold one poll's transfer totals into the published stats. Main-thread only.
    ///
    /// The engine's byte totals are monotonic, so `delta / elapsed` is the rate.
    /// This must NOT assume a 1s cadence: refresh() (which calls this) fires not
    /// only from the 1s timer but on command completions and pause/resume too. So
    /// the totals are updated every time, but a rate POINT is folded only once
    /// ~1s of real time has passed, dividing the byte delta by the ACTUAL elapsed
    /// seconds - an off-cadence refresh never injects a false sub-second dip, and
    /// the rolling window stays a true ~60 seconds. The first sample only primes
    /// the baseline (no spike from bytes moved before the view opened).
    private func sampleStats(_ stats: TransferStats) {
        totalDown = stats.totalDown
        totalUp = stats.totalUp

        let now = Date()
        guard statsPrimed else {
            statsPrimed = true
            lastSampleDown = stats.totalDown
            lastSampleUp = stats.totalUp
            lastSampleTime = now
            return
        }
        let elapsed = now.timeIntervalSince(lastSampleTime)
        guard elapsed >= 0.9 else { return }

        let dDown = stats.totalDown >= lastSampleDown ? stats.totalDown - lastSampleDown : 0
        let dUp = stats.totalUp >= lastSampleUp ? stats.totalUp - lastSampleUp : 0
        sampleIndex += 1
        rateHistory.append(
            RatePoint(id: sampleIndex, down: Double(dDown) / elapsed, up: Double(dUp) / elapsed))
        if rateHistory.count > rateHistoryCap {
            rateHistory.removeFirst(rateHistory.count - rateHistoryCap)
        }
        lastSampleDown = stats.totalDown
        lastSampleUp = stats.totalUp
        lastSampleTime = now
    }

    private func apply(_ event: EngineEventFfi) {
        switch event {
        case .state(let s):
            state = s
        case .status(let text):
            status = text
            // The reconnect banner is a HARD lifecycle requirement.
            reconnecting = (text == "Reconnecting...")
        case .server(let text):
            // Port-mapping results go to a DURABLE field so the connection line
            // can't overwrite them (that "an event is not state" bug again).
            if text.hasPrefix("UPnP:") {
                upnpStatus = text
            } else {
                // News ("Saved 'x'", a server MOTD), NOT the connection status.
                // Writing these to `status` would clobber the polled
                // "Connected to <server> (HighID|LowID)" line.
                notice = text
            }
        case .serverDropped(let addr):
            // The server kicked/dropped us: raise a prominent dialog and refresh
            // the server list (the connected row is no longer connected).
            serverKick = addr
            server = nil
            loadServers()
        case .kad(let contacts):
            kadContacts = contacts
        case .progress:
            break // downloads() already carries the numbers
        }
    }

    // MARK: - Servers

    /// Load + probe the server.met list for the Servers screen (off the main
    /// thread; the UDP pings take a few seconds).
    func loadServers() {
        guard let e = engine, !loadingServers else { return }
        loadingServers = true
        work.async { [weak self] in
            let list = e.serverList()
            DispatchQueue.main.async {
                self?.servers = list
                self?.loadingServers = false
            }
        }
    }

    /// Connect to a chosen (live) server, then refresh the list + status.
    func connectServer(_ addr: String) {
        guard let e = engine else { return }
        work.async { [weak self] in
            _ = e.connectToServer(addr: addr)
            DispatchQueue.main.async {
                self?.refresh()
                self?.loadServers()
            }
        }
    }

    /// Disconnect from the current server at the user's request.
    func disconnectServer() {
        guard let e = engine else { return }
        work.async { [weak self] in
            e.disconnectServer()
            DispatchQueue.main.async {
                self?.refresh()
                self?.loadServers()
            }
        }
    }
}
