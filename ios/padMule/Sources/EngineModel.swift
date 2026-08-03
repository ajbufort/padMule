// The SwiftUI-facing wrapper around the Rust engine's FFI facade (MuleEngine,
// from crates/mule-ffi via uniffi). Every MuleEngine call is synchronous and
// blocks (the facade drives the async engine on its own tokio runtime), so all
// of them run on a background queue and only results hop back to the main actor.
//
// Events are POLLED via drainEvents() - the MVP shape of the seam; a uniffi
// callback interface is the later upgrade. See docs/wiki/padmule-enhancement-channel.md
// ... and docs/wiki/lifecycle-and-reactivation.md for why pause/resume is honest.

import Foundation
import OSLog
import SwiftUI
import UIKit  // UIApplication.isIdleTimerDisabled (keep-screen-awake setting)

/// The engine's on-device log. Until this existed, `idevicesyslog -p padMule`
/// carried ZERO app-authored lines - a 1293-line capture across a full launch,
/// search and download was entirely system frameworks - because nothing in the
/// Swift shell or the Rust engine ever called os_log, and a GUI app's stdout
/// (where Rust `println!` goes) is not captured. The UI rows were the only
/// window into the engine on a device with no debugger.
///
/// Read it from a paired machine with:
///   idevicesyslog -p padMule
/// or filter to just these lines with:
///   idevicesyslog -p padMule -m padMule.engine
///
/// PRIVACY: os_log redacts interpolated strings unless marked `.public`, and
/// these are marked public DELIBERATELY - a redacted diagnostic is worthless.
/// What flows through here is safe to show: the engine never emits our own
/// public IP or client ID (`server_state_label` and `ServerInfo` exist precisely
/// to keep those out of user-visible text), server addresses are public
/// infrastructure, and the only local addresses that appear are RFC1918.
let engineLog = Logger(subsystem: "us.ajbconsulting.padMule", category: "padMule.engine")

// File-scope, NOT static members: a stored-property initializer cannot reference
// `Self.` (covariant Self), so the recents key/cap live here where the
// `recentSearches` default can read them directly.
private let recentsKey = "padMule.recentSearches"
private let recentsCap = 12

@MainActor
final class EngineModel: ObservableObject {
    @Published private(set) var state: EngineStateFfi = .stopped
    /// The engine object exists and start() has returned. Until this is true every
    /// action would silently no-op (`guard let e = engine else { return }`), so the
    /// UI must show that it is still starting rather than looking live and inert.
    /// Boot is 12-30s: two HTTP fetches, the always-failing multicast SSDP probe,
    /// then unicast + SOAP, then Kad.
    @Published private(set) var ready: Bool = false
    /// A stop (or a start after one) is in flight. Both talk to the router, so
    /// they take seconds; the Status screen shows progress instead of freezing.
    @Published private(set) var stopping: Bool = false
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
    /// The address currently being dialled. connect_to_server blocks up to 12s, so
    /// without this the first real action a new user takes appears to do nothing.
    @Published private(set) var connectingTo: String?
    @Published var serverKick: String?

    @Published private(set) var results: [SearchHit] = []
    /// The connected server has more result pages ("Load more results", #13).
    @Published private(set) var moreAvailable = false

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

    /// Whether padMule has any way to find files right now - a connected server
    /// or a populated Kad table. Mirrors the engine's own `can_discover`, and is
    /// what lets the UI say "nobody to ask" instead of "no results".
    var canDiscover: Bool { server != nil || kadContacts > 0 }

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
    /// Whether a router port mapping is actually held right now. Drives the Stop
    /// wording: a user on cellular, behind CGNAT, or on a router without UPnP
    /// never had one, and must not be told a port was handed back.
    @Published private(set) var portMapped: Bool = false
    /// Whether the current network is metered (cellular / hotspot / Low Data).
    @Published private(set) var meteredNow: Bool = false
    /// Whether padMule serves files to peers. Off is "Leech Mode". Polled as a
    /// SNAPSHOT, like the server login: the engine owns the truth, the UI mirrors
    /// it. Defaults to true so the switch reads correctly before the first poll.
    @Published private(set) var sharing = true

    private var engine: MuleEngine?
    private var timer: Timer?
    private let work = DispatchQueue(label: "us.ajbconsulting.padMule.engine")

    private var booting = false

    /// Create the engine and start it. Idempotent - safe to call from onAppear.
    ///
    /// Two directories, deliberately: working state (identity, part files, Kad
    /// contacts) lives in Application Support, which is invisible to the user
    /// and excluded from their view; FINISHED files land in Documents, which the
    /// Files app can see. A download the user cannot open is not a download.
    func boot() {
        // Retry on a later call (foreground) after a transient init failure - do
        // NOT latch on bootError, or one bad launch bricks the app forever. The
        // `booting` guard prevents a concurrent double-construct (onAppear + .active).
        guard engine == nil, !booting else { return }
        booting = true
        bootError = nil
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        let dir = base.appendingPathComponent("padMule", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]

        let path = dir.path
        let docsPath = docs.path
        engineLog.notice("boot: config=\(path, privacy: .public)")
        work.async { [weak self] in
            do {
                let e = try MuleEngine(configDir: path, downloadsDir: docsPath)
                let ident = e.identity()
                e.start()
                engineLog.notice("boot OK; engine started")
                DispatchQueue.main.async {
                    guard let self else { return }
                    self.booting = false
                    self.engine = e
                    self.ready = true
                    self.identity = ident
                    // Re-apply persisted settings the moment the engine exists.
                    // Without this the engine keeps its own defaults and the
                    // user's choices look like they were ignored.
                    self.applyEffectiveSharing()
                    self.applyLaunchSettings()
                    self.startPolling()
                    self.refresh()
                }
            } catch {
                // A cold-boot failure is otherwise visible only as a message on
                // screen, which is no help once the screen has moved on.
                engineLog.error("boot FAILED: \(String(describing: error), privacy: .public)")
                DispatchQueue.main.async {
                    self?.booting = false
                    self?.bootError = "\(error)"
                }
            }
        }
    }

    /// Search the connected server. The FFI call BLOCKS for up to ~20s waiting
    /// on the server, so it runs on the work queue and only the result hops back.
    func search(_ keyword: String) {
        let q = keyword.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let e = engine, !q.isEmpty, !searching else { return }
        recordRecent(q)
        saveSearchFilters()
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
            let outcome = e.search(keyword: q, filters: filters)
            DispatchQueue.main.async {
                guard let self else { return }
                self.searching = false
                self.apply(
                    EngineModel.searchUpdate(for: outcome, emptyMessage: "No results for \"\(q)\"."))
            }
        }
    }

    /// How a search outcome maps to the UI. Pure + `static` so it is unit-testable
    /// without an engine (see padMuleTests). `results == nil` means "leave the list
    /// untouched" (a throttle notice must not blank the current results).
    struct SearchUpdate {
        var results: [SearchHit]?  // nil = leave the list untouched (throttle)
        var moreAvailable: Bool?  // nil = leave the Load-more flag untouched
        var notice: String?
    }

    nonisolated static func searchUpdate(for outcome: SearchOutcome, emptyMessage: String)
        -> SearchUpdate
    {
        switch outcome {
        case let .results(hits, more):
            return SearchUpdate(
                results: hits, moreAvailable: more,
                notice: hits.isEmpty ? emptyMessage : nil)
        case let .throttled(waitSecs):
            // eMule/aMule guard: too-fast searches are refused. Keep the results
            // AND the Load-more flag as they are (the still-displayed results may
            // legitimately have more pages); just tell the user to wait. aMule
            // silently ignores the click; padMule is honest about the wait.
            return SearchUpdate(
                results: nil, moreAvailable: nil,
                notice: "Searching too fast - wait \(waitSecs)s and try again.")
        }
    }

    private func apply(_ u: SearchUpdate) {
        if let r = u.results {
            results = r
            searched = true
        }
        if let m = u.moreAvailable { moreAvailable = m }
        notice = u.notice
    }

    /// Fetch the next page of the last search and replace the list with the merged
    /// set (eMule's "Load more results", #13). The engine returns the full ranked
    /// view, so no client-side merge is needed.
    func loadMore() {
        guard let e = engine, !searching, moreAvailable else { return }
        searching = true
        work.async { [weak self] in
            let outcome = e.searchMore()
            DispatchQueue.main.async {
                guard let self else { return }
                self.searching = false
                let u = EngineModel.searchUpdate(for: outcome, emptyMessage: "")
                if let r = u.results { self.results = r }
                if let m = u.moreAvailable { self.moreAvailable = m }
                if let n = u.notice, !n.isEmpty { self.notice = n }
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
            let outcome = e.relatedSearch(hash: hash)
            DispatchQueue.main.async {
                guard let self else { return }
                self.searching = false
                self.apply(
                    EngineModel.searchUpdate(
                        for: outcome, emptyMessage: "No files related to \"\(name)\"."))
            }
        }
    }

    func clearSearch() {
        results = []
        searched = false
        moreAvailable = false
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
    ///
    /// This records the user's PREFERENCE and then applies the effective value,
    /// which may differ while a metered-network pause is in force.
    func setSharing(_ on: Bool) {
        UserDefaults.standard.set(on, forKey: SettingsKey.shareUploads)
        applyEffectiveSharing()
    }

    /// Push the sharing decision into the engine.
    ///
    /// effective = the user wants to share AND we are not pausing for a metered
    /// link. Kept in ONE place because the inputs arrive from three directions -
    /// the Shared-screen toggle, Settings, and the network path changing under us
    /// - and a rule spread across three call sites is a rule that will disagree
    /// with itself.
    ///
    /// Also the fix for a live bug: sharing was initialised true in the engine and
    /// never persisted, so turning it OFF silently turned itself back ON at the
    /// next launch.
    func applyEffectiveSharing() {
        guard let e = engine else { return }
        let wanted = UserDefaults.standard.bool(forKey: SettingsKey.shareUploads)
        let pauseOnMetered = UserDefaults.standard.bool(forKey: SettingsKey.pauseSharingOnCellular)
        let effective = wanted && !(pauseOnMetered && meteredNow)
        if effective != sharing {
            let detail = "user wants \(wanted ? "on" : "off"), metered \(meteredNow ? "yes" : "no")"
            engineLog.notice(
                "sharing -> \(effective ? "on" : "off", privacy: .public) (\(detail, privacy: .public))"
            )
        }
        sharing = effective
        work.async { e.setSharing(on: effective) }
    }

    /// True when sharing is off ONLY because of the metered-network rule, so the
    /// UI can explain itself rather than look broken.
    var sharingPausedForMeteredLink: Bool {
        meteredNow
            && UserDefaults.standard.bool(forKey: SettingsKey.pauseSharingOnCellular)
            && UserDefaults.standard.bool(forKey: SettingsKey.shareUploads)
    }

    /// Latest metered verdict from the NetworkWatcher; the app feeds this in.
    func setMetered(_ metered: Bool) {
        guard meteredNow != metered else { return }
        meteredNow = metered
        applyEffectiveSharing()
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
                    // Apply the user's default priority. add_download registers at
                    // Normal; set it right after, so a non-Normal default is
                    // honored without a new engine argument.
                    let pri = UserDefaults.standard.integer(forKey: SettingsKey.defaultPriority)
                    if pri != 1 { self.setPriority(hit.hash, priority: UInt8(pri)) }
                    self.notice = "Downloading \"\(hit.name)\"."
                case .alreadyAdded:
                    self.notice = "\"\(hit.name)\" is already downloading."
                case .noSources:
                    // Not an error: nobody who is online right now has it. Only
                    // reachable when we HAD a way to ask - the engine returns
                    // .notConnected otherwise, so this no longer blames the file
                    // for the user's connection.
                    self.notice = "No one online has \"\(hit.name)\" right now."
                case .notConnected:
                    self.notice = "Not connected yet - pick a server on the Servers tab, or wait for Kad to find contacts. padMule cannot look for this file until then."
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
    func pause() {
        engineLog.notice("lifecycle: pause (backgrounded)")
        run { $0.pause() }
    }

    /// App foregrounded: rebuild + reconnect.
    /// (shutdown() is NOT called from the lifecycle hooks: iOS gives no reliable
    /// termination hook, and pause() already checkpoints on .background. It is
    /// reachable only from the explicit Stop control - see `stop()`.)
    func resume() {
        engineLog.notice("lifecycle: resume (foregrounded)")
        run { $0.resume() }
    }

    /// The user asked to stop: disconnect, release the sockets, flush, and give
    /// the forwarded port back to the router. iOS has no app-quit an app may
    /// call, so this is the closest honest equivalent of eMule's Exit - the user
    /// still closes padMule from the app switcher, but nothing is left behind.
    ///
    /// Slower than the other actions (releasing the port means talking to the
    /// gateway), hence `stopping` for the UI to show progress rather than appear
    /// frozen. A resume() after this is a no-op while Stopped, so the stop sticks
    /// across an app switch until the user starts it again.
    func stop() {
        guard let e = engine else { return }
        engineLog.notice("lifecycle: STOP requested by the user")
        stopping = true
        work.async { [weak self] in
            e.shutdown()
            engineLog.notice("lifecycle: stopped (sockets released, port handed back)")
            DispatchQueue.main.async {
                self?.stopping = false
                self?.refresh()
            }
        }
    }

    /// Start again after an explicit stop, without relaunching the app.
    func startEngine() {
        guard let e = engine else { return }
        engineLog.notice("lifecycle: START requested by the user")
        stopping = true
        work.async { [weak self] in
            e.start()
            engineLog.notice("lifecycle: started")
            DispatchQueue.main.async {
                self?.stopping = false
                self?.refresh()
            }
        }
    }

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
    /// The downloads() call is ALSO the engine's heartbeat (share re-announce,
    /// completion finalize, server-drop detection) - the 1s timer must keep
    /// firing this even when no screen shows transfers.
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
            let mapped = e.hasPortMapping()
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
                self.portMapped = mapped
                self.sampleStats(stats)
                for ev in evs { self.apply(ev) }
                // Transfers start and finish between polls, and keep-awake is
                // gated on there being active ones, so re-evaluate it each poll.
                self.applyKeepAwake()
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
            engineLog.notice("state -> \(String(describing: s), privacy: .public)")
            state = s
        case .status(let text):
            engineLog.notice("status: \(text, privacy: .public)")
            status = text
            // The reconnect banner is a HARD lifecycle requirement.
            reconnecting = (text == "Reconnecting...")
        case .server(let text):
            // Logged before the UPnP/notice split below, so the log carries BOTH
            // kinds - the port-mapping results and the server news - in order.
            engineLog.notice("server: \(text, privacy: .public)")
            // Port-mapping results go to a DURABLE field so the connection line
            // can't overwrite them (that "an event is not state" bug again).
            if text.hasPrefix("UPnP:") {
                upnpStatus = text
            } else {
                // News ("Saved 'x'", a server MOTD), NOT the connection status.
                // Writing these to `status` would clobber the
                // "Connected to <server> (HighID|LowID)" line, which arrives as
                // its own `.status` event. NB that line is EVENT-fed, not polled:
                // the engine must emit `Status` on every connect/disconnect or
                // this row goes stale (it did - see engine.rs connect_to_server).
                notice = text
            }
        case .serverDropped(let addr):
            // The server kicked/dropped us: raise a prominent dialog and refresh
            // the server list (the connected row is no longer connected).
            engineLog.error("server DROPPED us: \(addr, privacy: .public)")
            serverKick = addr
            server = nil
            loadServers()
        case .kad(let contacts):
            // Only on CHANGE: this one can arrive on every poll, and a log that
            // repeats itself once a second is a log nobody reads.
            if contacts != kadContacts {
                engineLog.info("kad contacts: \(contacts, privacy: .public)")
            }
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

    // MARK: - Server list URLs (multi-source, eMule addresses.dat model)

    /// The user's configured list of server.met URLs. Always non-empty (the
    /// default is registered), and de-duplicated on write.
    var serverListUrls: [String] {
        UserDefaults.standard.stringArray(forKey: SettingsKey.serverListUrls)
            ?? [EngineModel.defaultServerListUrl]
    }

    func addServerListUrl(_ raw: String) {
        let url = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard url.hasPrefix("http://") || url.hasPrefix("https://") else {
            notice = "A server-list URL must start with http:// or https://"
            return
        }
        var urls = serverListUrls
        guard !urls.contains(url) else { return }
        urls.append(url)
        UserDefaults.standard.set(urls, forKey: SettingsKey.serverListUrls)
        objectWillChange.send()
    }

    func removeServerListUrl(_ url: String) {
        var urls = serverListUrls.filter { $0 != url }
        // Never leave it empty - fall back to the trusted default rather than a
        // list that can never find a server.
        if urls.isEmpty { urls = [EngineModel.defaultServerListUrl] }
        UserDefaults.standard.set(urls, forKey: SettingsKey.serverListUrls)
        objectWillChange.send()
    }

    /// Fetch and MERGE every configured list, one after another, then report the
    /// combined result. The engine merges into the on-disk server.met on each
    /// call, so this accumulates into one comprehensive set. Serial rather than
    /// concurrent: the engine holds a single lock, so parallel calls would just
    /// queue anyway, and serial keeps the running total honest.
    func updateAllServerLists() {
        guard let e = engine, !loadingServers else { return }
        let urls = serverListUrls
        loadingServers = true
        engineLog.notice("updating \(urls.count, privacy: .public) server list(s)")
        work.async { [weak self] in
            var added = 0
            var total = 0
            var failures: [String] = []
            for url in urls {
                switch e.updateServerList(url: url) {
                case let .updated(a, t):
                    added += Int(a)
                    total = Int(t)
                case .badUrl: failures.append("bad URL")
                case .notServerMet: failures.append("not a server.met")
                case .unreachable: failures.append("unreachable")
                }
            }
            DispatchQueue.main.async {
                guard let self else { return }
                self.loadingServers = false
                if failures.count == urls.count {
                    self.notice = "Could not update the server list (\(failures.first ?? "failed"))."
                } else if failures.isEmpty {
                    self.notice = "Server lists updated: +\(added) new (\(total) total)."
                } else {
                    self.notice = "Server lists updated: +\(added) new (\(total) total); \(failures.count) source(s) failed."
                }
                self.loadServers()
            }
        }
    }

    /// Persist the wire search filters, if the user asked us to remember them.
    /// iPadOS suspends and relaunches padMule constantly, so a filter set the user
    /// dialed in is otherwise lost many times a day.
    func saveSearchFilters() {
        guard UserDefaults.standard.bool(forKey: SettingsKey.rememberSearchFilters) else { return }
        let d = UserDefaults.standard
        d.set(wireCompleteOnly, forKey: SettingsKey.wireCompleteOnly)
        d.set(wireGlobal, forKey: SettingsKey.wireGlobal)
        d.set(Int(wireMinSizeMb), forKey: SettingsKey.wireMinSizeMb)
        d.set(Int(wireMaxSizeMb), forKey: SettingsKey.wireMaxSizeMb)
    }

    /// Restore the persisted wire filters at launch (guarded by the same flag).
    func restoreSearchFilters() {
        guard UserDefaults.standard.bool(forKey: SettingsKey.rememberSearchFilters) else { return }
        let d = UserDefaults.standard
        wireCompleteOnly = d.bool(forKey: SettingsKey.wireCompleteOnly)
        wireGlobal = d.bool(forKey: SettingsKey.wireGlobal)
        wireMinSizeMb = UInt64(max(0, d.integer(forKey: SettingsKey.wireMinSizeMb)))
        wireMaxSizeMb = UInt64(max(0, d.integer(forKey: SettingsKey.wireMaxSizeMb)))
    }

    /// Apply settings that only take effect at launch: refresh the server lists if
    /// the user asked for it, and honor the keep-awake preference.
    func applyLaunchSettings() {
        restoreSearchFilters()
        if UserDefaults.standard.bool(forKey: SettingsKey.updateServerListAtLaunch) {
            updateAllServerLists()
        }
        applyKeepAwake()
    }

    /// Keep the screen from sleeping while a transfer is active, IF the user opted
    /// in. This is the honest iPadOS translation of eMule's "Prevent Standby":
    /// padMule is foreground-only, so a screen that sleeps mid-transfer suspends
    /// the app and pauses everything. Gated on there being active transfers so it
    /// does not hold the screen awake on an idle Search screen.
    func applyKeepAwake() {
        let want = UserDefaults.standard.bool(forKey: SettingsKey.keepAwakeWhileTransferring)
        let active = downloads.contains { !$0.complete }
        UIApplication.shared.isIdleTimerDisabled = want && active
    }

    /// Connect to a chosen (live) server, then refresh the list + status.
    func connectServer(_ addr: String) {
        guard let e = engine else { return }
        engineLog.notice("connecting to \(addr, privacy: .public)")
        connectingTo = addr
        work.async { [weak self] in
            // The boolean was previously DISCARDED, so a failed dial produced only
            // a lowercase blue "could not connect to ..." notice that reads like
            // information. Report it as the failure it is.
            let ok = e.connectToServer(addr: addr)
            engineLog.notice("connect to \(addr, privacy: .public): \(ok ? "OK" : "FAILED", privacy: .public)")
            DispatchQueue.main.async {
                guard let self else { return }
                self.connectingTo = nil
                if !ok {
                    self.notice = "Could not connect to \(addr). It may be down, or your network may be blocking it - try another server."
                }
                self.refresh()
                self.loadServers()
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

    /// The canonical public server-list URL (plain http; the engine fetches over a
    /// raw socket, so no ATS exemption is needed).
    nonisolated static let defaultServerListUrl = "http://upd.emule-security.org/server.met"

    /// Fetch a server.met from `url` and merge it into the on-disk list, then
    /// re-probe. Reports the outcome via the notice banner.
    func updateServerList(_ url: String) {
        guard let e = engine, !loadingServers else { return }
        loadingServers = true
        work.async { [weak self] in
            let result = e.updateServerList(url: url)
            DispatchQueue.main.async {
                guard let self else { return }
                self.loadingServers = false
                switch result {
                case let .updated(added, total):
                    self.notice = "Server list updated: +\(added) new (\(total) total)."
                case .badUrl:
                    self.notice = "The server-list URL must start with http://"
                case .notServerMet:
                    self.notice = "That URL did not return a server.met."
                case .unreachable:
                    self.notice = "Could not reach the server-list URL."
                }
                self.loadServers()
            }
        }
    }

    /// Toggle the pin (favorite) on a server; a pinned server survives Prune. The
    /// FFI call takes the shared engine lock (block_on), so dispatch it off the UI
    /// thread like every other engine action - otherwise a pin tap during a
    /// multi-second op (Prune/Update/Connect) would freeze the main thread.
    func togglePin(_ addr: String) {
        guard let e = engine else { return }
        let pinned = servers.first(where: { $0.addr == addr })?.pinned ?? false
        work.async { [weak self] in
            e.setServerPinned(addr: addr, pinned: !pinned)
            DispatchQueue.main.async { self?.loadServers() }
        }
    }

    /// Drop every dead, unpinned server from the list, then re-probe.
    func pruneDeadServers() {
        guard let e = engine, !loadingServers else { return }
        loadingServers = true
        work.async { [weak self] in
            let removed = e.pruneDeadServers()
            DispatchQueue.main.async {
                guard let self else { return }
                self.loadingServers = false
                self.notice =
                    removed == 0 ? "No dead servers to prune." : "Pruned \(removed) dead server(s)."
                self.loadServers()
            }
        }
    }
}
