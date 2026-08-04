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

/// Which Servers-screen operation is currently running, if any. Lets each of
/// the four buttons (Refresh/Update/Prune/Discover) show its OWN spinner
/// instead of sharing one opaque `loadingServers` flag.
enum ServerOp: Equatable {
    case probing, updating, pruning, crawling
}

/// The factors a user can sort the Transfers list by. Mirrors SortKey's shape
/// (SearchPresentation.swift) but simpler - transfers have no type/bitrate/length.
enum TransferSortKey: String, CaseIterable, Identifiable {
    case name = "Name"
    case size = "Size"
    case progress = "Progress"
    case priority = "Priority"
    var id: String { rawValue }
}

/// How the Servers table is ordered - one case per column header, so tapping a
/// header sorts by it. Live servers always float above dead ones regardless:
/// a dead row cannot be connected to, so burying the usable ones under it would
/// make the sort actively unhelpful.
enum ServerSortKey: String, CaseIterable, Identifiable {
    case name = "Server"
    case users = "Users"
    case files = "Files"
    var id: String { rawValue }
}

/// How the Downloaded list is ordered. Name is the alphanumeric case: it uses
/// `localizedStandardCompare`, the Finder/Files ordering, so "file 2" sorts
/// before "file 10" instead of after it - which a plain string compare gets
/// wrong and is exactly what people mean by alphanumeric.
enum DownloadedSortKey: String, CaseIterable, Identifiable {
    case name = "Name"
    case size = "Size"
    case date = "Date"
    var id: String { rawValue }
}

/// One finished file as it actually sits in Documents (see boot()'s `docsPath`),
/// read straight from the filesystem for the Downloaded screen - NOT derived
/// from `sharedFiles`, which is the seeding library and goes silent on a file
/// the user unshared even though it is still sitting right there on disk.
struct DownloadedFile: Identifiable {
    let id: String
    let name: String
    let size: UInt64
    let url: URL
    let modified: Date
}

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
    /// Which of Refresh/Update/Prune/Discover is running, if any.
    @Published private(set) var serverOp: ServerOp?
    /// True while ANY server-screen op is running. Kept so every existing
    /// `.disabled(model.loadingServers)` call site keeps working unchanged;
    /// per-button spinners key off `serverOp` directly.
    var loadingServers: Bool { serverOp != nil }
    /// The address currently being dialled. connect_to_server blocks up to 12s, so
    /// without this the first real action a new user takes appears to do nothing.
    @Published private(set) var connectingTo: String?
    @Published var serverKick: String?
    /// Our public address (the HighID client id) changed between two logins -
    /// the engine has ALREADY paused sharing by the time this arrives, since a
    /// change usually means a VPN tunnel dropped and stock iOS has no kill
    /// switch. Settable so the alert can dismiss; the address itself never
    /// reaches the screen - see the .publicAddressChanged case in apply(_:).
    @Published var publicAddressAlert: Bool = false
    /// True while sharing is paused because of that address change. Polled as a
    /// SNAPSHOT (like `sharing`/`server`) so it survives past the one-shot
    /// alert and drives a persistent banner + the Shared-screen caption.
    @Published private(set) var sharingPausedForIpChange = false

    /// News from the engine's server side - a MOTD, a discovery result. Shown
    /// ONLY on the Servers tab: these are long, they persist, and they are not
    /// about whatever screen the user happens to be on. Distinct from `notice`,
    /// which is feedback for an action the user just took and follows them.
    @Published var serverNotice: String?

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

    // Transfers-screen sort inputs (UI-owned; applied client-side over `downloads`).
    @Published var transferSortKey: TransferSortKey = .name
    @Published var transferSortAscending = true

    /// Whether padMule has any way to find files right now - a connected server
    /// or a populated Kad table. Mirrors the engine's own `can_discover`, and is
    /// what lets the UI say "nobody to ask" instead of "no results".
    var canDiscover: Bool { server != nil || kadContacts > 0 }

    /// A pure connectivity verdict for the Status screen's "Status" row,
    /// derived entirely here rather than from the engine's free-text `status`
    /// (the Status screen now shows that separately, as "Activity", only when
    /// it differs). Collapses state/server/reconnecting/stopping/ready into
    /// one of: "Starting...", "Stopping...", "Stopped", "Paused",
    /// "Reconnecting...", "Connected", "Not connected". `stopping` is checked
    /// first because it means a Start/Stop tap is in flight and overrides
    /// whatever `state` still reads until it lands - the same distinction the
    /// Stop section below already draws between "Starting..." and
    /// "Stopping...".
    var connectionSummary: String {
        if stopping { return state == .stopped ? "Starting..." : "Stopping..." }
        if !ready { return "Starting..." }
        switch state {
        case .stopped: return "Stopped"
        case .paused: return "Paused"
        case .running:
            if reconnecting { return "Reconnecting..." }
            return server != nil ? "Connected" : "Not connected"
        }
    }

    /// The results after the current sort + filter. Recomputed on demand (cheap:
    /// a few hundred rows) so any input change reorders instantly.
    var presentedResults: [SearchHit] {
        present(results, sort: sortKey, ascending: sortAscending,
                nameFilter: nameFilter, typeFilter: typeFilter,
                trustedOnly: trustedOnly, hideHave: hideHave,
                statusFor: { self.liveStatus(for: $0) })
    }

    /// The status a search row should DISPLAY, live. `SearchHit.status` is a
    /// snapshot the engine stamps once at search time and never updates, so on
    /// its own it goes stale within a second: a completed download still shows
    /// as not-had, and a file the user just tapped "Get" on reverts to showing
    /// the Get button (allowing a double-start). `downloadingHashes` /
    /// `haveHashes` are rebuilt every refresh() poll, so this always prefers the
    /// live answer; the snapshot remains correct only for a file owned from a
    /// PREVIOUS session (already in the shared library before this search ran).
    func liveStatus(for hit: SearchHit) -> HitStatusFfi {
        if haveHashes.contains(hit.hash) { return .have }
        if downloadingHashes.contains(hit.hash) { return .downloading }
        return hit.status
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
    @Published var serverSortKey: ServerSortKey = .users
    @Published var serverSortAscending = false

    /// `servers` in the user's chosen column order, live ones first.
    var presentedServers: [ServerEntryFfi] {
        var xs = servers
        xs.sort { a, b in
            // A dead server cannot be connected to; keeping them below means the
            // sort orders what you can actually USE.
            if a.alive != b.alive { return a.alive }
            let cmp: ComparisonResult
            switch serverSortKey {
            // Alphanumeric, so "Server 10" follows "Server 2". Falls back to the
            // address when a server has published no name at all.
            case .name:
                let an = a.name.isEmpty ? a.addr : a.name
                let bn = b.name.isEmpty ? b.addr : b.name
                cmp = an.localizedStandardCompare(bn)
            case .users: cmp = a.users == b.users ? .orderedSame
                : (a.users < b.users ? .orderedAscending : .orderedDescending)
            case .files: cmp = a.files == b.files ? .orderedSame
                : (a.files < b.files ? .orderedAscending : .orderedDescending)
            }
            if cmp == .orderedSame { return a.addr < b.addr }
            return serverSortAscending
                ? cmp == .orderedAscending
                : cmp == .orderedDescending
        }
        return xs
    }

    @Published var downloadedSortKey: DownloadedSortKey = .date
    @Published var downloadedSortAscending = false

    /// `downloadedFiles` in the user's chosen order.
    var presentedDownloadedFiles: [DownloadedFile] {
        var xs = downloadedFiles
        xs.sort { a, b in
            let cmp: ComparisonResult
            switch downloadedSortKey {
            // localizedStandardCompare, NOT a plain <: it orders digit runs
            // numerically, so "part 2" precedes "part 10".
            case .name: cmp = a.name.localizedStandardCompare(b.name)
            case .size: cmp = a.size == b.size ? .orderedSame
                : (a.size < b.size ? .orderedAscending : .orderedDescending)
            case .date: cmp = a.modified == b.modified ? .orderedSame
                : (a.modified < b.modified ? .orderedAscending : .orderedDescending)
            }
            if cmp == .orderedSame { return a.name < b.name }
            return downloadedSortAscending
                ? cmp == .orderedAscending
                : cmp == .orderedDescending
        }
        return xs
    }

    /// Finished files as they sit in Documents right now (the Downloaded screen).
    /// Read straight off the filesystem by `loadDownloadedFiles()` - see that
    /// method's doc comment for why this is not derived from `sharedFiles`.
    @Published private(set) var downloadedFiles: [DownloadedFile] = []

    private var engine: MuleEngine?
    private var timer: Timer?
    private let work = DispatchQueue(label: "us.ajbconsulting.padMule.engine")
    /// A SECOND queue, for the one call that does not need the engine.
    ///
    /// `work` is SERIAL and every FFI call went through it, so a ~20s search or
    /// a ~10s crawl blocked all 27 other call sites behind it - including the
    /// event drain, which is why "Reconnecting..." could never render during
    /// one. `drainEvents()` locks only the event channel in the Rust seam, never
    /// the engine mutex, so it is safe to run CONCURRENTLY with a long
    /// engine-holding call and returns in microseconds.
    ///
    /// This does not fix the deeper half - `downloads()` and friends still block
    /// on the engine mutex while `Engine::search` holds `&mut self` across its
    /// whole join - so the numbers still freeze during a search. But the app
    /// keeps painting, banners and status text keep arriving, and it stays
    /// interactive, which is the difference between "busy" and "hung".
    private let eventQueue = DispatchQueue(label: "us.ajbconsulting.padMule.events")
    /// The background-task assertion held while pause() finishes; see pause().
    private var pauseBackgroundTask: UIBackgroundTaskIdentifier = .invalid
    /// The Documents directory `boot()` handed to the engine as `downloadsDir` -
    /// stashed here so `loadDownloadedFiles()` reads the SAME directory the
    /// engine finishes downloads into, rather than re-deriving it.
    private var docsURL: URL?

    private var booting = false

    /// Open padMule's Documents folder in the Files app.
    ///
    /// Documents is where finished, hash-verified downloads land, and it is
    /// already visible to Files because Info.plist sets `UIFileSharingEnabled`
    /// and `LSSupportsOpeningDocumentsInPlace` - so this lands the user on
    /// padMule's own folder under "On My iPad" rather than the Files root.
    ///
    /// `shareddocuments://` is the scheme Files answers on. It is not in the
    /// public SDK, which would be a problem for an App Store app and is not one
    /// here: padMule is sideload-only by necessity (a P2P client cannot ship on
    /// the App Store), the same reason the project is free to consider other
    /// review-blocked capabilities. It degrades honestly - if the open fails the
    /// user is told, rather than the button silently doing nothing.
    func openDownloadsInFiles() {
        let dir = docsURL ?? FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        var comps = URLComponents(url: dir, resolvingAgainstBaseURL: false)
        comps?.scheme = "shareddocuments"
        guard let url = comps?.url else {
            notice = "Could not locate padMule's Downloads folder."
            return
        }
        UIApplication.shared.open(url, options: [:]) { [weak self] ok in
            if !ok {
                self?.notice = "Could not open the Files app."
            }
        }
    }

    /// Retains the in-flight Open-In controller: UIKit does not, and a
    /// deallocated one dismisses its own menu instantly. Replaced per use, so at
    /// most one is ever alive.
    private var openInController: UIDocumentInteractionController?

    /// Hand a finished file to ANOTHER app, full screen - as opposed to the row
    /// tap, which previews it inside padMule via QuickLook.
    ///
    /// HONEST ABOUT WHAT iOS DOES: there is no "default app for this type" on
    /// iOS the way there is on a desktop, and `UIApplication.open` refuses a
    /// `file://` URL outright. The documented route is the Open In chooser,
    /// which lists every installed app that declares support for the file's
    /// type; the user picks, and that app takes over. So a video really does
    /// leave padMule for a video app - which BACKGROUNDS padMule and therefore
    /// pauses transfers, per the foreground-only rule.
    ///
    /// The popover needs a real anchor on iPad or UIKit has nowhere to put it.
    func openInAnotherApp(_ file: DownloadedFile) {
        guard
            let scene = UIApplication.shared.connectedScenes
                .compactMap({ $0 as? UIWindowScene })
                .first(where: { $0.activationState == .foregroundActive }),
            let root = scene.windows.first(where: { $0.isKeyWindow })?.rootViewController
                ?? scene.windows.first?.rootViewController
        else {
            notice = "Could not open \"\(file.name)\"."
            return
        }
        let controller = UIDocumentInteractionController(url: file.url)
        openInController = controller
        let view = root.view!
        let anchor = CGRect(x: view.bounds.midX, y: view.bounds.midY, width: 1, height: 1)
        if !controller.presentOpenInMenu(from: anchor, in: view, animated: true) {
            openInController = nil
            notice = "No app on this iPad can open \"\(file.name)\"."
        }
    }

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
        docsURL = docs

        let path = dir.path
        let docsPath = docs.path
        engineLog.notice("boot: config=\(path, privacy: .public)")
        work.async { [weak self] in
            do {
                let e = try MuleEngine(configDir: path, downloadsDir: docsPath)
                let ident = e.identity()
                // Ports and the UPnP toggle MUST be pushed before start(): they
                // take effect when the listener binds, and every launch builds a
                // fresh engine - so applying them afterwards (with the other
                // settings, below) would leave them inert forever rather than
                // merely one launch late. A stored 0 means "never set"; fall back
                // to the eD2k defaults rather than binding port 0.
                let d = UserDefaults.standard
                let storedPort = { (key: String, fallback: UInt16) -> UInt16 in
                    let v = UInt16(clamping: d.integer(forKey: key))
                    return v == 0 ? fallback : v
                }
                e.setPorts(
                    listen: storedPort(SettingsKey.listenPort, 5999),
                    advertised: storedPort(SettingsKey.advertisedPort, 5999),
                    kad: storedPort(SettingsKey.kadPort, 5999),
                    kadAdvertised: storedPort(SettingsKey.kadAdvertisedPort, 5999))
                e.setUpnpEnabled(on: d.bool(forKey: SettingsKey.upnpEnabled))
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

    /// `filteredDownloads`, then sorted by the current transfer sort key.
    /// Progress compares have/size fraction (guarded against size == 0, which
    /// would otherwise divide by zero for a download with no known size yet).
    var presentedDownloads: [DownloadInfo] {
        func threeWay<T: Comparable>(_ a: T, _ b: T) -> ComparisonResult {
            if a < b { return .orderedAscending }
            if b < a { return .orderedDescending }
            return .orderedSame
        }
        var xs = filteredDownloads
        xs.sort { a, b in
            let cmp: ComparisonResult
            switch transferSortKey {
            case .name: cmp = a.name.localizedCaseInsensitiveCompare(b.name)
            case .size: cmp = threeWay(a.size, b.size)
            case .progress:
                let fa = a.size == 0 ? 0 : Double(a.have) / Double(a.size)
                let fb = b.size == 0 ? 0 : Double(b.have) / Double(b.size)
                cmp = threeWay(fa, fb)
            case .priority: cmp = threeWay(a.priority, b.priority)
            }
            return transferSortAscending ? cmp == .orderedAscending : cmp == .orderedDescending
        }
        return xs
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

    // MARK: - Downloaded

    /// Enumerate Documents (the engine's `downloadsDir`, see boot()) for the
    /// Downloaded screen. Deliberately reads the FILESYSTEM rather than
    /// `sharedFiles`: `sharedFiles` is the seeding library, so a file the user
    /// unshared (still on disk) or whose bytes got pruned drops out of it - this
    /// list stays honest either way. Skips subdirectories and dotfiles, sorted
    /// most-recently-finished first. Cheap enough to run synchronously - this is
    /// one directory listing, not a recursive walk - so unlike the engine calls
    /// above it does not need the work queue.
    func loadDownloadedFiles() {
        let dir = docsURL ?? FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let keys: [URLResourceKey] = [.fileSizeKey, .contentModificationDateKey, .isDirectoryKey]
        guard let items = try? FileManager.default.contentsOfDirectory(
            at: dir, includingPropertiesForKeys: keys, options: [.skipsHiddenFiles])
        else {
            downloadedFiles = []
            return
        }
        let files: [DownloadedFile] = items.compactMap { url in
            guard let values = try? url.resourceValues(forKeys: Set(keys)), values.isDirectory != true
            else { return nil }
            return DownloadedFile(
                id: url.path,
                name: url.lastPathComponent,
                size: UInt64(values.fileSize ?? 0),
                url: url,
                modified: values.contentModificationDate ?? .distantPast)
        }
        downloadedFiles = files.sorted { $0.modified > $1.modified }
    }

    /// App backgrounded: checkpoint + release sockets. iPadOS would reclaim them
    /// anyway - doing it explicitly is what makes resume honest.
    ///
    /// pause() is dispatched onto the same SERIAL `work` queue as every other
    /// engine call, so it can land behind something slow (a 20s search) and
    /// miss iOS's ~5s background grace window entirely - losing up to 5
    /// minutes of unsaved download progress. Two mitigations: a
    /// beginBackgroundTask assertion asks iOS for real extra time to finish
    /// (ended on EVERY path - success or expiry - because leaking the
    /// assertion gets the app killed for overstaying it), and refresh()'s
    /// in-flight guard (below) keeps the 1s poll timer from stacking up ahead
    /// of this call in the same queue.
    func pause() {
        engineLog.notice("lifecycle: pause (backgrounded)")
        guard let e = engine else { return }
        pauseBackgroundTask = UIApplication.shared.beginBackgroundTask(withName: "padMule.pause") {
            [weak self] in
            DispatchQueue.main.async {
                engineLog.error("lifecycle: pause's background task EXPIRED before it finished")
                self?.endPauseBackgroundTask()
            }
        }
        work.async { [weak self] in
            e.pause()
            DispatchQueue.main.async {
                guard let self else { return }
                self.refresh()
                self.endPauseBackgroundTask()
            }
        }
    }

    /// End the background-task assertion pause() took, exactly once. Both the
    /// success path and the expiration handler call this, and either can win
    /// the race; guarding on `.invalid` (and resetting to it) is what stops
    /// the loser from double-ending the same identifier, which iOS treats as
    /// a misuse.
    private func endPauseBackgroundTask() {
        guard pauseBackgroundTask != .invalid else { return }
        UIApplication.shared.endBackgroundTask(pauseBackgroundTask)
        pauseBackgroundTask = .invalid
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
            Task { @MainActor in
                self?.pumpEvents()
                self?.refresh()
            }
        }
        RunLoop.main.add(t, forMode: .common)
        timer = t
    }

    /// Drain engine events on `eventQueue`, independent of the heavy poll.
    ///
    /// This is the ONLY caller of `drainEvents()`: the channel drains once, so
    /// two callers would race for which one saw a given event and the loser
    /// would silently drop it. It deliberately has no in-flight guard - the call
    /// is a try_recv loop over a channel and cannot pile up the way refresh()
    /// can.
    private func pumpEvents() {
        guard let e = engine else { return }
        eventQueue.async { [weak self] in
            let evs = e.drainEvents()
            guard !evs.isEmpty else { return }
            DispatchQueue.main.async {
                guard let self else { return }
                for ev in evs { self.apply(ev) }
            }
        }
    }

    /// Hashes backing `liveStatus(for:)`, rebuilt once per refresh() poll - NOT
    /// per search row - so deriving a row's displayed status stays O(1) instead
    /// of rescanning `downloads` / `sharedFiles` on every render.
    private var downloadingHashes: Set<String> = []
    private var haveHashes: Set<String> = []
    /// True while a refresh() poll is in flight; see refresh()'s doc comment.
    private var refreshInFlight = false

    /// Pull a fresh snapshot off the main thread. Events are NOT drained here
    /// any more - `pumpEvents()` owns that, on its own queue, so a banner or a
    /// status change still arrives while a long engine call is holding `work`.
    /// The downloads() call is ALSO the engine's heartbeat (share re-announce,
    /// completion finalize, server-drop detection) - the 1s timer must keep
    /// firing this even when no screen shows transfers.
    ///
    /// Guarded by `refreshInFlight` so a slow call ahead of this one on the
    /// serial `work` queue (e.g. a 20s search) cannot let the 1s timer stack
    /// dozens of queued jobs in front of something urgent like pause(). The
    /// heartbeat still fires every ~1s once the in-flight one clears; this
    /// only caps concurrency at one.
    private func refresh() {
        guard let e = engine, !refreshInFlight else { return }
        refreshInFlight = true
        work.async { [weak self] in
            let st = e.state()
            let dls = e.downloads()
            let shf = e.sharedFiles()
            let kad = e.kadContacts()
            let ipf = e.ipFilterRanges()
            let srv = e.serverInfo()
            let shr = e.isSharing()
            let ipPause = e.sharingPausedForIpChange()
            let stats = e.transferStats()
            let mapped = e.hasPortMapping()
            DispatchQueue.main.async {
                guard let self else { return }
                self.refreshInFlight = false
                self.state = st
                self.downloads = dls
                self.sharedFiles = shf
                // A completed-but-still-listed download counts as HAVE (not
                // downloading); anything shared counts as HAVE too.
                self.downloadingHashes = Set(dls.filter { !$0.complete }.map { $0.hash })
                self.haveHashes =
                    Set(dls.filter { $0.complete }.map { $0.hash }).union(shf.map { $0.hash })
                self.kadContacts = kad
                self.ipFilterRanges = ipf
                self.server = srv
                self.sharing = shr
                self.sharingPausedForIpChange = ipPause
                self.portMapped = mapped
                self.sampleStats(stats)
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
                // News from the SERVER side (a MOTD, "Discovered N servers",
                // "Saved 'x'") goes to its own field, shown only on the Servers
                // tab. A server MOTD is often a dozen lines and it PERSISTS -
                // parked at the top of every screen it pushed the actual content
                // down and had nothing to do with what the user was looking at.
                // Action feedback the user just triggered still uses `notice`
                // and stays global, because that must appear where they are.
                //
                // NOT `status`: that would clobber the "Connected to <server>"
                // line, which arrives as its own `.status` event (event-fed, not
                // polled - see engine.rs connect_to_server).
                serverNotice = text
            }
        case .serverDropped(let addr):
            // The server kicked/dropped us: raise a prominent dialog and refresh
            // the server list (the connected row is no longer connected).
            engineLog.error("server DROPPED us: \(addr, privacy: .public)")
            serverKick = addr
            server = nil
            loadServers()
        case .publicAddressChanged:
            // Our public address (the HighID client id) IS our route out. A
            // change usually means a VPN tunnel dropped, or the device jumped
            // networks - either way our traffic would otherwise keep leaving
            // by a route the user did not choose, with nothing on screen to
            // say so. Error-level: this is a privacy event, not routine
            // status. The engine has ALREADY paused sharing by the time this
            // arrives; the address itself must never appear here or on screen.
            engineLog.error("public address changed - sharing paused by the engine")
            publicAddressAlert = true
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
        serverOp = .probing
        work.async { [weak self] in
            let list = e.serverList()
            DispatchQueue.main.async {
                self?.servers = list
                self?.serverOp = nil
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
        serverOp = .updating
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
                self.serverOp = nil
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
        applyAskServersForServers()
        applyPortSettings()
        applyKeepAwake()
    }

    /// Push the "ask a fresh login for its server list" pref into the engine.
    /// The engine defaults it ON, so this only matters when the user turned it
    /// off - but re-applying unconditionally keeps engine and pref in step.
    func applyAskServersForServers() {
        guard let e = engine else { return }
        let on = UserDefaults.standard.bool(forKey: SettingsKey.askServersForServers)
        work.async { e.setAddServersFromServer(on: on) }
    }

    /// Push the listen/advertised/kad ports and the UPnP toggle into the engine.
    ///
    /// These take effect on the NEXT start() - changing them mid-session does
    /// NOT move a live listener. The split between "listen" and "advertised"
    /// exists for VPN use (AirVPN and similar): the provider forwards an
    /// assigned remote port into the tunnel, and may forward it to a LOCAL port
    /// different from the remote one, so peers must be told the external port
    /// while padMule actually listens on the local one. UPnP on the LAN router
    /// is meaningless in that setup - the tunnel bypasses it - so it can be
    /// turned off rather than fail with a misleading line.
    func applyPortSettings() {
        guard let e = engine else { return }
        let d = UserDefaults.standard
        let listen = UInt16(clamping: d.integer(forKey: SettingsKey.listenPort))
        let advertised = UInt16(clamping: d.integer(forKey: SettingsKey.advertisedPort))
        let kad = UInt16(clamping: d.integer(forKey: SettingsKey.kadPort))
        // Falls back to the BOUND port, not to 5999: same-port is the ordinary
        // case, and a stored 0 here must not silently advertise a wrong number.
        let kadAdvRaw = UInt16(clamping: d.integer(forKey: SettingsKey.kadAdvertisedPort))
        let kadAdvertised = kadAdvRaw == 0 ? kad : kadAdvRaw
        let upnp = d.bool(forKey: SettingsKey.upnpEnabled)
        work.async {
            e.setPorts(
                listen: listen, advertised: advertised, kad: kad,
                kadAdvertised: kadAdvertised)
            e.setUpnpEnabled(on: upnp)
        }
    }

    /// Keep the screen from sleeping while a transfer is active, IF the user opted
    /// in. This is the honest iPadOS translation of eMule's "Prevent Standby":
    /// padMule is foreground-only, so a screen that sleeps mid-transfer suspends
    /// the app and pauses everything. Gated on ACTUAL recent throughput, not
    /// merely a registered incomplete download - a download with zero sources
    /// sits at 0 bytes/sec forever, and holding the screen on for a transfer
    /// going nowhere is exactly what "while something is actually transferring"
    /// promises not to do. `rateHistory`'s most recent point (folded by
    /// sampleStats() on roughly every poll) is a faithful "is data moving right
    /// now" signal, and covers uploads too, not just downloads.
    func applyKeepAwake() {
        let want = UserDefaults.standard.bool(forKey: SettingsKey.keepAwakeWhileTransferring)
        // Look at the last few SAMPLES, not just the most recent one. A transfer
        // legitimately goes quiet for a second between block batches (padMule is
        // stop-and-wait per batch), and gating on a single zero sample would let
        // the display sleep mid-transfer - which suspends the app and stops the
        // very transfer this setting exists to protect. Still activity-based, so
        // a genuinely stalled download stops holding the screen within seconds.
        let moving = rateHistory.suffix(keepAwakeWindow).contains { $0.down + $0.up > 0 }
        UIApplication.shared.isIdleTimerDisabled = want && moving
    }

    /// How many 1s rate samples back `applyKeepAwake` looks for activity.
    private var keepAwakeWindow: Int { 5 }

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
        serverOp = .updating
        work.async { [weak self] in
            let result = e.updateServerList(url: url)
            DispatchQueue.main.async {
                guard let self else { return }
                self.serverOp = nil
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
        serverOp = .pruning
        work.async { [weak self] in
            let removed = e.pruneDeadServers()
            DispatchQueue.main.async {
                guard let self else { return }
                self.serverOp = nil
                self.notice =
                    removed == 0 ? "No dead servers to prune." : "Pruned \(removed) dead server(s)."
                self.loadServers()
            }
        }
    }

    /// Ask known servers for the OTHER servers they know (2 rounds - the engine
    /// clamps at 3), merging the safe survivors into server.met, then re-probe.
    /// Most servers stay silent to this request, so a 0 result is normal.
    func crawlServers() {
        guard let e = engine, !loadingServers else { return }
        serverOp = .crawling
        engineLog.notice("crawling for more servers")
        work.async { [weak self] in
            let added = e.crawlServers(rounds: 2)
            engineLog.notice("crawl added \(added, privacy: .public) new server(s)")
            DispatchQueue.main.async {
                guard let self else { return }
                self.serverOp = nil
                self.notice =
                    added == 0
                    ? "No new servers found - most servers do not answer list requests."
                    : "Discovered \(added) new server(s)."
                self.loadServers()
            }
        }
    }
}
