// The SwiftUI-facing wrapper around the Rust engine's FFI facade (MuleEngine,
// from crates/mule-ffi via uniffi). Every MuleEngine call is synchronous and
// blocks (the facade drives the async engine on its own tokio runtime), so all
// of them run on a background queue and only results hop back to the main actor.
//
// Events are POLLED via drainEvents() - the MVP shape of the seam; a uniffi
// callback interface is the later upgrade. See docs/wiki/padmule-enhancement-channel.md
// ... and docs/wiki/lifecycle-and-reactivation.md for why pause/resume is honest.

import AudioToolbox  // AudioServicesPlaySystemSound - the download-finished beep
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
/// Single source for the app's os_log identities (engine + keepalive).
/// `LoggingTests` pins these strings to the runbook; construct any app-side
/// Logger from them, never from a fresh literal, or the test cannot see the
/// rename it exists to catch.
enum EngineLogIdentity {
    static let subsystem = "us.ajbconsulting.padMule"
    static let category = "padMule.engine"
    /// The background keepalive's category (`BackgroundKeepAlive`), same
    /// subsystem - filter with `idevicesyslog -p padMule -m padMule.keepalive`.
    static let keepaliveCategory = "padMule.keepalive"
}

let engineLog = Logger(subsystem: EngineLogIdentity.subsystem, category: EngineLogIdentity.category)

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
    /// A warm boot is ~1s. The old "boot is 12-30s" claim here was the SUM of the
    /// worst-case timeouts (two HTTP fetches, the always-failing multicast SSDP
    /// probe, unicast + SOAP, then Kad), not a measurement - only a cold or
    /// blocked network actually runs them all out.
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
    /// How many times the LOCK-FREE status poll has published, and how many
    /// times the LOCK-TAKING heartbeat has completed.
    ///
    /// A PAIR, deliberately, so the instrument carries its own control: during a
    /// long engine operation (a search holds the lock up to 20s) the first must
    /// keep climbing at ~1/s while the second stalls. One counter alone would
    /// only say "something ticked"; the two together say WHICH path is free and
    /// which is blocked, in the same reading. Built 2026-08-07 to close Track 1,
    /// because every probe available from outside the app needs the engine lock
    /// itself and so cannot observe this.
    ///
    /// WHILE BACKGROUNDED, `heartbeatTicks` is a FROZEN MIRROR of the private
    /// `heartbeatCount` and is flushed current by `leaveBackground()`. The
    /// heartbeat itself never stops - only the publish does. Publishing this
    /// counter once a second was what re-rendered the whole hidden view
    /// hierarchy through the 2026-08-09 72-minute seeding soak (build
    /// d5fadb8): ~55 CoreFoundation localization lines plus one denied
    /// UIAccessibility post attempt (57 syslog lines) EVERY second, at
    /// exactly this counter's cadence, with a second render on each 5th
    /// tick - refreshFast's batch.
    /// See `coalescedCounterPublish` for the rule.
    @Published private(set) var uiPollTicks: UInt64 = 0
    @Published private(set) var heartbeatTicks: UInt64 = 0
    /// The TRUE heartbeat-completion count, kept even while the published
    /// mirror above is frozen - a diagnostic that loses ticks while
    /// backgrounded would misreport the very episode it exists to describe.
    private var heartbeatCount: UInt64 = 0
    /// THE LONGEST GAP between two consecutive status-poll publishes, in seconds.
    ///
    /// THE COUNTS ALONE CANNOT ANSWER THE QUESTION THEY WERE BUILT FOR, which the
    /// 2026-08-07 reanalysis found the hard way. `eventQueue` is SERIAL, so a poll
    /// that blocks does not skip its ticks - the timer keeps queueing work items
    /// and they all run the moment the block clears. Over any window that outlasts
    /// the stall, "stalled 10s then burst" and "never stalled" produce the SAME
    /// total, and the device reading taken from those totals ("0.94/s - keeps
    /// running") cannot tell them apart.
    ///
    /// A maximum gap can. It is the one statistic a burst cannot hide: whatever
    /// else happens, the interval that spans the stall is recorded. Idle it sits
    /// near the 1s poll period; if anything on this queue ever takes the engine
    /// lock again it jumps to the length of the longest operation, and the number
    /// on screen names the fault instead of hinting at it.
    ///
    /// SCOPE: it measures gaps between SCHEDULED FOREGROUND polls only.
    /// Suspensions and throttled ticks are excluded BY DESIGN, because this
    /// number exists to name engine-lock contention - a stall on our own
    /// queue - not an absence the OS imposed. Two exclusions:
    /// - a seeding-throttle skip (`shouldRunFastPoll` skips 4 ticks in 5)
    ///   clears the `lastUiPollAt` baseline so the next measured gap starts
    ///   fresh; without that, one seeding episode parked this max at ~5s
    ///   forever - the throttle's number, not a fault's - and poisoned the
    ///   1.1s device-pass regression bar.
    /// - a background episode: `sceneInBackground` goes up in
    ///   `enterBackground()` and down in `leaveBackground()`, and the pure
    ///   booking rule (`bookPollGap`) discards every interval while it is up,
    ///   nilling the baseline as it does. The flag is armed on the way OUT,
    ///   BEFORE the freeze - the load-bearing detail. The first attempt
    ///   cleared the baseline on the way back IN instead, and on glass
    ///   (2026-08-09, build 4bf04b1) it failed on 2 of 2 suspensions (booked
    ///   10.0s of a ~10.6s suspension, 84.8s of 85.7s): work queued before
    ///   the freeze drains on thaw BEFORE scenePhase delivers .active, so a
    ///   way-in clear runs after the damage, every time. Only a way-out
    ///   signal can precede every post-thaw booking.
    @Published private(set) var uiPollMaxGapSecs: Double = 0
    private var lastUiPollAt: Date?
    /// True between the scenePhase .background and .active transitions - set
    /// first thing in `enterBackground()`, cleared in `leaveBackground()`.
    /// Read by `bookPollGap` to discard poll-gap intervals that overlap a
    /// background episode; see the `uiPollMaxGapSecs` SCOPE doc for why the
    /// signal must be armed on the way out. Main-thread only, like the rest
    /// of the poll-gap state.
    private var sceneInBackground = false
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
    /// Samples kept, and therefore the chart's fixed X span: 60 SAMPLES -
    /// about 60 seconds in the foreground. While BACKGROUNDED no samples fold
    /// at all (the snapshot is gated off - see `shouldPublishUi`; before
    /// 2026-08-09 it merely ran throttled to ~5s). The sampling baseline
    /// survives the episode, so the first foreground sample after a
    /// background stretch is one point carrying the episode's true AVERAGE
    /// rate, and the window's remaining points still read in ~1s steps.
    static let rateWindow = 60
    private let rateHistoryCap = EngineModel.rateWindow

    /// `rateHistory` padded to exactly `rateWindow` points and re-indexed 0...59,
    /// newest at the RIGHT.
    ///
    /// The chart used to plot the raw samples against their absolute sample
    /// index, so its X domain was whatever range happened to be in the buffer.
    /// Early on that is a handful of points, and Swift Charts scaled the domain
    /// to fit them - so the live trace was squeezed into a sliver instead of
    /// using the width it had. Padding on the LEFT with zeros fixes the span at
    /// the full window and makes the newest sample always land on the right edge,
    /// so the trace scrolls leftwards the way a live rate graph should.
    var ratePlot: [RatePoint] {
        let recent = rateHistory.suffix(EngineModel.rateWindow)
        let pad = EngineModel.rateWindow - recent.count
        var out: [RatePoint] = []
        out.reserveCapacity(EngineModel.rateWindow)
        for i in 0..<pad {
            out.append(RatePoint(id: i, down: 0, up: 0))
        }
        for (i, p) in recent.enumerated() {
            out.append(RatePoint(id: pad + i, down: p.down, up: p.up))
        }
        return out
    }
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
        case .seeding: return "Sharing in the background"
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
    /// The download the started-download feedback banner points at. Only this
    /// POINTER is durable; the banner TEXT is derived from the row's live
    /// state on every render (`downloadBannerText`), so the banner cannot
    /// outlive its truth - pausing, queueing, finishing, cancelling, or
    /// stopping the engine takes the claim down with it. The old shape (a
    /// captured "Downloading ..." string in `notice`) kept asserting the
    /// download was running after it was paused - seen on glass 2026-08-09,
    /// the an-event-is-not-state bug family. nil = dismissed or never shown;
    /// not `private(set)` so the banner's dismiss button can clear it.
    @Published var downloadNoticeHash: String?
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
    /// Whether a VPN tunnel appears to be up. Drives the VPN badge in the top
    /// left. A heuristic - see `NetworkWatcher.vpnIsUp` for what it does and
    /// does not prove.
    @Published private(set) var vpnActive: Bool = false
    /// Set when a VPN that WAS up disappears; the UI raises an alert and clears
    /// it. Not `private(set)` so the alert binding can reset it on dismiss.
    @Published var vpnWentDown: Bool = false
    /// Whether a VPN has been seen up at all this launch. Without it, every
    /// user who has never used a VPN would be told theirs had dropped.
    private var sawVpn = false
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

    /// Should a Servers-list row wear the connected treatment RIGHT NOW?
    ///
    /// Keyed on the LIVE login, never on `ServerEntryFfi.connected`: the
    /// engine stamps that flag when the list is PROBED (probe_server_list
    /// reads its login once, at probe time), so it is a memory of the last
    /// probe, not a fact about now - and Stop/Start never re-probe. On glass
    /// (2026-08-09, build 0c846d1): after toolbar Stop -> Start the list kept
    /// the previous server's green name + checkmark while the Status screen
    /// honestly read "Not connected" - one fact in two voices, the drift
    /// class `serverLabel` exists to prevent. `server` is polled every second
    /// (refreshFast -> serverInfo, which the engine gates on being online),
    /// so this answer and the Status screen's come from the SAME measurement
    /// and cannot disagree. Both addr strings are `SocketAddr` renderings of
    /// "ip:port", so equality is a real identity match.
    ///
    /// `.running` is required too - but NOT for the reason first written
    /// here. The old doc claimed `.stopped`/`.paused` have no login to claim
    /// because the engine returns no `serverInfo` then; glass falsified that
    /// (2026-08-09, build 4bf04b1): `Engine::connect_to_server` guards only
    /// `offline`, never state, so a row tap while stopped logged in and left
    /// state stopped WITH serverInfo present - this rule then rendered the
    /// row unstyled while the app was genuinely logged in, the mirror image
    /// of the stale styling above (`serverInfo` is gated on the live server
    /// LINK, `is_online`, not on state). The pairing is now guaranteed BY
    /// CONSTRUCTION on the app side instead: `connectServer` - the only path
    /// to `connect_to_server` - runs `start()` before every dial in the same
    /// serial work item (see `serverTapAction`), so no app path can hand a
    /// stopped engine a login, and "stopped implies no live login" is
    /// enforced rather than assumed. The state check still covers the ~1s
    /// poll lag while a shutdown lands, and `.seeding` only exists while
    /// backgrounded, with no Servers screen on glass. Pure and static so the
    /// rule is testable without an engine - the `TransferRowState` seam
    /// pattern (see SettingsTests).
    static func serverRowConnected(
        rowAddr: String, state: EngineStateFfi, liveServerAddr: String?
    ) -> Bool {
        state == .running && liveServerAddr == rowAddr
    }

    /// What a Servers-row tap should DO - the pure decision, engine-free and
    /// static like `serverRowConnected` above (tested from
    /// ServerTapActionTests).
    enum ServerTapAction: Equatable {
        /// The engine is up: dial this row.
        case connect
        /// The engine is not running: bring it up FIRST - listener bound,
        /// port mapped - then dial, atomically (see `connectServer`).
        ///
        /// Why start rather than refuse: a tap on a server is an unambiguous
        /// "connect me". eMule 0.70b connects unconditionally on a server-row
        /// double-click (ServerListCtrl.cpp OnNmDblClk ->
        /// ConnectToServer) and can afford to, because its listen socket is
        /// bound at app startup (EmuleDlg.cpp:717) and lives for the whole
        /// process - "connect implies the listener is up" is an invariant it
        /// keeps structurally, to the point of restarting the listener
        /// rather than proceeding without it ("if you don't, you will get a
        /// low ID on all servers", ListenSocket.cpp:2073). padMule's Stop is
        /// an iOS-ism with no 0.70b counterpart (the closest is Exit, after
        /// which there is no list to click), so the faithful translation is
        /// to restore eMule's invariant before honoring the tap - not to
        /// refuse it; this codebase already treats an inert control as its
        /// own defect.
        case startThenConnect
        /// This row already holds the live login - nothing to do.
        case ignore
    }

    /// The rule: the already-connected row (per `serverRowConnected` - the
    /// SAME live measurement the row styles by, composed rather than copied,
    /// so the two cannot drift) is ignored; a running or seeding engine
    /// dials directly (seeding HOLDS the listener and login - that is its
    /// point - though the Servers screen is never on glass while
    /// backgrounded); a stopped or paused engine starts first, because both
    /// have released the listener and a login without one is a guaranteed
    /// LowID. Note where the on-glass split-brain input lands (state
    /// stopped, liveServerAddr PRESENT, tap on that very row):
    /// startThenConnect, not ignore - the tap REPAIRS the incoherence with a
    /// proper start + fresh login instead of being swallowed.
    static func serverTapAction(
        rowAddr: String, state: EngineStateFfi, liveServerAddr: String?
    ) -> ServerTapAction {
        if serverRowConnected(rowAddr: rowAddr, state: state, liveServerAddr: liveServerAddr) {
            return .ignore
        }
        switch state {
        case .running, .seeding: return .connect
        case .stopped, .paused: return .startThenConnect
        }
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
    /// Holds the app awake in the background so it can keep SERVING. Only ever
    /// started when the user has turned background seeding on AND sharing is
    /// actually enabled - see `enterBackground()`.
    private let keepAlive = BackgroundKeepAlive()

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
    /// most one is ever alive. KNOWN AND ACCEPTED: after a successful hand-off
    /// the last controller stays retained until the next use replaces it -
    /// there is no reliable completion hook to clear it on, and one idle
    /// controller costs nothing.
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
                // The engine RESTORES the ip-change pause from disk in its
                // constructor (the guard fired in a PREVIOUS launch and the
                // user has not resumed sharing). Captured here, before any
                // poll exists, so the main-thread seed below cannot miss it.
                // Both reads are lock-free.
                let ipPaused = e.sharingPausedForIpChange()
                let sharingNow = e.isSharing()
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
                e.setMaxActiveDownloads(
                    n: UInt32(clamping: d.integer(forKey: SettingsKey.maxActiveDownloads)))
                // BEFORE start(), for the same reason the ports are: the
                // inbound listener builds its HELLO once, when it binds, so a
                // nickname pushed afterwards would not reach a peer that dials
                // us until the next Stop -> Start.
                e.setNickname(
                    nick: EngineModel.nicknameToPush(
                        stored: d.string(forKey: SettingsKey.nickname)))
                e.start()
                engineLog.notice("boot OK; engine started")
                DispatchQueue.main.async {
                    guard let self else { return }
                    self.booting = false
                    self.engine = e
                    self.ready = true
                    self.identity = ident
                    // Seed the pause mirror BEFORE the first preference push
                    // and the first poll tick: after a relaunch with the
                    // restored pause, the banner and the Shared-screen caption
                    // must say WHY from the first frame, not a second later -
                    // and the sharing switch must not read ON in the meantime.
                    self.sharingPausedForIpChange = ipPaused
                    self.sharing = sharingNow
                    // Re-apply persisted settings the moment the engine exists.
                    // Without this the engine keeps its own defaults and the
                    // user's choices look like they were ignored.
                    self.applyEffectiveSharing()
                    self.applyLaunchSettings()
                    self.startPolling()
                    self.refreshFast()
                    self.refresh()
                    // Load + probe the server list ON APP OPEN (Anthony,
                    // 2026-08-04), not when the Servers tab first appears.
                    // start() has just fetched server.met if it was missing or
                    // unusable, and the probe takes a few seconds - doing it
                    // here means the list is READY when the user arrives at the
                    // tab, instead of them watching it fill (or, if they got
                    // there first, seeing "No server list on disk" because the
                    // tab's onAppear fired while start() still held the lock).
                    self.loadServers()
                    // ...and AGAIN a few seconds later (Anthony, 2026-08-05).
                    // The first probe runs while boot is still busy - two HTTP
                    // fetches, UPnP SOAP, Kad bootstrap - and it is UDP, so on a
                    // cold, contended start most answers are simply lost. Worse,
                    // the probe's memory is per-launch, so nothing vouches for
                    // any server on that first round and they all read as
                    // unknown at once. A single cheap re-probe once the boot
                    // rush has passed is what turns that into the correct list
                    // WITHOUT the user having to find the Refresh button, which
                    // is what Anthony had to do.
                    //
                    // Not a fixed "breather" before the FIRST probe: showing the
                    // list promptly matters too, and a second look costs one UDP
                    // fan-out. Do both - early AND correct.
                    self.work.asyncAfter(deadline: .now() + 6) { [weak self] in
                        self?.loadServers()
                    }
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
        // USER-INITIATED: this is the one path where the person actually decided
        // about sharing, so it is the one allowed to end a public-address pause.
        applyEffectiveSharing(userInitiated: true)
    }

    /// The sharing decision as a PURE rule: the value to push into the engine,
    /// or `nil` to push nothing at all.
    ///
    /// Pure and static so the real rule is testable without an engine - it used
    /// to be inline in `applyEffectiveSharing`, which forced the test to
    /// re-implement it, and a test that restates a rule cannot catch the CALLER
    /// getting it wrong. That is exactly what happened: see the `nil` case.
    ///
    /// THE `nil` CASE IS A SAFETY RULE, not an optimisation. `Engine::set_sharing(true)`
    /// CLEARS `sharing_paused_for_ip_change` - deliberately, because "the user
    /// has decided" should end the pause. But this function is also reached from
    /// events the user did not initiate: the metered-state change
    /// (`setMetered`), the Settings "pause on cellular" toggle, and boot. Left
    /// unguarded, flipping an unrelated switch - or simply walking onto cellular
    /// and back - RESUMED SEEDING FROM A CHANGED PUBLIC ADDRESS and cleared the
    /// banner explaining why it had stopped. On iOS there is no kill switch, so
    /// that guard is the whole protection. Turning sharing OFF is always safe
    /// and is never suppressed; only the ON direction is gated.
    static func sharingDecision(
        wanted: Bool,
        pauseOnMetered: Bool,
        metered: Bool,
        pausedForIpChange: Bool,
        userInitiated: Bool
    ) -> Bool? {
        let effective = wanted && !(pauseOnMetered && metered)
        if effective && pausedForIpChange && !userInitiated { return nil }
        return effective
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
    func applyEffectiveSharing(userInitiated: Bool = false) {
        guard let e = engine else { return }
        let wanted = UserDefaults.standard.bool(forKey: SettingsKey.shareUploads)
        let pauseOnMetered = UserDefaults.standard.bool(forKey: SettingsKey.pauseSharingOnCellular)
        guard
            let effective = Self.sharingDecision(
                wanted: wanted,
                pauseOnMetered: pauseOnMetered,
                metered: meteredNow,
                // From the ENGINE (a lock-free atomic read), not from the
                // published mirror: the mirror is poll-fed, so it runs a tick
                // stale in the steady state and a whole LAUNCH stale at boot -
                // and the engine now RESTORES this pause from disk, so a boot
                // push that misses it would set_sharing(true) and clear the
                // very pause the launch was supposed to honour.
                pausedForIpChange: e.sharingPausedForIpChange(),
                userInitiated: userInitiated
            )
        else {
            engineLog.notice(
                "sharing stays paused - the public address changed and the user has not resumed it"
            )
            return
        }
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

    /// Latest VPN verdict from the NetworkWatcher, fed in the same way as the
    /// metered one so the watcher stays the single owner of path facts.
    ///
    /// The DROP is a transition, not a state: a user who has never used a VPN
    /// must not be warned that theirs went down. `sawVpn` is what makes the
    /// difference, and it is deliberately not reset when the tunnel comes back -
    /// once padMule has seen a VPN on this launch, a later disappearance is
    /// always worth saying out loud.
    func setVpnActive(_ active: Bool) {
        guard vpnActive != active else { return }
        vpnActive = active
        if active { sawVpn = true }
        if EngineModel.vpnDropWarrants(active: active, sawVpnBefore: sawVpn) {
            vpnWentDown = true
            engineLog.error("VPN tunnel DROPPED while padMule was running")
        }
    }

    /// Should a VPN state change raise the drop warning? The rule alone, so the
    /// case that matters can be tested: a user who has NEVER had a VPN up must
    /// never be told theirs went down, and that is the difference between a
    /// useful warning and one everybody learns to dismiss.
    static func vpnDropWarrants(active: Bool, sawVpnBefore: Bool) -> Bool {
        !active && sawVpnBefore
    }

    /// The live-state text for the started-download feedback banner, or nil
    /// when no banner should show. PURE so the honesty rule is testable
    /// without an engine.
    ///
    /// The rule: the banner says "Downloading" only while the row it names
    /// would carry NO badge - judged by the same `TransferRowState.badge`
    /// precedence the Transfers row renders, so the banner and the row cannot
    /// tell different stories. A paused or finished row shows nothing (the
    /// row's own badge already says so), and a missing row (cancelled) shows
    /// nothing. A queued row gets its own honest line rather than silence,
    /// because with the max-active cap full a fresh Get lands queued AT BIRTH
    /// and the user still deserves feedback for the tap.
    static func downloadBannerText(
        hash: String?, downloads: [DownloadInfo], engineStopped: Bool
    ) -> String? {
        guard let hash, let row = downloads.first(where: { $0.hash == hash }) else {
            return nil
        }
        let badge = TransferRowState.badge(
            complete: row.complete, engineStopped: engineStopped,
            filePaused: row.paused, queued: row.queued)
        switch badge {
        case nil:
            return "Downloading \"\(row.name)\"."
        case .queued?:
            return "\"\(row.name)\" is queued - it starts when a download slot frees."
        case .paused?, .done?:
            return nil
        }
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
                    // POINT the banner at the row; the text is derived live
                    // (`downloadBannerText`), never captured as a string here.
                    self.downloadNoticeHash = hit.hash
                case .alreadyAdded:
                    // A positional fact, not an activity claim: the old "is
                    // already downloading" was false at birth for a row sitting
                    // paused or queued, and stayed on screen either way.
                    self.notice = "\"\(hit.name)\" is already in your downloads."
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
                self.refreshAll()
            }
        }
    }

    /// Cancel and remove an in-progress download, deleting its part files. The
    /// engine owns the truth; refresh() pulls the updated list right after.
    func cancel(_ hash: String) {
        guard let e = engine else { return }
        work.async { [weak self] in
            _ = e.cancelDownload(hash: hash)
            DispatchQueue.main.async { self?.refreshAll() }
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
            // Deterministic tiebreak on equal keys, always ascending - the
            // same idiom as presentedServers/presentedDownloadedFiles. Swift's
            // sort does not promise stability, so without this equal-key rows
            // could reorder between renders.
            if cmp == .orderedSame {
                let byName = a.name.localizedCaseInsensitiveCompare(b.name)
                if byName != .orderedSame { return byName == .orderedAscending }
                return a.hash < b.hash
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
            DispatchQueue.main.async { self?.refreshAll() }
        }
    }

    /// Set the local user's own rating (0-5, 0 = none) and comment on a shared
    /// file. Persisted and served to downloaders via OP_FILEDESC. refresh() pulls
    /// the updated library right after.
    func setFileRating(_ hash: String, rating: UInt8, comment: String) {
        guard let e = engine else { return }
        work.async { [weak self] in
            _ = e.setFileRating(hash: hash, rating: rating, comment: comment)
            DispatchQueue.main.async { self?.refreshAll() }
        }
    }

    /// Set a download's priority: 0 = Low, 1 = Normal, 2 = High. Persisted to
    /// part.met and honored by the running fetch. refresh() pulls the update.
    func setPriority(_ hash: String, priority: UInt8) {
        guard let e = engine else { return }
        work.async { [weak self] in
            _ = e.setDownloadPriority(hash: hash, priority: priority)
            DispatchQueue.main.async { self?.refreshAll() }
        }
    }

    /// Per-file pause (eMule 0.70b PauseFile): the engine stops that
    /// download's workers within a block and persists the flag via part.met
    /// FT_STATUS, so a paused row survives a restart.
    func pauseDownload(_ hash: String) {
        guard let e = engine else { return }
        work.async { [weak self] in
            _ = e.pauseDownload(hash: hash)
            DispatchQueue.main.async { self?.refreshAll() }
        }
    }

    /// Per-file resume (0.70b ResumeFile). The engine's retry sweep re-drives
    /// it within a few seconds, subject to the max-active admission.
    func resumeDownload(_ hash: String) {
        guard let e = engine else { return }
        work.async { [weak self] in
            _ = e.resumeDownload(hash: hash)
            DispatchQueue.main.async { self?.refreshAll() }
        }
    }

    /// Push the max-active cap (0 = unlimited) from UserDefaults into the
    /// engine. Called at boot and whenever the Settings stepper changes.
    func pushMaxActiveDownloads() {
        guard let e = engine else { return }
        let n = UInt32(
            clamping: UserDefaults.standard.integer(forKey: SettingsKey.maxActiveDownloads))
        work.async { e.setMaxActiveDownloads(n: n) }
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
    /// THE BACKGROUND DECISION, in one place.
    ///
    /// Either padMule keeps serving with an audio keepalive holding it awake, or
    /// it pauses honestly. What it must never do is claim the first while
    /// actually getting the second - iOS suspends an app without a keepalive
    /// within about thirty seconds and takes its sockets, so a "seeding" badge
    /// over a suspended process would be exactly the dishonest status
    /// docs/wiki/lifecycle-and-reactivation.md calls a hard requirement to avoid.
    ///
    /// So the keepalive is started FIRST and its result decides the path. Three
    /// conditions must all hold to seed: the user asked for it, sharing is
    /// actually on (seeding with uploads off would burn battery to serve
    /// nothing), and the keepalive actually started.
    func enterBackground() {
        // ARM THE POLL-GAP EXCLUSION FIRST, before anything below can queue
        // work. This is the way-OUT half of the background episode (see
        // `sceneInBackground`), and it must precede pause(): pause()'s
        // completion runs refreshAll(), whose booking would otherwise re-arm
        // the gap baseline INSIDE the background grace window. On glass the
        // 85.7s suspension booked 84.8s - a shortfall that says the baseline
        // DID move ~1s after backgrounding. That grace-window booking is also
        // why a one-shot skip flag armed here would fail: it would be
        // consumed pre-freeze, and the thaw booking would book the
        // suspension anyway. A state flag has no shots to consume.
        sceneInBackground = true
        let wanted = UserDefaults.standard.bool(forKey: SettingsKey.backgroundSeeding)
        guard wanted, sharing, keepAlive.start() else {
            if wanted && !sharing {
                engineLog.notice(
                    "lifecycle: background seeding SKIPPED - sharing is off, so there would be nothing to serve"
                )
            } else if wanted {
                engineLog.error(
                    "lifecycle: background seeding wanted but the keepalive did not start - pausing instead"
                )
            }
            pause()
            return
        }
        engineLog.notice("lifecycle: entering background SEEDING (keepalive held)")
        guard let e = engine else {
            // No engine to seed with: hand the keepalive straight back, or the
            // audio session would be held with nothing running behind it.
            keepAlive.stop()
            return
        }
        work.async { [weak self] in
            e.pauseForSeeding()
            DispatchQueue.main.async { self?.refreshAll() }
        }
    }

    /// Returning to the foreground: drop the keepalive before resuming, so the
    /// audio session is not held any longer than the background actually lasted.
    ///
    /// This is also where the poll-gap BACKGROUND EPISODE ends, because it is
    /// the ONE point every return to foreground passes through - the
    /// scenePhase .active arm calls it for the plain-pause path and the
    /// seeding path alike. Every booking between `enterBackground()` and here
    /// was discarded by `bookPollGap` with its baseline nil'd; the explicit
    /// clear below covers the one remaining case - NO booking drained during
    /// the episode (a short hop) - so a pre-background baseline cannot
    /// survive into the foreground by either route.
    ///
    /// ORDERING, because the first fix died on it: clearing the baseline here
    /// used to be the whole mechanism, described then as leaving only a
    /// "sub-millisecond residual race". Glass falsified that on 2 of 2
    /// suspensions (2026-08-09, build 4bf04b1): work queued before the freeze
    /// drains on thaw BEFORE this runs - the normal ordering, not an edge -
    /// so the way-in clear was always too late. The exclusion is therefore
    /// armed on the way OUT (`sceneInBackground` in `enterBackground()`), and
    /// this function only closes the episode. Both orderings of {thaw-drained
    /// booking, this call} are now correct: a booking before it sees the flag
    /// up and discards; a booking after it finds a nil baseline and only
    /// re-arms.
    ///
    /// NOT UNIT-REACHABLE, stated plainly (the same disclosure the throttle
    /// clear carries): the flag raise/drop rides a UIKit lifecycle
    /// transition; `PollGapBookingTests` pins the pure rule, and the wiring
    /// can only be watched on glass (suspend with seeding off, resume, read
    /// "Longest poll gap").
    func leaveBackground() {
        sceneInBackground = false
        lastUiPollAt = nil
        // Flush the heartbeats the episode counted but did not publish
        // (`coalescedCounterPublish` froze the mirror while backgrounded), so
        // the Stats pair is current from the first foreground frame.
        if let v = Self.coalescedCounterPublish(
            trueCount: heartbeatCount, published: heartbeatTicks, backgrounded: false)
        {
            heartbeatTicks = v
        }
        keepAlive.stop()
        resume()
        // Repaint from LIVE engine values NOW, not when the machinery gets
        // around to it: resume()'s own refreshAll lands only after e.resume()
        // clears the serial work queue (a reconnect can take seconds), and
        // the next timer tick may be throttled while `state` still reads
        // .seeding. refreshFast is lock-free and rides its own queue, so this
        // is the honest half of the background gate - suppressing publishes
        // while hidden is only acceptable because THIS makes the screen
        // correct and current the moment it is visible again.
        refreshFast()
    }

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
        // INSTRUMENT (2026-08-05). A device capture showed padMule suspended
        // 465ms after this ran, with the teardown not completing for another
        // 30.5s - it finished on the way back IN, immediately before resume, so
        // the "clean pause" never happened and the Kad fold landed too late to
        // be re-read. TWO mechanisms could do that and the log could not tell
        // them apart: the assertion was refused, or this work item sat behind
        // something long on the SERIAL `work` queue (a 6s server probe would).
        //
        // So: say whether the assertion was granted, and stamp when the work
        // actually STARTS as against when pause() was called. The gap between
        // those two lines is the queue wait, and it names the mechanism instead
        // of leaving it to be argued.
        let granted = pauseBackgroundTask != .invalid
        let requestedAt = Date()
        engineLog.notice(
            "lifecycle: pause background-task assertion \(granted ? "GRANTED" : "REFUSED", privacy: .public)"
        )
        work.async { [weak self] in
            let waited = Date().timeIntervalSince(requestedAt)
            engineLog.notice(
                "lifecycle: pause work STARTED after \(String(format: "%.2f", waited), privacy: .public)s on the work queue"
            )
            e.pause()
            DispatchQueue.main.async {
                guard let self else { return }
                self.refreshAll()
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
                self?.refreshAll()
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
                self?.refreshAll()
            }
        }
    }

    private func run(_ body: @escaping (MuleEngine) -> Void) {
        guard let e = engine else { return }
        work.async { [weak self] in
            body(e)
            DispatchQueue.main.async { self?.refreshAll() }
        }
    }

    /// How many 1s ticks between full UI snapshots while background-SEEDING.
    ///
    /// While seeding there is no UI on screen, and `refreshFast()` is not free:
    /// it marshals the whole downloads list and the whole shared library across
    /// the FFI every second, plus stats and five scalars, and then publishes all
    /// of it to views nobody is looking at.
    static let seedingPollDivisor = 5

    /// Should the FULL UI snapshot run on this tick?
    ///
    /// Pure, so the rule is testable without a runtime - and because it is the
    /// independent variable in an experiment. The 2026-08-07 soak proved
    /// background seeding SURVIVES (60 samples, ~70 min, footprint flat at
    /// 32.2MB) but left CPU unexplained: samples split almost exactly evenly
    /// above and below 5%, against 0.1% foreground-idle.
    ///
    /// DO NOT read this as "we know the poll is the cost" - that hypothesis has
    /// a hole in it, since a 1 Hz signal would be caught by essentially any
    /// sampling window rather than half of them. This exists to SEPARATE the two
    /// candidates: if the split survives with the snapshot throttled, the cost is
    /// the audio keepalive and the poll is exonerated.
    ///
    /// The heartbeat cadence is deliberately NOT changed here. It genuinely
    /// needs the engine lock and drives duties that must keep running while
    /// seeding (re-offer, finalize, server-drop detection), and an experiment
    /// with two variables answers neither.
    ///
    /// SINCE 2026-08-09 the background publish gate (`shouldPublishUi`, in
    /// `refreshFast` itself) sits AHEAD of this rule: while the scene is
    /// backgrounded the snapshot does not run at all, throttled or otherwise.
    /// This rule still governs the on-glass ticks where `state` reads
    /// .seeding - the brief return-to-foreground window before the engine
    /// flips back to running. The experiment it was built for is answered:
    /// the 2026-08-09 soak's syslog volume was FLAT (~4,100 lines/min) across
    /// both CPU regimes, so the poll was not what alternated.
    static func shouldRunFastPoll(state: EngineStateFfi, tick: Int) -> Bool {
        guard state == .seeding else { return true }
        return tick % seedingPollDivisor == 0
    }

    /// PURE: the poll-gap booking rule, in one testable place (the same seam
    /// shape as `shouldRunFastPoll` and `serverRowConnected`). Returns the new
    /// running max and the new `lastUiPollAt` baseline.
    ///
    /// While `backgrounded` (between the scenePhase .background and .active
    /// transitions) it books NOTHING and returns a nil baseline - so an
    /// interval that overlaps a background episode cannot be measured by this
    /// booking (discarded) OR by the next one (its baseline is gone).
    ///
    /// There is deliberately NO magnitude threshold ("ignore gaps over N
    /// seconds"): a multi-second FOREGROUND stall is the one thing this
    /// instrument exists to catch, and a threshold would discard the signal
    /// along with the noise. The discriminator is lifecycle state, which
    /// separates the two exactly.
    nonisolated static func bookPollGap(
        now: Date, last: Date?, backgrounded: Bool, maxGap: Double
    ) -> (maxGap: Double, baseline: Date?) {
        if backgrounded { return (maxGap, nil) }
        guard let last else { return (maxGap, now) }
        return (max(maxGap, now.timeIntervalSince(last)), now)
    }

    /// THE BACKGROUND PUBLISH GATE: may the poll write to `@Published`
    /// properties right now? Pure, in the seam pattern of `shouldRunFastPoll`
    /// and `bookPollGap`, and shared by BOTH periodic publishers -
    /// `refreshFast`'s snapshot batch and the heartbeat counter - so the two
    /// cannot come to different answers about the same episode.
    ///
    /// WHY IT EXISTS (2026-08-09, the 72-minute background-seeding soak on
    /// build d5fadb8): a publish is a render. Every `@Published` set fires
    /// `objectWillChange` - on SET, not on change - and SwiftUI re-renders
    /// the observing hierarchy even when nothing is on glass. The heartbeat
    /// counter alone re-rendered the hidden app once per second for the whole
    /// soak: ~55 CoreFoundation localization lookups plus one DENIED
    /// UIAccessibility post attempt every second, ~4,100 syslog lines a
    /// minute, in exactly the mode built to be frugal. The engine duties are
    /// untouched by this gate - `heartbeat()` runs every tick regardless, and
    /// events still drain and apply (they are rare, real changes, and how
    /// `state` stays current). Only the view-facing publish stops.
    ///
    /// The other half of the bargain lives in `leaveBackground()`: gating is
    /// honest only because the return path repaints from live engine values
    /// immediately - a stale screen after resume would be the worse bug.
    nonisolated static func shouldPublishUi(backgrounded: Bool) -> Bool {
        !backgrounded
    }

    /// What a tick counter's `@Published` mirror should be set to - or nil,
    /// meaning DO NOT TOUCH THE PROPERTY. The nil is the entire point:
    /// assigning even an unchanged value to a plain `@Published` still fires
    /// `objectWillChange`, so "publish the same number again" and "stay
    /// silent" are different render behaviours, and only an untouched
    /// property is silent. Backgrounded: always nil (the mirror freezes; the
    /// caller keeps the true count). Foreground: the true count, or nil when
    /// the mirror already shows it (the flush-with-nothing-to-flush case).
    nonisolated static func coalescedCounterPublish(
        trueCount: UInt64, published: UInt64, backgrounded: Bool
    ) -> UInt64? {
        guard shouldPublishUi(backgrounded: backgrounded) else { return nil }
        return trueCount == published ? nil : trueCount
    }

    private var pollTick = 0

    private func startPolling() {
        timer?.invalidate()
        // The NON-scheduling initializer, added to the run loop exactly once
        // (in .common, so it keeps firing during scroll). scheduledTimer had
        // already registered it in .default, so the add made a second
        // registration of the same timer.
        let t = Timer(timeInterval: 1.0, repeats: true) { [weak self] _ in
            Task { @MainActor in
                guard let self else { return }
                self.pollTick &+= 1
                // Events ALWAYS drain: they are cheap (a try_recv loop on a
                // channel, never the engine lock) and they are how `state`
                // itself stays current once the snapshot is throttled.
                self.pumpEvents()
                if Self.shouldRunFastPoll(state: self.state, tick: self.pollTick) {
                    self.refreshFast()
                } else {
                    // A deliberately skipped tick must not count against the
                    // poll-gap instrument: clear the baseline so the next
                    // measured gap does not span throttled ticks. Without
                    // this, one seeding episode pushed the max to ~5s - the
                    // throttle's number, not a fault's.
                    self.lastUiPollAt = nil
                }
                self.refresh()
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

    /// Both halves, for a caller that means "update the screen NOW" - a cancel, a
    /// priority change, a finished action. `refresh()` alone no longer touches
    /// the transfer list (that moved to `refreshFast`), so an action handler that
    /// called only it would leave the row it just changed stale for up to a
    /// second. The two dispatch to DIFFERENT queues, so this does not
    /// reintroduce the coupling: the fast half still runs while the slow half
    /// queues behind a long engine call.
    private func refreshAll() {
        refreshFast()
        refresh()
    }

    /// The LOCK-FREE half: transfers, the shared library, the sharing switch,
    /// byte totals and the port-mapping flag. None of these touches the engine
    /// mutex in the Rust seam, so they keep answering while a ~20s search or
    /// ~10s crawl holds it - which is exactly when the progress numbers used to
    /// freeze. Runs on its own queue for the same reason the event pump does:
    /// `work` is serial, so sharing it would reintroduce the very stall this
    /// removes. No in-flight guard needed - these calls cannot block.
    private func refreshFast() {
        guard let e = engine else { return }
        // THE BACKGROUND GATE (see `shouldPublishUi`). Nothing is on glass,
        // so neither the FFI marshalling (the whole downloads list + shared
        // library) nor the publish batch below - thirteen `@Published` sets,
        // each a render of a hidden hierarchy - should run at all. Gated at
        // the single choke point every caller funnels through (the tick, the
        // action-completion refreshAll()s, boot), and checked HERE on the
        // main thread rather than only at the tick site, so a completion
        // firing mid-episode is covered too. The baseline clears exactly as a
        // throttle-skipped tick's does; `bookPollGap` additionally discards
        // any interval booked by a closure already in flight when the flag
        // went up. On return, `leaveBackground()` calls this directly for the
        // immediate repaint.
        guard Self.shouldPublishUi(backgrounded: sceneInBackground) else {
            lastUiPollAt = nil
            return
        }
        eventQueue.async { [weak self] in
            let dls = e.downloads()
            let shf = e.sharedFiles()
            let shr = e.isSharing()
            let stats = e.transferStats()
            let mapped = e.hasPortMapping()
            // THE STATUS SCALARS MOVED HERE (2026-08-07) and that is the whole
            // GUI-responsiveness fix. They used to sit in refresh(), AFTER
            // heartbeat() in the same closure on the SERIAL `work` queue - so a
            // 10-20s search froze every status row on screen until it finished.
            // Measured: a user action issued 1.9s into a search took 20.62s
            // against 7.5-9.3s idle. They belong on this queue with the other
            // lock-free reads rather than behind the one call that genuinely
            // needs the lock.
            //
            // FOUR OF THE FIVE WERE LOCK-FREE WHEN THEY MOVED HERE. `serverInfo()`
            // was not - it kept taking the engine lock until the 2026-08-07
            // reanalysis found it - so this whole closure, and with it the event
            // drain that shares this queue, still stalled for the length of every
            // search. Anything added here must be lock-free on the Rust side AND
            // named in mule-ffi's `the_status_readers_answer_while_the_engine_lock
            // _is_held`, which is the only thing that can catch the next one.
            let st = e.state()
            let kad = e.kadContacts()
            let ipf = e.ipFilterRanges()
            let srv = e.serverInfo()
            let ipPause = e.sharingPausedForIpChange()
            DispatchQueue.main.async {
                guard let self else { return }
                self.downloads = dls
                self.sharedFiles = shf
                self.downloadingHashes = Set(dls.filter { !$0.complete }.map { $0.hash })
                self.haveHashes =
                    Set(dls.filter { $0.complete }.map { $0.hash }).union(shf.map { $0.hash })
                self.sharing = shr
                self.portMapped = mapped
                self.state = st
                self.setKadContacts(kad)
                self.ipFilterRanges = ipf
                self.server = srv
                self.sharingPausedForIpChange = ipPause
                self.sampleStats(stats)
                self.applyKeepAwake()
                self.uiPollTicks &+= 1
                // The booking rule is pure (`bookPollGap`); what this site
                // supplies is the ordering guarantee: `sceneInBackground` was
                // armed in enterBackground(), BEFORE any freeze, on the same
                // main thread this closure runs on - so a closure thawing out
                // of a suspension reads the flag as up no matter when it was
                // queued, and the suspension cannot book. See the
                // `uiPollMaxGapSecs` SCOPE doc.
                let booked = Self.bookPollGap(
                    now: Date(), last: self.lastUiPollAt,
                    backgrounded: self.sceneInBackground,
                    maxGap: self.uiPollMaxGapSecs)
                self.uiPollMaxGapSecs = booked.maxGap
                self.lastUiPollAt = booked.baseline
            }
        }
    }

    /// Pull a fresh snapshot off the main thread. Events are NOT drained here
    /// any more - `pumpEvents()` owns that, on its own queue, so a banner or a
    /// status change still arrives while a long engine call is holding `work`.
    /// This half takes the ENGINE LOCK, so it stalls behind a long search or
    /// crawl - by design, and honestly: only the Status scalars lag. It also
    /// drives `heartbeat()`, so the 1s timer must keep firing it even when no
    /// screen shows transfers.
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
            // HEARTBEAT ONLY. It genuinely needs the engine lock - it drives
            // the engine's background maintenance duties, all of which fail
            // SILENTLY if it stops - so it stays on the serial `work` queue
            // and is allowed to be slow. How many duties and which ones is
            // stated in ONE place: the doc on `MuleEngine::heartbeat()` in
            // crates/mule-ffi/src/lib.rs, where a source-scan test pins the
            // count to the body. This comment used to state the number itself
            // and lagged the Rust side (it still said seven after the roster
            // grew to eight); a count no Rust test can reach does not get a
            // copy here.
            //
            // What it must NOT do any more is carry the status reads with it.
            // They used to follow it in this same closure, which meant every
            // status row on screen froze for the length of whatever held the
            // lock (a search: up to 20s). They now ride refreshFast() on the
            // lock-free queue. Nothing here publishes to the UI except the
            // gated counter below, so a slow heartbeat costs background
            // timeliness and nothing visible.
            e.heartbeat()
            DispatchQueue.main.async {
                guard let self else { return }
                self.refreshInFlight = false
                // The true count always advances; the @Published mirror is
                // written only when `coalescedCounterPublish` says so. This
                // increment was THE once-per-second re-render of the hidden
                // hierarchy during background seeding (2026-08-09 soak) - the
                // one @Published write on the every-tick path. The gate is
                // read HERE, at publish time on the main thread, the ordering
                // `bookPollGap`'s way-out flag already proved on glass: a
                // closure queued before the episode still sees the flag up.
                self.heartbeatCount &+= 1
                if let v = Self.coalescedCounterPublish(
                    trueCount: self.heartbeatCount, published: self.heartbeatTicks,
                    backgrounded: self.sceneInBackground)
                {
                    self.heartbeatTicks = v
                }
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

    /// The ONE owner of the kad-contacts change log. Both writers - the 1s
    /// poll (refreshFast) and the `.kad` event - route through here, so a
    /// change is logged exactly once by whichever path sees it first, and only
    /// on change: a log that repeats itself once a second is a log nobody
    /// reads. Main-thread only, like every other publish.
    private func setKadContacts(_ n: UInt32) {
        if n != kadContacts {
            engineLog.info("kad contacts: \(n, privacy: .public)")
        }
        kadContacts = n
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
            // Through the ONE change-logging setter (see setKadContacts) - the
            // compare used to live here alone, where it almost never fired:
            // refreshFast folds the same engine counter in every tick, so by
            // the time this event drained the value had already been assigned
            // unlogged and the "change" had vanished.
            setKadContacts(contacts)
        case .progress:
            break // downloads() already carries the numbers
        case .finished(let name):
            // A TYPED completion, not a match on the "Saved '..'" server line
            // that accompanies it: that line is prose whose wording is free to
            // change, and a beep that stopped working the day someone reworded
            // it would be a silent regression.
            engineLog.notice("download finished: \(name, privacy: .public)")
            loadDownloadedFiles()
            if UserDefaults.standard.bool(forKey: SettingsKey.beepOnDownloadComplete) {
                EngineModel.playFinishedSound()
            }
        }
    }

    /// The finish sound. `AudioServicesPlaySystemSound` needs no session setup
    /// and no audio permission, and it follows the silent switch - which is the
    /// right behaviour for an alert the user did not ask to hear right now.
    /// 1057 is the short "Tink": audible without being an alarm, since a busy
    /// queue can finish several files in a row.
    static func playFinishedSound() {
        AudioServicesPlaySystemSound(1057)
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
    ///
    /// THE DIAL NEVER RUNS AGAINST A DOWN ENGINE. On glass (2026-08-09, build
    /// 4bf04b1) a row tap while the engine was STOPPED logged in anyway -
    /// `Engine::connect_to_server` guards only `offline`, never state - and
    /// with the listener down (shutdown had released it) the server's
    /// connect-back test failed, so the login was a LowID that then STUCK
    /// across the next Start (start() does not re-dial an established
    /// session). Status read "Stopped" beside "eD2k Connected, LowID": one
    /// engine, two stories.
    ///
    /// So the tap decision is the pure `serverTapAction`, and the dial is
    /// ALWAYS preceded by `e.start()` INSIDE THE SAME work item:
    /// - `Engine::start()` awaits the listener bind and the port mapping
    ///   BEFORE returning ("the inbound listener must exist BEFORE we log
    ///   in" - engine.rs, its own ordering comment), and it is an idempotent
    ///   no-op when already Running, so on an up engine it costs one lock
    ///   take on the queue about to hold that same lock for the dial anyway.
    /// - ONE work item, not two: `work` is serial, so start-then-dial as a
    ///   single closure admits no interleaving. Dispatched as two items, a
    ///   Stop tapped in between would queue shutdown BETWEEN start and dial
    ///   and reproduce the defect. As one item, a Stop lands wholly before
    ///   it (start revives, dial connects - the later intent wins) or wholly
    ///   after (stopped, no login). Every ordering ends coherent.
    /// A consequence worth stating: the `state` snapshot read here picks only
    /// the MESSAGE - a stale read cannot un-guard the dial.
    ///
    /// `stopping` is deliberately NOT raised for the bring-up:
    /// `connectionSummary` infers direction from `state`, which flips to
    /// running mid-item and would relabel the op "Stopping...". The row's
    /// spinner (`connectingTo`) and the notice carry the feedback instead.
    func connectServer(_ addr: String) {
        guard let e = engine else { return }
        switch Self.serverTapAction(rowAddr: addr, state: state, liveServerAddr: server?.addr) {
        case .ignore:
            return
        case .startThenConnect:
            // Reversing an explicit Stop must be said out loud, not done
            // silently - the user is told the tap is starting the engine.
            notice = "Starting padMule to connect."
            engineLog.notice(
                "connecting to \(addr, privacy: .public) - engine not running, starting it first")
        case .connect:
            engineLog.notice("connecting to \(addr, privacy: .public)")
        }
        connectingTo = addr
        work.async { [weak self] in
            // Ensure-running, atomically with the dial (see the doc above).
            e.start()
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
                self.refreshAll()
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
                self?.refreshAll()
                self?.loadServers()
            }
        }
    }

    /// The canonical public server-list URL. Plain http, because that is what the
    /// endpoint publishes; an https:// source is equally usable since 2026-08-10
    /// (the engine fetches it with rustls). Either way the fetch is a raw socket
    /// inside the Rust engine, never URLSession, so no ATS exemption is involved.
    nonisolated static let defaultServerListUrl = "http://upd.emule-security.org/server.met"

    /// The name padMule announces when the user has not chosen one. Must equal
    /// `mule_engine::DEFAULT_NICK`, which is the value the engine falls back to;
    /// they are the same string on both sides of the seam so a fresh install
    /// announces what every build before the setting announced.
    nonisolated static let defaultNickname = "padMule"

    /// What to push into the engine at boot for a stored nickname.
    ///
    /// The trap this exists for: `UserDefaults.string(forKey:)` returns nil for
    /// an absent key, and an absent key is the FIRST LAUNCH - so a naive
    /// `?? ""` would push an empty nickname on exactly the install that has
    /// never configured anything. Same shape as the ports' "a stored 0 means
    /// never set". The engine would repair an empty value anyway (it falls back
    /// to the same default), but a caller that relies on the far side to fix its
    /// input is a caller that is wrong; the fallback belongs here too.
    nonisolated static func nicknameToPush(stored: String?) -> String {
        let trimmed = (stored ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? defaultNickname : trimmed
    }

    /// Push the stored nickname into the engine. Called at boot (before
    /// `start()`, alongside the ports) and whenever the Settings field commits.
    ///
    /// It takes effect on the next server login and the next outbound fetch;
    /// peers that dial US keep seeing the previous name until the listener is
    /// rebuilt by Stop then Start. The Settings footer says exactly that rather
    /// than implying the change is instant everywhere.
    func pushNickname() {
        guard let e = engine else { return }
        let nick = EngineModel.nicknameToPush(
            stored: UserDefaults.standard.string(forKey: SettingsKey.nickname))
        work.async { e.setNickname(nick: nick) }
    }

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
                    self.notice = "The server-list URL must start with http:// or https://"
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

    // MARK: - Fetch diagnostics (the funnel)

    /// Dismiss the boot-failure banner. A method because `bootError` is
    /// `private(set)` - only boot() may SET it, so only the model may clear it.
    /// Clearing hides the banner without pretending the engine started: `ready`
    /// stays false and every control still reports honestly.
    func clearBootError() {
        bootError = nil
    }

    /// The fetch funnel as a printable block - where peer sessions die, the
    /// opcodes read out of turn, and how long dials take.
    ///
    /// Called STRAIGHT off the main thread, not via `work`: the engine side
    /// reads process-global atomics and never takes the engine lock. That is
    /// deliberate, because a stall is exactly when the engine is busy - routing
    /// this through the serial queue would make the diagnostic unavailable
    /// precisely when it is wanted. Returns a placeholder rather than an empty
    /// panel before the engine exists.
    var fetchReport: String {
        engine?.fetchReport() ?? "Engine not started."
    }

    /// The Kad lookup profile - rounds run, how many were held open by a peer
    /// that never answered, and the average round duration. Lock-free on the
    /// engine side for the same reason as `fetchReport`.
    ///
    /// It answers one question: a batch round ends when its last member answers
    /// OR at the full per-query deadline, and which dominates decides whether
    /// removing the round barrier is worth building. "with a SILENT peer"
    /// against "rounds run" is the reading.
    var kadReport: String {
        engine?.kadReport() ?? "Engine not started."
    }

    /// Zero the funnel counters AND the Kad profile, so the next reading
    /// describes one experiment rather than everything since launch.
    ///
    /// The UI-side "Longest poll gap" high-water mark resets here too
    /// (2026-08-09): it is the same kind of since-launch diagnostic, and it
    /// previously had NO reset at all - so a single historic pollution (any
    /// suspension on a build before the way-out exclusion) sat on screen as a
    /// permanently wrong number with nothing but a relaunch to clear it. The
    /// baseline clears with it so the first post-reset booking re-arms
    /// instead of measuring across the reset.
    func resetFetchStats() {
        engine?.resetFetchStats()
        uiPollMaxGapSecs = 0
        lastUiPollAt = nil
        notice = "Diagnostic counters reset - reproduce the problem, then read them."
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
