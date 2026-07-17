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

@MainActor
final class EngineModel: ObservableObject {
    @Published private(set) var state: EngineStateFfi = .stopped
    @Published private(set) var status: String = "Idle"
    @Published private(set) var reconnecting: Bool = false
    @Published private(set) var downloads: [DownloadInfo] = []
    @Published private(set) var kadContacts: UInt32 = 0
    @Published private(set) var identity: IdentityInfo?
    @Published private(set) var bootError: String?
    /// The live login. Polled as a SNAPSHOT rather than tracked from events:
    /// start() emits Server(...) then Status(...) into the same drain, so an
    /// event-derived ID is overwritten in the same frame it arrives.
    @Published private(set) var server: ServerInfoFfi?
    @Published private(set) var results: [SearchHit] = []
    @Published private(set) var searching = false
    /// True once a search has actually run, so "no results" is only ever shown
    /// about a real search - never about a box the user has not used yet.
    @Published private(set) var searched = false
    /// Hashes with an add_download call in flight (its source lookup blocks).
    @Published private(set) var adding: Set<String> = []
    /// A transient line reporting what just happened.
    @Published var notice: String?
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
        searching = true
        notice = nil
        work.async { [weak self] in
            let hits = e.search(keyword: q)
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

    func clearSearch() {
        results = []
        searched = false
        notice = nil
    }

    /// Toggle uploading. Off is "Leech Mode": padMule keeps downloading but stops
    /// serving files to peers. Optimistic - refresh() reconciles from the engine.
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
            let kad = e.kadContacts()
            let srv = e.serverInfo()
            let shr = e.isSharing()
            let evs = e.drainEvents()
            DispatchQueue.main.async {
                guard let self else { return }
                self.state = st
                self.downloads = dls
                self.kadContacts = kad
                self.server = srv
                self.sharing = shr
                for ev in evs { self.apply(ev) }
            }
        }
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
            // News ("Saved 'x'", a server MOTD), NOT the connection status.
            // Writing these to `status` would clobber the polled
            // "Connected to <server> (HighID|LowID)" line - the same
            // event-overwrites-state bug that hid the ID type in the first place.
            notice = text
        case .kad(let contacts):
            kadContacts = contacts
        case .progress:
            break // downloads() already carries the numbers
        }
    }
}
