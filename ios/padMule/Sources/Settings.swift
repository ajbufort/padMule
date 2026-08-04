// User settings. padMule had NONE until now: the only adjustable things were
// search filters and the Leech-Mode toggle, and not one of them survived a
// relaunch. eMule's Preferences is the design reference (docs/wiki/portability-audit.md
// records which of its pages are meaningless on iPadOS and are deliberately not
// ported), but the shape is a single iOS Form rather than its 16-page tree.
//
// Everything here is TIER 0: it persists locally and drives calls the engine
// already exposes. Nothing in this file needs new engine work - the settings that
// do (bandwidth caps, ports, obfuscation policy) are tracked in the audit.

import Foundation
import Network
import SwiftUI

/// UserDefaults keys, namespaced like the existing category/recent-search stores.
enum SettingsKey {
    /// The user's OWN sharing preference. Distinct from `EngineModel.sharing`,
    /// which is what the engine is doing right now - the two differ while a
    /// metered-network pause is in force.
    static let shareUploads = "padMule.shareUploads"
    static let pauseSharingOnCellular = "padMule.pauseSharingOnCellular"
    static let keepAwakeWhileTransferring = "padMule.keepAwakeWhileTransferring"
    /// A LIST of server.met URLs, not one - eMule's `addresses.dat` model. Every
    /// list is merged (the engine's `merge_server_met` keeps existing entries and
    /// appends only new ip:port pairs), so several lists accumulate into one
    /// comprehensive set rather than the last one winning. `server.met` is a
    /// single shared format: eMule and aMule both read and write it, and the
    /// published lists are the same files, so there is no such thing as an
    /// "eMule-only" or "aMule-only" list to reconcile.
    static let serverListUrls = "padMule.serverListUrls"
    static let updateServerListAtLaunch = "padMule.updateServerListAtLaunch"
    /// eMule's "update server list when connecting" (AddServersFromServer): every
    /// fresh server login also ASKS that server for the servers it knows
    /// (OP_GETSERVERLIST) and merges the answer. eMule defaults this OFF; padMule
    /// defaults it ON - the merge is filtered and bounded, the ask is one empty
    /// packet, and without it the discovered-servers feature is inert.
    static let askServersForServers = "padMule.askServersForServers"
    static let defaultPriority = "padMule.defaultDownloadPriority"
    static let rememberSearchFilters = "padMule.rememberSearchFilters"
    // Persisted wire-filter values (only read back when the flag above is on).
    static let wireCompleteOnly = "padMule.wire.completeOnly"
    static let wireGlobal = "padMule.wire.global"
    static let wireMinSizeMb = "padMule.wire.minSizeMb"
    static let wireMaxSizeMb = "padMule.wire.maxSizeMb"
    /// eD2k TCP port padMule listens on. Distinct from `advertisedPort` because a
    /// VPN's remote-forwarder can map an external port to a different local one -
    /// see the Network / VPN settings section for the full story.
    static let listenPort = "padMule.listenPort"
    /// The port padMule tells servers and peers to dial. Equal to `listenPort` in
    /// the ordinary home-router case; different behind a VPN forwarder.
    static let advertisedPort = "padMule.advertisedPort"
    static let kadPort = "padMule.kadPort"
    /// The Kad UDP port peers are TOLD to dial, when a provider forwards a
    /// remote port to a different local one. Equal to `kadPort` in the ordinary
    /// same-port case; the eD2k TCP side has had this split since 8bd.
    static let kadAdvertisedPort = "padMule.kadAdvertisedPort"
    /// Attempt a UPnP mapping on the LAN router. Off is correct on a VPN, where
    /// the provider does the forwarding and a LAN-router mapping is a no-op the
    /// tunnel bypasses anyway.
    static let upnpEnabled = "padMule.upnpEnabled"
}

/// Registers the DEFAULTS, so a first launch behaves correctly before the user
/// has opened Settings even once. `UserDefaults.bool(forKey:)` returns false for
/// an absent key, which would silently mean "sharing off" and "no metered
/// protection" - the opposite of what we want.
///
/// Sharing defaults ON, matching the engine's own initial state and eMule's
/// posture that a client contributes. The metered pause also defaults ON, so the
/// protective option is the one you get without asking (many iPads are cellular,
/// and an upload stream against a data plan costs real money).
enum SettingsDefaults {
    static func register() {
        UserDefaults.standard.register(defaults: [
            SettingsKey.shareUploads: true,
            SettingsKey.pauseSharingOnCellular: true,
            SettingsKey.keepAwakeWhileTransferring: true,
            SettingsKey.serverListUrls: [EngineModel.defaultServerListUrl],
            SettingsKey.updateServerListAtLaunch: false,
            SettingsKey.askServersForServers: true,
            SettingsKey.defaultPriority: 1, // Normal
            SettingsKey.rememberSearchFilters: true,
            // 5999 for all three: the port Anthony reserved on AirVPN,
            // forwarded same-port with TCP+UDP. eD2k's 4662/4672 remain the
            // engine's own constants for anything not driven by this screen.
            SettingsKey.listenPort: 5999,
            SettingsKey.advertisedPort: 5999,
            SettingsKey.kadPort: 5999,
            SettingsKey.kadAdvertisedPort: 5999,
            // OFF by default, to match the 5999 ports above. Those defaults say
            // "this build expects a VPN to forward a port into the tunnel", and
            // on a VPN a LAN router mapping accomplishes nothing - it maps a
            // port on the local gateway for traffic that never traverses it, so
            // the only thing it can produce is a misleading Port-mapping row.
            // The honest "UPnP: off - port forwarding is handled outside
            // padMule" status line names the setting, so a user NOT behind a
            // VPN can find and enable it.
            SettingsKey.upnpEnabled: false,
        ])
    }
}

/// Watches the network path so sharing can be paused on a metered link.
///
/// `isExpensive` covers cellular and personal hotspots; `isConstrained` covers
/// iOS Low Data Mode, where the user has explicitly asked apps to hold back. A
/// P2P client that keeps seeding through either is spending money or defying a
/// stated preference, so both count as metered.
@MainActor
final class NetworkWatcher: ObservableObject {
    @Published private(set) var isMetered = false

    private let monitor = NWPathMonitor()
    private let queue = DispatchQueue(label: "padMule.path")

    init() {
        monitor.pathUpdateHandler = { [weak self] path in
            let metered = path.isExpensive || path.isConstrained
            Task { @MainActor in
                guard let self, self.isMetered != metered else { return }
                self.isMetered = metered
                engineLog.notice(
                    "network is now \(metered ? "METERED (cellular/hotspot/low-data)" : "unmetered", privacy: .public)"
                )
            }
        }
        monitor.start(queue: queue)
    }

    deinit { monitor.cancel() }
}
