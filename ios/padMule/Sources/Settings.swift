// User settings. padMule had NONE until now: the only adjustable things were
// search filters and the Leech-Mode toggle, and not one of them survived a
// relaunch. eMule's Preferences is the design reference (docs/wiki/portability-audit.md
// records which of its pages are meaningless on iPadOS and are deliberately not
// ported), but the shape is a single iOS Form rather than its 16-page tree.
//
// Everything here is TIER 0: it persists locally and drives calls the engine
// already exposes. Nothing in this file needs new engine work - the settings that
// do (bandwidth caps, ports, obfuscation policy) are tracked in the audit.

// CFNetwork for CFNetworkCopySystemProxySettings (the VPN interface probe).
// Imported explicitly rather than relied on through Foundation, which does not
// reliably re-export it on iOS.
import CFNetwork
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
    /// Keep SERVING files after the app is backgrounded, using an audio
    /// keepalive. OFF by default: it costs battery, and the honest default for
    /// something that runs while the user is not looking is off.
    static let backgroundSeeding = "padMule.backgroundSeeding"
    /// INCOGNITO (handoff 32): stop declaring padMule on the wire - drop the
    /// enhancement-channel marker, write the 7-tag hello stock aMule writes,
    /// and replace an UNCHANGED default nickname with aMule's own default.
    /// ON by default (Anthony, 2026-08-11): the padMule-to-padMule enhancement
    /// channel it disables is DEFERRED and unbuilt, so the capability it costs
    /// is theoretical today while the exposure it removes is real on every
    /// connection. The registered default below says the same thing.
    static let incognito = "padMule.incognito"
    /// Who may BROWSE our shared files (eMule `CanSeeShares`). false = Nobody,
    /// true = Everybody. eMule's own default is Nobody, so refusing is upstream
    /// behavior rather than a padMule divergence. A "Friends" setting is
    /// deliberately absent: padMule has no friends list, and an option that
    /// silently behaved as Nobody would be a privacy control that lies.
    static let allowBrowse = "padMule.allowBrowse"
    /// Play a short sound when a download finishes, verifies and is saved.
    /// padMule is foreground-only, so a long transfer means the iPad is sitting
    /// there with the app open - a sound is the only way to be told it is done
    /// without watching the screen.
    static let beepOnDownloadComplete = "padMule.beepOnDownloadComplete"
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
    /// Max simultaneously-active downloads; 0 = unlimited. The rest queue in
    /// add order (padMule's own policy - eMule has no such cap).
    static let maxActiveDownloads = "padMule.maxActiveDownloads"
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
    /// The name padMule announces to peers (the HELLO's CT_NAME) and to servers
    /// (the login's CT_NAME). eMule's Options -> General "Nick"
    /// (0.70b PPgGeneral.cpp:88/187), stored the same way: a plain string,
    /// defaulted rather than left absent, so a fresh install is not nameless.
    /// Default "padMule" - the literal every build before this one announced.
    static let nickname = "padMule.nickname"
    /// Dark Mode. padMule pins its own appearance rather than following the
    /// system: it starts LIGHT unless this is on, so the look is a padMule
    /// setting rather than an inherited one, and it never changes underneath the
    /// user because the iPad crossed a sunset boundary mid-transfer.
    static let darkMode = "padMule.darkMode"
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
            // OFF: it runs while the user is not looking and costs battery, so
            // off is the only honest default. Must agree with the @AppStorage
            // initializer in SettingsView, or the toggle shows one state while
            // the engine is in the other.
            SettingsKey.backgroundSeeding: false,
            // ON by default (Anthony, 2026-08-11). It costs the
            // padMule-to-padMule enhancement channel, which is DEFERRED and
            // unbuilt - so the capability it disables is theoretical today,
            // while the exposure it removes is real on every connection.
            SettingsKey.incognito: true,
            SettingsKey.allowBrowse: false,
            SettingsKey.beepOnDownloadComplete: true,
            SettingsKey.serverListUrls: [EngineModel.defaultServerListUrl],
            SettingsKey.updateServerListAtLaunch: false,
            SettingsKey.askServersForServers: true,
            SettingsKey.defaultPriority: 1, // Normal
            SettingsKey.maxActiveDownloads: 0, // unlimited - the shipped behaviour
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
            // The nickname every padMule build announced before it became a
            // setting. Registering it (rather than leaning on nil for an absent
            // key) means the Settings field shows the name actually in force on
            // a fresh install instead of an empty box.
            SettingsKey.nickname: EngineModel.defaultNickname,
            // LIGHT unless the user says otherwise (Anthony, 2026-08-05).
            // Registering it explicitly rather than leaning on bool(forKey:)
            // returning false for an absent key: the two behave identically
            // today, but the DEFAULT is a decision and it belongs where the
            // other decisions are, not as an accident of the API.
            SettingsKey.darkMode: false,
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
    /// True while a VPN tunnel appears to be up. See `vpnIsUp` for exactly what
    /// that claim is worth.
    @Published private(set) var vpnActive = false

    private let monitor = NWPathMonitor()
    private let queue = DispatchQueue(label: "padMule.path")

    init() {
        monitor.pathUpdateHandler = { [weak self] path in
            let metered = path.isExpensive || path.isConstrained
            let vpn = NetworkWatcher.vpnIsUp()
            Task { @MainActor in
                guard let self else { return }
                if self.isMetered != metered {
                    self.isMetered = metered
                    engineLog.notice(
                        "network is now \(metered ? "METERED (cellular/hotspot/low-data)" : "unmetered", privacy: .public)"
                    )
                }
                if self.vpnActive != vpn {
                    self.vpnActive = vpn
                    engineLog.notice("VPN tunnel is now \(vpn ? "UP" : "DOWN", privacy: .public)")
                }
            }
        }
        monitor.start(queue: queue)
    }

    /// Re-read the VPN state on demand - used when padMule returns to the
    /// foreground. A tunnel that collapsed while the app was suspended may not
    /// produce a path callback we are awake to receive, and "the VPN dropped
    /// while you were away" is precisely the case worth catching.
    func refreshVpn() {
        let vpn = NetworkWatcher.vpnIsUp()
        guard vpnActive != vpn else { return }
        vpnActive = vpn
        engineLog.notice(
            "VPN tunnel is now \(vpn ? "UP" : "DOWN", privacy: .public) (foreground re-check)")
    }

    /// Interface-name prefixes used by VPN tunnels on iOS. `utun` covers
    /// NEPacketTunnelProvider (WireGuard, OpenVPN clients, most commercial apps
    /// including AirVPN), `ipsec` the built-in IKEv2/IPsec profiles, and
    /// `ppp`/`tap`/`tun` the older shapes.
    private static let tunnelPrefixes = ["utun", "tap", "tun", "ppp", "ipsec"]

    /// Is a VPN tunnel up? Provider-agnostic by construction - it looks for the
    /// tunnel INTERFACE, so it works for any client rather than any particular
    /// one, and needs no entitlement.
    ///
    /// BE CLEAR ABOUT WHAT THIS PROVES. It is a heuristic, and the honest
    /// limits are: (1) it detects that a tunnel interface EXISTS and is
    /// scoped for traffic, not that padMule's packets are going through it -
    /// a split-tunnel config could route this app outside the VPN and still
    /// read true; (2) iOS uses `utun` interfaces for non-VPN purposes too
    /// (AirDrop, Personal Hotspot, Continuity), so a false positive is
    /// possible; (3) a provider doing something unusual could read false while
    /// genuinely connected. It agrees with the system status-bar VPN badge in
    /// the ordinary case, which is the check to make if the reading ever looks
    /// wrong. It is a convenience indicator, NOT a safety guarantee - padMule's
    /// actual leak protection remains the public-address-change guard, which
    /// watches the address the network reports back rather than a local
    /// interface name.
    nonisolated static func vpnIsUp() -> Bool {
        guard
            let settings = CFNetworkCopySystemProxySettings()?.takeRetainedValue()
                as? [String: Any],
            let scoped = settings["__SCOPED__"] as? [String: Any]
        else { return false }
        return scoped.keys.contains { key in
            tunnelPrefixes.contains { key.hasPrefix($0) }
        }
    }

    deinit { monitor.cancel() }
}
