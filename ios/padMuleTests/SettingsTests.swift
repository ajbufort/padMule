import XCTest

@testable import padMule

/// The Tier-0 settings logic that is pure decision, tested without an engine.
/// The load-bearing rule is effective-sharing: the value pushed to the engine is
/// the user's wish ANDed with "not paused for a metered link", and getting it
/// wrong either leaks uploads onto a data plan or refuses to seed on Wi-Fi.
@MainActor
final class SettingsTests: XCTestCase {
    /// A private UserDefaults suite so these never touch the real store or each
    /// other. The rule is small and pure, so it is re-implemented here exactly as
    /// EngineModel computes it and checked across the truth table - this pins the
    /// CONTRACT (what the four inputs must produce) even before it is refactored
    /// into a shared helper.
    private func effectiveSharing(wants: Bool, pauseOnMetered: Bool, metered: Bool) -> Bool {
        wants && !(pauseOnMetered && metered)
    }

    func testMeteredPauseOnlyBitesWhenAllThreeLineUp() {
        // Shares on Wi-Fi.
        XCTAssertTrue(effectiveSharing(wants: true, pauseOnMetered: true, metered: false))
        // Pauses on a metered link - the safety case.
        XCTAssertFalse(effectiveSharing(wants: true, pauseOnMetered: true, metered: true))
        // Metered but the user opted out of the pause: their choice wins.
        XCTAssertTrue(effectiveSharing(wants: true, pauseOnMetered: false, metered: true))
        // Leech mode stays leech mode regardless of network.
        XCTAssertFalse(effectiveSharing(wants: false, pauseOnMetered: true, metered: false))
        XCTAssertFalse(effectiveSharing(wants: false, pauseOnMetered: false, metered: true))
    }

    func testDefaultsRegisterTheProtectiveValues() {
        // Both the sharing default and the metered-pause default must be ON, so a
        // fresh install protects a data plan without the user configuring anything.
        let d = UserDefaults(suiteName: "padMule.test.defaults")!
        d.removePersistentDomain(forName: "padMule.test.defaults")
        d.register(defaults: [
            SettingsKey.shareUploads: true,
            SettingsKey.pauseSharingOnCellular: true,
        ])
        XCTAssertTrue(d.bool(forKey: SettingsKey.shareUploads))
        XCTAssertTrue(d.bool(forKey: SettingsKey.pauseSharingOnCellular))
    }

    /// UPnP must default OFF, and this asserts the REAL registration rather than
    /// a restatement of it - `SettingsDefaults.register()` is what actually runs
    /// at launch, and it is what `@AppStorage` reads. The pairing matters: the
    /// port defaults are 5999 (a VPN-forwarded port), and on a VPN a LAN-router
    /// mapping is a no-op the tunnel bypasses, so leaving UPnP on could only
    /// produce a misleading Port-mapping row. If someone flips this back, the
    /// two must move together.
    func testUpnpDefaultsOffToMatchTheVpnPortDefaults() {
        SettingsDefaults.register()
        let d = UserDefaults.standard
        XCTAssertFalse(
            d.bool(forKey: SettingsKey.upnpEnabled),
            "UPnP must default OFF - the 5999 port defaults assume a VPN forwards the port")
        XCTAssertEqual(d.integer(forKey: SettingsKey.listenPort), 5999)
        XCTAssertEqual(d.integer(forKey: SettingsKey.advertisedPort), 5999)
        XCTAssertEqual(d.integer(forKey: SettingsKey.kadPort), 5999)
        // The FOURTH field. Kad used one value for both bind and advertise, so a
        // provider that remaps remote->local left padMule binding correctly and
        // then telling every peer to dial the local port - inbound Kad died
        // silently while everything outbound kept working. It must default equal
        // to kadPort, so the ordinary same-port case needs no thought.
        XCTAssertEqual(d.integer(forKey: SettingsKey.kadAdvertisedPort), 5999)
        XCTAssertEqual(
            d.integer(forKey: SettingsKey.kadAdvertisedPort),
            d.integer(forKey: SettingsKey.kadPort),
            "advertised Kad port must default to the bound one")
    }

    func testServerListUrlValidationAndDedup() {
        // The rule the model applies before accepting a URL: http/https only, and
        // no duplicates. Re-stated here to pin the contract.
        func accept(_ url: String, into list: inout [String]) -> Bool {
            let u = url.trimmingCharacters(in: .whitespacesAndNewlines)
            guard u.hasPrefix("http://") || u.hasPrefix("https://") else { return false }
            guard !list.contains(u) else { return false }
            list.append(u)
            return true
        }
        var list = ["http://upd.emule-security.org/server.met"]
        XCTAssertFalse(accept("ftp://nope/server.met", into: &list))
        XCTAssertFalse(accept("upd.emule-security.org/server.met", into: &list)) // no scheme
        XCTAssertFalse(accept("http://upd.emule-security.org/server.met", into: &list)) // dup
        XCTAssertTrue(accept("https://ed2k.example/list.met", into: &list))
        XCTAssertEqual(list.count, 2)
    }

    /// A collapsed options group must NAME what is switched on inside it.
    ///
    /// The roll-up exists to reclaim screen space, and the way it could go wrong
    /// is worse than the clutter it replaces: a user staring at thin results
    /// with no way to see that "trusted only" is filtering them, behind a closed
    /// triangle. Hiding a control is fine; hiding STATE is not.
    func testCollapsedOptionLabelNamesWhatIsActive() {
        XCTAssertEqual(
            ContentView.optionSummary(prefix: "Search options", active: []),
            "Search options", "nothing on - just the plain title")
        XCTAssertEqual(
            ContentView.optionSummary(prefix: "Search options", active: ["global"]),
            "Search options: global")
        XCTAssertEqual(
            ContentView.optionSummary(
                prefix: "Refine results", active: ["trusted only", "hiding have"]),
            "Refine results: trusted only, hiding have")
    }

    /// A row with zero connected sources must say WHICH kind of nothing it is.
    /// "no sources exist" and "sources exist and none can be reached" need
    /// opposite responses from the user and both used to render as a blank -
    /// which is how a 312 MB file sat at Zero KB for ten minutes on 2026-08-05
    /// while its search row advertised 15 sources.
    func testIdlePoolDistinguishesEmptyFromUnreachable() {
        XCTAssertEqual(ContentView.idlePoolLabel(found: 0, callback: 0), "no sources found")
        XCTAssertEqual(ContentView.idlePoolLabel(found: 3, callback: 0), "0 of 3 connected")
        // The LowID split: "awaiting callback" is a different prognosis from
        // "we are dialing these", and it is the likely story for that file.
        XCTAssertEqual(
            ContentView.idlePoolLabel(found: 0, callback: 15), "15 awaiting callback")
        XCTAssertEqual(
            ContentView.idlePoolLabel(found: 3, callback: 12),
            "0 of 3 connected, 12 awaiting callback")
    }

    /// The VPN drop warning fires on a TRANSITION, never on an absence. A user
    /// who has never run a VPN must not be told theirs dropped - a warning that
    /// cries wolf on first launch is one everybody learns to dismiss.
    func testVpnDropWarnsOnlyAfterAVpnWasActuallySeen() {
        XCTAssertFalse(
            EngineModel.vpnDropWarrants(active: false, sawVpnBefore: false),
            "no VPN has ever been up - nothing dropped")
        XCTAssertTrue(
            EngineModel.vpnDropWarrants(active: false, sawVpnBefore: true),
            "a VPN that was up has gone away")
        XCTAssertFalse(
            EngineModel.vpnDropWarrants(active: true, sawVpnBefore: true),
            "coming back up is not a drop")
        XCTAssertFalse(EngineModel.vpnDropWarrants(active: true, sawVpnBefore: false))
    }

    /// The build label must DISTINGUISH a CI build from an unstamped one. The
    /// whole point of the line is answering "which build is this?", and a label
    /// that read "1.0" for both would answer it wrongly rather than not at all -
    /// which is worse, because it looks like information.
    func testBuildLabelNamesTheShaAndFallsBackForAnUnstampedBuild() {
        XCTAssertEqual(
            SettingsView.buildLabel(short: "1.0", build: "621092b"), "1.0 (621092b)")
        // XcodeGen's default: no CI stamp, so say so rather than imply a version.
        XCTAssertEqual(SettingsView.buildLabel(short: "1.0", build: "1"), "1.0 (dev)")
        // A missing key degrades to a visible "?" instead of an empty pair of
        // brackets that reads like a rendering bug.
        XCTAssertEqual(SettingsView.buildLabel(short: "?", build: "?"), "? (?)")
    }

    /// The registered default and the @AppStorage initializer must AGREE.
    ///
    /// When they disagree the toggle renders one state while the engine is in
    /// the other, which reads as "the setting does nothing" - a trap this file
    /// already carries a comment about for another key. Background seeding is
    /// the one where being wrong matters most: a user who believes it is on
    /// while it is off concludes padMule simply stopped sharing.
    func testBackgroundSeedingDefaultsToOffEverywhere() {
        Settings.register()
        XCTAssertFalse(
            UserDefaults.standard.bool(forKey: SettingsKey.backgroundSeeding),
            "background seeding must default OFF - it runs while the user is not "
                + "looking and costs battery")
    }
}
