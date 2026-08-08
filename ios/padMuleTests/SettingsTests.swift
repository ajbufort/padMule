import XCTest

@testable import padMule

/// The Tier-0 settings logic that is pure decision, tested without an engine.
/// The load-bearing rule is effective-sharing: the value pushed to the engine is
/// the user's wish ANDed with "not paused for a metered link", and getting it
/// wrong either leaks uploads onto a data plan or refuses to seed on Wi-Fi.
@MainActor
final class SettingsTests: XCTestCase {
    /// Calls the REAL rule (`EngineModel.sharingDecision`), not a copy of it.
    /// This test used to re-implement the expression in this file, which pinned
    /// the arithmetic and nothing else - it stayed green through a live bug in
    /// the CALLER, because the caller was never invoked. See
    /// `testAnIncidentalRecomputeCannotCancelThePublicAddressPause`.
    private func effectiveSharing(wants: Bool, pauseOnMetered: Bool, metered: Bool) -> Bool? {
        EngineModel.sharingDecision(
            wanted: wants,
            pauseOnMetered: pauseOnMetered,
            metered: metered,
            pausedForIpChange: false,
            userInitiated: false
        )
    }

    func testMeteredPauseOnlyBitesWhenAllThreeLineUp() {
        // Shares on Wi-Fi.
        XCTAssertEqual(effectiveSharing(wants: true, pauseOnMetered: true, metered: false), true)
        // Pauses on a metered link - the safety case.
        XCTAssertEqual(effectiveSharing(wants: true, pauseOnMetered: true, metered: true), false)
        // Metered but the user opted out of the pause: their choice wins.
        XCTAssertEqual(effectiveSharing(wants: true, pauseOnMetered: false, metered: true), true)
        // Leech mode stays leech mode regardless of network.
        XCTAssertEqual(effectiveSharing(wants: false, pauseOnMetered: true, metered: false), false)
        XCTAssertEqual(effectiveSharing(wants: false, pauseOnMetered: false, metered: true), false)
    }

    /// THE PUBLIC-ADDRESS PAUSE SURVIVES AN UNRELATED RECOMPUTE.
    ///
    /// When padMule notices its public address changed it pauses sharing and
    /// says so, because on iOS there is no VPN kill switch - continuing to seed
    /// would announce the new address. `Engine::set_sharing(true)` clears that
    /// pause on purpose ("the user has decided"), so anything that pushes `true`
    /// without the user deciding silently cancels the protection AND its banner.
    /// Walking onto cellular and back, or toggling "pause on cellular", both did
    /// exactly that.
    func testAnIncidentalRecomputeCannotCancelThePublicAddressPause() {
        // A network event or an unrelated Settings toggle: push NOTHING.
        XCTAssertNil(
            EngineModel.sharingDecision(
                wanted: true, pauseOnMetered: true, metered: false,
                pausedForIpChange: true, userInitiated: false
            ),
            "an incidental recompute must not resume seeding from a changed address"
        )
        // The user turning sharing on IS the decision that ends the pause.
        XCTAssertEqual(
            EngineModel.sharingDecision(
                wanted: true, pauseOnMetered: true, metered: false,
                pausedForIpChange: true, userInitiated: true
            ),
            true,
            "an explicit user choice still resumes sharing"
        )
        // Turning sharing OFF is always safe, so it is never suppressed - even
        // while paused, even when not user-initiated.
        XCTAssertEqual(
            EngineModel.sharingDecision(
                wanted: false, pauseOnMetered: false, metered: false,
                pausedForIpChange: true, userInitiated: false
            ),
            false,
            "the OFF direction is never gated"
        )
        // And with no pause in force the flag changes nothing.
        XCTAssertEqual(
            EngineModel.sharingDecision(
                wanted: true, pauseOnMetered: true, metered: false,
                pausedForIpChange: false, userInitiated: false
            ),
            true
        )
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

    /// The REGISTERED default for background seeding is OFF.
    ///
    /// It runs while the user is not looking and costs battery, so off is the
    /// only honest default; and when the registered default and the
    /// `@AppStorage` initializer disagree the toggle renders one state while the
    /// engine is in the other, which reads as "the setting does nothing".
    ///
    /// SCOPE, stated because the name used to over-claim: this checks the
    /// REGISTERED half only. The `@AppStorage` initializer lives in a
    /// `SettingsView` property wrapper that a unit test cannot read, so the two
    /// are kept in agreement by the comment at each site rather than by an
    /// assertion. Calling that "everywhere" implied a guard that does not exist.
    ///
    /// THIS TEST NEVER RAN UNTIL 2026-08-08. It called `Settings.register()` -
    /// no such type; it is `SettingsDefaults` - so the whole padMuleTests bundle
    /// failed to COMPILE from e3ed990 onward, and three device builds shipped
    /// with the Swift suite red because ship.sh did not check it.
    func testBackgroundSeedingRegisteredDefaultIsOff() {
        SettingsDefaults.register()
        XCTAssertFalse(
            UserDefaults.standard.bool(forKey: SettingsKey.backgroundSeeding),
            "background seeding must default OFF - it runs while the user is not "
                + "looking and costs battery")
    }
}
