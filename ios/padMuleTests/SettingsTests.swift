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
    ///
    /// Since 2026-08-09 the pause also PERSISTS: the engine writes a marker
    /// file the moment the guard fires and restores it at construction, and
    /// `applyEffectiveSharing` consults the ENGINE's value directly (the
    /// published mirror is poll-fed and launch-stale at boot). So the boot
    /// preference push after a paused relaunch is exactly the nil case below:
    /// wanted ON, paused, not user-initiated -> push nothing, stay paused,
    /// keep saying why. The cross-launch round trip itself is engine-tested
    /// (`the_ip_change_pause_survives_a_relaunch_until_the_user_resumes`).
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

    /// WHICH PAUSE IS IN FORCE, through the REAL rule (`SharingStatus.of`) that
    /// both sharing screens render - not a restatement of it, per the
    /// `sharingDecision` lesson above.
    ///
    /// The two defects this pins: the Settings footer knew only the metered
    /// pause (so during an address-change pause it showed "Share uploads" ON
    /// and stated padMule was serving files), and the Shared screen knew only
    /// the address-change pause (so a metered pause read as the user's own
    /// Leech Mode). Every case below is one screen's former blind spot.
    func testSharingStatusNamesWhicheverPauseIsActuallyInForce() {
        // The two plain states.
        XCTAssertEqual(
            SharingStatus.of(
                wanted: true, pauseOnMetered: true, metered: false, pausedForIpChange: false),
            .sharing)
        XCTAssertEqual(
            SharingStatus.of(
                wanted: false, pauseOnMetered: true, metered: false, pausedForIpChange: false),
            .leech)
        // The metered pause - the Shared screen's blind spot.
        XCTAssertEqual(
            SharingStatus.of(
                wanted: true, pauseOnMetered: true, metered: true, pausedForIpChange: false),
            .pausedForMeteredLink,
            "a metered pause must not read as the user's own Leech Mode")
        // The address-change pause - the Settings footer's blind spot.
        XCTAssertEqual(
            SharingStatus.of(
                wanted: true, pauseOnMetered: false, metered: false, pausedForIpChange: true),
            .pausedForIpChange,
            "an address-change pause must not read as sharing")
        // BOTH at once: the address change wins, because it is the one that
        // does NOT end by itself. Naming the metered pause here would promise a
        // resumption on Wi-Fi that sharingDecision refuses to perform - it
        // returns nil for exactly these inputs.
        XCTAssertEqual(
            SharingStatus.of(
                wanted: true, pauseOnMetered: true, metered: true, pausedForIpChange: true),
            .pausedForIpChange,
            "the pause that needs the user must outrank the one that clears itself")
        XCTAssertNil(
            EngineModel.sharingDecision(
                wanted: true, pauseOnMetered: true, metered: true,
                pausedForIpChange: true, userInitiated: false),
            "the Wi-Fi promise would be false here - which is why the caption must not make it")
        // Neither pause applies to a user who is not trying to share. The
        // engine really can latch the address-change flag with sharing already
        // off: `note_public_id` does not consult it, and `set_sharing(false)`
        // deliberately leaves it alone.
        XCTAssertEqual(
            SharingStatus.of(
                wanted: false, pauseOnMetered: true, metered: true, pausedForIpChange: true),
            .leech,
            "with the preference off there is no choice left to have paused")
    }

    /// THE SCREEN AND THE ENGINE CANNOT DISAGREE, over EVERY input combination.
    ///
    /// Two rules describe one thing: `SharingStatus.of` decides what the screens
    /// say, `EngineModel.sharingDecision` decides what the engine is told. Both
    /// REAL methods are called here, and the invariant is that `.sharing` comes
    /// back for exactly the inputs that push `true`. That is the whole reason a
    /// caption can be trusted - and it is the property that broke when the two
    /// screens each carried their own half of the rule.
    func testTheCaptionRuleAndTheEnginePushCannotDisagree() {
        var checked = 0
        for wanted in [false, true] {
            for pauseOnMetered in [false, true] {
                for metered in [false, true] {
                    for ipPaused in [false, true] {
                        let inputs =
                            "wanted \(wanted), pauseOnMetered \(pauseOnMetered), "
                            + "metered \(metered), ipPaused \(ipPaused)"
                        let status = SharingStatus.of(
                            wanted: wanted, pauseOnMetered: pauseOnMetered,
                            metered: metered, pausedForIpChange: ipPaused)
                        // Not user-initiated: this is the launch push and every
                        // incidental recompute, which is the direction that can
                        // lie to the user.
                        let pushed = EngineModel.sharingDecision(
                            wanted: wanted, pauseOnMetered: pauseOnMetered,
                            metered: metered, pausedForIpChange: ipPaused,
                            userInitiated: false)
                        XCTAssertEqual(
                            status == .sharing, pushed == true,
                            "the screen says \(status) while the engine is pushed "
                                + "\(String(describing: pushed)) - \(inputs)")
                        if status != .sharing {
                            XCTAssertNotEqual(
                                pushed, true,
                                "a caption that explains why sharing is off must never ride "
                                    + "along with a push that turns it on - \(inputs)")
                        }
                        checked += 1
                    }
                }
            }
        }
        // COUNT that the loop actually ran the whole space - a nested loop that
        // silently iterated nothing is a green test that proves nothing.
        XCTAssertEqual(checked, 16, "all 16 input combinations must be compared")
    }

    /// ONE STATE, ONE SET OF WORDS. The captions live on `SharingStatus` so the
    /// two screens physically cannot word the same state differently; these pin
    /// the promises inside them, which is what made the old copies wrong.
    func testEachSharingStateGetsItsOwnWordsAndOnlyOneOfThemPromisesWiFi() {
        let all: [SharingStatus] = [.sharing, .leech, .pausedForIpChange, .pausedForMeteredLink]
        XCTAssertEqual(
            Set(all.map { $0.caption }).count, all.count,
            "four distinct states need four distinct captions")
        // "It resumes automatically on Wi-Fi" is TRUE of the metered pause and
        // FALSE of the address-change pause, which is exactly the sentence the
        // Settings footer used to show during an address-change pause.
        XCTAssertTrue(SharingStatus.pausedForMeteredLink.caption.contains("Wi-Fi"))
        for state in all where state != .pausedForMeteredLink {
            XCTAssertFalse(
                state.caption.contains("Wi-Fi"),
                "only the metered pause ends on its own, so only it may promise Wi-Fi - \(state)")
        }
        // "Leech Mode" credits the USER with the decision, so no padMule-imposed
        // pause may use it - the Shared screen's old defect.
        XCTAssertTrue(SharingStatus.leech.caption.contains("Leech Mode"))
        for state in all where state != .leech {
            XCTAssertFalse(
                state.caption.contains("Leech Mode"),
                "a pause padMule imposed must not be credited to the user - \(state)")
        }
        // And only the sharing state may claim padMule is serving - the
        // Settings footer's old defect.
        XCTAssertTrue(SharingStatus.sharing.caption.contains("padMule serves"))
        for state in all where state != .sharing {
            XCTAssertFalse(
                state.caption.contains("padMule serves"),
                "nothing but the sharing state may say padMule is serving files - \(state)")
        }
    }

    func testDefaultsRegisterTheProtectiveValues() {
        // Both the sharing default and the metered-pause default must be ON, so a
        // fresh install protects a data plan without the user configuring anything.
        // Call the REAL registration (not a restated dictionary) - a test that
        // registers its own defaults only proves UserDefaults.register works, and
        // would stay green if SettingsDefaults flipped either key to false.
        SettingsDefaults.register()
        let d = UserDefaults.standard
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

    /// THE DEFAULT SERVER-LIST URL IS `https://`, AND `register()` SEEDS IT.
    ///
    /// The SCHEME is the load-bearing part, so that is what the first assertion
    /// pins rather than the whole literal. A URL reaching the engine from this
    /// screen is a USER url: `Engine::update_server_list` fetches it exactly as
    /// written, and only the engine's BUILT-IN bootstrap retries in the clear
    /// when a TLS attempt never lands. Nothing downstream upgrades this string,
    /// and `register(defaults:)` supplies a value only for an ABSENT key - so a
    /// plaintext default here would be plaintext for good on every install that
    /// took it.
    ///
    /// NO TEST READ THIS CONSTANT UNTIL 2026-08-12. The five
    /// `http://upd.emule-security.org/server.met` literals in the test below are
    /// a fixture that test writes into UserDefaults itself, not a pin of the
    /// constant - so a silent revert to `http://` passed the entire suite.
    ///
    /// HONEST LIMIT on the second assertion: it compares against the constant,
    /// so the host may move without this test objecting, and a literal restated
    /// inside `register()` would pass it too. What it catches is the seeding
    /// going away or pointing somewhere else; the scheme pin above is what
    /// catches a downgrade.
    func testDefaultServerListUrlIsHttpsAndSeedsTheRegisteredDefault() {
        XCTAssertTrue(
            EngineModel.defaultServerListUrl.hasPrefix("https://"),
            "the default server-list URL must be https - a URL from this path is a USER "
                + "url the engine never downgrades, so plaintext here is plaintext for good")

        // Isolate the key the way the test below does: the REGISTERED default is
        // only visible while the persistent domain holds no value of its own.
        let d = UserDefaults.standard
        let saved = d.stringArray(forKey: SettingsKey.serverListUrls)
        defer {
            if let saved {
                d.set(saved, forKey: SettingsKey.serverListUrls)
            } else {
                d.removeObject(forKey: SettingsKey.serverListUrls)
            }
        }
        d.removeObject(forKey: SettingsKey.serverListUrls)

        SettingsDefaults.register()
        XCTAssertEqual(
            d.stringArray(forKey: SettingsKey.serverListUrls),
            [EngineModel.defaultServerListUrl],
            "register() must seed padMule.serverListUrls with the constant's value - that "
                + "is the list a fresh install starts with, and it is never revisited")
    }

    /// Calls the REAL `EngineModel.addServerListUrl`, not a restatement of its
    /// rule - the restated version pinned an accept function this file wrote
    /// itself and would have stayed green through any change in the model. The
    /// method touches only UserDefaults + `notice`, so it runs fine without an
    /// engine; the key is saved and restored so the test leaves no residue in
    /// the shared defaults.
    func testServerListUrlValidationAndDedupThroughTheRealMethod() {
        let d = UserDefaults.standard
        let saved = d.stringArray(forKey: SettingsKey.serverListUrls)
        defer {
            if let saved {
                d.set(saved, forKey: SettingsKey.serverListUrls)
            } else {
                d.removeObject(forKey: SettingsKey.serverListUrls)
            }
        }
        d.set(["http://upd.emule-security.org/server.met"], forKey: SettingsKey.serverListUrls)
        let model = EngineModel()

        model.addServerListUrl("ftp://nope/server.met")
        XCTAssertEqual(
            model.serverListUrls, ["http://upd.emule-security.org/server.met"],
            "a non-http(s) scheme must be rejected")
        XCTAssertNotNil(model.notice, "a rejected URL must tell the user why")
        model.notice = nil

        model.addServerListUrl("upd.emule-security.org/server.met")  // no scheme
        XCTAssertEqual(model.serverListUrls.count, 1)

        model.addServerListUrl("http://upd.emule-security.org/server.met")  // dup
        XCTAssertEqual(model.serverListUrls.count, 1, "a duplicate must not be re-added")

        model.addServerListUrl("  https://ed2k.example/list.met  ")  // trims, accepts
        XCTAssertEqual(
            model.serverListUrls,
            ["http://upd.emule-security.org/server.met", "https://ed2k.example/list.met"])
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
    ///
    /// Incognito defaults ON (Anthony, 2026-08-11). It costs the
    /// padMule-to-padMule enhancement channel - but that channel is DEFERRED
    /// and unbuilt, so the capability it disables is theoretical today while
    /// the exposure it removes is real on every connection.
    func testIncognitoRegisteredDefaultIsOn() {
        SettingsDefaults.register()
        XCTAssertTrue(
            UserDefaults.standard.bool(forKey: SettingsKey.incognito),
            "incognito must default ON - protection first, and the enhancement "
                + "channel it disables is not built yet")
    }

    /// Browsing defaults to NOBODY, which is also eMule's own default
    /// (`SeeShare`, vsfaNobody). Letting any peer list everything you share is
    /// not something to turn on for someone.
    func testAllowBrowseRegisteredDefaultIsNobody() {
        SettingsDefaults.register()
        XCTAssertFalse(
            UserDefaults.standard.bool(forKey: SettingsKey.allowBrowse),
            "browsing must default to Nobody - eMule defaults there too")
    }

    func testBackgroundSeedingRegisteredDefaultIsOff() {
        SettingsDefaults.register()
        XCTAssertFalse(
            UserDefaults.standard.bool(forKey: SettingsKey.backgroundSeeding),
            "background seeding must default OFF - it runs while the user is not "
                + "looking and costs battery")
    }

    /// The Downloads defaults, via the real `register()` path like the pins
    /// above: max-active 0 (unlimited - the shipped behaviour; a nonzero
    /// default would silently start queueing downloads on a fresh install) and
    /// priority 1 (Normal). HONEST LIMIT on the first pin: `integer(forKey:)`
    /// returns 0 for an absent key too, so it cannot distinguish "registered
    /// as 0" from "not registered" - what it CAN catch is the registered
    /// default changing to a nonzero value, which is the regression that
    /// matters.
    func testDownloadsDefaultsAreUnlimitedAndNormalPriority() {
        SettingsDefaults.register()
        let d = UserDefaults.standard
        XCTAssertEqual(
            d.integer(forKey: SettingsKey.maxActiveDownloads), 0,
            "0 = unlimited, the shipped behaviour")
        XCTAssertEqual(
            d.integer(forKey: SettingsKey.defaultPriority), 1,
            "new downloads must default to Normal priority")
    }

    /// THE SERVERS LIST CANNOT OUTLIVE THE LOGIN IT REMEMBERS. The real rule
    /// (`EngineModel.serverRowConnected`, the same call `serverRow` styles by,
    /// not a copy - the sharingDecision lesson above), which keys the
    /// connected treatment on the LIVE login instead of the row snapshot's
    /// probe-time `connected` flag. On glass 2026-08-09: after toolbar
    /// Stop -> Start the list kept the previous server green + checkmarked
    /// while Status honestly read "Not connected". HONEST LIMIT: this pins
    /// the rule, not the wiring - that `serverRow` feeds it `model.state` and
    /// `model.server?.addr` is only checkable on glass.
    func testServerRowConnectedDiscriminatesLiveLoginFromStaleSnapshot() {
        // Genuinely connected: running, and the live login IS this row. The
        // styling must survive the fix - green when true is as load-bearing
        // as grey when stale.
        XCTAssertTrue(
            EngineModel.serverRowConnected(
                rowAddr: "192.0.2.1:4661", state: .running, liveServerAddr: "192.0.2.1:4661"))
        // The on-glass defect, as the helper sees it: Stop -> Start leaves the
        // engine running with NO live login while the row snapshot still
        // remembers one. No login, no connected styling - a rule reading the
        // snapshot flag could not fail this case, because the flag is not an
        // input at all.
        XCTAssertFalse(
            EngineModel.serverRowConnected(
                rowAddr: "192.0.2.1:4661", state: .running, liveServerAddr: nil),
            "a remembered identity must not style a row connected after Stop -> Start")
        // Stopped outright with the login address still present. TWO real
        // routes into this input, not one: the ~1s poll lag while shutdown
        // lands, and - found on glass 2026-08-09, build 4bf04b1 - a login the
        // then-guardless connect-while-stopped path established (state
        // stopped, serverInfo present, STABLE). The second route is now
        // unreachable by construction: serverTapAction starts the engine
        // before every dial (see ServerTapActionTests, which pins that this
        // very input gets startThenConnect, not a swallowed tap). Either way
        // the row must not read connected - the treatment follows the
        // coherent whole, never one half of a split brain.
        XCTAssertFalse(
            EngineModel.serverRowConnected(
                rowAddr: "192.0.2.1:4661", state: .stopped, liveServerAddr: "192.0.2.1:4661"),
            "not Running-and-connected means no row is styled connected")
        // A row OTHER than the live login stays unstyled - the match is an
        // identity, not a boolean.
        XCTAssertFalse(
            EngineModel.serverRowConnected(
                rowAddr: "198.51.100.7:4661", state: .running, liveServerAddr: "192.0.2.1:4661"))
    }
}
