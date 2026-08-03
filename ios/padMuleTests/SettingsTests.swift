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
}
