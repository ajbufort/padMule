import OSLog
import XCTest

@testable import padMule

/// The engine log's IDENTITY is a contract, not an implementation detail: it is
/// what `idevicesyslog -p padMule -m padMule.engine` filters on from a paired
/// machine, and it is documented that way in docs/wiki/ipad-usb-tooling.md.
/// Renaming the subsystem or category silently breaks the one window into the
/// engine on a device with no debugger, so pin both.
///
/// HISTORY (2026-08-09): the original assertion here compared
/// `String(describing: type(of: engineLog))` against the same expression on a
/// freshly built Logger - both sides read "Logger" whatever the strings say, so
/// the test could not fail and neither string was pinned. OSLog's Logger
/// exposes no accessors, so the strings are single-sourced in
/// `EngineLogIdentity` (the only spelling of them in the app target;
/// `engineLog` is constructed from it) and THOSE are pinned here. Residual
/// gap, stated: a Logger built from fresh literals would evade this test -
/// the guard is that no such literal exists outside `EngineLogIdentity`.
final class LoggingTests: XCTestCase {
    func testEngineLogIdentityMatchesTheRunbook() {
        XCTAssertEqual(
            EngineLogIdentity.subsystem, "us.ajbconsulting.padMule",
            "the runbook filters `idevicesyslog -p padMule` by this subsystem; renaming it breaks the only window into the engine on a device with no debugger")
        XCTAssertEqual(
            EngineLogIdentity.category, "padMule.engine",
            "the runbook greps `-m padMule.engine`; renaming the category breaks the documented filter")
    }

    /// The subsystem doubles as the app's bundle id, so a filter by app and a
    /// filter by subsystem agree. CI's simulator test host IS the padMule app
    /// (TEST_HOST), so this reads the real bundle id, not a fixture.
    func testSubsystemIsTheAppBundleId() {
        XCTAssertEqual(
            Bundle.main.bundleIdentifier, EngineLogIdentity.subsystem,
            "filter-by-app and filter-by-subsystem must agree, or the two documented idevicesyslog commands return different lines")
    }

    /// Logging must never crash on the values the engine actually emits - a MOTD
    /// is attacker-influenced text that arrives straight from a server, and it is
    /// interpolated into the log line.
    func testLoggingHostileServerTextIsSafe() {
        let nasty = "%@ %n %s \u{0000} \\ \" ' <script> \u{1F600} " + String(repeating: "A", count: 4096)
        // Must not trap: os_log interpolation is type-safe, unlike a printf format.
        engineLog.notice("server: \(nasty, privacy: .public)")
        XCTAssertTrue(true, "interpolating hostile server text must not crash")
    }
}
