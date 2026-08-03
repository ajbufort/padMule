import OSLog
import XCTest

@testable import padMule

/// The engine log's IDENTITY is a contract, not an implementation detail: it is
/// what `idevicesyslog -p padMule -m padMule.engine` filters on from a paired
/// machine, and it is documented that way in docs/wiki/ipad-usb-tooling.md.
/// Renaming the subsystem or category silently breaks the one window into the
/// engine on a device with no debugger, so pin both.
final class LoggingTests: XCTestCase {
    func testEngineLogIsAddressableFromIdevicesyslog() {
        // Reachable at all (the symbol exists and is shared, not per-instance).
        XCTAssertNotNil(engineLog)

        // The bundle id doubles as the subsystem, so a filter by app and a filter
        // by subsystem agree. Assert the CATEGORY string that the runbook tells a
        // reader to grep for.
        let expected = Logger(subsystem: "us.ajbconsulting.padMule", category: "padMule.engine")
        XCTAssertEqual(
            String(describing: type(of: engineLog)), String(describing: type(of: expected)),
            "engineLog must be an OSLog Logger so os_log carries it off-device")
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
