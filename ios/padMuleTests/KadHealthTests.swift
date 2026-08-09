import SwiftUI
import XCTest

@testable import padMule

/// Pins the "Kad network" health-row rule (`ContentView.kadRowHealth`). The
/// VIEW calls this same helper, so the rule cannot drift between the test and
/// the row.
///
/// The load-bearing case is `.seeding`: the 2026-08-09 engine change keeps the
/// Kad node alive while background seeding (it answers inbound requests,
/// publishes, and runs the liveness sweep; only the growth refresh is
/// suspended), so the row must report Kad exactly as it does while `.running`.
/// The old `== .running` guard said "Stopped" there - honest before that
/// change, dishonest status after it (lifecycle requirement 1).
@MainActor
final class KadHealthTests: XCTestCase {
    /// All four EngineStateFfi cases, discriminated. The contact count is
    /// nonzero on purpose for the down states: the engine STATE must decide
    /// "Stopped", not a stale count.
    func testOnlyRunningAndSeedingReportALiveKadNode() {
        XCTAssertEqual(
            ContentView.kadRowHealth(state: .running, contacts: 42).text,
            "OK (42 contacts)")
        XCTAssertEqual(
            ContentView.kadRowHealth(state: .seeding, contacts: 42).text,
            "OK (42 contacts)",
            "the 2026-08-09 defect: seeding keeps Kad up but the row said Stopped")
        XCTAssertEqual(
            ContentView.kadRowHealth(state: .paused, contacts: 42).text, "Stopped")
        XCTAssertEqual(
            ContentView.kadRowHealth(state: .stopped, contacts: 42).text, "Stopped")
    }

    /// Seeding reports EXACTLY what running reports - every band, both edges
    /// of the amber band, color and text. This is the requirement itself, so
    /// it is pinned as an equivalence rather than re-enumerating the bands.
    func testSeedingReportsIdenticallyToRunning() {
        for n: UInt32 in [0, 1, 9, 10, 42] {
            let run = ContentView.kadRowHealth(state: .running, contacts: n)
            let seed = ContentView.kadRowHealth(state: .seeding, contacts: n)
            XCTAssertEqual(seed.text, run.text, "contacts=\(n)")
            XCTAssertEqual(seed.color, run.color, "contacts=\(n)")
        }
    }

    /// The bands and their copy, byte-for-byte - the words are a contract with
    /// the user, chosen to be true while seeding too (a count, not an activity
    /// claim like the old "Bootstrapping").
    func testBandsAndCopy() {
        let stopped = ContentView.kadRowHealth(state: .stopped, contacts: 0)
        XCTAssertEqual(stopped.text, "Stopped")
        XCTAssertEqual(stopped.color, .secondary)

        let none = ContentView.kadRowHealth(state: .running, contacts: 0)
        XCTAssertEqual(none.text, "Not connected")
        XCTAssertEqual(none.color, .red)

        let low = ContentView.kadRowHealth(state: .running, contacts: 9)
        XCTAssertEqual(low.text, "Low contacts (9)")
        XCTAssertEqual(low.color, .orange)

        let ok = ContentView.kadRowHealth(state: .running, contacts: 10)
        XCTAssertEqual(ok.text, "OK (10 contacts)")
        XCTAssertEqual(ok.color, .green)
    }
}
