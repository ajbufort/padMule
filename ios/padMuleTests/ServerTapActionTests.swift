import XCTest

@testable import padMule

/// What a Servers-row tap DOES, per engine lifecycle state - the pure rule
/// (`EngineModel.serverTapAction`), called directly rather than restated, per
/// the sharingDecision lesson in SettingsTests.
///
/// THE DEFECT THIS PINS AGAINST (on glass 2026-08-09, build 4bf04b1, twice):
/// tapping a server row while the engine was STOPPED dialed anyway -
/// `Engine::connect_to_server` guards only `offline`, never state - so the
/// app logged in with its listener down, earned a LowID that stuck across the
/// next Start, and showed "State stopped" beside "eD2k Connected, LowID".
/// The rule now routes every tap on a non-running engine through
/// startThenConnect, and `connectServer` runs the start and the dial in one
/// serial work item.
///
/// HONEST LIMITS - what these tests deliberately cannot reach:
/// - The ATOMICITY: that `connectServer` issues `e.start()` and the dial
///   inside ONE `work` item, which is what stops a queued shutdown from
///   landing between them. That is DispatchQueue wiring, not a pure rule.
/// - The ORDERING inside the engine: that `Engine::start()` awaits the
///   listener bind and port mapping before returning lives (and is
///   commented) in engine.rs on the Rust side.
/// - The OUTCOME: that a repaired tap then earns a HighID needs a real
///   server's connect-back test - a device pass (tap a row while stopped;
///   Status and eD2k must agree; the ID must be HighID once running).
/// - The row-local `srv.alive` gate and the notice text render in SwiftUI,
///   outside XCTest's reach.
@MainActor
final class ServerTapActionTests: XCTestCase {
    private let row = "192.0.2.1:4661"
    private let other = "198.51.100.7:4661"

    /// Tap while RUNNING on a row that is not the live login: a plain dial.
    /// No start detour appears in the decision - the atomic ensure-start in
    /// `connectServer` is a no-op on a running engine.
    func testTapWhileRunningDialsDirectly() {
        XCTAssertEqual(
            EngineModel.serverTapAction(rowAddr: row, state: .running, liveServerAddr: nil),
            .connect)
        XCTAssertEqual(
            EngineModel.serverTapAction(rowAddr: row, state: .running, liveServerAddr: other),
            .connect,
            "a row other than the live login is a reconnect target, not ignored")
    }

    /// Tap while STOPPED: the engine must be brought up before the dial. This
    /// is the defect case - a bare .connect here is a listener-down login and
    /// a guaranteed LowID.
    func testTapWhileStoppedStartsBeforeConnecting() {
        XCTAssertEqual(
            EngineModel.serverTapAction(rowAddr: row, state: .stopped, liveServerAddr: nil),
            .startThenConnect)
    }

    /// THE GLASS STATE ITSELF: stopped, yet a live login is present (the
    /// split-brain the guardless dial created), and the tap lands on that
    /// very row. It must be startThenConnect - the tap REPAIRS the
    /// incoherence with a proper start + fresh login. An .ignore here would
    /// swallow the one gesture that can fix the screen; a .connect would
    /// re-run the defect.
    func testTapOnTheSplitBrainRowRepairsRatherThanIgnores() {
        XCTAssertEqual(
            EngineModel.serverTapAction(rowAddr: row, state: .stopped, liveServerAddr: row),
            .startThenConnect,
            "stopped-but-logged-in must be repaired by the tap, not swallowed")
    }

    /// Tap while PAUSED: paused released the listener too (pause() drops the
    /// sockets), so it takes the same start-first route as stopped. In
    /// practice a resume() is already queued ahead on the serial work queue
    /// when this can happen (the brief post-foreground window), and the
    /// ensure-start no-ops by dial time - the decision stays safe either way.
    func testTapWhilePausedStartsBeforeConnecting() {
        XCTAssertEqual(
            EngineModel.serverTapAction(rowAddr: row, state: .paused, liveServerAddr: nil),
            .startThenConnect)
    }

    /// Tap on the ALREADY-CONNECTED row while running: nothing to do. This
    /// composes `serverRowConnected`, so "the row that wears the checkmark"
    /// and "the row whose tap is swallowed" are one measurement by
    /// construction.
    func testTapOnTheConnectedRowIsIgnored() {
        XCTAssertEqual(
            EngineModel.serverTapAction(rowAddr: row, state: .running, liveServerAddr: row),
            .ignore)
    }

    /// SEEDING holds the listener and the server login - that is its whole
    /// point - so a dial needs no start detour. Documented-unreachable on
    /// glass (seeding exists only while backgrounded, when no Servers screen
    /// is up), pinned so the case is a decision rather than an accident.
    func testTapWhileSeedingDialsDirectly() {
        XCTAssertEqual(
            EngineModel.serverTapAction(rowAddr: row, state: .seeding, liveServerAddr: nil),
            .connect)
    }
}
