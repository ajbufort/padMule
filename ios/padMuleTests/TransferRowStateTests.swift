import XCTest

@testable import padMule

/// Pins the row-badge precedence (eMule 0.70b vocabulary + padMule's Queued).
/// The VIEW calls this same helper, so the rule cannot drift between the test
/// and the row - the "a test that re-implements the rule cannot catch the
/// caller" lesson applied at authoring time.
final class TransferRowStateTests: XCTestCase {
    func testDoneBeatsEverything() {
        XCTAssertEqual(
            TransferRowState.badge(
                complete: true, engineStopped: true, filePaused: true, queued: true),
            "Done")
    }

    func testEngineStoppedBeatsPerFileState() {
        XCTAssertEqual(
            TransferRowState.badge(
                complete: false, engineStopped: true, filePaused: false, queued: true),
            "Paused")
    }

    func testFilePausedSaysPausedAndBeatsQueued() {
        XCTAssertEqual(
            TransferRowState.badge(
                complete: false, engineStopped: false, filePaused: true, queued: true),
            "Paused")
    }

    func testQueuedSaysQueued() {
        XCTAssertEqual(
            TransferRowState.badge(
                complete: false, engineStopped: false, filePaused: false, queued: true),
            "Queued")
    }

    func testAnActiveRowHasNoBadge() {
        XCTAssertNil(
            TransferRowState.badge(
                complete: false, engineStopped: false, filePaused: false, queued: false))
    }
}
