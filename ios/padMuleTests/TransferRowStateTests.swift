import XCTest

@testable import padMule

/// Pins the row-badge rule (eMule 0.70b vocabulary + padMule's Queued). The
/// VIEW calls this same helper, so the rule cannot drift between the test and
/// the row - the "a test that re-implements the rule cannot catch the caller"
/// lesson applied at authoring time.
///
/// SCOPE, stated: engine-stopped and per-file-paused both produce `.paused`,
/// so their MUTUAL precedence is unobservable through this API and no test
/// here claims to pin it. What is observable - and pinned - is that Done beats
/// everything, that either Paused cause beats Queued, and that the engine
/// mapping covers every non-running state.
final class TransferRowStateTests: XCTestCase {
    func testDoneBeatsEverything() {
        XCTAssertEqual(
            TransferRowState.badge(
                complete: true, engineStopped: true, fileStopped: false, filePaused: true, queued: true),
            .done)
    }

    /// The engine being stopped shows Paused even on a row that would
    /// otherwise say Queued. (filePaused is false here on purpose: with it
    /// true the outcome is `.paused` either way, so that input pair cannot
    /// discriminate anything - this test's old name claimed the stopped-over-
    /// paused precedence, which no observable output can witness.)
    func testEngineStoppedShowsPausedEvenForAQueuedRow() {
        XCTAssertEqual(
            TransferRowState.badge(
                complete: false, engineStopped: true, fileStopped: false, filePaused: false, queued: true),
            .paused)
    }

    func testFilePausedSaysPausedAndBeatsQueued() {
        XCTAssertEqual(
            TransferRowState.badge(
                complete: false, engineStopped: false, fileStopped: false, filePaused: true, queued: true),
            .paused)
    }

    func testQueuedSaysQueued() {
        XCTAssertEqual(
            TransferRowState.badge(
                complete: false, engineStopped: false, fileStopped: false, filePaused: false, queued: true),
            .queued)
    }

    func testAnActiveRowHasNoBadge() {
        XCTAssertNil(
            TransferRowState.badge(
                complete: false, engineStopped: false, fileStopped: false, filePaused: false, queued: false))
    }


    /// STOP is a distinct badge and must beat the file's own pause, because
    /// stop pauses on the way through: a stopped row is ALWAYS also paused, so
    /// testing pause first would swallow every stopped row and the action
    /// would be invisible on screen - which is the whole reason the flag was
    /// surfaced through the FFI at all.
    func testFileStoppedSaysStoppedAndBeatsFilePaused() {
        XCTAssertEqual(
            TransferRowState.badge(
                complete: false, engineStopped: false, fileStopped: true,
                filePaused: true, queued: true),
            .stopped)
    }

    /// The ENGINE being stopped still wins: when nothing is running every row
    /// is halted for the same reason, and saying "Stopped" on one of them
    /// would imply a per-file state the user never chose.
    func testEngineStoppedBeatsAFileStoppedRow() {
        XCTAssertEqual(
            TransferRowState.badge(
                complete: false, engineStopped: true, fileStopped: true,
                filePaused: true, queued: true),
            .paused)
    }

    func testStoppedLabelIsExactly() {
        XCTAssertEqual(TransferRowState.Badge.stopped.label, "Stopped")
    }

    /// The `engineStopped` input, derived from the ENGINE state: every
    /// non-running state halts downloads. `.stopped` was omitted at the call
    /// site (which enumerated `.paused || .seeding` inline), so after the user
    /// tapped Stop an incomplete row lost its badge and read as a live
    /// download - breaking the header contract "each transfer row carries a
    /// Paused badge". All four EngineStateFfi cases are enumerated, and the
    /// helper is written as `!= .running` so any FUTURE engine state defaults
    /// to "stopped" - the safe direction for a badge that must never show a
    /// halted download as live.
    func testEngineStoppedCoversEveryNonRunningState() {
        XCTAssertFalse(TransferRowState.engineStopped(.running))
        XCTAssertTrue(TransferRowState.engineStopped(.paused))
        XCTAssertTrue(TransferRowState.engineStopped(.seeding))
        XCTAssertTrue(TransferRowState.engineStopped(.stopped), "the tap-Stop regression")
    }

    /// The visible labels, byte-for-byte. The view styles by CASE and renders
    /// `label`, so rewording a label can no longer silently revert the green
    /// Done styling - but the words themselves are still a contract with the
    /// user and the help screen, so pin them.
    func testBadgeLabelsAreByteIdentical() {
        XCTAssertEqual(TransferRowState.Badge.done.label, "Done")
        XCTAssertEqual(TransferRowState.Badge.paused.label, "Paused")
        XCTAssertEqual(TransferRowState.Badge.queued.label, "Queued")
    }
}
