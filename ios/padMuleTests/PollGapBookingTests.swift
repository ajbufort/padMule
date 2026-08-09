import XCTest

@testable import padMule

/// The poll-gap booking rule behind "Longest poll gap" - the device-pass
/// regression bar ("Longest poll gap 1.0-1.1s"), which exists to name
/// engine-lock contention and nothing else.
///
/// A background episode has polluted it twice, through two different holes: a
/// seeding throttle parked it at ~5s (fixed by clearing the baseline on
/// skipped ticks), and then an app suspension booked its whole duration -
/// 10.0s and 84.8s on glass, 2026-08-09, build 4bf04b1 - THROUGH a fix that
/// cleared the baseline on return to foreground, because work queued before
/// the freeze drains on thaw before scenePhase delivers .active. The rule
/// under test is the replacement: a `backgrounded` flag armed on the way OUT
/// discards every interval while a background episode is open.
///
/// DISCLOSED LIMIT, the same one the sibling lifecycle fixes carry: these
/// tests pin the PURE rule only. That `enterBackground()` raises the flag
/// before the freeze, that `leaveBackground()` drops it, and that the booking
/// closure in `refreshFast()` consults it are UIKit-lifecycle wiring no unit
/// test can reach; only glass can verify the assembled behaviour (suspend
/// with seeding off ~10s and ~85s, resume, read "Longest poll gap").
@MainActor
final class PollGapBookingTests: XCTestCase {
    private let t0 = Date(timeIntervalSinceReferenceDate: 1_000_000)

    /// The instrument's bread and butter: a normal foreground interval books
    /// and moves the baseline forward.
    func testANormalForegroundIntervalBooks() {
        let r = EngineModel.bookPollGap(
            now: t0.addingTimeInterval(1.0), last: t0, backgrounded: false, maxGap: 0)
        XCTAssertEqual(r.maxGap, 1.0, accuracy: 0.001)
        XCTAssertEqual(r.baseline, t0.addingTimeInterval(1.0))
    }

    /// The defect: an interval spanning a background episode must book
    /// NOTHING - and must poison the baseline, so the NEXT booking cannot
    /// measure across the episode either. The 84.8s glass number is the
    /// exact shape: baseline armed ~1s into the background grace window by
    /// pause()'s completion refresh, booking drained at thaw.
    func testABackgroundedIntervalBooksNothingAndPoisonsTheBaseline() {
        let r = EngineModel.bookPollGap(
            now: t0.addingTimeInterval(84.8), last: t0, backgrounded: true, maxGap: 1.0)
        XCTAssertEqual(r.maxGap, 1.0, "a suspension booked into the contention bar is the defect")
        XCTAssertNil(
            r.baseline,
            "a surviving baseline hands the suspension to the NEXT booking - the same defect, one tick later"
        )
    }

    /// The first booking after an episode (baseline poisoned) only re-arms.
    func testTheFirstBookingAfterAnEpisodeOnlyRearms() {
        let r = EngineModel.bookPollGap(
            now: t0, last: nil, backgrounded: false, maxGap: 1.1)
        XCTAssertEqual(r.maxGap, 1.1, accuracy: 0.001)
        XCTAssertEqual(r.baseline, t0)
    }

    /// The reason the field exists: a long FOREGROUND stall must STILL book.
    /// This is the test that forbids the tempting wrong fix - a magnitude
    /// threshold ("ignore gaps over N seconds") passes the suspension test by
    /// silently discarding the engine-lock stall the instrument was built to
    /// catch. 20.6s is the measured 8cg freeze this bar guards against.
    func testALongForegroundStallStillBooks() {
        let r = EngineModel.bookPollGap(
            now: t0.addingTimeInterval(20.6), last: t0, backgrounded: false, maxGap: 1.1)
        XCTAssertEqual(r.maxGap, 20.6, accuracy: 0.001, "a foreground stall IS the signal")
    }

    /// A high-water mark never goes down: a shorter interval keeps the max.
    func testTheMaxIsARunningMax() {
        let r = EngineModel.bookPollGap(
            now: t0.addingTimeInterval(0.5), last: t0, backgrounded: false, maxGap: 2.0)
        XCTAssertEqual(r.maxGap, 2.0, accuracy: 0.001)
        XCTAssertEqual(r.baseline, t0.addingTimeInterval(0.5))
    }
}
