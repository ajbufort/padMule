import XCTest

@testable import padMule

/// Pins `SourcesView.queueRankLabel` - the honesty rule for a source's queue
/// position. The rank is a SNAPSHOT a peer sent (OP_QUEUERANKING), not a live
/// value, so the label must carry its age and must go silent past eMule's own
/// freshness horizon (FILEREASKTIME = 29 min, the cadence at which eMule
/// re-asks every on-queue source or drops it). These run on an iPad simulator
/// in CI; there is no Apple toolchain locally.
final class QueueRankLabelTests: XCTestCase {
    /// Rank 0 is the wire's "never told / cleared" - shown as nothing, exactly
    /// as eMule renders an unknown rank.
    func testRankZeroSaysNothing() {
        XCTAssertNil(SourcesView.queueRankLabel(rank: 0, ageSecs: 0))
        XCTAssertNil(SourcesView.queueRankLabel(rank: 0, ageSecs: 30))
    }

    /// A fresh snapshot says so without inventing sub-minute precision.
    func testFreshRankSaysJustNow() {
        XCTAssertEqual(
            SourcesView.queueRankLabel(rank: 8, ageSecs: 0),
            "In queue: #8 (just now)")
        XCTAssertEqual(
            SourcesView.queueRankLabel(rank: 8, ageSecs: 59),
            "In queue: #8 (just now)")
    }

    /// From one minute on, the label carries the age in whole minutes.
    func testAgedRankCarriesMinutes() {
        XCTAssertEqual(
            SourcesView.queueRankLabel(rank: 8, ageSecs: 60),
            "In queue: #8 (1m ago)")
        XCTAssertEqual(
            SourcesView.queueRankLabel(rank: 11, ageSecs: 125),
            "In queue: #11 (2m ago)")
    }

    /// The horizon is eMule's own: 29 minutes. One second inside it the label
    /// still speaks; at the boundary it says nothing - a rank that old would
    /// have been refreshed or its source dropped by the authority, so showing
    /// it would claim knowledge we no longer have.
    func testHorizonIsTwentyNineMinutes() {
        XCTAssertEqual(
            SourcesView.queueRankLabel(rank: 8, ageSecs: 29 * 60 - 1),
            "In queue: #8 (28m ago)")
        XCTAssertNil(SourcesView.queueRankLabel(rank: 8, ageSecs: 29 * 60))
        XCTAssertNil(SourcesView.queueRankLabel(rank: 8, ageSecs: 90 * 60))
    }
}
