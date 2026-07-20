import XCTest

@testable import padMule

/// Tests for EngineModel.searchUpdate - the pure mapping from an FFI SearchOutcome
/// to a UI update (results / moreAvailable / notice). This is the new decision
/// logic behind #32 (throttle) and #13 (load more), tested without an engine.
final class OutcomeTests: XCTestCase {
    private func hit(_ name: String) -> SearchHit {
        SearchHit(
            hash: "0123456789abcdef0123456789abcdef",
            name: name, size: 1, sources: 1, completeSources: 0, fileType: "Other",
            artist: "", album: "", title: "", lengthSecs: 0, bitrate: 0, codec: "",
            rating: 0, trusted: true, warning: "", status: .new)
    }

    func testResultsSetHitsAndMoreFlag() {
        let u = EngineModel.searchUpdate(
            for: .results(hits: [hit("a"), hit("b")], moreAvailable: true),
            emptyMessage: "none")
        XCTAssertEqual(u.results?.map(\.name), ["a", "b"])
        XCTAssertEqual(u.moreAvailable, true)
        XCTAssertNil(u.notice, "a non-empty result set shows no notice")
    }

    func testEmptyResultsShowTheEmptyMessage() {
        let u = EngineModel.searchUpdate(
            for: .results(hits: [], moreAvailable: false), emptyMessage: "none found")
        XCTAssertEqual(u.results?.count, 0)
        XCTAssertEqual(u.moreAvailable, false)
        XCTAssertEqual(u.notice, "none found")
    }

    // The core #32 guarantee: a throttle notice must NOT blank the current results
    // (results == nil means "leave the list untouched"), and it tells the user how
    // long to wait.
    func testThrottledKeepsResultsAndWarns() {
        let u = EngineModel.searchUpdate(for: .throttled(waitSecs: 2), emptyMessage: "none")
        XCTAssertNil(u.results, "throttle must not clear the current results")
        XCTAssertNil(u.moreAvailable, "throttle must not clear the Load-more flag")
        XCTAssertEqual(u.notice, "Searching too fast - wait 2s and try again.")
    }
}
