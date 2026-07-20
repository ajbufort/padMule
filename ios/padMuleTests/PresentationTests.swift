import XCTest

@testable import padMule

/// Unit tests for the pure search-result presentation logic in
/// `SearchPresentation.swift` (sort + filter). These run on an iPad SIMULATOR in
/// CI (there is no Apple toolchain locally); the generated FFI type `SearchHit`
/// resolves from the host app binary via `@testable import padMule`.
final class PresentationTests: XCTestCase {
    /// A `SearchHit` with sensible defaults, overriding only what a test cares
    /// about - keeps each case readable and insulated from the record's full shape.
    private func hit(
        name: String = "file.bin",
        size: UInt64 = 1_000_000,
        sources: UInt32 = 1,
        completeSources: UInt32 = 0,
        fileType: String = "Other",
        lengthSecs: UInt32 = 0,
        bitrate: UInt32 = 0,
        trusted: Bool = true,
        status: HitStatusFfi = .new
    ) -> SearchHit {
        SearchHit(
            hash: "0123456789abcdef0123456789abcdef",
            name: name,
            size: size,
            sources: sources,
            completeSources: completeSources,
            fileType: fileType,
            artist: "",
            album: "",
            title: "",
            lengthSecs: lengthSecs,
            bitrate: bitrate,
            codec: "",
            rating: 0,
            trusted: trusted,
            warning: "",
            status: status
        )
    }

    /// Thin wrapper over `present` with test-friendly defaults.
    private func p(
        _ hits: [SearchHit],
        sort: SortKey = .sources,
        ascending: Bool = false,
        nameFilter: String = "",
        typeFilter: String? = nil,
        trustedOnly: Bool = false,
        hideHave: Bool = false
    ) -> [SearchHit] {
        present(
            hits, sort: sort, ascending: ascending, nameFilter: nameFilter,
            typeFilter: typeFilter, trustedOnly: trustedOnly, hideHave: hideHave)
    }

    // The regression this guards: a descending sort written as `!(a < b)` is NOT a
    // strict weak ordering (it returns true for equal elements), which Swift's
    // `sort(by:)` contract forbids. The fix uses a 3-way compare; verify order AND
    // that equal keys keep input order (Swift 5 sort is stable).
    func testDescendingSortIsStrictWeakOrderAndStable() {
        let hits = [
            hit(name: "a", sources: 5), hit(name: "b", sources: 5),
            hit(name: "c", sources: 1), hit(name: "d", sources: 9),
        ]
        let out = p(hits, sort: .sources, ascending: false)
        XCTAssertEqual(out.map(\.sources), [9, 5, 5, 1])
        XCTAssertEqual(out.filter { $0.sources == 5 }.map(\.name), ["a", "b"])
    }

    func testAscendingSortBySize() {
        let hits = [hit(name: "a", size: 30), hit(name: "b", size: 10), hit(name: "c", size: 20)]
        XCTAssertEqual(p(hits, sort: .size, ascending: true).map(\.size), [10, 20, 30])
    }

    func testNameSortIsCaseInsensitive() {
        let hits = [hit(name: "Zebra"), hit(name: "apple"), hit(name: "Mango")]
        XCTAssertEqual(p(hits, sort: .name, ascending: true).map(\.name), ["apple", "Mango", "Zebra"])
    }

    func testNameFilterIsSubstringCaseInsensitive() {
        let hits = [hit(name: "Ubuntu ISO"), hit(name: "debian"), hit(name: "notes.txt")]
        XCTAssertEqual(p(hits, nameFilter: "UBUNTU").map(\.name), ["Ubuntu ISO"])
        // A blank/whitespace filter matches everything.
        XCTAssertEqual(p(hits, nameFilter: "   ").count, 3)
    }

    func testTypeFilter() {
        let hits = [hit(name: "a", fileType: "Video"), hit(name: "b", fileType: "Audio")]
        XCTAssertEqual(p(hits, typeFilter: "Video").map(\.name), ["a"])
        XCTAssertEqual(p(hits, typeFilter: nil).count, 2)
    }

    func testTrustedOnly() {
        let hits = [hit(name: "ok", trusted: true), hit(name: "bad", trusted: false)]
        XCTAssertEqual(p(hits, trustedOnly: true).map(\.name), ["ok"])
        XCTAssertEqual(p(hits, trustedOnly: false).count, 2)
    }

    func testHideHave() {
        let hits = [
            hit(name: "have", status: .have), hit(name: "new", status: .new),
            hit(name: "dl", status: .downloading),
        ]
        XCTAssertEqual(Set(p(hits, hideHave: true).map(\.name)), ["new", "dl"])
        XCTAssertEqual(p(hits, hideHave: false).count, 3)
    }

    // All filters AND together, then the survivors sort.
    func testFiltersCombine() {
        let hits = [
            hit(name: "Ubuntu video", fileType: "Video", trusted: true, status: .new),
            hit(name: "Ubuntu audio", fileType: "Audio", trusted: true, status: .new),
            hit(name: "Ubuntu have", fileType: "Video", trusted: true, status: .have),
            hit(name: "Debian video", fileType: "Video", trusted: true, status: .new),
        ]
        let out = p(
            hits, nameFilter: "ubuntu", typeFilter: "Video", trustedOnly: true, hideHave: true)
        XCTAssertEqual(out.map(\.name), ["Ubuntu video"])
    }
}
