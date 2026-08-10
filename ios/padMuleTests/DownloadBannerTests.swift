import XCTest

@testable import padMule

/// Pins `EngineModel.downloadBannerText` - the live-state rule behind the
/// started-download feedback banner. The defect this replaces (on glass,
/// 2026-08-09): the banner captured "Downloading X" as a STRING when the
/// download was added, so it kept asserting X was running after X was paused.
/// The rule now derives the text from the row's current badge on every render,
/// through the same `TransferRowState.badge` the Transfers row uses, so the
/// banner and the row cannot tell different stories.
///
/// SCOPE, stated honestly - what these tests cannot witness:
/// - That the VIEW passes live inputs. `statusBanners` calls this same helper
///   with `model.downloads` / `model.state`, but nothing here executes that
///   call site; a caller passing a stale array would pass these tests.
/// - Re-render timing: `downloads` and `state` are @Published, so SwiftUI
///   recomputes on change, but no test observes an actual render - the
///   2026-08-07 lesson that a layout/render bug needs eyes on glass.
/// - The brief window right after Get where the pointer is set but the row
///   has not yet arrived in `downloads` (the banner shows nothing until the
///   refresh lands - honest, but only a device pass can judge the feel).
/// A device pass must pause a downloading row and confirm the banner drops.
final class DownloadBannerTests: XCTestCase {
    /// A `DownloadInfo` with sensible defaults, overriding only what a test
    /// cares about (the PresentationTests `hit(...)` convention).
    private func row(
        hash: String = "0123456789abcdef0123456789abcdef",
        name: String = "file.bin",
        complete: Bool = false,
        paused: Bool = false,
        queued: Bool = false
    ) -> DownloadInfo {
        DownloadInfo(
            hash: hash,
            name: name,
            size: 1_000_000,
            have: 0,
            complete: complete,
            rating: 0,
            hasComment: false,
            priority: 1,
            preview: false,
            contiguousPrefix: 0,
            paused: paused,
            queued: queued,
            receiving: false,
            sourcesServer: 0,
            sourcesKad: 0,
            sourcesExchange: 0,
            sourcesFound: 0,
            sourcesCallback: 0,
            partsNeeded: 0,
            partsUnavailable: 0,
            partStatusReports: 0
        )
    }

    func testRunningRowSaysDownloading() {
        XCTAssertEqual(
            EngineModel.downloadBannerText(
                hash: row().hash, downloads: [row()], engineStopped: false),
            "Downloading \"file.bin\".")
    }

    /// THE ON-GLASS DEFECT: the same row, paused, must show nothing - the old
    /// captured-string banner kept saying "Downloading" here.
    func testPausedRowShowsNothing() {
        XCTAssertNil(
            EngineModel.downloadBannerText(
                hash: row().hash, downloads: [row(paused: true)], engineStopped: false))
    }

    /// Cancelling removes the row from the engine's list entirely.
    func testCancelledRowShowsNothing() {
        XCTAssertNil(
            EngineModel.downloadBannerText(
                hash: row().hash, downloads: [], engineStopped: false))
    }

    /// A finished row stays in the list with `complete` set; the banner must
    /// not claim it is still downloading.
    func testCompletedRowShowsNothing() {
        XCTAssertNil(
            EngineModel.downloadBannerText(
                hash: row().hash, downloads: [row(complete: true)], engineStopped: false))
    }

    /// Engine stop/pause/seeding halts every download; the banner follows.
    /// (`TransferRowStateTests` pins that all non-running states map to
    /// engineStopped = true, so one input here covers the family.)
    func testEngineStopTakesTheBannerDown() {
        XCTAssertNil(
            EngineModel.downloadBannerText(
                hash: row().hash, downloads: [row()], engineStopped: true))
    }

    /// Queue demotion (padMule's max-active cap) must not read "Downloading" -
    /// but a fresh Get with the cap full lands queued at birth, so the tap
    /// still gets an honest line rather than silence.
    func testQueuedRowSaysQueuedNotDownloading() {
        let text = EngineModel.downloadBannerText(
            hash: row().hash, downloads: [row(queued: true)], engineStopped: false)
        XCTAssertEqual(text, "\"file.bin\" is queued - it starts when a download slot frees.")
        XCTAssertFalse(text?.contains("Downloading") ?? false)
    }

    /// The banner names the row the HASH points at, not whichever row happens
    /// to be first in the list.
    func testNameTracksTheRowTheHashNames() {
        let a = row(hash: String(repeating: "a", count: 32), name: "first.bin")
        let b = row(hash: String(repeating: "b", count: 32), name: "second.bin")
        XCTAssertEqual(
            EngineModel.downloadBannerText(
                hash: b.hash, downloads: [a, b], engineStopped: false),
            "Downloading \"second.bin\".")
    }

    /// Dismissed (pointer dropped) means no banner, whatever the list holds.
    func testNilHashShowsNothing() {
        XCTAssertNil(
            EngineModel.downloadBannerText(
                hash: nil, downloads: [row()], engineStopped: false))
    }
}
