import XCTest

@testable import padMule

/// The background publish gate - the rule that stopped the hidden-hierarchy
/// re-render found by the 2026-08-09 72-minute seeding soak (build d5fadb8):
/// one `@Published` write per second (the heartbeat counter) re-rendered the
/// whole off-screen view tree - ~55 CoreFoundation localization lookups plus
/// one denied UIAccessibility post attempt every second, ~4,100 syslog lines
/// a minute - in exactly the mode built to run unattended on battery. The
/// per-second signature matched the heartbeat cadence and the every-5th-tick
/// double render matched `seedingPollDivisor`, which is what convicted the
/// publishes rather than a stray Timer or animation.
///
/// The load-bearing Swift fact under test: a plain `@Published` fires
/// `objectWillChange` on SET, not on change. Republishing an identical value
/// is therefore NOT silent - only an untouched property is - which is why
/// `coalescedCounterPublish` returns an Optional whose nil means "do not
/// touch the property" instead of returning a value to assign untouched.
///
/// DISCLOSED LIMITS, the same ones `PollGapBookingTests` carries: these pin
/// the PURE rule only. That `refreshFast()` and the heartbeat completion
/// actually consult the gate, that `enterBackground()` raises the flag and
/// `leaveBackground()` drops it and flushes, and that suppressing the
/// publishes actually suppresses SwiftUI rendering are lifecycle + rendering
/// wiring no unit test can reach. Only a device soak can close it: while
/// background-seeding, the per-second CoreFoundation/UIAccessibility syslog
/// traffic must be GONE, and the engine's Kad publish counters must still
/// climb through the seed (the duties ride `heartbeat()`, which the gate
/// never touches).
@MainActor
final class BackgroundPublishTests: XCTestCase {
    /// Foreground, counter advanced: publish the new value. The ordinary
    /// beat - a gate that ate foreground publishes would freeze the Stats
    /// pair on screen, the instrument built to be watched live.
    func testAForegroundAdvanceIsPublished() {
        XCTAssertEqual(
            EngineModel.coalescedCounterPublish(
                trueCount: 8, published: 7, backgrounded: false),
            8)
    }

    /// Foreground, mirror already current: nil, NOT "assign 7 again".
    /// Assigning the same value to a plain @Published still fires
    /// objectWillChange, so this case is a render if the rule gets it wrong.
    /// Reachable in life as the flush-with-nothing-to-flush: a background
    /// episode so short no heartbeat completed inside it.
    func testAnUnchangedValueIsNotRepublished() {
        XCTAssertNil(
            EngineModel.coalescedCounterPublish(
                trueCount: 7, published: 7, backgrounded: false))
    }

    /// THE DEFECT CASE: backgrounded, counter advanced - stay silent. This
    /// exact input fired once per second for 72 minutes on d5fadb8.
    func testABackgroundedAdvanceIsSilent() {
        XCTAssertNil(
            EngineModel.coalescedCounterPublish(
                trueCount: 8, published: 7, backgrounded: true))
    }

    /// The shared gate answers the same way for both publishers. The counter
    /// rule and the snapshot skip both key off `shouldPublishUi`; if these
    /// verdicts ever diverged, one path would render while the other slept
    /// through the same episode.
    func testTheGateMatchesTheCounterRuleInBothStates() {
        XCTAssertFalse(EngineModel.shouldPublishUi(backgrounded: true))
        XCTAssertTrue(EngineModel.shouldPublishUi(backgrounded: false))
        // Backgrounded: gate closed and the counter rule silent, together.
        XCTAssertNil(
            EngineModel.coalescedCounterPublish(
                trueCount: 2, published: 1, backgrounded: true))
        // Foreground: gate open and the counter rule speaking, together.
        XCTAssertNotNil(
            EngineModel.coalescedCounterPublish(
                trueCount: 2, published: 1, backgrounded: false))
    }

    /// The return-to-foreground flush, run through the REAL rule tick by
    /// tick rather than restated: an episode of silent backgrounded beats
    /// accrues in the true count, and the first foreground call publishes
    /// the accumulated total in ONE write - no stale mirror survives the
    /// episode, and no publish happened during it.
    func testTheEpisodeFlushesToOnePublishOnReturn() {
        var trueCount: UInt64 = 41
        var published: UInt64 = 41
        var publishes = 0
        for _ in 1...6 {
            trueCount &+= 1  // a heartbeat completed while backgrounded
            if let v = EngineModel.coalescedCounterPublish(
                trueCount: trueCount, published: published, backgrounded: true)
            {
                published = v
                publishes += 1
            }
        }
        XCTAssertEqual(publishes, 0, "a backgrounded beat that publishes is the defect")
        XCTAssertEqual(published, 41, "the mirror must hold, frozen, through the episode")
        // leaveBackground()'s flush: one foreground call, backgrounded false.
        if let v = EngineModel.coalescedCounterPublish(
            trueCount: trueCount, published: published, backgrounded: false)
        {
            published = v
            publishes += 1
        }
        XCTAssertEqual(publishes, 1, "the whole episode must cost exactly one publish, on return")
        XCTAssertEqual(published, 47, "the flush must carry every beat the episode counted")
    }
}
