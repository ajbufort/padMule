import XCTest

@testable import padMule

/// The poll-cadence rule, which is the independent variable in an experiment
/// rather than a tuning knob.
///
/// The 2026-08-07 soak proved background seeding SURVIVES - 60 samples over ~70
/// minutes, zero deaths, `physFootprint` flat at 32.2MB against a ~100MB jetsam
/// budget - but left the CPU unexplained: samples split almost exactly evenly
/// above and below 5%, against 0.1% foreground-idle. Two candidates, and the
/// obvious one has a hole in it (a 1 Hz signal would be caught by nearly any
/// sampling window, not half of them). Throttling the full UI snapshot while
/// seeding is what separates "the audio keepalive costs it" from "our own poll
/// costs it".
@MainActor
final class PollCadenceTests: XCTestCase {
    /// Foreground states must poll EVERY tick. A throttle that leaked into
    /// Running would make the transfer numbers stutter on screen for a reason
    /// nobody could see - and it would look exactly like the freeze row 8cg
    /// fixed, which is the worst kind of regression to reintroduce.
    func testEveryForegroundStatePollsOnEveryTick() {
        for state in [EngineStateFfi.running, .paused, .stopped] {
            for tick in 1...12 {
                XCTAssertTrue(
                    EngineModel.shouldRunFastPoll(state: state, tick: tick),
                    "\(state) must snapshot every tick; throttling a visible UI is the 8cg freeze"
                )
            }
        }
    }

    /// Seeding polls on ONE tick in `seedingPollDivisor`, not on all of them and
    /// not on none of them. Never polling would be worse than always: `state`
    /// would still refresh from events, but the transfer list and shared library
    /// would be arbitrarily stale the moment the user came back.
    func testSeedingPollsExactlyOncePerDivisor() {
        let d = EngineModel.seedingPollDivisor
        let polled = (1...(d * 4)).filter {
            EngineModel.shouldRunFastPoll(state: .seeding, tick: $0)
        }
        XCTAssertEqual(
            polled.count, 4,
            "expected one snapshot per \(d) ticks over four periods, got \(polled)"
        )
        // A LITERAL stride, not `d` again: comparing the rule against the same
        // constant it is derived from is the tautology that made two Kad cap
        // tests vacuous earlier today.
        XCTAssertEqual(polled, [5, 10, 15, 20])
    }

    /// The divisor must actually THIN the work - a value of 1 would make the
    /// whole change a no-op while reading as if it did something, which is the
    /// shape of a fix that is really a comment.
    func testTheSeedingDivisorActuallyThrottles() {
        XCTAssertGreaterThan(
            EngineModel.seedingPollDivisor, 1,
            "a divisor of 1 polls every tick, so seeding would be untouched"
        )
    }
}
