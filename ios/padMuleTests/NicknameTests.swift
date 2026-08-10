import XCTest

@testable import padMule

/// THE NAME EVERY PEER AND EVERY SERVER SEES.
///
/// padMule announced the literal "padMule" to the whole network and there was no
/// way to change it. Now there is, and three things must hold: an install nobody
/// touches still says "padMule", a name that cannot go on the wire is repaired
/// rather than announced, and the value the app pushes into the engine at boot is
/// the stored one - not an empty string produced by an absent key.
///
/// SCOPE, stated because it is easy to over-read: these pin the SWIFT half. The
/// bytes are pinned on the Rust side, where the packets are actually built
/// (`engine::tests::a_set_nickname_reaches_the_peer_hello_and_the_server_login`
/// reads CT_NAME back out of a real HELLO and a real login), and the seam itself
/// by `mule-ffi`'s `nickname_round_trips_via_the_facade_and_is_sanitized_by_the_engine`.
///
/// Marked `@MainActor` like `SettingsTests`: the members under test are
/// `nonisolated`, but a test file that guesses wrong about isolation is how the
/// whole padMuleTests bundle went red in CI on 2026-08-09.
@MainActor
final class NicknameTests: XCTestCase {
    /// THE DEFAULT IS UNCHANGED BEHAVIOUR. Every build before this setting
    /// existed announced "padMule"; a user who never opens Settings must be
    /// indistinguishable from one running the old build. Asserts the REAL
    /// registration, not a restated dictionary - a test that registers its own
    /// defaults only proves that UserDefaults.register works.
    func testTheRegisteredNicknameDefaultIsPadMule() {
        SettingsDefaults.register()
        XCTAssertEqual(
            UserDefaults.standard.string(forKey: SettingsKey.nickname), "padMule",
            "an untouched install must still announce padMule")
        // The constant the app and the engine share. `mule_engine::DEFAULT_NICK`
        // is the same string; the Rust side pins its own copy in
        // `engine::tests::the_default_nickname_is_padmule`.
        XCTAssertEqual(EngineModel.defaultNickname, "padMule")
    }

    /// THE ABSENT KEY IS THE FIRST LAUNCH.
    ///
    /// `UserDefaults.string(forKey:)` returns nil when nothing was ever stored,
    /// which is exactly the install that has configured nothing - so a caller
    /// doing `?? ""` would push an empty nickname on the one launch where it
    /// matters most. Same shape as the ports' "a stored 0 means never set".
    func testNicknameToPushFallsBackWhenNothingUsableIsStored() {
        XCTAssertEqual(
            EngineModel.nicknameToPush(stored: nil), "padMule",
            "an absent key is a fresh install, not a nameless client")
        XCTAssertEqual(EngineModel.nicknameToPush(stored: ""), "padMule")
        XCTAssertEqual(
            EngineModel.nicknameToPush(stored: "   \n "), "padMule",
            "whitespace-only is empty once trimmed")
        // A real stored name is passed through untouched but trimmed.
        XCTAssertEqual(EngineModel.nicknameToPush(stored: "Tony"), "Tony")
        XCTAssertEqual(EngineModel.nicknameToPush(stored: "  Tony  "), "Tony")
    }

    /// THE FIELD'S RULES ARE eMULE'S RULES.
    ///
    /// eMule 0.70b `CPPgGeneral::OnApply` (PPgGeneral.cpp:187-191) trims and
    /// substitutes the default for an empty nickname; the 50-character cap is
    /// `GetMaxUserNickLength()` (Preferences.h:690, and 0.50a Preferences.h:661
    /// agrees), applied at the edit control. This is the same table the engine
    /// asserts in
    /// `engine::tests::an_empty_or_oversized_or_control_laden_nickname_is_repaired`
    /// - deliberately duplicated, because the field must answer synchronously to
    /// snap a rejected entry to what will actually be announced, and the engine
    /// must enforce it because the engine writes the bytes. If one side moves,
    /// the other's table is where it shows up.
    func testSanitizedNicknameAppliesEMulesRules() {
        // Empty and whitespace-only fall back rather than announcing nothing.
        XCTAssertEqual(SettingsView.sanitizedNickname(""), "padMule")
        XCTAssertEqual(SettingsView.sanitizedNickname("   \t "), "padMule")
        // Trimmed, not rejected.
        XCTAssertEqual(SettingsView.sanitizedNickname("  Tony  "), "Tony")
        // Capped at eMule's 50. The LITERAL leads: an assertion written against
        // `maxNicknameLength` would move with the constant and could not catch
        // the constant itself changing.
        XCTAssertEqual(
            SettingsView.sanitizedNickname(String(repeating: "N", count: 120)),
            String(repeating: "N", count: 50))
        XCTAssertEqual(SettingsView.maxNicknameLength, 50, "eMule's GetMaxUserNickLength")
        // Control characters never reach the wire. A pasted newline is the
        // realistic one and is what mangles another client's log line.
        XCTAssertEqual(SettingsView.sanitizedNickname("Tony\r\niPad"), "TonyiPad")
        // '?' is KEPT - padMule's stated divergence from eMule's
        // IsValidEd2kString (StringConversion.h:21), whose own comment says the
        // character is a Windows ANSI-mode artifact. padMule writes UTF-8, where
        // it is an ordinary character, and discarding a whole nickname over a
        // question mark would surprise the user for no gain.
        XCTAssertEqual(SettingsView.sanitizedNickname("who? me"), "who? me")
    }
}
