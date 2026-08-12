/// WHY SHARING IS OR IS NOT HAPPENING, as ONE rule with ONE set of words.
///
/// padMule can stop serving files for four different reasons and two screens
/// have to say which one is in force: the Settings sharing footer and the
/// Shared screen's caption. Before this existed they each explained the pause
/// the OTHER one omitted, which is this project's named failure shape - the
/// screen saying one thing while the engine says another:
///
/// - Settings knew only the metered pause. While the public-address pause was
///   in force it showed "Share uploads" ON and stated padMule was serving
///   files, which was false; and on cellular it promised "It resumes
///   automatically on Wi-Fi", which is also false in that state because
///   `EngineModel.sharingDecision` returns nil while the address pause is
///   latched and the call is not user-initiated.
/// - The Shared screen knew only the address-change pause. A metered pause read
///   there as "Leech Mode: downloading only" - crediting the USER with a pause
///   padMule imposed - and tapping the switch bounced it back with nothing on
///   screen saying why.
///
/// This type is the fix: `of(...)` decides the state, `caption` supplies the
/// words, and both screens render the result. A state neither screen can name
/// differently is a state they cannot disagree about.
///
/// IT AGREES WITH THE ENGINE PUSH BY CONSTRUCTION. `EngineModel.sharingDecision`
/// decides what the ENGINE is told; this decides what the SCREEN says, and
/// `.sharing` is returned for exactly the inputs where that rule pushes `true`
/// (every combination is pinned by `SettingsTests`). Change one and the test
/// that compares them fails.
///
/// Top-level rather than nested in `EngineModel` for the same reason
/// `TransferRowState` is: `EngineModel` is `@MainActor`, and a pure rule that
/// may be needed off the main queue should not inherit an isolation it has no
/// use for.
enum SharingStatus: Equatable {
    /// padMule is serving its finished files to peers right now.
    case sharing
    /// The user's own choice: downloading only. Not a pause.
    case leech
    /// padMule paused sharing because the public address changed under it.
    /// Only the user can end this one - see `EngineModel.sharingDecision`.
    case pausedForIpChange
    /// padMule paused sharing for a metered link. This one ends by itself.
    case pausedForMeteredLink

    /// Which state is in force. PRECEDENCE IS THE WHOLE RULE:
    ///
    /// - Neither pause applies unless the user actually WANTS to share. A pause
    ///   is something padMule did to a choice, so with the preference off there
    ///   is no pause to report - and the address-change flag really can be
    ///   latched while sharing is already off, because `Engine::note_public_id`
    ///   does not consult it and `Engine::set_sharing` clears it only in the
    ///   `on` direction (both in mule-engine/src/engine.rs).
    /// - The address-change pause OUTRANKS the metered one, because it is the
    ///   one that does not end by itself. Naming the metered pause while both
    ///   are in force would promise a resumption on Wi-Fi that
    ///   `EngineModel.sharingDecision` refuses to perform.
    static func of(
        wanted: Bool,
        pauseOnMetered: Bool,
        metered: Bool,
        pausedForIpChange: Bool
    ) -> SharingStatus {
        guard wanted else { return .leech }
        if pausedForIpChange { return .pausedForIpChange }
        if pauseOnMetered && metered { return .pausedForMeteredLink }
        return .sharing
    }

    /// The user-visible explanation, pinned by `SettingsTests`. ONE string per
    /// state, in ONE place, so the two screens cannot word the same state
    /// differently - which is how the pair of defects above survived.
    var caption: String {
        switch self {
        case .sharing:
            return "padMule serves your finished files to other peers while it is open. Sharing earns you better standing in their queues, so your own downloads go faster."
        case .leech:
            return "Leech Mode: downloading only. padMule is not serving any files to peers."
        case .pausedForIpChange:
            return "Sharing is paused because your public address changed (likely a VPN drop or a network switch). Turn sharing back on when you're ready."
        case .pausedForMeteredLink:
            return "Sharing is paused right now because you are on a metered network. It resumes automatically on Wi-Fi. This pauses uploading only - downloads continue and still use data."
        }
    }
}
