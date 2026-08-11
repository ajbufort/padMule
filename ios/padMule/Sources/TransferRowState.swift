/// The per-transfer row badge, in eMule 0.70b's vocabulary plus padMule's own
/// "Queued" (0.70b has no max-active cap; its `getPartfileStatus` says
/// Downloading / Waiting / Paused / Stopped / Completing / Completed, and the
/// active pair rides padMule's progress + amber-activity presentation rather
/// than this badge).
///
/// The OBSERVABLE precedence, pinned by `TransferRowStateTests`:
/// - Done (complete) beats everything - a finished file is finished whatever
///   the engine state.
/// - Paused shows when the ENGINE is not running (every download halts then)
///   OR the file's own FT_STATUS flag pauses it, and either beats Queued.
///   WHICH of those two produced a given "Paused" is not observable through
///   this API - both return the same case - so their mutual order is
///   deliberately not claimed here or pinned by the tests.
/// - Stopped is the FILE's own StopFile state and is tested BEFORE the file's
///   pause, because stop pauses on the way through: a stopped row is always
///   also paused, so testing pause first would swallow every stopped row and
///   Stop would be invisible on screen. The ENGINE being stopped still wins
///   over both - when nothing is running, every row is halted for the same
///   reason and saying "Stopped" on one of them would imply a per-file state
///   the user did not choose.
enum TransferRowState {
    /// What a row's badge says, as a TYPED value: the view styles by case and
    /// renders `label`, so rewording a label cannot silently detach styling
    /// that used to compare the display string (the same regression shape the
    /// finish beep rejects by keying off a typed event, not the "Saved" text).
    enum Badge: Equatable {
        case done, paused, stopped, queued

        /// The user-visible text, pinned byte-for-byte by `TransferRowStateTests`.
        var label: String {
            switch self {
            case .done: return "Done"
            case .paused: return "Paused"
            case .stopped: return "Stopped"
            case .queued: return "Queued"
            }
        }
    }

    /// Does the ENGINE state stop every download? Anything but `.running`
    /// does: `.paused` and `.stopped` halt the engine outright, and `.seeding`
    /// serves uploads only. Pure so the mapping is testable - the call site
    /// used to enumerate states inline and omitted `.stopped`, so after the
    /// user tapped Stop an incomplete row lost its badge and read as a live
    /// download.
    static func engineStopped(_ state: EngineStateFfi) -> Bool {
        state != .running
    }

    static func badge(
        complete: Bool, engineStopped: Bool, fileStopped: Bool, filePaused: Bool,
        queued: Bool
    ) -> Badge? {
        if complete { return .done }
        if engineStopped { return .paused }
        if fileStopped { return .stopped }
        if filePaused { return .paused }
        if queued { return .queued }
        return nil
    }
}
