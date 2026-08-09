/// The per-transfer row badge, in eMule 0.70b's vocabulary plus padMule's own
/// "Queued" (0.70b has no max-active cap; its `getPartfileStatus` says
/// Downloading / Waiting / Paused / Stopped / Completing / Completed, and the
/// active pair rides padMule's progress + amber-activity presentation rather
/// than this badge).
///
/// Precedence is the point and is pinned by `TransferRowStateTests`:
/// - Done (complete) beats everything - a finished file is finished whatever
///   the engine state.
/// - The ENGINE being paused or seeding beats per-file state: every download
///   is stopped then, whatever its own flag says.
/// - Per-file Paused (the user's FT_STATUS flag) beats Queued: a paused row
///   consumes no admission slot, so both can be true only transiently.
enum TransferRowState {
    static func badge(
        complete: Bool, engineStopped: Bool, filePaused: Bool, queued: Bool
    ) -> String? {
        if complete { return "Done" }
        if engineStopped { return "Paused" }
        if filePaused { return "Paused" }
        if queued { return "Queued" }
        return nil
    }
}
