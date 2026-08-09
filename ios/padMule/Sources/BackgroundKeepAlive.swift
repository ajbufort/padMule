import AVFoundation
import Foundation
import OSLog

/// Keeps padMule awake with the screen off, so it can keep SERVING files after
/// the user switches away.
///
/// WHAT THIS IS, plainly. iOS suspends a backgrounded app within about thirty
/// seconds and reclaims its sockets, which is why padMule has been
/// foreground-only. An app with the `audio` background mode and an ACTIVE audio
/// session is not suspended - so our raw eD2k sockets keep running. That is the
/// whole mechanism. There is no private API here and nothing clever: `audio` is
/// an ordinary Info.plist key any free provisioning team may set.
///
/// WHY WE MAY USE IT AND AN APP STORE APP MAY NOT. App Store review guideline
/// 2.5.4 rejects an app that declares a background mode it does not genuinely
/// use for its stated purpose. padMule is sideload-only by necessity - a P2P
/// client can never ship on the App Store - so it is never reviewed. Sideloading
/// is precisely what makes the ordinary mechanism available to us.
///
/// WHAT IT DOES NOT BUY, and this is the part to be honest about: Apple's own
/// guidance is that audio "keeps you awake" is NOT "will not be terminated".
/// The app can still be killed for memory (jetsam) at any moment, without
/// warning. So this is best-effort, the engine still checkpoints on the way into
/// the background, and the app must always degrade cleanly back to
/// pause-and-resume. Measured 2026-08-07: padMule's footprint is ~31MB against a
/// jetsam budget around 100MB, so the headroom is real but it is not a promise.
///
/// COURTESY TO THE USER'S OTHER AUDIO: the session is `.mixWithOthers`, so
/// starting it does NOT stop their music or duck a podcast. A keepalive that
/// silences the user's audio to keep a file sharing would be an obnoxious trade.
final class BackgroundKeepAlive {
    // Constructed from EngineLogIdentity, never fresh literals - LoggingTests
    // pins the strings, and its guard is that no other spelling exists.
    private let log = Logger(
        subsystem: EngineLogIdentity.subsystem, category: EngineLogIdentity.keepaliveCategory)
    private var player: AVAudioPlayer?

    /// True while the keepalive is holding the app awake.
    private(set) var isRunning = false

    /// Start the keepalive. Returns false if it could not be started, which the
    /// caller MUST treat as "we are about to be suspended" and fall back to a
    /// full pause - reporting a background seed we are not performing would be
    /// the dishonest-status failure the lifecycle rules forbid. On ANY failure
    /// the audio session is left deactivated: `stop()` only cleans up when
    /// `isRunning` is true, so a failure path that kept the session active
    /// would hold it forever with nothing playing.
    @discardableResult
    func start() -> Bool {
        guard !isRunning else { return true }
        let session = AVAudioSession.sharedInstance()
        do {
            // .playback is the category that survives the screen lock;
            // .mixWithOthers keeps the user's own audio playing.
            try session.setCategory(.playback, mode: .default, options: [.mixWithOthers])
            try session.setActive(true)
        } catch {
            log.error("keepalive: could not start: \(String(describing: error), privacy: .public)")
            return false
        }
        // The session is ACTIVE from here on, so every failure below must hand
        // it back before returning - `isRunning` is still false, so nothing
        // else ever would.
        do {
            let player = try AVAudioPlayer(data: Self.silentWav())
            player.numberOfLoops = -1  // forever: a session that ends is a suspend
            player.volume = 0
            guard player.play() else {
                log.error("keepalive: AVAudioPlayer refused to play")
                try? session.setActive(false, options: [.notifyOthersOnDeactivation])
                return false
            }
            self.player = player
            isRunning = true
            log.notice("keepalive: STARTED - the app will stay awake in the background")
            return true
        } catch {
            log.error("keepalive: could not start: \(String(describing: error), privacy: .public)")
            try? session.setActive(false, options: [.notifyOthersOnDeactivation])
            return false
        }
    }

    /// Stop the keepalive and hand the audio session back. Called on returning
    /// to the foreground, and on any path that stops background seeding -
    /// holding an audio session we no longer need spends battery for nothing.
    func stop() {
        guard isRunning else { return }
        player?.stop()
        player = nil
        try? AVAudioSession.sharedInstance().setActive(false, options: [.notifyOthersOnDeactivation])
        isRunning = false
        log.notice("keepalive: stopped")
    }

    /// A one-second silent 8kHz mono WAV, built in code.
    ///
    /// Generated rather than shipped as a resource so there is no bundle asset
    /// to go missing, and so what is playing is auditable right here: it is
    /// silence, not a sound clipped to zero volume.
    private static func silentWav() -> Data {
        let sampleRate = 8000
        let samples = sampleRate  // one second
        let dataBytes = samples * 2  // 16-bit mono
        var d = Data()
        func le32(_ v: Int) -> Data { withUnsafeBytes(of: UInt32(v).littleEndian) { Data($0) } }
        func le16(_ v: Int) -> Data { withUnsafeBytes(of: UInt16(v).littleEndian) { Data($0) } }
        d.append("RIFF".data(using: .ascii)!)
        d.append(le32(36 + dataBytes))
        d.append("WAVE".data(using: .ascii)!)
        d.append("fmt ".data(using: .ascii)!)
        d.append(le32(16))  // PCM header size
        d.append(le16(1))  // PCM
        d.append(le16(1))  // mono
        d.append(le32(sampleRate))
        d.append(le32(sampleRate * 2))  // byte rate
        d.append(le16(2))  // block align
        d.append(le16(16))  // bits per sample
        d.append("data".data(using: .ascii)!)
        d.append(le32(dataBytes))
        d.append(Data(count: dataBytes))  // silence
        return d
    }
}
