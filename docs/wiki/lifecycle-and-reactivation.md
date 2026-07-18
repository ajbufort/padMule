# Lifecycle Status + Clean Reactivation (hard requirement)

Updated: 2026-07-18

padMule is foreground-only ([[ipados-constraints]]): iPadOS suspends the app
~30s after backgrounding and reclaims every TCP/UDP socket (EBADF). When focus
is lost the live state "turns to shit" - servers drop, Kad membership lapses,
peer sockets die. Two things MUST be clean: (1) the user-facing status
notice, and (2) the reactivation on return. This is a first-class requirement,
not polish. It shapes the engine's public API from Wave 3 onward - the engine
must expose lifecycle transitions and a rich connection-state event stream so
the UI can be honest; it cannot be inferred late.

## Engine state model (drives the UI; design in Wave 3c)

- `ServerState`: Disconnected, Connecting, Connected{ HighID | LowID },
  Reconnecting, PausedForBackground.
- `KadState`: Off, Bootstrapping, Connected{ open | firewalled }, Reconnecting,
  PausedForBackground.
- `AppActivity` (from the UI's ScenePhase): Active, Resigning (the ~30s
  checkpoint window), Suspended, Resuming.
- Per-transfer state must distinguish **Paused (lifecycle)** from **Stalled**
  (no sources / slow) from **Error** (disk full, corruption). A lifecycle pause
  is NOT an error and must never be shown as one.

The engine emits state-change EVENTS (not polled) over the FFI callback
interface. The UI renders directly from them - never a cached "Connected" that
is actually dead.

[AS BUILT (Wave 8): the opposite shape won. Events are POLLED - the UI drains
`drain_events()` on a 1s timer - and everything the UI must KEEP showing
(state, server info + ID type, sharing, UPnP result) is a polled SNAPSHOT,
because "an event is not state" (an event applied and overwritten in the same
batch hid the ID type on-device). The requirement this section states still
holds - the UI never renders a stale "Connected" - it is just met with
snapshots. A push callback interface remains a possible later upgrade.]

## Clean status notice (user-facing)

- A single, always-visible connection indicator with an honest label:
  Connected (HighID/LowID) / Reconnecting.../ Paused (app in background) /
  Offline (no network).
- On returning to foreground after suspension, the UI shows **Reconnecting...**
  immediately - never a stale green "Connected" for the seconds until sockets
  are actually rebuilt.
- Distinguish **"paused because you left the app"** (expected, calm messaging,
  e.g. "Transfers paused - padMule pauses when it is not in the foreground")
  from a real failure (server refused, no Wi-Fi, disk full), which gets a
  distinct error treatment.
- Transfers in the list show a "Paused" badge on background, flipping back to
  active on resume - progress is preserved (part files were checkpointed).
- Optional: a one-time explainer the first time the user backgrounds mid-
  transfer, so the pause is understood as by-design, not a bug. Local
  notifications are available on the free account if we later want a "still
  more to download - reopen padMule" nudge (do NOT overuse).

## Clean reactivation procedure

The UI's scene-phase observer calls an explicit engine `resume()` (and
`pause()` on the way out) over FFI - do NOT rely on implicit socket-death
detection. `resume()` must be:

1. **Idempotent + leak-free.** Tear down any lingering dead sockets/tasks first
   (they are EBADF anyway); never double-connect or leak the pre-suspend state.
2. **Fast + non-blocking.** No hangs; the UI stays responsive; work happens on
   the runtime, UI gets events.
3. **Correct on network change.** While backgrounded the device may have
   changed Wi-Fi / IP; a changed public IP flips HighID<->LowID, so re-login
   from scratch rather than assuming the old ID. Refresh the public-IP view.
4. **Order:** rebuild sockets -> reconnect to the last server (or reconnect
   list) -> re-bootstrap/refresh Kad from persisted nodes.dat -> re-issue source
   and A4AF requests for active downloads -> resume the transfer queue.
5. **Progress-safe.** No re-hash of already-verified parts; resume from the gap
   list. `pause()` on the way down flushes buffers and checkpoints every
   `.part.met` within the ~30s window.

`pause()`: flush + checkpoint + quiesce queues + mark all sockets disposable;
set states to PausedForBackground and emit the events.

## Can we avoid the pause in the first place?

Short answer: the pause is the DEFAULT and the only OS-GUARANTEED behavior, but
it is NOT strictly unavoidable. Sideloading changes the calculus - the classic
keepalive trick that App Store review (guideline 2.5.4) would reject is
available to us, because a dev-signed/AltStore build is never reviewed. It buys
best-effort screen-off running, not a guarantee. Options, weakest-guarantee to
strongest (verified in the iPadOS research, docs/raw/ipados-constraints-*):

1. **Silent-audio (or continuous-location) keepalive - the real "defeat the
   pause" lever.** An active audio session keeps the app awake with the screen
   off, so OUR raw eD2k/Kad sockets keep running. REVIEW-BLOCKED for the App
   Store but TECHNICALLY-ALLOWED on a sideloaded build; `UIBackgroundModes`
   (audio/location) are Info.plist keys a free team can set. Caveats that make
   it best-effort, not a guarantee: Apple DTS is explicit that audio "keeps you
   awake" is NOT "will not be suspended"; the dominant overnight failure is
   outright TERMINATION (jetsam) - so background memory MUST stay under ~100MB;
   heavy battery cost; audio-interruption re-arm needed. Verdict: genuinely
   defeats the pause for hours of active screen-off use; can still be killed.
2. **Foreground seedbox mode - the fully-supported always-on path.** Auto-Lock =
   Never + plugged in keeps the app foreground with the screen on: UNLIMITED,
   fully supported, sockets alive. The cost is only that the screen is on. Best
   for "leave it downloading on my desk" and for seeding.
3. **`BGContinuedProcessingTask` (iPadOS 26) - the legitimate "finish this
   file."** A user-initiated, bounded job with a mandatory system progress UI
   that can run a transfer past the ~30s window. Not indefinite seeding, but the
   clean supported way to let an in-progress download finish while away. (Its
   availability on the A12Z under iPadOS 26 is an open question to measure.)
4. **`BGProcessingTask` - opportunistic progress while charging.** Maintenance
   grade (OS discretion, may not fire): hash-check parts, prune sources, brief
   resume attempts while on power. Complements, never the primary runtime.

What is genuinely impossible: a fully-supported, always-on, screen-off P2P
daemon like on desktop. Background `URLSession` (the only thing that truly
survives suspension) is HTTP/HTTPS-only and cannot carry the eD2k/Kad wire
protocol. So there is no "free" always-on.

**Decision:** v1 stays foreground-only with the clean pause/resume above (it is
honest, simple, and always correct). Add background persistence as a LATER,
OPT-IN, tiered feature (a "Keep active in background" toggle = the audio
keepalive with a clear battery warning + the <100MB memory discipline; a
"Seedbox mode" = Auto-Lock=Never; use BGContinuedProcessingTask on iPadOS 26 to
finish an active download; BGProcessingTask for charging-time upkeep). Crucially,
**clean pause/resume remains REQUIRED regardless** - every one of these
mechanisms can be revoked or jetsam-killed by the OS, so the app must always
degrade gracefully back to pause-and-resume. On-device measurement needed:
keepalive longevity on the A12Z/iPadOS 26, and whether BGContinuedProcessingTask
is eligible there (open questions in the iPadOS research).

## Where it landed (both DONE)

- **Wave 3c+ (engine):** DONE - ServerLink + Engine expose idempotent
  `pause()`/`resume()` with the event stream; the CLI harness exercised
  simulated pause/resume before the iPad UI existed, and `resume()` rebinds
  the listener FIRST (the HighID ordering) then reconnects + re-bootstraps Kad.
- **Wave 8 (FFI + SwiftUI):** DONE - `PadMuleApp` maps ScenePhase (`.active`
  -> `resume()`, `.background` -> `pause()`, `.inactive` ignored to avoid
  thrashing); the honest status row, Reconnecting banner, per-transfer Paused
  badges, and calm background-pause notice all shipped ([[build-progress]]
  wave 8).

## Related

- [[ipados-constraints]] - why (the ~30s suspend + socket reclaim).
- [[arch-upstream-amule]], [[protocol-understanding]] - reconnect/re-bootstrap flows.
- [[build-progress]]
