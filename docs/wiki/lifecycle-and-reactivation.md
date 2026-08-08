# Lifecycle Status + Clean Reactivation (hard requirement)

Updated: 2026-08-08 (date corrected by the 8cp reanalysis - the body already carried 2026-08-07 background-seeding content under an 08-06 stamp. Annotated: the clean-pause requirement below is currently
NOT MET on device - see the banner. Seedbox mode DROPPED 2026-08-04 -
foreground-only is now the PERMANENT posture, so the research below is retained
as background, not as a roadmap)

> **[ANNOTATION 2026-08-05/06 - THE REQUIREMENT BELOW IS NOT WHAT HAPPENS.]**
> A device syslog capture measured **465ms** from `pause (backgrounded)` to
> `Suspending`, with `state -> paused` arriving only **30.5s later, on the way
> back IN**. So iPadOS freezes the process MID-TEARDOWN and reclaims its sockets;
> the orderly pause this entry calls a hard requirement is aspirational on the
> real device, not descriptive. Two mechanisms fit and the log could not separate
> them - the `beginBackgroundTask` assertion was refused, or `e.pause()` queued
> behind something long on the SERIAL work queue (the 6s server probe is a
> candidate). Build `2186e48` INSTRUMENTS both rather than guessing: `pause()`
> now logs the assertion as GRANTED/REFUSED and stamps how long the work item
> waited before it STARTED (EngineModel.swift:1040-1049). **One background round
> trip on that build answers it; do not theorise first.** Everything below stays
> as the design intent and as the spec any fix must satisfy.
> ([[handoff-next-session]] open lead 1, [[build-progress]] 8cd/8ce.)

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
2. **Foreground seedbox mode - the fully-supported always-on path.**
   [DROPPED 2026-08-04 as a padMule FEATURE - see [[decisions-and-lessons]]. The
   mechanism below is still simply TRUE of iPadOS, and a user who wants it can
   already have it by setting Auto-Lock to Never themselves and leaving padMule
   open, which is exactly what "Keep screen awake while transferring" assists.
   What is dropped is padMule shipping a MODE around it.] Auto-Lock =
   Never + plugged in keeps the app foreground with the screen on: UNLIMITED,
   fully supported, sockets alive. The cost is only that the screen is on. Best
   for "leave it downloading on my desk" and for seeding.
3. **`BGContinuedProcessingTask` (iPadOS 26) - the legitimate "finish this
   file."** A user-initiated, bounded job with a mandatory system progress UI
   that can run a transfer past the ~30s window. Not indefinite seeding, but the
   clean supported way to let an in-progress download finish while away. (Its
   availability on the target device under iPadOS 26 is an open question to
   measure. [Target changed 2026-08-02 to an M4 iPad Pro, iPad16,3 - measure
   there, not on the A12Z these notes assumed.])
4. **`BGProcessingTask` - opportunistic progress while charging.** Maintenance
   grade (OS discretion, may not fire): hash-check parts, prune sources, brief
   resume attempts while on power. Complements, never the primary runtime.

**[BUILT 2026-08-07, same day - see [[build-progress]] 8cj. Background SEEDING
ships: `EngineState::Seeding` + an `audio` keepalive, default OFF. So the
"permanent foreground-only posture" below is superseded for the SERVE side. What
is NOT built and is not planned: background DOWNLOADING, which stays off because
it is the expensive half and seeding is the half that earns standing. The
paragraphs below are kept because the analysis behind the decision stays
accurate and is why the build is safe.]**

**[REOPENED 2026-08-07 by Anthony: "we need to come up with a clever way to keep
Kad, and padMule in general, always running in the background."** The 2026-08-04
"permanent posture" decision below is therefore back on the table as a FEATURE
question. The analysis above does not change - it was right - so this is not new
research, it is a decision to revisit plus two measurements nobody has taken.

Read the framing carefully, because it is the opposite of how it is usually put:
there is no BACKDOOR to find. Option 1 is a documented `UIBackgroundModes` key
that a FREE team may set - it is not a provisioning entitlement - and the only
thing that normally forbids it is App Store review 2.5.4. padMule is never
reviewed. **Sideloading is precisely what makes the ordinary mechanism available**,
so the work is engineering, not evasion.

WHAT ACTUALLY DECIDES IT, and it is measurable rather than arguable:

1. **Jetsam, not suspension, is the enemy.** Audio keepalive stops the SUSPEND;
   it does nothing about TERMINATION for memory. Background residency wants
   memory under ~100MB. **MEASURED 2026-08-07 on the device (build 48b5128,
   foreground, server connected, Kad up): `physFootprint` 30.8 MB, stable across
   samples, CPU falling to 0.1% idle.** So padMule sits at under a THIRD of the
   budget, and the risk that killed this idea in the abstract is much smaller
   than assumed. A seed-only background mode - no source hunting, no Kad
   lookups, no block scheduling - would sit below even that. **The memory
   objection is answered; what remains untested is LONGEVITY.**
2. **The 1s heartbeat is a UI-owned clock** (`EngineModel.startPolling`, a
   `Timer` on the MAIN RUNLOOP) and seven background duties fail silently if it
   stops - see `MuleEngine::heartbeat`. Under audio keepalive the app is not
   suspended so it would still fire, but resting a background posture on the
   UI's runloop is fragile. **Move the clock into Rust (a tokio interval) before
   trusting any of this.** Found 2026-08-07; not in the research above.
3. The two open questions from the original research were never measured, and the
   target device has since changed to an M4 iPad Pro: keepalive LONGEVITY
   overnight, and whether `BGContinuedProcessingTask` is eligible on iPadOS 26
   there.

**Clean pause/resume stays REQUIRED whatever is decided** - every one of these
mechanisms can be revoked or jetsam-killed, so the app must always degrade back
to pause-and-resume. That is why the hard requirement above is not weakened by
reopening this.]

What is genuinely impossible: a fully-supported, always-on, screen-off P2P
daemon like on desktop. Background `URLSession` (the only thing that truly
survives suspension) is HTTP/HTTPS-only and cannot carry the eD2k/Kad wire
protocol. So there is no "free" always-on.

**Decision:** v1 stays foreground-only with the clean pause/resume above (it is
honest, simple, and always correct). [SUPERSEDED 2026-08-04: the "add background
persistence later" half is DROPPED. Foreground-only is the permanent posture, so
the tiered feature described next is research, not a plan. The paragraph is kept
in place because the ANALYSIS stays accurate and is why the decision is safe.]
Add background persistence as a LATER,
OPT-IN, tiered feature (a "Keep active in background" toggle = the audio
keepalive with a clear battery warning + the <100MB memory discipline; a
"Seedbox mode" = Auto-Lock=Never; use BGContinuedProcessingTask on iPadOS 26 to
finish an active download; BGProcessingTask for charging-time upkeep). Crucially,
**clean pause/resume remains REQUIRED regardless** - every one of these
mechanisms can be revoked or jetsam-killed by the OS, so the app must always
degrade gracefully back to pause-and-resume. On-device measurement needed:
keepalive longevity on the target device/iPadOS 26 (now an M4 iPad Pro,
iPad16,3, since 2026-08-02 - not the A12Z assumed here), and whether
BGContinuedProcessingTask
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
