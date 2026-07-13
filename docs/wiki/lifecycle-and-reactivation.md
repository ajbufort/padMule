# Lifecycle Status + Clean Reactivation (hard requirement)

Updated: 2026-07-13

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

## Where it lands

- **Wave 3c+ (engine):** implement the state model + explicit `pause()`/
  `resume()` + the event stream. Even the CLI harness should exercise a
  simulated pause/resume so the logic is tested before the iPad UI exists.
- **Wave 8 (FFI + SwiftUI):** wire ScenePhase -> `pause()`/`resume()`; render
  the honest status indicator and per-transfer Paused badges; the calm
  background-pause messaging.

## Related

- [[ipados-constraints]] - why (the ~30s suspend + socket reclaim).
- [[arch-upstream-amule]], [[protocol-understanding]] - reconnect/re-bootstrap flows.
- [[build-progress]]
