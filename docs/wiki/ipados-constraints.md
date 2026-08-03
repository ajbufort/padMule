# iPadOS Platform Constraints (padMule)

Updated: 2026-08-02 (TARGET DEVICE CHANGED - see the banner below)

Distilled from adversarially-verified 2026 research. Full reference:
`docs/raw/ipados-constraints-research-2026-07-12.md`. Free Apple ID sideload, no
Mac. Confidence high except Rust-on-iOS (medium).

> **TARGET DEVICE CHANGED (2026-08-02, confirmed by Anthony).** The target is now
> an **iPad Pro 11-inch, M4 generation**: `iPad16,3`, board `J717AP`, arm64e,
> iPadOS 26.5.2, 512GB with ~476GB free - read directly off the device over USB
> ([[ipad-usb-tooling]]), not assumed. It REPLACES the original target, an iPad
> Pro 4th gen (2020, A12Z, 6GB RAM).
>
> Everything below that is a PLATFORM rule (sandbox, background suspension,
> storage locations, sideload limits, no multicast) is unaffected - those are
> iPadOS behaviours, not hardware ones, and iPadOS 26 is what was already
> assumed. What IS affected is anything derived from A12Z SILICON: the "~3GB RAM"
> budget below was calibrated to a 6GB A12Z, and an M4 iPad Pro has substantially
> more (8GB or 16GB depending on storage tier - NOT yet read off the device, so
> not asserted here). Re-derive rather than scale the old number, and do not let
> the extra headroom weaken the stream-to-disk design: a P2P client should not
> hold a multi-GB file in RAM on any machine.

## The load-bearing verdicts

- **Sockets are NOT the blocker.** A normal app may `listen()`/`accept()`
  inbound TCP and `bind`/`sendto`/`recvfrom` arbitrary UDP to internet peers
  with NO entitlement and NO Local Network prompt (inbound + internet
  destinations are exempt; the prompt only gates LOCAL-subnet destinations).
  Keep BSD sockets + a reactor; do NOT rewrite onto Network.framework (it
  models UDP as one-flow-per-endpoint, wrong for a single shared Kad socket).
  MUST `setrlimit(RLIMIT_NOFILE)` at startup (default soft ~256), clamped to
  `kern.maxfilesperproc`.
- **Background = the dominant constraint. Foreground-only is the honest engine
  model.** On backgrounding, ~30s then the app suspends: threads freeze, all
  TCP/UDP sockets are reclaimed (EBADF/ECONNABORTED). No supported mechanism
  keeps custom-protocol sockets alive across suspension (background URLSession
  is HTTP-only). Realistic UX: transfers PAUSE on background, RESUME on
  foreground; Kad must re-bootstrap each return. Always-on requires a
  foreground kiosk mode (Auto-Lock=Never, plugged in) or a fragile,
  killable audio/location keepalive (sideload-only, battery-heavy, keep bg mem
  < ~100MB). iPadOS 26 `BGContinuedProcessingTask` = bounded "finish this file"
  with system progress UI, not indefinite seeding.
- **Free-team sideload limits:** 7-day re-sign, max 3 installed apps, 10 App
  IDs / 7 days. BLOCKED: Push, App Groups, iCloud, Network Extensions,
  Associated Domains. ALLOWED: all `UIBackgroundModes` Info.plist keys, local
  notifications, and (via AltStore + GetMoreRam) the increased-memory-limit
  entitlement. `UIBackgroundModes` keys are not provisioning entitlements, so
  free teams can set them.
- **Build/deploy with no (usable) Mac:** engine develops + unit-tests on WSL
  (host target); iOS `.a` + XCFramework built on a hosted macOS CI runner
  (uniffi-bindgen + `xcodebuild -create-xcframework`); local sign+install from
  Windows via Sideloadly with the free Apple ID (AltStore died on -22411).
  Working loop, no Mac - PROVEN, the app runs on-device.
  (Linux-only iOS builds are technically possible but the C-crypto + SDK/SLA
  friction makes CI-macOS the sound choice.)
  - **Anthony's 2011 Mac mini does NOT change this (confirmed 2026-07-16):** it
    maxes at macOS 10.13 -> Xcode 10.1 -> iOS 12 SDK, but the iPad Pro 4th gen
    [the target since 2026-08-02 is the M4 iPad Pro (iPad16,3); the point
    stands - it is on iPadOS 26.5.2 and can't downgrade] is on **iPadOS
    26.5.2** and can't downgrade, so the mini CANNOT build/sign
    for the device (App-Store builds would need Xcode 26 / macOS Tahoe; even a
    sideload SDK floor is far past Xcode 10 - see [[mac-toolchain-setup]] for
    the verified chain). CI-macOS builds the `.ipa` (deployment target iOS 16
    installs fine on iPadOS 26); Sideloadly on the Windows host installs it
    (AltServer failed here with -22411). The mini is optional. Only the final
    link+sign needs Apple tooling.
- **Rust-on-iOS:** tokio+mio staticlib works in-process; UniFFI (0.29+ stable,
  0.32 latest) for the Swift boundary with async + callback interfaces; every
  FFI entry panic-safe; XCFramework (device + sim arm64), no `lipo`, bitcode
  off; `signal(SIGPIPE,SIG_IGN)` only if doing raw non-socket fd I/O.
- **Storage:** in-progress part-files -> `Library/Application Support/padMule/
  incomplete/` with `isExcludedFromBackup=true`, DEFAULT protection (class C =
  writable while locked, in-foreground). NEVER `Caches/`/`tmp/` (purged) or
  `NSFileProtectionComplete` (unreadable when locked). Finished files -> atomic
  move to `Documents/`, exposed via `UIFileSharingEnabled` +
  `LSSupportsOpeningDocumentsInPlace`. [SUPERSEDED 2026-08-02: the "~3GB RAM on
  A12Z (not 6)" budget was calibrated to the OLD target device; the M4 iPad Pro
  has more, and the figure needs re-deriving - see the banner at the top.] Stream
  to disk regardless; guard free space before preallocating part-files [DONE
  2026-08-02, build-progress 8ap: PartStore::create refuses up front and keeps a
  256MB margin].

## Consequences for the design

1. The engine core is a lifecycle state machine keyed on UIApplication state
   (foreground=run, background=checkpoint in ~30s then frozen, foreground
   return=rebuild sockets + reconnect servers + re-bootstrap Kad). Every socket
   is disposable across a transition. This is the biggest deviation from
   desktop aMule and must be designed in from the start, not bolted on.
2. In-process UniFFI seam confirmed correct; EC stays a parity/desktop-control
   feature, not the UI boundary.
3. Single monolithic app target (App Groups blocked -> no extensions/widgets
   sharing a container); conserves the 3-install / App-ID budget.
4. Part-file path, data-protection class, and free-space guarding are
   first-class engine requirements, plus a build lint that the entitlements
   file contains only free-team-legal keys.

Unresolved items to measure on-device are in the full reference's "Open
questions" (A12Z memory-entitlement honoring, keepalive longevity, exact
fd/beginBackgroundTask limits, etc.).

## Related

- [[arch-upstream-amule]]
- [[decisions-and-lessons]]
