# padMule iPadOS Platform Constraints Reference

Definitive platform-constraints reference for padMule: a Rust rewrite of aMule's eD2k/Kad engine behind a SwiftUI shell, targeting an iPad Pro 4th gen (A12Z, 6GB RAM, Wi-Fi only), sideloaded with a FREE Apple ID by a Windows-only developer with no Mac. iPadOS 18/26-era (Apple's 2025 renaming made the 2025-2026 release iPadOS 26; the constraints below are stable across 18 -> 26 except where the new BGContinuedProcessingTask is called out). Verdicts use ALLOWED / BLOCKED / REQUIRES. Corrections from verification have been applied and refuted claims dropped.

---

## 1. Listening sockets, inbound peers, and HighID reachability

The socket layer is NOT the blocker. A normal third-party iPadOS app can do everything the eMule/Kad model needs at the socket layer with no entitlement and no Local Network permission. The real constraints are background suspension (Section 2), App Store review friction (moot under sideload), and ordinary NAT reachability.

### Verdicts
- Inbound TCP `listen()`/`accept()` on an arbitrary port from public-internet peers: ALLOWED (no entitlement, no Local Network permission). Inbound TCP is explicitly exempt from Local Network privacy.
- UDP `bind()` + arbitrary `sendto()`/`recvfrom()` to/from public-internet peers (Kad, eD2k server UDP): ALLOWED (no permission). Receiving incoming UDP unicast is unconditionally exempt from Local Network privacy.
- Raw BSD sockets `SOCK_STREAM` / `SOCK_DGRAM` in-process: ALLOWED and not deprecated. Network.framework is RECOMMENDED for new code but NOT required.
- `SOCK_RAW` (raw IP/ICMP): BLOCKED (requires root). Not needed by eD2k/Kad.
- UDP/TCP directed at LOCAL-subnet / RFC1918 / link-local destinations: REQUIRES-PERMISSION (`NSLocalNetworkUsageDescription` + user prompt). The gate keys on the DESTINATION being a local address, not on the protocol.
- LAN multicast/broadcast (send and receive): REQUIRES-ENTITLEMENT `com.apple.developer.networking.multicast`. Not needed for unicast Kad/eD2k.
- Many concurrent sockets: ALLOWED but REQUIRES raising `RLIMIT_NOFILE` via `setrlimit` at startup (default soft limit ~256; every socket/file/pipe counts).
- HighID reachability over NAT: ALLOWED at the iOS layer (governed by router/NAT exactly like desktop); effectively BLOCKED on cellular due to carrier CGNAT - this is a network property, not an iOS restriction. padMule is Wi-Fi-only, so a normal home router + port mapping behaves like desktop.
- Keeping the listener + connections alive while backgrounded/suspended: BLOCKED for general use (see Section 2).

### Detail
- There is NO iOS entitlement for TCP/UDP client or server. The `com.apple.security.network.server` / `.client` keys are macOS App Sandbox constructs and do not apply on iOS.
- `NSLocalNetworkUsageDescription` gates OUTBOUND traffic to LOCAL addresses plus Bonjour/mDNS discovery. It does NOT gate internet peers and does NOT gate inbound. Loopback (127.0.0.1 / ::1) is never gated. Implemented deep in the TCP/UDP stack, so it applies to BSD sockets and Network.framework equally. If padMule only talks to internet peers/servers and accepts inbound from the internet, it can ship WITHOUT the key and WITHOUT ever prompting.
- Correction applied: receiving incoming UDP multicast/broadcast does NOT currently require Local Network access (Apple states only a prospective intent to change this, advising you code as if it did). The actually-enforced gate on multicast/broadcast, for both send and receive, is the distinct `com.apple.developer.networking.multicast` entitlement, not the Local Network prompt. Non-load-bearing for a unicast-only client.
- Keep the existing aMule BSD-socket reactor (kqueue/epoll-style) for the core engine (TCP peer sockets plus the single shared Kad UDP socket). Network.framework models UDP as one flow per remote endpoint, which is awkward for a single shared Kad socket, and does not map onto a select/kqueue reactor. Apple's own fallback guidance: if you need something Network.framework does not support, use BSD Sockets.
- fd-limit correction applied: on Darwin, `getrlimit` reports the `RLIMIT_NOFILE` hard limit as effectively unlimited (`RLIM_INFINITY`), but the real enforced ceiling is the sysctl `kern.maxfilesperproc`; `setrlimit` fails with EINVAL if you request above it. Clamp the requested soft limit to `OPEN_MAX` / `kern.maxfilesperproc`, not to the reported hard limit. The practical concurrent-socket ceiling is memory/jetsam pressure, not the fd count.
- HighID is a NAT/router problem exactly as on desktop: rely on UPnP/NAT-PMP port mapping and expect LowID fallback. iOS adds no inbound firewall of its own for a foreground app that is `listen()`ing.

---

## 2. Background lifecycle and the true background ceiling

This is the dominant constraint for the whole project. The honest engine model is foreground-only.

### Verdicts
- Open TCP/UDP sockets on background: BLOCKED past ~30s. The kernel reclaims them on suspend; handles fail with EBADF / ECONNABORTED. Must close and rebuild on foreground.
- Threads on background: BLOCKED. Suspension freezes all threads; no code runs.
- `beginBackgroundTask` finish-up window: ~30s, ALLOWED for checkpoint/quiesce only. It is an APP-WIDE budget (two tasks do not give you 60s), non-contractual, and the expiration handler must end the task in under ~1s or the watchdog kills the app (0x8badf00d).
- `BGAppRefreshTask` for transfers: BLOCKED. ~30s, OS-heuristic, not guaranteed to run.
- `BGProcessingTask` for continuous transfers: BLOCKED as primary runtime (several minutes, charging/network-gated, OS discretion, may not fire). ALLOWED for opportunistic maintenance only (hash-check part-files, prune known-clients, brief resume attempts while charging).
- `voip` background mode: BLOCKED. Legacy persistent-socket mode deprecated; modern PushKit+CallKit requires reporting a real call in the same runloop or the OS terminates the app. Not usable to keep a socket engine alive.
- `audio` / `location` background modes as a keepalive: REVIEW-BLOCKED (Guideline 2.5.4) but TECHNICALLY-ALLOWED on a sideloaded build. An active session prevents suspension and keeps YOUR OWN sockets alive with the screen off - but see the strong correction below; this is fragile, not a guarantee.
- Background `URLSession` transfers for eD2k/Kad: BLOCKED. HTTP/HTTPS only; raw-TCP `URLSessionStreamTask` is not supported under a background configuration; cannot carry the custom binary protocol.
- `BGContinuedProcessingTask` (iPadOS 26): ALLOWED for a user-initiated, bounded "finish this transfer" job with mandatory system progress UI. Does NOT provide indefinite always-on background P2P (it is "finish this job," not "run a DHT node forever").
- Plugged into power alone: no change. REQUIRES foreground; charging does not stop suspension, it only makes discretionary background runs likelier.
- Foreground + Auto-Lock=Never (+ Guided Access) + power: ALLOWED and UNLIMITED - full execution, all sockets alive. This is the only fully supported always-on path.

### The true background ceiling
For a supported build the ceiling is foreground-only for the live engine, plus ~30s finish-up and best-effort discrete `BGProcessingTask` windows. None of the supported mechanisms keep arbitrary custom TCP/UDP sockets alive across suspension. The realistic UX is: transfers PAUSE on background and RESUME on foreground. User leaves app -> ~30s to checkpoint -> suspended -> all server connections, client TCP sessions, and the Kad UDP socket are torn down (EBADF on any lingering handle) -> on return, the engine must reconnect to servers, re-bootstrap/refresh Kad, and re-issue source/A4AF requests. Part-file data already flushed to disk is safe; the transport is not.

### Corrections applied
- Guided Access toggle direction was inverted in the raw finding. To keep the screen on you must set "Mirror Display Auto-Lock" ON so Guided Access obeys Display and Brightness -> Auto-Lock = Never. With it OFF, Guided Access sleeps the display after ~20 minutes of inactivity regardless of Auto-Lock=Never. Note also that several kiosk vendors report this toggle is deprecated/absent on newer iPadOS and that Display Auto-Lock=Never alone suffices; its presence on iPadOS 26 / A12Z is not guaranteed.
- The audio-keepalive "apps are never suspended when audio is playing" claim is overstated. Apple DTS: the audio category only "allows your app to remain awake while your audio session is active, which isn't quite the same as guaranteeing it will not be suspended." The dominant long-run (overnight) failure mode is outright TERMINATION, not suspension: the system terminates backgrounded apps to reclaim tmp/Caches and under memory pressure, so background memory should stay under ~100MB, and mixable (non-"Now Playing") sessions get less protection. The core claim that it technically keeps a socket engine alive still stands, but treat it as fragile and killable mid-run.

---

## 3. Free-account sideload limits and available entitlements

All numbers are current through 2026 for a free Personal Team (Apple Account not enrolled in the paid Developer Program).

### Verdicts
- 7-day certificate/provisioning expiry: CONFIRMED. Installed app stops launching until re-signed.
- Max 3 sideloaded apps installed at once on the device: CONFIRMED.
- 10 App IDs per 7 days + 3 devices per 7 days: CONFIRMED. Rebuilding the SAME bundle ID reuses its App ID and does not burn a slot; churning NEW bundle IDs does.
- No TestFlight, no App Store, no AltStore PAL from the US: CONFIRMED. The 2024-2026 EU DMA / notarization / AltStore PAL changes give a US free-account user NO new capability; you stay on AltStore Classic free-provisioning.
- Push Notifications / APNs (`aps-environment`): BLOCKED on free team.
- App Groups (`com.apple.security.application-groups`): BLOCKED. No shared container between app and any extension/widget.
- Associated Domains: BLOCKED. No verified universal links, web-credential autofill, or App Clips.
- iCloud / CloudKit, Sign in with Apple, In-App Purchase / Apple Pay / Wallet: BLOCKED on free team.
- Network Extensions / System Extensions: BLOCKED (managed entitlement Apple only grants to enrolled/approved teams).
- `UIBackgroundModes` (audio, location, fetch, processing/BGTaskScheduler, bluetooth, external-accessory, voip, nearby-interaction): ALLOWED. These are Info.plist keys, NOT provisioning entitlements, so the provisioning server is never consulted.
- `remote-notification` background mode: BLOCKED. Inert without the push entitlement.
- Local notifications (UNUserNotificationCenter), camera, mic, photos: ALLOWED (privacy prompts, not team entitlements).
- Increased Memory Limit (`com.apple.developer.kernel.increased-memory-limit`): ALLOWED on a free team via the sideload pipeline (correction below).
- AltServer on Windows with same-Wi-Fi background 7-day auto-refresh: ALLOWED but REQUIRES iTunes + iCloud installed from apple.com directly (NOT the Microsoft Store versions). Unattended refresh on Windows is unreliable (Apple Mobile Device Service loses the device when locked) - plan for a human opening AltStore roughly weekly and hitting "Refresh All."
- No Mac required anywhere in the AltStore/Sideloadly path: CONFIRMED.
- Build unsigned .ipa on a hosted macOS CI runner, then sign + install locally from Windows with a free Apple ID: ALLOWED (working loop, no owned Mac).

### Corrections applied
- Increased Memory Limit is NOT a restricted, approval-gated entitlement. Apple's automated on-device provisioning (including a free Personal Team) will stamp it. As of AltStore Classic v2.2 (April 2025) it can be injected during free-Apple-ID signing, and the standalone GetMoreRam (AltSign/StosSign wrapper) applies it to any AltStore/SideStore-installed app signed with a free Apple ID, raising the cap toward ~75% of physical RAM. It is simply not exposed in Xcode's Signing and Capabilities UI on a personal team; the AltStore/SideStore + GetMoreRam path supplies it. padMule CAN raise its per-app memory ceiling on a free team (device-honoring is a separate open question - see Section 5 and Open questions).
- The claim that each extension consumes one of the 3 install slots is unconfirmed. The documented, verifiable cost of an extension is that it needs its own App ID and embedded profile, consuming from the separate "10 App IDs per 7 days" pool. Treat "each extension eats an App ID (of the 10/7-days)" as confirmed and "each extension eats one of the 3 install slots" as unconfirmed.

### Build/deploy loop with no Mac
GitHub Actions macOS runner runs `xcodebuild archive`, then the `.app` is packaged into an UNSIGNED `.ipa` (`CODE_SIGNING_ALLOWED=NO`, zip `Payload/padMule.app` into `App.ipa`). Download that artifact to the Windows PC; AltStore or Sideloadly does the code-signing locally with the free Apple ID at install time (fetching a dev cert + 7-day profile for your device from Apple, then re-signing). The CI-built binary must declare ONLY free-team-legal entitlements, or local re-signing fails or strips.

---

## 4. Rust-on-iOS toolchain and UniFFI

### Verdicts
- Full iOS artifact pipeline on Linux/WSL: PRACTICALLY REQUIRES macOS (correction below softens the earlier absolute "BLOCKED"). Recommended build host is a hosted macOS CI runner (or local Apple Silicon Mac); `rustup target add aarch64-apple-ios aarch64-apple-ios-sim`.
- Develop and unit-test the Rust engine on Linux/WSL against the host target (`cargo test`, lint, fast iteration): ALLOWED. This is the right place for the bulk of engine development.
- tokio multi-thread runtime + mio + many sockets as an iOS `staticlib`: ALLOWED (works in-process). REQUIRES raising `RLIMIT_NOFILE` (correction below) and a modest worker pool.
- SIGPIPE process-kill on tokio sockets: NOT A RISK. mio sets `SO_NOSIGPIPE` per-fd on Apple (matching libstd), so writes to a dead peer surface as EPIPE / BrokenPipe. REQUIRES a manual `signal(SIGPIPE, SIG_IGN)` at engine init ONLY if the lib does raw non-socket fd/pipe I/O - because a `staticlib` has no Rust `main`, the libstd runtime SIGPIPE-ignore never runs.
- Long-lived persistent socket while backgrounded: BLOCKED by iOS (Section 2), identical for Rust sockets or URLSession.
- UniFFI `async fn` -> Swift `async`/`await` and callback interfaces for engine->UI events: ALLOWED. REQUIRES handling Swift 6 `Sendable`/strict-concurrency rough edges and rolling your own cancellation (no built-in cancellation).
- App Store submission / notarization of a Rust static lib: ALLOWED (no Rust-specific blocker; irrelevant under sideload anyway).
- Bitcode for Rust code: N/A. Deprecated/removed by Apple since Xcode 14; keep `ENABLE_BITCODE` off.

### Corrections applied
- The absolute "cannot produce iOS artifacts on Linux; the SDK dependency is in the compile" is technically wrong. A Rust `staticlib` for `aarch64-apple-ios` is an `ar` archive of Mach-O object files that rustc/LLVM emit without invoking Apple's platform linker or system libraries; the objc2 cross-compiling guide documents cross-compiling to Apple targets (including using `iPhoneOS.sdk`) from a Linux host via `rust-lld` plus a copied SDK pointed at with `SDKROOT` - `xcrun` is only used for auto-inference of the SDK path when `SDKROOT` is unset. The SDK dylibs are needed at FINAL-link time, which for an app happens in Xcode on the Mac regardless. So a Linux-built `.a` plus final link on Mac is feasible, not impossible. The genuine obstacles are practical/legal, not a hard technical wall: (1) the SDK must be obtained, and Apple's Xcode SLA restricts SDK use to Apple-branded hardware; (2) C-dependency TLS crates (ring, aws-lc-rs) need a C cross-toolchain plus SDK headers on Linux; (3) `uniffi-bindgen` and xcframework packaging are macOS-oriented. Net: the macOS/CI build host remains the sound, low-risk recommendation, but not because the compile is impossible on Linux.
- UniFFI version: the latest published `uniffi` crate is 0.32.0 (2026-06-30), with 0.31.2 (2026-06-17) and 0.31.1 (2026-04-13) in between; 0.29.5 (2025-11-14) is a widely-used stable baseline. The recommendation (UniFFI) is unchanged - actively maintained by Mozilla, battle-tested in Firefox mobile.
- tokio "many sockets" caveat: iOS/Darwin inherits the low default soft `RLIMIT_NOFILE` (~256, sockets included). A P2P client opening hundreds of concurrent sockets MUST raise the soft limit via `setrlimit(RLIMIT_NOFILE, ...)` at startup or it will hit EMFILE at ~256. Required design step, not a blocker (see Section 1 for the Darwin clamp-to-`kern.maxfilesperproc` nuance).

### Detail
- UniFFI model fits the use case: the foreign side supplies the executor, so Swift drives the Rust future to completion via its own async runtime - you are not forced to pin a global tokio reactor to the UI. Callback interfaces / foreign traits are the idiomatic engine->UI event and progress channel (Swift implements a protocol handed to Rust). Large/hot payloads should cross as opaque handle objects (`Arc<T>` interface types) pulled lazily, not big `Vec<u8>` copied per call.
- Known maturity gap: partial Swift 6 strict-concurrency conformance; generated foreign-trait protocols demand `Sendable`, pushing `Sendable` obligations onto Swift implementations. Plan for `@unchecked Sendable` / actor wrapping and cooperative cancellation (flag/channel the future checks).
- Packaging: use an XCFramework (device arm64 + simulator arm64); `cargo-lipo` is deprecated and a fat `lipo` binary cannot hold both arm64 slices. Flow (on macOS): `crate-type = ["staticlib","cdylib"]`; build both iOS targets; `uniffi-bindgen generate --library <dylib> --language swift`; `xcodebuild -create-xcframework`. Ship as a SwiftPM `binaryTarget` (Mozilla application-services pattern). CI shape: Linux jobs run `cargo test`/lint on the host target; a macOS job does the two iOS-target builds + bindgen + xcframework assembly.
- FFI boundary must be panic-safe: never let a Rust panic unwind into Swift. Catch at every `#[uniffi::export]` entry and convert to a typed error. Binary-size mitigations: `opt-level = "z"/"s"`, `lto = true`, `codegen-units = 1`, `strip = true`; a static `.a` dead-strips smaller than a dylib. Watch for duplicate-symbol / multiple-tokio issues if more than one Rust staticlib is linked.

---

## 5. Storage, data protection, and memory

### Sandbox layout
- `Documents/`: user content; backed up; OS does NOT purge. User-visible AND user-deletable once file sharing is enabled.
- `Library/Application Support/`: app files needed to run; backed up by default; OS does NOT purge.
- `Library/Caches/`: OS MAY delete under storage pressure.
- `tmp/`: OS MAY purge when the app is not running.

### Verdicts
- Purge-safe in-progress storage: REQUIRES `Library/Application Support/padMule/incomplete/` (or `Documents/`) with `isExcludedFromBackupKey = true`. BLOCKED (unsafe) in `Caches/` and `tmp/`, which the OS can reclaim and destroy a half-finished multi-GB download.
- Backing up multi-GB partials: BLOCKED by design intent. Set `isExcludedFromBackupKey` since partials are re-downloadable per Apple guidance (the exclude flag, NOT relocation to Caches/tmp, is the correct mechanism).
- File I/O while the screen is locked: ALLOWED by the default Data Protection class C (`NSFileProtectionCompleteUntilFirstUserAuthentication`) - the class key is not evicted on lock; files are read/write after the first unlock since boot. REQUIRES that padMule NOT opt into `NSFileProtectionComplete` (class A), NOT set `com.apple.developer.default-data-protection` to Complete, and NOT write with `.completeFileProtection`. IMPORTANT correction: this is necessary-but-NOT-sufficient for "download while screen off" - see below.
- Per-app storage cap: ALLOWED to use most of free device storage; no hard per-app quota (the 4GB bundle / 200MB cellular limits are about the install binary, not runtime writes). REQUIRES free-space checks and ENOSPC handling.
- Expose finished files to the user: ALLOWED via the simplest path - set BOTH `UIFileSharingEnabled = YES` and `LSSupportsOpeningDocumentsInPlace = YES` so `Documents/` appears under "On My iPad" in Files, with zero extra code. One key alone is insufficient. No File Provider extension REQUIRED for v1 (which also avoids the App Groups problem from Section 3).
- RAM headroom: baseline ~3GB per app on the A12Z 6GB iPad (~half of physical RAM); exceeding it triggers an immediate jetsam kill. REQUIRES streaming-to-disk and buffer caps. Increased Memory Limit entitlement ALLOWED (and usable on free/AltStore sideload per Section 3) to raise toward ~4.5GB on supported devices - treat as best-effort, NOT guaranteed on A12Z.

### Critical correction: data protection is necessary but not sufficient
"Download while screen locked: ALLOWED by default" is only true for file I/O in a still-executing (foreground) process. The real blocker for an unattended, screen-off download is background EXECUTION, not encryption: iOS suspends the app ~30s after backgrounding and tears down raw TCP/UDP sockets (Section 2). Only a background `URLSession` (HTTP/HTTPS) survives suspension, and it cannot carry the custom eD2k/Kad wire protocol. So an eMule/Kad download over custom sockets STALLS when the screen locks and the app backgrounds, regardless of class C. Read the class-C verdict strictly as "file writes do not fail while the device is locked AND the app is still running in the foreground (or under a keepalive)."

### Memory correction
The widely-cited ~5GB per-app cap is the M1 iPad Pro's number, not the A12Z's. On the A12Z/A12X 6GB iPad Pro the baseline is ~3GB, with the in-the-wild entitlement raise reported at ~4.5GB. Never apply the 5GB figure to the A12Z. Query live headroom with `os_proc_available_memory()` and wire `didReceiveMemoryWarning` into the engine to shed caches.

### Bottom-line storage plan
- Incomplete part-files/metadata (aMule `NNN.part` / `NNN.part.met`): `Library/Application Support/padMule/incomplete/`, default protection (class C), `isExcludedFromBackup = true`. Not purgeable, writable while locked (foreground), not in backups.
- Completed files: atomic move (same-volume rename) into `Documents/` on finish; expose via the two Info.plist keys. `Documents/` holds ONLY finished files (it is user-deletable).
- Persistent small state (known.met, server.met, nodes.dat, prefs): `Library/Application Support/padMule/`, backed up (no exclude flag).
- Never use `Caches/` or `tmp/` for anything a download must keep. Never opt into `NSFileProtectionComplete`.
- Free-disk guarding is a first-class engine feature: query `volumeAvailableCapacityForImportantUsageKey` before allocating a new part-file and while writing; on ENOSPC / `NSFileWriteOutOfSpaceError`, pause and surface an error rather than crash. aMule preallocates part-files, so full-size preallocation MUST be gated on this check.

---

## Architecture impacts on padMule

- Foreground-first engine is the honest, load-bearing model. Design the amuled/EC core so UIApplication background = graceful PAUSE, not continued operation. There is no supported iPadOS background daemon; the "headless always-on amuled + EC" seam holds only while the app is foreground. This is the single biggest deviation from desktop eMule.
- Keep the aMule BSD-socket reactor; do NOT rewrite the transport onto Network.framework. `listen()`/`accept()`/`bind()`/`sendto()`/`recvfrom()` to internet peers all work with no entitlement. Call `setrlimit(RLIMIT_NOFILE)` early (clamped to `kern.maxfilesperproc`) before scaling to hundreds of peers; budget the real ceiling as memory/jetsam.
- Lifecycle state machine keyed on UIApplication state: foreground = full engine; willResignActive/didEnterBackground = `beginBackgroundTask` (~30s) to checkpoint `.part.met`, flush buffers, quiesce queues; suspended = engine frozen; willEnterForeground = reconnect servers, re-bootstrap/refresh Kad, re-issue source requests. Treat every socket (client TCP, Kad UDP) as disposable across a lifecycle transition and expect EBADF/ECONNABORTED after any suspension - a dropped socket is a rebuild event, not a hard error.
- Kad DHT participation (needs steady UDP presence to hold routing-table membership) is incompatible with suspension. Plan for Kad re-bootstrap on every foreground return rather than continuous membership.
- HighID relies on NAT/router exactly like desktop: UPnP/NAT-PMP port mapping, LowID fallback. padMule is Wi-Fi-only, so a normal home router behaves like desktop; there is no iOS-level inbound block to design around.
- "Download with screen off" is a product decision that must be made explicitly, because the OS does not grant it for free. Pick ONE: (a) sideload-only silent-audio or continuous-location keepalive to hold the process live - accept heavy battery cost, handle audio-interruption re-arm, keep background memory under ~100MB, and treat it as fragile/killable; or (b) a foreground kiosk/seedbox mode (Auto-Lock=Never, Guided Access with "Mirror Display Auto-Lock" ON, plugged in) which is fully supported and unlimited. `BGContinuedProcessingTask` (iPadOS 26) is the most legitimate way to let a single user-initiated "finish this file" job run past the ~30s window, but it is not indefinite seeding. `BGProcessingTask` is maintenance-only (hash-check, prune, brief resume while charging), never the primary runtime. Background `URLSession` is irrelevant (HTTP/HTTPS only).
- In-process FFI seam via UniFFI: engine owns the tokio runtime (an `Arc`-backed UniFFI interface, started/stopped explicitly, modest worker pool). Engine->UI progress/events flow through callback interfaces, not polling; large payloads cross as opaque handles pulled lazily. Every FFI entry is panic-safe (catch and convert to a typed error). Bake cooperative cancellation into the async API from the start and budget for Swift 6 `Sendable` wrapping. If the engine ever does raw non-socket fd I/O, `signal(SIGPIPE, SIG_IGN)` once at init; socket writes are already SIGPIPE-safe via `SO_NOSIGPIPE`.
- Crate split and build loop: keep the engine as a pure-Rust workspace developed/tested on WSL against the host target; the iOS `.a` + XCFramework are produced on a hosted macOS CI runner (Linux jobs = test/lint; macOS job = two iOS-target builds + `uniffi-bindgen` + `xcodebuild -create-xcframework`). Ship as a SwiftPM `binaryTarget` (device arm64 + simulator arm64), never `lipo`d. Keep `ENABLE_BITCODE` off.
- Single monolithic app target. App Groups are BLOCKED, so no share extension, custom keyboard, or data-backed WidgetKit widget (they need a shared container). This also keeps the port simpler and conserves the free-team App-ID pool (each extension would consume an App ID of the 10/7-days). A single target leaves room for at most 2 other sideloaded apps under the 3-install ceiling.
- Free-team hygiene: assume a hard 7-day refresh cadence - persist all state to disk, never assume process continuity, and never let any expiry logic lock the user out on the refresh boundary. Ship an entitlements file with ONLY free-team-legal keys (a CI build declaring a blocked entitlement will fail to re-sign locally). Drop `remote-notification` and any silent-push wake; drive user-facing alerts via LOCAL notifications only. No iCloud/CloudKit -> device-local persistence (SQLite/files); any cross-device sync must use a non-Apple backend over plain networking. Use custom URL schemes (not universal links) for deep-linking.
- Part-file location is fixed: `Library/Application Support/padMule/incomplete/` with `isExcludedFromBackup=true` and DEFAULT (class C) protection - not `Documents/` (user could delete a live download), not `Caches/`/`tmp/` (OS purges). Finalize is a two-phase atomic move into `Documents/`. Add a build lint asserting `com.apple.developer.default-data-protection` is absent or set to CompleteUntilFirstUserAuthentication.
- Memory: engine streams part-file blocks to disk and caps in-RAM structures (source lists, hashsets, up/download buffers) against a ~3GB budget on the A12Z (not 6GB). Ship `com.apple.developer.kernel.increased-memory-limit=true` (harmless on unsupported devices, may lift toward ~4.5GB, compatible with AltStore free-account sideload via GetMoreRam) but design for the ~3GB floor and treat any raise as unverified on this SoC.
- Files-app exposure via `UIFileSharingEnabled=YES` + `LSSupportsOpeningDocumentsInPlace=YES`; no File Provider extension in v1.

---

## Open questions

1. Does the A12Z specifically honor `com.apple.developer.kernel.increased-memory-limit` and raise the cap toward ~4.5GB, or does it silently ignore the entitlement? Apple says "only available on some device models" and publishes no list; there are forum reports of no change after adding it. Must be measured on-device with `os_proc_available_memory()`.
2. Will Apple's free on-device provisioning continue to stamp `com.apple.developer.kernel.increased-memory-limit` (it works today because it is non-restricted, but Apple could reclassify it, and there is no explicit Apple statement guaranteeing free-team access)?
3. Does an app extension consume one of the 3 install slots, or only an App ID from the 10-per-7-days pool? No authoritative source pins this down.
4. Does the silent-audio (or continuous-location) keepalive still reliably prevent suspension on iPadOS 26 on the A12Z, and how many hours does a non-"Now Playing," mixable-session P2P engine survive before memory-pressure termination?
5. Is `BGContinuedProcessingTask` actually available/eligible on the A12Z under iPadOS 26 (via `BGTaskScheduler.supportedResources`), and what is its exact maximum duration, screen-off tolerance, and any compute-vs-network resource restriction?
6. What is the actual enforced hard `RLIMIT_NOFILE` / `kern.maxfilesperproc` value on current iPadOS on this hardware, and what is the real concurrent-socket ceiling once memory/jetsam pressure dominates?
7. Does the "Mirror Display Auto-Lock" toggle still exist in the iPadOS 26 Guided Access UI on an A12Z, or does Display Auto-Lock=Never alone now suffice for a kiosk/seedbox mode?
8. Can a real tokio+TLS engine (with ring or aws-lc-rs C/asm dependencies) be fully cross-compiled to an iOS staticlib on Linux in practice, given the C cross-toolchain + SDK-header requirement and Apple's Xcode SLA restricting SDK use to Apple hardware - or does the C-crypto step force the macOS build host regardless?
9. What is the precise current TN3179 wording on the public-internet / loopback / inbound exemptions and the exact "local network address" range set (does it include the full RFC1918 space, link-local, and the CGNAT 100.64/10 range)? The operation list is inferred from the still-live superseded FAQ-2 plus secondary sources; confirm edge cases before relying on them.
10. Does a connected UDP socket to a PUBLIC IP trigger no Local Network prompt (the governing "outgoing to a LOCAL address" rule implies not, and public servers are widely reported never to prompt, but the FAQ bullet "Connecting a UDP socket - yes" is terse)? Worth an on-device confirmation.
11. What is the real `beginBackgroundTask` grant on the A12Z under memory/thermal pressure (the ~30s figure is non-contractual and could be less)? Measure, do not hard-code.
12. Does a sideloaded (AltStore/dev-signed) build face any OS-level runtime restriction beyond the skipped review, and does foreground-but-inactive multitasking (Split View, Slide Over, Stage Manager where padMule is visible but not frontmost) change socket-reclaim behavior versus full foreground?
13. Is unattended AltServer background refresh reliable enough on Windows to avoid weekly manual "Refresh All," or should the design simply assume a human re-signs weekly? SideStore's on-device WireGuard-tunnel refresh (needs an initial pairing file) is the more hands-off alternative but was not stress-tested.
14. Does a background `URLSession` transfer completing in the post-reboot / pre-first-unlock window fail to write under class C (files briefly inaccessible)? Low practical risk, not verified against a dated source.
15. What is the exact baseline jetsam limit for the 6GB A12Z under iPadOS 26 specifically (the ~3GB figure comes from 2021 reporting and can shift between OS versions)?
