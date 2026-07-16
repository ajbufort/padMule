# Mac Toolchain Setup (getting padMule onto the iPad)

Updated: 2026-07-16

How to build + sign padMule's iOS app for Anthony's **iPad Pro 4th gen running
iPadOS 26.5.2**, given the available Mac is a **2011 Mac mini (Macmini5,x, 32GB,
non-Metal)**. The engine + [[padmule-ios-app-path]] FFI seam are done; this is the
last piece before the SwiftUI shell (Wave 8, [[build-progress]]).

## The blocker (verified 2026-07-16)

The standard chain is broken at the OCLP step:

`iPadOS 26.5.2` -> needs **Xcode 26** -> needs **macOS Tahoe 26.2+**
(developer.apple.com/xcode/system-requirements) -> **OpenCore Legacy Patcher has
NO Tahoe 26 support** (dortania issue #1167; v3.0 missed its winter-2025 deadline,
no public update). OCLP's Intel road effectively ENDS at Tahoe for architectural
reasons - it works by redirecting Intel code that disappears as macOS goes
Apple-silicon-only. And non-Metal Macs (2011 and older) are a degraded tier
regardless (graphical glitches; **the iOS Simulator needs Metal and will not run**).

=> **No configuration of the 2011 mini runs the Xcode this iPad requires.**

## The escape hatch: padMule is sideload-only anyway

Apple's "must build with Xcode 26 / iOS 26 SDK" mandate (from 2026-04-28) applies
**only to App Store submissions**. padMule can never be App-Store distributed (a
P2P client - see [[ipados-constraints]]), so it does not bind us. **Sideloading has
no minimum-SDK gate**, and iOS is backward compatible: an app built against an
older SDK runs on iPadOS 26 (only ~2 major versions back - 26 is the year-based
rename of what would have been 19).

## The three viable paths

| Path | Build machine | Debugger? | Cost |
|------|---------------|-----------|------|
| **A. Use the 2011 mini** | OCLP -> macOS **Ventura 13** + **Xcode 15** | No (log-only) | free |
| **B. Used M1 Mac mini** (RECOMMENDED) | macOS Tahoe 26 + Xcode 26 natively | **Yes**, full | ~$300-400 used |
| **C. CI, no Mac at all** | GitHub Actions macOS runner (Xcode 26) | No (log-only) | free tier |

All three end the same way: produce a signed `.ipa` and **install it with AltStore
/ Sideloadly**. AltServer runs on Anthony's **Windows host** (the same box as this
WSL2 dev env). Free-Apple-ID signing expires every **7 days**; AltStore auto-resigns
over Wi-Fi.

Path A costs you the Xcode debugger + Simulator and a slow IDE, but the CPU+32GB
+SSD compile fine. Path B is the only one with real on-device debugging - worth it
if you will iterate on the UI. Path C needs zero hardware but has the slowest loop
(push -> CI -> download .ipa -> sideload).

## DE-RISK FIRST (do this before any OCLP install)

Validate the **sideload leg** before investing days in OCLP: get a hello-world
`.ipa` (from CI/path C, or any borrowed Mac), and confirm **AltStore installs and
runs it on the iPadOS 26 iPad**. If that works, the whole approach is sound and you
can then pick a build machine. If it does not, no build machine helps.

## Phase A - the 2011 mini as a build box (path A)

1. Identify the model: About This Mac -> System Report -> Model Identifier
   (Macmini5,1 / 5,2 / 5,3). All are non-Metal.
2. **SSD**: if it is still on the stock 5400rpm HDD, replace it first - the single
   biggest speedup. Keep the 32GB RAM.
3. OCLP (github.com/dortania/OpenCore-Legacy-Patcher): "Create macOS Installer" ->
   **Ventura 13** (the mature non-Metal target; do NOT chase Sonoma/Sequoia/Tahoe
   here) -> flash a >=16GB USB -> "Build and Install OpenCore" to the USB, then the
   internal SSD -> install macOS -> **run the Post-Install Root Patch** (the
   non-Metal graphics patches) -> set OpenCore to auto-boot.
4. Install **Xcode 15** (via `xcodes` - the App Store will not offer old versions);
   `xcode-select --install`.
5. Rust: `curl https://sh.rustup.rs -sSf | sh`; `rustup target add aarch64-apple-ios`.
   (Skip the sim target - the Simulator will not run here.)

## Phase B - wire padMule in (any path)

1. Build the FFI staticlib for the device:
   `cargo build -p mule-ffi --release --target aarch64-apple-ios`
   -> `target/aarch64-apple-ios/release/libmule_ffi.a`.
2. Generate the Swift bindings (this command is proven working on the dev box):
   `cargo run -p mule-ffi --bin uniffi-bindgen -- generate --library
   target/aarch64-apple-ios/release/libmule_ffi.a --language swift --out-dir ios/gen`
   -> `mule_ffi.swift` + `mule_ffiFFI.h` + `mule_ffiFFI.modulemap`.
3. Xcode iOS App project (`ios/padMule`); set a LOW deployment target (e.g. iOS 15-17)
   so an older SDK build still installs on iPadOS 26. Add `mule_ffi.swift`; link
   `libmule_ffi.a`; add the header/modulemap to the module search path.
4. Build the SwiftUI shell against `MuleEngine` (the FFI facade): honest status
   notice + Paused badges + Reconnecting banner; wire `ScenePhase` ->
   `MuleEngine.pause()/resume()` ([[lifecycle-and-reactivation]]).

## Phase C - sideload to the iPad (the ACTIVE path; CI builds the .ipa)

CI (path C) already emits an UNSIGNED `padMule.ipa` artifact - AltStore re-signs it
with a free Apple ID at install, so no Xcode/Apple secrets are involved.

1. **Get it**: GitHub -> Actions -> latest green run -> Artifacts -> `padMule-ipa`
   (downloads as a **.zip**; unzip to get `padMule.ipa`).
2. **Windows prep - THE #1 FAILURE**: AltServer needs the STANDALONE iTunes and
   iCloud, NOT the Microsoft Store builds (it cannot talk to those at all). If the
   Store versions are installed, UNINSTALL them first.
   TRAP (hit 2026-07-16): apple.com/itunes now advertises ONLY the Store build -
   the standalone installers still exist, Apple just stopped linking them. These
   were verified live 2026-07-16:
   - iTunes 64-bit: `https://www.apple.com/itunes/download/win64`
     (301 -> a real iTunes64Setup.exe, ~208 MB, built 2026-03; current, just unlisted)
   - iCloud: `https://updates.cdn-apple.com/2020/windows/001-39935-20200911-1A70AA56-F448-11EA-8CC0-99D41950005E/iCloudSetup.exe`
     (~161 MB; the link AltStore's own FAQ specifies. It looks ancient and that is
     fine - it is the last standalone iCloud Apple shipped.)
3. Install **AltServer**: `https://cdn.altstore.io/file/altstore/altinstaller.zip`
   (~9 MB) -> unzip -> Setup.exe. **Run AltServer as administrator.** It lives in
   the system tray.
4. iPad by USB -> unlock -> **Trust This Computer**. In iTunes tick **"Sync with
   this iPad over Wi-Fi"** (required for AltStore's wireless 7-day refresh).
5. Tray -> **Install AltStore** -> pick the iPad -> Apple ID (Anthony's primary,
   already device-activated). 2FA prompts for a 6-digit code.
   TRAP (hit 2026-07-16, UNRESOLVED): **"This action cannot be completed at this
   time (-22411)"**. This is Apple's generic developer-service failure surfaced
   through AltServer, raised during the portal steps (register device -> create
   App ID -> issue provisioning profile). It has **no documented root cause**:
   AltStore's own error-codes page lists -22410 but NOT -22411, the
   troubleshooting guide never mentions it, and issues #417/#785/#1720 are open
   with reinstall-everything reported as not helping.
   One commonly cited trigger is an Apple ID never signed in on real hardware
   (Apple will not issue a free cert to an account it has not seen on a device).
   That is a REAL cause but was NOT ours - Anthony used his primary ID.
   Cheap checks, in order: Apple System Status (developer services);
   AltServer >= 1.7.3 (tray -> About; it fixed auth failures 1100/-22410); any
   MDM profile on the iPad (implicated in several reports); retry later (some
   reports are transient).
   => DO NOT SINK TIME HERE. Use **Sideloadly** instead (step 8) - an
   independent implementation of the same free-signing trick that does not share
   AltServer's Apple-auth path. Confirmed working on iPadOS 26 / Windows.
6. iPad -> Settings -> General -> **VPN & Device Management** -> trust the cert.
   (AltStore's docs call this "Profiles & Device Management" - the older name.)
7. iPad -> Settings -> Privacy & Security -> **Developer Mode** ON -> restart.
   GOTCHA: the toggle only APPEARS once a dev-signed app has been installed, so do
   step 5 first if you cannot find it.
8. Put the `.ipa` where the iPad's **Files** app can see it (iCloud Drive), then
   AltStore -> **My Apps** -> **+** -> pick it.
   **Sideloadly (sideloadly.io) is the RECOMMENDED route** after the -22411 wall:
   install it on Windows, plug the iPad in by USB, drag `padMule.ipa` onto it,
   enter the Apple ID, hit Start. No AltStore, no Files-app shuffle, no Wi-Fi
   sync, and it does not consume an AltStore app slot. It reuses the SAME free
   7-day certificate mechanism (so steps 6/7 - trust the cert, Developer Mode -
   still apply), but it is a separate codebase that does not share AltServer's
   Apple-auth path. Tradeoff: no auto-refresh - re-run it every 7 days by hand.
   For proving the sideload leg works at all, that tradeoff is irrelevant.
9. LIMITS of free-ID signing: apps expire every **7 days** (keep AltServer running
   on the same Wi-Fi and AltStore auto-refreshes) and **max 3 sideloaded apps**.
10. Debug by what the UI shows - there is no Xcode device support for iPadOS 26 on
    paths A/C, so the app's own status line IS the diagnostic. The Status screen
    shows State / Status / Server / ID (HighID|LowID) / Kad contacts.

## What the first real device run taught us (2026-07-16)

padMule RAN on the iPad first try: State running, Status Connected, Kad climbing
21 -> 158 contacts. Two findings, both now fixed or recorded:

1. **The ID type was computed and thrown away.** `start()` emitted
   `Server("Connected to <addr> (HighID)")` and then `Status("Connected")`; both
   land in the same 1s `drainEvents()` batch and Swift applied them in order, so
   the honest line was overwritten before a frame rendered. FIXED: `ServerInfo`
   is now engine state (not a transient event), `online_status()` carries the ID
   type, and the UI polls `server_info()` as a SNAPSHOT with its own row. Lesson:
   **an event is not state** - anything the UI must keep showing has to be
   readable at any time, not announced once.
2. **UPnP CANNOT WORK on iOS.** The "find devices on local networks" prompt was
   `upnp::discover()` firing SSDP M-SEARCH at multicast 239.255.255.250. Blocked
   twice: (a) `NSLocalNetworkUsageDescription` was missing, and without it iOS 14+
   **silently drops** every LAN packet - no error (developer.apple.com/forums/thread/661606);
   (b) multicast on real hardware needs the RESTRICTED
   `com.apple.developer.networking.multicast` entitlement, which needs Apple
   approval and is UNREACHABLE for a free-signed sideloaded app.
   The Info.plist key is added (it gates the unicast paths too), but the entitlement
   is a hard wall. => **on-device HighID needs UNICAST port mapping**: `portmap.rs`
   (NAT-PMP, unicast to gateway:5351) is already built but NOT wired into
   `map_port()`, which only tries UPnP. A unicast M-SEARCH aimed at the gateway is
   the UPnP-flavoured equivalent. Both still need the Info.plist key + user Allow.
   NOTE for this dev box specifically: 4662/4672 forward to the WINDOWS host, not
   the iPad, so the iPad is LowID regardless until that changes. LowID is
   survivable - the live wav + pdf both arrived via LowID callback.

Also fixed while here: `map_port()` emitted the gateway-reported **public IP** into
a UI event, and the login event embedded the client id, which ENCODES the public IP
on HighID. Both removed - this screen gets screenshotted. See
[[padmule-dev-box-networking]].

## Related

- [[padmule-ios-app-path]]
- [[build-progress]]
- [[ipados-constraints]]
- [[lifecycle-and-reactivation]]
