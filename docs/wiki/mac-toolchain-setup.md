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
2. **Windows prep - THE #1 FAILURE**: install **iTunes and iCloud from apple.com**,
   NOT the Microsoft Store versions. AltServer cannot talk to the Store builds.
3. Install **AltServer** (altstore.io); it runs in the system tray.
4. iPad by USB -> unlock -> **Trust This Computer**. In iTunes tick **"Sync with
   this iPad over Wi-Fi"** (required for AltStore's wireless 7-day refresh).
5. Tray -> **Install AltStore** -> pick the iPad -> Apple ID (a throwaway ID works).
6. iPad -> Settings -> General -> **VPN & Device Management** -> trust the cert.
7. iPad -> Settings -> Privacy & Security -> **Developer Mode** ON -> restart.
   GOTCHA: the toggle only APPEARS once a dev-signed app has been installed, so do
   step 5 first if you cannot find it.
8. Put the `.ipa` where the iPad's **Files** app can see it (iCloud Drive), then
   AltStore -> **My Apps** -> **+** -> pick it. Simpler one-shot alternative:
   **Sideloadly** installs straight from Windows over USB (but no auto-refresh).
9. LIMITS of free-ID signing: apps expire every **7 days** (keep AltServer running
   on the same Wi-Fi and AltStore auto-refreshes) and **max 3 sideloaded apps**.
10. Debug by what the UI shows - there is no Xcode device support for iPadOS 26 on
    paths A/C, so the app's own status line IS the diagnostic. A healthy first run:
    "Fetching network lists..." -> Kad count -> "Opening port..." -> "Connected to
    <server> (HighID|LowID)" -> "Connected".

## Related

- [[padmule-ios-app-path]]
- [[build-progress]]
- [[ipados-constraints]]
- [[lifecycle-and-reactivation]]
