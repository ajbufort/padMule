# Mac Toolchain Setup (getting padMule onto the iPad)

Updated: 2026-08-04 (dead paths + first-run narrative split to
[[mac-toolchain-setup-history]]). Previously: 2026-08-03 (annotated the AltStore claims as SUPERSEDED - it died with
-22411, Sideloadly is the proven installer; the body already carried
2026-08-01 content - the rust.yml mention - so the old header date was stale
regardless)

How to build + sign padMule's iOS app for Anthony's **iPad Pro (M4, iPad16,3) running
iPadOS 26.5.2**, given the available Mac is a **2011 Mac mini (Macmini5,x, 32GB,
non-Metal)**. RESOLVED: Path C (CI macOS runner -> unsigned .ipa -> Sideloadly)
is the active, proven route - the app ships on-device with no Mac at all
([[build-progress]] wave 8). This entry remains the toolchain reference.

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
[SUPERSEDED: AltStore died with -22411; Sideloadly is the proven installer - see
[[ipad-usb-tooling]]]

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
   [SUPERSEDED: AltStore died with -22411; Sideloadly is the proven installer -
   see [[ipad-usb-tooling]]]
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
   [SUPERSEDED: AltStore died with -22411, so this auto-refresh never applied in
   practice; reality is a MANUAL re-sign every 7 days via Sideloadly - the
   current cert expires 2026-08-10 - see [[ipad-usb-tooling]]]
10. Debug by what the UI shows - there is no Xcode device support for iPadOS 26 on
    paths A/C, so the app's own status line IS the diagnostic. The Status screen
    shows State / Status / Server / ID (HighID|LowID) / Kad contacts.

## CI workflows (2026-07-20; a third, rust.yml, added 2026-08-01)

- **`.github/workflows/ios-build.yml`** - the ACTIVE path above: builds the
  unsigned device `.ipa` (FFI for `aarch64-apple-ios`, staged to `ios/libs/`).
- **`.github/workflows/ios-test.yml`** - Swift UNIT TESTS on an iPad SIMULATOR.
  Builds the FFI for `aarch64-apple-ios-sim` (staged to `ios/libs-sim/`), generates
  the uniffi bindings, `xcodegen`s, then `xcodebuild test` on a dynamically-selected
  iPad sim. The `padMuleTests` bundle is hosted inside the padMule app, so
  `@testable import padMule` reaches internal symbols (`present`, `SortKey`) and the
  generated FFI records (`SearchHit`) resolve from the app binary. Key wiring:
  `LIBRARY_SEARCH_PATHS` is SDK-conditional (device `.a` cannot link a simulator
  binary) and `project.yml` defines a shared `padMule` scheme with a test action.
  First harness covers `SearchPresentation.present()` (the descending-sort
  strict-weak-ordering fix + all filters). Both workflows are secret-free (unsigned).
  This is the client-side half of task #46 (engine settings were already FFI-tested).


(The decided-against paths, the de-risk checklist and the first-device-run
narrative moved verbatim to [[mac-toolchain-setup-history]] on 2026-08-04.)

## Related

- [[padmule-ios-app-path]]
- [[build-progress]]
- [[ipados-constraints]]
- [[lifecycle-and-reactivation]]
