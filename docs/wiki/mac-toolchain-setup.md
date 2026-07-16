# Mac Toolchain Setup (build padMule for iPad on a 2011 Mac mini)

Updated: 2026-07-16

Runbook for turning Anthony's **2011 Mac mini (Macmini5,x, 32GB RAM, non-Metal
GPU)** into an Xcode box that can build + sign padMule's iOS app for the iPad Pro
4th gen. The engine + [[padmule-ios-app-path]] FFI seam are done; this is the
last piece before the SwiftUI shell (Wave 8, [[build-progress]]).

## The two facts that drive every choice

- **Non-Metal GPU.** A 2011 mini has Intel HD 3000 (or, on the 5,2, a Radeon HD
  6630M) - both pre-Metal. OpenCore Legacy Patcher (OCLP) runs modern macOS on it
  via "non-Metal" root patches, but: (a) the IDE UI is sluggish, and (b) **the iOS
  Simulator will not run** (it needs Metal). => develop by deploying to the
  PHYSICAL iPad (fine - that is padMule's real target). Compilation is CPU/RAM
  bound, so 32GB + the CPU + an SSD handle it; just not fast.
- **Xcode must match the iPad's iPadOS.** CHECK THE IPAD FIRST (Settings ->
  General -> About -> Software Version). This picks the whole chain:

| iPad is on ... | Target macOS | Xcode | Notes |
|----------------|-------------|-------|-------|
| iPadOS <= 17 | **Ventura 13** | Xcode 15.x | BEST for non-Metal (OCLP more stable on Ventura); Xcode 15 SDK deploys to <= 17. |
| iPadOS 18 | Sonoma 14.5+ | Xcode 16.x | Needed for the iPadOS 18 SDK; non-Metal on Sonoma is rougher. |

Downgrading the iPad's iPadOS is usually impossible (Apple stops signing old
versions), so the iPad's CURRENT version basically dictates the row. If it is
already on 18, you are on the Sonoma+Xcode16 road.

## Phase A - prep (do before touching the OS)

1. Identify the exact model: About This Mac -> System Report -> Model Identifier
   (Macmini5,1 / 5,2 / 5,3). Confirms non-Metal + which GPU patch OCLP applies.
2. **SSD**: if it is still on the stock 5400rpm HDD, clone/replace with a SATA SSD
   FIRST. Single biggest speedup for macOS + Xcode. Keep the 32GB RAM.
3. Back up anything on the mini.

## Phase B - OCLP + macOS install

1. On any working Mac (or the mini if it still boots High Sierra), download
   **OpenCore Legacy Patcher** (github.com/dortania/OpenCore-Legacy-Patcher).
2. In OCLP: "Create macOS Installer" -> download the target from Phase B table
   (Ventura or Sonoma) -> flash it to a >= 16GB USB.
3. OCLP: "Build and Install OpenCore" -> install to the USB (test-boot), then to
   the mini's internal SSD.
4. Boot the OpenCore USB, run the macOS installer, install to the SSD.
5. **Post-Install Root Patch** (OCLP applies the non-Metal graphics patches) ->
   reboot. Without this the GUI is unaccelerated/broken.
6. OCLP: set OpenCore to auto-boot the patched disk (so no USB needed).

Pick a non-Metal-friendly OCLP release; Ventura is the most mature non-Metal
target. Avoid Sequoia (15) here - its non-Metal support is experimental.

## Phase C - Xcode + Rust toolchain

1. Install **Xcode** (15 on Ventura, or 16 on Sonoma) - App Store won't offer old
   versions; use `xcodes` (github.com/XcodesOrg/xcodes) or Apple's developer
   downloads to get the exact version. It is a large, slow install.
2. `xcode-select --install` (command-line tools); open Xcode once to finish setup.
3. Install Rust: `curl https://sh.rustup.rs -sSf | sh`; then the device target:
   `rustup target add aarch64-apple-ios` (add `aarch64-apple-ios-sim` only if you
   ever get a Metal Mac - the Simulator will not run here).

## Phase D - wire padMule into an Xcode app

1. Build the FFI staticlib for the device:
   `cargo build -p mule-ffi --release --target aarch64-apple-ios`
   -> `target/aarch64-apple-ios/release/libmule_ffi.a`.
2. Generate the Swift bindings (already working on the dev box):
   `cargo run -p mule-ffi --bin uniffi-bindgen -- generate --library
   target/aarch64-apple-ios/release/libmule_ffi.a --language swift --out-dir ios/gen`
   -> `mule_ffi.swift` + `mule_ffiFFI.h` + `mule_ffiFFI.modulemap`.
3. New Xcode iOS App project (`ios/padMule`). Add `mule_ffi.swift`; add the
   staticlib to "Link Binary With Libraries"; add the header/modulemap dir to the
   module search path (or a bridging module). Link `libresolv`/system libs if the
   linker asks.
4. Build the SwiftUI shell against `MuleEngine` (the FFI facade): render the honest
   status notice + Paused badges + Reconnecting banner, and wire SwiftUI
   `ScenePhase` -> `MuleEngine.pause()/resume()` ([[lifecycle-and-reactivation]]).

## Phase E - sign + deploy to the iPad (sideload)

1. Add a free Apple ID as a "Personal Team" in Xcode -> Settings -> Accounts.
2. On the iPad: Settings -> Privacy & Security -> **Developer Mode** on; trust the
   dev certificate after first install (Settings -> General -> VPN & Device Mgmt).
3. Run to the connected iPad (NOT a simulator). Free-account signing expires every
   **7 days** - re-run to resign, or use **AltStore** (altstore.io) to auto-resign
   over Wi-Fi. See [[ipados-constraints]] for the sideload limits.

## Reality check / fallbacks

- Expect slow IDE UI (non-Metal) but workable compiles (CPU+32GB+SSD).
- No Simulator -> always test on the device.
- If it is too painful: a used **Apple-Silicon M1 mini** or a **cloud Mac**
  (or GitHub Actions macOS runners for CI signing) is dramatically better. The
  OCLP route is the free way to start.

## Related

- [[padmule-ios-app-path]]
- [[build-progress]]
- [[ipados-constraints]]
- [[lifecycle-and-reactivation]]
