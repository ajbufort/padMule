# Mac Toolchain Setup (getting padMule onto the iPad) - ARCHIVE

Updated: 2026-08-04 (split verbatim out of [[mac-toolchain-setup]], which had grown past the
~150-line entry guidance - the same treatment build-progress got when
[[build-history]] was carved out on 2026-08-01). Moved, not rewritten.

The DECIDED-AGAINST paths and the first-device-run narrative. Path C (CI builds
the .ipa, Sideloadly installs it) won and is the only one still live; the 2011
mini as a build box is dead for a reason recorded here, so nobody re-litigates
it.

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
[SUPERSEDED: AltStore died with -22411; Sideloadly is the proven installer - see
[[ipad-usb-tooling]]]

Path A costs you the Xcode debugger + Simulator and a slow IDE, but the CPU+32GB
+SSD compile fine. Path B is the only one with real on-device debugging - worth it
if you will iterate on the UI. Path C needs zero hardware but has the slowest loop
(push -> CI -> download .ipa -> sideload).

## DE-RISK FIRST (do this before any OCLP install)

Validate the **sideload leg** before investing days in OCLP: get a hello-world
`.ipa` (from CI/path C, or any borrowed Mac), and confirm **AltStore installs and
runs it on the iPadOS 26 iPad**. If that works, the whole approach is sound and you
can then pick a build machine. If it does not, no build machine helps.
[SUPERSEDED: AltStore died with -22411; Sideloadly is the proven installer - see
[[ipad-usb-tooling]]]

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
2. **MULTICAST SSDP cannot work on iOS** [SUPERSEDED in part - see the note at
   the end of this item]. The "find devices on local networks" prompt was
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
   [SUPERSEDED 2026-07-17: the unicast M-SEARCH path was built (`upnp.rs
   discover_unicast`; `map_port()` now falls back multicast -> unicast with
   delete-then-add) and the iPad EARNED HIGHID with it on the BE9700 - see
   [[net-highid-and-port-forwarding]]. NAT-PMP (`portmap.rs`) remains a codec +
   `mule-cli natpmp` path, still not wired into `map_port()`. The old dev-box
   forward chain this NOTE described is gone with the router swap.]

Also fixed while here: `map_port()` emitted the gateway-reported **public IP** into
a UI event, and the login event embedded the client id, which ENCODES the public IP
on HighID. Both removed - this screen gets screenshotted. See
[[padmule-dev-box-networking]].

## Related

- [[mac-toolchain-setup]] - the live entry.
- [[build-progress]]
