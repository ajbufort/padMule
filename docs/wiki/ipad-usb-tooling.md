# Driving the iPad from this box over USB (WSL2 + usbipd + pymobiledevice3)

Updated: 2026-08-02 (RUN END TO END - results below replace the predictions)

How to give this WSL2 box direct access to the iPad over USB-C, so device logs,
screenshots and app installs can happen from here instead of only through
Sideloadly on the Windows host. Written AND RUN end to end 2026-08-02; the
"VERIFIED RESULTS" section below is fact, not prediction.

## VERIFIED RESULTS (2026-08-02, run end to end)

WORKING NOW, all without root:
- **Screenshots** - `pymobiledevice3 developer dvt screenshot out.png` returns a
  2420x1668 PNG. It auto-falls back to a "no-root userspace tunnel" on iOS 17+,
  so the sudo tunnel this entry originally predicted is NOT needed. I can see
  the iPad's screen.
- **Live syslog** - `idevicesyslog -p padMule` streams padMule's own engine
  logging to this box.
- **App install** - `pymobiledevice3 apps install x.ipa` works. (NB
  `ideviceinstaller -i` timed out; prefer pymobiledevice3.)
- **Reading the installed bundle** - `pymobiledevice3 developer dvt ls <path>`
  lists any on-device path, which is how the WDA signing bug below was found.
- **Developer Mode** was ALREADY enabled, and the **personalized DDI mounts
  fine on iPadOS 26.5.2** (`pymobiledevice3 mounter auto-mount`) - both gates
  this entry flagged as risky turned out to be non-events.

STILL NOT POSSIBLE:
- Live screen MIRRORING. QuickTime/macOS only; repeated screenshots is the
  ceiling.
- Touch input, so far - see the WebDriverAgent section.

## Prerequisites (the usual reasons this fails)

1. A USB-C cable that carries DATA. Many charge cables do not, and a charge-only
   cable looks identical to a broken setup.
2. The iPad UNLOCKED, with "Trust This Computer" accepted. The trust prompt only
   appears on an unlocked device.
3. Verified present on this box already: WSL kernel 6.6.87.2 ships
   `vhci-hcd.ko` (the USB/IP client driver), and Python is 3.12.3. Apple Mobile
   Device Service + Bonjour are running on the Windows side.

## Phase 1 - Windows host, once (needs Administrator)

```powershell
winget install --exact --id dorssel.usbipd-win
```

Then, in a NEW Administrator PowerShell (so the new PATH is picked up):

```powershell
usbipd list
```

Find the iPad row (its VID is `05ac`, Apple) and note its BUSID, e.g. `2-4`.
Bind it once - this marks it shareable and persists across reboots:

```powershell
usbipd bind --busid 2-4
```

## Phase 2 - attach it to WSL (every time it is plugged in)

```powershell
usbipd attach --wsl --busid 2-4
```

To give the device BACK to Windows (see the Sideloadly warning below):

```powershell
usbipd detach --busid 2-4
```

## Phase 3 - WSL side, once

```bash
sudo apt update
sudo apt install -y usbutils usbmuxd libimobiledevice-utils ideviceinstaller pipx
pipx ensurepath && pipx install pymobiledevice3
```

Confirm the device arrived, then pair:

```bash
lsusb | grep -i apple            # expect an Apple Inc. line
sudo usbmuxd -f -v &             # only if systemd is not enabled in this WSL
idevice_id -l                    # prints the UDID
idevicepair pair                 # unlock the iPad + tap Trust, then re-run
```

## Phase 4 - the things that work over plain lockdown

```bash
ideviceinfo -k ProductVersion        # sanity: the iPadOS version
idevicesyslog -p padMule             # LIVE engine logging - the big win
ideviceinstaller -l                  # installed apps
pymobiledevice3 apps install padMule.ipa   # install (ideviceinstaller -i hung)
```

## Phase 5 - screenshots (NO root needed, contrary to the original prediction)

```bash
pymobiledevice3 mounter auto-mount                        # once per boot
pymobiledevice3 developer dvt screenshot /tmp/ipad.png    # just works
```

On iOS 17+ pmd3 announces "Trying again over a no-root userspace tunnel" and
proceeds. No `sudo`, no `tunneld`. Verified on iPadOS 26.5.2.

## Caveats that will bite

- **ATTACHING TO WSL TAKES THE DEVICE AWAY FROM WINDOWS.** While attached,
  Sideloadly cannot see the iPad. Run `usbipd detach` before a Sideloadly
  install, and re-attach afterwards. This is the single most likely source of
  confusion.
- Re-attach is needed after every unplug, host reboot, or device re-enumeration
  (locking/unlocking can trigger one).
- The pair record lives in `/var/lib/lockdown/`; deleting it forces a new Trust
  prompt.
- None of this changes the 7-day free-team signing expiry - that is a signing
  limit, unrelated to the transport.

## Gotchas hit during the real run (all cost time; none are obvious)

1. **Plain `usbipd bind` refused** because USBPcap is installed on the host
   (usbipd calls it incompatible). `bind --force` works.
2. **First attach failed "Device busy (exported)"**. usbipd warns a reboot may
   be needed; a REPLUG was enough, no reboot.
3. **usbmuxd could not open the device (errno 13)** because the device node was
   created BEFORE the usbmuxd package (and its udev rules) existed, leaving it
   root:root. A detach/re-attach re-fires udev and the node comes back owned by
   `usbmux`. So: install the packages FIRST, then attach.
4. **`sudo` cannot prompt** through the agent's shell (no TTY) - run apt in a
   real terminal window.
5. **Concurrent `pymobiledevice3 developer` commands break go-ios tunnels.**
   Each pmd3 developer invocation opens its own userspace RemoteXPC tunnel; a
   background poll loop doing that every few seconds prevented go-ios from
   establishing its tunnel at all. Do not leave pmd3 polling while using go-ios.
6. Beware `pkill -f <pattern>` here: the agent's own shell command line contains
   the pattern, so it kills its own session. Kill by PID (`ss -lptn`, `ps -eo
   pid,args`) instead.

## WebDriverAgent (touch control): signed + installed, launch still blocked

GOAL: taps/swipes via `pymobiledevice3 developer wda` (it has tap / swipe / type
/ press / list-items / screenshot - but it is a CLIENT and needs WDA running).

DONE:
- Prebuilt runner from `appium/WebDriverAgent` release v16.1.1 asset
  `WebDriverAgentRunner-Runner.zip`, repackaged as an `.ipa` (Payload/ + zip),
  with `PlugIns/WebDriverAgentRunner.xctest/Frameworks/WebDriverAgentLib.framework`
  MOVED to the app's outer `Frameworks/` (the xctest binary has both
  `@executable_path/Frameworks` and `@loader_path/Frameworks` rpaths, so either
  location resolves, and signers reliably cover the outer one).
- **ROOT CAUSE of XCTest error 103 (`Failed to load the test bundle`):
  Sideloadly signs the outer app and Frameworks but NOT the nested `.xctest`.**
  Confirmed on-device: the `.xctest` had no `_CodeSignature`. iOS will not load
  an unsigned bundle into a signed process.
- FIX: sign locally with **zsign** (built from github.com/zhlynn/zsign; needs
  `libssl-dev`), using Sideloadly's cached identity at
  `%APPDATA%/Sideloadly/cert-*.pem` + `key.pem`, and a provisioning profile
  pulled off the device with `ideviceprovision copy <dir>`. zsign DOES sign the
  nested `.xctest` (verified: `_CodeSignature` now present on-device).
- MUST pass `-b com.facebook.WebDriverAgentRunner.xctrunner.<TEAMSUFFIX>`; without
  it the bundle id does not match the profile and install fails with
  `0xe8008016 (invalid entitlements)`.
- Install with `pymobiledevice3 apps install wda-signed2.ipa`.

BLOCKED ON: starting the runner. `go-ios runwda` DID reach `testmanagerd` and
complete a full XCUITest capability handshake earlier in the session (so the
path is sound), but after several USB detach/attach cycles its tunnel stopped
establishing - `ios tunnel start --userspace` logs "start tunnel" yet
`ios tunnel ls` returns `[]`. Gotcha 5 above was one cause and was cleared;
it still did not come up before the session ended.

NEXT THINGS TO TRY (in order):
1. Fresh state: attach the device, start NO pmd3 commands, then
   `ios tunnel start --userspace`, confirm `ios tunnel ls` is non-empty, and
   only then `runwda`.
2. Give go-ios a kernel tunnel instead of userspace: `sudo ios tunnel start`, or
   `sudo setcap cap_net_admin+eip ./goios/ios-amd64`.
3. Or start pymobiledevice3's own tunnel (`sudo pymobiledevice3 remote tunneld`)
   and pass its address/RSD port to go-ios via `--address` / `--rsd-port` /
   `--userspace-port`.

## Signing padMule locally (a genuine win, independent of WDA)

zsign + the cached Sideloadly cert/key + a device-pulled profile means padMule
builds can be signed and installed FROM HERE, with no Sideloadly round trip and
no detach/attach dance: sign, `pymobiledevice3 apps install`, watch syslog.
The padMule profile pulled 2026-08-02 is
`iOS Team Provisioning Profile: us.ajbconsulting.padMule.Q444CHAF2Z`.
LIMIT: profiles + free-account cert expire **2026-08-10**. Renewal still needs
Sideloadly (Apple ID auth, App ID + device registration, cert issuance); after
each renewal, re-pull the profile with `ideviceprovision copy`.
SECURITY NOTE: the signing key is Anthony's; the agent's tool call touching it
was correctly blocked by a safety classifier, so ANTHONY runs the zsign command
himself. Keep it that way.

Until then the on-glass pass in [[on-device-test-checklist]] plus the FFI
simulation (`scripts/simulate.sh`) remain the way padMule is verified on the
device, and a Sideloadly install remains the way it gets there
([[mac-toolchain-setup]]).

## Related

- [[on-device-test-checklist]] - the human on-glass pass this would partly automate.
- [[mac-toolchain-setup]] - how the `.ipa` is built and installed today.
- [[ipados-constraints]] - platform limits (foreground-only, sideload-only).
- [[padmule-dev-box-networking]] - the WSL2/host network topology (memory).
