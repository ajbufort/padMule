# Driving the iPad from this box over USB (WSL2 + usbipd + pymobiledevice3)

Updated: 2026-08-02

How to give this WSL2 box direct access to the iPad over USB-C, so device logs,
screenshots and app installs can happen from here instead of only through
Sideloadly on the Windows host. Written 2026-08-02 after checking what this
machine can actually do; NOT yet executed end to end (see "Status" at the end).

## What this buys, and what it does NOT

- YES: device info, LIVE SYSLOG (padMule's own engine logging, which is the
  biggest win), `.ipa` install, app launch, and SCREENSHOTS.
- NO: live screen mirroring. That is a QuickTime/macOS facility; there is no
  supported Linux equivalent. The best available is repeated screenshots.
- NO: touch input (taps/swipes). That needs WebDriverAgent running ON the
  device (Appium), which must itself be signed + installed - with no Mac that
  means a prebuilt WDA `.ipa` through Sideloadly, carrying the same 7-day
  free-team expiry as padMule. Only worth it if automated UI driving becomes a
  real need.

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
idevicesyslog | grep -i padmule      # LIVE engine logging - the big win
ideviceinstaller -l                  # installed apps
ideviceinstaller -i padMule.ipa      # install the CI artifact directly
```

## Phase 5 - screenshots (iOS 17+ needs a tunnel; the UNCERTAIN part)

Classic `idevicescreenshot` relies on a Developer Disk Image and largely broke
for iOS 17+; iPadOS 26 is far newer still. The maintained path is
`pymobiledevice3`, whose developer services need a RemoteXPC tunnel that runs as
root:

```bash
sudo pymobiledevice3 remote tunneld       # leave running in one shell
# in another shell:
pymobiledevice3 developer dvt screenshot /tmp/ipad.png
```

HONEST STATUS: this phase is the one most likely to need fighting. The tunnel
uses an IPv6 link-local virtual interface, and whether that behaves under WSL2's
network stack on iPadOS 26 is unverified. Phases 1-4 are conventional and should
be reliable; treat Phase 5 as "probably, with effort".

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

## Status

Written 2026-08-02 from verified local facts (kernel has `vhci-hcd.ko`, Python
3.12.3, AMDS running, no Apple device currently enumerating on the Windows side,
`usbipd-win` NOT installed, no iOS tooling installed in WSL). The steps
themselves have NOT been run end to end yet - when they are, update this entry
with what actually happened, especially Phase 5.

Until then the on-glass pass in [[on-device-test-checklist]] plus the FFI
simulation (`scripts/simulate.sh`) remain the way padMule is verified on the
device, and a Sideloadly install remains the way it gets there
([[mac-toolchain-setup]]).

## Related

- [[on-device-test-checklist]] - the human on-glass pass this would partly automate.
- [[mac-toolchain-setup]] - how the `.ipa` is built and installed today.
- [[ipados-constraints]] - platform limits (foreground-only, sideload-only).
- [[padmule-dev-box-networking]] - the WSL2/host network topology (memory).
