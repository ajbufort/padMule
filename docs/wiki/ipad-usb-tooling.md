# Driving the iPad from this box over USB (WSL2 + usbipd + pymobiledevice3)

Updated: 2026-08-03 (TOUCH CONTROL NOW WORKS - go-ios was never needed; and
engine os_log logging LANDED - subsystem us.ajbconsulting.padMule, category
padMule.engine - device-verified 2026-08-03 via idevicesyslog)

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
- **Live syslog** - `idevicesyslog -p padMule` streams the app's log stream to
  this box, and since 2026-08-02 that INCLUDES padMule's own engine logging:

  ```bash
  idevicesyslog -p padMule                      # everything the app emits
  idevicesyslog -p padMule -m padMule.engine    # just the engine lines
  ```

  Every `EngineEvent` (state, status, server/UPnP text, a server drop, Kad
  contact changes) plus boot, boot FAILURES and every lifecycle transition
  (pause / resume / stop / start) now goes to `os_log` under subsystem
  `us.ajbconsulting.padMule`, category **`padMule.engine`**. Messages are marked
  `.public` deliberately - os_log redacts interpolated strings otherwise, and a
  redacted diagnostic is worthless; nothing sensitive flows through it, since the
  engine never emits our own public IP or client id and the only local addresses
  that appear are RFC1918.

  [HISTORY, kept because it is why the work happened: before that change this
  bullet had to be CORRECTED to say the opposite. A 1293-line capture across a
  full launch + search + download-add contained **ZERO app-authored lines** -
  every line came from a system framework - because nothing in the Swift shell or
  the Rust engine ever called os_log, and a GUI app's stdout (where Rust
  `println!` goes) is not captured. The UI rows were the engine's only window.]

  STILL TRUE: this carries what the engine EMITS AS EVENTS. Internals that never
  become an event (a peer refusing a block, a swallowed error) remain invisible;
  routing those through a `Log` event is the next step if it is ever needed.
- **App install** - `pymobiledevice3 apps install x.ipa` works. (NB
  `ideviceinstaller -i` timed out; prefer pymobiledevice3.)
- **Reading the installed bundle** - `pymobiledevice3 developer dvt ls <path>`
  lists any on-device path, which is how the WDA signing bug below was found.
- **Developer Mode** was ALREADY enabled, and the **personalized DDI mounts
  fine on iPadOS 26.5.2** (`pymobiledevice3 mounter auto-mount`) - both gates
  this entry flagged as risky turned out to be non-events.

- **TOUCH CONTROL (2026-08-02)** - taps, typing, element queries and the whole
  accessibility tree, via WebDriverAgent driven by **pymobiledevice3**. See the
  runbook section below; go-ios turned out to be unnecessary.

STILL NOT POSSIBLE:
- Live screen MIRRORING. QuickTime/macOS only; repeated screenshots is the
  ceiling.

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
7. **pymobiledevice3 can go blind while libimobiledevice still works** (hit
   2026-08-02, UNRESOLVED). After the iPad re-enumerated and **usbmuxd restarted**
   (new PID), `idevice_id -l` / `ideviceinfo` / `idevicepair validate` all kept
   working over USB, but every pmd3 command died with "Device is not connected"
   and `pymobiledevice3 usbmux list` returned `[]` - including a direct
   `await usbmux.list_devices()` against the same default socket. Ruled out:
   pairing (valid, record world-readable), socket permissions (connects fine),
   the Windows-usbmuxd-on-27015 theory (nothing listens there), an explicit
   `--udid`. NB pmd3's FIRST listing of the session reported
   `ConnectionType: Network`, so it may have been using a network path all along
   and lost it when the iPad's address changed. Suspected fix, needs a REAL
   terminal because sudo cannot prompt through the agent's shell (gotcha 4):
   `sudo systemctl restart usbmuxd`, then detach/re-attach. Touch control is
   down until pmd3 can enumerate again; libimobiledevice-based tools
   (idevicesyslog, ideviceinstaller) are unaffected.

## WebDriverAgent (touch control): WORKING (2026-08-02)

**go-ios was never needed.** The previous session was blocked on `ios tunnel
start --userspace` never registering a tunnel. pymobiledevice3 has its OWN
XCUITest launcher which opens the same no-root userspace tunnel that already
made screenshots work, so the whole go-ios detour is skippable.

THE WORKING SEQUENCE (four steps, all from this box):

```bash
# 0. If lockdownd says "Mux error (-8)", the attach is stale: detach + re-attach
#    on the Windows side ("/mnt/c/Program Files/usbipd-win/usbipd.exe"), then:
ideviceinfo -k ProductVersion            # must answer before going further

# 1. start the runner (leave it running; it holds the XCUITest session)
PYTHONUNBUFFERED=1 pymobiledevice3 developer dvt xcuitest \
  com.facebook.WebDriverAgentRunner.xctrunner.Q444CHAF2Z

# 2. expose WDA's HTTP API locally (leave it running)
pymobiledevice3 usbmux forward 8100 8100

# 3. drive it over plain HTTP
curl -s localhost:8100/status                       # "ready to accept commands"
curl -s -X POST localhost:8100/session -H 'Content-Type: application/json' \
  -d '{"capabilities":{"alwaysMatch":{"bundleId":"us.ajbconsulting.padMule.Q444CHAF2Z"}}}'
```

Endpoints that matter: `GET /screenshot` (base64 PNG), `GET /source?format=json`
(the ACCESSIBILITY TREE - labels + exact point rects, the best way to assert UI
state in text), `POST /session/{id}/actions` (W3C tap), `POST
/session/{id}/elements` then `.../element/{eid}/click` and `.../value`,
`POST /session/{id}/alert/accept`.

GOTCHAS (each cost real time):
- **`/wda/tap/0` and `/wda/keys` do NOT exist** in WDA 16.1.1 - they answer
  "Unhandled endpoint" / drop the connection. Use W3C `actions` and
  element `/value` instead.
- **Do not pipe the runner through `head`** - it buffers, and a working launch
  looks like a full minute of silence. `PYTHONUNBUFFERED=1`, no pipe.
- **Tap by ELEMENT, not by coordinate, whenever possible.** Dismissing the
  keyboard reflowed the result list by 32 points between two reads, so a
  coordinate tap captured moments earlier landed in the gap between rows and
  silently did nothing.
- iOS paints a **rotated "Automation Running" banner** over the screen for the
  whole session. It is system chrome, not padMule; it does not take touches, and
  holding both volume buttons kills the automation session (the user's escape
  hatch). It disappears when the session ends.
- padMule's **Local Network permission prompt** appears on a fresh install and
  BLOCKS the UPnP/HighID path until answered; `alert/accept` clears it.

The signing work below is what made this possible and still stands.

DONE (the signing saga that unblocked it):
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

[RESOLVED 2026-08-02 - see the working runbook at the top of this section. The
old blocker was go-ios's tunnel (`ios tunnel start --userspace` logged "start
tunnel" but `ios tunnel ls` stayed `[]`). It was never worth solving:
pymobiledevice3's own `developer dvt xcuitest` launches the runner directly, so
go-ios is not part of the path at all. The three go-ios recovery ideas queued
here are retained only as history.]

## SIGNING WORKS FROM HERE; INSTALLING OVER USB/IP DOES NOT (2026-08-02)

Anthony authorized the agent to use his signing key, and the signing half of the
loop now works end to end from this box:

```bash
# 1. the artifact CI just built (run inside the repo, gh needs the git remote)
gh run download <run-id> -D ./ipa

# 2. VERIFY it is the build you think it is, before signing anything
strings Payload/padMule.app/padMule | grep "<a string only the new code has>"

# 3. build zsign (no sudo needed - libssl-dev is already present here)
git clone --depth 1 https://github.com/zhlynn/zsign.git && cd zsign/build/linux && make
#    NB the Makefile lives in build/linux, NOT at the repo root.

# 4. pull the profile off the device, then sign
ideviceprovision copy ./profiles        # the dir must EXIST first
zsign -k "$SL/key.pem" -c "$SL/cert-*.pem" -m ./profiles/<padmule-uuid>.mobileprovision \
      -b us.ajbconsulting.padMule.Q444CHAF2Z -o padMule-signed.ipa -z 9 padMule.ipa
```

`SL` = `/mnt/c/Users/ajbuf/AppData/Roaming/Sideloadly`. The key is referenced BY
PATH and never copied, read out or moved.

**`-b` IS MANDATORY and the reason is easy to miss.** The .ipa CI builds carries
`us.ajbconsulting.padMule`, but free provisioning issues the App ID
`Q444CHAF2Z.us.ajbconsulting.padMule.Q444CHAF2Z` (read it out of the profile with
`openssl smime -inform der -verify -noverify -in <profile>`). Signing without
`-b` produces a bundle id the profile does not cover, and the install dies with
`0xe8008016 (invalid entitlements)` - the same trap the WDA section hit. Using
the team-suffixed id also means the install UPGRADES the existing app in place,
so downloads and config survive.

**THE INSTALL IS THE PART THAT DOES NOT WORK OVER USB/IP.** Repeated attempts:
`pymobiledevice3 apps install` runs for 10+ minutes with ZERO output and never
completes, and afterwards the link is wedged - lockdownd answers `Mux error
(-8)`, pmd3 hangs on every device call, and only a usbipd detach/re-attach
clears it. Small operations (screenshots, syslog, xcuitest, the accessibility
tree) are all reliable; it is specifically the multi-megabyte transfer that
destabilizes the USB/IP link. Contention makes it worse - kill the WDA runner and
any `usbmux forward` FIRST, since a live XCUITest session holds its own tunnel.
Handing the device back to Windows (`usbipd detach`) did not help either: the
Windows Apple Mobile Device Service did not re-enumerate it without a physical
replug.

So the working division of labour today is: **CI builds, this box signs,
Sideloadly (or a replug + retry) installs.** Copy the .ipa to
`/mnt/c/Users/ajbuf/Downloads/` and install it from Windows.

**...but hand Sideloadly the UNSIGNED artifact.** Learned the expensive way
2026-08-02: a build already signed here with `-b us.ajbconsulting.padMule.
Q444CHAF2Z` came back out of Sideloadly as
`us.ajbconsulting.padMule.Q444CHAF2Z.Q444CHAF2Z` - it appends the team suffix
AGAIN. That is a NEW bundle id, so it installs as a SEPARATE app with an empty
container (fresh userhash and Kad ID, visible on the Status screen) instead of
upgrading in place, and the previous app's downloads and identity are left
behind. `-b` is correct ONLY for a direct `pymobiledevice3 apps install` from
here; Sideloadly does its own signing and suffixing, so give it the raw CI
artifact.

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

With touch control working, the [[on-device-test-checklist]] pass is now
AGENT-DRIVABLE end to end (launch, tap, type, read the accessibility tree,
screenshot) rather than a human-only on-glass exercise; the FFI simulation
(`scripts/simulate.sh`) remains the offline equivalent, and a Sideloadly install
remains how a fresh build gets there when the cert is renewed
([[mac-toolchain-setup]]).

WHAT IT FOUND ON ITS FIRST RUN (2026-08-02), which is the argument for it: the
function strip verified visually; Kad healthy at 172 contacts with the wave-10
verified-bit gate ON (a live keyword search returned real results with no server
connected); and the UPnP stale-mapping dead end that had left the iPad on LowID
since its DHCP address changed - a failure invisible to CI, to the unit gate and
to all three oracles, sitting in the one row only the device can show
([[net-highid-and-port-forwarding]]).

## Related

- [[on-device-test-checklist]] - the human on-glass pass this would partly automate.
- [[mac-toolchain-setup]] - how the `.ipa` is built and installed today.
- [[ipados-constraints]] - platform limits (foreground-only, sideload-only).
- [[padmule-dev-box-networking]] - the WSL2/host network topology (memory).
