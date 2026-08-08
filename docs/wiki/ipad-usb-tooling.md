# Driving the iPad from this box over USB (WSL2 + usbipd + pymobiledevice3)

Updated: 2026-08-07 (THE INSTALL PATH is zsign + pymobiledevice3; Sideloadly is
for RENEWALS ONLY, and every Sideloadly round breaks WebDriverAgent - re-verified
this day, padMule f946e02 -> 7d1b349 with WDA still answering ready:True on the
same session. Plus MEASURING ANYTHING THROUGH WDA: the probe costs and the three
probes that were wrong before they were right. 2026-08-03:
TOUCH CONTROL WORKS - go-ios was never needed; and
engine os_log logging LANDED - subsystem us.ajbconsulting.padMule, category
padMule.engine - device-verified 2026-08-03 via idevicesyslog)

How to give this WSL2 box direct access to the iPad over USB-C, so device logs,
screenshots and app installs can happen from here instead of only through
Sideloadly on the Windows host. Written AND RUN end to end 2026-08-02; the
"VERIFIED RESULTS" section below is fact, not prediction.

## CORRECTION 2026-08-04: `usbipd bind` is NOT a prerequisite

Anthony caught this. `pymobiledevice3` reaches the iPad WITHOUT binding or
attaching the USB device to WSL at all - it talks to Windows' own Apple Mobile
Device Service, so the host keeps the device (Sideloadly still sees it) while
this box can screenshot, install, mount the DDI and drive WebDriverAgent.
`usbipd list` showing the iPad as "Not shared" is NOT a blocker.

What DOES fail in that state is the older libimobiledevice CLI set
(`idevice_id -l`, `idevicesyslog`), which speaks to the local
`/var/run/usbmuxd` socket - so prefer the `pymobiledevice3` equivalents.
`bind` also requires an elevated PowerShell, which is worth not asking for
when it buys nothing.

Device is now on **iPadOS 26.6** (was 26.5.2 when this entry was written).

## Prerequisites (the usual reasons this fails)

1. A USB-C cable that carries DATA. Many charge cables do not, and a charge-only
   cable looks identical to a broken setup.
2. The iPad UNLOCKED, with "Trust This Computer" accepted. The trust prompt only
   appears on an unlocked device.
3. Verified present on this box already: WSL kernel 6.6.87.2 ships
   `vhci-hcd.ko` (the USB/IP client driver), and Python is 3.12.3. Apple Mobile
   Device Service + Bonjour are running on the Windows side.

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

**READ-ONLY vs DISTURBING (learned by breaking it, 2026-08-04).** While a live
run is in progress, only two things are safe:

- `GET localhost:8100/source?format=json` - works with NO session at all
- `pymobiledevice3 developer dvt screenshot` - never touches the app

Creating a WebDriverAgent **session** disturbs the app, and this is not limited
to passing a `bundleId`: a session created with EMPTY capabilities backgrounded
padMule, which on a foreground-only app pauses every transfer; the screen then
slept and recovery needed a relaunch.

**AND A SESSION FOR A DIFFERENT BUNDLE KILLS THE APP THAT WAS RUNNING (2026-08-07).**
Not merely backgrounds it - TERMINATES it. This produced four straight "the
process is DEAD" samples that read exactly like background seeding failing, and
nearly went into the record as a failed feature. **To background an app for a
test, use `pymobiledevice3 developer dvt launch <other.bundle.id>`**, which does
not go through WDA at all; the app being tested then survives, which is the
whole point of the measurement. Download progress survived (byte counts
matched exactly) but the process-global fetch counters did not. If the run
matters, screenshot and read `/source` - do not open a session.



- **ATTACHING TO WSL TAKES THE DEVICE AWAY FROM WINDOWS.** While attached,
  Sideloadly cannot see the iPad. Run `usbipd detach` before a Sideloadly
  install, and re-attach afterwards. This is the single most likely source of
  confusion.
- **...AND `detach` IS NOT ENOUGH ON THIS BOX (found 2026-08-03).** Because
  USBPcap is installed here, the iPad had to be bound with `bind --force`
  (gotcha 1 below), which leaves it permanently in state `Shared (forced)`.
  A forced bind hands the device to the USB/IP stub driver at the WINDOWS
  level, so the Apple Mobile Device Service - and therefore Sideloadly and
  iTunes - cannot see it EVEN WHEN IT IS NOT ATTACHED TO WSL. The symptom is
  exactly the confusing one: `lsusb`/`idevice_id -l` show nothing in WSL
  (so it looks like Windows should have it) while Sideloadly still refuses to
  acknowledge the iPad. Diagnose with `usbipd list` and look at the STATE
  column for the `05ac:12ab` row.

  ```powershell
  usbipd list                       # STATE = "Shared (forced)" is the problem
  usbipd unbind --busid 7-12        # ADMINISTRATOR; returns it to Windows
  ```

  `unbind` (NOT `detach`) is the release, it needs an ADMINISTRATOR
  PowerShell, and the bind PERSISTS ACROSS REBOOTS - so this will recur every
  time the box is used for WSL device work and then Sideloadly. A physical
  replug may still be needed afterwards for Windows to re-enumerate. To go
  back to agent-driven device work: `usbipd bind --force --busid 7-12` then
  `usbipd attach --wsl --busid 7-12`. NB the BUSID is not stable across
  ports/reboots - read it from `usbipd list` each time (it was 2-4 in the
  original write-up and 7-12 on 2026-08-03).
- Re-attach is needed after every unplug, host reboot, or device re-enumeration
  (locking/unlocking can trigger one).
- The pair record lives in `/var/lib/lockdown/`; deleting it forces a new Trust
  prompt.
- None of this changes the 7-day free-team signing expiry - that is a signing
  limit, unrelated to the transport.

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

## MEASURING ANYTHING THROUGH WDA - the rules, with their costs

Kept HERE rather than only in [[handoff-next-session]], which is replaced
wholesale every session. `scripts/device-timing.sh` encodes all of it.

**Probe costs, timed on device 2026-08-07** (this is the whole reason the rules
below exist - every probe spends MAIN-THREAD time in the app you are measuring):

| Probe | Cost | Use it? |
|---|---|---|
| `GET /source?format=json` | **1.70s** | Only for a one-shot read at the END |
| `POST /session/{id}/elements` (one locator) | **0.53s** | YES - the polling probe |
| `pymobiledevice3 developer dvt screenshot` | **2.13s** | Out-of-process, but slow |

Polling `/source` once a second is a >100% duty cycle on the main thread. It
manufactures the freeze it is measuring, and on 2026-08-07 it produced a reading
that refuted a correct fix.

**THREE PROBES WERE WRONG BEFORE THEY WERE RIGHT (2026-08-07), each with a
plausible number first:**

1. **The results list is NOT cleared between searches.** A probe polling for
   result rows finds the PREVIOUS run's at t=0 and reports 1.3-1.5s - probe
   latency wearing a search time's clothes, and it looks like a spectacular win.
   Tap **Clear search** and assert ZERO rows before starting the clock.
2. **`srcs` is the wrong marker.** A probe matching it reported NO RESULTS by 46s
   while four results sat on screen, because a single-source row reads
   **`1 src`** - so it could never fire on a thin result set, which is exactly
   what a serverless or unpopular query returns. Match **`Get`**: one per row,
   regardless of source count.
3. **The search field CONCATENATES** (below). Clear, set, and READ BACK.

**And take the measurement OUT of the window where you can:** record, leave,
record once. The in-app instruments (Stats -> Longest poll gap, the fetch funnel)
cost the probe nothing at all and are always preferable to a polled one.

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

## THE INSTALL PATH: zsign + pymobiledevice3. Sideloadly is for RENEWALS ONLY.

**This is the default. Do not reach for Sideloadly to install a build.**
Promoted from a footnote 2026-08-07 after the footnote version cost a session:
this capability was documented here on 2026-08-02, was READ during the
2026-08-07 session, and a Sideloadly install was run anyway - which re-signed
WebDriverAgent, stripped its nested `.xctest` signature, and produced the
XCTest-103 dead end below. **A capability recorded as "a genuine win" at the
bottom of an entry reads as trivia. State the default at the top.**

    # 1. Anthony signs (his key, and it stays his - see the security note)
    zsign -k <sideloadly>/key.pem -c cert.pem -m padmule.mobileprovision \
          -b us.ajbconsulting.padMule.Q444CHAF2Z \
          -o padmule-signed.ipa padmule-unsigned.ipa
    # 2. the agent installs, ~30 seconds, no GUI, no detach/attach
    pymobiledevice3 apps install padmule-signed.ipa

Kits are staged and stay staged: `/home/ajbufort/padmule-resign/` and
`/home/ajbufort/wda-resign/` (zsign binary, cert, profile, unsigned ipa).

**WHY IT MATTERS BEYOND CONVENIENCE: every Sideloadly install re-signs whatever
it touches, and it does NOT sign a nested `.xctest`.** So a Sideloadly round
breaks WebDriverAgent every single time, and the automation has to be rebuilt
before any device testing can resume. The zsign path leaves the runner alone -
verified 2026-08-07: padMule went 92e5ab2 -> 32f1d0e with WDA still answering
`ready: True` on the same session.

**What Sideloadly is STILL required for: renewal.** zsign only USES an existing
cert + profile; it cannot ask Apple for new ones (Apple ID auth, App ID + device
registration, cert issuance). After each renewal, re-pull profiles with
`pymobiledevice3 provision dump <dir>` - NOT `ideviceprovision copy`, which
cannot see the device unless it is attached to WSL.

**THE 7-DAY CLOCK IS THE PROFILE, NOT THE CERT.** Read from the profile itself:
`TimeToLive: 7`, and the developer certificate inside it runs to **2027-07-16**.
So renewals are profile refreshes, not cert re-issues - the entry used to
conflate them. Live expiries as of 2026-08-07: WebDriverAgent **2026-08-10**,
padMule **2026-08-14**; WDA is the binding one. A paid Apple Developer Program
membership issues 1-year profiles and would end the treadmill for both.

SECURITY NOTE: the signing key is Anthony's; the agent's tool call touching it
was correctly blocked by a safety classifier, so ANTHONY runs the zsign command
himself. Keep it that way - the agent stages everything else and installs.

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

(The usbipd bind/attach phases, the first-run gotchas and the USB/IP install
dead end moved verbatim to [[ipad-usb-tooling-history]] on 2026-08-04.)

## Related

- [[on-device-test-checklist]] - the human on-glass pass this would partly automate.
- [[mac-toolchain-setup]] - how the `.ipa` is built and installed today.
- [[ipados-constraints]] - platform limits (foreground-only, sideload-only).
- [[padmule-dev-box-networking]] - the WSL2/host network topology (memory).
