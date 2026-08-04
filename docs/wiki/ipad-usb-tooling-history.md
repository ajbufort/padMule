# Driving the iPad over USB - ARCHIVE

Updated: 2026-08-04 (split verbatim out of [[ipad-usb-tooling]], which had grown
past the ~150-line entry guidance - the same treatment build-progress got when
[[build-history]] was carved out on 2026-08-01). Moved, not rewritten.

Three things live here:

1. **The usbipd bind/attach phases**, SUPERSEDED 2026-08-04. pymobiledevice3
   reaches the iPad through Windows' own Apple Mobile Device Service, so the
   bind buys nothing and needs an elevated PowerShell to boot. Kept because the
   USB/IP route is still the fallback if that service is ever unavailable, and
   because the commands are not obvious.
2. **The gotchas hit during the first real run** - each cost time, none are
   obvious, and they are the reason the live runbook looks the way it does.
3. **Installing over USB/IP does NOT work**, and why. A dead end worth keeping
   so it is not re-attempted.

## Phase 1 + Phase 2 - the usbipd route (SUPERSEDED, see above)

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

## Related

- [[ipad-usb-tooling]] - the live runbook.
- [[mac-toolchain-setup-history]] / [[build-progress]]
