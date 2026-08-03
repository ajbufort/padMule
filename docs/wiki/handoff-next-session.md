# HANDOFF - start here next session

Updated: 2026-08-02 (end of a very long session; everything below is verified,
not assumed, and what is NOT verified says so)

Living doc: replace it wholesale next time rather than appending. Full narrative
in [[build-progress]] rows 8as-8au and the [[log]] entries for 2026-08-02.

## State of the tree

- All work committed AND pushed; tree clean; branch even with origin/main at
  **11eec87**. CI green on all three workflows for every push tonight.
- **Gate**: 525 tests, clippy WARNING-FREE, fmt clean, ASCII clean.
- [[security-model]] scorecard unchanged: **23 OPERATIONAL / 1 PARTIAL / 2
  documented opt-outs**. The PARTIAL is AICH block recovery (wave 11), an
  optimization, not an integrity hole.

## THE FIRST THING TO DO

**Install `C:\Users\ajbuf\Downloads\padMule-INSTALL-THIS-unsigned-11eec87.ipa`**
via Sideloadly (Anthony was mid-reinstall when the session ended). It is the
UNSIGNED CI artifact on purpose - see the Sideloadly trap below. The three older
.ipas in that folder are superseded; `padMule-signed-0cf6791.ipa` in particular
is the double-suffixed trap and must NOT be used.

Then verify on device (touch control makes this ~5 minutes, [[ipad-usb-tooling]]):
1. Status -> **Stop padMule**, then check from the dev box that the mapping is
   really gone: `cargo run -p mule-cli -- upnp-query 4662` must report NOT mapped.
   That is the one piece of tonight's work with no test coverage on the device.
2. **Start padMule** from the same screen; confirm it re-maps and earns HighID
   without relaunching the app.
3. Leave it running >5 minutes and confirm the periodic checkpoint is invisible
   (no stutter, no log noise) - it should simply be there if the app is killed.

## What landed tonight (all pushed)

- **Agent-driven device control** - WebDriverAgent via pymobiledevice3; taps,
  typing, screenshots, the accessibility tree. go-ios was never needed.
- **The UPnP stale-mapping root cause**: a mapping can only be deleted by the
  address that OWNS it, so padMule's own permanent mapping outlived the iPad's
  DHCP address and stranded the port. Fixed three ways: eMule's
  verify-then-reopen refresh on resume and on a LowID answer, a conflict message
  that NAMES the holder, and (below) releasing the port on stop.
- **Status line** went stale after connect - device-verified fixed (8as).
- **Kad checkpoint** - mid-session contacts and verify keys were discarded; now
  enforced structurally by `set_kad` (8at/8au).
- **Explicit Stop action** - the closest honest analogue of eMule's Exit;
  releases the port, restartable in place.
- **Periodic checkpoint** every 300s, a documented deviation (both authorities
  save nodes.dat only from a destructor).

## Open tasks

1. **os_log the engine** - `idevicesyslog -p padMule` carries ZERO app-authored
   lines; neither the Swift shell nor the Rust engine ever calls os_log, so the
   UI rows are the only window into the engine on-device. This is the highest-
   leverage remaining tooling item now that the agent can drive the device.
2. **AICH block recovery** - the last scorecard PARTIAL, wave 11. Do NOT port the
   vendored 3.0.1 oracle's racy `known2_64.met` orphan-prune; route
   `localize_corruption`'s blamed parts into block-level recovery; ship the AICH
   rate limit and an O(1) index in the SAME change.
3. **Continuous block-request top-up** - padMule is stop-and-wait per 3-block
   batch (`multi_source.rs`), shallower than BOTH authorities. eMule tops up as
   each block completes (DownloadClient.cpp:870-919). No wire change, big win at
   cellular RTT. Do NOT adopt aMule master's [3,24] clamp.
4. **Smaller reanalysis findings**: `link.rs:96` aborts a whole magnet parse on a
   flag-style parameter; the Kad bootstrap dial list bypasses the ipfilter and
   routability gates that guard routing inserts; `ios/project.yml:56-61` names
   NAT-PMP where the shipped path is unicast-SSDP UPnP; the related-search
   fallback pollutes Recent Searches with a filename.
5. **Research-pass backlog** - Download Inspector, known/cancelled marking in
   search results, majority-filename rename, throughput-based slot recycling,
   bulk select, persisted search results, ipfilter auto-update.

Also open, not yet tasks: serving PARTIAL files (complete files only today), and
no oracle yet proves a real client CONSUMING our source-exchange answer.

## Device + signing (see [[ipad-usb-tooling]] for the full runbook)

- **CI builds, this box SIGNS, Sideloadly INSTALLS.** Signing from here works
  (zsign + the cached Sideloadly cert/key by PATH, never copied). Installing over
  usbipd does NOT - a multi-megabyte transfer wedges the USB/IP link every time.
- **THE SIDELOADLY TRAP**: hand Sideloadly the UNSIGNED artifact. A build already
  signed here with `-b ...Q444CHAF2Z` came back as `...Q444CHAF2Z.Q444CHAF2Z`,
  a NEW bundle id, so it installed as a SEPARATE app with an empty container
  (fresh userhash + Kad ID) instead of upgrading in place.
- **pymobiledevice3 defaults to the WINDOWS usbmuxd on 127.0.0.1:27015** (WSL
  mirrored networking). Set `USBMUXD_SOCKET_ADDRESS=/var/run/usbmuxd` to pin it
  to the real USB link, or it goes blind when the iPad's address changes.
- **Certs + profiles EXPIRE 2026-08-10.** Renewal needs Sideloadly; re-pull the
  profile with `ideviceprovision copy` afterwards.

## Discipline reminders that earned their keep TONIGHT

- **"The authorities surely do X" is a hypothesis.** It was wrong twice in one
  night: the planned UPnP finite-lease fix (nobody uses a finite lease) and the
  periodic checkpoint (nobody saves nodes.dat on a timer). Checking cost one grep
  each and produced smaller, better-grounded changes.
- **A test that exercises a HELPER is not evidence about the CALLER.** The first
  Kad checkpoint fix passed its test and did nothing on the pause path, because
  pause drops the node before checkpointing. When a fix is about ORDERING, the
  test must drive the ordering.
- **Mutation-check a regression test**: break the fix, watch the test go red. Two
  tests tonight only earned trust that way.
- **Verify before reporting** - it turned an apparent decode bug into a filename
  that is genuinely mojibake on the wire, and "the UPnP fix regressed" into a
  port conflict that proved the fix works.

## Related

- [[ipad-usb-tooling]] - device runbook, touch control, signing, the traps.
- [[net-highid-and-port-forwarding]] - the stale-mapping dead end, start to end.
- [[build-progress]] - wave-by-wave status.
- [[security-model]] - the scorecard.
