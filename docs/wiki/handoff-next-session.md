# HANDOFF - start here next session

Updated: 2026-08-02 (second session of the day; everything below is verified,
not assumed)

Living doc: replace it wholesale next time rather than appending. For the full
narrative see [[build-progress]] and the [[log]] entries for 2026-08-02.

## State of the tree

- **Gate**: 518 tests, clippy clean, fmt clean, ASCII clean (re-run this session).
- The reanalysis found the CODE SOUND - roughly 20 documented claims were
  cross-checked against the source and every one held (all 4 Kad landmines, all
  9 engine claims, 26 CLI subcommands, the six-screen function strip, secret-free
  CI). What drifted was the docs, and the load-bearing ones are now fixed.
- [[security-model]] scorecard unchanged: **23 OPERATIONAL / 1 PARTIAL / 2
  documented opt-outs**. The single PARTIAL is AICH block recovery (wave 11), an
  OPTIMIZATION, not an integrity hole.

## THE HEADLINE: the agent can now drive the iPad

Touch control WORKS ([[ipad-usb-tooling]] has the runbook). The previous
session's go-ios tunnel blocker was not solved - it was **bypassed**:
`pymobiledevice3 developer dvt xcuitest` launches WebDriverAgent directly, then
`pymobiledevice3 usbmux forward 8100 8100` exposes its HTTP API and plain curl
drives taps, typing, screenshots and the **accessibility tree** (the best way to
assert UI state as text). go-ios is not in the path at all.

So the on-glass pass in [[on-device-test-checklist]] is now agent-drivable end
to end, and the eleven previously-unexercised pushes HAVE now been exercised.

## What the first on-device run proved, and the bug it found

PASSED: the **function strip** renders correctly (six labelled icons - a visual
change CI cannot judge); **Kad is healthy at 172 contacts with the wave-10
verified-bit gate ON**, and a live keyword search returned real results with NO
server connected (the Kad-only path); the **free-space guard stayed silent**;
and a failed add reported HONESTLY ("No one online has ... right now").

FAILED, and it is a real defect: **the iPad has been LowID since its DHCP
address moved .182 -> .89.** The BE9700 still held padMule's own PERMANENT
`4662 -> .182` mapping, and this gateway refuses `DeletePortMapping` from a
non-owner (**Action not authorized**, reproduced independently from the dev box).
So padMule's delete-then-add cannot recover the exact case its own code comment
names, the add fails **ConflictInMappingEntry**, and the delete's real reason is
swallowed by `let _ =`. Second-order effect: eMule Sunrise KICKS LowID clients,
so the Servers screen honestly showed "Not connected" right after the MOTD
arrived. Full analysis + the queued fixes are in
[[net-highid-and-port-forwarding]].

**Was the stale mapping ever cleared?** It had NOT been at the end of this
session (`mule-cli upnp-query 4662` still answered `-> 192.168.0.182`). Anthony
was clearing it by hand in the router UI (TP-Link: Advanced -> NAT Forwarding ->
**UPnP**, NOT Port Forwarding, which lists only static rules). **First thing
next session: re-run `mule-cli upnp-query 4662`, then relaunch padMule and
confirm the Status row reads "UPnP: mapped port 4662" and the ID is HighID.**

## Open tasks

1. **UPnP stale-mapping fixes** (new, from the above): finite lease + renewal
   instead of `lease_secs = 0`; surface the swallowed delete error; consider an
   alternate-external-port fallback (needs padMule to advertise the EXTERNAL
   port, which it cannot express today); DHCP-reserve the iPad operationally.
2. **Kad mid-session state is never checkpointed** (new, from the reanalysis):
   `pause()` drops the KadNode without folding its routing table back into
   `Engine::routing` (the only sync is at the end of `start_kad`,
   `engine.rs:2056`), so `checkpoint()` persists the stale bootstrap snapshot and
   every contact AND per-peer UDP verify key learned during the session is lost.
   This undercuts wave 10's stated "echo the peer's verify key after a restart"
   intent (`engine.rs:94-99`). Small fix, directly serves work already paid for.
3. **Log the engine to os_log** (new): `idevicesyslog -p padMule` carries ZERO
   app-authored lines - a 1293-line capture was entirely system frameworks,
   because neither the Swift shell nor the Rust engine ever calls os_log. Until
   this lands, the UI rows are the engine's only window on-device.
4. **AICH block recovery** - the last PARTIAL, wave 11. Do NOT port the vendored
   3.0.1 oracle's racy `known2_64.met` orphan-prune (fixed upstream after 3.0.1);
   route `localize_corruption`'s blamed parts into block-level recovery; ship the
   AICH request rate limit and an O(1) index in the SAME change. Also lifts 8ai's
   sole-contributor limitation.
5. **Continuous block-request top-up** - padMule is stop-and-wait per 3-block
   batch (confirmed in `multi_source.rs:879-924`), shallower than BOTH
   authorities. eMule tops the pending list up as each block completes
   (DownloadClient.cpp:870-919); no wire change, big win at cellular RTT. Do NOT
   adopt aMule master's [3,24] BDP clamp - it cites eMule for a depth eMule never
   requests.
6. **Smaller code findings** from the reanalysis: `link.rs:96` aborts a whole
   magnet parse on a flag-style parameter (a bare `tr`) instead of skipping it;
   the Kad bootstrap dial list bypasses the ipfilter/routability gates that guard
   routing inserts; two stale comments (the preview "first+last" bias that
   `part_file.rs:314-320` explicitly does not do; an `Arc::try_unwrap` race
   rationale obsoleted by 8n's `finish_to`); `ios/project.yml:56-61` names NAT-PMP
   where the shipped path is unicast-SSDP UPnP; the related-search fallback
   pollutes Recent Searches with a filename.
7. **Research-pass backlog** - Download Inspector (content-fakes that hash
   correctly), known/downloaded/cancelled marking in search results,
   majority-filename rename, throughput-based upload-slot recycling, bulk select,
   persisted search results, ipfilter auto-update.

Also open, not yet tasks: serving PARTIAL files (we share complete files only),
and no oracle yet proves a real client CONSUMING our source-exchange answer.

## Remaining doc drift (found by the lint, NOT yet fixed)

Fixed this session: [[kad-verify-oracle]]'s superseded "Batch B pending" bullet,
[[index]]'s "NOT yet run end to end", CLAUDE.md's test count, plus the two
entries rewritten above. STILL OPEN: [[feature-server-hunter]] still proposes
steps 1-2 that shipped (8x/8y); AltStore's -22411 dead end is unannotated in
[[decisions-and-lessons]] (~line 87) and [[mac-toolchain-setup]] (3 places);
four files carry un-bumped `Updated:` dates (lifecycle, mac-toolchain,
protocol-reference, ref-source-trees); [[ed2k-server-oracle]] contradicts itself
on whether the self-filter is by hash or by IP; [[mac-toolchain-setup]] is 213
lines and wants an archive split.

## Discipline reminders that earned their keep

- **Verify before reporting.** This session it caught an on-screen mojibake
  filename that looked like a decode bug and was actually baked into the wire
  name (padMule uses `from_utf8_lossy` throughout); and it turned "the UPnP fix
  regressed" into the correct diagnosis - the SOAP call reached the gateway and
  got a specific UPnP error back, which PROVES the IGD:1 classification still
  works and the failure is a port conflict.
- **A tap that lands in a gap does nothing, silently.** Dismissing the keyboard
  reflowed the result list 32 points between two reads. Drive by ELEMENT, not by
  coordinate.
- **eMule 0.50a decides wire + formats; aMule is the runnable oracle +
  wire-neutral policy; where they conflict, follow eMule.**
- The vendored `amule-3.0.1/` oracle can itself contain bugs upstream later
  fixed - check `refs/amule-master/` before transcribing.

## Related

- [[ipad-usb-tooling]] - the device runbook, now including touch control.
- [[net-highid-and-port-forwarding]] - the stale-mapping dead end.
- [[build-progress]] - wave-by-wave status.
- [[security-model]] - the scorecard.
