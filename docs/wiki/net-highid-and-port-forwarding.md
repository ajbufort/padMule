# HighID and Port Forwarding (dev box + iPad)

Updated: 2026-08-03 (VPN/port-forwarding section added; the queued fixes below SHIPPED 2026-08-02 and are
device-verified; the finite-lease idea was investigated and KILLED - see the
annotations in place)

How padMule earns a **HighID** on the eD2k network. Dev-box HighID via a manual
forward chain **VALIDATED LIVE 2026-07-14**; iPad HighID via padMule's own
unicast-SSDP UPnP **VALIDATED ON-DEVICE 2026-07-17**.

## TOPOLOGY CHANGE (2026-07-17) - read this first

The network the 5-link chain below describes NO LONGER EXISTS. Because the
Xfinity XB8's UPnP toggle is COSMETIC (it never answers SSDP by any method,
confirmed exhaustively from WSL and native Windows), Anthony bridged the XB8
and put a **TP-Link Archer BE9700** in front as edge router:

- XB8 in bridge mode (hands off ~2 Gbps from its red 2.5G Port 4) -> BE9700 is
  the router: gateway **192.168.0.1**, real UPnP IGD, UPnP ON.
- Dev box is now **192.168.0.32**; iPad **192.168.0.182** (reserve it in the
  BE9700 so its permanent mapping never goes stale).
- Inbound now comes from **UPnP mappings**, not manual forwards: `mule-cli
  upnp-unicast 4662` maps the dev box; the iPad maps itself in `map_port()`
  (delete-then-add, so a stale mapping self-heals) and shows the result in the
  "Port mapping" Status row.
- Re-validate today with: `mule-cli upnp-unicast 4662` (expect the real public
  IP back = no double-NAT), then `listen` + `login` as below.
- LESSON: never trust an ISP-gateway UPnP toggle; verify with an independent
  SSDP probe. A leftover PERMANENT test mapping (lease 0) squats the port for
  every other device - clean up what a validation run creates.

The Windows/Hyper-V firewall links (3-4) and WSL mirrored mode (5) still apply
to the dev box unchanged; only the router links (1-2) are obsolete. Sections
below are kept as the historical record of the old Xfinity 10.0.0.x network.

## Why HighID matters

An eD2k server assigns a client ID at login. It connect-back-tests the TCP port
the client advertises in OP_LOGINREQUEST:

- **HighID** - the connect-back succeeded. The server sets `client_id` = the
  client's public IPv4, encoded first-octet-in-the-low-byte (LE). Any peer can
  connect to us directly.
- **LowID** (`id < 16777216`) - the connect-back failed (NAT/firewall). We can
  only reach peers that are themselves HighID, via server-brokered callbacks.
  Uploads and source-finding are badly degraded.

So HighID is not cosmetic: it decides whether padMule is a first-class peer.
It requires padMule to **listen** (`accept_peer`, Wave 4a) *and* for inbound
TCP to actually reach that listener.

## The chain (all five links must be open) [HISTORICAL - old Xfinity network]

Inbound TCP 4662 (eD2k peer) and UDP 4672 (client/Kad UDP) traverse:

1. **Router port forward** - Xfinity gateway (10.0.0.1): TCP 4662 + UDP 4672 ->
   `10.0.0.33`. Done via the Xfinity app -> WiFi -> Advanced Settings -> Port
   Forwarding.
2. **DHCP reservation** - 10.0.0.33 pinned to the host's wired NIC MAC
   (`<nic-mac>`, Realtek USB 2.5GbE) so the forward target cannot drift
   on lease renewal. Xfinity's port-forward flow usually auto-reserves.
3. **Windows Firewall** - inbound allow rules `padMule eD2k TCP 4662` /
   `padMule eD2k UDP 4672` (created by
   `/mnt/c/Users/ajbuf/Downloads/padmule-firewall.ps1`, run elevated).
4. **Hyper-V firewall** - **the mirrored-mode trap.** `networkingMode=mirrored`
   activates a *separate* Hyper-V firewall for the WSL VM whose
   `DefaultInboundAction` is **Block**. Host firewall rules are mirrored into it
   (WSL `firewall=true` default), so the two rules above cover it - but if
   inbound ever dies silently under mirrored mode, check here first:
   `Get-NetFirewallHyperVVMSetting -PolicyStore ActiveStore`.
5. **WSL2 networking** - default NAT gives the VM a private 172.x address that
   the LAN cannot reach. `networkingMode=mirrored` in `/mnt/c/Users/ajbuf/.wslconfig`
   makes WSL share the host's LAN IP (WSL now shows `10.0.0.33/24` on eth3), so
   the router's forward lands directly on the WSL listener. **Mirrored is
   required because `netsh portproxy` is TCP-only and cannot forward the UDP
   4672 that Kad needs.** Applying it needs `wsl --shutdown`.

## VALIDATED LIVE (2026-07-14)

With `mule-cli listen 4662` running, `mule-cli login 45.87.41.16 6262` returned:

```
login result: Connected { id: <client-id>, low_id: false }
```

- `<client-id>` = `<client-id-hex>` -> decoded LE (first octet in low byte) =
  **<public-ip>** = our public IP. That *is* the HighID definition, and it
  confirms our LE client-ID decode is correct against a real server.
- The listener logged the server's connect-back arriving from the internet:
  `inbound connection from 45.87.41.16:49144`.
- Pause -> resume -> reconnect kept HighID.

This upgrades the 2026-07-13 result (same server, **LowID**) and proves all five
links. It is the first time padMule has been a full first-class peer.

**Server connect-back behavior (observed):** the server opens a TCP connection
and closes it without sending an eD2k HELLO. A successful *accept* is enough to
earn HighID - the listener need not complete a handshake. Our listener logs this
as "connection reached us (forward works); handshake ended: connection closed",
which is the expected, healthy path, not an error.

## How to re-validate [HISTORICAL recipe - on the BE9700, run upnp-unicast first]

```bash
./target/release/mule-cli listen 4662 &          # bind the inbound listener
./target/release/mule-cli login 45.87.41.16 6262 # expect low_id: false
```

Cheap pre-check (no server needed): the Xfinity gateway supports **NAT hairpin**,
so `timeout 8 bash -c "</dev/tcp/<public-ip>/4662"` succeeding from inside the
LAN proves the forward rule + both firewalls + the listener. A hairpin *failure*
is inconclusive on gateways that disable NAT loopback; this one does not.

## iPad HighID - ACHIEVED (2026-07-17)

UPnP port mapping was the right answer and it SHIPPED: iOS silently drops
multicast SSDP without a restricted entitlement, so `upnp.rs` aims a UNICAST
M-SEARCH at the inferred gateway (.1/.254 of our /24), then runs the normal
IGD description/SOAP flow with delete-then-add. On the BE9700 the iPad mapped
4662->4662 itself and earned **HighID (green)**; the router's UPnP client list
shows `padMule 192.168.0.182`. Root cause of the earlier on-device LowID was a
leftover permanent 4662->dev-box mapping from a validation run plus a lenient
query that read any fault as "free" - both fixed (honest 714-vs-fault query;
delete-then-add). See [[build-progress]] row 8c.

## THE STALE-MAPPING DEAD END (found on-device 2026-08-02) - supersedes the
## "delete-then-add, so a stale mapping self-heals" claim above

Driving the iPad over USB ([[ipad-usb-tooling]]) put the Status screen on screen
for the first time since 2026-07-17, and it read:

```
UPnP: could not map port 4662 (gateway refused: ConflictInMappingEntry)
```

Traced to the end, and the conclusion is that **padMule's delete-then-add cannot
recover the case its own code comment names.** The chain:

1. The iPad's DHCP address moved **192.168.0.182 -> 192.168.0.89** (the
   reservation this entry recommended in 2026-07-17 was never actually made).
2. The BE9700 still held padMule's own PERMANENT mapping `4662 -> .182`
   (`mule-cli upnp-query 4662` confirms; .182 no longer answers ARP or ping).
3. `upnp.rs` map_port/map_port_unicast do `soap_delete_mapping` then
   `soap_add_mapping`. The DELETE is refused: **`Action not authorized`**
   (UPnP error 606) - reproduced from the dev box (.32), also a non-owner, via
   `mule-cli upnp-unmap 4662`.
   **The refusal is OWNERSHIP-based, not a blanket ban on deletes - proven with
   a positive control:** the dev box mapped :4663 (`mule-cli upnp 4663`) and then
   deleted that same mapping successfully (`mule-cli upnp-unmap 4663`, confirmed
   gone by a follow-up query). So a client CAN clean up after itself while its
   address is stable, and CANNOT once its address changes. That is exactly why
   the **finite-lease fix is the load-bearing one** [KILLED 2026-08-02 - see the
   FIXES WORTH MAKING section below; the idea was investigated and rejected, and
   eMule's CheckAndRefresh port shipped instead]: it is the only remedy that
   survives an address change without a human.
4. The add then fails **`ConflictInMappingEntry`** (error 718), and the delete's
   real reason never surfaces because the call site swallows it (`let _ =`).
5. LowID follows, and then a second-order failure: **eMule Sunrise KICKS LowID
   clients** ("WARNING : You have a lowid ..." then closes the socket -
   reproduced from the dev box), so the Servers screen honestly showed
   "Not connected" even though the MOTD had arrived.

So a permanent lease (padMule asks for `lease_secs = 0`) plus any address change
= **permanent LowID that padMule cannot fix by itself**.

**RESOLVED THE SAME SESSION by option 1 below - see the confirmation at the end
of this section.**

CLEARING IT IS HARDER THAN EXPECTED: the BE9700's UPnP page (Advanced -> NAT
Forwarding -> **UPnP**; NOT Port Forwarding, which lists only STATIC rules and is
empty) is **display-only - it has no delete control**. The ways out, best first:

1. **DHCP-reserve the iPad at its OLD address (.182) and reconnect.** Then
   padMule OWNS the mapping again, and its existing delete-then-add self-heals on
   the next launch - no router surgery, and the reservation is the durable fix
   that stops the drift recurring. (This is the reservation this entry already
   recommended on 2026-07-17 and which was never made.)
2. **Toggle UPnP off -> Save -> on -> Save**, which flushes the mapping table on
   most TP-Link firmware. Brief interruption for other UPnP clients.
3. Reboot the router (blunt; disrupts everything).

### CONFIRMED FIXED (2026-08-02, same session)

Anthony added the DHCP reservation (option 1) and the iPad moved **.89 -> .182**.
That alone resolved it, because the stale mapping now names the iPad's CURRENT
address, so padMule owns it again. Proven at the network layer, no UI needed:

- `192.168.0.182` answers ping; `.89` no longer does.
- `mule-cli upnp-query 4662` -> `:4662 -> 192.168.0.182` (now the live iPad).
- A direct LAN connect to `192.168.0.182:4662` SUCCEEDS - padMule is listening.
- **NAT hairpin from the dev box to `<public-ip>:4662` SUCCEEDS** - an
  external-facing connection reaches padMule on the iPad, which is the port
  forward working end to end. (The BE9700 supports NAT loopback, so this is a
  valid cheap proof; a hairpin FAILURE would have been inconclusive.)

Still to confirm in the APP itself (blocked at session end by an unrelated
pymobiledevice3 regression, [[ipad-usb-tooling]] gotcha 7): relaunch padMule and
read the Status row for "UPnP: mapped port 4662" plus a HighID. padMule only
attempts the mapping at start/resume, so the row still showed the old
ConflictInMappingEntry error from its LAST launch.
[SUPERSEDED 2026-08-02: confirmed the same day via the agent-driven device pass
([[ipad-usb-tooling]]) - the gateway itself was queried before/after Stop/Start
(Stop released 4662 at the gateway, Start re-claimed it), so this is no longer
open.]

FIXES WORTH MAKING (none shipped yet, queued as tasks) [SUPERSEDED 2026-08-03:
most of these SHIPPED 2026-08-02 (build-progress rows 8at/8au), device-verified -
verify-then-reopen refresh on resume AND on a LowID server answer
(upnp::refresh_mapping / refresh_and_remap), a conflict message that NAMES the
current holder, and release-on-Stop (Engine::shutdown awaits unmap_port; Stop
released 4662 at the gateway, Start re-claimed it). Per-item status below]:
- **Finite lease + renew** instead of `lease_secs = 0`, so a stale mapping
  self-heals within one lease. Check what eMule 0.50a asks for before picking a
  number ([[emule-vs-amule-authority]] - this is wire-neutral policy, so aMule
  is also legitimate precedent).
  [KILLED 2026-08-02: eMule 0.50a, eMule 0.70b, aMule 3.0.1, and aMule master
  ALL request NewLeaseDuration=0 (nobody on the wire uses a finite lease), so
  there was no precedent to follow either way. What shipped instead is eMule's
  own CheckAndRefresh port: verify-then-reopen on resume and on a LowID server
  answer (upnp::refresh_mapping / refresh_and_remap).]
- **Surface the delete failure**: the `let _ =` hides the ONE fact that explains
  the conflict, on the one platform with no debugger. `engine.rs:1535-1540`
  already argues this exact point for the add.
  [SHIPPED 2026-08-02: the conflict message now NAMES the current holder
  (build-progress rows 8at/8au), device-verified.]
- **Fall back to an alternate external port** on ConflictInMappingEntry (the
  UPnP-standard remedy) - but padMule advertises `TCP_PORT` to servers/peers, so
  it must then advertise the EXTERNAL port, which it cannot express today.
- The cheap operational fix regardless: **DHCP-reserve the iPad** on the BE9700.

Still true on foreign networks: UPnP-less routers, cellular, and CGNAT force
**LowID** regardless ([[ipados-constraints]]). LowID is survivable (the live
wav + pdf arrived via LowID callbacks) - HighID is a bonus, never an
assumption, and the UI surfaces which one we have plus the "Port mapping" row
(see [[lifecycle-and-reactivation]]).

## VPN + padMule: port forwarding is the whole question (2026-08-03)

Anthony asked which VPN is best for padMule. Recorded because the answer is
mostly a padMule fact, not a vendor opinion - and because NOTHING had been
written on this before (the only prior "VPN" mentions in the KB are eMuleAI's
VPN Guard, which we skipped since Network Extensions are blocked for free-team
sideloads, and a random eD2k server's MOTD advertising "VPN with port
forwarding (for High ID)" that scrolled past during a live login test - a
server's ad, not a vetted recommendation).

- **A VPN replaces the mechanism this whole entry documents.** On the tunnel,
  the UPnP mapping padMule negotiates with the BE9700 is irrelevant: inbound
  reachability now depends entirely on the PROVIDER forwarding a port. No
  forwarding -> LowID for the whole session, which costs direct dials,
  makes us dependent on server callbacks, and makes LowID-to-LowID peers
  unreachable outright.
- **Most consumer VPNs no longer forward ports.** As of the 2026-01 knowledge
  cutoff: Mullvad REMOVED it (2023), PIA dropped it earlier, and Proton has it
  on desktop but historically NOT on iOS. The ones that offered an
  iPad-usable path were AirVPN (port assigned in their control panel, works
  with a plain WireGuard config in the official WireGuard app) and TorGuard,
  with Windscribe offering ephemeral forwarding on paid plans. VERIFY before
  paying - this is exactly the feature providers quietly drop.
- **BLOCKER ON OUR SIDE: padMule's listening port is hardcoded to 4662**
  (`TCP_PORT`). A provider that assigns an ARBITRARY forwarded port cannot
  give padMule HighID until the app can be told to listen on it. So "port
  override" - already sitting in the Settings Tier 1/2 backlog - is a
  PREREQUISITE for the VPN story, not a nicety, and should be promoted before
  anyone subscribes for this purpose.
- Worth weighing honestly: on the home network HighID already works via UPnP,
  so a VPN is a privacy choice that COSTS connectivity unless the forwarding
  is real and the port is settable.

## Related

- [[protocol-understanding]] - login flow, LowID callbacks, client-ID encoding.
- [[build-progress]] - Wave 4a listener; Wave 7 UPnP.
- [[ipados-constraints]] - why cellular/CGNAT forces LowID on-device.
- [[lifecycle-and-reactivation]] - honest status reporting to the user.
- [[decisions-and-lessons]] - the earlier wrong "WSL blocks P2P ports" finding.
