# HighID and Port Forwarding (dev box + iPad)

Updated: 2026-07-18

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

Still true on foreign networks: UPnP-less routers, cellular, and CGNAT force
**LowID** regardless ([[ipados-constraints]]). LowID is survivable (the live
wav + pdf arrived via LowID callbacks) - HighID is a bonus, never an
assumption, and the UI surfaces which one we have plus the "Port mapping" row
(see [[lifecycle-and-reactivation]]).

## Related

- [[protocol-understanding]] - login flow, LowID callbacks, client-ID encoding.
- [[build-progress]] - Wave 4a listener; Wave 7 UPnP.
- [[ipados-constraints]] - why cellular/CGNAT forces LowID on-device.
- [[lifecycle-and-reactivation]] - honest status reporting to the user.
- [[decisions-and-lessons]] - the earlier wrong "WSL blocks P2P ports" finding.
