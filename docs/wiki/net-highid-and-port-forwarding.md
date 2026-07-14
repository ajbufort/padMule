# HighID and Port Forwarding (dev box + iPad)

Updated: 2026-07-14

How padMule earns a **HighID** on the eD2k network, and the exact chain that had
to be fixed on the WSL2 dev box. **VALIDATED LIVE 2026-07-14** (see below).

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

## The chain (all five links must be open)

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

## How to re-validate

```bash
./target/release/mule-cli listen 4662 &          # bind the inbound listener
./target/release/mule-cli login 45.87.41.16 6262 # expect low_id: false
```

Cheap pre-check (no server needed): the Xfinity gateway supports **NAT hairpin**,
so `timeout 8 bash -c "</dev/tcp/<public-ip>/4662"` succeeding from inside the
LAN proves the forward rule + both firewalls + the listener. A hairpin *failure*
is inconclusive on gateways that disable NAT loopback; this one does not.

## iPad implications (Wave 7/8)

The dev-box forward is a **dev-box** fix - it does not carry to the iPad. On the
same home LAN the iPad will hit the identical problem with its own address, so
padMule on-device needs one of:

- **UPnP / NAT-PMP port mapping** (Wave 7) - the right answer; what real clients
  do, no user config. This is now a stronger priority given HighID's value.
- a manual per-device forward + DHCP reservation for the iPad (works, but a bad
  user experience and useless off the home network),
- or accept **LowID** on foreign networks (cellular/CGNAT will force this
  regardless - see [[ipados-constraints]]).

Expect padMule to be LowID on most real-world networks. HighID must be a
*bonus*, never an assumption; the UI should surface which one we have honestly
(see [[lifecycle-and-reactivation]]).

## Related

- [[protocol-understanding]] - login flow, LowID callbacks, client-ID encoding.
- [[build-progress]] - Wave 4a listener; Wave 7 UPnP.
- [[ipados-constraints]] - why cellular/CGNAT forces LowID on-device.
- [[lifecycle-and-reactivation]] - honest status reporting to the user.
- [[decisions-and-lessons]] - the earlier wrong "WSL blocks P2P ports" finding.
