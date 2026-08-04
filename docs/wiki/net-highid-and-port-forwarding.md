# HighID and Port Forwarding (dev box + iPad)

Updated: 2026-08-04 (pre-VPN history split to
[[net-highid-and-port-forwarding-history]]. CORRECTED: the AirVPN "Local" field cannot be left blank - it refuses to save and keeps the old port, which is what held padMule at LowID; VPN/port-forwarding section added; the queued fixes below SHIPPED 2026-08-02 and are
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

## VPN + padMule: port forwarding is the whole question (2026-08-03)

### AirVPN specifically - researched 2026-08-03 (Anthony asked)

Verified against AirVPN's own FAQ and iOS guide, not from memory:

- **Ports are USER-CHOSEN, not randomly assigned**: "You can use ports >= 2048.
  Lower ports are already reserved", up to 5 forwarded simultaneously, held as
  long as the subscription is active. 4662 is >= 2048 so the eD2k default is
  requestable in principle - but **TESTED 2026-08-03 and it is NOT available**:
  AirVPN answered "The requested port is not available", i.e. another subscriber
  already holds the most famous eD2k port. Do not plan around getting it, and
  note this makes the port override (8bd) a hard PREREQUISITE rather than a
  nicety - without it padMule could not have used AirVPN at all.

  **The clean setup, given that:** reserve ONE available port X with BOTH TCP
  and UDP enabled, set the "Local" field EXPLICITLY TO X, and set
  padMule's listen = advertised = kad = X.

  [CORRECTED 2026-08-04, device-verified. This used to say "leave the Local
  field EMPTY (same-port forwarding)" and that is WRONG IN PRACTICE: the AirVPN
  UI REFUSES TO SAVE a blank Local port, and silently keeps the previous value.
  Anthony hit exactly this - the rule kept its old 4662 while the form appeared
  blank, so AirVPN delivered remote 5999 to local 4662 while padMule listened on
  5999. The tell was `Connection refused (111)` from the "Test open" checker
  rather than a timeout: refused means the packet TRAVERSED the tunnel and
  reached the iPad, which actively replied "nothing listening" - so the path was
  never the problem, only the port. A timeout would have meant the opposite.
  Type the port number into Local explicitly, and if an edit will not stick,
  REMOVE the rule and re-add it.] One number for TCP and UDP is fine -
  they are separate namespaces, and nothing in the eD2k protocol requires a
  client's UDP port to differ from its TCP port; the 4662/4672 split is only
  convention. That covers peer connections AND Kad from a single reservation,
  leaving four of the five spare. The alternative - Local = 4662, so remote X
  reaches local 4662 - is exactly what the advertised-vs-listen split exists
  for, and is the right shape if a local port must stay fixed.

  NB padMule binds its transient UDP sockets (status probe, global search, the
  crawl) on EPHEMERAL ports, so nothing else shifts when the TCP port moves:
  there is no local "TCP+3" socket to keep in step, despite the eD2k convention
  noted in [[protocol-reference]].
- **TCP and UDP both supported**, per-port ("TCP, UDP or both, according to
  your selection") - so Kad's UDP port can be forwarded too, as a second port.
- **Remote-to-local mapping is supported**: the "Local" field decides the local
  port. Setting it to n forwards remote n -> local n; setting it to a different
  x forwards remote n -> local x, which is the case that forces the
  advertised-vs-listen split. It CANNOT be left blank - the form refuses to save
  and keeps whatever was there before (device-verified 2026-08-04), so a rule
  that looks blank may still be pointing at an old port.
- **Forwarding is configured SERVER-SIDE** in Client Area -> Ports -> Manage,
  independent of the client app - which is what makes it usable on an iPad at
  all. A port can be bound to a specific device or to all devices.
- **iPadOS path**: the official WireGuard app from the App Store, fed a config
  from AirVPN's Config Generator by QR code or `.conf` import. Note the port
  forwarding is NOT set in the Config Generator - it is managed separately in
  the Ports panel, which is a documented source of confusion in their forums.
- Sources: <https://airvpn.org/faq/port_forwarding/>,
  <https://airvpn.org/ios/wireguard/appstore/>

### The iOS kill-switch gap, and padMule's answer (build-progress 8be)

AirVPN's own iOS page carries a footnote worth reading twice: Apple processes
and apps "can bypass any VPN tunnel at will" (and separately, App Store terms
conflict with the GPL, which is why they ship no iOS app - the same friction
that makes padMule sideload-only). The GPL half is a non-issue for a user: the
official WireGuard app is the client. The bypass half is real but does NOT
affect padMule's own traffic, which is ordinary app-level TCP/UDP to eD2k
servers and peers, not an Apple system service.

**The consequence that DOES matter is the missing kill switch.** Stock iOS has
none (Always-On VPN is MDM/supervised-only), so if the tunnel drops, iOS
silently falls back to the normal interface - and padMule would keep seeding
from the REAL address, with the advertised port now wrong, and nothing on
screen to say so. That is a privacy exposure and a LowID at the same moment.

padMule now defends against it, using a fact it already receives: **a HighID
client id IS our public address.** `note_public_id` compares it across logins
and, on a CHANGE, PAUSES SHARING and raises a loud alert. Anthony chose both
behaviours (auto-pause + warn) when asked.

- The address is compared internally and NEVER emitted. `EngineEvent::
  PublicAddressChanged` is deliberately PAYLOAD-FREE, for the same reason
  `connect_to_server` refuses to record the client id in user-visible text.
- A LowID login carries no public address, so it neither trips the guard nor
  overwrites what we knew - otherwise every LowID server would false-pause.
- The latch is cleared when the user turns sharing back on: the app keeps
  saying WHY sharing is off until they decide.
- Wired at BOTH login sites (connect and resume); a resume is a fresh login and
  is exactly when a tunnel is most likely to have gone. Mutation-checked at the
  caller, not just the helper: removing the call from `connect_to_server`, or
  removing the LowID exemption, each turns the right test red.
- HONEST LIMIT: this fires on ANY public-address change, so switching VPN exit
  servers or moving Wi-Fi-to-cellular also trips it. That is the safe direction
  - the action is a pause plus an explanation, never a silent continue - but it
  is a false positive from the user's point of view, and the wording says so.

### What padMule needed for this, and now has (build-progress 8bd)

- `set_ports(listen, advertised, kad)`: the LISTEN port is what we bind, the
  ADVERTISED port is what servers and peers are told. They are equal in the
  ordinary home case and differ under remote-to-local forwarding. Getting this
  wrong is INVISIBLE on the dev box - everything still binds and connects
  locally while every real peer dials a port nothing listens on - which is
  exactly what the mutation test showed before a wire-level assertion was added.
- `set_upnp_enabled(false)`: on a VPN the LAN-router mapping accomplishes
  nothing and its failure line actively misleads, so it must be switchable off.

(The pre-VPN chain, the VPN vendor survey, its validation, the first iPad HighID and the
stale-mapping dead end moved verbatim to
[[net-highid-and-port-forwarding-history]] on 2026-08-04.)

## Related

- [[protocol-understanding]] - login flow, LowID callbacks, client-ID encoding.
- [[build-progress]] - Wave 4a listener; Wave 7 UPnP.
- [[ipados-constraints]] - why cellular/CGNAT forces LowID on-device.
- [[lifecycle-and-reactivation]] - honest status reporting to the user.
- [[decisions-and-lessons]] - the earlier wrong "WSL blocks P2P ports" finding.
