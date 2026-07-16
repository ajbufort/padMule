# padMule NAT Traversal - Design

Updated: 2026-07-16

How two firewalled (LowID) padMule peers could connect DIRECTLY - which classic
eD2k/Kad cannot do. This rides the [[padmule-enhancement-channel]] Layer 2 (it is
padMule-only, never perturbs stock peers) and is the marquee enhancement behind
the LowID<->LowID question. Design only; not built. Source-grounded + SOTA recon
2026-07-16.

## The problem, confirmed from source

Stock eMule 0.50a / aMule 3.0.1 have ZERO hole punching. `CamuleApp::CanDoCallback`
(amule.cpp:2142-2189; eMule emule.cpp:1355-1405) hard-refuses when both peers are
firewalled, and every "reach a firewalled peer" path terminates in a TCP dial
FROM the firewalled callee TO a reachable requester (buddy-relayed OP_CALLBACK
ClientTCPSocket.cpp:1625; direct-UDP-callback ClientUDPSocket.cpp:318; server
OP_CALLBACKREQUESTED ServerSocket.cpp:545). Two LowIDs have no reachable endpoint
on either end -> `DS_LOWTOLOWIP` dead state. So the punch is genuinely new code.

## Reusable primitives already in Kad (we do NOT reinvent these)

- **Rendezvous mailbox = Kad publish/lookup at a shared key.** A firewalled peer
  can't BE an index node but CAN publish/search (the IsFirewalledUDP guard only
  blocks storing, KademliaUDPListener.cpp:1021). Two padMule peers deriving the
  same key (e.g. MD4(shared-secret)) each write/read a few dozen bytes (endpoint,
  NAT type, nonce) at the ~10 XOR-closest open nodes. Republish 5 h (sources).
- **STUN-equivalent already exists.** KADEMLIA2_PING/PONG returns your source
  port as the remote sees it (Process2Pong, KademliaUDPListener.cpp:1543-1583);
  KADEMLIA_FIREWALLED_RES returns your observed public IP; the UDP firewall tester
  learns intern-vs-extern port (UDPFirewallTester.cpp:144-162). That is how each
  peer learns its own punchable mapping.
- **Buddy relay pattern** (HighID forwards a trigger into a firewalled node over a
  standing TCP link, KADEMLIA_CALLBACK_REQ -> OP_CALLBACK) is reusable for the
  relay fallback - but its payload is a fixed struct, so padMule needs its own
  relay message over Layer 2 to carry arbitrary coordination/data bytes.

## Design (borrows libp2p DCUtR + BitTorrent BEP-55)

1. **Discovery (Kad).** Find a mutual HighID padMule "buddy" / rendezvous node;
   advertise padMule-reachability. Eventually-consistent, high-latency - discovery
   only, not the real-time channel.
2. **Signaling (HighID buddy or Kad mailbox).** Each peer learns its own observed
   `ip:port` (STUN-equiv above), publishes it to the other via the buddy (BEP-55
   Rendezvous/Connect shape) or the Kad mailbox. The buddy is the low-latency
   bidirectional channel DCUtR-style RTT timing needs.
3. **The punch (DCUtR-timed).** Both peers send raw UDP toward each other's
   observed mapping near-simultaneously; each outbound packet opens the sender's
   own NAT mapping so the peer's inbound is accepted. Measure RTT over the buddy,
   fire at half-RTT so packets cross in flight.
4. **Transport = QUIC over the punched socket (`quinn`).** After the raw-UDP punch
   opens the mapping, bring up a `quinn` connection on that SAME socket (its
   Endpoint hosts many conns over one UDP socket - documented for hole-punched
   sockets). Gives reliability + TLS 1.3 (eD2k is cleartext - a real win) + a
   built-in keep_alive_interval for NAT mapping upkeep. Raw-UDP-punch-first sidesteps
   QUIC's client/server handshake asymmetry (then pick one side as initiator).
5. **Relay fallback (TURN / circuit-relay-v2 analog).** When the punch fails, relay
   data through the HighID buddy with byte/time limits.

## NAT reality (why a fallback is mandatory)

Cone x cone (full / addr-restricted / port-restricted, any mix) generally punches
- the mapping is destination-independent, so the port learned via signaling is the
port the peer must hit. Symmetric NAT allocates a different unpredictable port per
destination, so the signaled endpoint is wrong: symmetric x cone sometimes works
via port prediction; **symmetric x symmetric never punches** -> relay only. Field
data: ~70-80% of pairs connect directly (libp2p DCUtR 2025 study ~70%+-7%, 97.6%
of successes on first attempt), ~20-30% need a relay, skewed WORSE on cellular
CGNAT (frequently symmetric) - a real iPad case.

## Phased plan

- **Phase 0** endpoint discovery: reuse Kad PING/PONG + FIREWALLED_RES to learn
  own observed ip:port; optionally classify cone-vs-symmetric.
- **Phase 1 (MVP)** two LowID padMule peers + a common HighID padMule buddy; buddy
  relays endpoints (Layer-2 message); RTT-synced raw-UDP punch; QUIC over the
  punched socket. Success = a cone x cone LowID pair moves bytes directly.
- **Phase 2** Kad-driven rendezvous (discover a mutual buddy automatically).
- **Phase 3** robustness: connection-reversal shortcut if either side is actually
  HighID (no punch needed); symmetric port prediction; retries; keepalive ~15-25 s;
  NAT-type-aware strategy.
- **Phase 4** relay fallback through the HighID buddy for symmetric x symmetric.

## Risks

- **Adoption/bootstrap (structural, biggest):** only helps padMule<->padMule pairs
  and Phases 1/4 need reachable HighID padMule buddies - little value until a
  critical mass of padMule HighID nodes exists.
- **Symmetric NAT / CGNAT, esp. cellular:** worst case for an iPad; expect the
  20-30% relay share, worse on mobile.
- **iOS lifecycle:** foreground-only + socket reclamation ([[ipados-constraints]])
  -> every direct link is ephemeral; design for cheap re-punch on resume.
- **Interop discipline:** all of this is gated behind a padMule Layer-2 capability
  bit; a stock aMule/eMule peer must never see any of it. [[decisions-and-lessons]].

## Related

- [[padmule-enhancement-channel]]
- [[net-highid-and-port-forwarding]]
- [[padmule-kad-notes]]
- [[ipados-constraints]]
- [[build-progress]]
