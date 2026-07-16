# padMule-to-padMule Enhancement Channel

Updated: 2026-07-16

How two padMule clients recognize each other and negotiate optional enhancements
WITHOUT any stock eMule/aMule peer noticing. This is the highest-compatibility-risk
feature in the port, so the carrier is chosen from source-grounded proof, not a
guess. See [[protocol-understanding]] and [[decisions-and-lessons]].

## The carrier: what stock clients provably ignore

Source recon across aMule 3.0.1 (`amule-3.0.1/src/`) and eMule 0.50a
(`refs/emule-0.50a/...srchybrid/`). Every ed2k/Kad taglist is read by looping
`tagcount` times, each `CTag` fully consumed regardless of use. TWO decision
points behave OPPOSITELY:

- Unknown tag **NAME/id** (not cased in the handler switch): tolerated. aMule's
  hello switch has NO default (`BaseClient.cpp:477-478,635`); eMule's is benign
  (`BaseClient.cpp:585-592`). The tag is consumed, position stays aligned.
- Unknown tag **TYPE byte**: UNSAFE. aMule THROWS -> disconnect
  (`Tag.cpp:179` -> `ClientTCPSocket.cpp:1984,2011`); eMule silently DESYNCS its
  whole parse, corrupting the trailing serverIP/port (`packets.cpp:565-572`).

Verdicts (both clients, identical unless noted):

| Carrier | Verdict |
|---------|---------|
| HELLO tag, unknown NAME, **standard type byte** | PROVABLY IGNORED |
| HELLO tag with a **nonstandard type byte** | UNSAFE (aMule disconnects, eMule desyncs) |
| Unknown TCP **opcode** on an existing proto byte (0xE3/0xC5) | PROVABLY IGNORED (default case logs, `return` discarded) |
| A **novel protocol byte** | UNSAFE (disconnect: `EMSocket.cpp:281-283`) |
| Kad unknown tag TYPE / unknown Kad opcode | RISKY (throws, but caught+logged on UDP -> packet dropped, no disconnect) |

Rule locked in: **standard TYPE byte, existing protocol byte, always.** A
string-named tag is the safest name space (never in any switch, no id collision).

## Design: two layers

- **Layer 1 - detection (passive, sent to everyone).** One extra HELLO/HELLOANSWER
  tag, string-named `"padMule"`, value a standard UINT32 = `<caps:u24><version:u8>`.
  Stock peers read-and-skip it; another padMule recognizes it. This is the ONLY
  thing a stock peer ever sees, so it must be provably ignored (it is). It never
  sets a standard capability bit we do not honour (the [[decisions-and-lessons]]
  Wave 4d lesson).
- **Layer 2 - negotiation (active, only to a CONFIRMED padMule).** Any
  padMule-specific message rides an unused opcode on 0xC5 and is sent ONLY after
  Layer 1 identifies the peer as padMule, so a stock client never receives it -
  which sidesteps the unknown-opcode path entirely. Wire spec'd (below); not built.

## Layer 2 wire (spec'd 2026-07-16, source-grounded)

A 0xC5 extended packet is `[0xC5][u32 packetlength LE][opcode][payload]`, where
`packetlength = 1 + len(payload)` (counts opcode + payload); total on wire =
`packetlength + 5`. The receiver drains by the SIZE field and never consults the
opcode during framing (eMule EMSocket.cpp:367-425 / aMule EMSocket.cpp:199-266),
so an unknown opcode carrying an arbitrary-length payload does NOT desync a stock
peer - it is consumed by length and dropped at the switch default with no throw
and no disconnect (eMule ListenSocket.cpp:2075-2078; aMule
ClientTCPSocket.cpp:1777-1780). The only framing constraints: the protocol byte
must stay 0xC5 (or 0xD4 packed), and a client object must exist - which it does,
because Layer 2 is only ever sent AFTER the hello handshake that identified the
peer as padMule.

- **Opcode: 0xD8** (secondary 0xC8). Unused on 0xC5 in both clients, in the
  0xC0-0xDF dead zone, FAR above eMule's current 0xB2 opcode frontier (so a future
  stock release extending upward won't collide), and not a protocol-byte value
  (0xC5/0xD4) or an edge (0xFE OP_PORTTEST/0xFF). Do NOT pick 0xB3+ - that is
  exactly where stock numbering grows next.
- **Compression:** a Layer-2 message may be zlib-packed exactly like
  OP_COMPRESSEDPART - build it as 0xC5+0xD8, PackPacket flips the protocol byte to
  0xD4 leaving the opcode intact, the peer unpacks back to 0xC5+0xD8. Keep the
  DECOMPRESSED size under the stock 50000-byte default cap (packets.h:44); pack
  only when it actually shrinks.
- **First message (planned):** a padMule capability/version detail exchange
  (richer than the Layer-1 u32 bitmask) - and later the NAT-traversal signaling
  (endpoint relay + punch coordination), see [[nat-traversal-design]].

## Status

- **Layer 1 DONE + adversarially validated (2026-07-16).** `peer.rs`:
  `padmule_marker_tag`, `ParsedHello::padmule() -> Option<PadMuleInfo>`; every
  hello now carries the marker (tag count 7 -> 8). 4 unit tests (round-trip
  detect, string-named-UINT32 shape, stock-hello-not-detected, caps/version
  decode). ADVERSARIAL GATE: the amuled differential test passes with the marker
  in every hello - real aMule 3.0.1 completes the handshake and serves all three
  files (single-part, multi-part+hashset) byte-for-byte, proving it ignores the
  marker. eMule 0.50a coverage is source-grounded (no eMule binary on this box).
- **Layer 2 + enhancements: wire spec'd, DEFERRED (decision 2026-07-16).** Not
  built. Every enhancement works only padMule<->padMule, so value is gated on
  adoption; with a mass-adoption goal that is chicken-and-egg, so Layer 2 now would
  be a speculative feature. Layer 1 stays deployed (cheap early seed); Layer 2 +
  NAT traversal are a de-risked design to revisit once real padMule<->padMule
  traffic exists. See [[decisions-and-lessons]]. The marquee enhancement is NAT
  traversal ([[nat-traversal-design]]).

## Why NAT traversal is the marquee enhancement (the LowID<->LowID question)

Classic eD2k/Kad cannot connect two firewalled (LowID) peers: at least one side
must accept an inbound connection, and servers refuse to relay a callback between
two LowIDs. That is by design, NOT a law - modern NAT traversal (UDP hole
punching via a mutually-reachable rendezvous, with a HighID relay fallback for
symmetric NAT) connects NAT'd peers routinely (WebRTC/BitTorrent do it). padMule
could unlock padMule<->padMule LowID transfers over the Layer-2 channel, fully
compatibly (it never changes how we talk to stock clients). Caveats: only helps
padMule pairs (adoption-gated), needs a reliable-UDP transport (eD2k transfers
are TCP) + a rendezvous + a relay fallback, and for a single user the cheaper
unlock is just becoming HighID (UPnP/NAT-PMP, see [[net-highid-and-port-forwarding]]).
Hole punching earns its keep only on CGNAT/cellular where HighID is impossible -
a real iPad scenario.

## Related

- [[nat-traversal-design]]
- [[protocol-understanding]]
- [[decisions-and-lessons]]
- [[net-highid-and-port-forwarding]]
- [[build-progress]]
