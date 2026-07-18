# Protocol Understanding: eD2k + Kademlia (mental model)

Updated: 2026-07-18

The conceptual companion to the byte-level tables in [[protocol-reference]].
Full study (flows, state machines, the why): `docs/raw/protocol-understanding-2026-07-12.md`
(869 lines, 5 areas, all high-confidence, adversarially verified). It informed
the engine (Wave 3+) and Kad (Wave 6) builds; still the background reading for
any wire work. This is the index.

## eD2k in one paragraph

A client holds ONE long-lived TCP connection to a server (an index, stores no
files). It logs in (OP_LOGINREQUEST -> OP_IDCHANGE assigns HighID = your public
IPv4 as a uint32, or LowID < 16,777,216 if the server's TCP connect-back +
HELLO fails). Then it repeatedly asks "who has this file hash" (OP_GETSOURCES ->
OP_FOUNDSOURCES) and "what matches these words" (OP_SEARCHREQUEST). Transfers
are peer-to-peer TCP: HELLO handshake -> request file -> enter the peer's upload
queue (OP_STARTUPLOADREQ, ranked by credits x wait x priority) -> get a slot
(OP_ACCEPTUPLOADREQ) -> request 3 blocks of 180 KiB at a time (OP_REQUESTPARTS)
-> receive OP_SENDINGPART/OP_COMPRESSEDPART -> write into the .part file, refill
the 3-in-flight window on each block completion. PARTSIZE 9,728,000 (MD4 unit),
EMBLOCKSIZE 184,320 (transfer unit). Credits (RSA-hardened secure ident) make it
reciprocal. AICH (SHA-1 tree, 180 KiB leaves) repairs corrupt blocks.

## Kad in one paragraph

Kad is a serverless index (Kademlia DHT, 128-bit IDs, XOR distance). It stores
tiny metadata: KEYWORD->file-hash, file-hash->SOURCE peer, file-hash->NOTES. One
primitive underlies everything: iteratively find the ~10 live nodes XOR-closest
to a target key (KADEMLIA2_REQ/RES), then PUBLISH (STORE) or SEARCH (fetch) at
them. Keyword key = MD4 of the first tokenized/lowercased word; source/notes key
= the file's ed2k hash. Firewalled nodes use a buddy relay (Kad's LowID
callback). UDP packets may be RC4-obfuscated. Transfers still use eD2k TCP once
sources are found.

## CRITICAL interop landmines (get these exactly right)

1. **Kad 128-bit ID wire encoding.** A raw 16-byte hash `b0..b15` goes on the
   wire byte-REVERSED within each 32-bit word, MSW first:
   `b3 b2 b1 b0 | b7 b6 b5 b4 | b11 b10 b9 b8 | b15 b14 b13 b12` (SetValueBE +
   four MSW-first LE dwords). Writing the raw hash targets the wrong node -
   every lookup/publish breaks.
2. **Kad tolerance zone = 2^120, NOT 2^104.** Close-enough iff
   `distance.Get32BitChunk(0) <= SEARCHTOLERANCE (0x1000000 = 2^24)`, with a
   `!IsLanIP` short-circuit. (The raw recon doc's "2^104" is wrong; it is
   corrected inline there and here.)
3. **Kad UDP crypt overhead = 16 bytes** (8 header + two 4-byte verify keys),
   payload starts at byte 16. [[protocol-reference]] already has this right.
4. **Server UDP send port = remote server_TCP + 4** (obfuscated stat ping +12).
   The "TCP+3" figure is only OUR local server-query socket bind, not where we
   send. See the fix in [[protocol-reference]].
5. **One canonical IP representation** (network order, first octet = low byte:
   `a | b<<8 | c<<16 | d<<24`). Swap only for display. For a HighID peer, trust
   the socket peer IP, not the packet's Hello ID. No internal "hybrid" field.
6. **Never advertise the VBT bit** (CT_EMULECOMPAT_OPTIONS bit 1) -> no peer
   sends ED2Kv2 -> do NOT implement the VarInt-tag path at all.

## Capability gating (from MISCOPTIONS1/2 tags), for the engine

- Compression: enable OP_COMPRESSEDPART iff `DataCompVer == 1`.
- UDP reask: gated by port/firewall/connection state, NOT by UDPVer; UDPVer only
  picks the reask payload format (>3 append part status, >2 append complete-src
  count).
- Extended requests: ExtReq >0 append part status, >1 append complete-src count.
- Source exchange: SX1 if `SourceExchange1Ver > 0`, prefer SX2 when its bit set.
- Secure ident: send v1 when `SupportSecIdent != 0`.
- Advertise the same values aMule does (AICH=1, Unicode=1, UDPver=4, DataComp=1,
  SecIdent=3 if crypto, SrcExch=3, ExtReq=2, Comment=1, MultiPacket=1).

## Ports + identity (confirmed)

TCP 4662; extended/Kad UDP 4672; our server-query UDP socket binds TCP+3; SEND
server UDP to remote server_TCP+4. Userhash = 16 random bytes with byte[5]=14,
byte[14]=111. HighID threshold 16,777,216.

## Kad parameters worth memorizing

K=10 (bin size), ALPHA_QUERY=5 in this tree (classic 3; wire-neutral, either
works), KADEMLIA_VERSION 0x08. REQ type byte = intent+count: FIND_NODE=11,
FIND_VALUE=2, STORE=4. Republish: sources 5h, keywords/notes 24h. Buddy target =
complement of our KadID. Bootstrap RES returns up to 20 spread contacts;
self-lookup within 3 min enables publishing.

## Related

- [[protocol-reference]] - byte-level tables + constants.
- [[decisions-and-lessons]]
- [[arch-upstream-amule]]
