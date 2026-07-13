# aMule 3.0.1 Upstream Reference (for the padMule Rust rewrite)

Generated 2026-07-12 from a 5-subsystem recon of amule-3.0.1/, each report
adversarially fact-checked against the C++ source. Corrections in each
subsystem's 'Verification corrections' block OVERRIDE the report text above
them. Exact constants (hex), field orders, byte sizes, formulas, and file:line
citations are the point of this document. See also the synthesized tail in the
task output (EC + open questions).



==============================================================================

## SUBSYSTEM: aMule 3.0.1 Kademlia (Kad2) protocol and engine

# aMule 3.0.1 KADEMLIA (Kad) - reimplementation reference

All paths below are relative to `/home/ajbufort/claude-projects/padMule/amule-3.0.1/src`. Byte order on the wire is LITTLE-ENDIAN for all multi-byte scalars (uint16/uint32/uint64) via `CFileDataIO::WriteUInt*`/`ReadUInt*` (SafeFile.cpp:271-292). 128-bit IDs have a special layout (see section 2). aMule 3.0.1 implements ONLY Kad2 opcodes for sending; it can parse but ignores legacy Kad1 opcodes. Local protocol/version constant `KADEMLIA_VERSION = 0x08` ("0.49b") is what we advertise (include/protocol/kad2/Constants.h:29).

WARNING - this repo is a modified aMule 3.0.1. Three engine parameters were changed from classic eMule/aMule and are flagged in "unclear": `ALPHA_QUERY=5` (classic Kad uses 3), `KADEMLIA_FIND_VALUE_MORE_REASKS=4` (new), and `SEARCH_ID_KAD_MASK=0x80000000` search-id allocation. These are LOCAL behavior only and do not change wire compatibility.

## 1. Component/file map
- Lifecycle/timers: kademlia/kademlia/Kademlia.cpp (CKademlia::Start/Stop/Process, keyword hash fn).
- UDP dispatch + all packet build/parse: kademlia/net/KademliaUDPListener.cpp (1716 lines; central switch at :237-368).
- Obfuscation/RC4: EncryptedDatagramSocket.cpp; RC4Encrypt.cpp; receive dispatch ClientUDPSocket.cpp:78-137; UDP send MuleUDPSocket.cpp:255-281.
- Routing: kademlia/routing/RoutingZone.cpp (tree/zones, nodes.dat), RoutingBin.cpp (bins, IP limits), Contact.cpp (contact type/expiry).
- Search: kademlia/kademlia/Search.cpp (state machine), SearchManager.cpp (registry/lifetimes).
- Index/store: kademlia/kademlia/Indexed.cpp, Entry.cpp/Entry.h.
- Prefs/self-ID/firewall flags: kademlia/kademlia/Prefs.cpp/Prefs.h.
- UDP firewall test: kademlia/kademlia/UDPFirewallTester.cpp.
- Flood/anti-spoof tracking: kademlia/net/PacketTracking.cpp.
- 128-bit int: kademlia/utils/UInt128.cpp/.h. UDP verify key holder: kademlia/utils/KadUDPKey.h.

## 2. CUInt128 (128-bit ID) representation and byte order (CRITICAL)
Internal storage: `union { uint32 u32_data[4]; uint64 u64_data[2]; }` little-endian whole number; u32_data[3] is most-significant chunk (UInt128.h:210-213).
- `Get32BitChunk(0)` = MOST significant 32 bits = u32_data[3]; chunk 3 = least significant (UInt128.h:109-120).
- `GetBitNumber(bit)`: bit 0 is MOST significant; `bit<=127 ? (u32_data[(127-bit)/32] >> ((127-bit)%32)) & 1 : 0` (UInt128.h:90-93).
- Wire serialization `WriteUInt128` writes 4 chunks via `Get32BitChunk(0..3)` each as a little-endian uint32 (SafeFile.cpp:298-304). Net effect: "four little-endian 32-bit ints stored in big-endian chunk order". `ReadUInt128` reverses (SafeFile.cpp:169-178).
- `SetValueBE(const uint8* be16)`: reads a 16-byte big-endian buffer into chunks: u32[3]=BE(be[0..3]), u32[2]=BE(be[4..7]), u32[1]=BE(be[8..11]), u32[0]=BE(be[12..15]) (UInt128.cpp:106-114). `ToByteArray` is the inverse (produces 16 bytes, chunk0 first as big-endian).
- `StoreCryptValue(buf16)`: writes u32[3],u32[2],u32[1],u32[0] each byte-swapped-on-BE (i.e. native/LE order) -> used as RC4 key material for obfuscation (UInt128.cpp:126-134).
- XOR distance = `a ^ b` chunk-wise (UInt128.h:148-153). Compare is unsigned, MSB-chunk first (UInt128.cpp:136-145). This XOR metric is THE Kademlia distance.
- MD4/MD5 hashes (ed2k file hash, keyword hash) are 16 raw bytes; converting a hash to a CUInt128 uses `SetValueBE(hash)` (treats hash bytes big-endian). Ex: Prefs.cpp:86 `m_clientHash.SetValueBE(userHash)`.

## 3. UDP framing (pre-encryption wire packet)
A Kad UDP datagram payload (after decryption) is: `[protocol 1][opcode 1][payload...]` (2-byte header only, NO 4-byte length used for UDP). Send builds `GetUDPHeader()` = {eDonkeyID=protocol, command=opcode} 2 bytes then data buffer (Packet.cpp:235-244; MuleUDPSocket.cpp:264-267). Receiver reads decrypted[0]=protocol, decrypted[1]=opcode, payload=decrypted+2 (ClientUDPSocket.cpp:87-88; KademliaUDPListener.cpp:229-231).

Protocol header bytes (include/protocol/Protocols.h:34-52):
- OP_KADEMLIAHEADER = 0xE4 (plain Kad).
- OP_KADEMLIAPACKEDPROT = 0xE5 (zlib-compressed Kad payload).
- OP_EDONKEYPROT/HEADER = 0xE3, OP_PACKEDPROT = 0xD4, OP_EMULEPROT = 0xC5, OP_UDPRESERVEDPROT1 = 0xA3, OP_UDPRESERVEDPROT2 = 0xB2, OP_ED2KV2HEADER=0xF4, OP_ED2KV2PACKEDPROT=0xF5, OP_MLDONKEYPROT=0x00.

Compression: in `SendPacket`, if built CPacket size > 200 bytes, call PackPacket() which zlib-`compress`es the payload (after the 2-byte header) and switches protocol byte E4 -> E5 (KademliaUDPListener.cpp:1609-1612; Packet.cpp:247-264). Receiver: protocol E5 -> zlib `uncompress` payload (bytes 2..end) into a new buffer, prepend {0xE4, opcode}, then process (ClientUDPSocket.cpp:106-124). Decompressed buffer sizing there = `packetLen*10 + 300`.

## 4. Obfuscation / encryption layer (RC4) - EncryptedDatagramSocket.cpp
Every Kad UDP packet may be wrapped in an obfuscation layer. Constants (EncryptedDatagramSocket.cpp:109-114):
- CRYPT_HEADER_WITHOUTPADDING = 8
- MAGICVALUE_UDP = 91 (0x5B)
- MAGICVALUE_UDP_SYNC_CLIENT = 0x395F2EC1
- (server variants: SYNC_SERVER=0x13EF24D5, SERVERCLIENT=0xA5, CLIENTSERVER=0x6B - ed2k-server only, not Kad).

Obfuscated Kad packet on the wire:
`[SemiRandomByte 1][randomKeyPart 2 (LE)][RC4( MAGICVALUE_UDP_SYNC_CLIENT (4, big-endian-swapped) )][RC4(padLen 1)][RC4(pad padLen)][RC4(receiverVerifyKey 4)][RC4(senderVerifyKey 4)][RC4(actual Kad packet incl 0xE4/E5 + opcode + payload)]`. padLen is currently always 0 (EncryptedDatagramSocket.cpp:271, 350-374). Overhead = 12 bytes for Kad (8 header + 2*4 verify keys), 8 for ed2k.

Marker bits in SemiRandomByte low 2 bits: bit0 (0x01) = ed2k(1)/kad(0) marker; bit1 (0x02) for kad = "receiver key used"(1) vs "nodeID key used"(0). These are HINTS only (old clients randomize). SemiRandomByte must not equal any protocol header byte (E3/E4/E5/D4/C5/A3/B2); a value is drawn up to 128 times (EncryptedDatagramSocket.cpp:312-348).

RC4 KEY DERIVATION (three possible keys; receiver tries in order suggested by marker, up to 3 tries) - EncryptedDatagramSocket.cpp:167-208:
- try 0 (kad, NodeID key): keyData[18] = `StoreCryptValue(ourKadID)` (16) || randomKeyPart (2 from bufIn+1). key = MD5(keyData). Used when a packet is encrypted TO us by our own NodeID.
- try 1 (ed2k): keyData[23] = userHash(16) || PokeUInt32@16=ip || [20]=MAGICVALUE_UDP(0x5B) || randomKeyPart@21 (2). key = MD5.
- try 2 (kad, ReceiverVerifyKey key): keyData[6] = PokeUInt32(CPrefs::GetUDPVerifyKey(ip)) (4) || randomKeyPart (2). key = MD5.
RC4 state: MD5 digest (16 bytes) is the RC4 key; RC4 is set up WITHOUT the usual 1024-byte discard for UDP (`SetKey(md5, true)` bSkipDiscard=true) (RC4Encrypt.cpp:104-141). Standard RC4 KSA/PRGA, key length 16 (RC4Encrypt.cpp:62-141).
Recognition: decrypt bytes 3..6 with candidate key; if it equals MAGICVALUE_UDP_SYNC_CLIENT (after ENDIAN_SWAP), it is an obfuscated packet; else pass through as plaintext. If first byte is one of E3/E4/E5/D4/C5/A3/B2 -> treated as NOT encrypted (plaintext), returned as-is (EncryptedDatagramSocket.cpp:140-150). So plaintext Kad packets start directly with 0xE4/0xE5.

VERIFY KEYS (anti-spoofing) - Prefs.cpp:234-239: `GetUDPVerifyKey(targetIP)` = let buf = (uint64)s_dwKadUDPKey<<32 | targetIP; md5=MD5(buf,8); return ((m[0..3]^m[4..7]^m[8..11]^m[12..15]) % 0xFFFFFFFE) + 1 (nonzero uint32). `s_dwKadUDPKey` is a persistent random uint32 secret stored in config key `/Obfuscation/CryptoKadUDPKey`, default GetRandomUint32(), never transmitted (Preferences.cpp:1377).
On SEND to targetIP (MuleUDPSocket.cpp:270 via KademliaUDPListener.cpp:1622): receiverVerifyKey field = `targetKey.GetKeyValue(myPublicIP)` (the sender key that contact previously gave us; 0 if unknown); senderVerifyKey field = `CPrefs::GetUDPVerifyKey(targetIP)` (OUR key for that IP, which we expect them to echo next time).
On RECEIVE from ip (ClientUDPSocket.cpp:100,117): `validReceiverKey = (CPrefs::GetUDPVerifyKey(ip) == receiverVerifyKey_extracted)` (proves the remote knew the key we handed them = proves they replied to our earlier packet); `senderKey = CKadUDPKey(senderVerifyKey_extracted, myPublicIP)` stored per-contact.
CKadUDPKey holds {uint32 m_key, uint32 m_ip}; `GetKeyValue(myIP)` returns m_key only if myIP==m_ip else 0 (KadUDPKey.h:44-49). Persisted in nodes.dat as key(4)+ip(4).
Port-53 rule: unencrypted incoming packets from source port 53 are dropped (KademliaUDPListener.cpp:216-219); contacts with udpPort==53 and version<=5 are rejected everywhere.

## 5. Kad2 opcodes (exact hex) - include/protocol/kad2/Client2Client/UDP.h:33-54
- KADEMLIA2_BOOTSTRAP_REQ = 0x01
- KADEMLIA2_BOOTSTRAP_RES = 0x09
- KADEMLIA2_HELLO_REQ = 0x11
- KADEMLIA2_HELLO_RES = 0x19
- KADEMLIA2_REQ = 0x21 (FIND node/value)
- KADEMLIA2_HELLO_RES_ACK = 0x22
- KADEMLIA2_RES = 0x29 (FIND response)
- KADEMLIA2_SEARCH_KEY_REQ = 0x33
- KADEMLIA2_SEARCH_SOURCE_REQ = 0x34
- KADEMLIA2_SEARCH_NOTES_REQ = 0x35
- KADEMLIA2_SEARCH_RES = 0x3B
- KADEMLIA2_PUBLISH_KEY_REQ = 0x43
- KADEMLIA2_PUBLISH_SOURCE_REQ = 0x44
- KADEMLIA2_PUBLISH_NOTES_REQ = 0x45
- KADEMLIA2_PUBLISH_RES = 0x4B
- KADEMLIA2_PUBLISH_RES_ACK = 0x4C
- KADEMLIA_FIREWALLED2_REQ = 0x53
- KADEMLIA2_PING = 0x60
- KADEMLIA2_PONG = 0x61
- KADEMLIA2_FIREWALLUDP = 0x62

Kad1 opcodes still USED by Kad2 (shared) - include/protocol/kad/Client2Client/UDP.h:29-59:
- KADEMLIA_FIREWALLED_REQ = 0x50, KADEMLIA_FINDBUDDY_REQ = 0x51, KADEMLIA_CALLBACK_REQ = 0x52, KADEMLIA_FIREWALLED_RES = 0x58, KADEMLIA_FIREWALLED_ACK_RES = 0x59, KADEMLIA_FINDBUDDY_RES = 0x5A. Also KADEMLIA_SEARCH_RES=0x38 and KADEMLIA_SEARCH_NOTES_RES=0x3A are parsed on receive (legacy). Kad1-only opcodes 0x00/0x08/0x10/0x18/0x20/0x28/0x30/0x32/0x40/0x42/0x48/0x4A are received but ignored (KademliaUDPListener.cpp:352-363).
ed2k-UDP opcode for Kad direct callback: OP_DIRECTCALLBACKREQ = 0x95 (payload <TCPPort 2><Userhash 16><ConnectOptions 1>) handled in ClientUDPSocket.cpp:285.

Request "type" byte (in KADEMLIA2_REQ) also encodes requested contact count (include/protocol/kad/Constants.h:52-55): KADEMLIA_FIND_VALUE=0x02, KADEMLIA_STORE=0x04, KADEMLIA_FIND_NODE=0x0B (=11), KADEMLIA_FIND_VALUE_MORE=KADEMLIA_FIND_NODE(0x0B).

## 6. Packet payload layouts (payload = bytes AFTER the [protocol][opcode] 2-byte header)

BOOTSTRAP_REQ (0x01): empty payload. Sent with cryptTargetID only if remote kadVersion>=6 (KademliaUDPListener.cpp:99-110).

BOOTSTRAP_RES (0x09) (KademliaUDPListener.cpp:450-480 build; :484-516 parse):
`ClientID(16 UInt128) | UDPport(2) | version(1) | numContacts(2) | numContacts * { ClientID(16) | IP(4) | UDPport(2) | TCPport(2) | version(1) }`. Contact block = 25 bytes. Max 20 contacts returned. Note IP written via WriteUInt32 of contact->GetIPAddress() which is stored host-order-swapped; see IP note in section 8.

HELLO_REQ (0x11) / HELLO_RES (0x19): built by SendMyDetails (KademliaUDPListener.cpp:113-159):
`KadID(16) | TCPport(2) | version(1=KADEMLIA_VERSION=0x08) | tagCount(1) | tags...`. Tags optionally present:
 - TAG_SOURCEUPORT (0xFC) varint = internal Kad UDP port, only if NOT using extern kad port.
 - TAG_KADMISCOPTIONS (0xF2) uint8, only if version>=8 and (requestAck or we are firewalled): bits: bit0=UDP firewalled, bit1=TCP firewalled, bit2=requesting HELLO_RES_ACK (KademliaUDPListener.cpp:139-143).
Parsed by AddContact2 (KademliaUDPListener.cpp:372-446): reads KadID, tport, version (0 invalid -> throw), tagCount, then tags. SOURCEUPORT overrides source udp port; KADMISCOPTIONS sets udpFirewalled/tcpFirewalled/requestsAck(only if version>=8). UDP-firewalled contacts are NOT added to routing table.
HELLO handshake (KademliaUDPListener.cpp:518-637): on HELLO_REQ, reply HELLO_RES; request an ACK (3-way handshake) if contact was added/updated AND not already validReceiverKey. If contact ver==7 and unverified, also send a KADEMLIA2_PING challenge; if ver<7 and unverified, send a legacy challenge (a KADEMLIA2_REQ with random target). If we still need our extern port and ver>5, send PING.

HELLO_RES_ACK (0x22) (KademliaUDPListener.cpp:614-618 build; :573-592 parse): `KadID(16) | tagCount(1, =0)`. Requires validReceiverKey; verifies contact IP via RoutingZone::VerifyContact. Min size 17.

KADEMLIA2_REQ (0x21) (Search.cpp:1096-1137 build; KademliaUDPListener.cpp:641-684 parse):
`type(1) | target(16 UInt128) | receiverKadID(16 UInt128)`. Parser masks `type &= 0x1F`; if target's receiverKadID != our KadID, silently drop (identity check). Else compute closest `min(count=type, available)` contacts with maxType<=2 and IP-verified, respond KADEMLIA2_RES. Contact count requested equals `type` value (2, 4, or 11).

KADEMLIA2_RES (0x29) (KademliaUDPListener.cpp:686-769):
`target(16) | numContacts(1) | numContacts * { ClientID(16) | IP(4) | UDPport(2) | TCPport(2) | version(1) }` (25-byte contact). Expected exact size 17 + 25*numContacts. Contacts with version<=1 (Kad1) ignored; DNS/filtered IPs skipped. If it matches an outstanding legacy challenge target, it verifies the contact instead. Results handed to CSearchManager::ProcessResponse.

SEARCH_KEY_REQ (0x33) (KademliaUDPListener.cpp:934-952 parse; Search.cpp:503-540 build):
`target(16, keyword hash) | startPosition(2)`; if `startPosition & 0x8000`, the rest is a search-expression tree (restrictive filter). Real start offset = `startPosition & 0x7FFF`.

SEARCH_SOURCE_REQ (0x34) (KademliaUDPListener.cpp:954-963; Search.cpp:470-499):
`target(16, file hash) | startPosition(2, &0x7FFF) | fileSize(8 uint64)`.

SEARCH_NOTES_REQ (0x35) (KademliaUDPListener.cpp:1271-1279; Search.cpp:541-573):
`target(16, file hash) | fileSize(8 uint64)`.

SEARCH_RES (0x3B) (Indexed.cpp:734-908 build; KademliaUDPListener.cpp:1001-1011 + ProcessSearchResponse:965-987 parse):
`senderKadID(16) | target(16, keyID) | count(2) | count * { answerID(16 UInt128) | tagCount(1) | tags... }`. Results are split into packets of at most 50 entries each (header re-sent each packet: KadID+keyID+count). Keyword responses cap 300 results, notes cap 150.

PUBLISH_KEY_REQ (0x43) (KademliaUDPListener.cpp:1013-1109; Search.cpp:663-722 build):
`keyID(16, keyword hash) | count(2) | count * { sourceID(16, file ed2k hash) | tagCount(1) | tags... }`. Receiver drops if UDP-firewalled, and drops if `distance.Get32BitChunk(0) > SEARCHTOLERANCE` and not LAN (tolerance zone check). Recognized tags: TAG_FILENAME(0x01), TAG_FILESIZE(0x02). Others stored as-is. Answers PUBLISH_RES.

PUBLISH_SOURCE_REQ (0x44) (KademliaUDPListener.cpp:1111-1226; Search.cpp:574-662 build):
`keyID(16, file hash) | sourceID(16, publisher's clientHash) | tagCount(1) | tags...`. Same firewall + tolerance-zone drop. Recognized source tags: TAG_SOURCETYPE(0xFF), TAG_FILESIZE(0x02), TAG_SOURCEPORT(0xFD TCP), TAG_SOURCEUPORT(0xFC UDP). A TAG_SOURCEIP(0xFE) is added server-side = sender IP. Requires a SOURCETYPE tag to index. Answers PUBLISH_RES.

PUBLISH_NOTES_REQ (0x45) (KademliaUDPListener.cpp:1294-1361; Search.cpp:723-770 build):
`keyID(16, file hash) | sourceID(16, publisher KadID) | tagCount(1) | tags{TAG_FILENAME, TAG_FILERATING(0xF7), TAG_DESCRIPTION(0x0B), TAG_FILESIZE}`. Same firewall+tolerance drop.

PUBLISH_RES (0x4B) (KademliaUDPListener.cpp:1104-1108 build; :1249-1269 parse):
`keyID(16) | load(1, 0-100)`. Optionally followed by `options(1)` where bit0=requestAck; if set and senderKey present, reply PUBLISH_RES_ACK.

PUBLISH_RES_ACK (0x4C): empty payload.

FIREWALLED_REQ (0x50) (KademliaUDPListener.cpp:172-177 build; :1365-1384 parse): `TCPport(2)`. Exact size 2. Server does a TCP connect-back test then replies FIREWALLED_RES.
FIREWALLED2_REQ (0x53) (KademliaUDPListener.cpp:162-171 build; :1388-1409 parse): `TCPport(2) | userID(16 UInt128) | connectOptions(1)`. Min size 19. Used for kadVersion>=7 (obfuscation-aware).
FIREWALLED_RES (0x58) (KademliaUDPListener.cpp:1380-1383 build; :1413-1431 parse): `IP(4, the requester's observed public IP)`. Exact size 4. Increments our verified-open counter, sets our external IP.
FIREWALLED_ACK_RES (0x59): empty; increments m_firewalled open-count (deprecated for ver>=7).

FINDBUDDY_REQ (0x51) (Search.cpp:771-799 build; KademliaUDPListener.cpp:1448-1482 parse): `buddyID(16) | userID(16, requester clientHash) | TCPport(2)`. Min size 34. Reply FINDBUDDY_RES only if we are open+verified and have no buddy.
FINDBUDDY_RES (0x5A): `buddyID(16) | userID(16, our clientHash) | TCPport(2) [| connectOptions(1) if senderKey/ver7]`. Requester checks `buddyID ^ CUInt128(true) == ourKadID` (KademliaUDPListener.cpp:1493-1495).
CALLBACK_REQ (0x52) (Search.cpp:800-831 build; KademliaUDPListener.cpp:1512-1540 parse): `buddyID(16) | fileID(16) | TCPport(2)`. Min 34. Forwarded to buddy over TCP as OP_CALLBACK.

PING (0x60): empty payload. PONG (0x61) reply carries `UDPport(2)` = the source port we saw (used to discover our external UDP port) (KademliaUDPListener.cpp:1543-1583). Min size 2. PING also doubles as a legacy verification challenge.

FIREWALLUDP (0x62) (KademliaUDPListener.cpp:1586-1604): `errorCode(1) | incomingPort(2)`. Min size 3. errorCode 0 + expected port => UDP open.

## 7. Tag wire format and tag constants
Kad tag lists: `count(1 uint8)` then `count` tags (SafeFile.cpp:573-583 WriteTagPtrList / :500-510 ReadTagPtrList). Each Kad tag (SafeFile.cpp:513-570 WriteTag / :408-497 ReadTag):
`type(1 uint8) | nameLen(2 uint16) | name(nameLen bytes) | value`. Kad always uses the 2-byte-length string name form (single-byte name char, e.g. 0xFC), NOT the 0x80 compact-name form. Value encoding by type:
- TAGTYPE_HASH16=0x01: 16 raw bytes.
- TAGTYPE_STRING=0x02: `len(2 uint16) | UTF8 bytes` (written UTF8/utf8strRaw; no BOM).
- TAGTYPE_UINT32=0x03: 4 bytes LE.
- TAGTYPE_FLOAT32=0x04: 4 bytes.
- TAGTYPE_UINT16=0x08: 2 bytes LE (on read promoted to UINT32 internally).
- TAGTYPE_UINT8=0x09: 1 byte (read promoted to UINT32).
- TAGTYPE_BSOB=0x0A: `size(1) | size bytes` (used for legacy 8-byte uint64 filesize).
- TAGTYPE_UINT64=0x0B: 8 bytes LE.
- TAGTYPE_BLOB=0x07: `size(4 uint32) | bytes`.
- TAGTYPE_STR1..STR16 = 0x11..0x20: inline fixed-length string, len=type-0x11+1 (read only). Values TagTypes.h:30-43.
CTagVarInt picks smallest of UINT8/16/32/64 by magnitude (Tag.h:169-185). So e.g. a port <256 is sent as UINT8. Consumers must accept any int width for a given name.

Kad tag NAME bytes (single-char) - Tag.h:81-124:
0x01 TAG_FILENAME(string), 0x02 TAG_FILESIZE(uint), 0x3A TAG_FILESIZE_HI, 0x03 TAG_FILETYPE(string), 0x04 TAG_FILEFORMAT(string), 0x0B TAG_DESCRIPTION(string), 0x15 TAG_SOURCES(uint32), 0x33 TAG_PUBLISHINFO(uint32), 0xD0 TAG_MEDIA_ARTIST, 0xD1 TAG_MEDIA_ALBUM, 0xD2 TAG_MEDIA_TITLE, 0xD3 TAG_MEDIA_LENGTH(uint32), 0xD4 TAG_MEDIA_BITRATE(uint32), 0xD5 TAG_MEDIA_CODEC, 0xF2 TAG_KADMISCOPTIONS(uint8), 0xF3 TAG_ENCRYPTION(uint8), 0xF7 TAG_FILERATING(uint8), 0xF8 TAG_BUDDYHASH(string), 0xFA TAG_SERVERPORT(uint16), 0xFB TAG_SERVERIP(uint32), 0xFC TAG_SOURCEUPORT(uint16), 0xFD TAG_SOURCEPORT(uint16), 0xFE TAG_SOURCEIP(uint32), 0xFF TAG_SOURCETYPE(uint8).
TAG_PUBLISHINFO encodes: (val>>24)&0xFF differentNames, (val>>16)&0xFF publishersKnown, val&0xFFFF trustValue*100 (Search.cpp:1050-1054).
Source TAG_SOURCETYPE values (Search.cpp:595-649): 1=HighID, 3=Firewalled(buddy), 4=HighID >4GB, 5=Firewalled >4GB, 6=Firewalled+direct-UDP-callback. Type 2 not used.

## 8. Routing table
Constants (kademlia/kademlia/Defines.h): K=10 (bucket/bin size), KBASE=4, KK=5, LOG_BASE_EXPONENT=5, SEARCHTOLERANCE=16777216 (=0x1000000). Contact IP note: contacts store IP already byte-swapped once (host order); many functions apply `wxUINT32_SWAP_ALWAYS` when comparing/filtering. On the wire (BOOTSTRAP_RES/RES) IP is written with WriteUInt32 of the stored (swapped) value; a fresh reimplementation should keep IPs consistently in one representation and swap only when calling IsGoodIPPort/ipfilter as aMule does.

Tree/zone structure (RoutingZone.cpp/.h): binary tree; internal node has 2 subzones and bin=NULL; leaf has bin != NULL. Root = level 0, zoneIndex 0. Self KadID is treated as 000..0 center. Contact placed by `distance.GetBitNumber(level)` at each internal node (RoutingZone.cpp:436).
Split rule `CanSplit()` (RoutingZone.cpp:391-400): allowed if `level < 127` AND `(zoneIndex < KK(5) OR level < KBASE(4))` AND `bin size == K(10)`. When a leaf's bin is full and CanSplit, Split() creates 2 subzones and redistributes by bit at `level` (RoutingZone.cpp:607-625). GenSubZone index = (parentIndex<<1)+side (RoutingZone.cpp:678-686).
Consolidate (merge) (RoutingZone.cpp:627-676): recursively; if both children are leaves and total contacts < K/2 (=5), merge back into one bin. Runs every 45 min (Kademlia.cpp:267-273).

Bins (RoutingBin.cpp): a leaf's bin holds up to K=10 contacts in a list (front=oldest). AddContact rejects duplicate ClientID; rejects if >=2 contacts already share the /24 subnet in this bin (except LAN); enforces GLOBAL limits MAX_CONTACTS_IP=1 (one contact per exact IP across whole table) and MAX_CONTACTS_SUBNET=10 (per /24 globally, except LAN) via static tracking maps (RoutingBin.cpp:51-101, :366-389). Only added if size < K.
Contact ordering / liveness: SetAlive/PushToBottom moves a refreshed contact to list end (RoutingBin.cpp:103-131,326-332). GetOldest = front.

Contact type/expiry (Contact.cpp) - "type" is a staleness rank 0(best)..4(dead):
- New contact starts type=3, created=now, expires=0 (Contact.cpp:54-72).
- UpdateType() by age since created: <1h -> type2 expire now+1h; 1..2h -> type1 expire now+90min; >=2h -> type0 expire now+2h (Contact.cpp:94-111).
- CheckingType(): if last-type-set >=10s and type!=4, bump type++ and set expire now+2min (Contact.cpp:80-92). Used when we send a HELLO to probe.
Small timer (per zone, every 60s) OnSmallTimer (RoutingZone.cpp:756-817): remove type==4 contacts whose expire elapsed and not InUse; pick oldest, if its expire in future or type4 push to bottom, else CheckingType() and send a HELLO_REQ (ver>=6 obfuscated with UDPKey; ver 2-5 plaintext) to re-verify.
Big timer (per zone) OnBigTimer (RoutingZone.cpp:700-708): if leaf and (zoneIndex<KK or level<KBASE or bin free slots >= K*0.8) do a RandomLookup (FindNode on random ID in this zone's prefix) to fill table. Root big timer cadence in Kademlia.cpp:238-252.

IP-verification / anti-spoof (verified flag): a contact's m_ipVerified must be true before it is returned by GetClosestTo (RoutingBin.cpp:195). Verification set by VerifyContact(id, ip) which requires matching id AND ip (RoutingZone.cpp:870-885). Verification happens via HELLO_RES_ACK (ver>=8 style), a PING challenge (ver7), or a legacy KADEMLIA2_REQ random-target challenge (ver<7). On update, a contact with a stored non-zero UDPKey must present the same key or the update is denied (anti-hijack) (RoutingZone.cpp:442-500). Legacy kad2 contacts (ver 1..5) that already sent a HELLO may only refresh their timer, not change IP/port/version.
GetClosestTo (RoutingZone.cpp:550-566): descend into the subzone whose bit matches distance at level; if fewer than maxRequired found, also descend the sibling. In bin: collect contacts with type<=maxType AND IsIPVerified, keyed by (clientID ^ target) distance, trimmed to maxRequired closest (RoutingBin.cpp:180-214).

## 9. Self-ID, Prefs, and on-disk formats
Self KadID: random 128-bit via GetRandomUint128 at first run, persisted (Prefs.cpp:75, :118-119). clientHash = ed2k user hash converted SetValueBE (Prefs.cpp:86). Note KadID and ed2k userhash are distinct.
preferencesKad.dat (Prefs.cpp:107-141): `myIP(4 uint32) | unused(2 uint16=0) | KadID(16 UInt128) | tagsByte(1 uint8=0)`. Read tolerates KadID==0 (regenerates). Written on shutdown.

nodes.dat (RoutingZone.cpp:135-340). Reader logic:
- Read uint32 numContacts. If nonzero => legacy version 0 file: REJECTED (unsupported).
- If first uint32 == 0: read uint32 fileVersion.
  - If fileVersion==3: read uint32 bootstrapEdition; if ==1 => special bootstrap-only file, parse via ReadBootstrapNodesDat (contacts NOT added to table; up to 50 closest kept in s_bootstrapList).
  - If fileVersion in 1..3: read uint32 numContacts.
- Each contact record (25 bytes core + optional): `ClientID(16) | IP(4) | UDPport(2) | TCPport(2) | version(1)`; if fileVersion>=2 also `UDPKey.m_key(4) | UDPKey.m_ip(4) | verified(1 uint8)`. Contacts with version<=1 (Kad1) ignored. Records validated with IsGoodIPPort + ipfilter + not (port53 && ver<=5).
- If no verified contacts found, all read contacts are marked verified (speeds bootstrap of old files).
Writer (RoutingZone.cpp:291-340): writes `0(4) | version=2(4) | numContacts(4)` then per contact `ClientID(16)|IP(4)|UDPport(2)|TCPport(2)|version(1)|UDPKey.key(4)|UDPKey.ip(4)|verified(1)`. Contacts chosen via GetBootstrapContacts(200), capped at CONTACT_FILE_LIMIT=500; not written if fewer than 25 contacts.
GetBootstrapContacts (RoutingZone.cpp:848-868): returns TopDepth(LOG_BASE_EXPONENT=5) contacts, i.e. contacts from the top 2^5 buckets, up to maxRequired.

## 10. Search state machine (Search.cpp / SearchManager.cpp)
Search types enum (Search.h:99-112): NODE, NODECOMPLETE, FILE, KEYWORD, NOTES, STOREFILE, STOREKEYWORD, STORENOTES, FINDBUDDY, FINDSOURCE, NODESPECIAL, NODEFWCHECKUDP.
Parallelism: ALPHA_QUERY=5 (Defines.h:57; classic Kad=3 - flagged). Go() (Search.cpp:154-185): seed m_possible with the 50 closest verified contacts (GetClosestTo maxType=3), then fire the top `count` initial FIND requests where count = 1 for NODE else min(ALPHA_QUERY, possible.size()).
Per-type requested contact count GetRequestContactCount (Search.cpp:1319-1343): NODE/NODECOMPLETE/NODESPECIAL/NODEFWCHECKUDP -> KADEMLIA_FIND_NODE(11); FILE/KEYWORD/FINDSOURCE/NOTES -> KADEMLIA_FIND_VALUE(2); FINDBUDDY/STOREFILE/STOREKEYWORD/STORENOTES -> KADEMLIA_STORE(4).
SendFindValue (Search.cpp:1096-1137): builds KADEMLIA2_REQ `type(1)=contactCount | target(16) | contact.clientID(16)`; sends obfuscated if contact ver>=6 (with contact.UDPKey + clientID), else plaintext. reaskMore=true bumps count to KADEMLIA_FIND_VALUE_MORE(11).
ProcessResponse (Search.cpp:307-448): dedup results by IP (reject multiple KadIDs sharing one IP), reject >2 per /24 subnet, ignore already-known/tried distances. For each result closer to target than the responder, add to m_best (cap ALPHA_QUERY) and immediately SendFindValue. Rejects responses containing more contacts than requested (anti-abuse), except when the peer was reasked with the wider variant.
JumpStart (Search.cpp:238-305), fired every SEARCH_JUMPSTART=1 second globally (Kademlia.cpp:261-264): skip if a response arrived within last 3s; if m_possible empty -> PrepareToStop; if the best KADEMLIA_FIND_VALUE(2) tried nodes are all dead and >=3*2 tried, reask closest responded node for MORE (11); otherwise send the next closest untried contact, or StorePacket() to an already-responded node.
StorePacket (Search.cpp:450-852): the type-specific action against the closest responded contact; guarded by tolerance: skip if `fromDistance.Get32BitChunk(0) > SEARCHTOLERANCE(16777216)` and not LAN. Updates m_closestDistantFound for user-count stats.
Tolerance zone: SEARCHTOLERANCE=16777216 = top 24 bits of distance must be 0 (distance < 2^104) for a node to be considered "close enough" to store to / to accept a publish (Search.cpp:464; KademliaUDPListener.cpp:1032,1130,1310).
Result processing (Search.cpp:854-1094): FILE -> ProcessResultFile (reads source tags, hands to downloadqueue); KEYWORD -> ProcessResultKeyword (name/size mandatory, media tags optional); NOTES -> ProcessResultNotes.

Lifetimes and totals (Defines.h:67-88, all seconds unless noted; SearchManager.cpp:281-425 uses them):
- HELLO_TIMEOUT 20; SEARCH_JUMPSTART 1; SEARCH_LIFETIME 45.
- FILE/KEYWORD/NOTES/NODE lifetimes = 45; NODECOMP_LIFETIME 10.
- STOREFILE/STOREKEYWORD lifetime 140; STORENOTES 100; FINDBUDDY 100; FINDSOURCE 45.
- Answer caps (PrepareToStop when GetAnswers exceeds): SEARCHFILE_TOTAL 300, SEARCHKEYWORD_TOTAL 300, SEARCHNOTES_TOTAL 50, SEARCHSTOREFILE_TOTAL 10, SEARCHSTOREKEYWORD_TOTAL 10, SEARCHSTORENOTES_TOTAL 10, SEARCHNODECOMP_TOTAL 10, SEARCHFINDBUDDY_TOTAL 10, SEARCHFINDSOURCE_TOTAL 20.
- Searches also stop 20s before lifetime (SEC(20)) via PrepareToStop; PrepareToStop leaves a 15s drain window (Search.cpp:234).
Search registry keyed by target hash; AlreadySearchingFor prevents duplicates. searchID allocation: `++m_nextID | 0x80000000` (SearchManager.cpp:62-63,173) - top bit marks Kad-allocated IDs (repo-specific).

## 11. Keyword hashing and key derivation (CRITICAL for interop)
Keyword hash (Kademlia.cpp:500-515 KadGetKeywordHash): take the search string, tokenize, use FIRST word; convert to UTF-8, MD4 digest (CryptoPP Weak::MD4) of the raw UTF-8 bytes; result 16 bytes -> `pKadID->SetValueBE(Output)`. The keyword is NOT lowercased in KadGetKeywordHash itself, BUT PrepareFindKeywords lowercases words first via GetWords (SearchManager.cpp:259-279 MakeLower). Word tokenizing uses invalid chars `" ()[]{}<>,._-!?:;\/\""` (SearchManager.h:101). Words shorter than 3 UTF-8 bytes are dropped (SearchManager.cpp:271). So: keyword search target = MD4(lowercased-UTF8-first-valid-word). Additional words become the restrictive search-expression tree filter (m_searchTermsData).
File source lookup key = the file's ED2K MD4 hash (16 bytes) interpreted as CUInt128 via SetValueBE; searches/publishes use this as target (Search.cpp:476-478 etc). Publishing a source: keyID=fileHash, sourceID=our clientHash (ed2k userhash as CUInt128) (Search.cpp:592, KademliaUDPListener SendPublishSourcePacket:187-211).
Publishing a keyword: keyID=keyword MD4 hash, each entry sourceID=file ED2K hash + tags(name,size,type,sources,media) (Search.cpp:663-722, PreparePacketForTags:1242-1310).
Notes: keyID=file ED2K hash, sourceID=our KadID.

Search-expression tree wire format (parser CreateSearchExpressionTree, KademliaUDPListener.cpp:780-930; max depth 24):
- op 0x00 = boolean node: next byte boolop 0x00=AND, 0x01=OR, 0x02=NOT, then two child subtrees.
- op 0x01 = String term: `string(2-byte-len UTF8)` (lowercased, then tokenized by invalid chars).
- op 0x02 = Meta tag: `value(2-byte-len string) | tagName(2-byte-len string)`.
- op 0x03 = 32-bit numeric relation: `value(4 uint32) | mmop(1) | tagName(2-byte-len string)`.
- op 0x08 = 64-bit numeric relation: `value(8 uint64) | mmop(1) | tagName(string)`. mmop: 0=EQ,1=GT,2=LT,3=GE,4=LE,5=NE.
NOTE: the ENCODER for this tree lives outside kademlia/ (SearchList/GetSearchPacket); only the decoder is in these files. Flagged.

## 12. Publish / Index (Indexed.cpp)
Store/index limits (include/protocol/kad/Constants.h:33-48):
- KADEMLIAMAXINDEX 50000 (keyword indexes), KADEMLIAMAXENTRIES 60000 (keyword entries), KADEMLIAMAXSOURCEPERFILE 1000, KADEMLIAMAXNOTESPERFILE 150.
- Republish/lifetime: KADEMLIAREPUBLISHTIMES = 5h (sources), KADEMLIAREPUBLISHTIMEK = KADEMLIAREPUBLISHTIMEN = 24h (keywords/notes). Publisher republish counts: KADEMLIATOTALSTOREKEY 2, KADEMLIATOTALSTORESRC 3, KADEMLIATOTALSTORENOTES 1. KADEMLIAPUBLISHTIME 2s, KADEMLIAREASKTIME 1h, KADEMLIATOTALFILE 5, KADEMLIAFIREWALLCHECKS 4.
Stored entry (CEntry, Entry.h:56-104): {IP, TCPport, UDPport, keyID, sourceID, size, lifetime, bSource, taglist}. CKeyEntry adds publish-tracking (per-IP publish counts, trust value) for keyword spam mitigation (Entry.h:106-142). load byte in PUBLISH_RES is `size*100/max` (0-100), 100 when full.
Index files (Indexed.cpp): src_index.dat (version 2), key_index.dat (version 3, includes publish tracking + own KadID guard), load_index.dat (version 1). Each: `version(4) | savetime(4) [| KadID(16) for key] | numKeys(4) | {keyID(16) | numSources(4) | {sourceID(16) | numEntries(4) | {lifetime(4) [| publishTrackingData for key v>=3] | tagList}}}`. Written on shutdown; only loaded if savetime>now.
SendValidKeywordResult (Indexed.cpp:734-813): two passes (trusted trustValue>=1 first), applies optional search-term filter, honors startPosition offset, caps 300, batches 50 per SEARCH_RES packet. Sources/notes analogous (:815-908), notes cap 150.

## 13. Firewall testing and buddy/callback (LowID)
TCP firewall: on HELLO exchange, if we are rechecking IP, send FIREWALLED2_REQ (ver>6) or FIREWALLED_REQ; peer does TCP connect-back and replies FIREWALLED_RES with our observed IP, and (legacy) FIREWALLED_ACK_RES increments open-count. We consider ourselves open once >=2 peers confirm (`m_firewalled >= 2` -> not firewalled; Prefs.cpp:161-189, GetRecheckIP uses KADEMLIAFIREWALLCHECKS=4). External IP updated in ProcessFirewalledResponse.
UDP firewall test (UDPFirewallTester.cpp): UDP_FIREWALLTEST_CLIENTSTOASK=2. Start a NODEFWCHECKUDP random-node search to collect fresh untested IPs (AddPossibleTestContact from RES results when a fw-check search is active, KademliaUDPListener.cpp:734-740). For each candidate (ver>6, unknown IP not previously UDP-contacted) ask clientlist->DoRequestFirewallCheckUDP; the remote sends a KADEMLIA2_FIREWALLUDP to our expected incoming port. One success => open (m_firewalledUDP=false, verified). If both tests fail => firewalled. 6-minute timeout forces firewalled (MIN2MS(6)). Incoming-port disambiguation prefers internal (forwarded) port over external NAT port. External Kad port discovery via PING/PONG: PONG reports the source port the remote saw; needs 2-of-3 matching results from different IPs (Prefs.cpp:280-319, EXTERNAL_PORT_ASKIPS=3).
Buddy system (for our own LowID): every ~20min if firewalled, SetFindBuddy triggers a FINDBUDDY search (target = CUInt128(true) ^ ourKadID, i.e. bitwise complement of KadID). We send FINDBUDDY_REQ; an open peer becomes our buddy and relays CALLBACK_REQ to us over TCP (as OP_CALLBACK) so remote peers can reach us. When publishing sources while firewalled with a buddy, we advertise SOURCETYPE 3/5 plus TAG_SERVERIP/TAG_SERVERPORT (buddy) and TAG_BUDDYHASH = complement-of-KadID (Search.cpp:617-633). If UDP-open+verified we instead advertise SOURCETYPE 6 (direct UDP callback) and skip the buddy. Direct callback uses ed2k-UDP OP_DIRECTCALLBACKREQ 0x95.
Connect options byte (Prefs.cpp:217-232 GetMyConnectOptions): bit3(0x08)=DirectCallback (only if open-UDP+verified+firewalled-TCP), bit2(0x04)=CryptLayerRequired, bit1(0x02)=CryptLayerRequested, bit0(0x01)=CryptLayerSupported.

## 14. Anti-flood / anti-spoof packet tracking (PacketTracking.cpp)
Outgoing-request tracking: only request opcodes are tracked (IsTrackedOutListRequestPacket: BOOTSTRAP_REQ, HELLO_REQ, HELLO_RES, REQ, SEARCH_NOTES_REQ(both), PUBLISH_*_REQ, FINDBUDDY_REQ, CALLBACK_REQ, PING). Kept 180s. Response opcodes are only accepted if a matching request to that IP is on the list (CHECK_TRACKED_PACKET macro, KademliaUDPListener.cpp:81-83); otherwise the response is dropped.
Incoming-request rate limits per IP per minute (PacketTracking.cpp:121-167): BOOTSTRAP_REQ 2, HELLO_REQ 3, REQ 10, SEARCH_(KEY/SOURCE/NOTES)_REQ 3 each, PUBLISH_KEY_REQ 3, PUBLISH_SOURCE_REQ 2, PUBLISH_NOTES_REQ 2, FIREWALLED(2)_REQ 2, FINDBUDDY_REQ 2, CALLBACK_REQ 1, PING 2. Over limit => drop; over 5x limit => ban IP. Cleanup every 12 min. No flood check for LAN IPs in LAN mode.
Legacy challenge (verify pre-ver7 contacts): send a KADEMLIA2_REQ with a random target (challenge) and the contact's ID; store {ip, opcode, contactID, challenge} 180s. When a KADEMLIA2_RES/PONG arrives matching, VerifyContact the ID (PacketTracking.cpp:259-308; KademliaUDPListener.cpp:1655-1691). KADEMLIA2_PING is used as a zero-challenge verifier for ver7.

## 15. Bootstrap process (Kademlia.cpp:284-292; KademliaUDPListener.cpp:99-110,484-516)
If not connected and s_bootstrapList non-empty: every >15s (or >=2s if table empty) pop the closest bootstrap contact and send BOOTSTRAP_REQ. The BOOTSTRAP_RES adds the responder plus its (up to 20) returned contacts to the routing table; if table was empty, all are assumed verified (fast start). Normal operation also learns contacts from every RES/HELLO. Self-lookup FindNode(ourKadID, complete) forced within 3 min of start and every 4h; when a NODECOMPLETE search finishes, publishing is enabled (SetPublish true).
Periodic timers (Kademlia.cpp:96-297): status update 60s; firewall recheck 1h; self-lookup 4h; find-buddy every 20min; consolidate zones every 45min; jumpstart searches 1s; extern-port request every 15s while UDP fw-check running; disconnect if no contact for KADEMLIADISCONNECTDELAY=20min.
LAN mode (Kademlia.cpp:463-494): if routing table <=256 nodes and all are LAN IPs (and FilterLanIPs off), enter LAN mode (skips firewall checks, extern-port, flood checks).

## 16. Version gating summary (contact->GetVersion() = advertised KADEMLIA_VERSION)
We advertise 0x08. Behavior gates seen: >=2 required to be added at all (Kad1 dropped); >=3 uses Kad2 SEARCH_KEY/SOURCE/NOTES (else legacy); >=6 => obfuscation supported (send with NodeID crypt key + UDPKey); >=7 => FIREWALLED2 + sender/receiver key verification + FINDBUDDY_RES connectOptions; >=8 => HELLO_RES_ACK 3-way handshake + KADMISCOPTIONS firewall-stats tag + UDP firewall test participation. A version 0 in a contact record is invalid (throw).



### Key constants (as reported)

- K = 10 (Defines.h:47) routing bin/bucket size
- ALPHA_QUERY = 5 (Defines.h:57) parallel lookups; classic Kad=3
- KBASE = 4, KK = 5, LOG_BASE_EXPONENT = 5 (Defines.h:48,49,66)
- SEARCHTOLERANCE = 16777216 = 0x1000000 (Defines.h:46) tolerance zone: distance top 24 bits must be 0
- KADEMLIA_VERSION = 0x08 (include/protocol/kad2/Constants.h:29) advertised version 0.49b
- OP_KADEMLIAHEADER = 0xE4, OP_KADEMLIAPACKEDPROT = 0xE5 (Protocols.h:44-45)
- KADEMLIA2_REQ = 0x21, KADEMLIA2_RES = 0x29 (kad2 UDP.h)
- KADEMLIA_FIND_VALUE=0x02, KADEMLIA_STORE=0x04, KADEMLIA_FIND_NODE=0x0B (kad/Constants.h:52-54) - also the requested-contact-count byte
- CRYPT_HEADER_WITHOUTPADDING = 8; MAGICVALUE_UDP = 91/0x5B; MAGICVALUE_UDP_SYNC_CLIENT = 0x395F2EC1 (EncryptedDatagramSocket.cpp:109-112)
- RC4 key = MD5(keyData) 16 bytes, SetKey bSkipDiscard=true (no 1024-byte discard) (RC4Encrypt.cpp:104-141)
- GetUDPVerifyKey: MD5((uint64)s_dwKadUDPKey<<32 | targetIP, 8); (m0^m1^m2^m3) % 0xFFFFFFFE + 1 (Prefs.cpp:236-238)
- MAX_CONTACTS_IP = 1, MAX_CONTACTS_SUBNET = 10 (RoutingBin.cpp:51-52); max 2 per /24 per bin
- Contact 25-byte wire record = ClientID(16)+IP(4)+UDPport(2)+TCPport(2)+version(1)
- nodes.dat: magic uint32=0, version=2 (write); records add UDPKey(8)+verified(1) for v>=2; bootstrap file version=3 edition=1 (RoutingZone.cpp:313-332,155-167)
- CanSplit: level<127 && (zoneIndex<KK || level<KBASE) && binSize==K (RoutingZone.cpp:391-400)
- Search lifetimes (s): NODE/FILE/KEYWORD/NOTES=45, NODECOMP=10, STOREFILE/STOREKEYWORD=140, STORENOTES/FINDBUDDY=100, FINDSOURCE=45 (Defines.h:69-88)
- Answer caps: FILE/KEYWORD=300, NOTES=50, STORE*=10, FINDSOURCE=20 (Defines.h:80-88)
- KADEMLIADISCONNECTDELAY = 20min; KADEMLIAFIREWALLCHECKS = 4; UDP_FIREWALLTEST_CLIENTSTOASK = 2 (kad/Constants.h:43,48; UDPFirewallTester.h:45)
- Index limits: KADEMLIAMAXINDEX=50000, KADEMLIAMAXENTRIES=60000, MAXSOURCEPERFILE=1000, MAXNOTESPERFILE=150 (kad/Constants.h:44-47)
- Republish: KADEMLIAREPUBLISHTIMES=5h (sources), REPUBLISHTIMEK/N=24h (keywords/notes) (kad/Constants.h:40-42)
- Keyword hash = MD4(lowercased UTF-8 first valid word) -> SetValueBE (Kademlia.cpp:504-514); invalid word chars = " ()[]{}<>,._-!?:;\/\"" (SearchManager.h:101); min 3 UTF-8 bytes
- TAGTYPE: HASH16=0x01,STRING=0x02,UINT32=0x03,FLOAT32=0x04,BLOB=0x07,UINT16=0x08,UINT8=0x09,BSOB=0x0A,UINT64=0x0B,STR1..16=0x11..0x20 (TagTypes.h:30-43)
- PacketTracking retention 180s; in-rate limits per min: REQ=10, HELLO=3, SEARCH_*=3, CALLBACK=1, others 2 (PacketTracking.cpp)
- PackPacket compression threshold: packet size > 200 bytes (KademliaUDPListener.cpp:1610)


### Flagged unclear (by the recon agent)

- ALPHA_QUERY is 5 in this repo (Defines.h:57) with an in-code comment stating classic eMule/aMule Kad uses 3; confirm whether the Rust port should match classic Kad (3) or this repo (5). It is a local search-parallelism parameter and does not affect wire compatibility, but affects lookup convergence/behavior.
- KADEMLIA_FIND_VALUE_MORE_REASKS=4 (Defines.h:65) and the m_requestedMoreNodes 'RequestMoreResults' widening feature appear to be repo-local additions not in stock aMule; confirm whether to port this user-triggered 'More results' widening at all.
- Search-id allocation uses SEARCH_ID_KAD_MASK=0x80000000 (SearchManager.cpp:62-63,173); this is a local GUI/ed2k-id-space partition, not protocol. Confirm the Rust design's search-id scheme separately.
- The ENCODER for the restrictive keyword search-expression tree (m_searchTermsData) is in SearchList.cpp/GetSearchPacket (outside kademlia/); only the DECODER (CreateSearchExpressionTree) is in the reviewed files. Read GetSearchPacket to reproduce exact byte encoding (op bytes 0x00/0x01/0x02/0x03/0x08, boolop, mmop) for outgoing filtered searches.
- Contact/IP byte-order: contacts store IP pre-swapped (host order) and code sprinkles wxUINT32_SWAP_ALWAYS at IsGoodIPPort/ipfilter/LAN checks and when writing FIREWALLED_RES (writes the un-swapped incoming ip). Confirm the exact swap points against a live capture so the Rust port keeps one canonical representation and swaps only where aMule does; getting this wrong silently breaks IP filtering and firewall responses.
- thePrefs::GetKadUDPKey() secret (Preferences.cpp:1377) default is GetRandomUint32() persisted in config; confirm it must be a stable per-install random uint32 (regenerating it invalidates all previously issued verify keys until contacts refresh).
- GetPublicIP(false) semantics feed both the receiver-key check and CKadUDPKey.GetKeyValue; verify how our public IP is determined (from FIREWALLED_RES / server) and its byte order, since verify-key validity depends on it matching what peers used as targetIP.
- TAGTYPE_STRING on the wire is written UTF-8 without BOM (utf8strRaw) but ReadOnlyString falls back to Latin-1 when UTF-8 decode yields empty; confirm the Rust string handling policy for search result tags (aMule allows local-codepage fallback only for display, per KademliaUDPListener.cpp:977-983).


==============================================================================

## SUBSYSTEM: aMule 3.0.1 protocol obfuscation, secure ident, EC protocol, and network/platform services (for Rust reimplementation)

# aMule 3.0.1 low-level protocols and services

All paths are under /home/ajbufort/claude-projects/padMule/amule-3.0.1/. Line
cites are `file:line`. Byte layouts given field-by-field. Everything needed to
reimplement in Rust without the C++ is here; residual ambiguities are in the
`unclear` list.

================================================================
## 1. RC4 primitive (shared by TCP and UDP obfuscation)
================================================================
File: src/RC4Encrypt.cpp, src/RC4Encrypt.h. Class CRC4EncryptableBuffer holds
RC4_Key_Struct { uint8 abyState[256]; uint8 byX; uint8 byY; } (RC4Encrypt.h:41).

Key schedule `RC4CreateKey(keyData, nLen, bSkipDiscard)` (RC4Encrypt.cpp:116):
- state[i]=i for i in 0..255; byX=byY=0; index1=index2=0.
- for i in 0..255: index2 = (keyData[index1] + state[i] + index2) mod 256;
  swap(state[i], state[index2]); index1 = (index1+1) mod nLen.
- if !bSkipDiscard: RC4Crypt(NULL,NULL,1024) i.e. drop first 1024 keystream bytes.

`SetKey(md5, bSkipDiscard=false)` always keys from the 16-byte MD5 raw hash,
nLen=16 (RC4Encrypt.cpp:104-113). TCP uses default (discard 1024). UDP calls
SetKey(md5, true) => NO discard (saves CPU; see EncryptedDatagramSocket.cpp:203,310).

Keystream step `RC4Crypt` (RC4Encrypt.cpp:62): standard PRGA:
byX=(byX+1)%256; byY=(state[byX]+byY)%256; swap(state[byX],state[byY]);
out[i]=in[i] ^ state[(state[byX]+state[byY])%256]. If in==NULL only advances
state (used to skip padding/discard).

Note: this is textbook RC4 with a 1024-byte drop (RC4-drop1024) for TCP. In Rust,
the `rc4` crate does NOT drop bytes; implement drop by running 1024 dummy bytes,
or hand-roll (trivial). MD5 is the standard 16-byte MD5 (src/libs/common/MD5Sum.h:44
m_rawhash[16]); use `md-5` crate. MD5Sum::GetHash() returns the 32-char lowercase
hex string; GetRawHash() the 16 raw bytes.

Random: src/RandomFunctions.cpp uses a single static CryptoPP::AutoSeededRandomPool
`cryptRandomGen`. GetRandomUint8/16/32/64 (RandomFunctions.cpp:35-53). Crypto-grade
RNG (use `rand` OsRng / `getrandom`). Some padding uses libc rand() (non-crypto),
which is fine to replicate with any PRNG.

================================================================
## 2. TCP protocol obfuscation (CEncryptedStreamSocket)
================================================================
Files: src/EncryptedStreamSocket.cpp/.h. Header block comment (lines 26-82)
documents the wire format; constants at EncryptedStreamSocket.cpp:98-113.

### 2.1 Magic constants
- MAGICVALUE_REQUESTER = 34 (0x22)   (client-A-send / server-receive key mod)
- MAGICVALUE_SERVER    = 203 (0xCB)  (server-send / client-A-receive key mod)
- MAGICVALUE_SYNC      = 0x835E6FC4  (uint32, verifies working encrypted stream)
- DHAGREEMENT_A_BITS   = 128         (DH private exponent size, bits)
- PRIMESIZE_BYTES      = 96          (768-bit prime, DH)
- dh768_p[96] = the fixed 768-bit prime, bytes at EncryptedStreamSocket.cpp:104-113
  (F2 BF 52 C5 5F 58 7A DD 53 71 A9 36 E8 86 EB 3C 62 17 A3 3E C3 4C B4 0D
   C7 3A 41 A6 43 AF FC E7 21 FC 28 63 66 53 5B DB CE 25 9F 22 86 DA 4A 91
   B2 07 CB AA 52 55 D4 F6 1C CE AE D4 5A D5 E0 74 7D F7 78 18 28 10 5F 34
   0F 76 23 87 F8 8B 28 91 42 FB 42 68 8F 05 15 0F 54 8B 5F 43 6A F7 0D F3).
  DH generator g = 2. Big-endian integer encoding, fixed 96-byte width.

### 2.2 Protocol first-byte markers (used to detect plain vs obfuscated)
From include/protocol/Protocols.h:34-45:
OP_EDONKEYPROT=0xE3, OP_PACKEDPROT=0xD4, OP_EMULEPROT=0xC5,
OP_KADEMLIAHEADER=0xE4, OP_KADEMLIAPACKEDPROT=0xE5,
OP_UDPRESERVEDPROT1=0xA3, OP_UDPRESERVEDPROT2=0xB2.

### 2.3 Detection (incoming, state ECS_UNKNOWN), EncryptedStreamSocket.cpp:234-289
On first Read of an incoming connection: if byte[0] is one of {OP_EDONKEYPROT,
OP_PACKEDPROT, OP_EMULEPROT} => treat as PLAIN (ECS_NONE), pass through. Else =>
begin obfuscation negotiation as the receiver (StartNegotiation(false)). The
first byte is the "SemiRandomNotProtocolMarker" and is consumed (nRead starts=1).
If ClientCryptLayerRequired and it looked plain, connection may be dropped
(ERR_ENCRYPTION_NOTALLOWED) except for server/kad firewall test connections.

### 2.4 Client<->Client key derivation (basic obfuscation)
Outgoing side (Client A), SetConnectionEncryption(EncryptedStreamSocket.cpp:151):
- m_nRandomKeyPart = GetRandomUint32() (crypto RNG).
- achKeyData[21] = UserHashClientB[16] || MAGICVALUE_* [1 at offset16] ||
  RandomKeyPartClientA[4 at offset17, little-endian via PokeUInt32].
- SendKey    = MD5(UserHashB || 34  || RKP)  (offset16 = MAGICVALUE_REQUESTER)
- ReceiveKey = MD5(UserHashB || 203 || RKP)  (offset16 = MAGICVALUE_SERVER)
Incoming side (Client B) mirrors: reads RKP off the wire, uses OWN UserHash
(thePrefs::GetUserHash()) at ONS_BASIC_CLIENTA_RANDOMPART (line 482):
- ReceiveKey = MD5(UserHash || 34 || RKP), SendKey = MD5(UserHash || 203 || RKP).
UserHashClientB is the target client's 16-byte ed2k user hash. Keys RC4-drop1024.

### 2.5 Client<->Server key derivation (DH), header comment lines 56-81
Outgoing client sends g^A mod p (96 bytes). Server replies g^B. Shared secret
S = g^(AB) mod p, encoded 96 bytes big-endian. Then:
- Client SendKey    = MD5(S[96] || 34),  ReceiveKey = MD5(S[96] || 203)
- Server SendKey    = MD5(S[96] || 203), ReceiveKey = MD5(S[96] || 34)
(97-byte key material). See ONS_BASIC_SERVER_DHANSWER, EncryptedStreamSocket.cpp:603-622.

### 2.6 Handshake wire format
Client A -> B (basic), StartNegotiation ECS_PENDING (line 377-397):
[SemiRandomNotProtocolMarker:1 PLAIN][RandomKeyPart:4 PLAIN, LE][MagicValueSync:4
enc][EncryptionMethodsSupported:1 enc][EncryptionMethodPreferred:1 enc]
[PaddingLen:1 enc][RandomBytes:PaddingLen enc]. Encryption starts at byte 5
(SendNegotiatingData(...,nStartCryptFromByte=5)). EncryptionMethod value
ENM_OBFUSCATION = 0x00 (only supported). Padding = GetRandomUint8() %
(GetCryptTCPPaddingLength()+1).
Client B -> A reply (ONS_BASIC_CLIENTA_PADDING, line 549-568):
[MagicValueSync:4][EncryptionMethodSelected:1][PaddingLen:1][RandomBytes] all enc.
Server-DH handshake: Client sends [marker:1][g^A:96][pad 0..15] all PLAIN;
Server sends [g^B:96 PLAIN][MagicSync:4][methodsSupported:1][methodPreferred:1]
[padLen:1][pad] (enc after g^B); Client final reply delayed and merged with first
payload frame (ONS_BASIC_SERVER_DELAYEDSENDING, line 670).

### 2.7 State machine
EStreamCryptState: ECS_NONE, ECS_UNKNOWN (incoming, awaiting first bytes),
ECS_PENDING (outgoing C2C), ECS_PENDING_SERVER (outgoing to server, DH),
ECS_NEGOTIATING, ECS_ENCRYPTING (EncryptedStreamSocket.h:52-59).
ENegotiatingState substates: ONS_BASIC_CLIENTA_{RANDOMPART,MAGICVALUE,
METHODTAGSPADLEN,PADDING}, ONS_BASIC_CLIENTB_{MAGICVALUE,METHODTAGSPADLEN,PADDING},
ONS_BASIC_SERVER_{DHANSWER,MAGICVALUE,METHODTAGSPADLEN,PADDING,DELAYEDSENDING},
ONS_COMPLETE (EncryptedStreamSocket.h:61-80). Negotiate() reads byte-count-driven
chunks via m_nReceiveBytesWanted and decrypts each step once the key exists
(EncryptedStreamSocket.cpp:434-691). Wrong MAGICVALUE_SYNC => OnError(ERR_ENCRYPTION).
Overhead ~18-48 bytes (C2C), ~206-251 bytes (server DH).

================================================================
## 3. UDP obfuscation (CEncryptedDatagramSocket, static funcs)
================================================================
File: src/EncryptedDatagramSocket.cpp/.h. All static. Constants at lines 109-114:
- CRYPT_HEADER_WITHOUTPADDING = 8
- MAGICVALUE_UDP             = 91 (0x5B)
- MAGICVALUE_UDP_SYNC_CLIENT = 0x395F2EC1
- MAGICVALUE_UDP_SYNC_SERVER = 0x13EF24D5
- MAGICVALUE_UDP_SERVERCLIENT = 0xA5
- MAGICVALUE_UDP_CLIENTSERVER = 0x6B
Padding is currently 0 for UDP (padLen=0 on send). Keys keyed with SetKey(md5,true)
=> NO 1024 discard.

### 3.1 Client/Kad packet keys (DecryptReceivedClient line 123, EncryptSendClient 264)
Wire header (8 bytes min + 8 more for kad): [marker:1][RandomKeyPart:2 LE PLAIN]
[MagicSyncClient:4 enc][PadLen:1 enc][pad][ (kad only) ReceiverVerifyKey:4 enc,
SenderVerifyKey:4 enc ][payload enc].
Three key variants tried on receive (indicated by marker low 2 bits, but not
trusted; `currentTry = (bufIn[0]&0x03)==3 ? 1 : bufIn[0]&0x03`, up to 3 tries):
- currentTry==1 ED2K: keyData[23] = UserHash[16] || IP[4 @16 LE] ||
  MAGICVALUE_UDP(91) [@20] || RandomKeyPart[2 @21]; key=MD5(keyData). On SEND the
  IP is theApp->GetPublicIP() (sender's own public IP); on RECEIVE it is the local
  receiver ip param.
- currentTry==0 KAD by NodeID: keyData[18] = KadID[16] || RandomKeyPart[2 @16];
  key=MD5. (KadID via Kademlia prefs GetKadID().StoreCryptValue.)
- currentTry==2 KAD by ReceiverKey: keyData[6] = ReceiverVerifyKey[4 LE] ||
  RandomKeyPart[2]; key=MD5. Used when encrypting to a node whose hash unknown but
  we hold its UDP verify key (CPrefs::GetUDPVerifyKey(ip)).
Magic check: decrypt bytes[3..7] and compare to MAGICVALUE_UDP_SYNC_CLIENT
(stored ENDIAN_SWAP_32 on the wire, i.e. transmitted big-endian; code byte-swaps).
On send, marker bit conventions (EncryptSendClient line 313-341): kad clears bit0
(ed2k/kad marker), ed2k sets bit0; kad-with-recvkey sets bit1 else clears bits0-1.
Marker must not collide with any protocol byte {OP_EMULEPROT, OP_KADEMLIAPACKEDPROT,
OP_KADEMLIAHEADER, OP_UDPRESERVEDPROT1, OP_UDPRESERVEDPROT2, OP_PACKEDPROT}.

Recognition (DecryptReceivedClient line 140): if byte[0] in {OP_EMULEPROT 0xC5,
OP_KADEMLIAPACKEDPROT 0xE5, OP_KADEMLIAHEADER 0xE4, OP_UDPRESERVEDPROT1 0xA3,
OP_UDPRESERVEDPROT2 0xB2, OP_PACKEDPROT 0xD4} => not obfuscated, pass through. Also
requires bufLen > 8. Kad packets carry 8 trailing verify-key bytes decrypted after
padding (line 236-247), subtracted from result.

### 3.2 Server packet keys (DecryptReceivedServer 377, EncryptSendServer 432)
keyData[7] = BaseKey[4 LE] || MagicValueDir[1] || RandomKeyPart[2].
- Client->Server SendKey MagicValueDir = MAGICVALUE_UDP_CLIENTSERVER (0x6B).
- Server->Client key MagicValueDir = MAGICVALUE_UDP_SERVERCLIENT (0xA5).
Sync value = MAGICVALUE_UDP_SYNC_SERVER (0x13EF24D5). Recognition: byte[0]==
OP_EDONKEYPROT(0xE3) => plain. PadLen masked &15. BaseKey is a per-server uint32
challenge/key from the server handshake.

Overhead: 8 bytes/packet (ed2k/server), 12 bytes/packet (kad, +4 verify keys).

================================================================
## 4. Secure identification (RSA, ClientCredits)
================================================================
Files: src/ClientCreditsList.cpp (crypto), src/ClientCredits.cpp/.h,
src/BaseClient.cpp:2043-2287 (packet exchange), src/CryptoPP_Inc.h.

### 4.1 Key pair and file
- RSAKEYSIZE = 384 bits (include/protocol/ed2k/Constants.h:49). Very small by modern
  standards; must reimplement exactly (interop). Crypto++ types:
  CryptoPP::RSASSA_PKCS1v15_SHA_Signer / _Verifier (RSA PKCS#1 v1.5 signatures with
  SHA-1). Key gen: InvertibleRSAFunction.Initialize(rng, 384) with
  AutoSeededX917RNG<DES_EDE3> (ClientCreditsList.cpp:249-279).
- cryptkey.dat: the RSA PRIVATE key, DER-encoded then Base64-encoded, written via
  FileSink(Base64Encoder(DEREncode)) (ClientCreditsList.cpp:257-261). Loaded via
  FileSource(Base64Decoder) into the Signer (line 310-311).
- Public key: derived from the signer, saved with pubkey.GetMaterial().Save into an
  80-byte buffer; MAXPUBKEYSIZE=80 (ClientCredits.h:31). Public key length is the
  DER/X.509 SubjectPublicKeyInfo blob length (variable, <=80). For 384-bit RSA it is
  typically ~59-64 bytes. Public key is stored on the wire and in clients.met.

### 4.2 What gets signed (challenge/response)
Signature creation (ClientCreditsList.cpp:329 CreateSignature). Buffer to sign:
  abyBuffer = pTarget.PublicKey[keylen] || challenge[4 LE, = m_dwCryptRndChallengeFrom]
              [ v2 only: || ChallengeIP[4 LE] || byChaIPKind[1] ]
Signed length = keylen + 4 (+5 for v2). SignMessage with the LOCAL signer.
Here pTarget.PublicKey is the REMOTE client's public key; challenge is the random
value the remote sent us in its OP_SECIDENTSTATE.
Verification (VerifyIdent, line 376): rebuild
  abyBuffer = MyPublicKey[m_nMyPublicKeyLen] || challenge[4 LE, = m_dwCryptRndChallengeFor]
              [ v2: || ChallengeIP[4 LE] || byChaIPKind[1] ]
VerifyMessage against the remote's public key and received signature. So: each side
signs (peer's public key || the random challenge that peer generated [+ IP kind]),
proving possession of the private key matching the public key it advertised.

v2 ChallengeIP kinds (ClientCredits.h:33-35): CRYPT_CIP_REMOTECLIENT=10 (use remote
client IP), CRYPT_CIP_LOCALCLIENT=20 (use our ed2k ID / public IP), CRYPT_CIP_NONECLIENT=30
(IP=0). Selection logic BaseClient.cpp:2091-2101.

### 4.3 Packet exchange (opcodes, ed2k C2C over OP_EMULEPROT 0xC5)
From include/protocol/ed2k/Client2Client/TCP.h:75-78:
OP_PUBLICKEY=0x85 [len:1][pubkey:len], OP_SIGNATURE=0x86 [len:1][sig:len]
(v2 appends [byChaIPKind:1]), OP_SECIDENTSTATE=0x87 [state:1][rndchallenge:4].
State enum ESecureIdentState (updownclient.h:63): IS_UNAVAILABLE=0,
IS_ALLREQUESTSSEND=0, IS_SIGNATURENEEDED=1, IS_KEYANDSIGNEEDED=2.
Flow (BaseClient.cpp): after both info packets, SendSecIdentStatePacket sends a
random challenge (rand()+1) + a state telling peer whether we need its key and/or a
signature (2217-2246). On receiving OP_SECIDENTSTATE (ProcessSecIdentStatePacket
2249) store peer's challenge; then send OP_PUBLICKEY (if key needed) and/or
OP_SIGNATURE. Only one signature accepted per remote IP (flood guard, 2191).
Result recorded on CClientCredits (Verified/SetIdentState). IdentState enum
(ClientCredits.h:51): IS_NOTAVAILABLE, IS_IDNEEDED, IS_IDENTIFIED, IS_IDFAILED,
IS_IDBADGUY.

### 4.4 clients.met (credit file)
CREDITFILE_VERSION = 0x12 (include/common/DataFileVersion.h:40). Format
(ClientCreditsList.cpp:118-205): uint8 version(0x12), uint32 count, then per entry:
key(16-byte MD4 hash) uploaded_lo(u32) downloaded_lo(u32) nLastSeen(u32)
uploaded_hi(u32) downloaded_hi(u32) nReserved3(u16) nKeySize(u8)
abySecureIdent[MAXPUBKEYSIZE=80 fixed]. Entries with nKeySize>80 => file corrupt.
Entries older than now-12960000s (150 days) dropped. All little-endian.
Rust crates: `rsa` (RSA PKCS1v15 sign/verify with SHA-1 via `rsa::pkcs1v15` +
`sha1`), DER via `rsa`/`pkcs8`/`der`, Base64 via `base64`. Must match Crypto++
DEREncode of the full RSA private key (PKCS#1 RSAPrivateKey inside; verify exact
format vs Crypto++ - see unclear).

================================================================
## 5. EC (External Connections) protocol
================================================================
Files: src/libs/ec/cpp/{ECSocket,ECPacket,ECTag}.cpp/.h,
src/libs/ec/abstracts/{ECCodes,ECTagTypes}.abstract, src/ExternalConn.cpp,
src/libs/ec/cpp/RemoteConnect.cpp, src/libs/ec/file_generator.pl.

### 5.1 Framing (ECSocket.cpp)
Fixed 8-byte header EC_HEADER_SIZE=8 (ECSocket.h:80): [flags:u32 network-order]
[length:u32 network-order] where length = bytes of the packet body following the
header (ReadHeader ECSocket.cpp:564-612; WritePacket writes a 0 placeholder then
patches offset 4 with the real body length, lines 833-855).
Flags base value 0x20 (bit5). Flag bits (ECCodes.abstract:28-31):
EC_FLAG_ZLIB=0x00000001, EC_FLAG_UTF8_NUMBERS=0x00000002,
EC_FLAG_LARGE_TAG_COUNT=0x00000010, EC_FLAG_UNKNOWN_MASK=0xff7f7f08.
Validity check (ReadPacket line 1000): reject if ((flags & 0x60) != 0x20) or
(flags & EC_FLAG_UNKNOWN_MASK) != 0. i.e. bit5 set, bit6 clear, no unknown bits.
m_my_flags starts 0x20 (ECSocket.cpp:281) and is OR'ed with negotiated caps.
Max body: 16 MiB pre-auth, 256 MiB post-auth (ReadHeader line 577-579).

### 5.2 zlib compression (per packet)
EC_MAX_UNCOMPRESSED=1024, EC_COMPRESSION_LEVEL=Z_DEFAULT_COMPRESSION (ECSocket.cpp:39-40).
On write (WritePacket line 783-827): flags=0x20; if packet logical length > 1024
AND (m_my_flags & EC_FLAG_ZLIB) AND not local-peer-bypass => set EC_FLAG_ZLIB else
set EC_FLAG_UTF8_NUMBERS; always OR EC_FLAG_LARGE_TAG_COUNT; then flags &= m_my_flags.
If ZLIB: whole body is a single zlib (deflate) stream (raw deflateInit/deflate/
deflateEnd, standard zlib, Z_DEFAULT_COMPRESSION). Reader inflates via inflateInit
(ECSocket.cpp:1008-1045, ReadBuffer 671-699). The 8-byte header is never compressed.
Local-peer bypass (m_isLocalPeer): skip zlib up to kLocalPeerZlibBypassMax=256 MiB
(ECSocket.cpp:46). Use `flate2` (zlib) in Rust.

### 5.3 Integer encoding: UTF-8 numbers vs network order (ReadNumber/WriteNumber)
Structural integers (opcode u8, tag name u16, tag type u8, tag length u32,
children-count u16/u32) are written by WriteNumber (ECSocket.cpp:645). If
EC_FLAG_UTF8_NUMBERS set: value is encoded as a UTF-8 / FSS-UTF multibyte sequence
of the numeric value (1-6 bytes; classic UTF-8 codepoint encoding, tables at
ECSocket.cpp:74-137). Reader uses utf8_mb_remain(firstByte) to size it. Else:
fixed-width big-endian (network byte order). CRITICAL: tag DATA payloads (the tag
body bytes) are NOT number-encoded; integer tag values are stored big-endian raw in
m_tagData at construction and copied verbatim via WriteBuffer. So UTF8_NUMBERS only
affects name/type/len/count/opcode, never the payload.

### 5.4 Tag tree wire format (ECTag.cpp)
Types: ec_opcode_t=u8, ec_tagname_t=u16, ec_tagtype_t=u8, ec_taglen_t=u32
(ECCodes.abstract:9-12). A packet is a CECPacket = an opcode + a root tag whose
children are the top-level tags (CECPacket derives CECEmptyTag; ECPacket.h:39).
Packet body layout (CECPacket::WritePacket ECPacket.cpp:41; ReadFromSocket 34):
[opcode: WriteNumber u8][children-count + children...] (the packet's own tag has no
name/type/len on the wire; it is just opcode then the child-tag block).
Per-tag layout (CECTag::WriteTag ECTag.cpp:463; ReadFromSocket 417):
- name field: WriteNumber(u16) of ((m_tagName << 1) | hasChildrenBit). LSB=1 if the
  tag has child tags. Reader: m_tagName = raw >> 1; hasChildren = raw & 1.
- type field: WriteNumber(u8) = ec_tagtype_t.
- length field: WriteNumber(u32) = GetTagLen = m_dataLen + serialized size of all
  children (name+type+len headers + counts + their bodies). i.e. length INCLUDES
  children.
- if hasChildren: children block (see below).
- then body: m_dataLen raw bytes (m_dataLen = length - childrenSerializedLen; reader
  computes childrenLen after reading children and subtracts; rejects if length <
  childrenLen, ECTag.cpp:446).
Children block (WriteChildren ECTag.cpp:524; ReadChildren 488):
- count: WriteNumber(u16). If EC_FLAG_LARGE_TAG_COUNT negotiated AND count>=0xFFFF:
  write sentinel u16 0xFFFF then u32 real count. Else plain u16 (capped 0xFFFE when
  not large-count-capable). Then each child tag serialized recursively.
Tag types (ECTagTypes.abstract): EC_TAGTYPE_UNKNOWN=0, CUSTOM=1, UINT8=2, UINT16=3,
UINT32=4, UINT64=5, STRING=6 (UTF-8, NUL-terminated: dataLen includes the trailing
0, ECTag.cpp:752-758), DOUBLE=7 (ASCII decimal string incl NUL), IPV4=8
(4 IP bytes + u16 port network-order, ECTag.cpp:108-116), HASH16=9 (16 bytes),
UINT128=10. Integer tag bodies are minimal-width big-endian, width chosen by value
magnitude in InitInt (ECTag.cpp:207-239): <=0xFF u8, <=0xFFFF u16, <=0xFFFFFFFF u32,
else u64.

### 5.5 Opcode/tag code generation
file_generator.pl reads .abstract files ([Section Definition]/[Section Content]
with Type Define/Enum/TypeDef) and emits C++ headers (ECCodes.h, ECTagTypes.h) and
Java. For a Rust port: parse the two .abstract files directly, or hardcode the
tables (full lists in section 5.7). EC_CURRENT_PROTOCOL_VERSION=0x0204
(ECCodes.abstract:20).

### 5.6 AUTH handshake (ExternalConn.cpp:521 server; RemoteConnect.cpp client)
Server state: CONN_INIT -> CONN_SALT_SENT -> CONN_ESTABLISHED / CONN_FAILED
(ExternalConn.cpp:218-223). Salt = GetRandomUint64() per connection (line 297).
Sequence:
1. Client -> EC_OP_AUTH_REQ (0x02) with tags: EC_TAG_CLIENT_NAME(string),
   EC_TAG_CLIENT_VERSION(string), EC_TAG_PROTOCOL_VERSION(u16 = 0x0204),
   [EC_TAG_VERSION_ID(hash16) if snapshot build], and capability EMPTY tags:
   EC_TAG_CAN_ZLIB(0x0C), EC_TAG_CAN_UTF8_NUMBERS(0x0D), EC_TAG_CAN_NOTIFY(0x0E),
   EC_TAG_CAN_LARGE_TAG_COUNT(0x11), EC_TAG_CAN_PARTIAL_UPDATE(0x12),
   [EC_TAG_PREFER_NO_ZLIB(0x14) optional] (RemoteConnect.cpp:47-86).
2. Server checks protocol==0x0204, sets m_my_flags from cap tags, replies
   EC_OP_AUTH_SALT (0x4F) with EC_TAG_PASSWD_SALT(0x0B, u64 salt) (line 564-566).
   Wrong version/proto => EC_OP_AUTH_FAIL(0x03) with EC_TAG_STRING reason.
3. Client computes salted hash and -> EC_OP_AUTH_PASSWD (0x50) with
   EC_TAG_PASSWD_HASH(0x01, hash16).
4. Server verifies; replies EC_OP_AUTH_OK (0x04) with EC_TAG_SERVER_VERSION(string)
   [+ EC_TAG_CAN_LARGE_TAG_COUNT / EC_TAG_CAN_PARTIAL_UPDATE echoes], or
   EC_OP_AUTH_FAIL. On OK m_conn_state=CONN_ESTABLISHED; if client sent CAN_NOTIFY,
   register for push notifications.

Password/salt MD5 scheme (server ExternalConn.cpp:638-643; client
RemoteConnect.cpp:324-325, identical):
- Stored password `P` = the lowercase 32-char hex string of MD5(plaintext password)
  (this is what is kept in prefs / passed to ConnectToCore). Empty password hash
  d41d8cd98f00b204e9800998ecf8427e is rejected.
- saltHash = MD5Sum(format("%lX", salt)).GetHash()  where format is uppercase-hex of
  the u64 salt with NO leading zeros, and GetHash() returns the 32-char lowercase
  hex string of that MD5.
- expected = MD5Sum( lower(P) + saltHash ).GetHash()  -> hex string, then
  Decode() to a 16-byte hash. EC_TAG_PASSWD_HASH sent by client must equal this.
  i.e. transmitted hash = MD5( lower(hex(MD5(plaintext))) || hex(MD5(hex_upper(salt))) ).
Caveat: "%lX" formats an unsigned long; on 64-bit Unix this is the full u64 uppercase
hex. Reimplement as uppercase hex of the u64 with no zero padding (see unclear about
32-bit).

### 5.7 Opcode and tag tables (ECCodes.abstract) - exact values
OPCODES (ec_opcode_t u8): EC_OP_NOOP 0x01, AUTH_REQ 0x02, AUTH_FAIL 0x03,
AUTH_OK 0x04, FAILED 0x05, STRINGS 0x06, MISC_DATA 0x07, SHUTDOWN 0x08,
ADD_LINK 0x09, STAT_REQ 0x0A, GET_CONNSTATE 0x0B, STATS 0x0C, GET_DLOAD_QUEUE 0x0D,
GET_ULOAD_QUEUE 0x0E, GET_SHARED_FILES 0x10, SHARED_SET_PRIO 0x11,
PARTFILE_SWAP_A4AF_THIS 0x16, ..._THIS_AUTO 0x17, ..._OTHERS 0x18, PARTFILE_PAUSE
0x19, RESUME 0x1A, STOP 0x1B, PRIO_SET 0x1C, DELETE 0x1D, SET_CAT 0x1E,
DLOAD_QUEUE 0x1F, ULOAD_QUEUE 0x20, SHARED_FILES 0x22, SHAREDFILES_RELOAD 0x23,
RENAME_FILE 0x25, SEARCH_START 0x26, SEARCH_STOP 0x27, SEARCH_RESULTS 0x28,
SEARCH_PROGRESS 0x29, DOWNLOAD_SEARCH_RESULT 0x2A, IPFILTER_RELOAD 0x2B,
GET_SERVER_LIST 0x2C, SERVER_LIST 0x2D, SERVER_DISCONNECT 0x2E, SERVER_CONNECT 0x2F,
SERVER_REMOVE 0x30, SERVER_ADD 0x31, SERVER_UPDATE_FROM_URL 0x32, ADDLOGLINE 0x33,
ADDDEBUGLOGLINE 0x34, GET_LOG 0x35, GET_DEBUGLOG 0x36, GET_SERVERINFO 0x37,
LOG 0x38, DEBUGLOG 0x39, SERVERINFO 0x3A, RESET_LOG 0x3B, RESET_DEBUGLOG 0x3C,
CLEAR_SERVERINFO 0x3D, GET_LAST_LOG_ENTRY 0x3E, GET_PREFERENCES 0x3F,
SET_PREFERENCES 0x40, CREATE_CATEGORY 0x41, UPDATE_CATEGORY 0x42, DELETE_CATEGORY
0x43, GET_STATSGRAPHS 0x44, STATSGRAPHS 0x45, GET_STATSTREE 0x46, STATSTREE 0x47,
KAD_START 0x48, KAD_STOP 0x49, CONNECT 0x4A, DISCONNECT 0x4B, KAD_UPDATE_FROM_URL
0x4D, KAD_BOOTSTRAP_FROM_IP 0x4E, AUTH_SALT 0x4F, AUTH_PASSWD 0x50, IPFILTER_UPDATE
0x51, GET_UPDATE 0x52, CLEAR_COMPLETED 0x53, CLIENT_SWAP_TO_ANOTHER_FILE 0x54,
SHARED_FILE_SET_COMMENT 0x55, SERVER_SET_STATIC_PRIO 0x56, FRIEND 0x57.
TAG NAMES (ec_tagname_t u16, selected/grouped; full list ECCodes.abstract:159-484):
Core: EC_TAG_STRING 0x0000, PASSWD_HASH 0x0001, PROTOCOL_VERSION 0x0002,
VERSION_ID 0x0003, DETAIL_LEVEL 0x0004, CONNSTATE 0x0005, ED2K_ID 0x0006,
LOG_TO_STATUS 0x0007, BOOTSTRAP_IP 0x0008, BOOTSTRAP_PORT 0x0009, CLIENT_ID 0x000A,
PASSWD_SALT 0x000B, CAN_ZLIB 0x000C, CAN_UTF8_NUMBERS 0x000D, CAN_NOTIFY 0x000E,
ECID 0x000F, KAD_ID 0x0010, CAN_LARGE_TAG_COUNT 0x0011, CAN_PARTIAL_UPDATE 0x0012,
FILE_REMOVED 0x0013, PREFER_NO_ZLIB 0x0014. Client id: CLIENT_NAME 0x0100,
CLIENT_VERSION 0x0101. Stats block base 0x0200 (UL_SPEED 0x0200, DL_SPEED 0x0201,
UL/DL limits 0x0202/3, up/down overhead 0x0204/5, ED2K_USERS 0x0209, KAD_USERS
0x020A, ED2K_FILES 0x020B, KAD_FILES 0x020C, LOGGER_MESSAGE 0x020D, ...,
TOTAL_SENT 0x0218, TOTAL_RECEIVED 0x0219, SHARED_FILE_COUNT 0x021A, KAD_NODES
0x021B). Partfile block base 0x0300 (NAME 0x0301, PARTMETID 0x0302, SIZE_FULL 0x0303,
SIZE_XFER 0x0304, SIZE_DONE 0x0306, SPEED 0x0307, STATUS 0x0308, PRIO 0x0309,
SOURCE_COUNT 0x030A, ED2K_LINK 0x030E, CAT 0x030F, PART_STATUS 0x0312, GAP_STATUS
0x0313, REQ_STATUS 0x0314, SOURCE_NAMES 0x0315, HASH 0x031E, ...). Knownfile block
base 0x0400. Server block base 0x0500 (NAME 0x0501, ADDRESS 0x0503, USERS 0x0505,
IP 0x050C, PORT 0x050D). Client (peer) block base 0x0600. Search block base 0x0700
(SEARCH_TYPE 0x0701, SEARCH_NAME 0x0702, MIN/MAX_SIZE 0x0703/4, FILE_TYPE 0x0705,
EXTENSION 0x0706, AVAILABILITY 0x0707, STATUS 0x0708). Friend base 0x0800. Prefs
tree base 0x1000..0x1E01 (categories 0x11xx, general 0x12xx incl USER_NICK 0x1201/
USER_HASH 0x1202, connections 0x13xx incl TCP_PORT 0x1306/UDP_PORT 0x1307/UDP_DISABLE
0x1308/NETWORK_ED2K 0x130D/NETWORK_KADEMLIA 0x130E, remotectrl/webserver 0x15xx,
directories 0x1Axx, security 0x1Cxx incl USE_SECIDENT 0x1C08, OBFUSCATION_SUPPORTED/
REQUESTED/REQUIRED 0x1C09/0A/0B). EC_DETAIL_LEVEL (u8): EC_DETAIL_CMD 0x00, WEB 0x01,
FULL 0x02, UPDATE 0x03, INC_UPDATE 0x04 (ECCodes.abstract:491-495). Default detail
FULL; omitted when FULL (ECPacket.h:42-49). EC_SEARCH_TYPE: LOCAL 0, GLOBAL 1, KAD 2,
WEB 3. EC_STATTREE_NODE_VALUE_TYPE 0..7. EcPrefs bitmask 0x1..0x2000.

### 5.8 Main request/response semantics (ExternalConn.cpp ProcessRequest2 line 1770)
Status: EC_OP_STAT_REQ -> EC_OP_STATS (adds CEC_ConnState_Tag). Detail level FULL/
INC_UPDATE include overhead, banned count, logger, totals, shared count, plus
speeds, limits, queue len, user/file counts, kad stats (Get_EC_Response_StatRequest
717). GET_CONNSTATE -> EC_OP_MISC_DATA + ConnState.
Shared files: GET_SHARED_FILES -> EC_OP_SHARED_FILES; FULL non-empty query uses a
per-file blob cache with SendCachedBodyResponse (line 1851-1879). Download queue:
GET_DLOAD_QUEUE -> EC_OP_DLOAD_QUEUE (1887). Upload queue: GET_ULOAD_QUEUE ->
EC_OP_ULOAD_QUEUE (1928). GET_UPDATE (INC_UPDATE only) -> EC_OP_SHARED_FILES bundle
of changed files+clients+servers+friends (Get_EC_Response_GetUpdate 869). Each
CKnownFile has an ECID (u32, monotonically assigned CECID s_IDCounter, ECID.h:38-43)
and an m_ecGen used to skip unchanged files; partial-update clients get explicit
EC_TAG_FILE_REMOVED tombstones.
Partfile commands (pause/resume/stop/prio/delete/setcat/swap A4AF): tags carry
EC_TAG_PARTFILE(hash16); dispatched Get_EC_Response_PartFile_Cmd (1162) ->
EC_OP_NOOP or EC_OP_FAILED.
Search: SEARCH_START -> Get_EC_Response_Search (1496): reads CEC_Search_Tag fields
(text/type/ext/min/max size/avail), starts Local/Global/Kad search; returns
EC_OP_STRINGS or EC_OP_FAILED. SEARCH_RESULTS -> EC_OP_SEARCH_RESULTS (per-result
CEC_SearchFile_Tag). SEARCH_PROGRESS -> progress u16. DOWNLOAD_SEARCH_RESULT: tags
hash16 + category u8 -> AddFileToDownloadByHash.
Servers: SERVER_ADD (EC_TAG_SERVER_ADDRESS "ip:port", NAME), CONNECT/DISCONNECT/
REMOVE, GET_SERVER_LIST -> EC_OP_SERVER_LIST of CEC_Server_Tag.
Config: GET_PREFERENCES(EC_TAG_SELECT_PREFS bitmask) -> CEC_Prefs_Packet;
SET_PREFERENCES applies + saves. Categories create/update/delete. Logs: GET_LOG ->
EC_OP_LOG(EC_TAG_STRING), GET_DEBUGLOG, GET_SERVERINFO, reset variants. Kad:
KAD_START/STOP/BOOTSTRAP_FROM_IP. Networks: CONNECT/DISCONNECT (text-client). Most
mutating ops answer EC_OP_NOOP on success, EC_OP_FAILED(EC_TAG_STRING) on error.
Push notifications: if CAN_NOTIFY, ECNotifier feeds packets asynchronously via
WriteDoneAndQueueEmpty (depth-capped at 8, ExternalConn.cpp:348-407).

================================================================
## 6. Core app lifecycle / timers (amuled.cpp, amule.cpp)
================================================================
Core timer: CORE_TIMER_PERIOD = 300 ms for the daemon (AMULE_DAEMON), 100 ms for
GUI (amule.h:102-108). Daemon creates CTimer(ID_CORE_TIMER_EVENT).Start(300)
(amuled.cpp:163-164). Event table: ID_CORE_TIMER_EVENT->OnCoreTimer,
ID_SERVER_RETRY_TIMER_EVENT->OnTCPTimer (amuled.cpp:79-82).
OnCoreTimer (amule.cpp:1377) runs each tick (300ms daemon):
- Every tick: uploadqueue->Process(); downloadqueue->Process();
  theStats::CalculateRates(); shutdown-flag check; reentrancy guard.
- History: when msCur-msPrevHist > 1000, msPrevHist += 1000 (fixed step, may fire
  twice to keep ~1 node/sec), m_statistics->RecordHistory() (line 1439-1449).
- Every ~1000 ms (msPrev1): clientcredits->Process(); clientlist->Process();
  sharedfiles->Process(); Kademlia::Process() (+ lost-connection reconnect that
  closes/reopens clientudp and restarts Kad if Reconnect()); serverconnect retry/
  timeout checks; listensocket->UpdateConnectionsStatus() (line 1452-1480).
- Every 5000 ms (msPrev5): listensocket->Process() (line 1483-1486).
- Every 60000 ms: theStats::Save() (line 1488-1491).
- Online signature: every thePrefs::GetOSUpdate()*1000 ms (line 1494).
- known.met: every 30*60*1000 ms (30 min): knownfiles->Save() (line 1499-1503).
- Every tick end: serverconnect->KeepConnectionAlive() (line 1507).
Other periodic saves not in OnCoreTimer:
- clientcredits (clients.met) SaveList when GetTickCount64()-m_nLastSaved > MIN2MS(13)
  (=13 min), checked from CClientCreditsList::Process() (ClientCreditsList.cpp:242-246).
Reconnect logic: OnTCPTimer (amule.cpp:1364) is the server-retry timer: stops the
current connection try; if still not connected to ed2k, ConnectToAnyServer().
Daemon startup: OnInit -> CamuleApp::OnInit then start core timer; OnRun requires
AcceptExternalConnections and a non-empty ECPassword or it refuses to run
(amuled.cpp:140-155). Optional fork to background with pid file (InitGui 171-214).
Shutdown: g_shutdownSignal flag polled in OnCoreTimer triggers ExitMainLoop /
window close; OnExit calls ShutDown(), deletes core_timer (amuled.cpp:258-263).

================================================================
## 7. Listen sockets / ports (amule.cpp:895-1053, Preferences)
================================================================
Defaults: TCP port 4662 (DEFAULT_TCP_PORT, Preferences.cpp:72; cfg /eMule/Port),
client UDP port 4672 (DEFAULT_UDP_PORT, Preferences.cpp:73; cfg /eMule/UDPPort),
EC port 4712 (cfg /ExternalConnect/ECPort, Preferences.cpp:1244).
Four sockets bound (amule.cpp:952-1053):
- myaddr[0] EC listener at ECPort (default 4712), created by ExternalConn.
- myaddr[1] Server-UDP socket at (TCP port + 3) (=4665), owned by CServerConnect;
  used for source asking / server UDP. Comment "Server UDP socket (TCP+3)"
  (amule.cpp:974-977).
- myaddr[2] main TCP listen socket at TCP port (4662), CListenSocket
  (amule.cpp:983-985). Bind failure => LowID.
- myaddr[3] client UDP socket at UDP port (4672), CClientUDPSocket; extended eMule
  protocol + Kademlia (amule.cpp:1008-1010).
Convention: the SERVER UDP port is TCP+3 (reserved). The CLIENT/Kad UDP port is the
separately configured GetUDPPort() (default 4672), NOT TCP+3. Sanity checks reject
ECPort==TCP port and UDPPort==TCP+3 (amule.cpp:905-948), picking a random port.
TCP port capped <=65532 because server UDP is TCP+3 (Preferences.cpp:2039).
GetEffectiveUDPPort() returns 0 when UDP disabled (Preferences.h:239). All bind to
GetAddress() or AnyAddress. CListenSocket.cpp handles accept loop / per-connection
CClientTCPSocket (which wraps CEncryptedStreamSocket).
User hash: 16-byte ed2k user hash, generated random (2 bytes at a time from rand())
then bytes[5]=14 and bytes[14]=111 as the aMule/eMule client marker
(Preferences.cpp:1049-1077); stored in the pref file.

================================================================
## 8. UPnP port mapping (UPnPBase.cpp)
================================================================
Uses libupnp (IGD). Standard URNs (UPnPBase.cpp:139-180):
InternetGatewayDevice:1, WANDevice:1, WANConnectionDevice:1, LANDevice:1,
Layer3Forwarding:1, WANCommonInterfaceConfig:1, WANIPConnection:1, WANPPPConnection:1.
On startup (amule.cpp:1019-1046) if GetUPnPEnabled(): build 4 CUPnPPortMapping and
new CUPnPControlPoint(GetUPnPTCPPort()); wait up to 3000 ms for WanServiceDetected();
AddPortMappings. The 4 mappings (amule.cpp:1021-1040):
[0] ECPort TCP "aMule TCP External Connections Socket" (enabled iff UPnPECEnabled),
[1] (TCP+3) UDP "aMule UDP socket (TCP+3)",
[2] TCP port TCP "aMule TCP Listen Socket",
[3] UDP port UDP "aMule UDP Extended eMule Socket".
SOAP AddPortMapping args (PrivateAddPortMapping UPnPBase.cpp:1085-1121):
NewRemoteHost="", NewExternalPort=port, NewProtocol="TCP"|"UDP",
NewInternalPort=port (same), NewInternalClient=UpnpGetServerIpAddress(),
NewEnabled="1", NewPortMappingDescription=desc, NewLeaseDuration="0". Executed
against every discovered WAN service. DeletePortMapping args: NewRemoteHost="",
NewExternalPort, NewProtocol (line 1188-1211). Deleted on shutdown (amule.cpp:1748-
1750). For Rust: `igd`/`igd-next` crate implements the exact same IGD AddPortMapping
SOAP; feed the same 4 mappings.

================================================================
## 9. IP filter matching (IPFilter.cpp)
================================================================
Loads ipfilter.dat + ipfilter_static.dat (also guardian.p2p/guarding.p2p inside
archives; auto-unpacked) on a background thread (CIPFilterTask, IPFilter.cpp:100).
Ranges kept in a CRangeMap keyed by [startIP,endIP] host-order with a uint8
AccessLevel; only ranges with AccessLevel < thePrefs::GetIPFilterLevel() are blocking
(line 143). Compiled to two parallel sorted vectors m_rangeIPs (start IP, host order)
and m_rangeLengths (encoded length). Length encoding (line 146-172):
- 0x0000..0x7FFF => exact (length-1), covers up to 32768 addresses.
- else (msb set): stored = ((curLength-1) >> 12) | 0x8000; decoded curLength =
  ((stored & 0x7FFF) << 12) + 0xFFF (covers up to ~0x08000000 = 8 class-A nets).
Large/odd ranges are split into multiple entries.
IsFiltered(IPTest, isServer) (line 419): early-out if filtering disabled for that
kind; if filter not ready yet, block everything. IP converted to host order via
wxUINT32_SWAP_ALWAYS. Binary search over m_rangeIPs; for candidate i where
curIP<=ip, decode length, match if curIP+curLength >= ip. Mutex-guarded. Stats
count filtered clients/servers. Reload() via thread; Update(url) downloads new list
over HTTP and reloads on success (line 476-519). LAN/local IPs optionally excluded
(IPFilterFilterLAN pref). For Rust: keep a sorted Vec of (start_u32_host, len_encoded)
and replicate the two-form length encoding and binary search exactly.

================================================================
## 10. Proxy (Proxy.cpp / Proxy.h)
================================================================
CProxyType enum (Proxy.h:103-108): PROXY_NONE=-1, PROXY_SOCKS5=0, PROXY_SOCKS4=1,
PROXY_HTTP=2, PROXY_SOCKS4a=3. Sockets (CSocketClientProxy / CDatagramSocketProxy)
run a proxy state machine before the real payload. Constants (Proxy.h):
SOCKS4: VERSION 0x04, CMD_CONNECT 0x01, CMD_BIND 0x02; replies granted 90, failed
91, no-identd 92, different-userids 93 (Proxy.h:43-52).
SOCKS5 (RFC1928/1929): VERSION 0x05; auth methods NO_AUTH 0x00, GSSAPI 0x01,
USER_PASS 0x02, NO_ACCEPTABLE 0xFF; user/pass auth version 0x01; cmds CONNECT 0x01,
BIND 0x02, UDP_ASSOCIATE 0x03; RSV 0x00; ATYP IPv4 0x01, DOMAIN 0x03, IPv6 0x04;
replies SUCCEED 0x00, general-fail 0x01, not-allowed 0x02, net-unreach 0x03,
host-unreach 0x04, conn-refused 0x05 (Proxy.h:66-90). HTTP proxy uses CONNECT with
up to HTTP_MAX_STATES=5 states (Proxy.h:373). Standard behavior; Rust `tokio-socks`
or a hand-rolled state machine covers it. Proxy is optional for a v1 engine.

================================================================
## 11. AsyncDNS (AsyncDNS.cpp)
================================================================
Trivial: a detached wxThread that resolves a hostname to u32 via
StringHosttoUint32 and posts a wx event (DNS_UDP -> wxEVT_CORE_UDP_DNS_DONE,
DNS_SOURCE -> wxEVT_CORE_SOURCE_DNS_DONE, DNS_SERVER_CONNECT ->
wxEVT_CORE_SERVER_DNS_DONE) carrying the resolved IP as ExtraInt64
(AsyncDNS.cpp:44-75). In Rust: async DNS resolution (tokio) returning the IPv4 as
u32; no wire protocol involved.

================================================================
## Crypto crate mapping (Rust)
================================================================
- MD5 (16 bytes): `md-5`. MD4 user hashes are just 16 opaque bytes (no MD4 compute
  needed for these paths; ed2k file hashing needs MD4 = `md4` crate, out of scope).
- RC4-drop1024: hand-roll (30 lines) or `rc4` + manual 1024 discard.
- SHA-1 (secure ident signatures): `sha1`.
- RSA PKCS#1 v1.5 sign/verify, 384-bit keys, DER key material: `rsa` + `pkcs1`/`der`
  + `base64` for cryptkey.dat.
- Diffie-Hellman mod p (768-bit fixed prime, g=2, 128-bit exponent): `num-bigint`
  (modpow) or `crypto-bigint`.
- CSPRNG: `getrandom`/`rand`.
- zlib (EC): `flate2`.
- UPnP IGD: `igd-next`.


### Key constants (as reported)

- MAGICVALUE_REQUESTER = 34 (0x22)  src/EncryptedStreamSocket.cpp:98
- MAGICVALUE_SERVER = 203 (0xCB)  src/EncryptedStreamSocket.cpp:99
- MAGICVALUE_SYNC = 0x835E6FC4  src/EncryptedStreamSocket.cpp:100
- DHAGREEMENT_A_BITS = 128, PRIMESIZE_BYTES = 96, g = 2  src/EncryptedStreamSocket.cpp:101-113
- RC4 drop = 1024 bytes for TCP, 0 for UDP  src/RC4Encrypt.cpp:138-140
- CRYPT_HEADER_WITHOUTPADDING = 8  src/EncryptedDatagramSocket.cpp:109
- MAGICVALUE_UDP = 91 (0x5B)  src/EncryptedDatagramSocket.cpp:110
- MAGICVALUE_UDP_SYNC_CLIENT = 0x395F2EC1, MAGICVALUE_UDP_SYNC_SERVER = 0x13EF24D5  src/EncryptedDatagramSocket.cpp:111-112
- MAGICVALUE_UDP_SERVERCLIENT = 0xA5, MAGICVALUE_UDP_CLIENTSERVER = 0x6B  src/EncryptedDatagramSocket.cpp:113-114
- Protocol first-byte markers: OP_EDONKEYPROT=0xE3 OP_PACKEDPROT=0xD4 OP_EMULEPROT=0xC5 OP_KADEMLIAHEADER=0xE4 OP_KADEMLIAPACKEDPROT=0xE5 OP_UDPRESERVEDPROT1=0xA3 OP_UDPRESERVEDPROT2=0xB2  src/include/protocol/Protocols.h:34-45
- RSAKEYSIZE = 384 bits  src/include/protocol/ed2k/Constants.h:49
- MAXPUBKEYSIZE = 80  src/ClientCredits.h:31; CREDITFILE_VERSION = 0x12  src/include/common/DataFileVersion.h:40
- Secure ident opcodes: OP_PUBLICKEY=0x85 OP_SIGNATURE=0x86 OP_SECIDENTSTATE=0x87 (under OP_EMULEPROT 0xC5)  src/include/protocol/ed2k/Client2Client/TCP.h:75-78
- CRYPT_CIP_REMOTECLIENT=10 LOCALCLIENT=20 NONECLIENT=30  src/ClientCredits.h:33-35
- EC header = 8 bytes: flags u32 + length u32, both network order  src/libs/ec/cpp/ECSocket.h:80, ECSocket.cpp:564-569
- EC flag base 0x20; EC_FLAG_ZLIB=0x01 UTF8_NUMBERS=0x02 LARGE_TAG_COUNT=0x10 UNKNOWN_MASK=0xff7f7f08; validity ((flags&0x60)!=0x20)  src/libs/ec/abstracts/ECCodes.abstract:28-31, ECSocket.cpp:1000
- EC_MAX_UNCOMPRESSED = 1024; max packet 16MiB pre-auth / 256MiB post-auth  src/libs/ec/cpp/ECSocket.cpp:40,577-579
- EC_CURRENT_PROTOCOL_VERSION = 0x0204  src/libs/ec/abstracts/ECCodes.abstract:20
- EC tag name wire = (name<<1)|hasChildrenBit; taglen includes children  src/libs/ec/cpp/ECTag.cpp:423,465,607
- EC tag types: UNKNOWN0 CUSTOM1 UINT8=2 UINT16=3 UINT32=4 UINT64=5 STRING6 DOUBLE7 IPV4=8 HASH16=9 UINT128=10  src/libs/ec/abstracts/ECTagTypes.abstract:10-20
- EC auth opcodes: AUTH_REQ=0x02 AUTH_FAIL=0x03 AUTH_OK=0x04 AUTH_SALT=0x4F AUTH_PASSWD=0x50  src/libs/ec/abstracts/ECCodes.abstract
- EC password hash = MD5(lower(hex(MD5(plaintext))) + MD5(uppercaseHex(u64 salt)))  src/ExternalConn.cpp:638-643, RemoteConnect.cpp:324-325
- CORE_TIMER_PERIOD = 300 (daemon) / 100 (gui) ms  src/amule.h:104,107
- Timer intervals: 1s clientlist/credits/sharedfiles/kad, 5s listensocket, 60s stats save, 30min known.met, 13min clients.met  src/amule.cpp:1452,1483,1488,1499 + ClientCreditsList.cpp:244
- Default ports: TCP 4662, client/Kad UDP 4672, EC 4712; server UDP = TCP+3 (4665)  src/Preferences.cpp:72-73,1244; amule.cpp:974,984,1009
- User hash: random 16 bytes with byte[5]=14 and byte[14]=111 client marker  src/Preferences.cpp:1049-1077
- UPnP 4 mappings (ECPort TCP, TCP+3 UDP, TCP port TCP, UDP port UDP); AddPortMapping NewLeaseDuration=0  src/amule.cpp:1021-1040, UPnPBase.cpp:1085-1111
- IPFilter length encode: <=0x7FFF exact len-1; else ((len-1)>>12)|0x8000 decode ((v&0x7FFF)<<12)+0xFFF  src/IPFilter.cpp:161-172,447-449
- Proxy types: PROXY_NONE=-1 SOCKS5=0 SOCKS4=1 HTTP=2 SOCKS4a=3  src/Proxy.h:103-108


### Flagged unclear (by the recon agent)

- cryptkey.dat exact DER layout: Crypto++ RSASSA_PKCS1v15_SHA_Signer.DEREncode writes the full private key (Crypto++ encodes RSAFunction private key as a DER SEQUENCE of n,e,d,p,q,dP,dQ,u = PKCS#1 RSAPrivateKey WITHOUT version field in some Crypto++ versions). Must byte-verify a real cryptkey.dat against Rust `rsa` DER decode before claiming interop; the public-key blob saved via GetMaterial().Save is an X.509 SubjectPublicKeyInfo but its exact ~59-64 byte length for 384-bit keys should be confirmed against a real clients.met.
- Password salt formatting uses C `printf("%lX", uint64 salt)`. On 64-bit Unix `long` is 64-bit so this is the full u64 uppercase hex with no padding; on 32-bit platforms `%lX` would only format 32 bits. Confirm the target/interop platform is 64-bit (aMule is effectively 64-bit today) before fixing the Rust formatting to full-u64 uppercase hex.
- EC integer tag payload endianness vs UTF8_NUMBERS: confirmed that tag DATA (m_tagData) is always raw big-endian and only structural numbers are UTF-8-number-encoded, but this should be validated end-to-end with a captured amulegui session because a mis-split here breaks every packet.
- The exact bit meaning of the UDP marker low-2-bits selection heuristic (bufIn[0]&0x03) is only a hint for which key to try first; old clients randomize it. A correct receiver must try all applicable keys (ed2k, kad-nodeid, kad-recvkey) up to 3 rounds; verify the try-order rotation `(currentTry+1)%3` matches for all initial marker values.
- GetSecureWaitStartTime / credit waiting-time logic (ClientCredits.cpp:234-266) governs upload queue fairness; not fully documented here since it is policy not wire-format. Revisit if the Rust engine implements the upload queue scheduler.
- CEC_*_Tag encoder classes (CEC_SharedFile_Tag, CEC_PartFile_Tag, CEC_UpDownClient_Tag, CEC_Server_Tag, CEC_Search_Tag, CEC_Prefs_Packet, CEC_ConnState_Tag) in ECSpecialCoreTags.cpp/ECSpecialMuleTags.cpp define exactly which child tags populate each object; the per-field tag lists were not enumerated here and must be read from those files to build byte-identical responses (RLE encoding of part/gap/req status via RLE_Data is also defined there).


==============================================================================

## SUBSYSTEM: aMule 3.0.1 on-disk file formats and hashing (ED2K/MD4, AICH/SHA1, known.met, part.met, known2_64.met, server.met, nodes.dat, canceled.met, clients.met, preferences/statistics/ipfilter)

# aMule 3.0.1 on-disk formats and hashing (byte-level spec)

Source root: /home/ajbufort/claude-projects/padMule/amule-3.0.1

## 0. Primitive encodings (CFileDataIO, src/SafeFile.cpp)

All integers are little-endian on disk: WriteUInt8/16/32/64 at SafeFile.cpp:265-292 (ENDIAN_SWAP_* are no-ops on LE hosts). MD4 hash = 16 raw bytes (SafeFile.cpp:307-310). AICH hash = 20 raw bytes (SHAHashSet.cpp:71-74). Float32 = 4 bytes byte-swapped as a uint32 (SafeFile.cpp:313-320). Kad UInt128 = four uint32 chunks, chunk 0 = most-significant 32 bits, each chunk LE, chunks written MSB-chunk first (SafeFile.cpp:295-304, kademlia/utils/UInt128.h:107-121).

Strings (WriteString/WriteStringCore, SafeFile.cpp:330-405): length prefix uint16 (default) or uint32, then bytes, NO NUL terminator. Encoding utf8strRaw = UTF-8 bytes; utf8strOptBOM = 3-byte BOM EF BB BF prepended and INCLUDED in the length; utf8strNone = Latin-1 bytes. Read side auto-detects BOM (SafeFile.cpp:37,247-259) and falls back UTF-8 then Latin-1.

MET-format tag (CFileDataIO::WriteTag, SafeFile.cpp:513-570; read CTag::CTag(CFileDataIO&,bool) Tag.cpp:85-189):
- uint8 tagtype
- name: if numeric ID: uint16 = 1, then uint8 nameID. If string name: uint16 len + Latin-1 bytes. (Read side also accepts the compact network form type|0x80 + uint8 nameID, Tag.cpp:93-95, but the file writers never produce it.)
- payload by type: STRING(0x02)= uint16 len + UTF-8 bytes (WriteTag hardcodes utf8strRaw); UINT8(0x09)=1B; UINT16(0x08)=2B; UINT32(0x03)=4B; UINT64(0x0B)=8B; HASH16(0x01)=16B; FLOAT32(0x04)=4B; BSOB(0x0A)=uint8 len + bytes; BLOB(0x07)=uint32 len + bytes.
CRITICAL byte-compat fact: CTag::WriteTagToFile ignores its EUtf8Str argument (declared WXUNUSED, Tag.cpp:394-409) and always delegates to WriteTag, which writes strings utf8strRaw (no BOM). Every place in the code that passes utf8strOptBOM "for eMule compatibility" (KnownFile.cpp:797, PartFile.cpp:921, ServerList.cpp:756-788) therefore actually writes a plain UTF-8 string with NO BOM; the doubled tags become byte-identical twins except where the string source differs. Readers must still accept BOM-prefixed strings (files written by eMule).
- CTagIntSized/CTagInt32 etc. write EXACTLY the declared width (Tag.h:112-155); met-file ints are never shrunk to smallest type (unlike the wire format WriteNewEd2kTag, Tag.cpp:312-392).

CFile open modes (src/CFile.cpp:240-272,298-322): write_safe writes to "<name>.new" and atomically renames over the target in Close(). Used by known.met, server.met, nodes.dat. write = O_CREAT|O_TRUNC; write_excl = O_CREAT|O_EXCL.

## 1. ED2K / MD4 file hashing (CERTAIN, including the exact-multiple rule)

Algorithm (CHashingTask::Entry + CreateNextPartHash, src/ThreadTasks.cpp:83-253; CKnownFile::CreateHashFromInput, src/KnownFile.cpp:888-967):
- MD4 (RFC1320, via CryptoPP::Weak::MD4, KnownFile.cpp:963-966) over each PARTSIZE=9728000-byte part; last part = fileSize % PARTSIZE bytes, or PARTSIZE bytes when fileSize is an exact multiple (SetFileSize, KnownFile.cpp:451-478: m_iPartCount = size/PARTSIZE + 1, m_sizeLastPart = size % PARTSIZE; if remainder 0 then m_sizeLastPart = PARTSIZE and m_iPartCount is decremented, so data parts n = ceil(size/PARTSIZE)).
- EXACT-MULTIPLE RULE (stated with certainty, two concordant sources): after hashing the final data part, if (partLength == PARTSIZE && file.Eof()) an extra part hash is appended equal to MD4 of zero bytes = 31D6CFE0D16AE931B73C59D7E0C089C0 (ThreadTasks.cpp:243-249, constant at ThreadTasks.cpp:45-47). So a file of exactly k*PARTSIZE bytes has k+1 part hashes, the last being the empty-MD4 sentinel. Reference vectors with real hashes for 1x, 2x, 3x PARTSIZE are in the comment block KnownFile.cpp:394-449 (e.g. size==PARTSIZE: file hash A72CA8DF7F07154E217C236C89C17619, hashes 4891ED2E5C9C49F442145A3A5F608299 + sentinel).
- Final file hash: if the hashlist has exactly 1 entry (fileSize < PARTSIZE... strictly: fileSize <= PARTSIZE-1, since an exact single part gets the sentinel appended and has 2 entries) the file hash IS that single part MD4 and the hashlist is cleared; otherwise fileHash = MD4(concatenation of all part hashes, 16 bytes each, in order, INCLUDING the sentinel) (ThreadTasks.cpp:167-181; CreateHashFromHashlist KnownFile.cpp:861-873).
- Derived counts (KnownFile.cpp:460-477): m_iPartCount (data parts) = ceil(size/PARTSIZE); m_iED2KPartCount (OP_FILESTATUS) = size/PARTSIZE + 1; m_iED2KPartHashCount (hashset exchange and known.met) = size/PARTSIZE, plus 1 if nonzero. Table at KnownFile.cpp:443-449. So on disk: size < PARTSIZE stores 0 part hashes; size == k*PARTSIZE stores k+1; otherwise k+1 where k = floor(size/PARTSIZE).
- Load validation: LoadFromFile requires stored hash count == GetED2KPartHashCount() (KnownFile.cpp:740); LoadHashsetFromFile recomputes MD4-of-hashlist and compares to the stored file hash when >1 hashes (KnownFile.cpp:557-599).
- MAX_FILE_SIZE guard 0x4000000000 (ThreadTasks.cpp:103); zero-size shared files are never hashed (ThreadTasks.cpp:107-118).

## 2. AICH (SHA-1 hash tree), known2_64.met, recovery packets

Hash algo: SHA-1 (CSHA implements CAICHHashAlgo, SHAHashSet.cpp:950-953; SHA1_DIGEST_SIZE 20, src/SHA.h:90-91). HASHSIZE=20 (SHAHashSet.h:84).

Tree shape (SHAHashSet.h:27-70 comment; CAICHHashTree::FindHash SHAHashSet.cpp:104-152): root covers the whole file (m_nDataSize = fileSize; m_nBaseSize = PARTSIZE if fileSize > PARTSIZE else EMBLOCKSIZE, SHAHashSet.cpp:972-976; root constructed as a LEFT branch, SHAHashSet.cpp:466-471). It is NOT a plain complete binary tree: the split of a node with nDataSize into left/right is nBlocks = ceil(nDataSize/nBaseSize); nLeft = floor((isLeftBranch ? nBlocks+1 : nBlocks)/2) * nBaseSize; nRight = nDataSize - nLeft (SHAHashSet.cpp:120-122; identical formula repeated at 296-298, 379-381, 432-434). Child base size = EMBLOCKSIZE if childSize <= PARTSIZE else PARTSIZE (SHAHashSet.cpp:130,144). Recursion stops when nDataSize <= nBaseSize (leaf = one 180 KiB block, or the tail block). PARTSIZE-level nodes exist as a fixed layer so a part hash can be addressed like MD4 parts. There is NO trailing empty part in AICH; tree covers exactly fileSize bytes.
- Leaf hashes: SHA-1 of each EMBLOCKSIZE=184320-byte block of the part (last block shorter). Computed inline during MD4 hashing in CreateHashFromInput (KnownFile.cpp:899-960) feeding CAICHHashTree::SetBlockHash (SHAHashSet.cpp:257-276); per-part subtree is located via FindHash(partOffset, partLen) (ThreadTasks.cpp:230-237).
- Internal node hash: SHA1(leftChildHash20 || rightChildHash20) (ReCalculateHash, SHAHashSet.cpp:159-184). Master hash = root hash. For a file <= 184320 bytes the master hash is simply SHA1(file data).
- Master hash textual form (FT_AICH_HASH tag, ed2k AICH links): base32, alphabet ABCDEFGHIJKLMNOPQRSTUVWXYZ234567, 20 bytes -> exactly 32 chars, no padding (CAICHHash::GetString SHAHashSet.cpp:59-62; EncodeBase32 OtherFunctions.cpp:398-425, alphabet OtherFunctions.cpp:310).

known2_64.met (hashset store; filename constants SHAHashSet.h:85-87): byte 0 = 0x02 (KNOWN2_MET_VERSION), then 0..n records appended, each: [20-byte master hash][uint32 nHashCount][nHashCount * 20-byte lowest-level block hashes, strict left-to-right, no identifiers] (SaveHashSet SHAHashSet.cpp:701-790; WriteLowestLevelHashs with bNoIdent=true SHAHashSet.cpp:342-368; LoadHashSet 793-928). nHashCount = 53*floor(size/PARTSIZE) + ceil((size % PARTSIZE)/184320) (SHAHashSet.cpp:762-765; 53 = ceil(9728000/184320)). Records are dedup-appended keyed by master hash. Legacy known2.met: NO version byte, same record layout but uint16 nHashCount; converter at ThreadTasks.cpp:454-516.

AICH recovery-data packet (V2 layout comment SHAHashSet.cpp:543-548; CreatePartRecoveryData SHAHashSet.cpp:478-534 and tree walk 279-321):
- Normal files (16-bit idents): uint16 count, then count * (uint16 ident + 20B hash), then trailing uint16 0 (the empty 32-bit section).
- Large files (IsLargeFile, > OLD_MAX_FILE_SIZE): leading uint16 0 (empty 16-bit section), uint16 count, then count * (uint32 ident + 20B hash).
- count = (nLevel-1) + ceil(partSize/EMBLOCKSIZE), where nLevel = depth of the part node counted by FindHash incrementing once per visited node including root (SHAHashSet.cpp:498-501). Content = the SIBLING hash at every level along the root-to-part path (written by WriteHash during descent, SHAHashSet.cpp:303-317) followed by all leaf hashes of the part subtree left-to-right, each with its ident.
- Ident encoding: path bits accumulated as ident = (ident << 1) | (isLeftBranch ? 1 : 0) starting from 0 at the root; the root itself is left so the master hash is ident 1; the receiver finds the highest set bit to determine depth (SetHash SHAHashSet.cpp:399-451). Ident 1 (master) may never be overwritten; 32-bit idents also rejected above 0x400000 (SHAHashSet.cpp:569,593-594).

When AICH repairs a part (src/PartFile.cpp): a completed part whose MD4 part hash fails is gapped, listed in m_corrupted_list, and RequestAICHRecovery(part) runs (PartFile.cpp:3564-3579). Preconditions: master hash valid and status AICH_TRUSTED or AICH_VERIFIED, and part size > EMBLOCKSIZE (PartFile.cpp:3816-3822). Trust of a received master hash requires >= 10 unique IPs (masked dwIP &= 0x00F0FFFF, SHAHashSet.cpp:456-459) and >= 92 percent agreement (SHAHashSet.cpp:45-46,1021-1022), or the IsTrustingEveryHash pref. On recovery data arrival, AICHRecoveryDataAvailable (PartFile.cpp:3895-4013) rehashes the on-disk part into a scratch subtree, compares each 180 KiB block hash to the verified tree, FillGap()s matching blocks so only bad blocks are redownloaded, and if the part becomes complete cross-checks with MD4 HashSinglePart before accepting.

## 3. known.met (src/KnownFileList.cpp, CKnownFile::WriteToFile/LoadFromFile src/KnownFile.cpp:723-858)

File: config dir + "known.met" (KnownFileList.cpp:86), written via write_safe. Layout: uint8 header = 0x0E, or 0x0F if ANY record has size > OLD_MAX_FILE_SIZE (written as placeholder 0 first, patched by Seek(0) before close, KnownFileList.cpp:218,240-241); uint32 record count; records (duplicates first, KnownFileList.cpp:222-238).

Record (WriteToFile KnownFile.cpp:745-858):
1. uint32 date = m_lastDateChanged = mtime (seconds) of the shared file at hashing time (ThreadTasks.cpp:125, LoadDateFromFile KnownFile.cpp:715-720).
2. 16B file MD4 hash; uint16 part-hash count; count * 16B part hashes (must equal ED2KPartHashCount, i.e. includes the empty-MD4 sentinel for exact multiples, 0 for sub-part files).
3. uint32 tagcount, then tags. Fixed 9 tags in order: FT_FILENAME(0x01) STRING = filename (GetRaw; nominally BOM but actually plain UTF-8, see section 0); FT_FILENAME again = CPath::ToUniv form (raw filesystem bytes decoded as Latin-1 then re-encoded UTF-8; Path.cpp:302-309); FT_FILESIZE as UINT32, or UINT64 iff IsLargeFile (KnownFile.cpp:805-806); FT_ATTRANSFERRED(0x50) UINT32 = low 32 of lifetime uploaded; FT_ATTRANSFERREDHI(0x54) UINT32 = high 32; FT_ATREQUESTED(0x51) UINT32; FT_ATACCEPTED(0x52) UINT32; FT_ULPRIORITY(0x19) UINT32 (PR_AUTO if auto); FT_LASTSEEN(0x28) UINT32 epoch (aMule-3.x-specific TTL tag, FileTags.h:55-59). Optional: FT_AICH_HASH(0x27) STRING base32 master hash when HasProperAICHHashSet (status HASHSETCOMPLETE or VERIFIED, KnownFile.cpp:1680-1687); FT_KADLASTPUBLISHSRC(0x21) / FT_KADLASTPUBLISHNOTES(0x26) UINT32 when nonzero; then any retained foreign tags that are Int or Str only (float tags deliberately not written, KnownFile.cpp:766-779).

## 4. part.met / .part (src/PartFile.cpp)

Names: temp dir, NNN.part (data), NNN.part.met, NNN.part.met.bak (previous met promoted by rename), NNN.part.met.seeds (CreatePartFile PartFile.cpp:341-381; save/rename dance 864-1052).

part.met write (SavePartFile PartFile.cpp:820-1053):
1. uint8 version = 0xE0 (PARTFILE_VERSION) or 0xE2 (PARTFILE_VERSION_LARGEFILE) iff size > OLD_MAX_FILE_SIZE (line 881). 0xE1 is only read (edonkey import).
2. uint32 date = mtime of the .part DATA file (line 883); on load a mismatch with the actual .part mtime forces a rehash (lines 781-797).
3. 16B file hash; uint16 count; count * 16B part hashes (m_hashlist; may be 0 if hashset not yet fetched; includes sentinel rule as above).
4. uint32 tagcount = 15 fixed + m_taglist.size() + 2*gapcount + optionals (lines 892-914). Fixed 15 in order (921-950): FT_FILENAME STRING printable name; FT_FILENAME again (identical bytes in practice); FT_FILESIZE UINT32/UINT64(large); FT_TRANSFERRED UINT32/UINT64(large); FT_STATUS UINT32 (1 = paused else 0); FT_DLPRIORITY UINT32 and FT_OLDDLPRIORITY(0x13) UINT32 (PR_AUTO if auto); FT_LASTSEENCOMPLETE(0x05) UINT32; FT_ULPRIORITY and FT_OLDULPRIORITY(0x17) UINT32; FT_CATEGORY(0x53) UINT32; FT_ATTRANSFERRED, FT_ATTRANSFERREDHI, FT_ATREQUESTED, FT_ATACCEPTED UINT32. Optionals: FT_CORRUPTEDPARTS(0x24) STRING = comma-separated decimal part numbers (953-966); FT_AICH_HASH STRING iff master hash valid AND status == AICH_VERIFIED (969-972); FT_KADLASTPUBLISHSRC, FT_KADLASTPUBLISHNOTES, FT_DL_ACTIVE_TIME(0x23) UINT32 when nonzero; then m_taglist extras.
5. GAP LIST (990-1004): for gap i (ascending file order), two tags named by 2+ char STRINGS: name[0] = byte 0x09 (FT_GAPSTART) or 0x0A (FT_GAPEND), followed by ASCII decimal of i ("\x09" "0", "\x0A" "0", "\x09" "1"...). Values are CTagIntSized UINT32, or UINT64 iff large file. SEMANTICS: FT_GAPSTART value = offset of first missing byte (inclusive); FT_GAPEND value = it.end() + 1 = first byte NOT missing (EXCLUSIVE end). Internally CGapList stores inclusive [start,end] (GapList.h:32-35, iterator 89-105); the loader converts back with gap->end = value - 1 (PartFile.cpp:626-627) and clips end >= fileSize to fileSize-1 (714-721). Gaps are ranges still MISSING. A freshly created download is one gap [0, fileSize) i.e. GAPSTART 0, GAPEND fileSize.
Load quirks (LoadPartFile PartFile.cpp:384-817): version 0xE0 files whose bytes 24..27 == 00 00 02 01 are treated as edonkey "newold" style (435-445); gap tags keyed by the decimal suffix are merged from a map so order/duplication is tolerated; unknown tags kept in m_taglist; missing trailing file range is auto-gapped from actual .part length (743-750); over-long .part is truncated.

.part data file: created either as a normal empty file (grows on write; optionally preallocated full-size by CAllocateFileTask when AllocFullFile pref) or as a sparse file of full logical size via PlatformSpecific::CreateSparseFile when CreateFilesSparse pref (PartFile.cpp:356-366). Readers must not rely on physical size; logical length <= fileSize.

.seeds file (SaveSourceSeeds PartFile.cpp:1056-1154): uint8 0 (v3 marker), uint8 count, per source: uint32 userID(hybrid), uint16 port, 16B userhash, uint8 cryptoptions bitfield (bit0 supports, bit1 requests, bit2 requires); trailing uint32 epoch save time. Loader also accepts v1 (first byte = count, 6-byte entries, no time).

## 5. server.met (src/ServerList.cpp:94-197 load, 689-825 save)

Header uint8 0xE0 (save; load also accepts 0x0E); uint32 server count; per server: uint32 IP, uint16 port, uint32 tagcount, then MET-format tags. Written tags in order (750-807): ST_SERVERNAME STRING twice when non-empty (both plain UTF-8 in practice); ST_DYNIP STRING twice; ST_DESCRIPTION STRING twice; ST_AUXPORTSLIST(0x93) STRING iff connport != port; then UINT32 tags ST_FAIL, ST_PREFERENCE, string-named "users", string-named "files", ST_PING, ST_LASTPING(0x90), ST_MAXUSERS(0x87), ST_SOFTFILES(0x88), ST_HARDFILES(0x89); ST_VERSION STRING twice when non-empty; ST_UDPFLAGS(0x92), ST_LOWIDUSERS(0x94) UINT32; optional ST_UDPKEY(0x95), ST_UDPKEYIP(0x96) UINT32; optional ST_TCPPORTOBFUSCATION(0x97), ST_UDPPORTOBFUSCATION(0x98) UINT16. tagcount arithmetic at 706-748. Written via write_safe with prior rename of old file to server.met.bak (812-817).

## 6. nodes.dat (src/kademlia/routing/RoutingZone.cpp:135-341)

Write (v2, lines 308-335): uint32 0 (guard against pre-v1 readers), uint32 2 (version), uint32 contact count, then per contact: 16B UInt128 client ID (chunked encoding, section 0), uint32 IP, uint16 UDP port, uint16 TCP port, uint8 kad version, 8B CKadUDPKey = uint32 key + uint32 ip (kademlia/utils/KadUDPKey.h:48-49), uint8 verified flag. Entry = 34 bytes. Read (135-226): if first uint32 != 0 it is a v0 count (rejected); else uint32 fileVersion; version 3 + next uint32 == 1 means bootstrap-style nodes.dat (25-byte v1 entries, no key/verified, RoutingZone.cpp:228-289); versions 1..3 then read uint32 count; entries as above, key+verified only when fileVersion >= 2. Note: contact IPs stored in eMule convention; aMule applies wxUINT32_SWAP_ALWAYS before validity checks (line 194), so preserve the stored uint32 verbatim when round-tripping.

## 7. canceled.met (src/CanceledFileList.cpp)

uint8 0x21 (CANCELEDFILE_VERSION); uint32 count; count * 16-byte MD4 hashes (of the canceled files). Load rejects other versions.

## 8. clients.met + cryptkey.dat (src/ClientCreditsList.cpp:65-219)

clients.met: uint8 0x12 (CREDITFILE_VERSION); uint32 count (written as 0 placeholder, patched via Seek(1) at end, lines 186-212); per record 102 bytes: 16B user hash key, uint32 uploaded_lo, uint32 downloaded_lo, uint32 nLastSeen (epoch), uint32 uploaded_hi, uint32 downloaded_hi, uint16 nReserved3, uint8 nKeySize, 80B abySecureIdent (public key, garbage beyond nKeySize). Records with 150-day-stale nLastSeen are dropped on load. cryptkey.dat: base64 (Crypto++ Base64) DER RSA private key, RSAKEYSIZE 384 bits (ClientCreditsList.cpp:305-312, ed2k Constants.h:49).

## 9. preferences and misc .dat files

- preferences.dat (Preferences.cpp:1034-1072, Save 1626-1647): uint8 0x14 (PREFFILE_VERSION) + 16B userhash. Only these 17 bytes. Userhash bytes 5 and 14 are forced to 14 and 111 in memory (eMule marker) after load (1076-1077).
- amule.conf: wxFileConfig INI ([Section] / Key=Value lines) via CamuleFileConfig (CamuleFileConfig.h:41-80). Key names are built in CPreferences::BuildItemList (Preferences.cpp:1094 onward), e.g. /eMule/Nick, /Browser/OpenPageInTab, /eMule/KadNodesUrl (1400). Not a binary format; full key inventory not enumerated here.
- shareddir.dat, shareddir-explicit.dat, shareddir-recursive.dat: UTF-8 text, one directory path per line (SaveSharedFolders Preferences.cpp:1650-1672); shareddir.dat is regenerated as the union for backward compat.
- addresses.dat: text, one server-list URL per line (Preferences.cpp:1084-1087).
- statistics.dat (Statistics.cpp:291-324): uint8 0 (version) + uint64 totalSent + uint64 totalReceived.

## 10. ipfilter.dat / ipfilter_static.dat (src/IPFilter.cpp, src/IPFilterScanner.l)

Text file (possibly delivered zipped; UnpackArchive tried first, IPFilter.cpp:298). Two accepted line grammars (IPFilterScanner.l:108-143): PeerGuardian "IP1 - IP2 , level , description" and AntiP2P "description : IP1 - IP2" (level defaults 0). Lines starting with # (after optional whitespace) are comments; malformed lines counted and skipped. A range is filtered iff its access level < the user pref IPFilterLevel (IPFilter.cpp:143). Files loaded: config ipfilter.dat, then ipfilter_static.dat (IPFilter.cpp:113-130). This is input-only; aMule writes only placeholder comment headers when creating empty files (IPFilter.cpp:375-390).

## 11. Large-file (64-bit) impact summary

IsLargeFile() = size > 4290048000 (KnownFile.h:115). Changes: part.met version byte 0xE2; FT_FILESIZE, FT_TRANSFERRED and all gap tags written as TAGTYPE_UINT64 (PartFile.cpp:881,924-925,998-1001); known.met header 0x0F when any record is large and its FT_FILESIZE becomes UINT64 (KnownFileList.cpp:241, KnownFile.cpp:805); AICH recovery packets switch to 32-bit hash identifiers with the leading empty 16-bit section (SHAHashSet.cpp:502-528); known2_64.met already uses uint32 hash counts for all files. server.met, canceled.met, clients.met, nodes.dat are unaffected.


### Key constants (as reported)

- PARTSIZE = 9728000 (src/include/protocol/ed2k/Constants.h:82)
- BLOCKSIZE = EMBLOCKSIZE = 184320 (180 KiB) (src/include/protocol/ed2k/Constants.h:83-84)
- OLD_MAX_FILE_SIZE = 4290048000 (largefile threshold, strictly greater-than) (Constants.h:77, KnownFile.h:115)
- MAX_FILE_SIZE = 0x4000000000 (256 GiB) (Constants.h:80)
- empty-MD4 sentinel part hash = 31D6CFE0D16AE931B73C59D7E0C089C0 (src/ThreadTasks.cpp:45-47)
- PARTFILE_VERSION = 0xE0, PARTFILE_SPLITTEDVERSION = 0xE1, PARTFILE_VERSION_LARGEFILE = 0xE2 (src/include/common/DataFileVersion.h:33-37)
- MET_HEADER = 0x0E, MET_HEADER_WITH_LARGEFILES = 0x0F (DataFileVersion.h:43-46)
- CANCELEDFILE_VERSION = 0x21 (DataFileVersion.h:49)
- PREFFILE_VERSION = 0x14 (DataFileVersion.h:30)
- CREDITFILE_VERSION = 0x12 (DataFileVersion.h:40)
- KNOWN2_MET_VERSION = 0x02, HASHSIZE = 20, files known2_64.met / known2.met (src/SHAHashSet.h:84-87)
- server.met written with header byte 0xE0 (src/ServerList.cpp:700); load accepts 0xE0 or 0x0E (ServerList.cpp:125)
- nodes.dat: leading uint32 0, then uint32 version 2 on write (src/kademlia/routing/RoutingZone.cpp:313-315)
- TAGTYPE_HASH16=0x01 STRING=0x02 UINT32=0x03 FLOAT32=0x04 BLOB=0x07 UINT16=0x08 UINT8=0x09 BSOB=0x0A UINT64=0x0B STR1..STR16=0x11..0x20 (src/include/tags/TagTypes.h:29-58)
- FT_FILENAME=0x01 FT_FILESIZE=0x02 FT_TRANSFERRED=0x08 FT_GAPSTART=0x09 FT_GAPEND=0x0A FT_STATUS=0x14 FT_DLPRIORITY=0x18 FT_ULPRIORITY=0x19 FT_KADLASTPUBLISHSRC=0x21 FT_DL_ACTIVE_TIME=0x23 FT_CORRUPTEDPARTS=0x24 FT_KADLASTPUBLISHNOTES=0x26 FT_AICH_HASH=0x27 FT_LASTSEEN=0x28 FT_ATTRANSFERRED=0x50 FT_ATREQUESTED=0x51 FT_ATACCEPTED=0x52 FT_CATEGORY=0x53 FT_ATTRANSFERREDHI=0x54 (src/include/tags/FileTags.h:30-70)
- ST_SERVERNAME=0x01 ST_DESCRIPTION=0x0B ST_PING=0x0C ST_FAIL=0x0D ST_PREFERENCE=0x0E ST_DYNIP=0x85 ST_LASTPING=0x90 ST_VERSION=0x91 ST_UDPFLAGS=0x92 ST_AUXPORTSLIST=0x93 ST_LOWIDUSERS=0x94 ST_UDPKEY=0x95 ST_UDPKEYIP=0x96 ST_TCPPORTOBFUSCATION=0x97 ST_UDPPORTOBFUSCATION=0x98 (src/include/tags/ServerTags.h:30-53)
- AICH trust thresholds: MINUNIQUEIPS_TOTRUST=10, MINPERCENTAGE_TOTRUST=92 (src/SHAHashSet.cpp:45-46)
- MAXPUBKEYSIZE = 80 (src/ClientCredits.h:31)
- base32 alphabet ABCDEFGHIJKLMNOPQRSTUVWXYZ234567, no padding (src/OtherFunctions.cpp:310,398)
- blocks per full part = ceil(9728000/184320) = 53


### Flagged unclear (by the recon agent)

- Old-format known2.met (pre-64-bit): the aMule converter (ThreadTasks.cpp:454-516) reads it with NO leading version byte (record stream starts at offset 0, uint16 hash counts). Verify against an actual eMule-written known2.met before implementing a reader; also note the converter's loop condition compares newfile position to oldfile length (ThreadTasks.cpp:490), which only works because the new file is the same size + 1 byte header + 2 extra bytes per record; do not replicate that logic literally.
- nodes.dat contact IP byte order: stored uint32 is used with wxUINT32_SWAP_ALWAYS for validity checks (RoutingZone.cpp:194), meaning the on-disk value is byte-swapped relative to aMule's in-memory convention. For byte compatibility treat it as an opaque round-tripped uint32 matching eMule; confirm endianness against a real eMule nodes.dat if the Rust code must interpret (not just store) the IP.
- amule.conf: full key/default inventory (several hundred entries across BuildItemList and s_MiscList, Preferences.cpp:1094-1620) was not enumerated; wxFileConfig quoting/escaping rules (backslash escapes, quoted values with leading/trailing spaces) must be matched if byte-identical .conf output is required.
- part.met PMT_SPLITTED (0xE1) and PMT_NEWOLD import layouts (PartFile.cpp:432-461,644-662) are read-only legacy paths documented here only partially; if the Rust port must import eDonkey/hybrid part.mets, map those formats from an actual sample.
- The doubled string tags (FT_FILENAME, ST_SERVERNAME/ST_DYNIP/ST_DESCRIPTION/ST_VERSION) are byte-identical in aMule 3.0.1 output because WriteTagToFile ignores the BOM request (Tag.cpp:394); eMule-written files instead contain a BOM-prefixed first copy. If the goal is compatibility with eMule readers that expect the BOM copy, decide whether to reproduce aMule 3.0.1 behavior (no BOM) or eMule behavior (BOM); this report documents aMule 3.0.1 as-is.
- CPath::ToUniv second FT_FILENAME encoding depends on wxConvFileName (the running locale's filesystem encoding) (Path.cpp:302-309); byte-identical output requires replicating the platform filesystem-encoding to Latin-1-string mapping, which is environment dependent.
- known.met FT_LASTSEEN (0x28) and the known2_64.met orphan-pruning rewrite (ThreadTasks.cpp:288-345) are aMule-3.x additions not present in eMule or aMule 2.3.x; older clients ignore the tag, but confirm the target interop set before relying on it.


==============================================================================

## SUBSYSTEM: ED2K wire protocol (aMule 3.0.1): packet framing, tag system, server login/search/sources, client-to-client transfer, UDP

# ED2K Wire Protocol - aMule 3.0.1 Reimplementation Reference

All multi-byte integers on the ED2K wire are LITTLE-ENDIAN. Confirmed by CFileDataIO::ReadUInt16/32/64 and WriteUInt16/32/64 using ENDIAN_SWAP macros (identity on LE hosts), src/SafeFile.cpp:139-292. All hashes are raw 16-byte MD4 (MD4HASH_LENGTH=16), no length prefix, written/read verbatim (SafeFile.cpp:181-187, 307-310). Floats are 4 bytes, byte-swapped as a uint32 (SafeFile.cpp:190-199).

## 1. PACKET FRAMING (TCP)

TCP header is 6 bytes, struct Header_Struct (src/OtherStructs.h:39-49), PACKET_HEADER_SIZE=6 (src/EMSocket.h:45):
- byte 0: protocol/eDonkeyID (int8)
- bytes 1..4: packetlength (uint32 LE)
- byte 5: command/opcode (int8)
- bytes 6..: payload

`packetlength` = 1 (opcode byte) + payload_size. So payload_size = packetlength - 1. On receive: CPacket ctor sets size = ENDIAN_SWAP_32(packetlength) - 1; opcode = command; prot = eDonkeyID (src/Packet.cpp:80-94). GetRealPacketSize() = size + 6 (Packet.h:55). Total bytes on wire = 5 + packetlength = 6 + payload_size.

CPacket::GetPacketSizeFromHeader returns packetlength - 1, rejecting values < 1 or >= 0x7ffffff0 (returns 0) (Packet.cpp:169-176). EMSocket enforces MAX_PACKET_SIZE = 2000000; larger triggers ERR_TOOBIG (EMSocket.cpp:42, 199-204). Receive loop reads 6-byte header first, then payload_size bytes (EMSocket.cpp:192-291). After a full packet, protocol is validated: must be one of OP_EDONKEYPROT, OP_PACKEDPROT, OP_EMULEPROT, OP_ED2KV2HEADER, OP_ED2KV2PACKEDPROT, else ERR_WRONGHEADER (EMSocket.cpp:274-284).

## 2. PROTOCOL BYTES (src/include/protocol/Protocols.h:33-52)

- OP_EDONKEYPROT / OP_EDONKEYHEADER = 0xE3  (base eDonkey protocol)
- OP_EMULEPROT = 0xC5  (eMule extended C2C/UDP protocol)
- OP_PACKEDPROT = 0xD4  (zlib-compressed packet; payload decompresses to an eMule-ext packet)
- OP_KADEMLIAHEADER = 0xE4, OP_KADEMLIAPACKEDPROT = 0xE5
- OP_ED2KV2HEADER = 0xF4, OP_ED2KV2PACKEDPROT = 0xF5  (aMule experimental ED2Kv2)
- OP_UDPRESERVEDPROT1 = 0xA3, OP_UDPRESERVEDPROT2 = 0xB2, OP_MLDONKEYPROT = 0x00
- EMULE_PROTOCOL = 0x01 (used only inside legacy OP_EMULEINFO body, NOT a header protocol byte)

## 3. ZLIB PACKING (Packet.cpp:247-307)

PackPacket (compress): compress2 with Z_BEST_COMPRESSION (level 9) into buffer of size+300. If result != Z_OK OR compressed size >= original size, keep uncompressed and return. On success set prot = OP_PACKEDPROT (0xD4), or OP_KADEMLIAPACKEDPROT (0xE5) if prot was OP_KADEMLIAHEADER. size becomes compressed length. Only the PAYLOAD is compressed; the 6-byte header is regenerated with the new size and new protocol byte.

UnPackPacket (decompress, Packet.cpp:275-307): valid only for prot OP_PACKEDPROT or OP_ED2KV2PACKEDPROT. Allocates nNewSize = size*10 + 300, capped at uMaxDecompressedSize (default 50000; ServerSocket passes 250000 at ServerSocket.cpp:632; ClientTCPSocket uses default at ClientTCPSocket.cpp:1946). On Z_OK: size = decompressed length, prot = OP_EMULEPROT (0xC5). NOTE: server code then overrides prot back to OP_EDONKEYPROT (ServerSocket.cpp:639); client code leaves it as OP_EMULEPROT and routes to ProcessExtPacket (ClientTCPSocket.cpp:1957-1962). Meaning: an OP_PACKEDPROT packet on a client link always carries an eMule-extended packet after decompression.

## 4. "SPLIT PACKET" RULES

aMule 3.0.1 does NOT fragment one oversized logical packet into multiple ED2K-headered wire packets. A large data packet (e.g. OP_SENDINGPART) is ONE ED2K packet; the socket only splits it at the byte/TCP level for bandwidth pacing (EMSocket::Send, EMSocket.cpp:467-650) with no extra headers inserted. The "splitted" CPacket constructor (Packet.cpp:139-152, m_bSplitted=true) is used only to wrap an already-formed raw buffer that may contain several concatenated ED2K packets, and for such packets GetPacket()/DetachPacket() do NOT prepend a header (Packet.cpp:184-222). Its single real use bundles multiple OP_GETSOURCES packets into one TCP frame (DownloadQueue.cpp:1130). Reassembly of large incoming data packets is by the normal header-length loop in EMSocket::OnReceive. A reimplementation does not need to emit multi-fragment split packets; it must handle arbitrarily large single packets bounded by MAX_PACKET_SIZE.

## 5. PRIMITIVE ENCODINGS
- uint8/16/32/64: LE, fixed width.
- hash: 16 raw bytes.
- float32: 4 bytes (endian-swapped uint32 representation).
- string (CFileDataIO::WriteString/ReadString, SafeFile.cpp:215-405): default is a uint16 LE byte-length prefix, then that many bytes. The length-field width is a parameter `lenBytes` defaulting to 2 (SafeFile.h:155, 198); some call sites use 4 (uint32 length). Encoding: utf8strNone(0) writes Latin-1 (ISO-8859-1); utf8strOptBOM(1) writes UTF-8 with a leading EF BB BF BOM (length includes the 3 BOM bytes); utf8strRaw(2) writes UTF-8 without BOM (EUtf8Str enum, src/libs/common/StringFunctions.h:34-39). Reading: if the first 3 bytes are EF BB BF it is decoded as UTF-8; else if bOptUTF8 flag set, tries UTF-8 then falls back to Latin-1; else Latin-1 (SafeFile.cpp:234-262). A 16-bit string length is clamped to 0xFFFF (SafeFile.cpp:371-385).

## 6. TAG SYSTEM

### 6.1 Tag type values (src/include/tags/TagTypes.h:29-77)
- TAGTYPE_HASH16 = 0x01 (16 raw bytes)
- TAGTYPE_STRING = 0x02 (uint16 length + bytes)
- TAGTYPE_UINT32 = 0x03 (4 bytes)
- TAGTYPE_FLOAT32 = 0x04 (4 bytes)
- TAGTYPE_BOOL = 0x05 (1 byte; read/consumed, rarely used)
- TAGTYPE_BOOLARRAY = 0x06 (uint16 len, then (len/8)+1 bytes; skipped)
- TAGTYPE_BLOB = 0x07 (uint32 length + bytes)
- TAGTYPE_UINT16 = 0x08 (2 bytes)
- TAGTYPE_UINT8 = 0x09 (1 byte)
- TAGTYPE_BSOB = 0x0A (uint8 length + bytes)
- TAGTYPE_UINT64 = 0x0B (8 bytes)
- TAGTYPE_STR1..STR16 = 0x11..0x20 (SPECIAL inline strings; value length = type - 0x11 + 1, NO separate length field, string bytes follow immediately). STR17..STR22 = 0x21..0x26 are defined but the reader does NOT handle them (throws) (Tag.cpp:172-180).

### 6.2 Two tag NAME encodings; the reader accepts both (CTag ctor, Tag.cpp:85-104)
On read: type = ReadUInt8(). 
- If (type & 0x80): this is the NEW/compact form. Clear the high bit (type &= 0x7F), then read a single uint8 = the numeric tag-name ID.
- Else (high bit clear): OLD form. Read a uint16 name-length. If length == 1, read a single uint8 = numeric tag-name ID (this is the common single-byte-name case). If length != 1, read `length` raw bytes = a string tag name (used for Kad-style string names).

### 6.3 Writers
- OLD form, CFileDataIO::WriteTag (SafeFile.cpp:513-570), used by CTag::WriteTagToFile (Tag.cpp:394-409): writes type byte (high bit NOT set), then name: if the tag has a string name, WriteString(name) (uint16 len + bytes); else WriteUInt16(1) + WriteUInt8(nameID). Then the value per type. STRINGs are always written UTF-8 (utf8strRaw) here.
- NEW/compact form, CTag::WriteNewEd2kTag (Tag.cpp:312-392): chooses the smallest int type (UINT8/16/32/64) for int values; for strings of raw length 1..16 uses TAGTYPE_STR1..STR16 (type carries the length, no length field written); else TAGTYPE_STRING. Name: if numeric ID, writes (type | 0x80) then uint8 ID; if string name, writes type then WriteString(name).
Which writer is used per file offer is decided by peer capability (KnownFile.cpp:1277-1294): new form for eMule > 0.42f, aMule with OSInfo, or servers advertising SRV_TCPFLG_NEWTAGS; else old form. The server login always uses the OLD form (ServerConnect.cpp:220-257).

### 6.4 Tag list framing
Most tag lists in payloads are preceded by a uint32 tag count (e.g. login, offerfiles, search results, hello). Each tag is then type+name+value as above. (Note: CFileDataIO::WriteTagPtrList/ReadTagPtrList use a uint8 count, SafeFile.cpp:500-583, but the ED2K packet bodies documented here use explicit uint32 counts written by hand.)

## 7. TAG NAME CONSTANTS

### File tags FT_* (src/include/tags/FileTags.h:30-77), used in offers, search, sources
- FT_FILENAME=0x01 (string), FT_FILESIZE=0x02 (uint32 low or uint64), FT_FILESIZE_HI=0x3A (uint32 high 32 bits), FT_FILETYPE=0x03 (string or uint32), FT_FILEFORMAT=0x04 (string, file extension), FT_LASTSEENCOMPLETE=0x05, FT_TRANSFERRED=0x08, FT_GAPSTART=0x09, FT_GAPEND=0x0A, FT_PARTFILENAME=0x12, FT_STATUS=0x14, FT_SOURCES=0x15 (uint32 avail count), FT_PERMISSIONS=0x16, FT_DLPRIORITY=0x18, FT_ULPRIORITY=0x19, FT_KADLASTPUBLISHKEY=0x20, FT_KADLASTPUBLISHSRC=0x21, FT_FLAGS=0x22, FT_AICH_HASH=0x27, FT_COMPLETE_SOURCES=0x30 (uint32), FT_FILERATING=0xF7 (uint8), media: FT_MEDIA_ARTIST=0xD0, FT_MEDIA_ALBUM=0xD1, FT_MEDIA_TITLE=0xD2, FT_MEDIA_LENGTH=0xD3, FT_MEDIA_BITRATE=0xD4, FT_MEDIA_CODEC=0xD5.

### Client (hello) tags CT_* (src/include/tags/ClientTags.h:29-52)
- CT_NAME=0x01 (nick string), CT_SERVER_UDPSEARCH_FLAGS=0x0E, CT_PORT=0x0F, CT_VERSION=0x11, CT_SERVER_FLAGS=0x20 (server-connect capabilities), CT_EMULECOMPAT_OPTIONS=0xEF, CT_EMULE_UDPPORTS=0xF9, CT_EMULE_MISCOPTIONS1=0xFA, CT_EMULE_VERSION=0xFB, CT_EMULE_BUDDYIP=0xFC, CT_EMULE_BUDDYUDP=0xFD, CT_EMULE_MISCOPTIONS2=0xFE.

### Legacy MuleInfo tags ET_* (ClientTags.h:55-67), used inside OP_EMULEINFO
- ET_COMPRESSION=0x20, ET_UDPPORT=0x21, ET_UDPVER=0x22, ET_SOURCEEXCHANGE=0x23, ET_COMMENTS=0x24, ET_EXTENDEDREQUEST=0x25, ET_COMPATIBLECLIENT=0x26, ET_FEATURES=0x27, ET_MOD_VERSION=0x55, ET_OS_INFO=0x94.

### Server tags ST_* (src/include/tags/ServerTags.h:30-53), in OP_SERVERIDENT / server.met
- ST_SERVERNAME=0x01 (string), ST_DESCRIPTION=0x0B (string), ST_PING=0x0C, ST_FAIL=0x0D, ST_PREFERENCE=0x0E, ST_DYNIP=0x85, ST_MAXUSERS=0x87, ST_SOFTFILES=0x88, ST_HARDFILES=0x89, ST_LASTPING=0x90, ST_VERSION=0x91 (string), ST_UDPFLAGS=0x92 (uint32), ST_AUXPORTSLIST=0x93 (string), ST_LOWIDUSERS=0x94, ST_UDPKEY=0x95, ST_UDPKEYIP=0x96, ST_TCPPORTOBFUSCATION=0x97, ST_UDPPORTOBFUSCATION=0x98.

## 8. SERVER TCP OPCODES (src/include/protocol/ed2k/Client2Server/TCP.h)
Client->Server: OP_LOGINREQUEST=0x01, OP_GETSERVERLIST=0x14, OP_OFFERFILES=0x15, OP_SEARCHREQUEST=0x16, OP_DISCONNECT=0x18, OP_GETSOURCES=0x19, OP_SEARCH_USER=0x1A, OP_CALLBACKREQUEST=0x1C, OP_QUERY_MORE_RESULT=0x21, OP_GETSOURCES_OBFU=0x23.
Server->Client: OP_REJECT=0x05, OP_SERVERLIST=0x32, OP_SEARCHRESULT=0x33, OP_SERVERSTATUS=0x34, OP_CALLBACKREQUESTED=0x35, OP_CALLBACK_FAIL=0x36, OP_SERVERMESSAGE=0x38, OP_IDCHANGE=0x40, OP_SERVERIDENT=0x41, OP_FOUNDSOURCES=0x42, OP_USERS_LIST=0x43, OP_FOUNDSOURCES_OBFU=0x44.

### 8.1 OP_LOGINREQUEST (0x01), prot OP_EDONKEYPROT (ServerConnect.cpp:210-259)
Sent right after TCP connect (state CS_WAITFORLOGIN). Payload:
1. hash 16 (user hash, thePrefs::GetUserHash)
2. uint32 client ID (current GetClientID; 0 on first connect)
3. uint16 TCP port
4. uint32 tagcount = 4
5. Tags (OLD form): CT_NAME=string(nick); CT_VERSION=int32(EDONKEYVERSION=0x3C); CT_SERVER_FLAGS=int32(CAPABLE_ZLIB 0x1 | CAPABLE_AUXPORT 0x4 | CAPABLE_NEWTAGS 0x8 | CAPABLE_UNICODE 0x10 | CAPABLE_LARGEFILES 0x100 | optional crypt flags SRVCAP_SUPPORTCRYPT 0x200 / SRVCAP_REQUESTCRYPT 0x400 / SRVCAP_REQUIRECRYPT 0x800); CT_EMULE_VERSION=int32((SO_AMULE=3 << 24) | make_full_ed2k_version(3,0,1)).
make_full_ed2k_version(a,b,c) = (a<<17)|(b<<10)|(c<<7) (OtherFunctions.h:340-342).

### 8.2 OP_IDCHANGE (0x40) server->client (ServerSocket.cpp:228-370)
This is the login answer that assigns the client ID. Payload (fields optional depending on size):
- uint32 new_id (the assigned ID; LowID if < 16777216, else HighID = the client public IP)
- if size>=8: uint32 TCP flags (SRV_TCPFLG_* below)
- if size>=12: uint32 aux/standard port
- if size>=20: uint32 server-reported client IP, uint32 obfuscation TCP port
If new_id==0 the server rejected login (disconnect). Sets connection state CONNECTED.
Server TCP flags (Client2Server/TCP.h:65-71): SRV_TCPFLG_COMPRESSION=0x1, SRV_TCPFLG_NEWTAGS=0x8, SRV_TCPFLG_UNICODE=0x10, SRV_TCPFLG_RELATEDSEARCH=0x40, SRV_TCPFLG_TYPETAGINTEGER=0x80, SRV_TCPFLG_LARGEFILES=0x100, SRV_TCPFLG_TCPOBFUSCATION=0x400.

### 8.3 OP_SERVERMESSAGE (0x38) (ServerSocket.cpp:144-227): uint16 length, then `length` bytes of text (Latin-1/UTF-8). Multiple lines separated by CRLF. Special prefixes "server version", "ERROR", "WARNING", "[emDynIP: ...]" are parsed.

### 8.4 OP_SERVERSTATUS (0x34) (ServerSocket.cpp:400-415): uint32 user count, uint32 file count (min size 8).

### 8.5 OP_SERVERIDENT (0x41) (ServerSocket.cpp:417-470): hash 16 (server hash), uint32 server IP, uint16 server port, uint32 tagcount, then tags (ST_SERVERNAME, ST_DESCRIPTION, etc.). Min size 38.

### 8.6 OP_SERVERLIST (0x32) (ServerSocket.cpp:473-506): uint8 count, then count * (uint32 IP, uint16 port).

### 8.7 OP_CALLBACKREQUESTED (0x35) server->client (ServerSocket.cpp:508-547): uint32 IP, uint16 port; if size>=23: uint8 crypt options, hash 16 (user hash). Tells us a LowID peer wants us to connect back.

### 8.8 OP_GETSERVERLIST (0x14): empty payload; OP_REJECT (0x05): empty.

## 9. SEARCH REQUEST + EXPRESSION ENCODING

### 9.1 OP_SEARCHREQUEST (0x16), prot OP_EDONKEYPROT (SearchList.cpp:393). Payload is a single "search tree" of parameters, built by CSearchExprTarget (SearchList.cpp:156-257). No leading count; the tree is self-delimiting by operator arity. Parameter encodings (first byte = parameter type):
- 0x00 boolean operator: followed by 1 op byte: 0x00=AND, 0x01=OR, 0x02=NOT (WriteBoolean*, SearchList.cpp:168-184).
- 0x01 string term (plain keyword): uint16 string-length + string bytes (WriteMetaDataSearchParam(value), SearchList.cpp:186-190).
- 0x02 string term bound to a meta tag: uint16 string-length + string bytes, then meta-tag-id. Meta-tag-id for a single-byte id: uint16(1) + uint8(id). For a string name: WriteString(name) (SearchList.cpp:192-213).
- 0x03 numeric term int32: uint32 value, uint8 comparison operator, then meta-tag-id (as above) (SearchList.cpp:224-232).
- 0x08 numeric term int64: uint64 value, uint8 comparison operator, then meta-tag-id (only if peer supports 64-bit, else falls back to 0x03 with value clamped to 0xFFFFFFFF) (SearchList.cpp:215-232).

Comparison operators (enum ed2k_search_compare, src/include/protocol/ed2k/Constants.h:94-101): EQUAL=0, GREATER=1, LESS=2, GREATER_EQUAL=3, LESS_EQUAL=4, NOTEQUAL=5.

### 9.2 Boolean tree shape (SearchList.cpp:714-1034)
Operators are written PREFIX (Polish) relative to their two operands: e.g. "a AND b" is [AND][a][b]. The boolean tokens (0xAD "AND"/"OR"/"NOT" internal markers, SearchExpr.h:42-44) are emitted as 0x00-type operator params.
Special optimization: when the expression has only implicit ANDs (no OR, no NOT), aMule prepends the ANDs interleaved rather than as a fully left-leaning tree ("AND a AND minsize maxsize" instead of "AND AND a minsize..."). It writes at most parametercount-1 leading AND operators (one fewer AND than the number of terms), each guarded by `if (++iParameterCount < parametercount)`.
Standard filter terms appended after the keyword term (SearchList.cpp:795-829): FT_FILETYPE (0x03) as ASCII string (types "Audio","Video","Image","Doc","Pro","Arc","Iso"); FT_FILESIZE (0x02) minSize with op GREATER; FT_FILESIZE (0x02) maxSize with op LESS; FT_SOURCES (0x15) availability with op GREATER; FT_FILEFORMAT (0x04) extension as string.

### 9.3 OP_SEARCHRESULT (0x33) parsing (ServerSocket.cpp:372-385, SearchList.cpp:572-583, SearchFile.cpp:40-98)
Payload: uint32 result count, then per result:
- hash 16
- uint32 client ID (IP; zeroed if bad/LowID for direct use)
- uint16 client port
- uint32 tagcount, then tagcount tags (read via the dual-form CTag reader)
Relevant tags: FT_FILENAME (name), FT_FILESIZE (low 32), FT_FILESIZE_HI (high 32, shifted <<32), FT_FILERATING, FT_SOURCES (avail), FT_COMPLETE_SOURCES. A result with no filename is rejected; size 0 or > MAX_FILE_SIZE dropped (SearchList.cpp:595-607).

## 10. GET SOURCES / FOUND SOURCES

### 10.1 OP_GETSOURCES (0x19) client->server (DownloadQueue.cpp:1102-1120)
Payload: hash 16, then file size: for normal files uint32 size; for large files uint32(0) + uint64 size (requires server SRV_TCPFLG_LARGEFILES). Multiple GETSOURCES may be concatenated into one TCP frame. Obfuscated variant opcode OP_GETSOURCES_OBFU=0x23.

### 10.2 OP_FOUNDSOURCES (0x42) server->client (ServerSocket.cpp:387-398, PartFile.cpp:1779-1848)
Payload: hash 16, uint8 count, then count * (uint32 ID, uint16 port). OP_FOUNDSOURCES_OBFU=0x44 adds after each ID/port: uint8 crypt options; if (options & 0x80) then hash 16 (user hash). ID may be LowID (needs callback) or HighID (direct IP).

## 11. OP_OFFERFILES (0x15) client->server (KnownFile.cpp:1154-1297, SharedFileList.cpp)
Payload: uint32 file count, then per file:
- hash 16
- uint32 client ID: our IP if connected with HighID else 0; OR on compression-capable servers a sentinel encoding completion: complete file ID=0xFBFBFBFB, incomplete ID=0xFCFCFCFC (KnownFile.cpp:1173-1185).
- uint16 client port: our port, or sentinel 0xFBFB (complete) / 0xFCFC (incomplete).
- uint32 tagcount, then tags: FT_FILENAME (string), FT_FILESIZE (int32; or int32 low + FT_FILESIZE_HI for large files to servers; int64 to clients), optional FT_FILERATING, FT_FILETYPE (int32 if server has SRV_TCPFLG_TYPETAGINTEGER else string). Tags use NEW or OLD form per peer (KnownFile.cpp:1277-1296).
A zero-count OFFERFILES is used as a keep-alive ping (ServerConnect.cpp:621-635).

## 12. OP_CALLBACKREQUEST (0x1C) client->server (BaseClient.cpp:1530-1539)
Payload: uint32 target LowID client ID (m_nUserIDHybrid). Sent when we (HighID) want a LowID peer, and we are connected to that peer's server. The server relays as OP_CALLBACKREQUESTED to the LowID peer, who connects out to us.

## 13. LowID vs HighID (src/NetworkFunctions.h:123-129)
HIGHEST_LOWID_ED2K_KAD = 16777216 (0x01000000). IsLowID(id) = (id < 16777216). A HighID equals the client's public IPv4 (in the server's byte order); the server assigns it in OP_IDCHANGE. A LowID (< 16M) means the peer is firewalled: it cannot accept inbound connections and must be reached via server callback (OP_CALLBACKREQUEST relayed to OP_CALLBACKREQUESTED) or via a Kad buddy. In client hello the ID field carries the peer's ID in "hybrid" (byte-swapped) form; if the peer sent no/self ID the code substitutes the swapped IP (BaseClient.cpp:675-677).

## 14. SERVER UDP PROTOCOL

UDP header is 2 bytes (struct UDP_Header_Struct, OtherStructs.h:54-63): byte 0 = protocol, byte 1 = opcode. NO length field. Payload follows. Server UDP port = server TCP port + 4 by default (port_offset=4; 12 for obfuscated ping) (ServerUDPSocket.cpp:373). Received server responses are attributed to TCP port = source_port - 4 (ServerUDPSocket.cpp:126,152,178).

Opcodes (src/include/protocol/ed2k/Client2Server/UDP.h:29-46): OP_GLOBSEARCHREQ3=0x90, OP_GLOBSEARCHREQ2=0x92, OP_GLOBGETSOURCES2=0x94, OP_GLOBSERVSTATREQ=0x96, OP_GLOBSERVSTATRES=0x97, OP_GLOBSEARCHREQ=0x98, OP_GLOBSEARCHRES=0x99, OP_GLOBGETSOURCES=0x9A, OP_GLOBFOUNDSOURCES=0x9B, OP_GLOBCALLBACKREQ=0x9C, OP_SERVER_DESC_REQ=0xA2, OP_SERVER_DESC_RES=0xA3, OP_SERVER_LIST_REQ2=0xA4.

- OP_GLOBSERVSTATREQ (0x96): payload = uint32 challenge (e.g. 0x55AA0000 + rand16; first two bytes chosen so it is not a valid string length) (ServerList.cpp:335-338).
- OP_GLOBSERVSTATRES (0x97) (ServerUDPSocket.cpp:175-233): uint32 challenge (must match), uint32 user count, uint32 file count; then optionally uint32 maxusers, uint32 softfiles, uint32 hardfiles, uint32 UDP flags, uint32 lowid users, uint16 UDP-obfuscation port, uint16 TCP-obfuscation port, uint32 server UDP key (each guarded by min-size checks at sizes 16/24/28/32/40).
- OP_GLOBSEARCHREQ/REQ2/REQ3 (0x98/0x92/0x90): carry the same search tree as TCP OP_SEARCHREQUEST. REQ3 prepends a tag-set (uint32 count + CT_SERVER_UDPSEARCH_FLAGS tag with SRVCAP_UDP_NEWTAGS_LARGEFILES=0x01) then the search body (SearchList.cpp:475-505).
- OP_GLOBSEARCHRES (0x99): one or more concatenated result blocks; each parsed like a single search result; between blocks a 2-byte [OP_EDONKEYPROT][OP_GLOBSEARCHRES] separator is present (ServerUDPSocket.cpp:121-146).
- OP_GLOBGETSOURCES (0x9A): hash 16 (may be repeated). OP_GLOBGETSOURCES2 (0x94): hash 16 + size (uint32, or uint32(0)+uint64 for large). OP_GLOBFOUNDSOURCES (0x9B): repeated blocks of hash 16 + uint8 count + count*(uint32 ID, uint16 port), separated by [OP_EDONKEYPROT][OP_GLOBFOUNDSOURCES] (ServerUDPSocket.cpp:147-172).
Server UDP flags (Client2Server/UDP.h:50-57): SRV_UDPFLG_EXT_GETSOURCES=0x1, SRV_UDPFLG_EXT_GETFILES=0x2, SRV_UDPFLG_NEWTAGS=0x8, SRV_UDPFLG_UNICODE=0x10, SRV_UDPFLG_EXT_GETSOURCES2=0x20, SRV_UDPFLG_LARGEFILES=0x100, SRV_UDPFLG_UDPOBFUSCATION=0x200, SRV_UDPFLG_TCPOBFUSCATION=0x400.

## 15. CLIENT-TO-CLIENT TCP

Standard opcodes prot OP_EDONKEYPROT (src/include/protocol/ed2k/Client2Client/TCP.h:30-58); extended opcodes prot OP_EMULEPROT (TCP.h:61-102). Dispatch by protocol byte: EDONKEYPROT to ProcessPacket, EMULEPROT to ProcessExtPacket, ED2KV2HEADER to ProcessED2Kv2Packet; PACKEDPROT/ED2KV2PACKEDPROT decompressed first then routed as EMULEPROT (ClientTCPSocket.cpp:1943-1980).

Standard (EDONKEYPROT): OP_HELLO=0x01, OP_SENDINGPART=0x46, OP_REQUESTPARTS=0x47, OP_FILEREQANSNOFIL=0x48, OP_END_OF_DOWNLOAD=0x49, OP_ASKSHAREDFILES=0x4A, OP_ASKSHAREDFILESANSWER=0x4B, OP_HELLOANSWER=0x4C, OP_CHANGE_CLIENT_ID=0x4D, OP_MESSAGE=0x4E, OP_SETREQFILEID=0x4F, OP_FILESTATUS=0x50, OP_HASHSETREQUEST=0x51, OP_HASHSETANSWER=0x52, OP_STARTUPLOADREQ=0x54, OP_ACCEPTUPLOADREQ=0x55, OP_CANCELTRANSFER=0x56, OP_OUTOFPARTREQS=0x57, OP_REQUESTFILENAME=0x58, OP_REQFILENAMEANSWER=0x59, OP_CHANGE_SLOT=0x5B, OP_QUEUERANK=0x5C, OP_ASKSHAREDDIRS=0x5D, OP_ASKSHAREDFILESDIR=0x5E, OP_ASKSHAREDDIRSANS=0x5F, OP_ASKSHAREDFILESDIRANS=0x60, OP_ASKSHAREDDENIEDANS=0x61.

Extended (EMULEPROT): OP_EMULEINFO=0x01, OP_EMULEINFOANSWER=0x02, OP_COMPRESSEDPART=0x40, OP_QUEUERANKING=0x60, OP_FILEDESC=0x61, OP_REQUESTSOURCES=0x81, OP_ANSWERSOURCES=0x82, OP_REQUESTSOURCES2=0x83, OP_ANSWERSOURCES2=0x84, OP_PUBLICKEY=0x85, OP_SIGNATURE=0x86, OP_SECIDENTSTATE=0x87, OP_MULTIPACKET=0x92, OP_MULTIPACKETANSWER=0x93, OP_PUBLICIP_REQ=0x97, OP_PUBLICIP_ANSWER=0x98, OP_CALLBACK=0x99, OP_AICHREQUEST=0x9B, OP_AICHANSWER=0x9C, OP_AICHFILEHASHANS=0x9D, OP_AICHFILEHASHREQ=0x9E, OP_BUDDYPING=0x9F, OP_BUDDYPONG=0xA0, OP_COMPRESSEDPART_I64=0xA1, OP_SENDINGPART_I64=0xA2, OP_REQUESTPARTS_I64=0xA3, OP_MULTIPACKET_EXT=0xA4, OP_CHATCAPTCHAREQ=0xA5, OP_CHATCAPTCHARES=0xA6.
NOTE: There is NO OP_SLOTREQUEST / OP_SLOTRELEASE in this ED2K codebase; upload slotting uses OP_STARTUPLOADREQ / OP_ACCEPTUPLOADREQ / OP_QUEUERANK(ING) / OP_CANCELTRANSFER / OP_OUTOFPARTREQS.

### 15.1 OP_HELLO (0x01) and OP_HELLOANSWER (0x4C) (BaseClient.cpp:721-1170)
OP_HELLO payload begins with a uint8 = 0x10 (16, the hash size), then the "hello body". OP_HELLOANSWER omits that leading byte and starts directly with the hello body. Hello body (SendHelloTypePacket, BaseClient.cpp:1020-1170):
1. hash 16 (our user hash)
2. uint32 client ID (theApp->GetID)
3. uint16 TCP port
4. uint32 tagcount
5. Tags (written via WriteTagToFile / VarInt, forced to 32-bit type unless peer supports value-based tags): CT_NAME (nick), CT_VERSION (EDONKEYVERSION 0x3C), CT_EMULE_UDPPORTS (=(kadUDPport<<16)|udpPort), optionally CT_EMULE_BUDDYIP + CT_EMULE_BUDDYUDP (if firewalled with buddy), CT_EMULE_VERSION (=(SO_AMULE<<24)|make_full_ed2k_version(3,0,1)), CT_EMULE_MISCOPTIONS1, CT_EMULE_MISCOPTIONS2, CT_EMULECOMPAT_OPTIONS, optionally ET_MOD_VERSION (GIT builds).
6. uint32 server IP (0 if not connected)
7. uint16 server port

CT_EMULE_MISCOPTIONS1 bitfield (built BaseClient.cpp:1096-1110, parsed 530-570): bits from high to low: [4*7+1] AICH version(3b), [4*7] Unicode(1b), [4*6] UDP version(4b), [4*5] data-compression version(4b), [4*4] secure ident(4b), [4*3] source-exchange v1(4b), [4*2] extended-requests(4b), [4*1] accept-comment(4b), [1*3] peercache(1b), [1*2] no-view-shared(1b), [1*1] multipacket(1b), [1*0] preview(1b). aMule sends AICH=1, Unicode=1, UDPver=4, DataComp=1, SecIdent=3(if crypto), SrcExch=3, ExtReq=2, Comment=1, MultiPacket=1.
CT_EMULE_MISCOPTIONS2 bitfield (BaseClient.cpp:1131-1144, parsed 573-613): [12] direct UDP callback, [11] captcha, [10] source-exchange2, [9] requires crypt, [8] requests crypt, [7] supports crypt, [6] reserved/mod, [5] ext multipacket, [4] large files (implies 64-bit tag support), [3..0] Kad version (KADEMLIA_VERSION=0x08).
CT_EMULE_UDPPORTS value: high 16 bits Kad UDP port, low 16 bits eMule UDP port (BaseClient.cpp:1059, parsed 502-511).
Hello tail (after tags) for OP_HELLOANSWER also carries server IP+port. Extra trailing uint32 == 0x4B444C4D ("KDLM") marks an MLDonkey peer (BaseClient.cpp:643-655).

### 15.2 OP_EMULEINFO (0x01) / OP_EMULEINFOANSWER (0x02) legacy (BaseClient.cpp:746-1004)
Body: uint8 mule/client-version (CURRENT_VERSION_SHORT=0x47), uint8 protocol_version (EMULE_PROTOCOL=0x01, or 0xFF for the aMule OS-info variant), uint32 tagcount, then ET_* tags: ET_COMPRESSION=1, ET_UDPVER=4, ET_UDPPORT, ET_SOURCEEXCHANGE=3, ET_COMMENTS=1, ET_EXTENDEDREQUEST=2, ET_FEATURES, ET_COMPATIBLECLIENT=SO_AMULE, ET_MOD_VERSION. The 0xFF variant sends a single ET_OS_INFO string tag.

### 15.3 File request handshake
- OP_REQUESTFILENAME (0x58): hash 16, optionally followed by extended info (part status, complete-sources count) (DownloadClient.cpp:280-297). Answer OP_REQFILENAMEANSWER (0x59): hash 16, string filename (ClientTCPSocket.cpp:404-414).
- OP_SETREQFILEID (0x4F): hash 16. Answer OP_FILESTATUS (0x50): hash 16, part-status bitfield (ClientTCPSocket.cpp:461-471).
- OP_FILEREQANSNOFIL (0x48): hash 16 (peer does not have the file).
- Part-status bitfield (WritePartStatus, PartFile.cpp:1463-1481): uint16 part count (ED2K part count = ceil(size/PARTSIZE)); then ceil(parts/8) bytes; within each byte bit i (LSB first, i=0..7) is set if that part is complete, parts numbered sequentially. For a complete/whole non-part file the sender writes uint16(0) (zero parts) meaning "all complete" (ClientTCPSocket.cpp:466).
- OP_MULTIPACKET (0x92, EMULEPROT) bundles several sub-requests for one file (ClientTCPSocket.cpp:995-1144): hash 16, then a sequence of [uint8 sub-opcode][sub-body] where sub-opcode is one of OP_REQUESTFILENAME, OP_SETREQFILEID, OP_AICHFILEHASHREQ, OP_REQUESTSOURCES(2). OP_MULTIPACKET_EXT (0xA4) inserts a uint64 file size right after the hash. Answer OP_MULTIPACKETANSWER (0x93): hash 16 then [uint8 sub-opcode][sub-body] for OP_REQFILENAMEANSWER / OP_FILESTATUS / OP_AICHFILEHASHANS.

### 15.4 Upload slot flow
- OP_STARTUPLOADREQ (0x54): hash 16 (DownloadClient.cpp:170-175). Requests entry to uploader's queue.
- OP_ACCEPTUPLOADREQ (0x55): empty payload (UploadQueue.cpp:212, 502). Granted a slot.
- OP_QUEUERANK (0x5C, EDONKEYPROT): uint32 rank (ClientTCPSocket.cpp:562-570).
- OP_QUEUERANKING (0x60, EMULEPROT): uint16 rank followed by 10 bytes padding (uint32 0, uint32 0, uint16 0), total payload size exactly 12 (UploadClient.cpp:585-590; receiver enforces size==12 and reads only the leading uint16, ClientTCPSocket.cpp:1378-1384).
- OP_CANCELTRANSFER (0x56): empty. OP_OUTOFPARTREQS (0x57): empty.

### 15.5 Block request / data transfer
- OP_REQUESTPARTS (0x47, EDONKEYPROT) (DownloadClient.cpp:782-820, parsed UploadClient.cpp:691-716): hash 16, then THREE uint32 start offsets, then THREE uint32 end offsets (all starts first, then all ends; NOT interleaved). End offset is exclusive (EndOffset+1). Unused slots are zero-filled; receiver ignores pairs where end <= start.
- OP_REQUESTPARTS_I64 (0xA3, EMULEPROT): identical but uint64 offsets (hash 16 + 3x uint64 start + 3x uint64 end). Used when any offset > 0xFFFFFFFF.
- OP_SENDINGPART (0x46, EDONKEYPROT) (UploadDiskIOThread.cpp:457-500, parsed DownloadClient.cpp:853-953): hash 16, uint32 start, uint32 end, then (end-start) raw data bytes. Receiver validates size == (end-start) + header_size (16+8).
- OP_SENDINGPART_I64 (0xA2, EMULEPROT): hash 16, uint64 start, uint64 end, then data.
- OP_COMPRESSEDPART (0x40, EMULEPROT) (UploadDiskIOThread.cpp:505-562, parsed DownloadClient.cpp:890-902): hash 16, uint32 start, uint32 packedTotalSize, then a slice of zlib-compressed data. All chunks of one compressed block carry the SAME start offset and the same total packed size; the receiver streams them through one zlib inflate stream, deriving positions from cumulative decompressed bytes.
- OP_COMPRESSEDPART_I64 (0xA1, EMULEPROT): hash 16, uint64 start, uint32 packedTotalSize, then compressed data.
Compression uses zlib compress2 (level 1 for upload chunks); if not smaller, falls back to uncompressed OP_SENDINGPART.

### 15.6 Hash set
- OP_HASHSETREQUEST (0x51): hash 16 (DownloadClient side sends; ClientTCPSocket.cpp:631-640 enforces size 16).
- OP_HASHSETANSWER (0x52) (UploadClient.cpp:528-565): hash 16 (file hash), uint16 part-hash count, then count * hash 16 (the per-9.28MB-part MD4 hashes).

### 15.7 Other C2C
- OP_MESSAGE (0x4E): uint16 length + text (chat).
- OP_FILEDESC (0x61, EMULEPROT): uint8 rating, then a uint32-length string comment (UploadClient.cpp:597-619).
- OP_CHANGE_CLIENT_ID (0x4D): uint32 old ID, uint32 new ID.
- OP_PUBLICIP_REQ (0x97) / OP_PUBLICIP_ANSWER (0x98): answer carries uint32 IP (BaseClient.cpp:2345-2360).
- Secure identification: OP_SECIDENTSTATE (0x87) = uint8 state + uint32 challenge; OP_PUBLICKEY (0x85) = uint8 len + key; OP_SIGNATURE (0x86) = uint8 len + signature (+ optional uint8 sigIPused for v2).

## 16. CLIENT UDP PROTOCOL (src/ClientUDPSocket.cpp)
2-byte header (protocol, opcode), no length. Client extended UDP opcodes (src/include/protocol/ed2k/Client2Client/UDP.h:30-36), prot OP_EMULEPROT: OP_REASKFILEPING=0x90, OP_REASKACK=0x91, OP_FILENOTFOUND=0x92, OP_QUEUEFULL=0x93, OP_REASKCALLBACKUDP=0x94, OP_PORTTEST=0xFE.
- OP_REASKFILEPING (0x90): hash 16 [+ UDP-version-dependent extended info: for UDPver>3 part status; for UDPver>2 a uint16 complete-source count] (ClientUDPSocket.cpp:171-234). Answer OP_REASKACK (0x91): [if UDPver>3 part status], uint16 queue rank.
- OP_FILENOTFOUND (0x92): empty. OP_QUEUEFULL (0x93): empty.
- OP_REASKCALLBACKUDP (0x94): 16-byte buddy key + payload; server-side buddy relays as TCP OP_REASKCALLBACKTCP (0x9A).
- OP_DIRECTCALLBACKREQ (a kad2 UDP opcode reused here, ClientUDPSocket.cpp:285-323, BaseClient.cpp:1509-1517): uint16 our TCP port, hash 16 (our user hash), uint8 connect options.
Kad UDP uses prot OP_KADEMLIAHEADER (0xE4) / OP_KADEMLIAPACKEDPROT (0xE5) and is out of scope here.

## 17. KEY SIZES / CONSTANTS (src/include/protocol/ed2k/Constants.h)
PARTSIZE = 9728000 (0x94_5000) bytes (one ED2K part). BLOCKSIZE = EMBLOCKSIZE = 184320 (0x2D000) bytes (one requestable block). MAX_FILE_SIZE = 0x4000000000 (256 GB). OLD_MAX_FILE_SIZE = 4290048000. Standard 3-block request wire count STANDARD_BLOCKS_REQUEST = 3 (implicit). EDONKEYVERSION = 0x3C. CURRENT_VERSION_SHORT = 0x47. KADEMLIA_VERSION = 0x08. SO_AMULE = 3. MAX_PACKET_SIZE = 2000000.

## 18. ENDIANNESS / STRING SUMMARY FOR IMPLEMENTERS
- Wire integers: little-endian.
- Hash: 16 raw bytes as-is.
- Strings: uint16-LE length prefix (unless a 4-byte length is explicitly used) + bytes; UTF-8 detection via BOM or the bOptUTF8 flag; otherwise Latin-1.
- ClientID/HighID values are the peer IPv4 in the server's network byte order; code frequently byte-swaps (wxUINT32_SWAP_ALWAYS) between "hybrid" and host forms - verify byte order per field against BaseClient.cpp:675-677 and updownclient handling when reimplementing.


### Key constants (as reported)

- OP_EDONKEYPROT = 0xE3 (Protocols.h:34)
- OP_EMULEPROT = 0xC5 (Protocols.h:37)
- OP_PACKEDPROT = 0xD4 (Protocols.h:36)
- PACKET_HEADER_SIZE = 6 (EMSocket.h:45); packetlength = 1 + payload_size (Packet.cpp:84,230)
- MAX_PACKET_SIZE = 2000000 (EMSocket.cpp:42); GetPacketSizeFromHeader rejects >= 0x7ffffff0 (Packet.cpp:173)
- HIGHEST_LOWID_ED2K_KAD = 16777216; IsLowID(id) = id < 16777216 (NetworkFunctions.h:123-129)
- EDONKEYVERSION = 0x3C (ClientVersion.h:42); CURRENT_VERSION_SHORT = 0x47 (ClientVersion.h:39)
- make_full_ed2k_version(a,b,c) = (a<<17)|(b<<10)|(c<<7) (OtherFunctions.h:341); VERSION 3.0.1 (ClientVersion.h:69-71); SO_AMULE=3 (ClientSoftware.h:33)
- TAGTYPE_HASH16=0x01, STRING=0x02, UINT32=0x03, FLOAT32=0x04, BLOB=0x07, UINT16=0x08, UINT8=0x09, BSOB=0x0A, UINT64=0x0B, STR1..STR16=0x11..0x20 (TagTypes.h:29-77)
- Tag name compact-form flag: type & 0x80 => 1-byte numeric name id; else uint16 len (len==1 => 1-byte id) (Tag.cpp:92-104)
- PARTSIZE = 9728000; BLOCKSIZE = EMBLOCKSIZE = 184320; MAX_FILE_SIZE = 0x4000000000 (Constants.h:80-84)
- Login CT_SERVER_FLAGS = CAPABLE_ZLIB 0x1 | AUXPORT 0x4 | NEWTAGS 0x8 | UNICODE 0x10 | LARGEFILES 0x100 (ServerConnect.cpp:241-246; ClientTags.h:70-80)
- Search param types: 0x00 bool(op 0=AND/1=OR/2=NOT), 0x01 string, 0x02 string+metatag, 0x03 int32+op+metatag, 0x08 int64+op+metatag (SearchList.cpp:168-249)
- Search compare ops: EQUAL=0,GREATER=1,LESS=2,GE=3,LE=4,NE=5 (Constants.h:94-101)
- OFFERFILES completion sentinels: complete ID=0xFBFBFBFB port=0xFBFB, incomplete ID=0xFCFCFCFC port=0xFCFC (KnownFile.cpp:1173-1185)
- Server UDP port = TCP port + 4 (obfuscated ping +12) (ServerUDPSocket.cpp:373)
- OP_REQUESTPARTS: hash16 + 3x start + 3x end (uint32 legacy / uint64 _I64), ends exclusive (DownloadClient.cpp:782-820, UploadClient.cpp:697-716)
- OP_QUEUERANKING payload size exactly 12 = uint16 rank + 10 pad bytes (UploadClient.cpp:585-590, ClientTCPSocket.cpp:1378)


### Flagged unclear (by the recon agent)

- Exact byte order of the ID fields in client Hello and in OP_FOUNDSOURCES: the code stores IDs in eDonkey 'hybrid' form and applies wxUINT32_SWAP_ALWAYS in several places (BaseClient.cpp:675-677, ClientTCPSocket.cpp:301). A reimplementation must confirm, per field, whether the 4 ID bytes are the raw IPv4 in network order or byte-swapped. Not fully traced here.
- OP_QUERY_MORE_RESULT (0x21) and OP_SEARCH_USER (0x1A) payloads were not traced (only their opcodes are defined).
- The exact GetED2KPartCount rounding (whether a file that is an exact multiple of PARTSIZE gets an extra empty part in the OP_FILESTATUS bitfield) was not verified in source; WritePartStatus uses GetED2KPartCount() (PartFile.cpp:1465) but that function body was not read.
- AICH hash-set packet bodies (OP_AICHREQUEST/OP_AICHANSWER/OP_AICHFILEHASHREQ/ANS) and source-exchange answer bodies (OP_ANSWERSOURCES/2) were not decoded field-by-field.
- Encryption/obfuscation layer (CEncryptedStreamSocket / CEncryptedDatagramSocket) transforms bytes before the framing described here when enabled; this report documents the cleartext protocol only.
- ED2Kv2 OP_REQUESTPARTS variant (prot OP_ED2KV2HEADER) uses tag-encoded offsets (CTagVarInt with no-name id 0) and a leading uint8 block count (DownloadClient.cpp:766-781); this aMule-specific path was documented only briefly and its interop scope is unclear.


==============================================================================

## SUBSYSTEM: aMule 3.0.1 transfer engine: download/upload queues, chunk selection, credits/secure ident, bandwidth throttler, source exchange, corruption handling, source management

# aMule 3.0.1 Transfer Engine, Queues, Credits, Source Management

Source root: /home/ajbufort/claude-projects/padMule/amule-3.0.1/src (all paths below relative to it).
WARNING: this tree is a locally modified aMule 3.0.1 (comments cite internal PRs and eMule 0.70b backports). Wire formats match classic eMule/aMule; some local policies differ from stock 2.3.x. Deviations are flagged inline and in the unclear list.

## 1. Core sizes and units

- PARTSIZE = 9728000 bytes (one "part"/"chunk", the MD4-hashed unit) - include/protocol/ed2k/Constants.h:82
- BLOCKSIZE = EMBLOCKSIZE = 184320 bytes (one requestable "block", 180 KiB) - include/protocol/ed2k/Constants.h:83-84
- 52.78 blocks per part; last block of a part and last part of a file are short.
- STANDARD_BLOCKS_REQUEST = 3 (blocks per legacy OP_REQUESTPARTS packet) - updownclient.h:103
- Requested_Block_Struct = { StartOffset u64, EndOffset u64, FileID[16], transferred u32 }. On the DOWNLOAD side EndOffset is INCLUSIVE (GetNextEmptyBlockInPart, PartFile.cpp:1417). On the wire the end offsets are EXCLUSIVE: SendBlockRequests writes EndOffset+1 (DownloadClient.cpp:812); the UPLOAD side stores EndOffset exclusive (UploadClient.cpp:726, and the v2 parser does +1 at 752).

## 2. Download state machine per source

Enum EDownloadState (Constants.h:137-153): DS_DOWNLOADING=0, DS_ONQUEUE, DS_CONNECTED, DS_CONNECTING, DS_WAITCALLBACK, DS_WAITCALLBACKKAD, DS_REQHASHSET, DS_NONEEDEDPARTS, DS_TOOMANYCONNS, DS_TOOMANYCONNSKAD, DS_LOWTOLOWIP, DS_BANNED, DS_ERROR, DS_NONE, DS_REMOTEQUEUEFULL(stats only).

Life cycle:
1. Source added (server GETSOURCES, Kad, SX, seeds, link) via CDownloadQueue::CheckAndAddSource (DownloadQueue.cpp:623). Starts DS_NONE.
2. CPartFile::Process (PartFile.cpp:1488) walks sources each second (full source walk only when m_icounter >= 10, i.e. every 10th tick; downloading sources every tick). If connected and (never asked or now - lastAsked > FILEREASKTIME = 1300000 ms, ed2k/Constants.h:35) it calls AskForDownload (states DS_ONQUEUE/CONNECTING/TOOMANYCONNS/NONE/WAITCALLBACK*, PartFile.cpp:1606-1621).
3. AskForDownload (DownloadClient.cpp:139): if too many sockets set DS_TOOMANYCONNS, else DS_CONNECTING and TCP connect (with LowID callback via server OP_CALLBACKREQUEST or Kad, handled elsewhere in BaseClient::TryToConnect).
4. After handshake, SendFileRequest (DownloadClient.cpp:216): OP_MULTIPACKET / OP_MULTIPACKET_EXT (with u64 filesize) if supported, containing sub-opcodes OP_REQUESTFILENAME (+ our part status bitfield if peer ExtendedRequestsVersion>0, + our complete-sources count if >1), OP_SETREQFILEID (if >1 part), optional OP_REQUESTSOURCES/OP_REQUESTSOURCES2, optional OP_AICHFILEHASHREQ. Legacy path sends separate OP_REQUESTFILENAME then OP_SETREQFILEID packets.
5. Replies: OP_REQFILENAMEANSWER (ProcessFileInfo, DownloadClient.cpp:337), OP_FILESTATUS (ProcessFileStatus:386, part bitmap, bits little-endian per byte, count nED2KPartCount u16, 0 means complete source). No needed parts sets DS_NONEEDEDPARTS. Missing hashset triggers OP_HASHSETREQUEST, DS_REQHASHSET; then OP_HASHSETANSWER (hash + u16 count + 16-byte MD4 per part).
6. SendStartupLoadReq (DownloadClient.cpp:163): OP_STARTUPLOADREQ with file hash; state DS_ONQUEUE. Peer queues us and sends OP_QUEUERANKING (u16 rank + 10 zero bytes) or OP_ACCEPTUPLOADREQ.
7. OP_ACCEPTUPLOADREQ (ClientTCPSocket.cpp:573): only honored in DS_ONQUEUE; sets DS_DOWNLOADING, SetLastPartAsked(0xffff), calls SendBlockRequests.
8. Block download loop (section 3). Timeout: if no block data for DOWNLOADTIMEOUT = 100000 ms, send OP_CANCELTRANSFER and drop back to DS_ONQUEUE (DownloadClient.cpp:1209-1218).
9. Reask while DS_ONQUEUE prefers UDP: UDPReaskForDownload (DownloadClient.cpp:1269) fires when now - lastAsked > FILEREASKTIME - 20000 (PartFile.cpp:1595-1601): OP_REASKFILEPING (hash [+ our part status if peer UDP ver>3] [+ complete src count if >2]). Answers: OP_REASKACK (their part status if UDPver>3, then u16 rank), OP_QUEUEFULL, OP_FILENOTFOUND (adds dead source and removes, DownloadClient.cpp:1248). Handling: ClientUDPSocket.cpp:171-284. If remote queue full and source count >= 80 percent of max, source is purged after 60 s (PartFile.cpp:1585-1592).
10. DS_NONEEDEDPARTS sources: every 40 s try SwapToAnotherFile (A4AF), else purge when source count >= 0.8*max; reask period doubled (2x FILEREASKTIME) and state reset to DS_NONE to force TCP reask (PartFile.cpp:1559-1583). DS_LOWTOLOWIP purged after 30 s when >= 0.8*max sources (PartFile.cpp:1542-1557).

A4AF (ask for another file): each client keeps m_A4AF_list of other part files (DownloadClient.cpp:496-517); swap logic SwapToAnotherFile picks highest GetDownPriority, +10 if it has needed parts (DownloadClient.cpp:1431-1540); a swapped-away file is barred for PURGESOURCESWAPSTOP = 15 min (ed2k/Constants.h:69, DownloadClient.cpp:1549).

## 3. Block request pipeline (download)

CUpDownClient::SendBlockRequests (DownloadClient.cpp:590):
- Adaptive pipelining (ED2Kv2/VBT peers only): if last block completed < 5 s ago, m_MaxBlockRequests doubles, cap 0x20 (32); else halves, floor STANDARD_BLOCKS_REQUEST = 3 (DownloadClient.cpp:600-611). Non-VBT peers stay at 3.
- If local block list empty: ask PartFile::GetNextRequestedBlock for (m_MaxBlockRequests - pending) new blocks.
- Pending_Block_Struct wraps Requested_Block_Struct + zlib z_stream + totalUnzipped + flags fZStreamError/fRecovered/fQueued.
- If nothing left to request: optionally drop the slowest downloading source when thePrefs::GetDropSlowSources() (GetSlowerDownloadingClient: any other DS_DOWNLOADING source whose KBpsDown*1024*DROP_FACTOR(=2) < our m_lastaverage, PartFile.cpp:4575-4595); the victim gets OP_CANCELTRANSFER and DS_NONEEDEDPARTS, then we take its freed blocks. Otherwise we send OP_CANCELTRANSFER ourselves.
- Wire: legacy OP_REQUESTPARTS (OP_EDONKEYPROT) or OP_REQUESTPARTS_I64 (OP_EMULEPROT, u64 offsets when any offset > 0xFFFFFFFF): hash + 3 starts + 3 ends (ends exclusive), zero pairs pad unused slots (DownloadClient.cpp:783-820). LOCAL DEVIATION: this tree batches >3 pending blocks by emitting one 3-block packet per call; stock eMule/aMule sends exactly the 3-block packet. ED2Kv2 variant (aMule-only): OP_ED2KV2HEADER + OP_REQUESTPARTS = hash + u8 count + per block two varint tags (DownloadClient.cpp:766-781).
- Requesting from a client without large-file support when offset > 32 bit: OP_CANCELTRANSFER + DS_ERROR (DownloadClient.cpp:744-753).

Receiving data, ProcessBlockPacket (DownloadClient.cpp:853):
- OP_SENDINGPART: hash + start u32 + end u32 (exclusive) + data. OP_SENDINGPART_I64: u64 offsets. OP_COMPRESSEDPART: hash + start (u32 or u64 for _I64) + packedLen u32 + zlib stream fragment; uncompressed extent derived from inflate output; a 180 KB block arrives as one zlib stream split over ~10 KB sub-packets, inflate with Z_SYNC_FLUSH incrementally (unzip, DownloadClient.cpp:1069).
- Validates size == (end - start) + header, matches pending block by StartOffset within [block.Start, block.End], rejects data exceeding block end, credits->AddDownloaded(payload) (DownloadClient.cpp:911).
- Write via CPartFile::WriteToBuffer; when nEndPos == block EndOffset the block is complete: compute m_lastaverage = blockBytes*1000/elapsed_ms, RemoveBlockFromList, erase pending, immediately call SendBlockRequests again (DownloadClient.cpp:1028-1053).
- zlib error: mark fZStreamError, ignore further fragments of that block, RemoveBlockFromList so it can be re-requested (DownloadClient.cpp:995-1020).

## 4. Chunk (part) selection - GetNextRequestedBlock (PartFile.cpp:1976-2216)

All blocks requested from one source must come from the same part (sender->GetLastPartAsked, 0xffff = none). Within the selected part, GetNextEmptyBlockInPart (PartFile.cpp:1369-1434) scans the gap list for the first gap overlapping the part, clamps the block to BLOCKSIZE-aligned boundaries relative to part start: blockLimit = partStart + BLOCKSIZE*(((start-partStart)/BLOCKSIZE)+1) - 1, and to partEnd, and skips ranges overlapping any entry in m_requestedblocks_list (IsAlreadyRequested = interval overlap, PartFile.cpp:1356-1367). So requests fill gaps and may be smaller than 180K.

Part selection ranks every candidate part i where sender has it (IsPartAvailable) and an unrequested empty block exists. Chunk fields: part, frequency (m_SrcpartFrequency[i], count of sources having the part), rank u16 (lower = better).
- Bounds: modif = 10 (or 5 if file sources > 200, 2 if > 800); limit = modif*sourceCount/100, min 1; veryRareBound = limit; rareBound = 2*limit (PartFile.cpp:2080-2091).
- critPreview: only when pref PreviewPrio and file type archive or video: part 0, last part, or last-1 when last part size < PARTSIZE/3 (PartFile.cpp:2094-2123).
- critRequested: frequency > veryRareBound AND IsAlreadyRequested(whole part range) (some other source is downloading in it) (PartFile.cpp:2127-2129).
- critCompletion = percent complete of the part = (PARTSIZE - gapSize(part)) / (PARTSIZE/100), 0..100 (uses PARTSIZE even for the short last part) (PartFile.cpp:2133-2134).
- Rank formula (PartFile.cpp:2137-2168):
  - frequency <= veryRareBound: rank = 25*frequency + (critPreview ? 0 : 1) + (100 - critCompletion)   [0..xxxx]
  - else if critPreview: rank = (requested ? 30000 : 10000) + (100 - critCompletion)
  - else if frequency <= rareBound: rank = 25*frequency + (requested ? 30101 : 10101) + (100 - critCompletion)
  - else common: unrequested rank = 20000 + (100 - critCompletion); requested rank = 40000 + critCompletion (inverted so new sources spread across common parts).
- Selection: find minimum rank, count ties, pick uniformly at random among ties with rand() (PartFile.cpp:2172-2205), set LastPartAsked, remove from list, loop until `count` blocks gathered or nothing left.

## 5. Gaps, write buffering, part verification (PartFile)

- Gap list (CGapList, GapList.h) stores incomplete byte ranges; persisted in the .part.met as paired named tags FT_GAPSTART/FT_GAPEND with decimal index suffix; end stored exclusive on disk, converted to inclusive-1 at load (PartFile.cpp:608-627).
- WriteToBuffer (PartFile.cpp:3107): skips duplicates (IsComplete(start,end)) and anything touching an already hashed complete part; logs to CorruptionBlackBox (TransferredData(start,end,clientIP)); inserts into ordered m_BufferedData_list; FillGap(start,end) IMMEDIATELY (gap list is optimistic, before disk write); block->transferred += len; flush if gaplist complete.
- FlushBuffer (PartFile.cpp:3204): fired when buffered > thePrefs::GetFileBufferSize() (pref * 15000, Preferences.h:346) or every BUFFER_TIME_LIMIT = 60000 ms (PartFile.h:46) or pending hash work. LOCAL DEVIATION: this tree queues writes to CPartFileWriteThread and hashes on CPartFileHashThread; stock aMule writes and hashes synchronously here. Parts touched by writes are marked dirty (m_aChangedPart); when a dirty part IsComplete it is hashed.
- HashSinglePart (PartFile.cpp:2460): MD4 of the part (GetPartSize = PARTSIZE except last part) compared to the part hash from the hashset (or the file hash when single-part). Missing hashset sets m_hashsetneeded and treats as pass.
- OnAsyncHashComplete (PartFile.cpp:3543): failure on a complete part: log, AddGap(whole part), push to m_corrupted_list, RequestAICHRecovery(part), m_iLostDueToCorruption += partsize. Success: CorruptionBlackBox->VerifiedData(true, part, 0, partSize-1); first verified part flips PS_EMPTY to PS_READY and shares the partfile.
- ICH via AICH (RequestAICHRecovery, PartFile.cpp:3813): requires trusted/verified AICH master hash and part > EMBLOCKSIZE; picks a random source supporting AICH whose reported master hash matches (prefers high-ID); OP_AICHREQUEST = hash + u16 part + master hash; answer carries the AICH recovery data (block-level SHA1 tree). AICHRecoveryDataAvailable (PartFile.cpp:3895): re-hash the local part into an AICH subtree, compare per 180K block; for each matching block FillGap and VerifiedData(true,...); mismatching blocks VerifiedData(false,...); then CorruptionBlackBox->EvaluateData(). If the part became complete, MD4 must also agree or the whole part is re-gapped and the AICH set marked AICH_ERROR. Part is then removed from m_corrupted_list regardless.
- CompleteFile when gap list is complete: rehash whole file (CHashingTask), move to incoming dir, share, m_CorruptionBlackBox->Free() (PartFile.cpp:2239-2330).

## 6. CorruptionBlackBox (CorruptionBlackBox.cpp)

- TransferredData(start,end,ip) (line 78): converts to part-relative 32-bit offsets, splits at part borders, merges only adjacent same-IP records, appends to per-part record list.
- VerifiedData(ok, part, relStart, relEnd) (line 116): subtracts the verified range from records, crediting each overlapped byte count to m_goodClients[ip].m_downloaded or m_badClients[ip]; a corrupt attribution is counted as max(actual, EMBLOCKSIZE) (line 171). Records fully consumed are dropped.
- EvaluateData() (line 191): for each bad client, nCorruptPercentage = bad*100/(bad+good); if > CBB_BANTHRESHOLD = 32 (line 38) then Ban() the client (2 h IP ban via ClientList), set its DS_BANNED, disconnect; else just track it.
- Granularity: attribution is only possible at AICH 180K block level (from AICHRecoveryDataAvailable); plain MD4 part failure alone never calls VerifiedData(false, ...) - without AICH recovery data no one is blamed.

## 7. Upload queue (UploadQueue.cpp, UploadClient.cpp)

Waiting queue score, CalculateScoreInternal (UploadClient.cpp:75-148):
- 0 if: empty username, no credits object, no upload file, IsBadGuy (failed secure ident, BaseClient.cpp:2559), banned, or already holding a slot (IsDownloading == m_nUploadState==US_UPLOADING, updownclient.h:265).
- Friend with friend slot and high ID: 0x0FFFFFFF (always first). Friend slot is exclusive: FriendList::SetFriendSlot clears it from all other friends (FriendList.cpp:227-251); friend-slot clients are never kicked (UploadQueue.cpp:578-580).
- Else score = floor( waitSeconds * creditRatio * filePrio * oldMuleFactor ), where waitSeconds = (now - GetWaitStartTime())/1000 (wait time tracked in credits, survives per IP; UploadClient.cpp:375-397), creditRatio = credits->GetScoreRatio (section 8), filePrio multiplier from the requested file upload priority: PR_POWERSHARE 250.0, PR_VERYHIGH 1.8, PR_HIGH 0.9, PR_NORMAL 0.7, PR_LOW 0.6, PR_VERY_LOW 0.2 (UploadClient.cpp:121-141), oldMuleFactor 0.5 for eMule version <= 0x19 (line 144).

Queue admission, AddClientToQueue (UploadQueue.cpp:396):
- Rejected if we are LowID on a foreign server with >50 waiting, or client banned.
- Same-userhash clash: unidentified duplicates are removed (lines 411-474).
- Max 3 clients per IP in queue, and reject if >= 3 tracked clients from that IP (lines 477-492).
- Queue cap thePrefs::GetQueueSize() (pref value * 100, Preferences.h:348).
- If queue empty, a slot is free, and >= 1000 ms since last upload start: upload immediately; else append, resort, send OP_QUEUERANKING (u16 rank + u32 0 + u32 0 + u16 0, OP_EMULEPROT; UploadClient.cpp:575-594).
- Aggression ban: re-request faster than MIN_REQUESTTIME = 590000 ms adds 3 to m_Aggressiveness, polite requests subtract 1, score >= 10 bans (2 h) (UploadClient.cpp:647-677, ed2k/Constants.h:67,71).

Sorting and slot grant, SortGetBestClient (UploadQueue.cpp:76): insertion sort descending by score; purges clients idle > MAX_PURGEQUEUETIME = 1 h or whose file is unshared; assigns waiting positions 1..N; the best high-ID (or currently connected low-ID) client is popped for the slot; unconnected low-ID clients ranked above it get m_bAddNextConnect = true and are granted a slot when they next connect (may temporarily exceed slot count by one; alternates via lastupslotHighID, UploadQueue.cpp:429-441). Full resort every 2 min if not triggered otherwise (UploadQueue.cpp:298).

Slot count, GetMaxSlots (UploadQueue.cpp:304): kBpsUpPerClient = thePrefs::GetSlotAllocation(); if MaxUpload unlimited: slots = max(20, uploadRateKBps/kBpsUpPerClient + 2) (LOCAL DEVIATION: the floor of 20 is not in stock aMule); else if MaxUpload >= 10 kB/s: slots = round(MaxUpload/kBpsUpPerClient), min MIN_UP_CLIENTS_ALLOWED = 2; else 2. Cap MAX_UP_CLIENTS_ALLOWED = 250 (ed2k/Constants.h:56,63).

Process loop (UploadQueue.cpp:239): once per core tick; if slot free (and >= 1 s since last start, sockets available) add next client; if all slots full set m_allowKicking. CheckForTimeOver (line 571) kicks at most one ordinary slot per cycle after upload session > 3600000 ms OR session bytes > 10485760 ("transfer full chunks": 10 MB or 1 h). PowerShare slots protected while VIP (friend or PowerShare) slots <= maxSlots/2. Kicked client receives OP_OUTOFPARTREQS and is re-queued (keeps credit wait time) (UploadClient.cpp:495-513).

Serving blocks: OP_REQUESTPARTS parsers (UploadClient.cpp:691-775) then AddReqBlock validation (must be in slot, file shared, requested range complete on part files, 0 < len <= 3*EMBLOCKSIZE, dedupe) (UploadClient.cpp:291-372). CUploadDiskIOThread (UploadDiskIOThread.cpp) drains m_BlockRequests_queue per slot, keeping at most nBufferLimit = EMBLOCKSIZE+1 bytes of prepared-but-unsent payload per client, or 5*EMBLOCKSIZE+1 when client datarate > BIGBUFFER_MINDATARATE = 76800 B/s (lines 205-219). Data packets: split into sub-packets of chunkSize = clamp(uploadDatarate/8, 10240, EMBLOCKSIZE) (LOCAL DEVIATION: stock uses fixed 10240); OP_SENDINGPART = hash + start + end (u32, or u64 with OP_SENDINGPART_I64/OP_EMULEPROT) + data (lines 457-501). Compression: zlib compress2 level 1 (stock eMule used 9) over the whole block unless file type is archive or client m_byDataCompVer != 1; skipped if not smaller; OP_COMPRESSEDPART = hash + start + packedTotalLen u32 + stream fragment (lines 504-563). Compression is permanently disabled for a client mid-session if the socket is starved at high rates (> SLOT_COMPRESSIONCHECK_DATARATE = 153600 B/s) (lines 381-400). SendBlockData on the main loop accounts sent bytes into credits->AddUploaded and session counters (UploadClient.cpp:422-492).

## 8. Credit system (ClientCredits.cpp, ClientCreditsList.cpp)

Multiplier GetScoreRatio(ip, cryptoAvailable) (ClientCredits.cpp:121-161); "downloaded" = bytes we received FROM the peer, "uploaded" = bytes we sent TO the peer:
- 1.0 if ident state is IS_IDFAILED/IS_IDBADGUY/IS_IDNEEDED while crypto is available (cheater guard).
- 1.0 if downloadedTotal < 1000000 bytes.
- ratio = (uploadedTotal == 0) ? 10.0 : downloadedTotal*2.0/uploadedTotal
- bound = sqrt(downloadedTotal/1048576.0 + 2.0)
- result = min(ratio, bound), clamped to [1.0, 10.0].
Accounting skips both counters for unverified secure-ident clients when crypto available (AddDownloaded/AddUploaded, lines 71-106).

Persistence clients.met (ClientCreditsList.cpp:65-219): u8 version = CREDITFILE_VERSION = 0x12 (include/common/DataFileVersion.h:40), u32 count, then per record: 16B user hash key, u32 uploaded_lo, u32 downloaded_lo, u32 lastSeen (unix), u32 uploaded_hi, u32 downloaded_hi, u16 reserved, u8 keySize, 80B abySecureIdent (DER public key, garbage beyond keySize). Records older than 150 days (now - 12960000 s) dropped at load (line 120). Backup clients.met.bak maintained. Saved every 13 min (line 244). Only records with nonzero up or down are written (line 194).

cryptkey.dat: Base64-encoded DER RSA private key, RSAKEYSIZE = 384 bits (ed2k/Constants.h:49), created with Crypto++ InvertibleRSAFunction; signer/verifier are RSASSA-PKCS1v15 with SHA-1 (ClientCreditsList.cpp:249-326). Own public key = DER of key material, <= 80 bytes (MAXPUBKEYSIZE, ClientCredits.h:31).

Secure identification handshake (BaseClient.cpp:2043-2287):
1. After hello/mule-info exchange, InfoPacketsReceived sends OP_SECIDENTSTATE if the peer advertises SecIdent support: u8 state (2 = IS_KEYANDSIGNEEDED if we lack his public key, 1 = IS_SIGNATURENEEDED if we have it but m_dwLastSignatureIP != current IP) + u32 random challenge (rand()+1) stored as credits->m_dwCryptRndChallengeFor (2217-2246).
2. Peer symmetric: on receiving state 2 we send OP_PUBLICKEY = u8 len + DER pubkey, then OP_SIGNATURE; state 1 only OP_SIGNATURE (2043-2122). SecureIdentState per client: IS_UNAVAILABLE=0, IS_SIGNATURENEEDED=1, IS_KEYANDSIGNEEDED=2 (updownclient.h:64-67).
3. Signature message (CreateSignature, ClientCreditsList.cpp:329-373): RSASSA-PKCS1v15-SHA1 over [receiver's public key bytes (as we know them)] + [u32 challenge the receiver sent us] and, for v2, + [u32 ChallengeIP] + [u8 byChaIPKind]. byChaIPKind: CRYPT_CIP_REMOTECLIENT=10 (IP = receiver's view of us... actually IP of remote client as we see it), CRYPT_CIP_LOCALCLIENT=20 (our ED2K ID), CRYPT_CIP_NONECLIENT=30 (ClientCredits.h:33-35). Sender picks v1 unless peer supports only v2 (m_bySupportSecIdent bit logic, BaseClient.cpp:2086-2102). OP_SIGNATURE payload: u8 sigLen + sig + optional u8 byChaIPKind (v2).
4. VerifyIdent (ClientCreditsList.cpp:376-441): verifies with the peer's stored public key over [our own public key] + [challenge we issued] (+ v2 IP fields, where CRYPT_CIP_LOCALCLIENT means the peer's IP as we see it and CRYPT_CIP_REMOTECLIENT our public IP/ED2K ID). Pass: credits->Verified(ip); the first-ever verification with a stored key resets both credit counters to 1 if downloaded > 0 (anti credit-theft, ClientCredits.cpp:188-204). Fail from IS_IDNEEDED sets IS_IDFAILED. One signature accepted per IP (m_dwLastSignatureIP, BaseClient.cpp:2191).
5. Ident states (ClientCredits.h:51-57): IS_NOTAVAILABLE, IS_IDNEEDED, IS_IDENTIFIED, IS_IDFAILED, IS_IDBADGUY. GetCurrentIdentState returns IS_IDBADGUY when identified but from a different IP (ClientCredits.cpp:219-231); IsBadGuy zeros the upload score.
6. A public key, once verified and stored, can never be replaced (SetSecureIdent refuses when nKeySize != 0, ClientCredits.cpp:207-216). Userhash changes on a tracked IP+port cause a ban (BaseClient.cpp:680-692). Credits are keyed by user hash (GetCredit(m_UserHash)).
7. Wait time: credits track m_dwSecureWaitTime / m_dwUnSecureWaitTime / m_dwWaitTimeIP; secure clients keep wait time across IP changes only when identified; unverified clients get wait reset when their IP changes (ClientCredits.cpp:234-266).

## 9. Source exchange (SX)

Requesting (DownloadClient.cpp:179-213, 249-263): IsSourceRequestAllowed requires ext protocol and (SX2 support or SX1 version > 1), sourceCount < GetMaxSourcePerFileSoft (= 0.9*maxSourcesPerFile capped 1000, Preferences.h:294), and one of:
- incomplete source, (never asked or > SOURCECLIENTREASKS = 40 min since this client answered), file very rare (sources <= RARE_FILE/5 = 10); or
- incomplete source, same client-cooldown, file rare (sources <= RARE_FILE = 50 or sources - validSources <= 25) and file-level cooldown nTimePassedFile > SOURCECLIENTREASKF = 5 min; or
- not rare: client cooldown > 40 min * MINCOMMONPENALTY(=4) = 160 min and file cooldown > 5 min * 4 = 20 min.
Request wire: SX2 = OP_REQUESTSOURCES2 (OP_EMULEPROT) with u8 version (SOURCEEXCHANGE2_VERSION = 4) + u16 options(0) + hash; SX1 = OP_REQUESTSOURCES + hash. Inside multipacket the sub-opcode carries the same fields.

Answering, CKnownFile::CreateSrcInfoPacket (KnownFile.cpp:976-1150): sources drawn from m_ClientUploadList (clients uploading or on our upload queue for the file); excluded: low-ID sources, the asker itself, wrong states. Needed-part filtering: if asker sent an upload chunk map, include only sources having a part the asker lacks; else include sources with at least one complete part. Cap: stops after 501 entries (nCount > 500 break). Reply: [u8 usedVersion if SX2] + hash + u16 count + per source: u32 ID (userIDHybrid if version >= 3 else IP), u16 port, u32 serverIP, u16 serverPort, +16B userhash if version >= 2, +u8 cryptOptions if version >= 4 (bit0 supported, bit1 requested, bit2 required). Opcode OP_ANSWERSOURCES / OP_ANSWERSOURCES2.

Receiving, CPartFile::AddClientSources (PartFile.cpp:2915-3058): SX1 infers packet version from entry size (12, 28, or 29 bytes per source vs advertised client SX1 version); SX2 validates the announced version <= 4 and exact size, else discard. Per source: version >= 3 IDs are hybrid (swap for ed2k order when high-ID); high-ID sources are checked against IsGoodIP (zero/localhost/LAN filter), the ipfilter.dat (theApp->ipfilter->IsFiltered) and the ban list; then CanAddSource (PartFile.cpp:1711-1777) rejects LowID 0, our own ID/IP+port (server and Kad forms), and any LowID source when we are firewalled ourselves; stop entirely when GetMaxSourcePerFile reached. Accepted sources go through CDownloadQueue::CheckAndAddSource.

SX1 client version (GetSourceExchange1Version) comes from the MISC_OPTIONS hello tag (not re-verified here). Server sources (OP_FOUNDSOURCES / UDP OP_GLOBFOUNDSOURCES) use CPartFile::AddSources (PartFile.cpp:1779-1851): u8 count + per source u32 id + u16 port (+ u8 cryptOptions + optional 16B hash when obfuscated form), same IsGoodIP/ipfilter/CanAddSource gauntlet.

## 10. Source admission and dedup (DownloadQueue.cpp:623-773)

CheckAndAddSource: drop if source hash == our hash; file stopped; dead source (global ClientList list OR per-file list); crypt-layer mismatch (they require crypt and we do not support, or we require and they do not). Duplicate detection: same userhash already queued for another file becomes an A4AF request on that client; else AttachToAlreadyKnown merges with an existing client object; unknown clients are registered in ClientList. CheckAndAddKnownSource additionally applies IsGoodIP LAN filtering for high-ID (line 739-745).

## 11. Dead sources (DeadSourceList.cpp)

Keyed by UserIDHybrid in a multimap; equality = same ID and (same TCP port or same Kad port), plus same server IP for LowID (lines 63-76). Timeouts set at add time: global list 30 min (45 min if LowID), per-file list 45 min (60 min if LowID) (lines 34-35). Entries checked lazily on lookup and purged; full cleanup every 60 min (line 32). Sources are added on UDP FILENOTFOUND (DownloadClient.cpp:1256), failed connects etc. Both a global list (CClientList, ClientList.cpp:806-815) and one per CPartFile exist.

## 12. Client bans, tracking, IP filtering (ClientList.cpp)

- Ban list: IP keyed, duration CLIENTBANTIME = 2 h (ed2k/Constants.h:71), cleanup periodic (lines 522-540, 727-753). IsBanned additionally requires the client not be DS_DOWNLOADING (UploadClient.cpp:642-645).
- Tracked clients: per IP list of (port, credits pointer) with KEEPTRACK_TIME = 2 h, cleanup TRACKED_CLEANUP_TIME = 1 h; used to detect userhash changes (ban) and to cap clients per IP (lines 461-519).
- IP filter application points: on outgoing hello (BaseClient.cpp:726 SendHelloPacket disconnects filtered peers), on filter reload FilterQueues disconnects all connected filtered clients (ClientList.cpp:756-767), on server sources (PartFile.cpp:1819), SX sources (PartFile.cpp:3026), Kad sources (DownloadQueue.cpp:1594).

## 13. Upload bandwidth throttler (UploadBandwidthThrottler.cpp)

Dedicated thread; loop cadence TIME_BETWEEN_UPLOAD_LOOPS = 1 ms baseline with adaptive backoff extraSleepTime *= 5 up to 1000 ms when nothing was sent (lines 486-489); woken early by condition signal when the disk thread queues payload or when the control queue goes non-empty (lines 76-80, 191-230).
- Budget: bytesToSpend accumulator (sint32); per loop += allowedRate/1000 * elapsedMs; allowedRate = MaxUpload*1024 or bypass when unlimited (rate capped at 1 GB/s for the accumulator; LOCAL DEVIATION). Negative carry forces sleep of (-bytesToSpend+1)*1000/rate + 2 ms. After spending: clamp carry-over to [-(slots+1)*minFragSize, slots*512 + 1] (lines 470-481).
- Fragment sizing: minFragSize = 1300, doubleSendSize = 2600 (two fragments share one ACK); below 6 KB/s rate: 536/536 (lines 329-334).
- Ordering per loop: (1) drain control-packet queues first (two lists: ControlQueueFirst for sockets that already sent, then ControlQueue; temp lists are swapped in under a separate lock); each socket SendControlData(budgetLeft, minFragSize). (2) trickle pass: any standard-list socket not sent to for > 1 s gets GetNeededBytes() worth (anti-timeout; CEMSocket::GetNeededBytes computes the minimum to keep a 90 s (45 s accelerated) full-packet pace, EMSocket.cpp:668-717). (3) main pass over upload-slot sockets in list order starting at rememberedSlotCounter (round robin across loops), two laps: first lap gives doubleSendSize per socket, second lap gives all remaining budget (lines 444-468). Slot 0 is the head of m_StandardOrder_list; UploadQueue inserts new slots at index = current slot count (end of list) (UploadQueue.cpp:224).
- Interface (ThrottledSocket.h): ThrottledControlSocket::SendControlData, ThrottledFileSocket adds SendFileAndControlData, GetLastCalledSend, GetNeededBytes; both return SocketSentBytes{success, standardBytes, controlBytes}. CEMSocket maps them to Send(maxBytes, minFragSize, onlyControl).
- Stats: sent bytes (total and overhead-only) accumulated and fetched-and-reset once per UploadQueue::Process (UploadQueue.cpp:289).
- Download side (LOCAL DEVIATION): stock aMule/eMule per-socket download limits are replaced here by a global token bucket CDownloadBandwidthThrottler refilled each DownloadQueue::Process (DownloadQueue.cpp:417-427).

## 14. Download queue global logic (DownloadQueue.cpp)

- Process each tick: per-file Process, dynamic rarity thresholds from the sorted per-file source counts: bottom 25 percent boundary defines m_rareFileThreshold, next 50 percent m_commonFileThreshold (RARITY_FACTOR 4, NORMALITY_FACTOR 2, lines 405-522); these drive auto priority: sources <= rareThreshold PR_HIGH, < commonThreshold PR_NORMAL, else PR_LOW (PartFile.cpp:3060-3075).
- File list sorted every 10 s by download priority desc, then by (sources - notCurrentSources), then notCurrentSources (lines 991-1021).
- Local server GETSOURCES: queue serviced oldest-first weighted by priority; <= 15 files per TCP frame; next frame allowed after 15*(16+4) seconds; OP_GETSOURCES(_OBFU) = hash + u32 size (or u32 0 + u64 size for large files) (lines 1047-1143).
- Global UDP: rotates over other servers, OP_GLOBGETSOURCES(2) with up to MAX_FILES_PER_UDP_PACKET = 31 hashes (GETSOURCES2 appends sizes), <= MAX_REQUESTS_PER_SERVER = 35 per server, only for files with sourceCount < GetMaxSourcePerFileUDP (= 0.75*max capped 100), every UDPSERVERREASKTIME = 1300000 ms (lines 881-969, 64-70).
- Kad search per file when sources < UDP limit, at most 5 concurrent (KADEMLIATOTALFILE), backoff KADEMLIAREASKTIME = 1 h times search count (PartFile.cpp:1647-1676).

## 15. Misc facts for the port

- CMemFile (MemFile.h): little-endian binary buffer with transparent endian conversion; ReadUInt8/16/32/64, ReadHash (16B), length-prefixed strings; used for all packet payload build/parse.
- Upload states (Constants.h:156-166): US_UPLOADING=0, US_ONUPLOADQUEUE, US_WAITCALLBACK, US_CONNECTING, US_PENDING, US_LOWTOLOWIP, US_BANNED, US_ERROR, US_NONE.
- Part status bitmaps everywhere: u16 partCount then ceil(count/8) bytes, bit i of byte = part (byteIndex*8 + i), LSB first (PartFile.cpp:1463-1481, DownloadClient.cpp:430-450).
- OP_QUEUERANKING payload is exactly 12 bytes (u16 rank + 10 zero bytes).
- UDP OP_REASKACK answer: optional part status (UDP ver > 3) + u16 waiting position (ClientUDPSocket.cpp:221-231).
- OP_OUTOFPARTREQS moves the downloader back to on-queue without socket teardown (UploadClient.cpp:495-513).
- Complete-sources estimation (UpdatePartsInfo, PartFile.cpp:1853-1973): min part frequency = observed complete count, then percentile blend 80/20 with peers' reported counts (median/75th/87.5th percentiles depending on n).
- EXTENDED_UPLOADQUEUE is compiled out (UploadQueue.h:43 = 0); ignore PopulatePossiblyWaitingList.


### Key constants (as reported)

- PARTSIZE = 9728000 (include/protocol/ed2k/Constants.h:82)
- BLOCKSIZE = EMBLOCKSIZE = 184320 (include/protocol/ed2k/Constants.h:83-84)
- STANDARD_BLOCKS_REQUEST = 3, pipeline cap 0x20 (updownclient.h:103, DownloadClient.cpp:603)
- RSAKEYSIZE = 384 bits, RSASSA-PKCS1v15-SHA1 (include/protocol/ed2k/Constants.h:49, ClientCreditsList.cpp:311)
- MAXPUBKEYSIZE = 80 (ClientCredits.h:31)
- CREDITFILE_VERSION = 0x12 (include/common/DataFileVersion.h:40)
- credit expiry = 12960000 s = 150 days (ClientCreditsList.cpp:120)
- credit ratio: min(2*dl/ul, sqrt(dl/1048576+2)) clamped 1.0..10.0, dl<1000000 gives 1.0 (ClientCredits.cpp:138-158)
- upload prio multipliers: PowerShare 250.0, VeryHigh 1.8, High 0.9, Normal 0.7, Low 0.6, VeryLow 0.2; friend slot 0x0FFFFFFF (UploadClient.cpp:97-141)
- slot kick: session > 3600000 ms or > 10485760 bytes (UploadQueue.cpp:602-603)
- MIN_UP_CLIENTS_ALLOWED = 2, MAX_UP_CLIENTS_ALLOWED = 250 (include/protocol/ed2k/Constants.h:56,63)
- FILEREASKTIME = 1300000 ms; SOURCECLIENTREASKS = 40 min; SOURCECLIENTREASKF = 5 min; MINCOMMONPENALTY = 4; RARE_FILE = 50 (include/protocol/ed2k/Constants.h:35-43,66)
- SOURCEEXCHANGE2_VERSION = 4; SX entry sizes v1=12 v2/3=28 v4=29 bytes (include/protocol/ed2k/Constants.h:58, PartFile.cpp:2933-2946)
- CBB_BANTHRESHOLD = 32 percent, corrupt attribution min = EMBLOCKSIZE (CorruptionBlackBox.cpp:38,171)
- CLIENTBANTIME = 2 h; KEEPTRACK_TIME = 2 h; MIN_REQUESTTIME = 590000 ms; aggression: +3 per fast reask, ban at 10 (include/protocol/ed2k/Constants.h:67,71,73; UploadClient.cpp:658-669)
- dead source timeouts: global 30/45 min, per-file 45/60 min (LowID longer) (DeadSourceList.cpp:34-35)
- throttler: minFragSize 1300 (536 below 6 KB/s), doubleSendSize 2x, trickle after 1 s idle, backoff x5 max 1000 ms (UploadBandwidthThrottler.cpp:329-334,428,487)
- chunk rank bands: veryRare 25*freq+preview+100-completion; preview 10000/30000; rare +10101/30101; common 20000+(100-c) / 40000+c (PartFile.cpp:2137-2168)
- BUFFER_TIME_LIMIT = 60000 ms; DOWNLOADTIMEOUT = 100000 ms; MAX_PURGEQUEUETIME = 1 h (PartFile.h:46; include/protocol/ed2k/Constants.h:64,68)
- upload prepare buffer: EMBLOCKSIZE+1, or 5*EMBLOCKSIZE+1 above 76800 B/s; compression off above 153600 B/s when starved (UploadDiskIOThread.cpp:50-52,205-219)
- max 3 queued clients per IP; queue cap = pref x100; 1000 ms between upload starts (UploadQueue.cpp:488-492,510,517)


### Flagged unclear (by the recon agent)

- This tree is a locally modified aMule 3.0.1, not stock: GetMaxSlots floor of 20 slots in unlimited mode (UploadQueue.cpp:314), adaptive upload sub-packet size datarate/8 instead of fixed 10240 (UploadDiskIOThread.cpp:468), zlib level 1 instead of 9 (UploadDiskIOThread.cpp:512), global download token bucket replacing per-socket limits (DownloadQueue.cpp:426), SendBlockRequests batching more than 3 pending blocks across successive 3-block packets (DownloadClient.cpp:700-730), async PartFileWriteThread/PartFileHashThread FlushBuffer pipeline. Decide whether the Rust port must match this tree or upstream aMule 2.3.x/eMule behavior (wire formats are identical either way).
- ED2Kv2/VBT OP_REQUESTPARTS variant (OP_ED2KV2HEADER + varint tags, DownloadClient.cpp:766) is an aMule-only extension; whether to implement it (and GetVBTTags negotiation details from the hello tags) was not traced.
- CalculateScoreInternal returns 0 when IsDownloading() which on the upload side means m_nUploadState == US_UPLOADING (updownclient.h:265), i.e. the client already holds a slot; the method name collides with download-side semantics. Verify intent before porting.
- Default preference values used in formulas were not traced to Preferences.cpp: GetSlotAllocation (kB/s per slot), GetQueueSize (stored value x100), GetFileBufferSize (stored value x15000), GetMaxSourcePerFile.
- m_dwUploadTime used in the GetWaitStartTime clamp (UploadClient.cpp:382) - where it is set was not traced.
- OP_ANSWERSOURCES/OP_ANSWERSOURCES2 processing (ClientTCPSocket.cpp:1450-1495) appears to accept answers without verifying we actually sent a request to that client; confirm whether any anti-spoof gate exists elsewhere before replicating.
- Full .part.met tag serialization (FT_GAPSTART/FT_GAPEND named-tag encoding, other tags) was only spot-checked (PartFile.cpp:608-627, 820ff); it must be documented separately for on-disk compatibility.
- Hello/MuleInfo tag negotiation (m_bySupportSecIdent bits, MISC_OPTIONS bit layout giving SX1 version, ExtendedRequestsVersion, UDP version, m_byDataCompVer) was not extracted; needed for exact capability gating.
- VerifyIdent v2 ChallengeIP selection on the verifying side falls back between GetPublicIP and GetED2KID when LowID (ClientCreditsList.cpp:404-421); edge-case behavior when our public IP is unknown is best-effort and may fail identification legitimately.
- CreateSrcInfoPacket caps at 'nCount > 500 break' meaning up to 501 sources can be written; confirm intended cap (eMule historically capped at 500).


==============================================================================

## Verification corrections and gaps (ALL subsystems; these OVERRIDE reports)


### (verify pass, confidence=high)

- CLAIM: Section 3 / 3.2 overhead summary: 'Overhead: 8 bytes/packet (ed2k/server), 12 bytes/packet (kad, +4 verify keys).'
  CORRECTION: Kad UDP overhead is 16 bytes, not 12. The two verify keys are uint32 (4 bytes each = 8 bytes total), not 4 bytes. Total kad crypt header = CRYPT_HEADER_WITHOUTPADDING(8) + padLen(0) + 8 (two 4-byte verify keys) = 16 bytes. The report is internally contradictory: its own section 3.1 correctly states '8 trailing verify-key bytes' and 'ReceiverVerifyKey:4 enc, SenderVerifyKey:4 enc', but the overhead line says 12/'+4'. The report evidently trusted the STALE source header comment (EncryptedDatagramSocket.cpp:83 '<ReceiverVerifyKey 2><SenderVerifyKey 2>' and :85 'Overhead: 12 Bytes'), which the actual code contradicts.
  EVIDENCE: src/EncryptedDatagramSocket.cpp:272 `const uint32_t cryptHeaderLen = padLen + CRYPT_HEADER_WITHOUTPADDING + (kad ? 8 : 0);`; :365-366 encrypt writes 4 bytes each for receiverVerifyKey/senderVerifyKey; :242-243 decrypt reads 4 bytes each; :246 `result -= 8`; EncryptedDatagramSocket.h:39-40 params are `uint32_t *receiverVerifyKey, uint32_t *senderVerifyKey` (4 bytes each). Stale comment at :83,:85 says 2-byte keys / 12-byte overhead.
- CLAIM: Section 3.1 ed2k key: 'On SEND the IP is theApp->GetPublicIP() (sender's own public IP); on RECEIVE it is the local receiver ip param.'
  CORRECTION: The receive-side IP is NOT the local receiver's own IP; it is the source address of the received UDP datagram (the remote sender's public IP), passed in as the `ip` argument. For the RC4 keys to match, the receiver must key on the SENDER's public IP (which the sender put in via theApp->GetPublicIP()), i.e. the datagram source IP. Describing it as 'the local receiver ip' is misleading and would break interop if a reimplementer plugged in the local machine's own IP.
  EVIDENCE: src/ClientUDPSocket.cpp:78 `void CClientUDPSocket::OnPacketReceived(uint32 ip, uint16 port, ...)` where `ip` is the recvfrom source address; :85 passes that `ip` to DecryptReceivedClient. src/EncryptedDatagramSocket.cpp:187 receive uses `PokeUInt32(keyData + 16, ip)`; :304 send uses `PokeUInt32(keyData+16, theApp->GetPublicIP())` (sender's own public IP). The two only match when receive `ip` == sender's public IP == datagram source.
  GAPS:
  - UDP ed2k key hash differs by direction and the report never states it. Section 3.1 lists 'keyData[23] = UserHash[16]' generically, but on SEND the 16-byte hash is the TARGET client's hash (the clientHashOrKadID argument), while on RECEIVE it is the LOCAL client's own user hash (thePrefs::GetUserHash().GetHash()). This is the exact analogue of the send/receive hash asymmetry the report DID document for TCP C2C (section 2.4), and is load-bearing for correct key derivation. Evidence: src/EncryptedDatagramSocket.cpp:303 (send: md4cpy(keyData, clientHashOrKadID)) vs :185 (receive: md4cpy(keyData, thePrefs::GetUserHash().GetHash())).
  - The UDP magic-value endianness is produced by an UNCONDITIONAL byte swap (ENDIAN_SWAP_32 / ENDIAN_SWAP_I_32), not htonl. The report says the sync value is 'transmitted big-endian; code byte-swaps', which is only the practical result on a little-endian host (real x86 aMule). A reimplementer should hardcode big-endian on the wire for MAGICVALUE_UDP_SYNC_CLIENT/SERVER to interoperate with real (little-endian) aMule, and be aware this scheme is not endian-portable in the original. Evidence: src/EncryptedDatagramSocket.cpp:353,471 (encrypt) and :205,:402 (decrypt).
  - The EC_TAG_PASSWD_SALT tag value is encoded with EC's minimal-width integer rule (InitInt), so a salt whose high 32 bits are zero is transmitted as a UINT32 (or smaller) tag, not always 8 bytes; both sides recover the full value via GetInt() and format it with '%lX' over the full 64-bit value. A reimplementer must NOT assume the salt tag body is a fixed 8-byte field. Evidence: src/libs/ec/cpp/ECTag.cpp:207-221 (InitInt width selection); ExternalConn.cpp:565 constructs the tag from a uint64 m_passwd_salt; :638/RemoteConnect.cpp:324 compute the hash from GetInt().

### (verify pass, confidence=high)

- CLAIM: Section 4: 'Overhead = 12 bytes for Kad (8 header + 2*4 verify keys), 8 for ed2k.'
  CORRECTION: The Kad obfuscation overhead is 16 bytes, not 12. The report's own parenthetical (8 header + 2*4 verify keys) sums to 16 and contradicts the stated 12.
  EVIDENCE: EncryptedDatagramSocket.cpp:272 `cryptHeaderLen = padLen + CRYPT_HEADER_WITHOUTPADDING + (kad ? 8 : 0)` = 0 + 8 + 8 = 16 for kad (8 for ed2k). CRYPT_HEADER_WITHOUTPADDING=8 at line 109.
- CLAIM: Section 4 (twice): plaintext-passthrough / SemiRandomByte-excluded protocol set is 'E3/E4/E5/D4/C5/A3/B2'.
  CORRECTION: 0xE3 (OP_EDONKEYPROT) is NOT in either switch. The correct set is only 6 bytes: E4/E5/D4/C5/A3/B2. An incoming packet starting with 0xE3 is NOT treated as plaintext passthrough by DecryptReceivedClient; it is passed into the decryption attempt.
  EVIDENCE: EncryptedDatagramSocket.cpp:141-147 (DecryptReceivedClient passthrough switch) and 328-333 (semiRandom exclusion switch) list only OP_EMULEPROT(0xC5), OP_KADEMLIAPACKEDPROT(0xE5), OP_KADEMLIAHEADER(0xE4), OP_UDPRESERVEDPROT1(0xA3), OP_UDPRESERVEDPROT2(0xB2), OP_PACKEDPROT(0xD4). OP_EDONKEYPROT=0xE3 (Protocols.h:34-35) is absent.
- CLAIM: Sections 10 & CLAIMED KEY CONSTANTS: tolerance zone = 'distance top 24 bits must be 0 (distance < 2^104)'.
  CORRECTION: Wrong magnitude. The check is Get32BitChunk(0) (the MOST-significant 32 bits) <= SEARCHTOLERANCE = 0x01000000 = 2^24. That requires only the top ~7-8 bits of the 128-bit distance to be zero, i.e. distance up to ~2^120, not distance < 2^104. Implementing '< 2^104' would reject many publishes/stores that aMule accepts.
  EVIDENCE: Defines.h:46 `SEARCHTOLERANCE 16777216` (=2^24). Get32BitChunk(0)=u32_data[3]=top 32 bits (UInt128.h:109-111). Reject condition `distance.Get32BitChunk(0) > SEARCHTOLERANCE` at KademliaUDPListener.cpp:1032, 1130, 1310 and Search.cpp:464.
- CLAIM: Section 5: 'Kad1-only opcodes 0x00/0x08/0x10/0x18/0x20/0x28/0x30/0x32/0x40/0x42/0x48/0x4A are received but ignored (KademliaUDPListener.cpp:352-363).'
  CORRECTION: 0x48 (KADEMLIA_PUBLISH_RES) is NOT ignored; it is dispatched to a live handler (ProcessPublishResponse). The actually-ignored set (11 opcodes) is 0x00/0x08/0x10/0x18/0x20/0x28/0x30/0x32/0x40/0x42/0x4A. Also, the report's list of parsed legacy responses (0x38, 0x3A) should include 0x48.
  EVIDENCE: KademliaUDPListener.cpp:302-305 `case KADEMLIA_PUBLISH_RES: ProcessPublishResponse(...)`. The ignored no-op cases are 352-363: KADEMLIA_BOOTSTRAP_REQ/RES_DEPRECATED(0x00/0x08), HELLO_REQ/RES_DEPRECATED(0x10/0x18), REQ/RES_DEPRECATED(0x20/0x28), SEARCH_REQ(0x30), SEARCH_NOTES_REQ(0x32), PUBLISH_REQ(0x40), PUBLISH_NOTES_REQ/RES_DEPRECATED(0x42/0x4A).
- CLAIM: Section 7: 'Kad tag NAME bytes (single-char) - Tag.h:81-124'.
  CORRECTION: The tag name-byte constants (TAG_FILENAME..TAG_SOURCETYPE) live in include/tags/FileTags.h:81-124, not Tag.h. The values quoted are correct, but a reimplementer following the citation would look in the wrong file (Tag.h at src root defines CTag/CTagVarInt, not these constants).
  EVIDENCE: include/tags/FileTags.h:81-124 define TAG_FILENAME(\x01) .. TAG_SOURCETYPE(\xFF). `find . -name Tag.h` -> ./Tag.h, which contains CTag/CTagVarInt (Tag.h:157-186) and no TAG_* name macros.
- CLAIM: Section 7: TAGTYPE_BLOB=0x07 and TAGTYPE_STR1..STR16=0x11..0x20 are listed as Kad tag value encodings (BLOB bidirectional; STR1..16 'read only').
  CORRECTION: The Kad tag reader CFileDataIO::ReadTag decodes only 8 types (HASH16, STRING, UINT64, UINT32, UINT16, UINT8, FLOAT32, BSOB) and throws on everything else, including BLOB(0x07) and STR1..16(0x11-0x20). A received Kad tag of those types aborts the whole packet parse; they are not parseable on the wire despite being listed.
  EVIDENCE: SafeFile.cpp:438-479 ReadTag switch handles only those 8 cases; default at line 481-485 throws 'Invalid Kad tag type'. (WriteTag at 553-558 can write BLOB, but Kad publish builders never emit it.)
  GAPS:
  - Verify-key endianness on the wire: the receiverVerifyKey and senderVerifyKey uint32s are byte-swapped to BIG-ENDIAN before being RC4-encrypted (and swapped back after decryption). The report notes the magic value is big-endian-swapped but omits that the two verify keys are also big-endian in the encrypted stream. Byte-exact interop requires this. Evidence: EncryptedDatagramSocket.cpp:363-366 (ENDIAN_SWAP_I_32 on both keys before RC4Crypt on send) and 244-245 (ENDIAN_SWAP_I_32 after RC4Crypt on receive).
  - SEARCH_RES on-wire count field: the report says the header (KadID+keyID+count) is re-sent per 50-entry packet but omits that the count(2) field is written as the literal value 50 in every full batch and only the final partial packet rewrites it to (count % 50) by seeking back to offset 32. A reimplementer parsing must trust the count field per packet; a sender must fix up the last packet's count. Evidence: Indexed.cpp:743 writes 50, :781 resets length to 16+16+2 keeping the '50', :803-806 seeks to 16+16 and rewrites countLeft.

### (verify pass, confidence=high)

- CLAIM: Section 8: clients.met "per record 102 bytes: 16B user hash key, uint32 uploaded_lo, uint32 downloaded_lo, uint32 nLastSeen, uint32 uploaded_hi, uint32 downloaded_hi, uint16 nReserved3, uint8 nKeySize, 80B abySecureIdent"
  CORRECTION: The field list and order are correct, but the record size is 119 bytes, not 102: 16+4+4+4+4+4+2+1+80 = 119.
  EVIDENCE: src/ClientCreditsList.cpp:125-133 (read: ReadHash 16B, five ReadUInt32 = 20B, ReadUInt16 2B, ReadUInt8 1B, Read(abySecureIdent, MAXPUBKEYSIZE) 80B) and src/ClientCreditsList.cpp:196-205 (write, same fields); MAXPUBKEYSIZE=80 at src/ClientCredits.h:31
  GAPS:
  - MET tag READ paths the report never specifies: the met-file tag reader CTag::CTag(CFileDataIO&,bool) (src/Tag.cpp:110-181) has NO case for TAGTYPE_BSOB (0x0A) - a BSOB tag in a met file throws CInvalidPacket('Unknown tag type') and aborts the record, even though WriteTag can emit BSOB. The reader also must handle: TAGTYPE_BOOL (0x05) = 1 payload byte read-and-discarded; TAGTYPE_BOOLARRAY (0x06) = uint16 len then skip (len/8)+1 bytes; TAGTYPE_STR1..STR16 (0x11-0x20) = implicit payload length (type - 0x11 + 1), normalized to STRING; TAGTYPE_BLOB length sanity check m_nSize > (fileLen - pos) -> throw (Tag.cpp:158-169). Only the Kad-packet path CFileDataIO::ReadTag (SafeFile.cpp:408-497) accepts BSOB.
  - Round-trip type widening: on read, UINT16 and UINT8 tags are normalized to UINT32 in memory (src/Tag.cpp:122-131 sets m_uType = TAGTYPE_UINT32), so 'retained foreign tags' in known.met/part.met that arrived as type 0x08/0x09 are rewritten as type 0x03 (4-byte payload) on the next save - re-serialization is not byte-identical for foreign u8/u16 int tags.
  - PR_AUTO numeric value is never given: PR_AUTO = 5 (src/Constants.h:118; PR_LOW=0, PR_NORMAL=1, PR_HIGH=2, PR_VERYLOW=4 per src/Constants.h:110-118). Required to write FT_ULPRIORITY/FT_DLPRIORITY/FT_OLDDLPRIORITY 'PR_AUTO if auto', and the load-side validation clamps unknown priorities to PR_NORMAL (src/KnownFile.cpp:650-670).
  - .seeds v2 format is omitted: loader accepts non-zero first byte = count with 6-byte entries PLUS a trailing uint32 save-time (v2); seeds older than 2 hours (timeFromFile + MIN2S(120) < now) are discarded (src/PartFile.cpp:1206-1218); and in the v1/v2 (non-SX2) path the stored uint32 user ID is byte-swapped with wxUINT32_SWAP_ALWAYS on load (src/PartFile.cpp:1194).
  - part.met save mechanics: the new content is written to '<name>.part.met.tmp' (not write_safe/.new), then rename(.part.met -> .part.met.bak) and rename(.tmp -> .part.met) (src/PartFile.cpp:864-878, 1030-1046); a zero-length .tmp is detected and discarded, preserving the old .part.met (PartFile.cpp:1020-1030). A reimplementer duplicating the save path needs the exact temp suffix for crash-recovery/cleanup compatibility.
  - .part creation precedence: a sparse file is created only when CreateFilesSparse is set AND AllocFullFile is NOT set - the condition is if (GetAllocFullFile() || !CreateFilesSparse()) create-normal else create-sparse (src/PartFile.cpp:356-361); the report's wording loses the precedence when both prefs are set.
  - server.met load, like ipfilter.dat, first passes the file through UnpackArchive (it may be a zip/gzip archive containing 'server.met') and requires EFT_Met detection (src/ServerList.cpp:106-111).
  - clients.met sidecar: on load, clients.met is copied to 'clients.met.bak' (unless the existing .bak is larger) before parsing (src/ClientCreditsList.cpp:84-115, CLIENTS_MET_BAK_FILENAME at line 45); the save itself is a plain truncating write (CFile::Create + write), not an atomic write_safe.
  - nodes.dat read validation: normal files require numContacts * 25 <= remaining bytes (src/kademlia/routing/RoutingZone.cpp:175), bootstrap files require numContacts * 25 == remaining bytes exactly (RoutingZone.cpp:246), and contacts with kad version <= 1 are silently dropped (RoutingZone.cpp:193-206).
  - String writer truncation rule: WriteStringCore truncates any string whose encoded length (incl. BOM) exceeds 0xFFFF bytes down to 0xFFFF when using the default uint16 length prefix (src/SafeFile.cpp:361-380).
  - known.met load fallback: if FT_LASTSEEN is absent (pre-3.x file), m_lastSeen is set to m_lastDateChanged (src/KnownFile.cpp:730-739), which is what gets written back into FT_LASTSEEN on the next save - affects byte-level round-trip of upgraded files.
  - ipfilter fallback path: if config-dir ipfilter.dat fails to load and the UseIPFilterSystem pref is set, a system-wide ipfilter.dat (wxStandardPaths data dir) is loaded before ipfilter_static.dat (src/IPFilter.cpp:114-127).

### (verify pass, confidence=high)

- CLAIM: Section 1: Requested_Block_Struct = { StartOffset u64, EndOffset u64, FileID[16], transferred u32 }
  CORRECTION: The struct has a uint32 packedsize field between EndOffset and FileID: { StartOffset u64, EndOffset u64, packedsize u32, FileID[16], transferred u32 }. Field order/contents as given are wrong.
  EVIDENCE: src/OtherStructs.h:69-75
- CLAIM: Section 7: 'Kicked client receives OP_OUTOFPARTREQS and is re-queued (keeps credit wait time)'
  CORRECTION: The kicked client does NOT keep its wait time. SendOutOfPartReqsAndAddToWaitingQueue calls AddClientToQueue, which unconditionally calls client->ClearWaitStartTime() before appending to the waiting queue; the credit wait clock restarts at the next scoring (GetSecureWaitStartTime re-seeds both timers when they are 0).
  EVIDENCE: src/UploadQueue.cpp:515 (client->ClearWaitStartTime()), src/UploadClient.cpp:495-513, src/ClientCredits.cpp:236-237,262-266
- CLAIM: Section 5: AICHRecoveryDataAvailable - 'Part is then removed from m_corrupted_list regardless'
  CORRECTION: Not in the MD4-mismatch path. When the part became complete but HashSinglePart fails, the function sets AICH_ERROR, re-gaps the part and RETURNS early (line 3980), skipping EraseFirstValue(m_corrupted_list, nPart) at line 4002 and the SavePartFile. Removal happens in every path except that one.
  EVIDENCE: src/PartFile.cpp:3973-3980 (early return) vs 4002 (EraseFirstValue)
- CLAIM: Section 2 step 9/10: 'source is purged after 60 s' (queue-full), 'DS_LOWTOLOWIP purged after 30 s', 'DS_NONEEDEDPARTS sources: every 40 s try SwapToAnotherFile' - described as per-source timers
  CORRECTION: The 30 s / 40 s / 60 s values gate (dwCurTick - lastpurgetime), where lastpurgetime is a single per-FILE timestamp shared by all three branches and updated on each successful purge/swap. It is a rate limiter of roughly one purge (or successful A4AF swap) per interval per file, not a per-source age. E.g. after one NNP source swaps, no other NNP source of that file swaps or is purged for 40 s.
  EVIDENCE: src/PartFile.cpp:1547-1550 (LOWTOLOWIP, 30000), 1561-1572 (NNP, 40000), 1587-1591 (queue-full, 60000) - all test/set the same lastpurgetime member
- CLAIM: Section 7: '0 if: ... IsBadGuy (failed secure ident, BaseClient.cpp:2559)'
  CORRECTION: IsBadGuy is not 'failed secure ident'. IsBadGuy() returns true when GetCurrentIdentState == IS_IDBADGUY, i.e. the client IS identified but is currently connecting from a different IP than the one it verified from. Failed ident is IS_IDFAILED (SUIFailed(), BaseClient.cpp:2564). (Report section 8.5 states this correctly; section 7 contradicts it.)
  EVIDENCE: src/BaseClient.cpp:2559-2567, src/ClientCredits.cpp:219-231
- CLAIM: Section 7: 'oldMuleFactor 0.5 for eMule version <= 0x19 (line 144)'
  CORRECTION: The 0.5 factor applies only when (IsEmuleClient() || GetClientSoft() < 10) AND m_byEmuleVersion <= 0x19. As stated, the rule would halve the score of any client whose m_byEmuleVersion happens to be <= 0x19 (e.g. 0 for non-eMule clients with soft id >= 10).
  EVIDENCE: src/UploadClient.cpp:144: if ( (IsEmuleClient() || GetClientSoft() < 10) && m_byEmuleVersion <= 0x19)
- CLAIM: Section 14: Kad search per file when sources < UDP limit, with the UDP limit defined earlier as 'GetMaxSourcePerFileUDP (= 0.75*max capped 100)'
  CORRECTION: Two different functions exist. The server-UDP loop (DownloadQueue.cpp:927) uses thePrefs::GetMaxSourcePerFileUDP() = 0.75*maxSourcesPerFile capped at 100 (Preferences.h:298-301). The Kad gate (PartFile.cpp:1648) uses CPartFile::GetMaxSourcePerFileUDP() = 0.75*GetMaxSources() capped at MAX_SOURCES_FILE_UDP = 50. The report gives a single cap-100 limit for both.
  EVIDENCE: src/PartFile.cpp:1648, src/PartFile.cpp:4566-4573, src/include/protocol/ed2k/Constants.h:52 (MAX_SOURCES_FILE_UDP 50), src/Preferences.h:298-301
- CLAIM: Section 4: 'All blocks requested from one source must come from the same part'
  CORRECTION: Overstated. Within a single GetNextRequestedBlock call, when the current part has no more empty blocks the code sets LastPartAsked=0xffff, selects a new chunk, and keeps filling the SAME batch - so one batch (and thus one wire packet) can contain blocks from two different parts. The invariant is only that each block comes from the sender's LastPartAsked at the moment it is generated.
  EVIDENCE: src/PartFile.cpp:2037-2076 (main loop re-selects a chunk mid-batch and continues until newBlockCount == count)
- CLAIM: Section 13: main pass 'two laps: first lap gives doubleSendSize per socket, second lap gives all remaining budget'
  CORRECTION: The doubleSendSize amount is given only for the first (slots-1) iterations: data = (slotCounter < slots - 1) ? doubleSendSize : (bytesToSpend - spentBytes). The LAST socket of the first lap already receives the full remaining budget (the code comment says 'Second pass starts with the last slot of the first pass actually'). With slots == 1, the single socket immediately gets the whole budget.
  EVIDENCE: src/UploadBandwidthThrottler.cpp:448-454
  GAPS:
  - No opcode byte values or protocol header IDs anywhere in the report. Wire compatibility requires them: OP_EDONKEYPROT=0xE3, OP_EMULEPROT=0xC5, OP_ED2KV2HEADER=0xF4 (src/include/protocol/Protocols.h:44-48); OP_COMPRESSEDPART=0x40, OP_SENDINGPART=0x46, OP_REQUESTPARTS=0x47, OP_STARTUPLOADREQ=0x54, OP_OUTOFPARTREQS=0x57, OP_QUEUERANKING=0x60, OP_REQUESTSOURCES=0x81..OP_ANSWERSOURCES2=0x84, OP_PUBLICKEY=0x85, OP_SIGNATURE=0x86, OP_SECIDENTSTATE=0x87, OP_MULTIPACKET=0x92, OP_AICHREQUEST=0x9B, OP_COMPRESSEDPART_I64=0xA1, OP_SENDINGPART_I64=0xA2, OP_REQUESTPARTS_I64=0xA3, OP_MULTIPACKET_EXT=0xA4 (src/include/protocol/ed2k/Client2Client/TCP.h:32-99); UDP OP_REASKFILEPING=0x90, OP_REASKACK=0x91, OP_FILENOTFOUND=0x92, OP_QUEUEFULL=0x93 (src/include/protocol/ed2k/Client2Client/UDP.h:31-34).
  - ED2Kv2 OP_REQUESTPARTS encoding: each offset is written as a full eD2K varint TAG via CTagVarInt(0, offset).WriteTagToFile(&data) (src/DownloadClient.cpp:776-777) - the tag wire format (type byte, name encoding, varint layout) is load-bearing and unspecified; 'two varint tags' alone is not implementable.
  - Tick period is never defined: CORE_TIMER_PERIOD = 100 ms (GUI) / 300 ms (daemon) (src/amule.h:100-107). CPartFile::Process runs every core tick with the full source walk on every 10th tick (~1 s at 100 ms); UploadQueue::Process and DownloadQueue::Process also run per core tick (src/amule.cpp:1434-1435). All 'per tick' semantics in the report depend on this value.
  - VBT/ED2Kv2 peers only fetch NEW blocks when ALL pending blocks are complete - SendBlockRequests returns early if m_PendingBlocks_list is non-empty for GetVBTTags() peers (src/DownloadClient.cpp:593-598). Legacy peers refill the pipeline incrementally. This changes pipelining behavior materially.
  - m_dwLastBlockReceived is stamped both on every arriving block packet (src/DownloadClient.cpp:868) AND at the top of every SendBlockRequests call (src/DownloadClient.cpp:614); DOWNLOADTIMEOUT and the 5-second adaptive-pipeline window both key off it, so the 100 s timeout is 'since last block packet or last request sent', not strictly since last data.
  - UDP reask side conditions: UDPReaskForDownload is skipped entirely when IsSourceRequestAllowed() is true (TCP is preferred to also exchange sources, src/DownloadClient.cpp:1291-1293); LowID targets go via the buddy with OP_REASKCALLBACKUDP = buddyID hash + file hash + [status] + [complete count] (src/DownloadClient.cpp:1317-1341). OP_QUEUEFULL is only sent when (waiting users + 50) > queue size (src/ClientUDPSocket.cpp:240-244), and the UDP reask path also runs CheckForAggressive (src/ClientUDPSocket.cpp:194).
  - Second compression-disable trigger omitted: compression is also permanently disabled for a client when the disk thread's finished-read backlog exceeds MAX_FINISHED_REQUESTS_COMPRESSION = 15 while global upload rate > SLOT_COMPRESSIONCHECK_DATARATE (src/UploadDiskIOThread.cpp:51, 387-391).
  - Kad backoff search count is capped: m_TotalSearchesKad increments only up to 7, so max backoff is 7 h (src/PartFile.cpp:1665-1668). Report says 'times search count' without the cap.
  - AddClientToQueue LowID-server rejection has extra gates: it only applies when the client's download state is DS_NONE and it is not a friend (src/UploadQueue.cpp:398). Also every client entering the waiting queue gets ClearWaitStartTime() (src/UploadQueue.cpp:515) - wait time starts at queue entry, which is the mechanism behind scoring.
  - Upload data sub-packet framing rules beyond chunkSize: the first packet takes the whole block when togo <= chunkSize + 2600, and the final packet absorbs the remainder whenever togo < 2*nPacketSize (src/UploadDiskIOThread.cpp:469-473, 525-529) - needed to reproduce exact packet boundaries; compressed parts also report an approximated payloadSize = nPacketSize*origSize/packedSize for stats/throttling (src/UploadDiskIOThread.cpp:550-556).
  - clients.met load details: a record with nKeySize > 80 causes the ENTIRE credit map to be discarded as corrupt (src/ClientCreditsList.cpp:135-146), and the .bak backup is only (re)created when the existing backup is not larger than the main file (src/ClientCreditsList.cpp:86-103).
  - SecureIdentState has the alias IS_ALLREQUESTSSEND = 0 (src/updownclient.h:63-68): after sending OP_SIGNATURE the client's m_SecureIdentState returns to 0, which gates the wxCHECK in SendSignaturePacket - needed to reproduce the handshake state machine.
  - OP_ACCEPTUPLOADREQ handling when the request file is stopped/not PS_READY|PS_EMPTY: reply OP_CANCELTRANSFER and set DS_NONE or DS_ONQUEUE (src/ClientTCPSocket.cpp:583-597) - the report only covers the DS_ONQUEUE happy path.

### (verify pass, confidence=high)

- CLAIM: Section 15.3: "Part-status bitfield ... uint16 part count (ED2K part count = ceil(size/PARTSIZE))"
  CORRECTION: ED2K part count is floor(size/PARTSIZE) + 1, NOT ceil. For a file of exactly N*PARTSIZE bytes the ED2K part count is N+1 (one more than ceil). Source: `m_iED2KPartCount = nFileSize / PARTSIZE + 1;` with an explicit table showing PARTSIZE -> 2 ED2K parts, PARTSIZE*2 -> 3 ED2K parts. This is wire-critical: the peer compares the received uint16 against its own GetED2KPartCount() and discards the whole part status on mismatch (UploadClient.cpp:214-218).
  EVIDENCE: amule-3.0.1/src/KnownFile.cpp:471 (formula), KnownFile.cpp:443-449 (table: "PARTSIZE -> 2(!) ED2K parts"), UploadClient.cpp:210-218 (mismatch check)
- CLAIM: Section 13/18: "In client hello the ID field carries the peer's ID in 'hybrid' (byte-swapped) form"
  CORRECTION: The hello ID field is sent as theApp->GetID() - the plain server-assigned ED2K client ID (or NTOHL'd Kad IP), not byte-swapped. The "hybrid" byte-swap exists only on the receiver side: the received value is stored into m_nUserIDHybrid and, for any non-LowID value, is unconditionally overwritten with wxUINT32_SWAP_ALWAYS(m_dwUserIP); only LowID values pass through unchanged.
  EVIDENCE: amule-3.0.1/src/BaseClient.cpp:1023 (`data->WriteUInt32(theApp->GetID())`), amule.cpp:2399-2415 (GetID), BaseClient.cpp:675-677 (receiver-side swap for non-LowID)
- CLAIM: Section 15.7: "OP_CHANGE_CLIENT_ID (0x4D): uint32 old ID, uint32 new ID"
  CORRECTION: The two fields are: uint32 NEW client ID, then uint32 NEW SERVER IP. The handler reads `nNewUserID` then `nNewServerIP` and looks the second value up in the server list. (The stale <ID_old><ID_new> comment in Client2Client/TCP.h:38 does not match the implementation.)
  EVIDENCE: amule-3.0.1/src/ClientTCPSocket.cpp:703-719 (`uint32 nNewUserID = data.ReadUInt32(); uint32 nNewServerIP = data.ReadUInt32();` then GetServerByIP(nNewServerIP))
- CLAIM: Section 9.2: FT_FILETYPE search filter types are "Audio","Video","Image","Doc","Pro","Arc","Iso"
  CORRECTION: "Arc" and "Iso" are never sent on the wire. They are aMule-internal only (FileTags.h marks them "*Mule internal use only") and are remapped to "Pro" before the search parameter is written; file publishing does the same via GetED2KFileTypeSearchTerm. Only Audio/Video/Image/Doc/Pro appear in wire packets.
  EVIDENCE: amule-3.0.1/src/SearchList.cpp:725-733 (typeText == ED2KFTSTR_ARCHIVE/CDIMAGE -> ED2KFTSTR_PROGRAM), src/include/tags/FileTags.h:132-133 ("*Mule internal use only"), src/OtherFunctions.cpp:1072-1083
- CLAIM: Section 17: "PARTSIZE = 9728000 (0x94_5000) bytes"
  CORRECTION: 9728000 decimal = 0x947000, not 0x945000 (0x945000 = 9719808). The decimal value is correct; the hex gloss is wrong and would corrupt an implementation that copies the hex.
  EVIDENCE: amule-3.0.1/src/include/protocol/ed2k/Constants.h:85 (`const uint64 PARTSIZE = 9728000ull;`); printf verification: 9728000 = 0x947000
- CLAIM: Section 17 header attributes EDONKEYVERSION, CURRENT_VERSION_SHORT, KADEMLIA_VERSION, SO_AMULE, MAX_PACKET_SIZE and STANDARD_BLOCKS_REQUEST ('implicit') to src/include/protocol/ed2k/Constants.h
  CORRECTION: None of these live in ed2k/Constants.h. EDONKEYVERSION=0x3c and CURRENT_VERSION_SHORT=0x47 are in include/common/ClientVersion.h:42,39; KADEMLIA_VERSION=0x08 is in include/protocol/kad2/Constants.h:29; SO_AMULE=3 is in include/protocol/ed2k/ClientSoftware.h:33; MAX_PACKET_SIZE=2000000 is in EMSocket.cpp:42; STANDARD_BLOCKS_REQUEST=3 is explicitly #defined (not implicit) at updownclient.h:103. (The report's separate 'CLAIMED KEY CONSTANTS' block cites most of these correctly, so this is an internal contradiction.)
  EVIDENCE: amule-3.0.1/src/include/common/ClientVersion.h:39,42; src/include/protocol/kad2/Constants.h:29; src/include/protocol/ed2k/ClientSoftware.h:33; src/EMSocket.cpp:42; src/updownclient.h:103
- CLAIM: Section 6.1 tag table presents TAGTYPE_BSOB = 0x0A as a readable wire tag type alongside the others, flagging only STR17..STR22 as types the reader throws on
  CORRECTION: The ED2K CTag wire reader (CTag::CTag(const CFileDataIO&, bool)) has NO case for TAGTYPE_BSOB - a BSOB tag in an ED2K packet hits the default branch and throws CInvalidPacket("Unknown tag type"), exactly like STR17-22. BSOB is only parsed by the separate Kad-side CFileDataIO::ReadTag. The 'uint8 length + bytes' encoding is correct for the writer (WriteBsob) but a reimplementation of the ED2K tag reader must reject 0x0A, not parse it.
  EVIDENCE: amule-3.0.1/src/Tag.cpp:110-180 (switch has HASH16/STRING/UINT32/UINT64/UINT16/UINT8/FLOAT32/BOOL/BOOLARRAY/BLOB + STR1-16 default; no TAGTYPE_BSOB case), Tag.cpp:172-180 (throw)
  GAPS:
  - OP_HASHSETANSWER count rule: part-hash count is 0 for files < PARTSIZE, else floor(size/PARTSIZE)+1 (KnownFile.cpp:474-478), and the receiver hard-checks the received uint16 against its own GetED2KPartHashCount() and drops the hashset on mismatch (KnownFile.cpp:578). Tied to the ceil-vs-floor+1 error: a reimplementer using ceil produces off-by-one hashsets for exact-multiple file sizes.
  - Upload data is CHUNKED: a single requested block (<= 184320 bytes) is answered with MULTIPLE self-contained OP_SENDINGPART packets, each with its own hash/start/end covering a sub-range (adaptive chunk size clamp(uploadDatarate/8, 10240, EMBLOCKSIZE); UploadDiskIOThread.cpp:456-502). Section 4's "a large data packet is ONE ED2K packet" is true of framing but a reimplementer must accept (and ideally emit) sub-range packets within a requested block, and must not assume one packet per block. Same chunking applies to OP_COMPRESSEDPART slices (UploadDiskIOThread.cpp:505-562).
  - ED2Kv2 wire formats are actually emitted by this codebase, not just dispatched: when the peer advertises VBT tags (CT_EMULECOMPAT_OPTIONS bit 1), block requests go out as OP_ED2KV2HEADER (0xF4) OP_REQUESTPARTS with body [hash16][uint8 blockCount][per block: VarInt-tag start, VarInt-tag end] (DownloadClient.cpp:766-784), and ProcessED2Kv2Packet parses ED2Kv2 OP_REQUESTPARTS/OP_QUEUERANK replies (ClientTCPSocket.cpp:1786+, UploadClient.cpp:741+ ProcessRequestPartsPacketv2, note its EndOffset+1 semantics). aMule 3.0.1 itself advertises nValueBasedTypeTags=0 (BaseClient.cpp:1148-1152), but a Rust port must either implement these formats or never set the VBT bit.
  - OP_HELLO receive validation: the leading hash-size byte MUST be exactly 16 or the packet is rejected with an exception/disconnect (BaseClient.cpp:361-372). The report gives the send format but not this receive-side hard requirement.
  - Source-exchange packet bodies are entirely omitted although the opcodes are listed: standalone OP_REQUESTSOURCES2 body is [uint8 SX2 version=SOURCEEXCHANGE2_VERSION(4, Constants.h:59)][uint16 options=0][hash16] (DownloadClient.cpp:305-317) - note version/options come BEFORE the hash standalone but AFTER the sub-opcode inside OP_MULTIPACKET (ClientTCPSocket.cpp:1098-1106); OP_ANSWERSOURCES/OP_ANSWERSOURCES2 reply is [uint8 version (SX2 only)][hash16][uint16 count][count * source entry whose layout varies by negotiated version] (CKnownFile::CreateSrcInfoPacket, KnownFile.cpp:976+).
  - The protocol-obfuscation layer is not described at all: CEncryptedStreamSocket TCP handshake (CryptPrepareSendData is applied to every outgoing buffer, EMSocket.cpp:548), CEncryptedDatagramSocket for UDP, the server UDP key / obfuscated ping raw-packet format (ServerList.cpp:296-313, random challenge (rand()<<17|rand()<<2|rand()&3), sent to TCP port+12). The report documents the crypt capability flags and *_OBFU opcodes, so a reimplementer will negotiate crypt it cannot speak unless it also clears those flags.
  - Float tags on the wire are NOT endian-swapped: both the CTag reader (Tag.cpp:135-138, `data.Read(&m_fVal, 4)`) and WriteNewEd2kTag (Tag.cpp:365-367) move the raw 4 bytes, unlike CFileDataIO::ReadFloat/WriteFloat which swap. Section 5's blanket "float32 ... endian-swapped" statement does not hold on the tag path (the only path where floats appear in ED2K packets).
  - Simple-search AND-optimization scope: the interleaved-AND form is only used when the parsed expression has <= 1 term (`_SearchExpr.m_aExpr.GetCount() <= 1`, SearchList.cpp:777); with a multi-term boolean expression the ANDs for filter parameters are all emitted up front before the expression tree (SearchList.cpp:888-960). The report describes only the first branch ("no OR, no NOT" is an approximation of the actual GetCount()<=1 condition).
  - OP_REQUESTFILENAME extended info is version-gated: part status appended only if peer ExtendedRequestsVersion > 0, complete-sources uint16 only if > 1 (DownloadClient.cpp:274-279 and 235-240); receiver throws if a peer advertising extreq>0 sends a bare 16-byte packet (UploadClient.cpp:205-208). The report says "optionally followed" without giving the gating rule a reimplementer needs.
  - Server UDP opcodes OP_INVALID_LOWID (0x9E), OP_SERVER_LIST_REQ (0xA0), OP_SERVER_LIST_RES (0xA1) exist in Client2Server/UDP.h:41-43 but are absent from the report's opcode list.
