# Wave 6 Kad research - nodes.dat, UDP protocol, routing, search, UDP obfuscation

Date: 2026-07-14
Method: 5 parallel source-grounded agents over eMule 0.50a kademlia/ (WIRE
AUTHORITY) + aMule 3.0.1 cross-ref, synthesised. Fixture (crates/mule-files/
tests/fixtures/nodes.dat) confirmed byte-exact: v2, 179 contacts, 34-byte records.
RAW - do not edit; corrections go in the wiki.

Fixture confirmed byte-exact (179 records x 34 bytes + 12-byte header = 6098; next record boundary at 0x2E). Here is the reconciled spec.

---

# padMule Wave 6 (Kad DHT) - Implementation Spec

Wire source of truth: **eMule 0.50a** (`refs/emule-0.50a/.../srchybrid/kademlia` + `EncryptedDatagramSocket.cpp`). Cross-checked: **aMule 3.0.1** (`amule-3.0.1/src`). Where wire differs, eMule wins; aMule divergences flagged `[DIV]`.

---

## 0. Cross-cutting: CUInt128 (the one landmine everything shares)

- Storage: `ULONG m_uData[4]`, **word 0 = most-significant** (bits 127..96), word 3 = LSW (`UInt128.h:90`).
- `SetValueBE(pby)`: `m_uData[i/4] |= pby[i] << 8*(3-(i%4))` -> word 0 = BE value of hash bytes H0..H3 (`UInt128.cpp:114-118`).
- `ToByteArray`: `_byteswap_ulong` per word -> recovers canonical BE H0..H15 (`UInt128.cpp:220-226`). Used for **local file-id lookup only**, never the wire.
- `GetData()`/`GetDataPtr()` = `(byte*)m_uData`, **raw memory, no swap** (`UInt128.cpp:346-353`).
- **Disk + wire both serialize the raw form** (`WriteUInt128`/`ReadUInt128` = `Read/Write(GetDataPtr(),16)`, `SafeFile.cpp:62-65,171-174,409-422`). So a 128-bit ID on both disk and wire is:

  **4 dwords, MSW-first, each dword little-endian.** For canonical hash `H[0..15]` the 16 bytes are:
  ```
  H3 H2 H1 H0 | H7 H6 H5 H4 | H11 H10 H9 H8 | H15 H14 H13 H12
  ```
  Rust: to recover the canonical hash, byteswap each of the four 4-byte groups (keep group order). **Never `SetValueBE` on-disk/on-wire bytes** - double-transform, wrong node. Recon CONFIRMED by all 5 reports.
- `Get32BitChunk(i) = m_uData[i]`; chunk 0 = top word (bits 127..96). Underpins tolerance test.
- `GetBitNumber(uBit)`: `iLongNum=uBit/32; iShift=31-(uBit%32); return (m_uData[iLongNum]>>iShift)&1`. **Bit 0 = MSB of the whole 128.** Returns 0 if `uBit>127`.
- Keyword target = `SetValueBE(MD4(utf8 keyword))` (`Kademlia.cpp:536-541`); source target = file's ed2k hash loaded BE. Both then word-swapped by `WriteUInt128` on the wire.

All scalar fields (ports, counts) are ordinary little-endian `WriteUInt16/32/64`. IP is a `WriteUInt32` of a **network-order** value -> on disk/wire the 4 bytes are octets `a.b.c.d` in order; store/forward verbatim, `ntohl` only for display.

---

## A. nodes.dat on-disk format

Header (`RoutingZone.cpp` ReadFile eMule:177-197, writeFile:366-370):

| Field | Size | Notes |
|---|---|---|
| legacyContactCount | u32 LE | Modern writer emits **0** (old clients bail). Nonzero ? v0 file, value = contact count. |
| fileVersion | u32 LE | 1..3 known; else ignored (:192). Present only if first dword==0. |
| bootstrapEdition | u32 LE | **only if version==3**. ==1 ? bootstrap-only file -> `ReadBootstrapNodesDat` (:184-190). |
| numContacts | u32 LE | if version 1..3 (:193). |

Sanity gate: `numContacts!=0 && numContacts*25 <= (len-pos)` (:198). The `*25` is a **floor only** (v0-record size), not the real v2/v3 size.

**Modern header = 12 bytes:** `00000000 | version | count`. Writer always emits `WriteUInt32(0); WriteUInt32(2); WriteUInt32(count)` - **version 2**, cap 200 (`GetBootstrapContacts(&list,200)`, :364).

Per-contact record (order, ReadFile:207-226):

| Field | Size | Notes |
|---|---|---|
| Kad ID | 16 | raw CUInt128 form (?0) |
| IP | 4 | network-order octets |
| UDP port | 2 LE | |
| TCP port | 2 LE | |
| - then version-dependent - | | |
| v0: byType | 1 | (rejected by aMule) |
| v1: contactVersion | 1 | |
| v2/v3: contactVersion | 1 | |
| v2/v3: CKadUDPKey | 8 | `key u32 LE` + `creatorIP u32 LE` (`KadUDPKey.h:33-34`) |
| v2/v3: verified | 1 | `ReadUInt8()!=0` |

**Record sizes: v0/v1 = 25 bytes; v2/v3 = 34 bytes.**

Bootstrap-only file (v3/edition1): records are v1-style 25-byte (ID+IP+UDP+TCP+version, no key/verified), exact-fit check `numContacts*25 == remaining` (`:286,292-296`).

**Fixture VERIFIED byte-exact** (`crates/mule-files/tests/fixtures/nodes.dat`, 6098 B): header `00000000 | 02000000 | b3000000` -> legacy 0, version 2, count 179. `(6098-12)/34 = 179.0` exact. First record @0x0C: ID raw `5cd0b88f 27b73493 09efb1ee 28f96ee8` (canonical `8fb8d05c 9334b727 eeb1ef09 e86ef928`), IP `226.80.49.93`, UDP 4672 (0x1240), TCP 4662 (0x1236), version 8, key 0x33146564, issuerIP `2d572910`, verified 01. Next record at 0x2E ? **34 bytes confirmed**.

`[DIV]` aMule: refuses v0 outright (`RoutingZone.cpp:170-173`); on load admits only `contactVersion>1` (drops Kad1). Byte layout identical.

---

## B. Kad UDP protocol - framing + opcodes + message layouts

### Framing (after obfuscation stripped)
`[0]=0xE4 (OP_KADEMLIAHEADER) | [1]=opcode | [2..]=payload` (`opcodes.h:136-137`). If total > 200 bytes -> zlib-pack, header becomes `0xE5 (OP_KADEMLIAPACKEDPROT)`, opcode byte NOT compressed (copied verbatim after decompress) (`KademliaUDPListener.cpp:2050-2090`, receive `ClientUDPSocket.cpp:103-123`). Dispatch: `byOpcode=pbyData[1]`, payload=`pbyData+2`, `uLenPacket=uLenData-2` (`:251-253`). Port-53 packets dropped (:239). Every RES handler checks `IsOnOutTrackList(ip, matchingReqOpcode)` first, throws on unsolicited.

### Kad2 opcode table (byte = packet byte[1]) - eMule==aMule identical (`opcodes.h:561-625`)

| Opcode | Byte |
|---|---|
| KADEMLIA2_BOOTSTRAP_REQ | 0x01 |
| KADEMLIA2_BOOTSTRAP_RES | 0x09 |
| KADEMLIA2_HELLO_REQ | 0x11 |
| KADEMLIA2_HELLO_RES | 0x19 |
| KADEMLIA2_REQ (FIND_NODE) | 0x21 |
| KADEMLIA2_HELLO_RES_ACK | 0x22 |
| KADEMLIA2_RES | 0x29 |
| KADEMLIA2_SEARCH_KEY_REQ | 0x33 |
| KADEMLIA2_SEARCH_SOURCE_REQ | 0x34 |
| KADEMLIA2_SEARCH_NOTES_REQ | 0x35 |
| KADEMLIA2_SEARCH_RES | 0x3B |
| KADEMLIA2_PUBLISH_KEY_REQ | 0x43 |
| KADEMLIA2_PUBLISH_SOURCE_REQ | 0x44 |
| KADEMLIA2_PUBLISH_NOTES_REQ | 0x45 |
| KADEMLIA2_PUBLISH_RES | 0x4B |
| KADEMLIA2_PUBLISH_RES_ACK | 0x4C |
| KADEMLIA_FIREWALLED2_REQ | 0x53 |
| KADEMLIA2_PING | 0x60 |
| KADEMLIA2_PONG | 0x61 |
| KADEMLIA2_FIREWALLUDP | 0x62 |

Kad1 opcodes (0x00,0x08,0x10,0x18,0x20,0x28,0x30,0x32,0x38,0x3A,0x40,0x48,0x50-0x5A) are **deprecated - do NOT emit** (`opcodes.h:562-614`).

REQ `type` values (`opcodes.h:622-625`): `FIND_VALUE=0x02`, `STORE=0x04`, `FIND_NODE=0x0B`, `FIND_VALUE_MORE=FIND_NODE=0x0B`.

**Version byte `KADEMLIA_VERSION`: eMule = `0x09`; `[DIV]` aMule = `0x08`** (`opcodes.h:23-31` / `[aMule] kad2/Constants.h:29`). Real on-wire difference; written into every self-contact. Ladder: 6=obfuscation/UDP-fwcheck, 7=keys+FIREWALLED2, 8=KADMISCOPTIONS+HELLO_RES_ACK, 9=AICH on keyword storage. **For padMule pick one and be consistent; recommend eMule 0x09 (SOT) but interop-test both.**

### BOOTSTRAP_REQ (0x01)
**Payload EMPTY** (`Bootstrap()` sends zero-length `CSafeMemFile(0)`, `:94-103`). (Corrects earlier recon "carries our contact" - that was deprecated Kad1.) If target version>=6, target Kad ID passed to crypt layer for obfuscation, but Kad body empty.

### BOOTSTRAP_RES (0x09) (`:511-582`)
```
selfKadID     16   (?0 form)
selfTCPPort    2   u16 LE
version        1   u8
contactCount   2   u16 LE   (<=20)
contactCount x 25-byte records:
   clientKadID 16
   IP           4   (network-order)
   UDPPort      2   u16 LE
   TCPPort      2   u16 LE
   version      1   u8
```
On RES: first (self) contact added; if our zone was empty, all listed marked `bAssumeVerified=true`.

### HELLO_REQ (0x11) / HELLO_RES (0x19) - body from `SendMyDetails` (:106-160)
```
selfKadID   16
selfTCPPort  2   u16 LE
version      1   u8
tagCount     1   u8
[tag TAG_SOURCEUPORT]    present unless UseExternKadPort -> internal UDP port
[tag TAG_KADMISCOPTIONS] only if version>=8 AND (reqAck|TCPfw|UDPfw)
```
Parsed `AddContact_KADEMLIA2` (:429-508). `TAG_KADMISCOPTIONS` bits: `0x01`=UDP-fw, `0x02`=TCP-fw, `0x04`=requests HELLO_RES_ACK (sender packs `(reqAck<<2)|(tcpFw<<1)|udpFw`, :138-142). **UDP-firewalled contacts NOT added to routing table** (:502-506).

**Kad tag wire format (NOT eD2k):** `<type u8><nameLen u16 LE><name bytes><value>`, `TagList` prefixed by `<u8 count>` (`DataIO.cpp:312-420`). Names are single bytes. Types: STRING=0x02, HASH=0x01, UINT32=0x03, FLOAT32=0x04, UINT16=0x08, UINT8=0x09, BSOB=0x0A, UINT64=0x0B. STRING value = `<u16 len><utf8>`; UINTxx = raw LE; BSOB = `<u8 size><bytes>`. Example SOURCEUPORT tag = `08 01 00 FC <port u16 LE>`.

### 3-way handshake / liveness (`:586-708`)
- HELLO_REQ -> add/update, reply HELLO_RES; request ACK only if `bAddedOrUpdated && !bValidReceiverKey` (:601), carried via TAG_KADMISCOPTIONS bit 0x04 (v8+).
- HELLO_RES -> if ACK requested & sender key exists, reply **HELLO_RES_ACK (0x22)** body `<selfKadID 16><u8 0>` (:684-690).
- HELLO_RES_ACK -> require `len>=17` + `bValidReceiverKey`, then `VerifyContact(id,ip)` marks verified (:633-652).
- v7 contacts: `KADEMLIA2_PING` challenge instead; pre-v7: `SendLegacyChallenge` (a KADEMLIA2_REQ w/ random target).

### FIND_NODE: KADEMLIA2_REQ (0x21) - CONFIRMED byte-exact (`:711-763`)
```
type      1   u8   (masked & 0x1F on recv; 0 rejected; low 5 bits = requested count/mode)
target   16   node id searched
receiver 16   recipient's own KadID  (MUST == our KadID else silent drop, :734)
```
= 33 bytes. Answers via `GetClosestTo(2, target, distance, type, &results)`.

### KADEMLIA2_RES (0x29) (`:744-829`)
```
target   16   (echoes REQ target)
count     1   u8   (max 32)
count x 25-byte records: clientKadID 16 | IP 4 | UDPPort 2 | TCPPort 2 | version 1
```
Exact-length check: `uLenPacket == 17 + 25*count` (:806). Kad1 (version<=1) contacts ignored (:831).

`[DIV]` aMule: only the version byte differs on the wire (0x08 vs 0x09). All opcodes, 0xE4/0xE5 headers, >200 compression threshold, payload layouts identical.

---

## C. Routing table - XOR distance, bin tree, lifecycle

Files: `Defines.h`, `RoutingZone.cpp/.h`, `RoutingBin.cpp/.h`, `Contact.cpp/.h`.

### Constants (`Defines.h`)
`K = 10` (bin size), `KBASE = 4`, `KK = 5`, `LOG_BASE_EXPONENT = 5`, `MAXLEVELS = 127`, `SEARCHTOLERANCE = 16777216 (0x01000000 = 2^24)`, **`ALPHA_QUERY = 3`** (eMule SOT).
IP-flood: `MAX_CONTACTS_IP = 1` (per exact IP, global), `MAX_CONTACTS_SUBNET = 10` (per /24, global), per-bin <=2 per /24 (LAN-exempt) (`RoutingBin.cpp:56-57,98-113`).

### Distance & tolerance
- `distance = self_KadID XOR contact_KadID`, computed at contact construction (`Contact.cpp:76-78`). Root zone stores `uMe = self KadID`.
- **Tolerance zone = `distance.Get32BitChunk(0) <= 0x01000000` ? 2^120** (chunk 0 = bits 127..96, so 2^24 . 2^96). **CONFIRMED 2^120 by Reports 1/2/3 + arithmetic. Report 4's "2^104" is WRONG - flagged.** Test: `if (chunk0 > SEARCHTOLERANCE && !IsLANIP(ntohl(ip)))` -> reject (anti-poisoning). Sites: `KademliaUDPListener.cpp:1277,1407,1671`, `Search.cpp:543`.

### Bin tree (`RoutingZone`)
- Zone = internal (`m_pBin==NULL`, two `m_pSubZones`) or leaf (`m_pBin!=NULL`). Fields: `m_uLevel` (0=whole space), `m_uZoneIndex`. Root `Init(NULL,0,0)`.
- Bin size K=10: `AddContact` appends only if `size < K` (`RoutingBin.cpp:116`).
- **CanSplit()** (`:459-468`): `if (m_uLevel>=127) return false; return (m_uZoneIndex < KK || m_uLevel < KBASE) && bin.GetSize()==K;` - full bin splits only if among 5 closest zones OR shallower than level 4.
- **Split** redistributes each entry by `distance.GetBitNumber(m_uLevel)`; `GenSubZone(side)`: `newIndex = zoneIndex<<1; if(side) +1; level+1`.
- **Add** descends by `GetDistance().GetBitNumber(m_uLevel)`; sub-zone 0 = closer to self. On full bin: split if `CanSplit()`, **else drop the new contact** (no ping-oldest-swap on insert).
- **Consolidate** merges two leaf subzones when `GetNumContacts() < K/2 (=5)`.
- `GetBootstrapContacts` returns top `TopDepth(LOG_BASE_EXPONENT=5)` contacts, capped (called w/ 200).

### Contact lifecycle (`Contact.cpp`)
- Init: `m_byType=3` (brand-new/unproven; lower=more trusted; **type 4 = dead-pending-removal**), `m_tExpires=0`, `m_tCreated=now`.
- **UpdateType()** (on confirmed-alive), by age `uHours=(now-created)/3600`: h0->type 2, expires now+1h; h1->type 1, now+1.5h; h>=2->type 0, now+2h.
- **CheckingType()** (before pinging oldest): no-op if `now-lastTypeSet<10` or type==4; else `lastTypeSet=now; expires=now+2min; type++`. Unanswered contact degrades one step per cycle until type 4 -> expiry.
- **Bin = LRU by list position:** new/refreshed -> back (`push_back`/`PushToBottom`); `GetOldest()=front()`.
- **OnSmallTimer** (per leaf, every `MIN2S(1)`, first fire staggered by `zoneIndex.Get32BitChunk(3)` secs): (1) remove entries with `type==4 && 0<expires<=now && !InUse`; if `expires==0` set to now. (2) oldest: if `expires>=now` or type==4 -> PushToBottom, stop. (3) else `CheckingType()` + send HELLO_REQ (v>=6 with UDPKey+clientID; v2..5 key 0, clientID NULL).
- **VerifyContact(id,ip):** requires `ip==GetIPAddress()`, sets `m_bIPVerified=true`. `SetIPAddress` clears verified on any IP change.
- Update guards (`:520-590`): UDP sender-key must match (anti-hijack); `pContact.version >= existing.version` (Kad1 can't overwrite Kad2).

Timers (`Kademlia.cpp`): big timer reschedule `now+SEC(10)`, fired zone next `now+HR2S(1)`; small timer `now+MIN2S(1)`; self-lookup every `HR2S(4)`. `OnBigTimer` does `RandomLookup` if leaf AND (`zoneIndex<KK || level<KBASE || bin free slots>=8`).

`[DIV]` aMule: `ALPHA_QUERY=5` (both upstream-aMule and the padMule tree), plus padMule-tree edits - **use eMule authoritative 3** (behavior, not wire; affects lookup parallelism / `m_mapBest` size only). All other routing constants identical.

---

## D. Search - iterative lookup + source search (Wave-6 gate)

### Iterative FIND_NODE (`Search.cpp`)
- **Seed** (`Go`): `GetClosestTo(3, target, distance, 50, &m_mapPossible)` -> up to 50 candidates keyed by XOR distance. Initial burst `iCount = (type==NODE)?1:min(ALPHA_QUERY, possible.size())`; each moved to `m_mapTried`, `SendFindValue`.
- **Per-query contact count** `GetRequestContactCount()`: NODE/NODECOMPLETE/NODESPECIAL/NODEFWCHECKUDP -> `FIND_NODE(11)`; FILE/KEYWORD/FINDSOURCE/NOTES -> `FIND_VALUE(2)`; FINDBUDDY/STORE* -> `STORE(4)`. (Independent of ALPHA_QUERY.)
- **ProcessResponse:** match responder in `m_mapTried` by (IP,UDPport); reject if `results.size() > GetRequestContactCount()` (unless reask); dedup (reject dup IP this response; max 2 IDs per /24 unless LAN); new contacts -> `m_mapPossible` by distance; maintain `m_mapBest` (size <= ALPHA_QUERY), immediately `SendFindValue` to any contact entering best set (parallel frontier).
- **JumpStart** (every `SEARCH_JUMPSTART=1`s): skip if response within 3s; pick closest untried, move to tried, send. If tried+responded -> `StorePacket()`. Closer-nodes reask: when top-2 tried all dead and `m_mapTried.size() >= 6`, reask with `bReAskMore` -> count bumped to `FIND_VALUE_MORE(11)`.
- Self-stops at TOTAL answers or (lifetime?20s). Lifetimes: SEARCHFILE/KEYWORD=45s, TOTAL=300, FINDSOURCE_TOTAL=20.

### SOURCE search - the Wave-6 differential gate
**Trigger:** `PrepareLookup(CSearch::FILE, true, fileHashUInt128)`, target = ed2k file hash.

**KADEMLIA2_SEARCH_SOURCE_REQ (0x34) payload** (sent to responded node closest-in-tolerance, contact version>=3):
```
target       16   file hash (?0 word-swapped)
startPos      2   u16 LE  (0x0000..0x7FFF)
fileSize      8   u64 LE
```
= 26 bytes. v>=6 obfuscated (UDPKey+clientID), else plain. Handler (`KademliaUDPListener.cpp:1155-1163`): read target, `startPos = ReadUInt16() & 0x7FFF`, filesize -> `SendValidSourceResult`.

**KADEMLIA2_SEARCH_RES (0x3B) response** (`Indexed.cpp:814-901`):
```
[0] 0xE4  [1] 0x3B
responderKadID  16
uKeyID          16   (echoes target/file hash)
count            2   u16 LE  (back-patched)
count x {
  sourceClientHash 16
  taglist  (<u8 count> then tags)
}
```
Filtered `uFileSize==0 || entry.size==0 || entry.size==uFileSize`; cap 300; fragmented at `UDP_KAD_MAXFRAGMENT=1420`, each fragment re-emits header+responderID+keyID+count.

Parser `Process_KADEMLIA2_SEARCH_RES` (`:1213-1254`): read uSource, uTarget, count; loop {ReadUInt128 answer; ReadTagList(bOptACP=true)} -> `ProcessResultFile`.

**Source tags** (single-byte names): `TAG_SOURCETYPE 0xFF u8` (1=HighID, 3=FW+buddy, 4=HighID>4GB, 5=FW>4GB, 6=FW direct-callback); `TAG_SOURCEIP 0xFE u32` (server-inserted from packet); `TAG_SOURCEPORT 0xFD u16` (TCP); `TAG_SOURCEUPORT 0xFC u16` (auto-added if absent); `TAG_SERVERIP 0xFB u32` / `TAG_SERVERPORT 0xFA u16` (buddy, FW); `TAG_BUDDYHASH 0xF8 string`; `TAG_ENCRYPTION 0xF3 u8`; `TAG_FILESIZE 0x02`. `ProcessResultFile` accepts types {1,3,4,5,6} -> `KademliaSearchFile(...)`.

### KEYWORD search (for completeness)
Target = MD4 of primary keyword; tokens split on `INV_KAD_KEYWORD_CHARS`, keep UTF-8 byte-len>=3. **KADEMLIA2_SEARCH_KEY_REQ (0x33):** `target 16 | flags u16` (`0x0000` no expr; `0x8000` + search-expression-tree if restrictive). Response = same 0x3B frame, per-result taglist w/ file tags (TAG_FILENAME 0x01 string, TAG_FILESIZE 0x02 u32/BSOB-u64, TAG_SOURCES 0x15 u32, TAG_PUBLISHINFO 0x33 u32 if sender v>=6, TAG_KADAICHHASHRESULT 0x37 BSOB if v>=9, media tags 0xD0-0xD5). Result kept only if filename+nonzero-size present and every query word appears in filename. `CreateSearchExpressionTree` (boolean AND/OR/NOT) **UNSURE - not byte-decoded; out of Wave-6 core scope.**

### PUBLISH (defer past gate) 
KADEMLIA2_PUBLISH_SOURCE_REQ (0x44): `targetID 16 | contactID(our hash) 16 | taglist`; stored only if in tolerance/LAN, lifetime `now+5h`, replies PUBLISH_RES (0x4B) `filehash 16 | load u8`. KADEMLIA2_PUBLISH_KEY_REQ (0x43): `target 16 | fileCount u16 | count x {fileID 16 | taglist}`, <=50 files/packet, cap 150.

`[DIV]` aMule: opcodes/constants identical; `ALPHA_QUERY=5` (use 3); renames reask cap `KADEMLIA_FIND_VALUE_MORE_REASKS=4`.

---

## E. Kad UDP obfuscation (CEncryptedDatagramSocket) - 5b

WIRE SOT `EncryptedDatagramSocket.cpp`. Both clients identical wire.

### Constants (:132-137)
`CRYPT_HEADER_WITHOUTPADDING=8`, `MAGICVALUE_UDP_SYNC_CLIENT=0x395F2EC1` (Kad sentinel), `MAGICVALUE_UDP=0x5B` (ed2k, unused for Kad). **Kad overhead = 16 bytes = 8 base + 8 (two verify keys)** = `byPadLen + 8 + (bKad?8:0)` with padLen=0 (:289).

### Packet layout (padLen normally 0)

| Off | Size | Field | Crypt |
|---|---|---|---|
| [0] | 1 | `bySemiRandomNotProtocolMarker` (low 2 bits = Kad markers) | plaintext |
| [1..2] | 2 | `nRandomKeyPart` u16 LE (`memcpy`) | plaintext |
| [3..6] | 4 | `MAGICVALUE_UDP_SYNC_CLIENT` (LE bytes `C1 2E 5F 39`) | RC4 |
| [7] | 1 | `byPadLen` (0 for UDP) | RC4 |
| [8..8+pad-1] | pad | random pad | RC4 |
| [8+pad..+3] | 4 | `nReceiverVerifyKey` u32 | RC4 |
| [8+pad+4..+3] | 4 | `nSenderVerifyKey` u32 | RC4 |
| [16+pad..] | rest | Kad payload (starts 0xE4/0xE5) | RC4 |

Everything from byte [3] on is **one contiguous RC4 keystream**. Recon offsets CONFIRMED.

**`[DIV]` aMule doc typo:** comment `:83` says verify keys are 2 bytes each; **code writes/reads 4 each** (`:242-243,365-366`). Follow eMule = 4+4.

### Marker byte low bits (hint only, never trusted): bit0 `0`=Kad/`1`=ed2k; bit1 (Kad only) `0`=NodeID key/`1`=ReceiverKey. Upper 6 bits random but rerolled if byte equals any protocol opcode (0xC5,0xE5,0xE4,reserved,packed).

### RC4: `RC4CreateKey(MD5digest, 16, key, bSkipDiscard=true)` - **NO 1024-byte discard** (UDP), standard 256-byte KSA, key = full 16-byte MD5 (`:228,329,404,451`). (TCP uses discard=false.)

### Three key derivations (RC4 key = raw 16-byte MD5 digest)
- **(a) Kad NodeID key** (requests; keyed on the target's KadID): `achKeyData[18] = KadID.GetData()[0..15] || nRandomKeyPart[16..17]`, `MD5(...,18)` (:197-200/307-310). NodeID bytes = ?0 form (MSW-first, each word LE). aMule reaches identical 16 via `StoreCryptValue`. **Do NOT feed raw BE hash.**
- **(b) Kad ReceiverKey** (responses): `achKeyData[6] = verifyKey_u32[0..3] || nRandomKeyPart[4..5]`, `MD5(...,6)` (:219-222/300-303). On encrypt verifyKey=`nReceiverVerifyKey` (what remote told us to echo); on decrypt = `GetUDPVerifyKey(senderIP)` (key WE issued).
- (c) ed2k key - not Kad.

### GetUDPVerifyKey (anti-spoof) (`Prefs.cpp:430-436`)
```
ui64 = (u64)KadUDPKey << 32 | targetIP        // MD5 input bytes LE = targetIP[4] then KadUDPKey[4]
h = MD5(&ui64, 8)
return ((h0 ^ h4 ^ h8 ^ h12) % 0xFFFFFFFE) + 1   // range 1..0xFFFFFFFF, never 0
```
`KadUDPKey` = per-install persisted random u32. `targetIP` = socket network-order bytes (opaque; use same on-wire bytes both sides).

### Verify-key semantics
- Outgoing `senderVerifyKey = GetUDPVerifyKey(destIP)` - our secret + their IP; we want them to echo it later (proves they received a packet actually sent to their IP).
- Outgoing `receiverVerifyKey` = the senderVerifyKey the peer previously handed us (`CKadUDPKey`, bound to our public IP via `GetKeyValue(ourIP)`).
- Incoming `bValidReceiverKey = (GetUDPVerifyKey(senderIP) == nReceiverVerifyKey)` -> their echo of the key we issued for their IP -> our-packet-to-them genuinely received -> IP verified. Gates routing/track-list acceptance & the HELLO challenge decision.

### Receiver dispatch (`DecryptReceivedClient` :160-231)
1. `len<=8` -> passthrough. 2. If `[0]` is a real protocol byte (0xC5/0xE5/0xE4/reserved/packed) -> plaintext, return as-is. 3. Else `byCurrentTry = ((b0&3)==3)?1:(b0&3)` (0=NodeID,1=ed2k,2=ReceiverKey). 4. Kad not running -> 1 try forced ed2k; else up to 3 tries cycling `(try+1)%3`. 5. Each try: build key, RC4 `[3..6]`, compare `== 0x395F2EC1`. 6. On match: RC4 `[7]`->padLen; skip pad; if Kad require `>8` remaining then RC4 the two u32 keys; RC4 payload in place. `[DIV]` aMule byteswaps value+both keys (host-order compares); LE Rust reads them as LE u32 directly.

---

## F. padMule slice plan (each with a differential checkpoint)

### 6a - nodes.dat + CUInt128 + routing table (pure, testable, real fixture)
Scope: CUInt128 (?0: raw/BE/word-swap, Xor, GetBitNumber, Get32BitChunk); nodes.dat reader/writer (?A); routing bin tree + K/KBASE/KK/tolerance-2^120 (?C); contact type/lifecycle math.
**Checkpoints:** (1) Parse the 6098-B fixture -> 179 contacts; assert first contact canonical ID `8fb8d05c...`, IP 226.80.49.93, UDP 4672, TCP 4662, version 8, verified. (2) Round-trip write -> byte-identical (version 2, 34-B records). (3) Unit: `distance.Get32BitChunk(0) <= 0x01000000` ? within 2^120; GetBitNumber(0)=MSB; CanSplit truth table. (4) Insert 179 fixture contacts into routing tree, assert bin/split invariants + per-/24 <=2.

### 6b - Kad UDP framing + obfuscation + bootstrap/hello
Scope: 0xE4/0xE5 framing + >200 pack (?B); full obfuscation layer (?E: RC4 no-discard, 16-B header, verify keys, GetUDPVerifyKey, key-try dispatch); BOOTSTRAP + HELLO 3-way handshake.
**Checkpoints:** (1) Encrypt->decrypt round-trip: sentinel 0x395F2EC1 recovered; NodeID-key and ReceiverKey paths both. (2) GetUDPVerifyKey known-vector test. (3) Live differential: send BOOTSTRAP_REQ (empty) to a real bootstrap node, decode BOOTSTRAP_RES, assert self-contact + <=20 contacts parse; complete a HELLO_REQ/RES/RES_ACK handshake and observe a contact reach IP-verified.

### 6c - iterative node lookup
Scope: FIND_NODE REQ/RES (?B/D), `m_mapPossible/Tried/Best`, ALPHA_QUERY=3 frontier, JumpStart, tolerance filtering.
**Checkpoints:** (1) Simulated-network unit test: lookup converges to K closest under churn. (2) Live: self-lookup against real Kad, assert routing table fills and closest-to-self set stabilizes; every RES passes `len == 17 + 25*count`.

### 6d - source/keyword search + differential gate (Wave-6 goal)
Scope: SEARCH_SOURCE_REQ (0x34, 26-B) / SEARCH_RES (0x3B) parse + source tags (?D).
**Gate checkpoint:** join real Kad, resolve a **known-available ed2k file hash** to sources - issue FIND_NODE toward the file hash, then SEARCH_SOURCE_REQ to the closest-in-tolerance node, parse SEARCH_RES, and surface >=1 source (type ? {1,3,4,5,6}) with IP/TCP/UDP port. This resolving-a-hash-to-sources is the Wave-6 differential success criterion.

---

## Divergences & UNSURE (consolidated)

**eMule-vs-aMule WIRE:**
- **`KADEMLIA_VERSION` byte: eMule 0x09 vs aMule 0x08** - only true on-wire diff. Pick consistently (recommend 0x09 SOT; interop-test).
- aMule refuses v0 nodes.dat, drops Kad1 contacts on load, `ALPHA_QUERY=5` - all behavior, not wire. Use eMule values.
- aMule byteswaps verify keys/sentinel internally (host-order); wire bytes identical.

**Report conflicts resolved:**
- **Tolerance = 2^120** (Reports 1/2/3 + arithmetic: 0x01000000 in chunk0 = bits 127..96 = 2^24.2^96). **Report 4's "2^104" is incorrect.**
- BOOTSTRAP_REQ payload is **empty** (Report 2 corrects the older recon "carries our contact" note; that was Kad1).
- CKadUDPKey / verify keys are **4+4 bytes** (Report 5 corrects the aMule 2+2 comment typo).
- Contact record on disk is **34 B (v2/v3)**, distinct from the 25-B wire contact record in RES/BOOTSTRAP_RES (no key/verified on the wire). Fixture proves 34.

**UNSURE / not byte-verified:**
- `SEC()/MIN2S()/HR2S()` macro exact text (`srchybrid/Opcodes.h` not opened; values inferred seconds/x60/x3600).
- `GetClosestTo` `type`->returned-count/bucket-level mapping not fully extracted.
- `CreateSearchExpressionTree` (keyword boolean AND/OR/NOT tree) not byte-decoded - out of Wave-6 core scope.
- KADEMLIA version-gate numeric constants (VERSION1_46c/5_48a/6_49aBETA/8_49b) referenced in Add/OnSmallTimer not enumerated (in `Kademlia.h`).
- IP-field endianness is pass-through (`WriteUInt32` of network-order value, reader `ntohl`s): store/forward the 4 IP bytes verbatim; only `ntohl` for display. Worth a live-capture byte-dump confirmation in 6b.

Relevant fixture: `/home/ajbufort/claude-projects/padMule/crates/mule-files/tests/fixtures/nodes.dat` (6098 B, v2, 179 records, verified this session).