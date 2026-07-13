# padMule Protocol Understanding Reference

A conceptual companion to the byte-level recon tables. This document builds the *mental model* an implementer needs: the flows, the reasons behind them, the state machines, and the load-bearing parameters. Where the traced aMule 3.0.1 source (the reimplementation target) or the base specs diverge from a naive reading, that is called out inline. All corrections verified against source override any looser phrasing.

Wire-format tables (exact field offsets, tag encodings) live in the recon doc; here we explain *why* each field exists and *when* each message fires.

---

## Part 1 - eD2k: Overview and Server Protocol

### 1.1 What the server is for

An eD2k server stores **no file content**. It is a rendezvous/index node. A client opens **one long-lived TCP connection**, announces who it is and what it shares, then repeatedly asks two questions:

- "Who has this file hash?" (sources)
- "What files match these words?" (search)

The server answers from an in-memory index of every logged-in client's shared files. Every hard part of the protocol traces back to one fact: **many clients sit behind NAT/firewalls and cannot accept inbound TCP.** So the server is also (a) a *reachability oracle* (HighID vs LowID) and (b) a *relay of last resort* (callback) for unreachable clients.

### 1.2 Wire basics (framing)

- Integers little-endian. Hashes are raw 16-byte MD4 (no length prefix). Strings are `uint16-LE length + bytes` (UTF-8 or Latin-1).
- **TCP framing** = 6-byte header `[protocol 1][packetlength uint32 LE][opcode 1]`, where `packetlength = 1 + payloadsize`. `MAX_PACKET_SIZE = 2000000`.
- Protocol byte `0xE3` (OP_EDONKEYPROT) = base server traffic. `0xD4` (OP_PACKEDPROT) = a zlib-compressed body that the server decompresses and then treats as `0xE3`.
- **UDP framing is different**: a bare 2-byte header `[protocol][opcode]`, NO length field (the datagram boundary is the length).

### 1.3 The TCP login handshake, end to end

State machine on the client socket: `CS_CONNECTING -> CS_WAITFORLOGIN -> CS_CONNECTED`.

1. `ConnectToServer()` -> optional async DNS for dyn-IP servers -> `Connect(addr)`. Picks the obfuscated TCP port if crypt is requested and advertised, else the normal port.
2. TCP handshake completes -> `OnConnect(success)` -> `SetConnectionState(CS_WAITFORLOGIN)`. That transition builds and sends **OP_LOGINREQUEST**.
3. The server processes the login, runs its reachability test (section 1.4), and replies with a burst of packets in **no guaranteed order** (each handled independently).

**OP_LOGINREQUEST (0x01), prot 0xE3.** Payload:

1. `userhash` 16 bytes - a stable per-install random ID (NOT per-file).
2. `clientID` uint32 - 0 on first connect. Meaningless at login time; the code itself notes it.
3. `TCP port` uint16 - our listen port (default 4662). **This is what the server reachability-tests.**
4. `tagcount` uint32 = 4
5. Four tags in **OLD (verbose) tag form**:
   - `CT_NAME (0x01)` = our nick (string)
   - `CT_VERSION (0x11)` = int32 `EDONKEYVERSION = 0x3C`
   - `CT_SERVER_FLAGS (0x20)` = int32 capability bitmask (see key params)
   - `CT_EMULE_VERSION (0xFB)` = int32 `(SO_AMULE=3 << 24) | make_full_ed2k_version(3,0,1)`, where `make_full_ed2k_version(a,b,c) = (a<<17)|(b<<10)|(c<<7)`

*Why CT_EMULE_VERSION rides in the login:* a LowID client can never receive the server's reachability hello, so it would otherwise have no chance to advertise its eMule capabilities. Putting the version in the login guarantees the server learns it up front.

*Why the login uses OLD tag form even while advertising CAPABLE_NEWTAGS:* at login the client does not yet know the server's flags, so it cannot risk the compact encoding.

**Server reply burst** (order-independent):

- `OP_SERVERMESSAGE (0x38)` - MOTD / welcome text. **Payload begins with a `uint16 length` prefix, then that many text bytes** (the recon table shows this; the study wording "just text" is incomplete - a server reimplementation MUST emit `uint16 len + text`). May carry "server version", "ERROR", "WARNING", "[emDynIP: ...]" lines.
- `OP_IDCHANGE (0x40)` - **the login answer**; assigns our client ID (section 1.4).
- `OP_SERVERSTATUS (0x34)` - uint32 usercount, uint32 filecount.
- `OP_SERVERIDENT (0x41)` - server hash 16, IP uint32, port uint16, tagcount, tags (ST_SERVERNAME, ST_DESCRIPTION, ...). Min size 38.
- `OP_SERVERLIST (0x32)` - uint8 count, then count*(uint32 IP, uint16 port): peer-server gossip to grow our `server.met`.

On reaching `CS_CONNECTED`, `ConnectionEstablished` marks us connected, clears ED2K publish info, optionally sends `OP_GETSERVERLIST (0x14, empty)` to solicit more servers, and the shared-file loop begins publishing via `OP_OFFERFILES`.

```
CLIENT                                       SERVER
  | --- TCP connect (port 4662 or obf) ------> |
  | --- OP_LOGINREQUEST(hash,id=0,port,tags) -> |
  |                                             | (server dials back to our IP:port
  |                                             |  = HighID reachability test)
  | <-- OP_SERVERMESSAGE (uint16 len + MOTD) -- |
  | <-- OP_IDCHANGE (new_id, tcpflags, ...) --- |  <- assigns HighID or LowID
  | <-- OP_SERVERSTATUS (users, files) -------- |
  | <-- OP_SERVERIDENT (hash, name, desc) ----- |
  | <-- OP_SERVERLIST (other servers) --------- |
  | --- OP_GETSERVERLIST (optional) ----------> |
  | <-- OP_SERVERLIST ------------------------- |
  | --- OP_OFFERFILES (our shared files) ------> |
  |            ... connection stays open ...     |
```

**OP_IDCHANGE parsing** (fields optional by size):

- `new_id` uint32 (assigned ID)
- if size>=8: `TCP flags` uint32 (SRV_TCPFLG_*, cached on the CServer -> gates large files, compression, obfuscation, unicode for the whole session)
- if size>=12: aux/standard port uint32 (when we logged in on an aux port, the "real" port to advertise)
- if size>=20: server-reported client IP uint32 + obfuscation TCP port uint32

On `new_id == 0` the server explicitly refused an ID (gave up its HighID callback test). aMule disconnects immediately (robustness patch) rather than hanging to a 15s timeout. Otherwise it stores the ID; if LowID and a reported-IP was given, `SetPublicIP(reportedIP)` - this is how a LowID client learns its own public IP.

### 1.4 HighID vs LowID: the reachability test and its numeric meaning

`HIGHEST_LOWID_ED2K_KAD = 16777216 = 0x01000000`. `IsLowID(id) == (id < 16777216)`. Anything below 16M is a LowID; anything >= 16M is a HighID.

**The test (server side):** after OP_LOGINREQUEST the server takes the client's *source IP* and the *TCP port advertised in field 3* and tries to open a fresh TCP connection back. Per the Kulbak/Bickson spec, a bare TCP handshake is **not** sufficient - the server must also receive a well-formed **OP_HELLO / OP_HELLOANSWER** on that callback socket before granting HighID. (This is load-bearing for a server reimplementation.)

- Callback succeeds -> **HighID = the client's public IPv4 encoded as a uint32** (server byte order). A HighID literally *is* the client's IP address.
- Callback fails -> **LowID**: a small session-local identifier < 16M, meaningless as an address, valid only for the lifetime of this one TCP connection.

**On LowID value assignment:** the spec only guarantees a LowID is an *opaque* integer whose highest byte is 0 (hence < 16777216) and that only makes sense to the assigning server. "Sequential counter" is a lugdunum-eserver implementation detail, **not** a protocol requirement. A server reimplementation may pick any value < 16777216 as long as it can map it back to the live connection for callbacks.

Consequences: a HighID peer can be handed to others as a direct `(IP,port)` source and can accept inbound. A LowID peer can only be reached via a server callback. **Two LowID peers can never connect over eD2k.** aMule also runs a "smart ID" reconnect heuristic hoping for promotion - a client policy, not part of the protocol.

### 1.5 The LowID callback flow

We (HighID) want a file whose source list includes a LowID peer L. We cannot dial L, but the server holds L's control channel. So we ask the server to tell L to dial us.

- **Requester** (only if connected to the *same server* that indexed L): send `OP_CALLBACKREQUEST (0x1C)`, payload = uint32 L's client ID in **hybrid form** (`m_nUserIDHybrid`). Enter `DS_WAITCALLBACK`.
- **Server relays** to L as `OP_CALLBACKREQUESTED (0x35)`: uint32 OUR IP, uint16 OUR port; if size>=23 also uint8 crypt options + 16-byte our user hash.
- **L** finds-or-creates a client for our IP:port, adopts the crypt options/hash, and `TryToConnect()` -> L dials out to us. From there it is an ordinary C2C connection.
- If the server cannot deliver (L gone), it sends `OP_CALLBACK_FAIL (0x36)`, and we drop the source.

```
US (HighID)          SERVER (shared by us and L)        L (LowID)
   | --OP_CALLBACKREQUEST(L_id)--> |                        |
   |                               | --OP_CALLBACKREQUESTED-> |
   |                               |   (our IP, our port, hash)
   | <====== L dials out to us (normal C2C TCP) =========== |
 (or: | <--OP_CALLBACK_FAIL-- |  if L is unreachable)
```

Callback only works when requester and LowID peer share a server (or, off-network, via a Kad buddy relay - see Part 4).

### 1.6 Search: expression encoding, local TCP vs global UDP

`OP_SEARCHREQUEST (0x16)` payload is a single self-delimiting **search tree** - NO leading count. Each node begins with a 1-byte parameter type:

- `0x00` boolean operator + op byte (0x00=AND, 0x01=OR, 0x02=NOT)
- `0x01` plain string keyword: uint16 len + bytes
- `0x02` string bound to a meta tag
- `0x03` numeric int32: value, compare-op, meta-tag-id
- `0x08` numeric int64 (only if server advertises SRV_TCPFLG_LARGEFILES; else downgraded to 0x03 clamped to 0xFFFFFFFF)

Compare ops: `EQUAL=0, GREATER=1, LESS=2, GREATER_EQUAL=3, LESS_EQUAL=4, NOTEQUAL=5`.

**Tree shape:** operators are written **prefix (Polish)** with fixed arity (AND/OR binary, NOT unary), which is why no count is needed - the reader knows how many operands to pull. Two encoding paths:

- **Simple query** (no explicit OR/NOT): sent as **interleaved leading ANDs** ("AND a AND min max" rather than the naive "AND AND a min max") at lugdunum's request to cost servers less. Emits at most `parametercount-1` AND operators - exactly one fewer than the number of terms.
- **Complex query** (has OR/NOT): the parsed boolean tree written token-by-token in prefix order.

**Standard filter terms** appended in both paths: `FT_FILETYPE (0x03)` as ASCII string, `FT_FILESIZE (0x02)` min (GREATER) and max (LESS), `FT_SOURCES (0x15)` (GREATER), `FT_FILEFORMAT (0x04)` extension.

> **FT_FILETYPE on the wire is only ever `Audio` / `Video` / `Image` / `Doc` / `Pro`.** Although the code has string constants `Arc` (archive) and `Iso` (CD image), both are remapped to `Pro` (ED2KFTSTR_PROGRAM) *before* the term is built, in both search and OFFERFILES paths. Do not emit `Arc` or `Iso`.

**LOCAL search:** the packet goes over the open TCP link to the connected server; the server answers with one `OP_SEARCHRESULT (0x33)` over the same link.

> Implementation note: the send call is `SendPacket(searchPacket, (type == LocalSearch))` where the second argument is the *delete-after-send* flag, not a control/priority flag. The control-packet flag is hardcoded `true` one level down in `CServerConnect::SendPacket`. Net effect (server packets are control packets) is correct.

**GLOBAL search:** the same packet is first sent over TCP to the local server, then retained and blasted by UDP to **every other server** in `server.met`, one server every **750 ms**. The connected server is skipped (already asked over TCP). Per-server UDP opcode is chosen by that server's UDP flags:

- `OP_GLOBSEARCHREQ3 (0x90)` if SupportsLargeFilesUDP and SRV_UDPFLG_EXT_GETFILES: prepends a tag-set (count=1 + CT_SERVER_UDPSEARCH_FLAGS = SRVCAP_UDP_NEWTAGS_LARGEFILES 0x01, NEW tag form) then the body.
- `OP_GLOBSEARCHREQ2 (0x92)` if SRV_UDPFLG_EXT_GETFILES.
- `OP_GLOBSEARCHREQ (0x98)` otherwise.
- Servers lacking large-file UDP are skipped when the packet used a 64-bit term.

UDP replies arrive as `OP_GLOBSEARCHRES (0x99)`: one or more concatenated result blocks, each parsed like a single result, with a 2-byte `[0xE3][0x99]` separator between blocks. Attributed to `source_port - 4`.

**Result parsing** (both TCP and UDP): uint32 count, then per result: hash 16, uint32 client ID (source IP; zeroed if LowID/bad), uint16 port, uint32 tagcount, then tags (FT_FILENAME, FT_FILESIZE low, FT_FILESIZE_HI high<<32, FT_SOURCES, FT_COMPLETE_SOURCES, FT_FILERATING, media). No filename -> rejected; size 0 or > MAX_FILE_SIZE -> dropped.

`OP_QUERY_MORE_RESULT (0x21)` (pagination) and `OP_SEARCH_USER (0x1A)` are **declared but not built/sent** in aMule 3.0.1's traced server path. A reimplementation wanting pagination or user-search must add them.

### 1.7 Source acquisition and publishing

**OP_GETSOURCES (0x19)** over TCP to the connected server. Per file: hash 16, then size - normal: uint32; large (>4GB): `uint32(0) + uint64` (only if SRV_TCPFLG_LARGEFILES; the leading 0 lets old servers ignore the extra 8 bytes). If crypt is supported and the server supports it, `OP_GETSOURCES_OBFU (0x23)` is used. aMule bundles **up to 15** GETSOURCES packets into one TCP frame and rate-limits the next frame.

**OP_FOUNDSOURCES (0x42)** reply: hash 16, uint8 count, then count*(uint32 ID, uint16 port). Each ID is a HighID (direct) or a LowID (needs callback). `OP_FOUNDSOURCES_OBFU (0x44)` adds, after each ID/port, a uint8 crypt-options byte, and if `(options & 0x80)` a 16-byte user hash.

**OP_OFFERFILES (0x15)** - publishing what WE share. Payload: uint32 file count, then per file:

- hash 16
- uint32 client ID: our HighID IP if we have one, else 0; OR on compression-capable servers a completion sentinel: complete `0xFBFBFBFB`, incomplete `0xFCFCFCFC`.
- uint16 port: our port, or sentinel `0xFBFB` (complete) / `0xFCFC` (incomplete).
- uint32 tagcount + tags: FT_FILENAME, FT_FILESIZE (int32; or int32-low + FT_FILESIZE_HI for large files), FT_FILETYPE (int32 if SRV_TCPFLG_TYPETAGINTEGER else string), optional FT_FILERATING. NEW or OLD tag form per server capability.

Policy: sorted, unpublished files only, capped at the server's soft file limit (or 200); large files filtered out if the server lacks LARGEFILES; **the count field is written as 0 first and patched to the actual number after the loop** so the header never overstates the body; if 0 files survive, nothing is sent. Compressed via PackPacket if SRV_TCPFLG_COMPRESSION. Sent once on connect and periodically.

**Keep-alive:** a zero-count OP_OFFERFILES (just `uint32 0`) pings the TCP link to keep it warm when idle past the keep-alive timeout - lugdunum's own recommendation, not base spec.

### 1.8 Server UDP protocol

UDP header is 2 bytes: `[protocol][opcode]`. **Server UDP port = server TCP port + 4** by default. The obfuscated stat ping uses **+12**; encrypted traffic uses the advertised UDP-obfuscation port. Incoming datagrams are attributed back to TCP port = `source_port - 4`.

> **The "+3" comment is stale.** The `ServerUDPSocket.cpp` header literally reads "(TCP+3) UDP socket", but every code path uses offset **+4** (and classic eDonkey also used +4). Do not implement +3 for the remote destination. (Note: our *own* local server-query UDP socket binds to *our* TCP+3 - see Part 5, Q6 - that is a different thing.)

**(a) Server stats ping - OP_GLOBSERVSTATREQ (0x96).** Rotates over `server.met`, one server at a time. Payload = `uint32 challenge = 0x55AA0000 + rand16`.

> **Correction to the common rationale:** the string-length disambiguation trick does *not* apply here. The GLOBSERVSTATRES handler does only an exact `uint32` equality check on the echoed challenge - there is no overloaded string-length-prefixed packet. Also, `0x55AA` sits in the *high* 16 bits, so on the little-endian wire it is the *last* two bytes, not the first. The value itself (`0x55AA0000 + rand16`) is correct; the "first two bytes chosen so..." rationale is wrong on both count and byte-position.

Reply `OP_GLOBSERVSTATRES (0x97)`: uint32 challenge (must equal), uint32 usercount, uint32 filecount; then optional fields guarded by min-size gates at 16/24/28/32/40: maxusers, softfiles, hardfiles, UDP flags, lowid users, UDP-obf port (uint16), TCP-obf port (uint16), server UDP key (uint32). This is how a client learns each server's counts, capacity, and UDP capability bits *without logging in*.

On reply, aMule follows up with `OP_SERVER_DESC_REQ (0xA2)` to fetch name/description via `OP_SERVER_DESC_RES (0xA3)`. The DESC_REQ challenge disambiguates old vs new DESC_RES:

> **This** is where the invalid-string-length trick lives. `challenge = (rand16 << 16) + INV_SERV_DESC_LEN`, where `INV_SERV_DESC_LEN = 0xF0FF`. `0xF0FF` is in the **LOW** 16 bits with the random value in the high 16 bits. Because ed2k serializes little-endian, `0xF0FF` becomes the **first two wire bytes** - exactly what the DESC_RES reader checks as the leading uint16 "length". A reimplementer who put `0xF0FF` in the high bits (last wire bytes) would break the disambiguation.

If crypt is enabled and our public IP is known, aMule first sends an obfuscated stat ping (raw encrypted datagram to TCP+12), waits 20s, and falls back to the plain ping if unanswered.

**(b) Global sources - OP_GLOBGETSOURCES (0x9A) / OP_GLOBGETSOURCES2 (0x94).** Ask a rotating *non-connected* UDP server for sources, harvesting from servers we are NOT logged into. GETSOURCES2 carries hash 16 + size; plain GETSOURCES carries hash 16 only. Reply `OP_GLOBFOUNDSOURCES (0x9B)`: repeated blocks `hash 16 + uint8 count + count*(uint32 ID, uint16 port)`, separated by `[0xE3][0x9B]`. Added with SF_REMOTE_SERVER.

**When UDP vs TCP:** TCP is the one authoritative link to your connected server (login, local search, local GETSOURCES, publishing). UDP is the cheap fan-out channel to the whole server list (global search, background source harvesting, periodic health/stat maintenance) - no login, no server slot. That is exactly why lugdunum built these extensions.

> aMule forces Unicode=true when parsing server name/description tags **regardless** of the server's SRV_TCPFLG_UNICODE bit, because real servers ship UTF-8 without advertising it.

### 1.9 Connection lifecycle glue

- Multi-connect: up to `max_simcons` parallel attempts (1 if SafeServerConnect, else 2). First to reach login wins; the rest are torn down. Pending attempts age out at `CONSERVTIMEOUT = 25000 ms`. Fatal error -> auto-retry after `CS_RETRYCONNECTTIME = 30 s`.
- Obfuscation-first: if crypt is requested, try obfuscated TCP ports across the whole list first; if all fail and crypt is not required, make a second pass in the clear.
- Disconnect: `CS_WAITFORLOGIN -> CS_SERVERFULL` (dropped at login), `CS_CONNECTED -> CS_DISCONNECTED` (clears publish info, cancels searches, auto-connects elsewhere if Reconnect is on).

### 1.10 Key server-protocol parameters

```
Protocol bytes:  OP_EDONKEYPROT=0xE3, OP_PACKEDPROT=0xD4 (zlib -> treated as 0xE3)
TCP header:      [prot 1][packetlength uint32 LE][opcode 1]; packetlength = 1+payload; MAX_PACKET_SIZE=2000000
UDP header:      [prot][opcode], no length
Server UDP port: TCP+4 (obf stat ping TCP+12); replies attributed to source_port-4
HIGHEST_LOWID_ED2K_KAD = 16777216 (0x01000000); IsLowID = id<16777216; HighID == public IPv4 as uint32
EDONKEYVERSION=0x3C; SO_AMULE=3; make_full_ed2k_version(a,b,c)=(a<<17)|(b<<10)|(c<<7)
CT_SERVER_FLAGS bits: ZLIB 0x1 | AUXPORT 0x4 | NEWTAGS 0x8 | UNICODE 0x10 | LARGEFILES 0x100
                      | SUPPORTCRYPT 0x200 | REQUESTCRYPT 0x400 | REQUIRECRYPT 0x800
Server TCP flags (IDCHANGE): COMPRESSION 0x1, NEWTAGS 0x8, UNICODE 0x10, RELATEDSEARCH 0x40,
                             TYPETAGINTEGER 0x80, LARGEFILES 0x100, TCPOBFUSCATION 0x400
Server UDP flags: EXT_GETSOURCES 0x1, EXT_GETFILES 0x2, NEWTAGS 0x8, UNICODE 0x10,
                  EXT_GETSOURCES2 0x20, LARGEFILES 0x100, UDPOBFUSCATION 0x200, TCPOBFUSCATION 0x400
C->S TCP opcodes: LOGINREQUEST 0x01, GETSERVERLIST 0x14, OFFERFILES 0x15, SEARCHREQUEST 0x16,
                  DISCONNECT 0x18, GETSOURCES 0x19, SEARCH_USER 0x1A, CALLBACKREQUEST 0x1C,
                  QUERY_MORE_RESULT 0x21, GETSOURCES_OBFU 0x23
S->C TCP opcodes: REJECT 0x05, SERVERLIST 0x32, SEARCHRESULT 0x33, SERVERSTATUS 0x34,
                  CALLBACKREQUESTED 0x35, CALLBACK_FAIL 0x36, SERVERMESSAGE 0x38, IDCHANGE 0x40,
                  SERVERIDENT 0x41, FOUNDSOURCES 0x42, USERS_LIST 0x43, FOUNDSOURCES_OBFU 0x44
Server UDP opcodes: GLOBSEARCHREQ3 0x90, GLOBSEARCHREQ2 0x92, GLOBGETSOURCES2 0x94, GLOBSERVSTATREQ 0x96,
                    GLOBSERVSTATRES 0x97, GLOBSEARCHREQ 0x98, GLOBSEARCHRES 0x99, GLOBGETSOURCES 0x9A,
                    GLOBFOUNDSOURCES 0x9B, GLOBCALLBACKREQ 0x9C, SERVER_DESC_REQ 0xA2,
                    SERVER_DESC_RES 0xA3, SERVER_LIST_REQ2 0xA4
Search param types: 0x00 bool | 0x01 keyword | 0x02 string+metatag | 0x03 int32+op+metatag | 0x08 int64+op+metatag
Compare ops: EQUAL=0, GREATER=1, LESS=2, GREATER_EQUAL=3, LESS_EQUAL=4, NOTEQUAL=5
OFFERFILES sentinels (compression servers): complete ID=0xFBFBFBFB port=0xFBFB; incomplete ID=0xFCFCFCFC port=0xFCFC
GLOBSERVSTATREQ challenge = 0x55AA0000 + rand16 (echo-equality check only)
SERVER_DESC_REQ challenge = (rand16 << 16) + 0xF0FF  (0xF0FF in LOW 16 bits = first wire bytes)
Timing: CONSERVTIMEOUT 25000 ms; CS_RETRYCONNECTTIME 30 s; UDPSERVSTATREASKTIME 4.5 h;
        UDPSERVSTATMINREASKTIME 20 min; global-search UDP cadence 750 ms/server; max_simcons 1 (safe) or 2
GETSOURCES batching: up to 15 per TCP frame; large-file size wire form uint32(0)+uint64
server.met on-disk version byte 0xE0
```

---

## Part 2 - eD2k: Client-to-Client and File Transfer

All C2C traffic is TCP. Framing is the same 6-byte header as the server protocol. The protocol byte selects the opcode namespace and dispatch:

- `0xE3` OP_EDONKEYPROT -> base/standard C2C opcodes
- `0xC5` OP_EMULEPROT -> eMule extended opcodes
- `0xD4`/`0xF5` OP_PACKEDPROT -> zlib inflate, then routed as EMULEPROT
- `0xF4` OP_ED2KV2HEADER -> aMule-experimental (niche; see Part 5, Q2)

An optional RC4 obfuscation layer may wrap all of this before framing (deferred here - the cleartext protocol is described; see Part 5, Q5 and Part 4 for the crypt layer). **Core sizes:** `PARTSIZE = 9728000` (the MD4-hashed "part"), `EMBLOCKSIZE = BLOCKSIZE = 184320` (the requestable "block", 180 KiB), ~52.78 blocks per part.

### 2.1 The peer handshake

Whoever OPENS the connection sends `OP_HELLO (0x01)` first; the accepter replies `OP_HELLOANSWER (0x4C)`. Both carry the same "hello body"; the only wire difference is OP_HELLO prepends a `uint8 = 0x10` (the userhash length) and OP_HELLOANSWER does not.

**Hello body order:** `userhash(16) | clientID(uint32) | TCPport(uint16) | tagcount(uint32) | tags... | serverIP(uint32) | serverPort(uint16)`. A trailing `uint32 == 0x4B444C4D ("KDLM")` flags an MLDonkey peer.

> ClientID is the peer's ID in **hybrid (byte-swapped)** internal form. The store rule is broader than "only when the peer sent no/self ID": `if (!HasLowID() || m_nUserIDHybrid == 0 || m_nUserIDHybrid == m_dwUserIP) SetUserIDHybrid(swap(m_dwUserIP))` - the swapped remote IP is stored for **every HighID peer**. For well-behaved HighID peers the result is identical to trusting the packet, so this rarely matters, but a reimplementation should trust the actual socket peer IP for HighID rather than the raw packet ID (see Part 5, Q1).

**Hello tags** carry version + capabilities: CT_NAME, CT_VERSION (=0x3C), CT_EMULE_UDPPORTS (=`(kadUDPport<<16)|eMuleUDPport`), optional CT_EMULE_BUDDYIP/BUDDYUDP (only if firewalled with a Kad buddy), CT_EMULE_VERSION, **CT_EMULE_MISCOPTIONS1**, **CT_EMULE_MISCOPTIONS2**, CT_EMULECOMPAT_OPTIONS.

**Two capability-negotiation paths:**

- **New eMule/aMule:** capabilities packed into MISCOPTIONS1/2 tags. An eMule-style HELLO/HELLOANSWER alone satisfies the "both info packets received" (IP_BOTH) state.
- **Old eMule:** a separate `OP_EMULEINFO (0x01) / OP_EMULEINFOANSWER (0x02)` over prot 0xC5. aMule only sends OP_EMULEINFO when the peer's userhash is old-eMule-style AND the received hello was not already a mule-hello. Body carries ET_* tags (ET_COMPRESSION, ET_UDPVER, ET_UDPPORT, ET_SOURCEEXCHANGE, ET_COMPATIBLECLIENT=SO_AMULE, ...). A `0xFF` protocol-version variant carries a single ET_OS_INFO string (aMule-only).

**Capability bitfields** (see key params for exact bit layout). These gate later behavior: data-compression version enables OP_COMPRESSEDPART; secure-ident kicks off the RSA exchange; source-exchange v1 / SX2 bit choose OP_REQUESTSOURCES vs OP_REQUESTSOURCES2; extended-requests version decides whether we append our part-status bitmap; UDP version enables reasks; multipacket / ext-multipacket enable OP_MULTIPACKET(_EXT); large-files enables the `_I64` (uint64-offset) opcode family.

**Completion sequence:** on OP_HELLO -> create/attach client, IP/ipfilter checks, optionally SendMuleInfoPacket, SendHelloAnswer, ConnectionEstablished(), and if IP_BOTH -> InfoPacketsReceived() (starts secure ident). On OP_HELLOANSWER -> process, clear `m_bHelloAnswerPending`, if IP_BOTH -> InfoPacketsReceived, then ConnectionEstablished(). `CheckHandshakeFinished()` gates all upload/queue actions on `m_bHelloAnswerPending == false`.

`ConnectionEstablished()` is the fan-out: moves download DS_CONNECTING/DS_WAITCALLBACK* -> DS_CONNECTED and calls SendFileRequest(); moves upload states -> US_UPLOADING sending OP_ACCEPTUPLOADREQ if we owe a slot; issues queued file-list/chat requests; flushes waiting packets.

```
[TCP connect] --open--> SEND_HELLO (set HelloAnswerPending)
     |                        |
     | (we accepted)          v
     v                  recv HELLOANSWER --> clear pending
 recv HELLO                   |
     |                        v
     v              InfoPacketsReceived (IP_BOTH) -> secure-ident (optional)
 SEND HELLOANSWER (+MuleInfo   |
   for old eMule)              v
     +-------> ConnectionEstablished --> dispatch (download / upload / filelist / chat)
```

### 2.2 Download acquisition state machine (downloader side)

`EDownloadState`: DS_NONE, DS_CONNECTING, DS_WAITCALLBACK, DS_WAITCALLBACKKAD, DS_CONNECTED, DS_ONQUEUE, DS_DOWNLOADING, DS_REQHASHSET, DS_NONEEDEDPARTS, DS_TOOMANYCONNS(+KAD), DS_LOWTOLOWIP, DS_BANNED, DS_ERROR, DS_REMOTEQUEUEFULL.

Life cycle (`CPartFile::Process` each second; full source walk every 10th tick):

1. Source discovered (server GETSOURCES, Kad, source-exchange, ed2k link) -> `CheckAndAddSource` -> DS_NONE.
2. If disconnected or reask timer elapsed (`FILEREASKTIME = 1300000 ms`) -> `AskForDownload`.
3. `AskForDownload`: too many sockets -> DS_TOOMANYCONNS; else DS_CONNECTING + TryToConnect. A LowID peer is reached via server callback -> DS_WAITCALLBACK, or via Kad buddy -> DS_WAITCALLBACKKAD. Two firewalled peers -> DS_LOWTOLOWIP.
4. Socket up + handshake -> ConnectionEstablished sets DS_CONNECTED -> SendFileRequest.
5. **SendFileRequest** bundles, when the peer supports it, `OP_MULTIPACKET (0x92)` or `OP_MULTIPACKET_EXT (0xA4, inserts uint64 filesize after the hash)` with sub-opcodes: OP_REQUESTFILENAME (+our part-status bitmap if peer ExtendedRequestsVersion>0, +complete-sources count if >1), OP_SETREQFILEID (only if >1 part), optional OP_REQUESTSOURCES/2, optional OP_AICHFILEHASHREQ. Legacy peers get separate OP_REQUESTFILENAME (0x58) then OP_SETREQFILEID (0x4F).
6. **Replies:**
   - `OP_REQFILENAMEANSWER (0x59)` = hash + filename. `OP_FILEREQANSNOFIL (0x48)` = hash means the peer does not have the file.
   - `OP_FILESTATUS (0x50)` = hash + uint16 partcount + bitfield. The bitfield: `uint16 ED2K part count`, then `ceil(parts/8)` bytes; bit i (LSB-first within a byte) set = part complete. A `uint16(0)` count means "complete source" (whole file). No needed part -> DS_NONEEDEDPARTS.
   - **When the request arrived via OP_MULTIPACKET/_EXT, the reply is a single bundled `OP_MULTIPACKETANSWER (0x93)`** (prot 0xC5): `file hash(16)` then per handled sub-request `[uint8 sub-opcode][sub-answer]` - OP_REQFILENAMEANSWER(0x59)+utf8 filename, OP_FILESTATUS(0x50)+partcount+bitfield, OP_AICHFILEHASHANS(0x9D)+20-byte master hash. Sent only if `data_out > 16` bytes. **Critical nuance:** the source-exchange answer (OP_ANSWERSOURCES/2) is **never** bundled into 0x93 - it is always its own separate packet. A client that only implements the legacy separate-opcode replies will fail to parse responses from real modern peers.
   - If the file has >1 part and we lack the part-hash list -> send OP_HASHSETREQUEST, enter DS_REQHASHSET.
7. `SendStartupLoadReq`: `OP_STARTUPLOADREQ (0x54)` = hash -> enter the peer's upload queue, DS_ONQUEUE. Peer answers `OP_QUEUERANKING (0x60)` or, on grant, OP_ACCEPTUPLOADREQ.
8. `OP_ACCEPTUPLOADREQ (0x55, empty)` is honored ONLY in DS_ONQUEUE -> DS_DOWNLOADING, reset chunk selection, call SendBlockRequests(). If the file is gone/wrong status, send OP_CANCELTRANSFER and fall back.
9. Block download loop (section 2.3). No block data for `DOWNLOADTIMEOUT = 100000 ms` -> OP_CANCELTRANSFER, drop to DS_ONQUEUE.
10. While DS_ONQUEUE, aMule prefers **UDP reask**: `OP_REASKFILEPING` when `now - lastAsked > FILEREASKTIME - 20000`. Answers OP_REASKACK (part status + queue rank), OP_QUEUEFULL, or OP_FILENOTFOUND (adds a dead source and drops it).
11. DS_NONEEDEDPARTS sources try A4AF (swap to another file) every 40 s, else purge; DS_LOWTOLOWIP purged after 30 s under source pressure; DS_REMOTEQUEUEFULL purged after 60 s when saturated.

```
DS_NONE --AskForDownload--> DS_CONNECTING --(LowID)--> DS_WAITCALLBACK[KAD]
   ^                              |                            |
   |                        handshake ok                 callback in
   |                              v                            |
   |                        DS_CONNECTED <---------------------+
   |                              | SendFileRequest
   |          no hashset -> DS_REQHASHSET --answer--> back
   |                              |
   |         no needed parts -> DS_NONEEDEDPARTS
   |                              | OP_STARTUPLOADREQ
   |                              v
   |   DS_ONQUEUE <--QUEUERANKING/timeout/UDP reask--+
   |      |                                          |
   | OP_ACCEPTUPLOADREQ (only from DS_ONQUEUE)       |
   |      v                                          |
   +-- DS_DOWNLOADING --(100s no data / cancel)------+
        (SendBlockRequests loop)
```

### 2.3 Block-request pipeline: the 3-block batch

A **part** (9728000) is the MD4-hashed integrity unit. A **block** (184320, 180 KiB) is the requestable transfer unit. `STANDARD_BLOCKS_REQUEST = 3`: one `OP_REQUESTPARTS` carries up to 3 block ranges (~540 KB max), so a downloader keeps ~3 outstanding requests in flight - enough to fill the TCP pipe without over-committing a slot. This 3-at-a-time window is the classic eD2k transfer engine.

**SendBlockRequests:** `m_MaxBlockRequests` defaults to 3. Only VBT/ED2Kv2-capable peers adapt: last block completed <5 s ago -> double (cap 0x20=32); else halve (floor 3). Stock peers stay at exactly 3.

**Wire:** `OP_REQUESTPARTS (0x47, prot 0xE3)` = `hash(16) | 3x uint32 start | 3x uint32 end`. **Starts come first, then all ends (not interleaved).** End offsets are **exclusive on the wire** (the code writes `EndOffset + 1`) although stored **inclusive** internally. Unused slots are zero-filled; the uploader ignores pairs where `end <= start`. `OP_REQUESTPARTS_I64 (0xA3, prot 0xC5)` is identical with uint64 offsets, used when any offset > 0xFFFFFFFF.

**Chunk (part) selection - GetNextRequestedBlock:** all blocks requested from ONE source must lie in the SAME part. Part choice ranks every part the sender has, using rarity (`m_SrcpartFrequency`), completion %, preview priority, and an "already-requested" flag; the minimum-rank part is chosen, ties broken uniformly at random. Within the chosen part, the first gap is clamped to a BLOCKSIZE-aligned boundary. A requested block is <= 180 KiB and may be shorter at gap/part edges.

**Receiving data - ProcessBlockPacket:** `OP_SENDINGPART (0x46, prot 0xE3)` = `hash | start(uint32) | end(uint32 exclusive) | (end-start) raw bytes`. `OP_SENDINGPART_I64 (0xA2)` uses uint64. Match the incoming StartOffset to a pending block; reject data past block end; `credits->AddDownloaded(payload)` (reciprocity). `WriteToBuffer` drops duplicates, `FillGap` **immediately** (optimistic gap list, before the disk write). When `nEndPos == block EndOffset` the block is complete: compute speed, remove from list, and **immediately call SendBlockRequests() again** - this refill is the pipelining that keeps 3 in flight. `FlushBuffer` fires when the buffer exceeds the pref or every `BUFFER_TIME_LIMIT = 60000 ms`; dirty parts that become complete are MD4-hashed.

### 2.4 The uploader side: queue, slots, credits, trickle

**There is NO OP_SLOTREQUEST / OP_SLOTRELEASE in eD2k.** Slotting uses OP_STARTUPLOADREQ (ask to enter queue), OP_ACCEPTUPLOADREQ (slot granted), OP_QUEUERANK(ING) (position), OP_CANCELTRANSFER (downloader aborts), OP_OUTOFPARTREQS (uploader kicks back to queue). Upload states: US_NONE, US_ONUPLOADQUEUE, US_WAITCALLBACK, US_CONNECTING, US_PENDING, US_LOWTOLOWIP, US_BANNED, US_ERROR, US_UPLOADING.

**Admission - AddClientToQueue** (on OP_STARTUPLOADREQ, after handshake + ban checks): reject if we are LowID on a foreign server with >50 waiting, or the client is banned; dedup same-userhash unidentified duplicates; max 3 clients per IP. Queue cap = `GetQueueSize()` (pref*100). If the queue is empty, a slot is free, and >=1000 ms since the last upload start -> grant immediately (OP_ACCEPTUPLOADREQ, US_UPLOADING). Otherwise append and send `OP_QUEUERANKING` (**exactly 12 bytes**: uint16 rank + 10 zero pad).

**Ordering/score - CalculateScoreInternal:** score = 0 for empty nick / no credits / no upload file / bad guy / banned / already has a slot. Friend-with-friend-slot high-ID = `0x0FFFFFFF` (always first; friend slots exclusive, never kicked). Else `score = floor(waitSeconds * creditRatio * filePrio * oldMuleFactor)`, where waitSeconds is tracked in credits per IP (survives reconnects), creditRatio comes from GetScoreRatio (section 2.7), filePrio multipliers are `PowerShare 250.0 / VeryHigh 1.8 / High 0.9 / Normal 0.7 / Low 0.6 / VeryLow 0.2`, and oldMuleFactor is 0.5 for eMule ver <= 0x19. Insertion sort descending; the best high-ID (or a connected low-ID) is popped for a freed slot. Unconnected low-ID clients ranked above it get `m_bAddNextConnect=true`.

**Slot count - GetMaxSlots** (from upload rate / per-client allocation): unlimited upload -> `max(20, rate/perClient + 2)`; >=10 kB/s -> `round(rate/perClient)`, min `MIN_UP_CLIENTS_ALLOWED = 2`; else 2. Cap `MAX_UP_CLIENTS_ALLOWED = 250`. (The floor of 20 is a local aMule deviation.)

**Process loop:** free slot (and >=1 s since last start) -> AddUpNextClient; all full -> allow kicking. Iterate slots calling SendBlockData. `CheckForTimeOver` kicks at most ONE ordinary slot per cycle once a session exceeds `3600000 ms (1 h)` OR `10485760 bytes (10 MB)`. PowerShare/friend (VIP) slots are protected while VIP <= maxSlots/2. A kicked client gets OP_OUTOFPARTREQS and is re-queued keeping its credit wait time (no socket teardown).

**Serving data:** OP_REQUESTPARTS parser validates (must hold a slot, file shared, range complete on part files, `0 < len <= 3*EMBLOCKSIZE`, dedup). A disk-IO thread keeps <= EMBLOCKSIZE+1 prepared bytes per client (5*EMBLOCKSIZE+1 for fast clients), splitting into sub-packets and optionally compressing. The dedicated bandwidth throttler (1 ms base loop) runs a **trickle pass**: any upload socket not served for >1 s gets `GetNeededBytes()` worth of data - the minimum to keep a ~90 s (45 s accelerated) full-packet pace - purely to prevent the downloader's 100 s timeout from firing when bandwidth is scarce.

```
US_NONE --OP_STARTUPLOADREQ--> AddClientToQueue
   |                               |
   |     slot free + queue empty + >1s     else append
   |                               |             |
   |                               v             v
   |          OP_ACCEPTUPLOADREQ -> US_UPLOADING  US_ONUPLOADQUEUE
   |                               |  ^  serve OP_REQUESTPARTS   (OP_QUEUERANKING)
   |                               |  |  -> OP_SENDINGPART / COMPRESSEDPART (trickle keeps alive)
   |   CheckForTimeOver kick       |  |
   |   -> OP_OUTOFPARTREQS --------+  |
   +-- OP_CANCELTRANSFER / disconnect -> RemoveFromUploadQueue
```

**Reciprocity:** the score multiplies raw wait time by the credit ratio, so peers who uploaded a lot *to us* are served first. Credits are keyed by user hash and optionally hardened by RSA secure identification so the ratio cannot be spoofed by forging a userhash.

### 2.5 Compression (zlib)

Two independent layers:

- **(a) Whole-packet packing:** PackPacket zlib-compresses a payload and switches prot `0xC5 -> 0xD4` (or `0xE4 -> 0xE5` for Kad); kept only if smaller. Mainly for control packets, not bulk data.
- **(b) Per-block data compression (the important one):** the uploader zlib-compresses a whole 180 KiB block and, if smaller, sends `OP_COMPRESSEDPART (0x40, prot 0xC5)` = `hash | start(uint32) | packedTotalSize(uint32) | one slice of the zlib stream`. Every fragment repeats the SAME start and packed size; the receiver streams all fragments through ONE inflate, deriving each fragment's position from cumulative inflated bytes. `OP_COMPRESSEDPART_I64 (0xA1)` uses uint64 start. Falls back to plain OP_SENDINGPART if compression does not shrink, the file is an archive, or the peer's data-comp version != 1. Also permanently disabled mid-session if the socket starves at >153600 B/s. (This tree uses zlib level 1; stock eMule historically used level 9.)

### 2.6 Hashset and AICH exchange

**Hashset (part-hash list).** Before downloading a multi-part file, the downloader needs the per-part MD4 hashes to verify each 9.28 MB part. Requested only when the file has >1 part and the hashset is missing:

- `OP_HASHSETREQUEST (0x51)` = file hash(16). Enter DS_REQHASHSET.
- `OP_HASHSETANSWER (0x52)` = file hash(16) | uint16 count | count * MD4(16). Validated by recomputing `MD4(concatenation of all part hashes)` == the file's ed2k hash. A file that is an exact multiple of PARTSIZE carries a trailing empty-MD4 sentinel part (`31D6...C0`). Single-part files (< PARTSIZE) have no separate hashset; the file hash IS the part hash.

**AICH (SHA-1 hash tree)** enables recovery at BLOCK granularity (180 KiB leaves) instead of re-downloading a whole part:

- `OP_AICHFILEHASHREQ (0x9E) / OP_AICHFILEHASHANS (0x9D)`: learn a peer's AICH master (root) hash (often bundled in OP_MULTIPACKET).
- `OP_AICHREQUEST (0x9B)` = file hash(16) | uint16 part number | master hash(20) -> request recovery data for one part. Requester must hold a trusted master.
- `OP_AICHANSWER (0x9C)` = same header + the SIBLING SHA-1 hash at every level along the root-to-part path, then all 180 KiB leaf hashes of that part's subtree.

**ICH / corruption handling:** on flush, a completed part is MD4-checked against the hashset. A failing part is re-gapped (whole part), pushed to the corrupted list, `m_iLostDueToCorruption += partsize`, and `RequestAICHRecovery` scheduled. Recovery needs a verified master and part > EMBLOCKSIZE; it picks a random AICH-capable source whose master matches. On receiving recovery data, aMule re-hashes the on-disk part into a scratch subtree, `FillGap`s only the matching 180 KiB blocks (so only bad blocks are re-downloaded), and if the part becomes complete MD4 must *also* agree or the whole part is re-gapped. **Trust of a master hash requires >= 10 unique (masked) IPs reporting it and >= 92% agreement.** `CorruptionBlackBox` tracks per-IP good/bad bytes; a client whose corrupt share exceeds `CBB_BANTHRESHOLD = 32%` is banned 2 h (DS_BANNED). Blame is only assignable at AICH block level - a plain MD4 part failure with no AICH data blames no one.

### 2.7 Credits and secure identification

`GetScoreRatio(ip)`: "downloaded" = bytes we received FROM the peer, "uploaded" = bytes we sent TO the peer. `ratio = (uploaded==0 ? 10.0 : downloaded*2/uploaded)`; `bound = sqrt(downloaded/1048576 + 2)`; `result = min(ratio, bound)` clamped `[1.0, 10.0]`; forced to 1.0 if downloaded < 1,000,000 bytes or if secure-ident failed while crypto is available (cheater guard). This is the creditRatio in the upload score.

**Secure identification** (started by InfoPacketsReceived when the peer advertises SecIdent): `OP_SECIDENTSTATE (0x87)` = uint8 state + uint32 challenge; the peer answers `OP_PUBLICKEY (0x85)` (first time) and `OP_SIGNATURE (0x86)` = RSASSA-PKCS1v15-SHA1 over `[our public key] + [the challenge we issued]` (+ IP fields for v2). Binds credits to a stable RSA key; a verified public key can never be replaced, and a userhash change on a tracked IP+port triggers a ban.

### 2.8 Source exchange (SX) and admission plumbing

Peers swap known sources directly, offloading server/Kad:

- **SX1:** `OP_REQUESTSOURCES (0x81)` = file hash(16). Answer `OP_ANSWERSOURCES (0x82)`.
- **SX2:** `OP_REQUESTSOURCES2 (0x83)` = uint8 version(=4) | uint16 options(0) | file hash(16). Answer `OP_ANSWERSOURCES2 (0x84)`.

Gating (`IsSourceRequestAllowed`): requires ext protocol and (SX2 support or SX1 version > 1), current sources < ~0.9*max, and per-client/per-file cooldowns (`SOURCECLIENTREASKS = 40 min`, `SOURCECLIENTREASKF = 5 min`) that relax for rare files (`RARE_FILE = 50`, very rare <= 10) and tighten x4 (`MINCOMMONPENALTY`) for common files.

Answer body: `[uint8 usedVersion if SX2] | file hash(16) | uint16 count | per source: uint32 ID | uint16 port | uint32 serverIP | uint16 serverPort | +16B userhash if version>=2 | +uint8 cryptOptions if version>=4`. Sources drawn from clients uploading/queued on us for that file, excluding low-ID and the asker; needed-part filtered; capped ~500. Receiving (`AddClientSources`): SX1 infers entry version from size (12/28/29 bytes); each source runs the IsGoodIP + ipfilter + ban gauntlet and `CanAddSource`, then `CheckAndAddSource`.

`CheckAndAddSource` (shared entry for every discovered source): drop if source hash == ours, file stopped, dead source, or crypt-layer mismatch. Same-userhash queued for another file becomes an A4AF entry; otherwise AttachToAlreadyKnown merges or registers a new client. Dead sources are keyed by UserIDHybrid with timeouts (global 30/45 min, per-file 45/60 min, longer for LowID) and added on UDP OP_FILENOTFOUND, failed connects, etc.

### 2.9 Key C2C parameters

```
PARTSIZE = 9728000 (MD4 part); EMBLOCKSIZE = BLOCKSIZE = 184320 (180 KiB block); ~52.78 blocks/part
STANDARD_BLOCKS_REQUEST = 3 per OP_REQUESTPARTS; VBT pipeline cap 0x20=32
Protocol bytes: OP_EDONKEYPROT=0xE3, OP_EMULEPROT=0xC5, OP_PACKEDPROT=0xD4, OP_ED2KV2HEADER=0xF4
Standard opcodes: HELLO 0x01, SENDINGPART 0x46, REQUESTPARTS 0x47, FILEREQANSNOFIL 0x48, HELLOANSWER 0x4C,
                  SETREQFILEID 0x4F, FILESTATUS 0x50, HASHSETREQUEST 0x51, HASHSETANSWER 0x52,
                  STARTUPLOADREQ 0x54, ACCEPTUPLOADREQ 0x55, CANCELTRANSFER 0x56, OUTOFPARTREQS 0x57,
                  REQUESTFILENAME 0x58, REQFILENAMEANSWER 0x59, QUEUERANK 0x5C, PUBLICKEY 0x85, SIGNATURE 0x86
Extended opcodes: EMULEINFO 0x01, EMULEINFOANSWER 0x02, COMPRESSEDPART 0x40, QUEUERANKING 0x60,
                  REQUESTSOURCES 0x81, ANSWERSOURCES 0x82, REQUESTSOURCES2 0x83, ANSWERSOURCES2 0x84,
                  SECIDENTSTATE 0x87, MULTIPACKET 0x92, MULTIPACKETANSWER 0x93, AICHREQUEST 0x9B,
                  AICHANSWER 0x9C, AICHFILEHASHANS 0x9D, AICHFILEHASHREQ 0x9E, COMPRESSEDPART_I64 0xA1,
                  SENDINGPART_I64 0xA2, REQUESTPARTS_I64 0xA3, MULTIPACKET_EXT 0xA4
MISCOPTIONS1 (MSB->LSB): AICHver(3b)|Unicode(1b)|UDPver(4b)|DataComp(4b)|SecIdent(4b)|SrcExch1(4b)
                         |ExtReq(4b)|Comment(4b)|peercache(1)|noviewshared(1)|multipacket(1)|preview(1)
   aMule sends AICH=1,Unicode=1,UDPver=4,DataComp=1,SecIdent=3(if crypto),SrcExch=3,ExtReq=2,Comment=1,MultiPacket=1
MISCOPTIONS2: bit12 directUDPcallback, bit11 captcha, bit10 SX2, bit9 requiresCrypt, bit8 requestsCrypt,
              bit7 supportsCrypt, bit5 extMultipacket, bit4 largeFiles(64-bit), bits0-3 KadVersion(0x08)
FILEREASKTIME = 1300000 ms (TCP reask); UDP reask at FILEREASKTIME-20000
DOWNLOADTIMEOUT = 100000 ms (no block data -> cancel)
Upload kick: session > 3600000 ms OR > 10485760 bytes; GetMaxSlots cap 250, min 2
OP_QUEUERANKING = 12 bytes (uint16 rank + 10 zero pad)
Prio multipliers: PowerShare 250.0, VeryHigh 1.8, High 0.9, Normal 0.7, Low 0.6, VeryLow 0.2; friend slot 0x0FFFFFFF
Credit ratio = min(2*downloaded/uploaded, sqrt(downloaded/1048576+2)) clamped [1.0,10.0]; 1.0 if downloaded<1000000
SOURCEEXCHANGE2_VERSION=4; SX entry size v1=12, v2/v3=28, v4=29
SX cooldowns: SOURCECLIENTREASKS=40min, SOURCECLIENTREASKF=5min, MINCOMMONPENALTY=4, RARE_FILE=50
AICH: leaf 180 KiB, master SHA-1 20 bytes; trust >=10 IPs + 92% agreement; recovery needs part>EMBLOCKSIZE
CBB_BANTHRESHOLD = 32% -> 2 h ban
MAX_PACKET_SIZE = 2000000; PACKET_HEADER_SIZE = 6
```

---

## Part 3 - Kademlia: Algorithm Foundations

Kademlia is a distributed hash table. Every participant and every stored key live in the SAME identifier space, and one primitive - "find the k nodes closest to an ID" - is what everything else (routing maintenance, storing, finding, joining) is built from. The whole design follows from one choice: **distance = bitwise XOR interpreted as an unsigned integer.**

> This part describes the *base algorithm* (Maymounkov/Mazieres paper). Where the aMule 3.0.1 codebase diverges from the classic description, it is flagged inline and detailed in Part 4. Two important structural divergences (routing-table split rule, and eviction mechanism) are noted here so the classic description is not taken verbatim.

### 3.1 Node IDs and the XOR metric (and why XOR)

- Each node picks a random `B`-bit ID; keys are also `B`-bit values. Paper uses B = 160 (SHA-1 sized); **eMule/aMule use B = 128** (MD4-sized). Nodes and keys share one flat 2^B space.
- `d(x,y) = x XOR y`, read as a base-2 integer. Magnitude is dominated by the most-significant differing bit: sharing a longer common prefix => smaller distance. "Close in XOR" == "shares a long high-order prefix".
- Metric properties, and the work each does:
  - **Identity:** `d(x,x)=0`, `d(x,y)>0` for `x!=y`.
  - **Symmetry:** `d(x,y)=d(y,x)`. **The key win over Chord.** Because distance is symmetric, a node that queries me is exactly as far from me as I am from it, so an incoming query carries a contact that belongs in MY routing table. Kademlia learns useful routing state *for free* from traffic it already receives; Chord's asymmetric (clockwise) metric cannot.
  - **Triangle inequality:** `d(x,z) <= d(x,y) + d(y,z)`.

    > **Do not attribute lookup progress to the triangle inequality.** It is a genuine property of XOR, but Kademlia never computes `d(x,y)+d(y,z)` anywhere and convergence does not depend on additivity. Monotone progress comes from the routing-table **invariant** (each node knows a live contact in every non-empty non-containing subtree) plus **unidirectionality**, which force each hop to a node sharing a strictly longer prefix with the target. aMule's lookup selects strictly-closer unqueried contacts purely by XOR ordering; there is no additive-distance test in the code.
  - **Unidirectionality:** for a fixed `x` and distance `delta > 0`, there is exactly one `y` with `d(x,y)=delta`. Consequence: a lookup for key K converges along essentially the same neighborhoods no matter who starts it - which is what makes path-caching effective.
- **Tree picture (the mental model):** treat every node as a leaf of a binary trie keyed by ID bits, top bit at the root. For a node u, the trie splits into ever-smaller subtrees that do NOT contain u. XOR distance == height of the smallest subtree spanning both leaves. Core **invariant:** u knows at least one live contact in each non-containing subtree (whenever one exists), so u can always forward a query into the correct subtree and at least halve the remaining distance -> O(log n) hops.

### 3.2 k-buckets: the routing table (classic form)

- The table realizes the invariant as up to B lists called k-buckets. Bucket i holds contacts whose distance from self lies in `[2^i, 2^(i+1))` - one live pointer into the i-th non-containing subtree.
- A contact is `(IP, UDP port, node ID)`.
- Each bucket holds up to `k` entries. **k = 20** (paper) is sized so all k contacts are very unlikely to die within one hour; k is also the value replication factor. **eMule uses ~10.**
- **Least-recently-seen eviction (classic):** bucket sorted head(oldest)->tail(newest). On any message from a peer, if present move to tail; if absent and not full, append; if absent and FULL, PING the head - head responds -> move to tail and discard the newcomer; head fails -> evict head, insert newcomer. A live old contact is never displaced by a newcomer.
- **Why LRS:** (a) longevity statistics - a node up a long time is likelier to stay up; (b) attack resistance - an adversary cannot flush a table by flooding fresh IDs, since a full bucket rejects newcomers while its contacts answer.
- **Bucket splitting (classic):** start with one bucket spanning the whole range; split a full bucket only if its range contains the node's own ID; otherwise just evict. This yields fine resolution near your own ID, coarse far away.

> **aMule diverges from both of these (see Part 4.8):**
> - **Split rule:** `CanSplit()` splits a full bin (size==K=10) when `level < 127 && (zoneIndex < KK=5 || level < KBASE=4)` - a *relaxed, fixed-shape* tree that always splits the first few levels, not the classic "only if the range contains our own ID".
> - **Eviction:** aMule does **not** ping-head-and-evict on insert and has **no replacement cache.** A full bin simply rejects new contacts. Liveness is maintained by a periodic timer that pings the *oldest* contact and by per-contact staleness tiers. New contacts only enter when a slot frees up.

### 3.3 The four RPCs (all over UDP)

Every request carries a random RPC-ID the responder echoes, so replies match requests and spoofed responses are rejected. A reply also implicitly confirms the responder's address.

1. **PING(target)** - probe liveness.
2. **STORE(key, value)** - hold `(key,value)` for later retrieval.
3. **FIND_NODE(targetID)** - return the k contacts the recipient knows closest to targetID.
4. **FIND_VALUE(key)** - like FIND_NODE, unless the recipient has a stored value for key, in which case it returns the VALUE.

> **eMule/Kad2 does not implement this literally (see Part 4.3):** it uses one FIND opcode (`KADEMLIA2_REQ`) whose type byte encodes both the requested contact count and the intent (FIND_NODE=11 / FIND_VALUE=2 / STORE=4), and RES **always returns contacts only** - value retrieval is a *separate* SEARCH_*_REQ RPC. PING/STORE are also distinct opcodes. The four RPCs are conceptually intact but literally false at the wire level.

### 3.4 Iterative node lookup (the central procedure)

Goal: find the k closest live nodes to a target. Initiator-driven and iterative; intermediate nodes only answer, they do not recurse.

Parameters: `alpha` = concurrency (paper 3; **this aMule tree = 5**), `k` = shortlist width.

1. Seed a shortlist with alpha nodes from the initiator's closest non-empty bucket(s).
2. Send FIND_NODE(target) to alpha closest-unqueried nodes, **in parallel and asynchronously** - one slow/dead node never stalls the lookup.
3. Merge returned contacts, keep sorted by XOR distance, keep the k closest.
4. Next round: pick alpha of the closest not-yet-queried and query them.

   > Paper wording, corrected: a node that fails to respond quickly is simply **removed from consideration** (it may still be used if it later responds). There is no prescribed "re-query once" rule; the alpha-parallelism is what tolerates dead nodes.
5. **Convergence check:** if a round returns no strictly-closer node, broaden - query ALL of the k closest not-yet-queried nodes.
6. **Termination:** the lookup ends when the initiator has queried and heard from the k closest nodes it has seen. Result = those k closest responsive nodes.

Each round fixes at least one more high-order prefix bit -> O(log n) rounds.

### 3.5 Value storage and retrieval

- **STORE (key,value):** run a node lookup for key -> k closest nodes -> send STORE to all k. k-fold replication survives churn.
- **FIND value:** run the same lookup with FIND_VALUE; as soon as any node returns the value, halt.

### 3.6 Caching, republishing, expiration (paper values)

- **Caching:** after a successful FIND_VALUE, the requester STOREs `(key,value)` at the closest node it saw that did NOT already have the value. By unidirectionality, later lookups pass through that neighborhood and hit the cache early. Cached-copy expiration is inversely proportional to the number of nodes between it and the key's k-closest, so far copies die quickly.
- **Replication:** every storing node re-replicates each pair once per hour (`tReplicate = 1h`). Convoy optimization: a node that receives a STORE for a pair it already holds suppresses its own republish for the next hour, so typically only one custodian republishes per interval.
- **Republish:** the original publisher must re-publish every 24h (`tRepublish = 24h`).
- **Expire:** a pair expires 24h after last publication (`tExpire = 24h`).

> **aMule does NOT use these constants (see Part 4.5).** Its store lifetimes/republish/expire are the KADEMLIAREPUBLISHTIMES/K/N family - source publish every 5h, keyword/notes every 24h - not the paper's uniform 1h/24h/24h.

### 3.7 Bucket refresh, joining, self-lookup

- **Refresh:** a bucket untouched by any lookup for `tRefresh = 1h` is refreshed by looking up a random ID in its range.
- **Joining:** a new node u knows one live participant w (out-of-band), inserts w, then **does a node lookup for its OWN ID.** This both fills u's close buckets and announces u to its neighborhood automatically (every node u contacts files u into its own table). u then refreshes farther buckets.

### 3.8 How the 160-bit paper maps to eMule's 128-bit Kad

The ID length B is a parameter, not part of the logic. eMule sets B = 128 (MD4-sized). XOR over 128 bits has identical symmetry/unidirectionality/triangle properties; the trie is depth 128; the space is 2^128. Asymptotically irrelevant: real network size n << 2^128, so populated-bucket count and O(log n) hops are governed by n, not B. The paper's *constants* (k, timers) are what Kad2 re-tunes; the width change alone is just substitution.

### 3.9 Key algorithm parameters (paper vs this repo)

```
k = 20 (paper: k-bucket size AND replication factor)          |  aMule K = 10
alpha = 3 (paper: lookup concurrency)                         |  this aMule tree ALPHA_QUERY = 5
B = 160 bits (paper, SHA-1)                                   |  eMule/aMule B = 128 (MD4)
b = 5 (accelerated routing symbol bits; base form b=1)
tExpire = 86400 s (24h); tRefresh = 3600 s (1h);
tReplicate = 3600 s (1h); tRepublish = 86400 s (24h)          |  aMule uses different intervals (Part 4.5)
RPC ID = random nonce echoed in replies (match + anti-spoof)
Complexity: lookup/store/find = O(log n); table = O(log n) buckets x k
Eviction = least-recently-seen (paper)                        |  aMule = periodic-ping-oldest, no LRS-on-insert
Split = only if range contains own ID (paper)                 |  aMule = relaxed CanSplit(KBASE=4/KK=5)
```

---

## Part 4 - eMule Kad2: The Application Layer

### 4.1 What Kad is for

Kad is a serverless replacement for the ed2k server layer. It moves NO file content; it is a DHT storing tiny metadata records so peers can (a) turn a text query into file hashes (**KEYWORD index**), (b) turn a file hash into peers who have it (**SOURCE index**), and (c) attach comments/ratings to a file hash (**NOTES index**). Transfer still uses ed2k TCP once sources are known. Everything reduces to a NODE LOOKUP plus, on top, STORE (publish) and value-fetch (search) at the ~10 live nodes XOR-closest to the target key. All lookups run locally.

> aMule 3.0.1 predominantly sends Kad2 opcodes, but the "ONLY Kad2" claim is an overstatement: it still emits the Kad1 `KADEMLIA_SEARCH_REQ` to contacts with version < 3/< 6, and the firewall/buddy flows actively use shared-opcode-space Kad1 opcodes 0x50-0x5A. In practice all live nodes are ver>=6, so the legacy send paths are effectively dead.

One 128-bit address space, three roles for an ID: a NODE **KadID** (random per-install, persisted in `preferencesKad.dat`); a **KEY** = hash of the indexed thing; a **VALUE** owner-id inside a record. DHT invariant: a record with key K lives on the live nodes whose KadID is XOR-closest to K.

### 4.2 128-bit IDs and key derivation (interop-critical)

IDs are `CUInt128` = four uint32 chunks, **chunk0 = most significant**. `GetBitNumber(0)` is the MOST significant bit; that ordering drives tree descent. Distance is pure XOR, compared unsigned MSB-chunk-first.

A 16-byte MD4/MD5 hash becomes a CUInt128 via **SetValueBE** (treats hash bytes big-endian: `u32[3]=BE(bytes0..3), ... u32[0]=BE(bytes12..15)`).

> **The single most interop-critical detail.** SetValueBE composed with WriteUInt128 ("four LE uint32 in big-endian chunk order") produces a wire layout that is **byte-reversed within each 32-bit word** relative to the raw hash. A raw hash `b0..b15` goes on the wire as:
>
> `b3 b2 b1 b0 | b7 b6 b5 b4 | b11 b10 b9 b8 | b15 b14 b13 b12`
>
> A reimplementer who writes the raw hash bytes directly (instead of SetValueBE then four MSW-first little-endian dwords) produces a different, wire-incompatible target ID. Get this exactly right or every lookup/publish targets the wrong node.

**Key derivations:**

- **KEYWORD key:** tokenize the query on the invalid-char set `" ()[]{}<>,._-!?:;\/"`, drop words < 3 UTF-8 bytes, lowercase. MD4 (CryptoPP `Weak::MD4`) of the **first** surviving word's raw UTF-8 bytes -> SetValueBE. Additional query words become a restrictive **search-expression tree** (boolean filter) carried in SEARCH_KEY_REQ, NOT part of the key. (`KadGetKeywordHash` itself does not lowercase; the caller lowercases first.)
- **SOURCE key** = the file's ed2k MD4 hash (16 bytes) as CUInt128 via SetValueBE. Publishing a source: keyID = fileHash, record sourceID = OUR clientHash (ed2k userhash as CUInt128).
- **NOTES key** = the file's ed2k MD4 hash. Publishing a note: keyID = fileHash, sourceID = OUR KadID.

So one shared file causes: 1 SOURCE publish under the file hash + 1 KEYWORD publish per keyword-word (value = file hash + name/size/type tags) + optional NOTES publish.

### 4.3 The tolerance zone (eMule-specific closeness cutoff)

Base Kademlia stores at the k-closest by rank. eMule adds a hard cutoff: `SEARCHTOLERANCE = 16777216 = 0x1000000 = 2^24`. A node is close enough only if the **top 32-bit chunk of the XOR distance <= 0x1000000**, i.e. the top ~8 bits of the 128-bit distance are zero.

> **Magnitude:** this means distance up to **~2^120**, NOT ~2^104. `2^24 * 2^96 = 2^120`. (Both the study draft and the recon doc carry the wrong `2^104` figure; the implementable check `Get32BitChunk(0) <= 0x1000000` is correct regardless, but any reasoning about zone size would otherwise be off by 2^16.)

The gate is applied in three places: on the STORE side (publisher skips too-far responded contacts), on the RECEIVER side of every publish (drop if too far), and conceptually as a bound on how far a searcher keeps asking. This makes "the ~10 closest" a self-consistent zone both sides agree on, defending against fake-close storers.

> **LAN exception (must not be omitted):** the rejection is `distance.Get32BitChunk(0) > SEARCHTOLERANCE && !IsLanIP(swap(ip))`. LAN-IP peers bypass the tolerance rejection entirely.

### 4.4 The Kad2 RPC set and wire framing

```
Node/bootstrap/liveness:
  KADEMLIA2_BOOTSTRAP_REQ 0x01 -> _RES 0x09
  KADEMLIA2_HELLO_REQ 0x11 -> _RES 0x19 -> _RES_ACK 0x22   (3-way, ver>=8)
  KADEMLIA2_PING 0x60 -> KADEMLIA2_PONG 0x61                (PONG echoes the source UDP port it saw)
Node lookup (FIND_NODE equivalent):
  KADEMLIA2_REQ 0x21 -> KADEMLIA2_RES 0x29
     REQ type byte = requested contact count AND intent: FIND_VALUE=0x02, STORE=0x04, FIND_NODE=0x0B(11)
     parser masks type &= 0x1F; RES returns CONTACTS ONLY
Value fetch (second phase, to already-close responded nodes):
  KADEMLIA2_SEARCH_KEY_REQ 0x33, _SOURCE_REQ 0x34, _NOTES_REQ 0x35 -> KADEMLIA2_SEARCH_RES 0x3B
Publish:
  KADEMLIA2_PUBLISH_KEY_REQ 0x43, _SOURCE_REQ 0x44, _NOTES_REQ 0x45 -> _RES 0x4B -> _RES_ACK 0x4C
Firewall/buddy (some shared with Kad1 opcode space):
  KADEMLIA_FIREWALLED_REQ 0x50, _FIREWALLED2_REQ 0x53, _FIREWALLED_RES 0x58, _FIREWALLED_ACK_RES 0x59,
  KADEMLIA2_FIREWALLUDP 0x62, KADEMLIA_FINDBUDDY_REQ 0x51, _RES 0x5A, KADEMLIA_CALLBACK_REQ 0x52
  Plus ed2k-UDP OP_DIRECTCALLBACKREQ 0x95
```

**Wire framing (after decryption):** `[protocol 1][opcode 1][payload]`. protocol = `0xE4` (plain Kad) or `0xE5` (zlib-packed, when a built packet > 200 bytes). All scalars little-endian. 128-bit IDs use WriteUInt128 (see 4.2). Tags: `count(1)` then tags of `{type(1) | nameLen(2) | name | value}` - Kad always uses the 2-byte-name form even for single-char names like `0xFC`.

### 4.5 Node lookup, publish, and search flows

A `CSearch` has a target and a type (NODE, NODECOMPLETE, FILE, KEYWORD, NOTES, STOREFILE, STOREKEYWORD, STORENOTES, FINDBUDDY, FINDSOURCE, NODESPECIAL, NODEFWCHECKUDP).

**Node lookup (`Go()`):** seed `m_possible` with the 50 verified contacts closest to target from the routing table. Fire initial `KADEMLIA2_REQ` to the top `count` nodes: count = 1 for NODE, else `min(ALPHA_QUERY, possible)` parallel. Each REQ = `type(1)=requestedContactCount | target(16) | contact.clientID(16)` - the receiverKadID lets the peer verify you are talking to the right node (drop if it != my KadID). Requested count per type: NODE*=11, FILE/KEYWORD/NOTES/FINDSOURCE=2, STORE*/FINDBUDDY=4.

RES = `target(16) | numContacts(1) | numContacts*{ClientID16, IP4, UDPport2, TCPport2, version1}`. ProcessResponse dedups by IP (reject 2 KadIDs on one IP; reject >2 per /24), inserts each returned contact CLOSER to target into `m_best` (cap ALPHA_QUERY) and immediately fires the next query -> the frontier marches inward. Responses with more contacts than requested are rejected (anti-abuse), except the deliberate wider reask.

`JumpStart()` every 1s: skip if a response came in the last 3s; if the best FIND_VALUE nodes are all dead and >=6 tried, reask the closest RESPONDED node for the wider set (11) to escape a dead-closest trap; otherwise probe the next untried closest, or run `StorePacket()` (the type-specific value action) if the closest is already responded. This is the transition from "find nodes" to "do the real work".

**Lifetimes:** FILE/KEYWORD/NOTES/NODE=45s, NODECOMPLETE=10s, STOREFILE/STOREKEYWORD=140s, STORENOTES/FINDBUDDY=100s, FINDSOURCE=45s. Answer caps: FILE/KEYWORD=300, NOTES=50, STORE*=10, FINDSOURCE=20. PrepareToStop leaves a ~15s drain window.

**KEYWORD publish (STOREKEYWORD):** `KADEMLIA2_PUBLISH_KEY_REQ 0x43` = `keyID(16 keyword hash) | count(2) | count*{sourceID(16 file hash) | tagCount(1) | tags}`, up to 50 file entries per packet. Tags: TAG_FILENAME(0x01), TAG_FILESIZE(0x02, split hi/lo for >4GB), TAG_FILETYPE, TAG_SOURCES, media tags. Receiver drops if UDP-firewalled or outside tolerance, else indexes and replies `PUBLISH_RES = keyID(16) | load(1, 0-100)` (load = fill*100/max, so the publisher learns saturation).

**SOURCE publish (STOREFILE):** `KADEMLIA2_PUBLISH_SOURCE_REQ 0x44` = `keyID(16 file hash) | sourceID(16 our clientHash) | tagCount(1) | tags`. The crucial tag is **TAG_SOURCETYPE (0xFF)**, encoding reachability:

```
1 = HighID (not firewalled), TCP-reachable directly
3 = Firewalled, reachable via buddy callback
4 = HighID, file >4GB
5 = Firewalled, file >4GB
6 = Firewalled but UDP-open+verified -> direct UDP callback (no buddy)
```

Plus TAG_SOURCEPORT(0xFD TCP), TAG_SOURCEUPORT(0xFC UDP), TAG_FILESIZE(0x02), TAG_ENCRYPTION(0xF3). For firewalled+buddy (3/5) it also sends TAG_SERVERIP/PORT (the buddy address) and TAG_BUDDYHASH (complement-of-our-KadID). Receiver requires a SOURCETYPE tag, adds TAG_SOURCEIP = sender IP server-side, drops on firewall/tolerance, indexes.

**NOTES publish (STORENOTES):** `KADEMLIA2_PUBLISH_NOTES_REQ 0x45` = `keyID(16 file hash) | sourceID(16 our KadID) | tagCount | tags{FILENAME, FILERATING(0xF7), DESCRIPTION(0x0B), FILESIZE}`.

**Republish cadence (aMule constants, NOT the paper's):** sources every `KADEMLIAREPUBLISHTIMES = 5h`; keywords and notes every 24h. Store-side caps: `KADEMLIAMAXINDEX 50000` keys, `KADEMLIAMAXENTRIES 60000` entries, `KADEMLIAMAXSOURCEPERFILE 1000`, `KADEMLIAMAXNOTESPERFILE 150`. `CKeyEntry` carries per-IP publish counts and a trust value for keyword-spam mitigation. Index persisted to `src_index.dat / key_index.dat / load_index.dat`.

**Search** = node lookup toward the key, then SEARCH_*_REQ to the closest responded nodes:

- **KEYWORD search:** `KADEMLIA2_SEARCH_KEY_REQ 0x33` = `target(16) | startPosition(2)`. If `startPosition & 0x8000`, the remainder is a search-expression tree (the boolean filter from the extra words/size/type). Real offset = `startPosition & 0x7FFF`. Responder does two passes (trusted `trustValue>=1` first), applies the filter, honors the offset, caps 300, batches <=50 per packet.
- **SOURCE search:** `KADEMLIA2_SEARCH_SOURCE_REQ 0x34` = `target(16) | startPosition(2 &0x7FFF) | fileSize(8 uint64)`. Entries carry SOURCETYPE + IP/port. ProcessResultFile reconstructs each source (type 1 -> connect; 3/5 -> buddy; 6 -> direct UDP callback).
- **NOTES search:** `KADEMLIA2_SEARCH_NOTES_REQ 0x35` = `target(16) | fileSize(8)`. Cap 150.

`KADEMLIA2_SEARCH_RES 0x3B` = `senderKadID(16) | target(16 keyID) | count(2) | count*{answerID(16) | tagCount(1) | tags}`.

### 4.6 Bootstrap (joining)

Sources: `nodes.dat`, a bootstrap IP, or contacts from ed2k servers.

1. While not connected and the bootstrap list is non-empty: every >15s (or >=2s if the table is empty) pop the closest bootstrap contact, send `KADEMLIA2_BOOTSTRAP_REQ 0x01` (empty payload; includes cryptTargetID only for remote ver>=6).
2. Peer replies `KADEMLIA2_BOOTSTRAP_RES 0x09` = `ClientID(16) | UDPport(2) | version(1) | numContacts(2) | up to 20 * {ClientID16, IP4, UDP2, TCP2, ver1}`. The responder returns a **spread** of contacts (not just closest) to seed a fresh table.
3. Add responder + all returned contacts. If the table was empty, all are marked verified for a fast start.
4. Within 3 min of start (and every 4h) force a **self-lookup**: a NODECOMPLETE FindNode toward OUR OWN KadID. This fills every bucket along the path. When it finishes, publishing is enabled.
5. No contact for `KADEMLIADISCONNECTDELAY = 20min` -> considered disconnected.

```
NewNode                          BootstrapPeer
  |-- BOOTSTRAP_REQ 0x01 ---------->|
  |<- BOOTSTRAP_RES 0x09 (<=20 -----|   seed routing table (spread of contacts)
  |   spread contacts)              |
  |  (self-lookup toward ownKadID: iterative REQ/RES fans out)
  |-- REQ 0x21 type=11 target=ownKadID -> closeNode
  |<- RES 0x29 (closest contacts) <----- closeNode
  |  ... converge -> buckets fill -> SetPublish(true)
```

### 4.7 Search / publish flows (ASCII)

```
Keyword search (name -> file hashes):
Searcher                          NodeCloseToKeywordHash
  |== iterative REQ/RES until inside tolerance of keywordHash ==|
  |-- SEARCH_KEY_REQ 0x33 (keywordHash, startPos[, filter]) --->|
  |<- SEARCH_RES 0x3B (<=50/pkt: fileHash + name/size/media) ---|

Source search (fileHash -> peers):
Searcher                          NodeCloseToFileHash
  |== iterative REQ/RES to fileHash ==|
  |-- SEARCH_SOURCE_REQ 0x34 (fileHash, startPos, size) ------->|
  |<- SEARCH_RES 0x3B (sourceID + SOURCETYPE + IP/port tags) ---|

Keyword publish (share -> index):
Publisher                         NodeCloseToKeywordHash
  |== STOREKEYWORD lookup (inside tolerance) ==|
  |-- PUBLISH_KEY_REQ 0x43 (keywordHash|count|{fileHash+tags} up to 50) ->|
  |<- PUBLISH_RES 0x4B (keyID | load 0..100) ----------------------------|
```

### 4.8 Routing table (zones = tree, bins = k-buckets)

A binary tree of **zones**. An internal node has 2 subzones and `bin=NULL`; a leaf has a bin (k-bucket). Root = level 0. Your own KadID is the tree's center (treated as 000..0); a contact is placed by walking `distance.GetBitNumber(level)` at each internal node. Near-you contacts end up in deep fine buckets; distant contacts share coarse buckets.

- **k-bucket size K = 10.** Split rule `CanSplit`: split a full (`size==K`) leaf only if `level < 127 && (zoneIndex < KK=5 || level < KBASE=4)`. This bounds the tree - fine-grained only near yourself and in the top few levels (KBASE=4, KK=5, LOG_BASE_EXPONENT=5). Consolidate/merge runs every 45min: sibling leaves with combined < K/2 merge back.
- **Bin rules:** up to K=10, front=oldest. Reject duplicate ClientID; reject if >=2 contacts already share the /24 in this bin (anti-eclipse, except LAN); global caps `MAX_CONTACTS_IP=1` (one per exact IP table-wide), `MAX_CONTACTS_SUBNET=10` per /24 globally. A refreshed contact is pushed to the bottom (MRU); GetOldest = front.
- **Contact liveness ("type" = staleness 0 best .. 4 dead):** new contact starts type=3; UpdateType ages it (<1h -> type2, 1-2h -> type1, >=2h -> type0). A per-zone timer (every 60s) removes dead contacts and re-HELLOs the oldest to re-verify. A big timer does a RandomLookup within the zone's prefix to keep buckets full.
- **IP verification / anti-spoof:** a contact must have `m_ipVerified=true` before `GetClosestTo` returns it. Verification requires matching BOTH id AND ip, via one of: HELLO_RES_ACK (ver>=8 3-way), a PING challenge (ver7), or a legacy KADEMLIA2_REQ random-target challenge (ver<7). Once a contact has a stored non-zero UDPKey, any update must present the SAME key (anti-hijack).

### 4.9 Firewall handling and the buddy system (Kad's LowID)

Kad separates TCP-firewalled from UDP-firewalled state.

- **TCP firewall test:** during a HELLO exchange, send `KADEMLIA_FIREWALLED2_REQ 0x53` (ver>6: `TCPport|userID16|connectOptions1`) or legacy `0x50`. The peer attempts a TCP connect-back to your advertised port; on success it replies `KADEMLIA_FIREWALLED_RES 0x58` with your observed public IP. You declare yourself OPEN after >=2 confirmations (budget `KADEMLIAFIREWALLCHECKS=4`). This is the Kad analog of ed2k HighID.
- **UDP firewall test:** run a NODEFWCHECKUDP random-node search to collect fresh IPs; ask up to `UDP_FIREWALLTEST_CLIENTSTOASK=2` of them to send you a `KADEMLIA2_FIREWALLUDP 0x62` = `errorCode(1)|incomingPort(2)` at your expected port. One success => UDP open+verified; both fail or 6-min timeout => UDP firewalled. External UDP port discovered separately via PING/PONG (2-of-3 agreeing results, `EXTERNAL_PORT_ASKIPS=3`).
- **Buddy system:** every ~20min if firewalled, start a FINDBUDDY search whose target = `complement-of-your-KadID (CUInt128(true) ^ ourKadID)`. Send `KADEMLIA_FINDBUDDY_REQ 0x51` = `buddyID(16)|userID(16 our clientHash)|TCPport(2)`. An OPEN+verified peer with no buddy accepts (`FINDBUDDY_RES 0x5A`) and holds an open TCP link to you. Remote peers who found your firewalled source (SOURCETYPE 3/5) send `KADEMLIA_CALLBACK_REQ 0x52` = `buddyID(16)|fileID(16)|TCPport(2)` to your buddy, which relays it to you over TCP so you call them back. This is the ed2k LowID callback, decentralized. If instead you are UDP-open+verified you advertise SOURCETYPE 6 and use ed2k-UDP `OP_DIRECTCALLBACKREQ 0x95`.

Connect-options byte: `bit3(0x08)=DirectCallback`, `bit2=CryptLayerRequired`, `bit1=CryptLayerRequested`, `bit0=CryptLayerSupported`.

```
Firewalled download via buddy (Kad LowID callback):
FW-Peer(A)        Buddy(B, open)          Remote(C, wants A's file)
  |-- FINDBUDDY_REQ 0x51 ->|                        |
  |<- FINDBUDDY_RES 0x5A ---| (B is now A's buddy)   |
  |                         |<- CALLBACK_REQ 0x52 ---| (C found A as SOURCETYPE 3, buddy=B)
  |<--- relay OP_CALLBACK (TCP) --|                  |
  |------------------ A calls back C (TCP) --------->|  transfer starts
```

### 4.10 UDP obfuscation / encryption layer

Every Kad UDP datagram MAY be wrapped in RC4 obfuscation. Purpose: defeat naive ISP fingerprinting and add spoofing resistance, not strong confidentiality. Plaintext Kad packets start with `0xE4`/`0xE5`; obfuscated ones start with a semi-random byte.

Obfuscated layout:

```
[SemiRandomByte 1][randomKeyPart 2 LE][RC4(MAGICVALUE_UDP_SYNC_CLIENT=0x395F2EC1)]
[RC4(padLen 1)][RC4(pad)][RC4(receiverVerifyKey 4)][RC4(senderVerifyKey 4)]
[RC4(actual Kad packet: 0xE4/E5 + opcode + payload)]
```

> **Kad crypt overhead = 16 bytes, not 12.** Base header `CRYPT_HEADER_WITHOUTPADDING = 8` + Kad's two 4-byte verify keys (8) = 16. `padLen` is currently 0. The encrypted payload starts at byte 16. (Both the study draft and the recon doc miscompute this as 12; `8 + 2*4 = 16`. This sets every byte offset for the payload.)

The low 2 bits of SemiRandomByte are hints: bit0 = ed2k(1)/kad(0); bit1 (kad) = receiver-key(1) vs node-id-key(0). Old clients randomize these, so the receiver tries up to 3 candidate keys.

Two keying schemes:

- **NODE-ID key** (packet encrypted TO us by our own KadID, e.g. a peer who knows our node id): `keyData = StoreCryptValue(ourKadID)(16) || randomKeyPart(2)`; `RC4 key = MD5(keyData)`.
- **RECEIVER-VERIFY key:** `keyData = GetUDPVerifyKey(senderIP)(4) || randomKeyPart(2)`; `RC4 key = MD5`. Ties the packet to an anti-spoof token.

RC4 is set up with NO 1024-byte discard for UDP. Recognition: decrypt bytes 3..6 with a candidate key; if they equal the magic sync value it is a valid obfuscated packet.

**Verify keys (anti-spoof, distinct from obfuscation):** `GetUDPVerifyKey(targetIP) = a keyed hash MD5((uint64)s_dwKadUDPKey<<32 | targetIP)`, folded to a nonzero uint32. `s_dwKadUDPKey` is a persistent per-install secret, never transmitted. On SEND to X: receiverVerifyKey = the key X handed us (proves continuity); senderVerifyKey = OUR key for X's IP, expected echoed next time. On RECEIVE: `validReceiverKey = (our key for that IP == the receiverVerifyKey they sent)` proves they actually replied to our earlier packet - round-trip proof of IP ownership, which is what lets a contact pass routing-table IP verification. **Port-53 rule:** unencrypted packets from source port 53 are dropped; ver<=5 contacts on port 53 rejected everywhere.

**Anti-flood:** outgoing requests tracked 180s; a response is accepted only if a matching request to that IP is tracked. Per-IP-per-minute inbound limits (REQ 10, HELLO 3, SEARCH_* 3 each, PUBLISH_KEY 3, PUBLISH_SOURCE 2, PING 2, CALLBACK 1, ...); over 5x limit => ban the IP.

### 4.11 Kad2 key parameters

```
K = 10 (routing bin size)                    ALPHA_QUERY = 5 (this tree; classic Kad = 3; local, non-wire)
KBASE = 4, KK = 5, LOG_BASE_EXPONENT = 5     KADEMLIA_VERSION = 0x08 advertised (0.49b)
SEARCHTOLERANCE = 0x1000000 = 2^24: close-enough iff distance.Get32BitChunk(0) <= this (distance up to ~2^120)
REQ type byte = count/intent: FIND_VALUE=2, STORE=4, FIND_NODE=11
Keyword key = MD4(first lowercased UTF-8 word, >=3 bytes) -> SetValueBE; extra words = filter tree
Source/Notes key = file ed2k MD4 hash -> SetValueBE; source sourceID = clientHash, note sourceID = KadID
SOURCETYPE: 1=HighID, 3=FW(buddy), 4=HighID>4GB, 5=FW>4GB, 6=FW direct-UDP-callback
Republish: sources 5h, keywords+notes 24h
Index caps: MAXINDEX 50000, MAXENTRIES 60000, MAXSOURCEPERFILE 1000, MAXNOTESPERFILE 150
Search lifetimes(s): FILE/KEYWORD/NOTES/NODE=45, NODECOMP=10, STOREFILE/STOREKEYWORD=140,
                     STORENOTES/FINDBUDDY=100, FINDSOURCE=45; caps FILE/KEYWORD=300, NOTES=50, STORE*=10, FINDSOURCE=20
SEARCH_RES batches <=50/pkt; keyword cap 300, notes 150
CanSplit: level<127 && (zoneIndex<KK || level<KBASE) && binSize==K
MAX_CONTACTS_IP=1 (per exact IP), MAX_CONTACTS_SUBNET=10 (per /24 global), max 2 per /24 per bin
Obfuscation: MAGICVALUE_UDP_SYNC_CLIENT=0x395F2EC1, CRYPT_HEADER=8, Kad overhead 16B; RC4 key = MD5(keyData), no discard
Verify key = fold(MD5((uint64)s_dwKadUDPKey<<32 | targetIP)) nonzero uint32
Firewall: >=2 TCP connect-back = open (budget 4); UDP asks 2 nodes, 1 success=open, 6-min timeout=firewalled;
          EXTERNAL_PORT_ASKIPS=3 (2-of-3 PONG agreement)
Buddy target = CUInt128(true) ^ ourKadID; every ~20min while firewalled
Bootstrap: BOOTSTRAP_RES up to 20 spread contacts; self-lookup within 3min + every 4h enables publish;
           disconnect after 20min no contact
Wire: [0xE4 plain / 0xE5 zlib >200B][opcode][payload], LE; contact record 25B; tag = type1|nameLen2|name|value
Anti-flood: requests tracked 180s; per-IP/min caps (REQ 10, HELLO 3, SEARCH_* 3, PUBLISH_SRC 2, CALLBACK 1)
```

---

## Part 5 - Resolved Open Questions and padMule Recommendations

These are the byte-order and capability traps that will silently break interop if guessed wrong. Each has been resolved against the target source.

### 5.0 Canonical IP order (foundation for Q1/Q5/Q6)

aMule's internal IP uint32 is **network byte order stored so the FIRST octet is the LOW byte**: for `a.b.c.d`, `uint32 = a | b<<8 | c<<16 | d<<24`. Proof: `Uint32toStringIP` formats `(uint8)ip . (uint8)(ip>>8) . (uint8)(ip>>16) . (uint8)(ip>>24)`. Reading the 4 wire bytes `[a,b,c,d]` with a little-endian ReadUInt32 yields exactly this value, so a raw IPv4 on the wire needs **no swap** to become the connect IP.

**Recommendation:** keep ONE canonical IP representation (network order, first octet low). Swap only for human display. Do not carry an internal "hybrid" field.

### 5.1 Q1 - 4-byte client ID byte order (Hello + FOUNDSOURCES)

The wire always carries a HighID as the raw IPv4 in network order (first octet = lowest wire byte), and a LowID as a small integer < 16777216. The `wxUINT32_SWAP_ALWAYS` "hybrid" form is an **internal storage/display convention (byte-swapped IP), never on the wire.**

- Hello SEND: `WriteUInt32(theApp->GetID())`.
- Hello RECEIVE: read the raw LE uint32, then set IP from the real TCP peer, then (for every HighID peer) overwrite the internal hybrid = swap(real peer IP).
- OP_FOUNDSOURCES: `userid = ReadUInt32()` (LE), passed with `ed2kID=true`; HighID source -> `m_nConnectIP = in_userid` directly (no swap). A Kad source (`ed2kID=false`) -> `m_nConnectIP = swap(in_userid)`.

**Recommendation:** read/write the 4 ID bytes as a plain LE uint32. For a HighID peer, **ignore the Hello ID and trust the actual socket peer IP.** Do not replicate the hybrid swap on the wire.

> Note: `m_nUserIDHybrid` IS serialized to the wire once - in `OP_CALLBACKREQUEST` to the server. But for a LowID client hybrid == the LowID integer (no swap applied), so a plain WriteUInt32 sends exactly the LowID, which is correct. The plain-LE recommendation reproduces this.

### 5.2 Q2 - ED2Kv2 / VBT

aMule hard-codes `nValueBasedTypeTags = 0`, so its outgoing CT_EMULECOMPAT_OPTIONS never sets the VBT bit. ED2Kv2 OP_REQUESTPARTS (header 0xF4) is emitted ONLY when the *remote* peer's VBT flag is set; all tag writes use `GetVBTTags() ? 0 : 32` (standard type-widened encoding) whenever the peer lacks VBT.

**Recommendation:** NEVER advertise the VBT bit (bit 1 of CT_EMULECOMPAT_OPTIONS). Then no peer sends us ED2Kv2 and we always emit legacy OP_REQUESTPARTS and standard tags -> **do not implement the VarInt-tag ED2Kv2 path at all.** Safe: VBT is "Experimental, disabled" in eMule too; essentially no real peer sets it.

### 5.3 Q3 - Capability bit layout

**CT_EMULE_MISCOPTIONS1** (MSB->LSB): `[29..31] AICH ver(3b); [28] Unicode; [24..27] UDP ver(4b) -> m_byUDPVer; [20..23] data-comp ver(4b) -> m_byDataCompVer; [16..19] secure ident(4b) -> m_bySupportSecIdent; [12..15] source-exchange v1(4b); [8..11] ext-requests(4b) -> m_byExtendedRequestsVer; [4..7] accept-comment(4b); [3] peercache; [2] no-view-shared; [1] multipacket; [0] preview`. aMule sends `AICH=1, Unicode=1, UDPver=4, DataComp=1, SecIdent=3 if crypto else 0, SrcExch=3, ExtReq=2, Comment=1, MultiPacket=1, Preview=0`. Secure-ident encoding: `bit0(&1)=v1, bit1(&2)=v2`; send v1 unless only v2 available.

**CT_EMULE_MISCOPTIONS2:** `[12] direct UDP callback; [11] captcha; [10] SourceExchange2 (overrides SX1 version when set); [9] requires crypt; [8] requests crypt; [7] supports crypt; [5] ext multipacket; [4] large files/64-bit tags; [0..3] Kad version`.

**Recommendation:** parse both tags into these fields. Gate:

- **Compression on `m_byDataCompVer == 1`** (not `>= 1` - only version 1 is ever defined, so treat exactly 1 as capable).
- **UDP reask is NOT gated by `m_byUDPVer`.** The enable gate for OP_REASKFILEPING is `GetEffectiveUDPPort() != 0 && peer m_nUDPPort != 0 && !IsFirewalled() && !IsConnected()`. `m_byUDPVer` only selects the reask **payload format**: version > 3 appends our WritePartStatus; version > 2 appends the uint16 complete-sources count. (Same version thresholds on the answer side.)
- Extended-request extras on `m_byExtendedRequestsVer > 0` (append part status) and `> 1` (append complete-source count).
- Source exchange on `m_bySourceExchange1Ver > 0` but prefer SX2 when the SX2 bit is set.
- Secure ident when `m_bySupportSecIdent != 0` (send v1 by default).

Advertise the same values aMule does.

### 5.4 Q4 - Kad alpha, tolerance, keyword hash

- **ALPHA_QUERY = 5** in this tree (in-code comment says classic Kad = 3). Local search-parallelism only, no wire effect. **Recommendation:** use classic 3 for stock-compatible convergence, or 5 to mirror this tree exactly. Either is wire-compatible.
- **Tolerance:** `SEARCHTOLERANCE = 0x01000000 = 2^24`. Accept iff `distance.Get32BitChunk(0) (the MOST-significant 32 bits) <= SEARCHTOLERANCE`. The top ~8 bits of the 128-bit distance must be zero (distance up to **~2^120**), NOT `< 2^104`.

  > **Landmine:** the recon reference doc states "top 24 bits must be 0 (distance < 2^104)". That is WRONG. Follow this section, not the recon doc. Also include the LAN short-circuit: rejection is `Get32BitChunk(0) > SEARCHTOLERANCE && !IsLanIP(swap(ip))`.
- **Keyword hash:** (1) tokenize with the delimiter set `" ()[]{}<>,._-!?:;\/\""`; (2) keep tokens whose UTF-8 byte length >= 3, lowercase each; (3) for a SEARCH hash only the FIRST surviving word (remaining words become the boolean filter); for a PUBLISH hash each keyword separately; (4) MD4 the UTF-8 bytes of the word -> load via SetValueBE (big-endian into the 128-bit ID, per 4.2).

### 5.5 Q5 - GetPublicIP and verify-key byte order

`GetPublicIP()` returns, in **precedence order**: `m_dwPublicIP` if set (from server IDChange or OP_PUBLICIP_ANSWER, always HighID); else if Kad connected with an IP, `wxUINT32_SWAP_ALWAYS(kadIP)` (Kad m_ip is host order -> swap -> network order); else `ignorelocal ? 0 : m_localip`. **All outputs are in the same network/anti-host order as ed2k IPs.**

Related `GetID()` precedence (Q1): the **Kad-connected-and-NOT-firewalled branch is evaluated FIRST** ("we trust Kad above ED2K") and returns `ENDIAN_NTOHL(kadIP)`; only then the server-assigned ED2K id; then 1 if firewalled Kad; else 0. (Low impact since the Q1 recommendation is to trust the socket peer IP anyway.)

The ed2k UDP obfuscation RC4 key bakes `GetPublicIP()` on SEND (via `PokeUInt32`, the little-endian-normalizing poke - *not* the "raw" variant) vs the datagram source IP on RECEIVE. The Kad receiverVerifyKey RC4 key uses `GetUDPVerifyKey(datagram-source-ip)` on receive. All feed the uint32 IP through Poke/Peek, so on a little-endian host the bytes land in wire order regardless; on a big-endian host only `PokeUInt32` produces correct wire-order bytes.

**Recommendation:** keep one IP representation (network order). Set public IP from server IDChange (HighID) or `htonl(KadIP)`, feed it through the endian-normalizing poke (not a raw copy) into both the ed2k UDP RC4 key and the Kad verify-key MD5. On receive, key on the datagram source address in the same order. Keys only match when sender's advertised public IP == receiver's view of the datagram source.

### 5.6 Q6 - Ports and userhash markers

- **Client TCP listen:** `DEFAULT_TCP_PORT = 4662`. Confirmed.
- **Client extended UDP (Kad + client-to-client reask):** `DEFAULT_UDP_PORT = 4672`. Confirmed.
- **Our local server-query UDP socket binds to (our TCP port) + 3.** Confirmed - but this is OUR local bind, NOT the remote server's port.
- **Sending UDP to a REMOTE server:** destination = server's advertised TCP port **+ 4** (default `port_offset = 4`); the obfuscated server ping uses **+12**. So "server UDP = TCP+3" describes only our own socket, not where we send. **Send to +4, not +3.**
- **Userhash:** 16 random bytes with `byte[5] = 14` and `byte[14] = 111` forced, tagging it an eMule-type hash. Confirmed.

**Recommendation:** default TCP 4662, extended/Kad UDP 4672; bind the server-query UDP socket to (our TCP)+3; when querying a remote server via UDP, target `server_TCP + 4`. Generate the userhash as 16 random bytes then force `byte[5]=14, byte[14]=111`.

### 5.7 Consolidated padMule guidance

```
IP representation:  ONE canonical network-order uint32 (a|b<<8|c<<16|d<<24). No internal "hybrid" field.
                    Swap only for display; for HighID peers trust the socket peer IP, not the packet ID.
Client ID on wire:  plain LE uint32 (HighID = raw IPv4; LowID = int < 16777216).
ED2Kv2/VBT:         never advertise VBT bit -> never implement the VarInt-tag path.
Capability gating:  compression == DataCompVer 1; UDP reask gated by port/firewall/connection state
                    (version only picks payload format: >3 part status, >2 complete-sources count);
                    ExtReq >0 part status / >1 complete-source; SX prefer SX2 when advertised; SecIdent v1 default.
Kad IDs:            SetValueBE + four MSW-first LE dwords -> byte-reversed within each 32-bit word vs raw hash.
Kad alpha:          3 for stock behavior (5 mirrors this tree); wire-neutral.
Kad tolerance:      distance.Get32BitChunk(0) <= 0x1000000 (up to ~2^120), with the !IsLanIP short-circuit.
Kad crypt overhead: 16 bytes (payload starts at byte 16).
Server UDP dest:    remote server_TCP + 4 (obf +12); our own server-query socket binds TCP+3.
Ports:              TCP 4662, extended/Kad UDP 4672.
Userhash:           16 random bytes, force byte[5]=14, byte[14]=111.
Watch for:          the recon doc's two wrong figures (Kad tolerance 2^104, crypt overhead 12) - both are wrong;
                    use 2^120 and 16 as above.
```
