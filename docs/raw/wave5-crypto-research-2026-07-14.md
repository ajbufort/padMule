# Wave 5 crypto research - obfuscation (TCP+UDP) + secure identification

Date: 2026-07-14
Method: 4 parallel source-grounded agents over eMule 0.50a (WIRE AUTHORITY) +
aMule 3.0.1 cross-ref, synthesised into one implementation-ready spec. Every
claim carries a file:line citation; spot-verified against source this session.
RAW - do not edit; corrections go in the wiki.

All spot-checks confirm the reports exactly (TCP achKeyData[21] layout at 318-327, encryption starts at byte 5 via nStartCryptFromByte, UDP achKeyData layouts 197-324, RSA CreateSignature buffer `keylen+4+ChIpLen` at 522, RSAKEYSIZE 384). Reconciled spec follows.

---

# padMule Wave 5 - Obfuscation + Secure Identification Implementation Spec

Wire authority: eMule 0.50a `srchybrid/`. aMule 3.0.1 is **byte-identical on the wire** for every item below; all divergences are internal-only and flagged inline. Spot-verified against source this session.

---

## A. TCP stream obfuscation (`EncryptedStreamSocket`)

### A.1 Constants (`EncryptedStreamSocket.cpp:101-106`)
| Name | Value | Role |
|---|---|---|
| `MAGICVALUE_REQUESTER` | `34` / 0x22 | keys requester->responder direction |
| `MAGICVALUE_SERVER` | `203` / 0xCB | keys responder->requester direction |
| `MAGICVALUE_SYNC` | `0x835E6FC4` | UInt32 **LE** on wire (bytes C4 6F 5E 83) |
| `DHAGREEMENT_A_BITS` | `128` | DH private exponent (server path only) |
| `PRIMESIZE_BYTES` | `96` | DH prime/g^x size (768-bit) |
| `ENM_OBFUSCATION` | `0x00` | only crypt method; both method bytes = 0 |
| RC4 discard | **1024 bytes** | TCP drops first 1024 keystream bytes (`bSkipDiscard=false`) |
| Plaintext markers | `0xE3, 0xD4, 0xC5` | OP_EDONKEYPROT, OP_PACKEDPROT, OP_EMULEPROT |

### A.2 Initiator handshake byte layout, client<->client (`:360-380`)
Built in `StartNegotiation(bOutgoing=true)`, state `ECS_PENDING`:
```
[0]        SemiRandomNotProtocolMarker   1        PLAINTEXT
[1..4]     RandomKeyPart (uint32 LE)     4        PLAINTEXT
[5..8]     MAGICVALUE_SYNC (uint32 LE)   4        RC4(sendkey)
[9]        EncryptionMethodsSupported=0  1        RC4(sendkey)
[10]       EncryptionMethodPreferred=0   1        RC4(sendkey)
[11]       PaddingLen (byPadding)        1        RC4(sendkey)
[12..]     RandomBytes                   PaddingLen  RC4(sendkey)
```
- **Encryption boundary = byte 5.** `SendNegotiatingData(..., nStartCryptFromByte=5)` (`:379`) copies `[0,5)` verbatim, RC4s from byte 5 (verified `:650-651`).
- `byPadding = cryptRandomGen.GenerateByte() % (GetCryptTCPPaddingLength()+1)` (`:370`), range 0..padlen. **eMule padlen default 128, aMule 254** (internal only; both cap 254, so wire range 0-254).
- **SemiRandomNotProtocolMarker** (`:706-729`): random byte, retried up to 128x until NOT in {0xE3,0xD4,0xC5}; fallback `0x01`. This is what makes the receiver's byte[0] test work.

### A.3 RC4 key derivation, client<->client (`:318-328` out / `:453-462` in) - VERIFIED
21-byte buffer `achKeyData[21]`:
```
[0..15]  target client's userhash (md4cpy, 16 bytes)
[16]     magic (34 or 203)
[17..20] RandomKeyPart (4 raw LE wire bytes)
```
`MD5(achKeyData,21)` -> 16-byte digest -> `RC4CreateKey(digest, 16)` -> **drop 1024 keystream bytes**.
- **Outgoing (initiator A):** hash = `pTargetClientHash`; Sendkey magic=34, Receivekey magic=203.
- **Incoming (responder B):** hash = `thePrefs.GetUserHash()` (OUR own hash = the initiator's target); roles swap - **Receivekey magic=34, Sendkey magic=203**.
- Invariant: magic 34 always keys requester->responder; magic 203 always keys responder->requester.

### A.4 RC4 primitive (`otherfunctions.cpp:3655-3703`)
Standard KSA over 16-byte key (nLen=16), then `RC4Crypt(NULL,NULL,1024,key)` discard unless skip. PRGA: `out[i] = in[i] ^ state[(state[X]+state[Y])&0xFF]`. aMule identical (`RC4Encrypt.cpp:116-141`).

### A.5 Receiver auto-detection (`:214-272`, state `ECS_UNKNOWN`)
Socket init: `m_StreamCryptState = IsClientCryptLayerSupported() ? ECS_UNKNOWN : ECS_NONE` (`:123`).
- byte[0] in {0xE3,0xD4,0xC5} -> `bNormalHeader=true` -> `ECS_NONE`, pass plaintext through. If `IsClientCryptLayerRequired()` reject with `ERR_ENCRYPTION_NOTALLOWED` **except** LowID/firewall-test conns unless strict (aMule strict hardcoded false).
- else -> `StartNegotiation(false)`, consume byte[0] (marker), begin `Negotiate(lpBuf+1, len-1)`.
- **No multi-key probing on TCP** (unlike UDP): reads 4 plaintext RandomKeyPart bytes (`ONS_BASIC_CLIENTA_RANDOMPART`), derives keys from OWN userhash + those bytes, decrypts next 4, checks == MAGICVALUE_SYNC (`:468-482`). Mismatch -> `ERR_ENCRYPTION`, disconnect.

### A.6 Responder reply + steady state
Responder reply (`:495-515`, `ECS_ENCRYPTING`): RC4(sendkey) `<SYNC 4><MethodSelected=0 1><PadLen 1><random PadLen>`. Note padding bytes here use `rand()` not crypto RNG (`:510`). Initiator 2nd leg (`:517-544`) decrypts + verifies sync/method==0.
Steady state: all bytes RC4'd in place both directions with two independent keys (`:273-276` recv, `:149-162` send). Stateful stream - each byte crosses keystream once.

### A.7 Client<->server DH path (`:381-407` / `:545-564`)
First client->server packet is **entirely plaintext**: `<SemiRandomMarker 1><g^a 96><PadLen 1><random PadLen>`, PadLen = `GenerateByte()%16` (0-15). DH: g=2, p=`dh768_p` (96-byte BE literal `:107-116`), private exponent 128-bit, `g^a mod p` BE-encoded to 96 bytes. Key buffer = `<sharedSecret 96><magic 1>` (97 bytes), MD5->RC4. This path is only used for obfuscated server connections (`SetConnectionEncryption(true, NULL, true)`).

---

## B. UDP datagram obfuscation (`EncryptedDatagramSocket`)

### B.1 Constants (`EncryptedDatagramSocket.cpp:132-137`) - VERIFIED
| Name | Value |
|---|---|
| `CRYPT_HEADER_WITHOUTPADDING` | `8` |
| `MAGICVALUE_UDP` | `91` / 0x5B |
| `MAGICVALUE_UDP_SYNC_CLIENT` | `0x395F2EC1` (client + all Kad) |
| `MAGICVALUE_UDP_SYNC_SERVER` | `0x13EF24D5` (server only) |
| `MAGICVALUE_UDP_SERVERCLIENT` | `0xA5` (server->client key marker) |
| `MAGICVALUE_UDP_CLIENTSERVER` | `0x6B` (client->server key marker) |
| RC4 discard | **NONE** - `RC4CreateKey(...,true)` skip-discard; keystream from byte 0 |

### B.2 Packet layout (`EncryptSendClient :363-379`; header len `:289`)
```
[0]        SemiRandomNotProtocolMarker  1     PLAINTEXT (marker bits, B.4)
[1..2]     nRandomKeyPart (uint16 LE)   2     PLAINTEXT
[3..6]     sync magic (uint32 LE)       4     RC4
[7]        byPadLen                     1     RC4 (always 0 on send)
[8..]      padding                      padLen RC4 (0 currently)
--- Kad only ---
[+0..3]    nReceiverVerifyKey (u32 LE)  4     RC4
[+4..7]    nSenderVerifyKey   (u32 LE)  4     RC4
--- payload ---
[hdrlen..] payload                            RC4
```
`nCryptHeaderLen = byPadLen + 8 + (bKad ? 8 : 0)`. **Overhead: ed2k/server = 8, Kad = 16.** First 3 plaintext bytes consume NO keystream; RC4 is continuous from byte 3 onward.
Server path uses `MAGICVALUE_UDP_SYNC_SERVER`; client AND Kad both use `_SYNC_CLIENT`.

### B.3 Key derivation - VERIFIED (`:197-324`)
All: MD5 of buffer -> `RC4CreateKey(digest,16,skip=true)`.

**ed2k client** `achKeyData[23]`:
```
[0..15]  userhash (recv: OUR GetUserHash; send: target's hash)
[16..19] IP (recv: sender dwIP; send: our GetPublicIP), raw 4 bytes host LE
[20]     MAGICVALUE_UDP (91)
[21..22] nRandomKeyPart (recv: bufIn[1..2]; send: fresh random)
```
**Kad NodeID key** `achKeyData[18]`:
```
[0..15]  KadID (recv: OUR GetKadID; send: target node's KadID)
[16..17] nRandomKeyPart
```
**Kad ReceiverKey/verify** `achKeyData[6]`:
```
[0..3]   VerifyKey u32 (recv: GetUDPVerifyKey(dwIP); send: nReceiverVerifyKey)
[4..5]   nRandomKeyPart
```
**Server** `achKeyData[7]`:
```
[0..3]   dwBaseKey u32 (per-server, negotiated over TCP)
[4]      recv: 0xA5 (SERVERCLIENT); send: 0x6B (CLIENTSERVER)
[5..6]   nRandomKeyPart
```

### B.4 Marker byte + receiver trial (`:163-231`)
Plaintext bypass if `bufIn[0]` in {0xC5 OP_EMULEPROT, 0xE5 KADPACKEDPROT, 0xE4 KADHEADER, 0xA3 RESERVED1, 0xB2 RESERVED2, 0xD4 PACKEDPROT} (server path: only 0xE3), OR `nBufLen <= 8`.
Marker bits: bit0 = ed2k(1)/Kad(0); bit1 = Kad NodeID(0)/ReceiverKey(1). Hints only.
Trial: `byCurrentTry = ((bufIn[0]&3)==3)?1:(bufIn[0]&3)`. If Kad prefs uninit -> 1 try forced `byCurrentTry=1` (ed2k). Else up to 3 tries, `byCurrentTry=(byCurrentTry+1)%3`. Each: build key material, RC4-decrypt [3..6], compare `_SYNC_CLIENT`. Loop `while(dwValue != SYNC && byTries>0)`. Exhausted -> plaintext passthrough.

### B.5 GetUDPVerifyKey (`kademlia/kademlia/Prefs.cpp:430-435`)
```
buf64 = (GetKadUDPKey() << 32) | dwTargetIP;   // 8 bytes LE layout
md5 = MD5(&buf64, 8);
return ((u32[0] ^ u32[1] ^ u32[2] ^ u32[3]) % 0xFFFFFFFE) + 1;  // range [1..0xFFFFFFFF]
```
Anti-spoof: key WE assign to a remote IP; remote echoes it as senderVerifyKey proving IP control.

### B.6 Padding
Sender always `byPadLen=0`. Server-recv masks `byPadLen &= 15` (0-15); client-recv reads full byte, validates `nResult > byPadLen`.

### B.7 Endianness (aMule proves via explicit ENDIAN_SWAP)
`nRandomKeyPart`, sync magic, padLen, verify keys, IP, BaseKey - all **little-endian** on wire. Rust must treat them as LE.

---

## C. Secure identification (RSA)

### C.1 Crypto primitives - VERIFIED
- `RSAKEYSIZE = 384` bits (`opcodes.h:94`). Signature = **48 bytes** fixed.
- Primitive: Crypto++ `RSASSA_PKCS1v15_SHA_Signer/Verifier` = RSA + PKCS#1 v1.5 + **SHA-1**.
- `MAXPUBKEYSIZE = 80` (`ClientCredits.h:29`); DER public key ~59-60 bytes.

### C.2 cryptkey.dat (`ClientCredits.cpp:448-489`)
- Store: `InvertibleRSAFunction` (full private key n,e,d,p,q,dp,dq,u) **DER-encoded then Base64-encoded**, raw to file. No header/length prefix - whole file is Base64 text.
- Load: `FileSource("cryptkey.dat", true, Base64Decoder)` -> `RSASSA_PKCS1v15_SHA_Signer`. Empty/absent -> regenerate.
- Public key **derived at load** (not stored): `RSASSA_PKCS1v15_SHA_Verifier pubkey(*signkey); pubkey.DEREncode(ArraySink(m_abyMyPublicKey,80))`. On-wire pubkey = DER encoding of (n,e).

### C.3 Packets (proto byte = `OP_EMULEPROT` 0xC5)
**OP_PUBLICKEY = 0x85** (`SendPublicKeyPacket :2024-2042`):
```
[0]     pubkey len (uint8)
[1..]   DER pubkey bytes
```
Recv validity: `pachPacket[0]==nSize-1 && nSize>=10 && nSize<=250`. `SetSecureIdent` rejects if >80 or key already stored (**pubkey immutable once set**).

**OP_SECIDENTSTATE = 0x87**, fixed 5-byte body (`SendSecIdentStatePacket :2198-2227`):
```
[0]     state (1=IS_SIGNATURENEEDED, 2=IS_KEYANDSIGNEEDED)
[1..4]  dwRandom (uint32 LE), = rand()+1, stored m_dwCryptRndChallengeFor (challenge WE issue)
```
Recv stores `m_dwCryptRndChallengeFrom = PeekUInt32(+1)` (challenge peer wants us to sign).

**OP_SIGNATURE = 0x86** (`SendSignaturePacket :2044-2100`):
```
[0]        siglen (uint8, =48)
[1..48]    signature
[49]       byChaIPKind    (v2 only)
```

### C.4 EXACTLY the signed bytes (`CreateSignature :491-533`) - VERIFIED `abyBuffer[MAXPUBKEYSIZE+9]`, sign len `keylen+4+ChIpLen`
Signer's buffer:
```
[0 .. keylen-1]      TARGET peer's pubkey (pTarget->GetSecureIdent()); keylen=GetSecIDKeyLen()
[keylen .. +3]       PokeUInt32(m_dwCryptRndChallengeFrom)  (challenge peer sent US, LE, non-zero)
--- v2 only (byChaIPKind != 0), +5 bytes ---
[keylen+4 .. +7]     PokeUInt32(ChallengeIP)
[keylen+8]           PokeUInt8(byChaIPKind)
```
`SignMessage(rng, abyBuffer, keylen+4+ChIpLen, sig)` where ChIpLen = 0 (v1) or 5 (v2).
**You sign the OTHER client's pubkey, not your own.**

Verifier (`VerifyIdent :535-599`) rebuilds from ITS perspective:
```
[0 .. m_nMyPublicKeyLen-1]   OUR OWN pubkey (m_abyMyPublicKey)
[.. +3]                      PokeUInt32(m_dwCryptRndChallengeFor)  (challenge WE issued)
v2: [+4..+7] ChallengeIP, [+8] byChaIPKind
```
`pubkey.VerifyMessage(abyBuffer, m_nMyPublicKeyLen+4+nChIpSize, sig, siglen)` using peer's pubkey.

**byChaIPKind (v2 CRYPT_CIP, `ClientCredits.h:31-33`):** REMOTECLIENT=10, LOCALCLIENT=20, NONECLIENT=30. Sender: own ID unknown/LowID -> remote's IP + kind 10; else own HighID + kind 20. Verifier resolves by kind: 20->dwForIP; 10->own ClientID (or LocalIP if LowID); 30->0. ChallengeIP serialized as-stored via PokeUInt32 LE (no extra byte-swap).

### C.5 Support advertisement - `CT_EMULE_MISCOPTIONS1` bits 16-19
`m_bySupportSecIdent` = `(temptag.GetInt()>>16)&0x0f`. We advertise **3** (bit0=v1, bit1=v2) when `CryptoAvailable()` (`m_nMyPublicKeyLen>0 && signkey && IsSecureIdentEnabled()`), else 0. `SendSignaturePacket`: v1 unless only v2 offered (`if((m_bySupportSecIdent&1)==1) bUseV2=false`). `ProcessSignaturePacket` reads trailing IP-kind byte only if `(m_bySupportSecIdent&2)>0`.

### C.6 State machine + credit tie-in
Enums: sender `IS_UNAVAILABLE/ALLREQUESTSSEND=0, IS_SIGNATURENEEDED=1, IS_KEYANDSIGNEEDED=2` (`ClientStateDefs.h:96`). Credit `EIdentState: IS_NOTAVAILABLE=0, IS_IDNEEDED=1, IS_IDENTIFIED=2, IS_IDFAILED=3, IS_IDBADGUY=4`.
- Trigger `InfoPacketsReceived()` when both hello+extinfo received AND peer advertised secident -> `SendSecIdentStatePacket()`.
- State decision: no peer pubkey -> send state 2 (KEYANDSIGNEEDED); else `m_dwLastSignatureIP != GetIP()` -> state 1 (SIGNATURENEEDED); else nothing. Issues `m_dwCryptRndChallengeFor`.
- Peer: state 2 -> sends OP_PUBLICKEY (transitions to SIGNATURENEEDED) then OP_SIGNATURE; state 1 -> OP_SIGNATURE directly.
- `ProcessSignaturePacket` guards: reject if already verified this IP, no stored pubkey, or `m_dwCryptRndChallengeFor==0`. Then `VerifyIdent`.
- Success -> `Verified(dwForIP)`: `m_dwIdentIP=dwForIP`, IdentState=IS_IDENTIFIED. **First-time key persist:** if `nKeySize==0`, copy pubkey into CreditStruct; if record had downloaded>0, **wipe credits** (Downloaded/Uploaded reset Hi=0/Lo=1) to block stolen-hash credit theft.
- `GetCurrentIdentState(dwForIP)`: IS_IDENTIFIED only if `dwForIP==m_dwIdentIP`, else **IS_IDBADGUY** (hash replayed from another IP). `HasPassedSecureIdent` passes on IS_IDENTIFIED (checked vs GetConnectIP).
- Credit coupling: `GetSecureWaitStartTime` - SecureHash client (nKeySize!=0) that is IS_IDENTIFIED for this IP keeps real `m_dwSecureWaitTime`; else wait time reset (loses queue position). Credit lookup key = 16-byte userhash.

### C.7 Dispatch
eMule `ListenSocket.cpp:1415/1431/1440`. aMule: dispatch in `ClientTCPSocket.cpp`, Process* methods on `CUpDownClient` in `BaseClient.cpp`. aMule impl in `ClientCreditsList.cpp` (CreateSignature :329-374, VerifyIdent :376-430, keygen/load :248-320) - every offset identical; only cosmetic diff (signer handle typed `void*` and cast).

---

## D. Negotiation / gating

### D.1 Local prefs (nested accessors, aMule `Preferences.h:617-619`)
`Required => Requested => Supported`. `IsClientCryptLayerRequested() = Supported && s_bCryptLayerRequested`; `IsClientCryptLayerRequired() = Requested && s_IsClientCryptLayerRequired`.
**aMule/amuled defaults (`Preferences.cpp:1371-1373`): Supported=true, Requested=true, Required=false.**

### D.2 CT_EMULE_MISCOPTIONS2 bits (hello) - `BaseClient.cpp:530-560`/`1085-1110`
bit9=RequiresCryptLayer, bit8=RequestsCryptLayer, bit7=SupportsCryptLayer (also: 13=FileIdent, 12=DirectUDPCallback, 11=Captcha, 10=SourceEx2, 5=ExtMultiPacket, 4=LargeFiles, 3..0=KadVersion).
Write: `Supported?1:0 <<7`, `Requested?1:0 <<8`, `Required?1:0 <<9`.
**Read MUST sanitize peer's claim (`:558-559`):** `m_fRequestsCryptLayer &= m_fSupportsCryptLayer; m_fRequiresCryptLayer &= m_fRequestsCryptLayer;`

### D.3 Crypt-options byte (source-exchange v4, server sources, callback)
bit0=Supported, bit1=Requested, bit2=Required, bit3=DirectUDPCallback; bit7 (0x80) = userhash-present flag (server found-sources only).
Write SXv4 (`PartFile.cpp:4310`): `(Required<<2)|(Requested<<1)|(Supported<<0)`.
`SetConnectOptions` decode (`BaseClient.cpp:3187-3193`): each crypt bit ANDed with `bEncryption` param (must be true to take effect); bit3 ANDed with `bCallback`.

### D.4 Outgoing obfuscate decision
**Gate A - hard reject** (`TryToConnect`, `:1437-1447`):
```
if ((RequiresCryptLayer() && !thePrefs.IsClientCryptLayerSupported())
 || (thePrefs.IsClientCryptLayerRequired() && !SupportsCryptLayer())) -> disconnect
```
**Gate B - enable obf** (`Connect()`, `:1647-1651`):
```
if (HasValidHash() && SupportsCryptLayer() && thePrefs.IsClientCryptLayerSupported()
    && (RequestsCryptLayer() || thePrefs.IsClientCryptLayerRequested()))
    socket->SetConnectionEncryption(true, GetUserHash(), false);
else socket->SetConnectionEncryption(false, NULL, false);
```
(`SupportsCryptLayer()`/`RequestsCryptLayer()` = peer's masked bits; `thePrefs.*` = ours.)

### D.5 Incoming: accept both. Required-but-not-strict still answers LowID/firewall-test in plaintext; aMule strict hardcoded false (`Preferences.h:620`). Merely-Supported accepts all plaintext unconditionally.

### D.6 Server-connect (`ServerSocket.cpp:693-703`)
```
if (!bNoCrypt && IsServerCryptLayerTCPRequested() && server->GetObfuscationPortTCP()!=0
    && server->SupportsObfuscationTCP()) { nPort=ObfPort; SetConnectionEncryption(true,NULL,true); }  // DH path
else { nPort=server->GetPort(); SetConnectionEncryption(false,NULL,true); }
```
Obfuscated server TCP uses a **separate port**. `SRV_TCPFLG_TCPOBFUSCATION=0x400`. Key = DH-negotiated (A.7), NOT userhash.

### D.7 padMule policy - CONFIRMED interoperable
Advertise **Supported=1, Requested=1, Required=0** = exact amuled default. Consequences: Gate A never rejects on our side; Gate B obfuscates to every crypt-capable peer whose hash we hold; incoming plaintext accepted unconditionally, obfuscated auto-detected by byte[0]. No open incompatibilities.

---

## E. padMule slice plan

**5a - TCP stream obfuscation**
Scope: `EncryptedStreamSocket` equivalent - initiator + responder client<->client handshake (A.2/A.3/A.5/A.6), RC4 primitive with 1024-discard (A.4), byte[0] auto-detect. Defer DH server path (A.7) to 5d/optional.
Checkpoint: (1) unit: MD5(userhash||magic||rand) key vectors match a captured eMule handshake or a golden vector; RC4 KSA+1024-discard produces known keystream. (2) Differential: run padMule initiator against real amuled listener with obfuscation forced; confirm ECS_ENCRYPTING reached and a real payload (hello) decodes. (3) Reverse: amuled initiates to padMule listener.

**5b - UDP datagram obfuscation**
Scope: `EncryptedDatagramSocket` - ed2k client key (B.3), 8-byte header, marker+3-way trial (B.4), no-discard RC4. Kad keys (NodeID/ReceiverKey, 16-byte overhead) + GetUDPVerifyKey (B.5) included since Kad UDP is padMule's DHT transport.
Checkpoint: (1) unit: each of the 4 key-material buffers -> MD5 -> sync-magic round-trips (encrypt then decrypt-trial recovers SYNC). (2) Differential: padMule sends obfuscated ed2k UDP to amuled, amuled sends obfuscated Kad response back, both decode. (3) VerifyKey echo: confirm senderVerifyKey we assign is echoed and validates.

**5c - secure identification**
Scope: cryptkey.dat gen/load (DER+Base64, C.2), OP_PUBLICKEY/SECIDENTSTATE/SIGNATURE (C.3), exact signed buffer (C.4), state machine + credit tie-in (C.6), MISCOPTIONS1 advertise=3 (C.5). Needs a Rust RSA-PKCS1v15-SHA1 lib (e.g. `rsa` + `sha1`) that can consume Crypto++ DER keys.
Checkpoint: (1) unit: sign our buffer, verify with derived pubkey; cross-verify a signature produced by real eMule/aMule against our verifier (and vice versa) - this is the critical interop gate. (2) Differential: full handshake with amuled -> observe IdentState=IS_IDENTIFIED bound to correct IP; force IP mismatch -> IS_IDBADGUY. (3) Credit-wipe path on first-time key persist.

**5d - wiring + differential gate**
Scope: negotiation bits (D.2/D.3), Gate A/B decisions (D.4), incoming accept-both (D.5), policy Supported/Requested/Required=1/1/0 (D.7). Optional: DH server-connect path (A.7/D.6). Wire obfuscation selection into the existing Wave 4c transfer path.
Checkpoint: (1) end-to-end padMule<->amuled file transfer with obfuscation negotiated automatically (no forcing). (2) Matrix test: {plaintext-only peer, support-both peer, require peer} x {our support/require} - confirm Gate A/B outcomes match the boolean table. (3) MISCOPTIONS2 sanitize-mask test (peer sends Requires-without-Supports -> downgraded to nothing).

---

## Divergences + UNSURE

**eMule-vs-aMule wire divergences: NONE.** All four modules byte-identical. Internal-only: TCP padding default (eMule 128 / aMule 254, both cap 254, no wire effect); aMule uses `CRC4EncryptableBuffer` vs bare `RC4_Key_Struct*`; aMule adds explicit ENDIAN_SWAP (x86-portability, same bytes); aMule secident split into `ClientCreditsList.cpp/.h` with `void*` signer handle.

**UNSURE / needs code spike:**
1. **DER interop of cryptkey.dat with Rust `rsa` crate** - Crypto++ `InvertibleRSAFunction::DEREncode` field ordering vs `rsa::pkcs1`/`pkcs8`. The public-key DER (RSAPublicKey n,e) is the load-bearing interop surface (it is what gets signed). Spike: generate a key in aMule, load in Rust, confirm byte-identical DER re-encode and a cross-verified signature. HIGH priority - gates 5c.
2. **Server BaseKey (`dwBaseKey`) origin** - reports state "per-server, negotiated over TCP" but the exact TCP packet that carries it was not re-derived here. Only needed if padMule does obfuscated server UDP; defer unless server-obf is in scope.
3. **DH server-path RC4 direction magic** - server path key buffer is `<secret 96><magic 1>` with magic 34/203 swapped by role, but which side is "requester" on a client->server DH connect was inferred, not line-verified. Spike only if implementing A.7.
4. **`rand()` vs crypto RNG for responder padding** (`:510`) - cosmetic (padding is discarded), but replicate as non-crypto rand only if bit-exact fuzz matching is desired; irrelevant to interop.