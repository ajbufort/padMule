# aMule Protocol + Format Reference (load-bearing constants)

Updated: 2026-07-12

Distilled from the full verified recon: `docs/raw/amule-upstream-reference-2026-07-12.md`
(1746 lines, 5 subsystems, all high-confidence, adversarially checked against
`amule-3.0.1/`). This entry is the quick index; the raw doc has field-by-field
layouts, opcode tables, and file:line cites. Go there before implementing any
subsystem.

## Global invariants

- eD2k AND Kad wire: ALL multi-byte scalars are LITTLE-ENDIAN
  (`CFileDataIO::Read/WriteUInt*`). EC protocol numbers are BIG-ENDIAN
  (network order); EC tag DATA payloads are raw big-endian, never
  number-encoded.
- Packet framing: 1 protocol byte (OP_EDONKEYPROT 0xE3 / OP_EMULEPROT 0xC5 /
  OP_PACKEDPROT 0xD4) + u32 size + u8 opcode + body. Packed = zlib body.
  Oversized packets are split.
- PARTSIZE = 9,728,000 bytes. BLOCKSIZE = EMBLOCKSIZE = 184,320 (180 KiB).
- eD2k part count = `floor(fileSize / PARTSIZE) + 1` (NOT ceil). A file of
  exactly N*PARTSIZE bytes has N+1 eD2k parts, the last empty. This drives MD4
  file-hash combination and the part-status bitfield. Get this wrong and every
  hash of an exact-multiple file mismatches.

## Hashing

- File hash = MD4 over each 9,728,000-byte part, then MD4 of the concatenated
  part hashes (single-part files: the part hash IS the file hash). The
  exact-multiple trailing-empty-part rule above applies.
- AICH = SHA-1 hash tree, 180 KiB blocks per part; master hash serialized in
  the hashset; used to repair a corrupt block. Full tree layout in raw doc.
- Rust crates: `md4` (file), `md-5` (EC auth), `sha1` (AICH).

## Ports + identity

- Defaults: TCP 4662, client/Kad UDP 4672, EC 4712; server UDP = TCP+3 (4665).
  Sanity: ECport != TCP, UDP != TCP+3; TCP capped <= 65532.
- User hash: 16 random bytes, then byte[5]=14, byte[14]=111 (aMule/eMule
  marker).

## Obfuscation + secure ident

- TCP: RC4 with drop-1024. MAGICVALUE_REQUESTER=0x22, MAGICVALUE_SERVER=0xCB,
  MAGICVALUE_SYNC=0x835E6FC4. Header-without-padding = 8 bytes.
- UDP: RC4 drop-0. MAGICVALUE_UDP=0x5B; kad UDP crypt overhead = 16 bytes
  (8 header + two 4-byte verify keys), ed2k UDP = 8. Receiver must try 3 keys
  (ed2k / kad-node-id / kad-recv-key); marker low-2-bits is only a hint.
- Secure ident: RSA PKCS#1 v1.5 SHA, 384-bit keys in cryptkey.dat (Crypto++
  DER). clients.met record = 119 bytes. DH handshake: 768-bit fixed prime,
  g=2, 128-bit exponent.
- Rust crates: `rc4` + manual 1024-byte discard (the crate does NOT drop);
  `rsa`+`pkcs1`/`der`; `num-bigint` or `crypto-bigint` for DH modpow.

## EC (External Connections)

- 8-byte header (u32 flags + u32 length, big-endian). Protocol version 0x0204.
  Per-packet zlib when body > 1024 and peer supports it. Tag tree: name field
  = `(tagName << 1) | hasChildrenBit`; length INCLUDES children. Auth =
  MD5-salt scheme (full formula in raw doc). Full opcode + tag-name tables in
  raw doc.

## Core lifecycle (to replicate in the Rust engine's scheduler)

- Core timer: 300 ms (daemon) / 100 ms (GUI). Per tick: process upload +
  download queues, calculate rates. Every 1 s: credits, clientlist,
  sharedfiles, Kad. Every 5 s: listensocket. Every 60 s: stats save. Every
  30 min: known.met. Every 13 min: clients.met.

## CRITICAL CAVEAT: this tree is a locally-modified aMule

The recon flagged (transfers-credits especially) that `amule-3.0.1/` here is a
locally MODIFIED tree, not pristine upstream: e.g. GetMaxSlots floor 20,
adaptive sub-packet size (datarate/8), zlib level 1, a global download token
bucket, >3-block request batching, async write/hash threads, ALPHA_QUERY=5 (vs
classic Kad 3). WIRE FORMATS are identical; POLICY/behavior may differ. Open
decision: does padMule match pristine aMule/eMule behavior or this tree's? See
the raw doc's per-subsystem "Open questions". Resolve per subsystem before
implementing, and diff against the pristine zip when it matters.

## Open questions (must resolve against source before implementing that piece)

The raw doc ends each subsystem with concrete open questions (32 total): eD2k
ID byte-order per field, ED2Kv2 VarInt tags (implement or never negotiate?),
AICH request/answer bodies, Kad ALPHA/search-id choices, cryptkey.dat exact DER
layout, EC per-field CEC_*_Tag child lists + RLE part/gap status, capability
negotiation bits, and byte-verifying every .met against a real sample. These
are the first tasks in each implementation wave.

## Related

- [[arch-upstream-amule]]
- [[ipados-constraints]]
- [[decisions-and-lessons]]
