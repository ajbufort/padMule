# Wave 4d upstream research - upload, credits, source exchange, part files

Date: 2026-07-14
Method: 4 parallel source-grounded agents over `amule-3.0.1/src` (primary) with
`refs/emule-0.50a` as the canonical-eMule oracle. Every claim carries a
file:line citation in the agent transcripts; the load-bearing facts are distilled
here. RAW - do not edit; corrections go in the wiki.

Path keys: `A/` = amule-3.0.1/src, `E/` = refs/emule-0.50a/.../srchybrid.

---

## 0. BUGS IN aMULE 3.0.1 - DO NOT REPLICATE

These are genuine upstream defects found while extracting the algorithms. Per
the replicate-then-improve rule, faithful replication here would be *wrong*.
Each is a deliberate, documented divergence for padMule.

1. **Exactly-PARTSIZE single-part file is permanently "corrupt".**
   `A/PartFile.cpp:2512` compares the part MD4 against `m_abyFileHash` when
   `GetPartCount() == 1`. But for a file of exactly 9,728,000 bytes the hashset
   has TWO entries (`h0` + the empty-MD4 `31D6CFE0D16AE931B73C59D7E0C089C0`) and
   `m_abyFileHash = MD4(h0 || h_empty) != h0` -> the part never verifies.
   eMule guards it: `if (GetPartCount() > 1 || GetFileSize() == PARTSIZE)` use
   the part hash (`E/PartFile.cpp:3652`). **Use eMule's condition.** This is the
   same exact-multiple edge case our `part_count()` already handles in Wave 1.

2. **aMule cannot receive a standalone `OP_REQUESTSOURCES2`** - it throws and
   disconnects (`A/ClientTCPSocket.cpp:1399-1416`). Two defects: (a) it checks
   `size != 16` but an SX2 request is **19** bytes, so it always throws (the
   throw message even says "OP_QUEUERANKING" - a copy-paste tell); (b) it then
   reads the hash at offset 0 instead of offset 3. Still unfixed in amule-master.
   **Use `size >= 16` (SX1) / `size >= 19` (SX2) and read the hash at the cursor.**

3. **SX record ID byte order is gated on the wrong version variable.**
   `A/PartFile.cpp:2867` gates on the peer's *SX1* version while writing a record
   of version `byUsedVersion` (usually 4). aMule's own `CKnownFile` and eMule
   both gate on `byUsedVersion` (`A/KnownFile.cpp:1104`, `E/PartFile.cpp:4292`).
   Failure mode: source IPs arrive byte-reversed. **Gate on `byUsedVersion`.**

4. **`AddSources` OBFU skip path is misaligned** - hardcodes `count*(4+2)`,
   ignoring the per-record crypt byte and optional 16-byte userhash
   (`A/PartFile.cpp:1789, 1844`). Inert today only because the buffer is
   discarded. **Size the skip from the real record layout.**

5. **ICH (Intelligent Corruption Handling) is dead code in 3.0.1** - the only
   enqueue path does `if (!IsComplete(partNumber)) continue;` before
   `QueueHashCheck`, so the incomplete-but-corrupt branch is unreachable.
   Do not "faithfully" replicate a dead path.

6. **Header-comment lies (the code is right, the comments are wrong):**
   - OBFU found-sources userhash flag is **0x80**, not `0x08` as
     `A/.../TCP.h:61` claims (code: `A/PartFile.cpp:1800`, eMule agrees).
   - `OP_REQUESTSOURCES2` is **version-first** (`<ver u8><opts u16><hash 16>`),
     not hash-first as `E/opcodes.h:255` claims (both senders prove it).

7. **500 vs 501 sources.** The emit loop breaks *after* writing
   (`if (nCount > 500) break;`), so up to **501** records go out
   (`A/PartFile.cpp:2894`). eMule sizes its buffer for 501 too. Emit and accept
   up to 501, not 500.

---

## 1. clients.met + credits

### File format (version 0x12) - BYTE EXACT

`CREDITFILE_VERSION = 0x12` (`A/include/common/DataFileVersion.h:40`).
`MAXPUBKEYSIZE = 80`. Fixed-width records - NOT tag-based. All ints LE.

Header (5 bytes): `u8 version(0x12)` + `u32 count`.
Then `count` records of **exactly 119 bytes**:

| off | size | field |
|-----|------|-------|
| 0   | 16   | userhash (raw MD4) |
| 16  | 4    | uploaded **LOW** dword |
| 20  | 4    | downloaded **LOW** dword |
| 24  | 4    | last_seen (unix secs) |
| 28  | 4    | uploaded **HIGH** dword |
| 32  | 4    | downloaded **HIGH** dword |
| 36  | 2    | reserved (always 0) |
| 38  | 1    | key_size (0..80) |
| 39  | 80   | secure_ident public key (always full 80 bytes) |

**THE TRAP: the 64-bit halves are NOT adjacent.** `last_seen` sits *between* the
low dwords and the high dwords - a v0x11 backwards-compat artifact. Field order
is `up_lo, down_lo, last_seen, up_hi, down_hi`
(`A/ClientCreditsList.cpp:125-133`, write at `:196-205`).

Save rules: skip entries where `uploaded == 0 && downloaded == 0`; backfill the
count at offset 1 after writing. Load rules: reject version != 0x12 (aMule cannot
read eMule's legacy 0x11); **`key_size > 80` -> discard the ENTIRE list**; drop
records with `last_seen < now - 12_960_000` (**150 days**). Autosave every 13 min.
Record order is map order - NOT part of the format contract.

### Credit formula (`A/ClientCredits.cpp:121-161`)

```
if ident is IDFAILED/IDBADGUY/IDNEEDED and crypto_available -> 1.0
if downloaded < 1_000_000            -> 1.0        // decimal MB, NOT 1 MiB
r1 = (uploaded == 0) ? 10.0 : (downloaded * 2.0) / uploaded
r2 = sqrt(downloaded / 1_048_576.0 + 2.0)          // this one IS MiB
result = clamp(min(r1, r2), 1.0, 10.0)
```

Totals are raw byte counts (no scaling/decay). eMule differs (1 MiB threshold +
a third linear cap `r3`) -> aMule awards a higher ratio in the 1..9.6 MB band.
Local policy, wire-invisible. **Replicate aMule's version** (we are an aMule port).

### Secure ident can be deferred safely (Wave 5)

With no RSA identity, `crypto_available == false`, so every ident branch is a
pass-through and **credits work fully**. A peer with `key_size == 0` maps to
`IS_NOTAVAILABLE`, which is explicitly *not* penalised - unidentified peers get
the normal computed ratio, not 1.0. Write `key_size = 0` + 80 zero bytes; a real
aMule reads that file fine. Only real loss: userhash spoofing. Note for Wave 5:
on first successful verification aMule **resets both totals to 1** if credits
were accrued pre-key ("Credits deleted due to new SecureIdent").

---

## 2. Upload queue, slots, scoring

### Score (`A/UploadClient.cpp:75-148`) - one score; the RANK is separate

Short-circuits: no username / no credits / no upload file / bad guy -> 0;
**friend-with-friend-slot (not LowID) -> 0x0FFFFFFF**; banned -> 0;
**already downloading -> 0** (aMule never kicks by score; eMule does).

```
base  = (now_ms - wait_start_ms) / 1000.0     // seconds waiting
base *= score_ratio                            // credits, 1.0..10.0
base *= file_priority_multiplier
if (peer is old eMule <= 0x19) base *= 0.5
score = (u32) base
```

`wait_start` is **persisted per userhash in clients.met**, so the wait clock
survives disconnects.

Priority multipliers (`A/UploadClient.cpp:120-142`): POWERSHARE(6) **250.0**,
VERYHIGH(3) 1.8, HIGH(2) 0.9, NORMAL(1) 0.7, LOW(0) 0.6, VERY_LOW(4) 0.2.
(POWERSHARE is aMule-only; eMule's integer /10 values are numerically identical
for the rest.)

### Slots (`A/UploadQueue.cpp:304-333`)

```
per_slot = slot_allocation_kBps            // pref, default 10, min 1
if (max_upload == UNLIMITED /* 0 */) {
    N_FLOOR = 20
    slots = max((measured_up_kBps / per_slot) + 2, N_FLOOR)
} else if (max_upload >= 10) {
    slots = round(max_upload / per_slot)
    slots = max(slots, MIN_UP_CLIENTS_ALLOWED)
} else slots = MIN_UP_CLIENTS_ALLOWED
slots = min(slots, MAX_UP_CLIENTS_ALLOWED)
```
`MIN_UP_CLIENTS_ALLOWED = 2`, `MAX_UP_CLIENTS_ALLOWED = 250` (eMule: 100).

Open at most **one slot per 1000 ms**. Re-sort the waiting list every 120 s.
Queue cap = `queue_size * 100`, default **5000** waiting clients; over cap the
TCP request is dropped **silently** (no packet). A LowID client can push the slot
count **one over** the max when it reconnects.

Session limits (`A/UploadQueue.cpp:571-609`): kick when
`upload_time > 3_600_000 ms (1 h)` OR `session_up > 10_485_760 (10 MiB)`.
Friends are never dropped. At most one kick per Process() cycle.
(eMule uses `PARTSIZE + 20 KiB = 9_748_480` *payload* - a wire-visible difference
in when the peer gets bounced.)

Dead-queue purge: drop a waiting client after `MAX_PURGEQUEUETIME = 1 h` of no
re-ask. Aggressive-reask ban: re-asking sooner than `MIN_REQUESTTIME = 590_000 ms`
adds +3 to aggressiveness; at >= 10 -> ban for 2 h.

### Wire (all confirmed byte-compatible with eMule)

- **`OP_QUEUERANKING` = 0x60, proto 0xC5 (EMULE), payload exactly 12 bytes:
  `u16 rank (LE, 1-BASED)` + 10 zero bytes.** Rank 0 = not queued and is NEVER
  sent. **Not on a timer** in either client - it is sent only on queue insertion
  and on each re-ask (TCP `OP_STARTUPLOADREQ` or UDP `OP_REASKFILEPING`).
  Receiver enforces size == 12.
- `OP_ACCEPTUPLOADREQ` = 0x55, proto 0xE3, **zero-length**.
- `OP_OUTOFPARTREQS` = 0x57, proto 0xE3, **zero-length** - sent when a slot is
  revoked, immediately followed by re-queueing (so a fresh QUEUERANKING follows).
- `OP_FILEREQANSNOFIL` = 0x48, proto 0xE3, payload = **16-byte hash**. NOTE the
  asymmetry: only `OP_SETREQFILEID` and the multipackets answer with it;
  `OP_REQUESTFILENAME` and `OP_STARTUPLOADREQ` for an unknown file send
  **nothing at all**.
- `OP_QUEUEFULL` = 0x93 - **UDP re-ask path only**, never in reply to a TCP
  `OP_STARTUPLOADREQ`.
- Uploader rejects a block request if `end - start > EMBLOCKSIZE*3` (552960),
  `start >= end`, or `end > filesize`.

### Sending part data (WIRE-VISIBLE aMule divergence)

`OP_SENDINGPART` 0x46 (0xE3) / `_I64` 0xA2 (0xC5):
`<hash 16><start u32|u64><end u32|u64><data>`.
`OP_COMPRESSEDPART` 0x40 / `_I64` 0xA1 (both 0xC5):
`<hash 16><start u32|u64><newsize u32><compressed fragment>` where `newsize` is
the **total** compressed length of the whole block, repeated in every fragment.

- **Fragment size is ADAPTIVE in aMule 3.0.1**:
  `chunk = clamp(upload_datarate / 8, 10240, EMBLOCKSIZE)`. Classic eMule uses a
  **fixed 10240**. Protocol-legal either way (receiver reassembles by offset),
  but a receiver must NOT assume ~10 KB fragments.
- zlib level **1** (not 9). Never compress already-compressed file types
  (ftArchive). Only to peers advertising `data_comp_ver == 1`.

---

## 3. Source exchange + get-sources

### IP byte order - the thing that is easiest to get wrong

All ints are LE. A u32 read LE from wire bytes `b0 b1 b2 b3`:

| Source | order | wire bytes mean |
|--------|-------|-----------------|
| Server `OP_FOUNDSOURCES` | ed2k | IP `b0.b1.b2.b3` (**no swap**) |
| SX record **v1 / v2** | ed2k | IP `b0.b1.b2.b3` (**no swap**) |
| SX record **v3 / v4** | hybrid | IP `b3.b2.b1.b0` (**byte-swapped**) |

v3's *only* change vs v2 is this ID semantics flip - the record size is
identical (30 bytes). The rationale (source comment): sending the hybrid form
stops HighID clients whose IP ends in `.0` from being misparsed as LowID.
LowID ids (< 16777216) are never swapped.

### Server side

- **`OP_GETSOURCES` = 0x19** (0xE3). aMule ALWAYS writes the size; it never
  sends the bare 16-byte form:
  `<hash 16><size u32>`, or for large files `<hash 16><0 u32><size u64>`.
  OBFU variant `OP_GETSOURCES_OBFU = 0x23` iff the server advertises
  `SRV_TCPFLG_TCPOBFUSCATION (0x400)`. Large files require
  `SRV_TCPFLG_LARGEFILES (0x100)`, else the request is DROPPED, not downgraded.
  Up to 15 packets are concatenated into one TCP frame.
- **`OP_FOUNDSOURCES` = 0x42** (0xE3):
  `<hash 16><count u8><per source: ip u32, port u16>`; the OBFU variant 0x44
  appends `<crypt u8>` and, **if `crypt & 0x80`**, `<userhash 16>`.
  Count is a **u8** -> hard wire cap of 255 per packet.
- Re-ask: `SERVERREASKTIME = 800_000 ms` (13 min 20 s) per file; global TCP
  source-request throttle 300 s. Client caps `MAX_SOURCES_FILE_SOFT = 500`,
  `MAX_SOURCES_FILE_UDP = 50`.
- **LowID callback:** `OP_CALLBACKREQUEST` = 0x1C, payload `<id u32 LE>` (NOT
  byte-reversed - deliberate, to match servers); only sent if the LowID source is
  on OUR server. Inbound `OP_CALLBACKREQUESTED` = 0x35:
  `<ip u32><port u16>` and, **only if size >= 23**, `<crypt u8><userhash 16>`.
  `OP_CALLBACK_FAIL` = 0x36, null payload.

### Peer side (all 0xC5)

Opcodes: `OP_REQUESTSOURCES` 0x81, `OP_ANSWERSOURCES` 0x82,
`OP_REQUESTSOURCES2` 0x83, `OP_ANSWERSOURCES2` 0x84.

```
OP_REQUESTSOURCES  (SX1):              <hash 16>                            = 16 B
OP_REQUESTSOURCES2 (SX2): <ver u8><opts u16><hash 16>                       = 19 B
OP_ANSWERSOURCES   (SX1):              <hash 16><count u16><record>[count]
OP_ANSWERSOURCES2  (SX2): <ver u8>     <hash 16><count u16><record>[count]
```
Note `count` is **u16** here (the server's FOUNDSOURCES count is u8).

Record layouts:

| ver | fields | size |
|-----|--------|------|
| 1 | id u32 (ed2k), port u16, server_ip u32, server_port u16 | **12** |
| 2 | v1 + userhash 16 | **28** |
| 3 | same fields as v2, but id is **hybrid** (byte-swapped) | **28** |
| 4 | v3 + crypt u8 | **29** |

CORRECTED 2026-07-14: the research pass first reported these as 14/30/31. That
was WRONG - it double-counted 2 bytes. Upstream's own size checks are literally
`nCount*(4+2+4+2)`, `nCount*(4+2+4+2+16)`, `nCount*(4+2+4+2+16+1)`
(`A/PartFile.cpp:2934-2946`), i.e. **12 / 28 / 29**. This matters because SX1
disambiguates the record version BY PACKET SIZE - the wrong table would have made
padMule reject every real source-exchange answer. Caught by a byte-exact test.

crypt byte = `(requires << 2) | (requests << 1) | supports`. Bits 3-7 reserved
(eMule's "DirectCallback" bit 3 is commented out in 0.50a - not on the wire).

**v2 and v3 are the same length**, so an SX1 receiver disambiguates by the
sender's *announced* SX1 version:
```
count*12 == size -> v1  (require announced == 1, else DROP)
count*28 == size -> v2 if announced == 2; v3 if announced > 2; else DROP
count*29 == size -> v4  (require announced == 4, else DROP)
else                DROP
```
For SX2 the version byte in the packet governs; valid range 1..=4.

Capability discovery:
- **SX2**: `CT_EMULE_MISCOPTIONS2` (0xFE) **bit 10**. aMule hardcodes it to 1.
- **SX1 version**: `CT_EMULE_MISCOPTIONS1` (0xFA), 4-bit field at **shift 12**.
  **aMule advertises 3; eMule advertises 4.** So an SX1-only peer sends aMule
  v3 records (30 B, no crypt byte) but sends eMule v4 (31 B, with crypt). Over
  SX2 (both prefer it, both negotiate 4) the difference vanishes.

Limits: only **HighID** sources are ever exchanged; only "live" ones
(downloading / on-queue); only sources holding a part the requester lacks.
Emit up to **501** (see bug 7). Re-ask gates: rare file (<= 50 sources) -> per
client 40 min + per file 5 min; common -> 160 min / 20 min.

**zlib**: if the built packet is `> 354` bytes, try to pack; if compression fails
or does not shrink, leave it unpacked. On success the **protocol byte** flips
0xC5 -> **0xD4**, the **opcode is unchanged**. A receiver must accept
ANSWERSOURCES under either 0xC5 or 0xD4.

---

## 4. PartFile: block allocation, writing, verification

### Geometry
`PARTSIZE = 9_728_000`, `BLOCKSIZE = EMBLOCKSIZE = 184_320`,
`STANDARD_BLOCKS_REQUEST = 3`. A full part = **52 full blocks + a final short
block of 143,360 bytes** (9,728,000 - 52*184,320). Blocks never cross a part
boundary.

### Block selection (`A/PartFile.cpp:1369-1434`, `1976-2216`)
`GetNextEmptyBlockInPart` walks the gap list; a candidate block is bounded by
BOTH the gap and the `partStart + k*BLOCKSIZE` lattice, so **a block can be
SHORTER than 184320**. It skips ranges already reserved by another source.

Part selection is the Maella 4-criteria rank (lower = better). Rarity zones:
`modif = 10` (5 if >200 sources, 2 if >800); `limit = max(modif*sources/100, 1)`;
`veryRare = limit`, `rare = 2*limit`. Completion
`critCompletion = (PARTSIZE - gap_size(part)) / (PARTSIZE/100)` (deliberately
PARTSIZE, not the true part size - biases toward the short last part).
```
freq <= veryRare : rank = 25*freq + (preview ? 0 : 1) + (100 - completion)
else if preview  : rank = (requested ? 30000 : 10000) + (100 - completion)
else if freq<=rare: rank = 25*freq + (requested ? 30101 : 10101) + (100 - completion)
else (common)    : rank = requested ? 40000 + completion      // NOTE: inverted
                                    : 20000 + (100 - completion)
```
Ties are broken by uniform random pick. Once a part is chosen, ALL blocks for
that source come from it until it is exhausted.

**Reservations** are a plain overlap list on the part file; they are released on
block completion, on protocol error, and **always on disconnect**.

On the wire, legacy `OP_REQUESTPARTS` **always carries exactly 3 start + 3 end
values, zero-padded** if fewer are needed; `end` is written **exclusive**
(`EndOffset + 1`). The uploader ignores pairs where `end <= start`. (This matches
what we already built in Wave 4b.)

### Writing
Gaps are **[start, end] INCLUSIVE in memory** but **end-EXCLUSIVE on disk**
(`FT_GAPEND` = `end + 1`), so a fresh download's single gap is
`start=0, GAPEND=filesize`. (Wave 2c already has this right.)
`FillGap` runs at buffer-insert time - **before** the bytes reach disk. Flush when
the buffer exceeds ~240,000 bytes, or after `BUFFER_TIME_LIMIT = 60_000 ms`, or
when the gap list empties. part.met is re-saved after a flush only if dirty;
writes are tmp + 2-rename atomic (`.part.met.tmp` -> `.bak` -> live).
Naming: lowest free `NNN` from 1 -> `001.part` + `001.part.met`.

Worth stealing from eMule: it **persists still-buffered data as extra gaps** in
the .met precisely because FillGap precedes the disk write (aMule instead
compensates with a file-length heuristic at hash time). eMule's approach is the
safer durability story for an app that can be suspended mid-write - which is
exactly padMule's situation on iPadOS.

### Verification + corruption
`HashSinglePart(p)`: MD4 over `[p*PARTSIZE, p*PARTSIZE + part_size(p))`, compared
to the hashset entry (or the file hash when there is only one part - **see bug
1**). A missing hashset is treated as OK and flags `hashsetneeded`.

On MISMATCH: re-gap the **entire part**, add it to the corrupted list, count the
lost bytes, and (only as an optimisation) attempt AICH recovery.
**Basic corruption handling therefore needs NO AICH** - AICH only narrows the
re-download from a 9.28 MB part to the bad ~180 KB blocks, and it bails unless
the master hash is trusted and `part_size > EMBLOCKSIZE`.

The corrupted-part list persists as `FT_CORRUPTEDPARTS` (0x24), a
comma-separated decimal string. There is **no per-block verified bookkeeping**;
the persisted invariant is exactly: *a part is verified iff it is gap-complete
AND not in the corrupted list*.

On completion: full re-hash of all parts, then rename `NNN.part` into the
incoming dir, delete the `.met`/`.bak`/`.seeds`, and add to known.met.
