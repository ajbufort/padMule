# Build Progress

Updated: 2026-07-14

Wave-by-wave status of the padMule Rust engine (waves defined in
`docs/superpowers/specs/2026-07-12-padmule-design.md` section 10). Each wave
ends at a differential/round-trip gate.

## Status

| Wave | Scope | Plan | State |
|------|-------|------|-------|
| 1 | `mule-proto`: eD2k/MD4 file hashing | `plans/2026-07-12-wave1-mule-proto-ed2k-hash.md` | DONE. |
| 1b | `mule-proto`: LE byte I/O + eD2k tag codec | `plans/2026-07-12-wave1b-io-and-tags.md` | DONE. Reviewed + corrected (see below). 20 tests total, clippy clean. |
| 1c | `mule-proto`: AICH SHA-1 hash tree + search-expr encoding | - | not started (remaining Wave-1 codec slices) |
| 2a | `mule-files` crate + `server.met` | `plans/2026-07-12-wave2a-mule-files-server-met.md` | DONE (5 tests). |
| 2b | `known.met` | `plans/2026-07-12-wave2b-known-met.md` | DONE (10 mule-files tests total). |
| 2c | `part.met` (+64-bit + gap list) | `plans/2026-07-12-wave2c-part-met.md` | DONE (17 mule-files tests). `nodes.dat` moved to Wave 6 (Kad). |
| 3a | `mule-proto` packet framing + zlib | `plans/2026-07-13-wave3a-packet-framing.md` | DONE (31 mule-proto tests). |
| 3b | `mule-engine` crate + login-handshake codecs (offline) | `plans/2026-07-13-wave3b-login-codecs.md` | DONE (8 tests): build_login_request, parse_id_change/server_message/server_status. |
| 3b-2 | search codec + server list/ident | `plans/2026-07-13-wave3b2-search-codec.md` | DONE (15 mule-engine tests): build_search_request (ANDed-terms), parse_search_result, parse_server_list, parse_server_ident. Full boolean tree (OR/NOT) + global UDP search + OP_FOUNDSOURCES deferred. |
| 3c-1 | async framing + login handshake (tokio) | (implemented directly, no separate plan doc) | DONE (21 mule-engine tests): FramedStream, ServerState/ServerEvent, login_handshake, connect_server. Mock-server tested. |
| 3c-2 | pause/resume ServerLink + mule-cli live harness | `plans/2026-07-13-wave3c2-link-and-cli.md` | DONE (23 mule-engine tests): ServerLink connect/pause/resume over a real loopback socket; mule-cli login / login-any. Live run: see note below. |
| 3d | client-to-client peer HELLO codec | (implemented directly) | DONE (28 mule-engine tests): build_hello/answer, baseline MISCOPTIONS1/2 (0x34103212/0x438) byte-verified, parse_hello + Capabilities. Pivoted from get-sources (server-dependent, untestable here) to the peer protocol (locally testable). |
| 4a | client-to-client peer connection + inbound listener | (implemented directly) | DONE (30 tests): peer_handshake_outbound/inbound, connect_peer/accept_peer; two engines handshake on loopback. mule-cli `listen` command for HighID validation. |
| 4b | download-side transfer message codecs | (implemented directly) | DONE (37 tests): request_filename/setreqfileid/startupload/hashset, file-status bitfield, request_parts (3-block u32/u64), sending_part, queue-ranking. |
| 4c | first end-to-end transfer (two engines) | (implemented directly) | DONE (40 tests): download_file + serve_file; two engines transfer a 3-block file on loopback, ed2k hash matches byte-for-byte. Next: write to a real .part, multi-part+hashset, differential vs local amuled. |
| 4d | upload side + queue/slots + credits + source exchange + corruption; get-sources codec | (implemented directly) | **DONE - Wave 4 GATE MET (180 tests + differential test vs real amuled passes).** 4d-1/2 credits + clients.met + upload queue/slots/ranking; 4d-3 source exchange (SX1/SX2 v1-v4) + get-sources + LowID callback; 4d-4/5 PartFile block allocation + corruption handling; 4d-6 disk-backed PartStore (.part + byte-compat .part.met, resume, atomic save); 4d-7 multi-source Download driver; 4d-8 adversarial review + 6 fixes; 4d-9 DIFFERENTIAL TEST: padMule downloads from a real amuled 3.0.1 byte-for-byte (raw + compressed paths). Fixed 4 aMule bugs + 6 review findings + 1 interop bug the differential test caught. See notes below. |
| 5a | TCP protocol obfuscation (EncryptedStreamSocket) | (implemented directly) | DONE + VALIDATED vs real amuled. RC4 (textbook vectors) + key derivation MD5(target_userhash \| magic \| randomkey) + handshake + FramedStream cipher integration + connect_peer_obf/accept_peer auto-detect. padMule downloaded single-part AND multi-part (hashset) from amuled through the RC4 stream, byte-for-byte. Research: docs/raw/wave5-crypto-research-2026-07-14.md. |
| 5b | UDP obfuscation (EncryptedDatagramSocket) | - | not started (needs Kad/UDP, Wave 6) |
| 5c | secure identification (RSA) | (implemented directly) | DONE + INTEROP-VALIDATED vs real amuled. RSA-384 PKCS1v15-SHA1 (48-byte sig); Identity keygen + cryptkey.dat (PKCS#8, NOT PKCS#1 - Crypto++ writes the PKCS#8 wrapper); sign_v1 signs PEER pubkey \| challenge, verify_v1 mirrors; OP_PUBLICKEY/SECIDENTSTATE/SIGNATURE codecs. Integration test loads a REAL aMule cryptkey.dat. v1 only (v2 challenge-IP deferred). Remaining: live state machine + credit tie-in (5d). |
| 5d | crypto wiring + gating; secure-ident state machine; differential gates | (implemented directly) | MOSTLY DONE + VALIDATED vs amuled. (1) TCP obfuscation wired into peer connect/accept + serve-file, validated (download + secure-ident vs amuled). (2) SecureIdentSession live mutual RSA - padMule VERIFIED real amuled's signature. Caught on-wire pubkey = SPKI not PKCS#1. (3) Credit tie-in: IdentState + resolve_ident_state (IP binding) + score_ratio_ident (no bonus for unverified/failed/badguy). (4) Obfuscation gating: should_obfuscate_outbound / should_reject (crypt_policy.rs). REMAINING (integration, lower-risk): drive secure-ident + gating during a live transfer (multi_source); server-connect (DH) obfuscation; amuled uploader-pull (serve is obf-aware + proven P2P; blocked only by amuled's flaky offline link-source dialer). |
| 6a | Kad128 (CUInt128) + nodes.dat + routing table | (implemented directly) | DONE + real-fixture-validated. mule_proto::Kad128 (XOR distance, MSB-first bit(), 2^120 tolerance; canonical from_hash/to_hash vs raw from_wire/to_wire - dword-byte-reversal landmine). mule_files::nodes_dat byte-compat (parses + round-trips the REAL 6098-B nodes.dat byte-identical). NEW crate mule-kad: routing bin-tree (K=10, KBASE=4, KK=5, split rule, closest_to) - loads the 179-contact fixture (retains ~142, far bins cap at K). Research: docs/raw/wave6-kad-research-2026-07-14.md. |
| 6b | Kad UDP framing + obfuscation (5b) + bootstrap/hello | (implemented directly) | DONE (codecs) + source-verified + adversarial-reviewed. mule-kad: frame.rs (0xE4/0xE5, pack iff PAYLOAD>200 - opcode excluded), udp_obf.rs (CEncryptedDatagramSocket: 16-B header, contiguous RC4 no-discard, sentinel 0x395F2EC1 + verify keys plain-LE since aMule ENDIAN_SWAP is a no-op on LE, NodeID/ReceiverKey derivations, GetUDPVerifyKey, is_protocol_byte = UDP set {C5,D4,E4,E5,A3,B2}), message.rs (BOOTSTRAP/HELLO/RES_ACK + Kad tag <type><nameLen u16=1><name><value> w/ CTagVarInt minimal sizing; version 0x08 aMule). Pipeline test: build->frame->obfuscate->deobfuscate->deframe->parse (NodeID + ReceiverKey paths, 20-contact packed RES). 3 bugs fixed pre-commit (proto-byte set, zero-payload reject, pack off-by-2). REMAINING 6b: live gate = UDP socket to a real bootstrap node (empty BOOTSTRAP_REQ -> decode RES -> HELLO 3-way -> IP-verified). |
| 6c | iterative node lookup (FIND_NODE) | - | not started |
| 6d | source/keyword search + differential gate (resolve a hash) | - | not started |
| 7 | `mule-ec` + `mule-cli` parity (IP filter, UPnP, categories) | - | not started |
| 8 | `mule-ffi` + `ios/padMule` SwiftUI shell + lifecycle + sideload | - | not started. Must render the honest status notice + per-transfer Paused badges + Reconnecting banner, and wire ScenePhase -> engine pause()/resume() ([[lifecycle-and-reactivation]]). |
| 9 | (v1.1) seedbox mode | - | not started |

## Wave 4d notes - aMule bugs we deliberately do NOT replicate (2026-07-14)

Source-grounded research for Wave 4d (docs/raw/wave4d-upstream-research-2026-07-14.md)
turned up genuine defects in aMule 3.0.1 in exactly the subsystems the wave
builds. Per [[decisions-and-lessons]] replicate-then-improve, faithful
replication here would be WRONG. Each divergence is documented at its call site.

1. **Exactly-PARTSIZE file is permanently corrupt.** aMule verifies a single-part file
   against the FILE hash, but a 9,728,000-byte file has a two-entry hashset (real
   part + empty-MD4 sentinel), so the file hash is `MD4(h0 || h_empty) != h0`.
   The part never verifies, on every retry. We use eMule's guard
   (`part_count > 1 || size == PARTSIZE`). A test builds exactly that file.
2. **aMule cannot receive a standalone `OP_REQUESTSOURCES2`** - it checks
   `size != 16` (SX2 is 19 bytes) and reads the hash at offset 0 instead of 3, so
   it throws and disconnects. Still broken in amule-master.
3. **SX id byte order gated on the wrong version** in `CPartFile` - sends
   byte-reversed source IPs when a peer's SX1 and SX2 versions disagree. aMule's
   own `CKnownFile` and eMule both get it right; we gate on the version written.
4. **OBFU found-sources userhash flag is 0x80**, not `0x08` as the header comment
   says. The code is right; the comment lies.

Also: aMule's ICH (intelligent corruption handling) is unreachable dead code in
3.0.1 - do not "faithfully" port a dead path.

**Lesson (recorded in [[decisions-and-lessons]]):** our own research pass got the
SX record sizes wrong (14/30/31; they are 12/28/29). Since SX1 resolves the
record version BY PACKET SIZE, that would have made padMule reject every real
source-exchange answer. A byte-exact test caught it within minutes. Agent-derived
constants are a hypothesis until a test pins them against the actual bytes.

## Differential test vs amuled - PASSED (2026-07-14, the true Wave 4 gate)

padMule downloads files from a REAL headless amuled 3.0.1, byte-for-byte, over
both the raw (`OP_SENDINGPART`) and compressed (`OP_COMPRESSEDPART`) block paths.
This is the oracle that padMule-to-padMule testing cannot be: it catches mistakes
made symmetrically on both our ends.

Build: `scripts/build-amuled-oracle.sh` builds daemon-only amuled (deps: cmake,
libwxgtk3.2-dev, libcrypto++-dev, zlib1g-dev, libboost-dev, pkg-config,
libglib2.0-dev; optional GeoIP/UPnP/BFD/NLS disabled with -DENABLE_*=NO). The
upstream ctest suite (11 tests) PASSES - an independent cross-check of our
tag/io/hash codecs. Run: `scripts/differential-test.sh` (shares a compressible +
a random file from amuled, downloads both with `mule-cli peer-download`, asserts
byte-for-byte match).

**What the differential run validated against real aMule:**
- our ed2k file hash == amuled's known.met hash, byte-for-byte (600 KB file);
- our block reassembly incl. the Wave-4d compressed-part fix, against amuled's
  actual per-block zlib;
- verification against amuled's real per-part hashset.

**The interop bug it caught (that all 166 padMule-to-padMule tests missed):**
We advertise `ExtendedRequestsVersion=2` in the hello (MISCOPTIONS1) but sent a
BARE 16-byte `OP_REQUESTFILENAME`. aMule's `ProcessExtendedInfo`
(UploadClient.cpp:193) THROWS and disconnects a client that advertised extended
requests but omitted the payload - we advertised a capability and violated it.
Fix: `build_request_filename_ext` appends requester-part-count (0) +
complete-sources-count (0), matching aMule's own `SendFileRequest`. Diagnosed
with `mule-cli peer-probe` (wire trace) after aMule's own debug logging refused
to emit client-level events. **Lesson: advertise no capability you do not
honour on the wire - a symmetric client never punishes the mismatch, a real one
disconnects.**

### Extended coverage (2026-07-14)

- **Multi-part + hashset download: PROVEN.** padMule downloads a 15 MB /
  2-eD2k-part file from real amuled byte-for-byte, exercising
  OP_HASHSETREQUEST/ANSWER and per-part MD4 verification against amuled's REAL
  hashset, over mixed compressed+raw blocks. Now in `differential-test.sh`.
- **Upload direction (amuled pulls FROM padMule): PARTIAL.** `mule-cli
  serve-file <port> <path>` makes padMule the uploader. A real amuled CONNECTS
  to padMule's listener (inbound reachability + our accept path proven), but the
  full pull is blocked by amuled-side orchestration, not padMule:
  * amuled unconditionally rejects loopback 127/8 and (with FilterLanIPs=1, the
    default) LAN sources - `IsGoodIP` (NetworkFunctions.cpp:133). Serve on the
    mirrored **10.0.0.33** with **FilterLanIPs=0** so 10/8 passes (10/8 is only
    in the conditional LAN table, not the unconditional reserved table).
  * amuled attempts an **OBFUSCATED** client handshake by default
    (`IsCryptLayerRequested=1`) - a Wave 5 feature padMule lacks; its one
    successful dial failed the handshake for this reason. Disable with the three
    `[Obfuscation]` keys = 0.
  * amuled rewrites amule.conf on startup, so a manual pref edit needs the file
    chmod'd read-only to stick. And a leftover `.part` makes amuled say "already
    trying to download" and skip the link's source - clear Temp between runs.
  * even with all that, amuled's offline link-source dialing is irregular.
  padMule's `serve()` is independently proven by the padMule-to-padMule
  multi_source tests. Revisit the amuled-pull after Wave 5 adds obfuscation.

## Wave 4d adversarial review + fixes (2026-07-14)

8-dimension multi-agent review of all Wave 4d code against the C++ oracles, each
finding attacked by 3 independent skeptics (majority-refute kills it). 6 real
defects survived; ALL fixed and cross-checked against eMule 0.50a as the wire
authority. None were catchable by padMule-to-padMule tests - they only appear
against a real/hostile peer, which is exactly what the review substitutes for
until the amuled differential test runs.

- HIGH remote PANIC: a peer sending data longer than its declared range hit
  `copy_from_slice` with mismatched lengths (transfer_session).
- HIGH remote HANG: a zero-length block (start==end) advanced the completion
  counter by 0 forever (both download loops).
- HIGH interop break: padMule advertises `data_comp=1`, so a stock uploader
  sends `OP_COMPRESSEDPART` (0x40/0xA1); the loop only matched OP_SENDINGPART and
  silently dropped them -> every real-network download of a compressible file
  hung. Fix required per-block STREAMING zlib inflate (each fragment carries the
  block START; write position = running total_out), matching eMule's
  ProcessBlockPacket (DownloadClient.cpp:1201) exactly.
- The three collapse into ONE hardened `BlockReceiver` that both download loops
  route through, killing the duplicated receive logic that let the same bug live
  in two copies. Guards reject zip-bomb over-expansion and short streams.
- MEDIUM unverified accept: `needs_hashset` gated on `data_part_count > 1`, so an
  exactly-PARTSIZE file never fetched its hashset and was moved into place
  UNVERIFIED - silently defeating the PARTSIZE-bug fix. Now matches verify_part.
- MEDIUM x2 wrong large-file boundary: used `u32::MAX` where it is
  `OLD_MAX_FILE_SIZE = 4_290_048_000` (eMule OLD_MAX_EMULE_FILE_SIZE, same value,
  = `(u32::MAX / PARTSIZE) * PARTSIZE`). Files in the ~4.9M-byte band between them
  were mis-encoded on the wire (OP_GETSOURCES) and in .part.met.

180 workspace tests (was 166); 14 new regression tests pin each finding.

**Lesson (in [[decisions-and-lessons]]):** for wire behaviour, eMule 0.50a is the
source of truth - not aMule. The fixes were derived from aMule and then CONFIRMED
identical in eMule (bounds guard DownloadClient.cpp:1123, compressed opcodes +
inflate formula, the 4_290_048_000 constant). Cross-checking turned "probably
fine" into "verified"; do it on every wire fix, not just when a bug is suspected.

## Review pass (2026-07-12)

Multi-agent adversarial review of Wave 1 + 1b (3 dimensions completed before a
session limit: Rust quality, hash faithfulness, tag/io faithfulness; docs
consistency self-audited). The hashing algorithm, endianness, tag byte layout,
and panic-safety were independently CONFIRMED faithful against the aMule C++
source. Corrections applied: length-prefixed writers now cap+truncate (no
stream desync), BOOL/BOOLARRAY tags accepted with round-trip, docs tightened.
See [[decisions-and-lessons]] for the deliberate divergences (do NOT "fix"
them). Residual: no fully-independent end-to-end eD2k hash vector exists on this
box (no rhash/pycryptodome); the algorithm is source-verified + MD4 is
RFC-anchored, and the live differential test vs amuled (Wave 3+) is the true
end-to-end oracle. aMule's own `unittests/tests/CTagTest.cpp` /
`FileDataIOTest.cpp` are a future cross-check for the tag/io codec.

## Wave 2 notes

- `mule-files` mirrors the `mule-proto` approach: parse into structs that
  preserve every field as read, so read-then-write is bit-identical. The header
  byte is preserved (server.met 0xE0/0x0E, known.met 0x0E/0x0F) rather than
  forced, which is more faithful than aMule's own re-save.
- 2c DONE: `part.met` round-trips (version 0xE0/0xE2, accepts 0xE1); the gap
  list is carried as string-named tags (`\x09`/`\x0A` + decimal index) that the
  generic codec handles, with `gaps()`/`gap_tags()` translating to `(start,
  end)` ranges - start inclusive, end EXCLUSIVE (the on-disk GAPEND value =
  file size for a fresh download). Pairing is by decimal index (order/dup
  tolerant). `nodes.dat` moved to Wave 6 (its 128-bit id needs interpretation
  there); real fixture available from emule-security.org.
- Not yet golden-tested against a REAL aMule-written file (only hand-built
  golden vectors). Generating real .met files needs a built amuled or samples;
  tracked as a cross-check for when the engine wave can produce them.

## Wave 1 notes

- Workspace at repo root; first crate `crates/mule-proto` (pure, no I/O).
- `ed2k_hash(&[u8]) -> [u8;16]` is an in-memory reference implementation. The
  engine will need a STREAMING `Ed2kHasher` (feed parts from disk) for multi-GB
  files; that lands with `mule-files`/engine and must match this reference.
- Toolchain: Rust 1.96.1; `source "$HOME/.cargo/env"` before every cargo call
  (cargo not on default PATH). No aarch64-apple-ios target installed here (iOS
  builds happen on CI macOS per [[ipados-constraints]]).

## Remaining Wave-1 slices (next plans)

1. DONE (1b): LE byte reader/writer primitives (`io`) + eD2k tag codec (`tag`).
2. Packet framing (protocol byte, u32 size, opcode, split packets, packed/zlib)
   - deferred to the engine wave; `.met` files need tags, not framing.
3. AICH SHA-1 hash tree (180 KiB blocks, non-trivial split formula, master
   hash, recovery packet). See [[protocol-reference]] section 2. Needed by
   part.met (Wave 2) and hashset exchange (engine).
4. Search-expression encoding (boolean AND/OR/NOT + parameter terms) - engine
   search wave.

Tag codec divergences (matching aMule MET writers): `write_tag` emits the
non-compact form only; the `(type|0x80)` short form and inline STR1..16 are
read-only. Values preserve on-disk width/bytes for bit-identical round-trip.

## Wave 3 plan (eD2k engine core)

Decomposed so most protocol logic stays offline-testable before any socket:
- 3a DONE: packet framing + zlib in `mule-proto` (streaming `read_packet`,
  `write_packet`, `compress`/`decompress`). New deps: flate2 (miniz_oxide
  backend, pure Rust, iOS-safe).
- 3b: server login/search MESSAGE codecs as pure functions in `mule-engine`
  (build OP_LOGINREQUEST, parse OP_IDCHANGE/SERVERMESSAGE/SERVERSTATUS; build
  OP_SEARCHREQUEST + search-expression encoding; parse OP_SEARCHRESULT/
  OP_FOUNDSOURCES). Golden-byte tested, no networking.
- 3c: tokio `ServerConnection` driving the handshake over a real socket; live
  smoke test against a public eD2k server (from a fetched server.met) or a local
  amuled. Apply the protocol-understanding recommendations (plain-LE client IDs,
  never advertise VBT, capability gating, userhash markers, one canonical IP).
  ALSO design in the lifecycle state model + explicit `pause()`/`resume()` +
  connection-state EVENT STREAM now (not later) - see
  [[lifecycle-and-reactivation]]; the CLI harness exercises a simulated
  pause/resume so it is tested before the iPad UI exists.
- 3d: OP_GETSOURCES -> OP_FOUNDSOURCES, connect a source, download one file to a
  `.part` via the 3-block window, verify the ed2k hash. First differential test
  vs `amuled`. See [[protocol-understanding]] for all flows.

## LIVE VALIDATED against a real eD2k server (2026-07-13)

padMule successfully LOGGED IN to a live eD2k server: `45.87.41.16:6262` (from
the emule-security.org trusted list), assigned a LowID (expected - this NATed
box cannot accept the server's HighID connect-back test). Full lifecycle also
validated live: connect -> pause -> resume -> reconnect (fresh LowID each time)
-> disconnect. So Wave 3a-3c (login handshake, framing, IDCHANGE parse,
ServerLink pause/resume) are proven end-to-end against real server software, not
just mocks. The byte-level fidelity (exact login tags/flags/version) interoperated
with the real eD2k network on the first try.

CORRECTION to an earlier wrong finding: this WSL2 env does NOT block P2P ports.
Arbitrary outbound ports work (SSH 22, DNS 53, DoT 853, IRC 6667 all open; UDP
egress works). The earlier all-fail runs were STALE server lists (the 38.107.x
block and some server-met.de entries are dead). Lesson: use a CURRENT, trusted
list. Working source: `http://upd.emule-security.org/server.met` (0xE0 header,
~9 servers). Good news for later: Kad UDP (Wave 6) should work from here too.

## HIGHID ACHIEVED - inbound chain validated live (2026-07-14)

padMule now gets a **HighID** from the live server `45.87.41.16:6262`:
`Connected { id: <client-id>, low_id: false }`. `<client-id>` = `<client-id-hex>` ->
decodes (LE, first octet low) to **<public-ip>** = our public IP, which is what a
HighID IS - and it independently confirms our client-ID decode against real
server software. The `mule-cli listen 4662` listener logged the server's
connect-back arriving from the internet (`45.87.41.16:49144`). Pause/resume kept
HighID.

This closes the 2026-07-13 gap (same server gave LowID then). All five inbound
links now work: router forward -> DHCP reservation -> Windows Firewall ->
Hyper-V firewall (the mirrored-mode trap) -> WSL mirrored networking -> our
listener. Full detail + how to re-validate: [[net-highid-and-port-forwarding]].

Observed: the server's HighID test is a bare TCP connect+close, no eD2k HELLO -
a successful accept is enough. Our listener treats that as the healthy path.

Remaining live gaps: the dev-box forward does NOT carry to the iPad; on-device
HighID needs UPnP/NAT-PMP (raises Wave 7's priority), and cellular/CGNAT will
force LowID regardless. Client-to-client transfer is validated on loopback
(Wave 4c); differential vs a local amuled still pending.

### eMule vs aMule format/server notes (Anthony flagged 2026-07-13)

- server.met format is the SAME for eMule and aMule (0xE0/0x0E header + tag
  records); confirmed - our parser read emule-security.org's file fine.
- The eD2k SERVER software (eserver/lugdunum) is shared; both eMule and aMule
  connect identically. Our aMule-based login interoperated with a real server,
  confirming aMule's login is eMule-network-compatible (aMule mirrors eMule).
- String tags: eMule writes some BOM-prefixed strings; aMule 3.0.1 does not. Our
  reader accepts BOM (preserves raw bytes); strip the BOM only for DISPLAY
  (server names). Non-load-bearing for connecting. See [[decisions-and-lessons]]
  tag-codec divergences.
- We advertise SO_AMULE (software id 3) in CT_EMULE_VERSION, so peers/servers see
  us as an aMule client - correct and intended.

## Test fixtures / live data (from [[ref-ecosystem]])

emule-security.org provides real `nodes.dat` (Wave-2 round-trip + Wave-6 Kad
bootstrap) and `ipfilter.dat` (Wave-7 IP filter). Fetch at the relevant wave;
do not vendor. For known.met/part.met/clients.met round-trips, generate golden
files by building/running amuled from `amule-3.0.1/`, or hand-construct from the
verified byte layouts in [[protocol-reference]] / docs/raw.

## Related

- [[protocol-reference]]
- [[ref-ecosystem]]
- [[arch-upstream-amule]]
- [[decisions-and-lessons]]
