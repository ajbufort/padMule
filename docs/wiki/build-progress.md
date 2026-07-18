# Build Progress

Updated: 2026-07-18 (code-fix round)

Wave-by-wave status of the padMule Rust engine (waves defined in
`docs/superpowers/specs/2026-07-12-padmule-design.md` section 10). Each wave
ends at a differential/round-trip gate.

## Status

| Wave | Scope | Plan | State |
|------|-------|------|-------|
| 1 | `mule-proto`: eD2k/MD4 file hashing | `plans/2026-07-12-wave1-mule-proto-ed2k-hash.md` | DONE. |
| 1b | `mule-proto`: LE byte I/O + eD2k tag codec | `plans/2026-07-12-wave1b-io-and-tags.md` | DONE. Reviewed + corrected (see below). 20 tests total, clippy clean. |
| 1c | `mule-proto`: AICH SHA-1 hash tree + search-expr encoding | (implemented directly) | AICH DONE (2026-07-15): mule_proto::aich::aich_master_hash - SHA-1 tree (leaf=SHA1(EMBLOCKSIZE block), node=SHA1(L||R)), verbatim from SHAHashSet.cpp; structurally tested vs SHA1, byte-validation vs a live eMule AICH pending. Search-expression tree (boolean OR/NOT) still deferred. |
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
| 5b | UDP obfuscation (EncryptedDatagramSocket) | - | DONE - absorbed into Wave 6b (`mule-kad::udp_obf` implements CEncryptedDatagramSocket; see row 6b). |
| 5c | secure identification (RSA) | (implemented directly) | DONE + INTEROP-VALIDATED vs real amuled. RSA-384 PKCS1v15-SHA1 (48-byte sig); Identity keygen + cryptkey.dat (PKCS#8, NOT PKCS#1 - Crypto++ writes the PKCS#8 wrapper); sign_v1 signs PEER pubkey \| challenge, verify_v1 mirrors; OP_PUBLICKEY/SECIDENTSTATE/SIGNATURE codecs. Integration test loads a REAL aMule cryptkey.dat. v1 only (v2 challenge-IP deferred). Remaining: live state machine + credit tie-in (5d). |
| 5d | crypto wiring + gating; secure-ident state machine; differential gates | (implemented directly) | MOSTLY DONE + VALIDATED vs amuled. (1) TCP obfuscation wired into peer connect/accept + serve-file, validated (download + secure-ident vs amuled). (2) SecureIdentSession live mutual RSA - padMule VERIFIED real amuled's signature. Caught on-wire pubkey = SPKI not PKCS#1. (3) Credit tie-in: IdentState + resolve_ident_state (IP binding) + score_ratio_ident (no bonus for unverified/failed/badguy). (4) Obfuscation gating: should_obfuscate_outbound / should_reject (crypt_policy.rs). REMAINING (integration, lower-risk): drive secure-ident + gating during a live transfer (multi_source); server-connect (DH) obfuscation; amuled uploader-pull (serve is obf-aware + proven P2P; blocked only by amuled's flaky offline link-source dialer). |
| 6a | Kad128 (CUInt128) + nodes.dat + routing table | (implemented directly) | DONE + real-fixture-validated. mule_proto::Kad128 (XOR distance, MSB-first bit(), 2^120 tolerance; canonical from_hash/to_hash vs raw from_wire/to_wire - dword-byte-reversal landmine). mule_files::nodes_dat byte-compat (parses + round-trips the REAL 6098-B nodes.dat byte-identical). NEW crate mule-kad: routing bin-tree (K=10, KBASE=4, KK=5, split rule, closest_to) - loads the 179-contact fixture (retains ~142, far bins cap at K). Research: docs/raw/wave6-kad-research-2026-07-14.md. |
| 6b | Kad UDP framing + obfuscation (5b) + bootstrap/hello | (implemented directly) | DONE (codecs) + source-verified + adversarial-reviewed. mule-kad: frame.rs (0xE4/0xE5, pack iff PAYLOAD>200 - opcode excluded), udp_obf.rs (CEncryptedDatagramSocket: 16-B header, contiguous RC4 no-discard, sentinel 0x395F2EC1 + verify keys plain-LE since aMule ENDIAN_SWAP is a no-op on LE, NodeID/ReceiverKey derivations, GetUDPVerifyKey, is_protocol_byte = UDP set {C5,D4,E4,E5,A3,B2}), message.rs (BOOTSTRAP/HELLO/RES_ACK + Kad tag <type><nameLen u16=1><name><value> w/ CTagVarInt minimal sizing; version 0x08 aMule). Pipeline test: build->frame->obfuscate->deobfuscate->deframe->parse (NodeID + ReceiverKey paths, 20-contact packed RES). 3 bugs fixed pre-commit (proto-byte set, zero-payload reject, pack off-by-2). LIVE GATE PASSES (2026-07-15): mule-engine::kad_live::KadNode + `mule-cli kad-bootstrap <nodes.dat>` - against a fresh nodes.dat from upd.emule-security.org, padMule sends an obfuscated BOOTSTRAP_REQ to a real node (v10), decodes BOOTSTRAP_RES (20 contacts, ReceiverKey path), seeds routing, and completes HELLO_REQ/RES. aMule version 0x08 accepted by a v10 peer. Fixed the IP byte-order landmine (contact ip is HOST order; dotted quad = Ipv4Addr::from(ip) big-endian view, NOT to_le_bytes). |
| 6c | iterative node lookup (FIND_NODE) | (implemented directly) | DONE (codec + pure lookup) + source-verified. message.rs: KADEMLIA2_REQ 0x21 (type&0x1F|target|receiver, 33B, zero-type rejected) + KADEMLIA2_RES 0x29 (target|count|25B contacts, exact-len 17+25*count, Kad1 dropped); type bytes FIND_VALUE 0x02 / STORE 0x04 / FIND_NODE=FIND_VALUE_MORE 0x0B (GetRequestContactCount). lookup.rs: Lookup state machine - candidates BTreeMap keyed by XOR distance (injective per id), next_queries(ALPHA=3, frontier) returns closest untried + marks tried, on_response folds in closer contacts, converges when frontier fully queried. Convergence test: 160-node net where each node's knowledge is a real 6a RoutingTable (navigable) -> lookup reaches the exact k-closest. Timers/JumpStart/IP-dedup left to the live layer. REMAINING 6c: drive it live over UDP (self-lookup fills the routing table). |
| 6d | source/keyword search + differential gate (resolve a hash) | (implemented directly) | **DONE - WAVE 6 GOAL MET (live).** Codecs (mule-kad): SEARCH_SOURCE_REQ 0x34 (target 16|startPos 2 &0x7FFF|fileSize 8 = 26B) + SEARCH_RES 0x3B (responderID 16|keyID 16|count 2|count x {answer 16|taglist}); SearchResult::as_source distils source tags (SOURCETYPE 0xFF/SOURCEIP 0xFE/SOURCEPORT 0xFD/SOURCEUPORT 0xFC; accepts types {1,3,4,5,6}). read_kad_tag relaxed to eMule behavior (name = length-prefixed string, any length; unknown TYPE still errors). Driver (kad_live): find_node+search_source drive resolve_sources (iterative lookup toward the hash, then SEARCH_SOURCE_REQ to closest in-tolerance); ed2k hash -> Kad target via from_hash (SetValueBE). mule-cli `kad-search <nodes.dat> <hash> <size>`. LIVE: bootstrap -> 15/16 nodes answer FIND_NODE -> 5/10 in-tolerance return SEARCH_RES -> resolves a real source (type 3, real IP:port), reliably. |
| 7 | end-to-end fetch (give a hash, get the file) - RE-SCOPED from EC | (implemented directly) | DONE (orchestration) + loopback-validated + live discovery/connect. mule-engine::fetch: PeerSource unifies Kad/server/peer sources (reconciles the TWO IP conventions in one place - Kad TAG_SOURCEIP = host-order/big-endian view Ipv4Addr::from(ip); server FOUNDSOURCES = eD2k low-byte; verified vs DownloadQueue::KademliaSearchFile). SourceRegistry dedups by addr; fetch_from_sources drives Download across sources (obf when userhash known). Only HighID Kad types {1,4} + non-LowID server ids connectable. mule-cli kad-fetch <nodes.dat> <hash> <size> <out>. 5 unit tests (IP conventions/filtering/dedup) + loopback test (serve->fetch->verify ed2k hash) + dead-source test. LIVE: kad-fetch bootstrapped, resolved a HighID source, completed an OBFUSCATED handshake with a real internet peer (1/1); 0 bytes only because the degenerate test hash isn't a file that peer holds. NOTE: EC protocol deferred (iPad seam is FFI/Wave 8, not a separate EC daemon; EC would be interop-only). |
| 7.5 | pre-Wave-8 engine hardening (identity, Engine facade+lifecycle, resume, download mgr) | (implemented directly) | DONE (WSL-tested). NodeIdentity (persistent userhash/KadID/udpkey/RSA; aMule-compat preferences.dat/preferencesKad.dat). Engine facade = the UniFFI seam: EngineState/EngineEvent + idempotent pause/resume lifecycle (foreground-only). start() loads nodes.dat + resumes .part downloads; checkpoint() saves identity+nodes.dat. download_file = parallel multi-source + retry manager (rides out eD2k upload-queue rationing). 300 tests. Optional coverage remaining at the time - all since closed except one: LowID callback PROVEN live (three-file milestone), full UPnP done (7.8), Kad keyword search done (8c); still open: AICH byte-validation vs a live eMule (row 1c). |
| 7.6 | intelligent fetch engine + LIVE three-file completion | (implemented directly) | **DONE - live-proven (2026-07-16).** Search catalog (catalog.rs: dedup by ed2k hash, aggregate availability FT_SOURCES/FT_COMPLETE_SOURCES, trust flags, rank Ok-before-suspect then sources-desc) + completion-optimized fetcher (mule-cli fetch-complete). Downloaded THREE real files to completion, one each from a pdf/wav/txt keyword search, every one ed2k-hash-verified. See the milestone section below. |
| 7.7 | padMule-to-padMule enhancement channel (Layer 1) | (implemented directly) | **DONE + adversarially validated (2026-07-16).** Layer 1 detection: every peer HELLO/HELLOANSWER carries a string-named "padMule" UINT32 marker (`<caps:u24><version:u8>`); `ParsedHello::padmule()` recognizes another padMule. Carrier chosen from SOURCE-GROUNDED proof that stock eMule 0.50a + aMule 3.0.1 read-and-skip a string-named tag with a standard type byte (and THROW/DESYNC on a nonstandard type - so never do that). ADVERSARIAL GATE: the amuled differential test passes with the marker in every hello (real aMule serves all 3 files byte-for-byte). Also fixed a regression the differential test caught in my own queue fast-bail (see below). Layer 2 (opcode on 0xC5, only to confirmed padMule) + NAT-traversal enhancement: designed, not built. Full design: [[padmule-enhancement-channel]]. |
| 7.8 | UPnP-IGD port mapping (on-device HighID) | (implemented directly) | **DONE (2026-07-16), socket-validated.** mule-engine::upnp - full UPnP-IGD, hand-rolled zero-dep (tokio sockets + minimal HTTP/XML), the path NAT-PMP (portmap.rs) does not cover and the one our Xfinity gateway needs: SSDP M-SEARCH discovery -> HTTP GET device description -> parse the WANIP/PPP service control URL -> SOAP AddPortMapping + GetExternalIPAddress. mule-cli `upnp <port>`. 10 tests incl. a loopback integration test that drives http_get + parse_wan_service + soap_add_mapping + external_ip against a mock IGD over a real socket (validates the HTTP/SOAP framing end-to-end). LIVE attempt vs the real gateway got NO SSDP response - but an independent raw-Python M-SEARCH also got nothing, so it is an ENVIRONMENT limit (WSL2 multicast and/or Xfinity UPnP disabled), NOT our code; discovery should work on a real iPad on a UPnP-enabled home net. On-device HighID now has both mapping protocols (NAT-PMP + UPnP). |
| 8a | `mule-ffi` UniFFI seam (Rust <-> Swift) | (implemented directly) | **DONE (2026-07-16), builds + generates Swift bindings.** New crate `crates/mule-ffi` (lib + cdylib + staticlib) wraps `Engine` in an FFI-friendly facade `MuleEngine`: opaque hashes -> hex strings, `EngineState`/`EngineEvent` -> `#[uniffi::Enum]`s, `IdentityInfo`/`DownloadInfo` records, `FfiError`. The async `&mut self` lifecycle is driven on an internal tokio runtime so exported methods are simple/sync (start/pause/resume/shutdown/state/identity/kad_contacts/downloads/drain_events - events polled). uniffi 0.28 proc-macro (`setup_scaffolding!`); a `uniffi-bindgen` bin generates the bindings from the compiled cdylib. VALIDATED here: crate compiles, a Rust-side test drives the full lifecycle + reads events through the FFI types, and `uniffi-bindgen generate --library ... --language swift` emits mule_ffi.swift (open class MuleEngine + all records/enums). Needed a `Download::name()` accessor. On-device wiring waits for the Mac. |
| 8 | `ios/padMule` SwiftUI shell + lifecycle + sideload | (implemented directly) | **BUILDS - a real arm64 .ipa exists (2026-07-16), CI GREEN ON THE FIRST RUN.** Path C from [[mac-toolchain-setup]]: no Apple hardware - a GitHub-hosted macOS runner builds it. `ios/project.yml` (XcodeGen; pbxproj generated in CI, never committed; wires uniffi's module.modulemap + `-lmule_ffi`; iPad-only; deployment target iOS 16 so an older-SDK build installs on iPadOS 26). `ios/padMule/Sources`: PadMuleApp (ScenePhase -> pause/resume, only on `.background`), EngineModel (blocking FFI calls off the main thread; polls `drainEvents()`), ContentView (all three HARD [[lifecycle-and-reactivation]] requirements: honest foreground-only notice, Reconnecting banner, per-transfer Paused badges). `.github/workflows/ios-build.yml` -> `padMule.ipa` artifact, UNSIGNED, needing NO Apple secrets (AltStore re-signs at install; legit because padMule is sideload-only). VERIFIED by downloading the artifact: 588 KB .ipa -> `Payload/padMule.app/padMule` is a **Mach-O 64-bit arm64 executable**; Info.plist = us.ajbconsulting.padMule / MinimumOSVersion 16.0 / UIDeviceFamily [2]; and the Rust engine is genuinely linked in (432 uniffi/mule_ffi strings, `mule_ffi_rustbuffer_free`, `EngineStateFfi`, the "Reconnecting..." string). REMAINING: sideload it to the device and see it run (AltStore + AltServer on the Windows host; Developer Mode on the iPad); then real server/Kad wiring behind the UI. |
| 8b | on-device search + download + HighID/LowID surfaced | (implemented directly) | **DONE + on-device-proven (2026-07-16/17).** Search + add-download exposed through the FFI (`MuleEngine::search`/`add_download`, SearchHit/AddOutcome records) and wired to a SwiftUI search box + Get buttons. `finish_download` re-derives the whole-file ed2k hash (the only check for a single-part file) before saving to Documents (Files-app visible). ServerInfo made durable state + polled snapshot after the "an event is not state" bug hid the ID type. FULL LOOP PROVEN ON THE IPAD: a `test` search -> Get -> a 168KB .doc pulled from one HighID source -> hash-verified -> saved -> opened in Files. Two public-IP leaks aimed at the screenshotted screen closed. |
| 8c | on-device feature round: uploads, cancel, Kad-in-search, unicast HighID | (implemented directly) | **DONE (2026-07-17).** Four features on the running app: (1) **upload/serve** completed files + a "Share uploads"/Leech-Mode toggle (`share.rs` serve_shared reads blocks off disk; the listener PEEKS the first packet to tell a leecher from a called-back source; AtomicBool sharing switch + 8-slot cap; `serve_inbound`). (2) **cancel/delete** a download (cooperative AtomicBool cancel checked in take_blocks + the fetch loops; `.part` deleted; SwiftUI swipe-to-delete). (3) **Kad keyword search merged INTO the search box** (server + Kad concurrently via `tokio::join!` over the disjoint link+node fields; Kad FileResult -> synthetic tagged SearchResultFile so ONE catalog pass dedupes across both by hash; either half may be absent). (4) **on-device HighID via UNICAST SSDP** M-SEARCH at the inferred gateway (`upnp::discover_unicast`; `map_port` falls back multicast->unicast; iOS has no gateway API so infer .1/.254 of our /24; `mule-cli upnp-unicast` for live checks). Feature 4 was initially LIVE-UNVERIFIED (the Xfinity XB8's UPnP toggle is cosmetic - it never answers SSDP, confirmed exhaustively from Windows natively), but is now **LIVE-VALIDATED (2026-07-17)**: Anthony bridged the XB8 behind a TP-Link Archer BE9700, and `mule-cli upnp-unicast 4662` mapped the port against the BE9700's real IGD and returned the real public IP (no double-NAT) - proving the exact iOS unicast-SSDP path end to end. Then confirmed ON THE IPAD itself: padMule earned HighID, the "Port mapping" row read "UPnP: mapped port 4662", and the BE9700's UPnP client list shows `padMule 192.168.0.182 4662->4662`. (Root cause of the earlier LowID: a leftover permanent 4662->dev-box mapping from a validation run squatted the port + a lenient query masked it; fixed with delete-then-add + an honest query.) See [[net-highid-and-port-forwarding]]. Also landed: root LICENSE (GPL v2) + NOTICE + README. 374 workspace tests, clippy + fmt + ASCII clean. |
| 8d | search-panel eMule parity + launch splash + app icon | docs/superpowers/plans/2026-07-17-search-richness-and-splash.md | **DONE + MERGED to main (2026-07-18).** Search now matches eMule's SearchListCtrl FUNCTIONALITY (touch-native, not the 15-col grid): rich rows (New/Downloading/Have status dot, type + media metadata line, complete-sources), client-side sort (7 keys asc/desc) + filter (name/type/trusted/hide-have), and a detail sheet (all fields, ed2k link copy, Download, Search-related). Engine `catalog` surfaces type + media tags it already receives (FT_FILETYPE/FT_MEDIA_* pinned from opcodes.h) + `hit_status` (New/Downloading/Have). FFI `SearchHit` + `HitStatusFfi`. No wire change; sort/filter is pure client-side over the fetched set. Also: a 3s launch splash (2px-stroked splash.png) and the app icon (mascot; white corners flood-filled to an opaque 1024 square since iOS icons cannot have alpha). 379 Rust tests, clippy/fmt/ASCII clean; Swift verified by CI. Brainstorm->spec->plan->execute (specs/plans in docs/superpowers/). |
| 8e | code-fix round (7 fixes from the 2026-07-18 lint) | - | **DONE (2026-07-18).** See the code-fix-round section below. |
| 8f | GUI round (splash 7s; eMule-style top-toolbar nav; real Shared library screen) | - | **DONE (2026-07-18).** Icons Search/Transfers/Shared/Status switch one content area, inline title (never collapses); Shared screen lists the persisted library via FFI `shared_files`. |
| 8g | 0.70b first feature slice (IP filter, search history, wire search filters) | [[emule-070b-features]] | **DONE (2026-07-18).** IP-filter blocklist (ipfilter.dat/.p2p) gating sources+inbound; persisted search recents; availability+size filters pushed onto OP_SEARCHREQUEST. All gated incl. the differential test. |
| 8h | 0.70b second feature slice (server ratings on search rows; per-file unshare) | [[emule-070b-features]] | **DONE (2026-07-18).** Catalog parses FT_FILERATING (masked, aMule decode) -> rating pill + Fake-flag; per-file unshare drops a file from the library + known.met (keeps the file). Comments (OP_FILEDESC, post-connect) deferred. |
| 9 | (v1.1) seedbox mode | - | not started |

## CODE-FIX ROUND (2026-07-18)

Seven fixes from the full-repo lint pass, each gated (383 workspace tests +
clippy + fmt + the amuled differential test still passes byte-for-byte on all
three files). Wire-touching fixes were checked against eMule 0.50a first.

1. **Persisted Kad identity now used.** `KadNode::bind` generated a fresh random
   Kad ID + UDP install key every run, re-keying Kad on every app start (the
   failure `identity.rs` exists to prevent - lost routing reciprocity, stale UDP
   verify keys peers stored for us). New `bind_with_identity` takes
   `NodeIdentity::{kad_id, kad_udp_key}`; `start_kad` passes them. `bind()` keeps
   the fresh-identity path for one-shot CLI use.
2. **Resumed downloads now fetch (+ Kad merged into source-finding).** `start`
   loaded `.part` downloads into the registry but only `add_download` spawned a
   fetch task, so a resumed download progressed only via an inbound callback.
   Extracted `find_sources` (server get_sources AND Kad `resolve_sources`
   concurrently via `tokio::join!`, one `SourceRegistry` - either half may be
   absent, so a serverless client can now download what Kad search found),
   `request_callbacks`, `spawn_fetch`; new `resume_fetches` drives every
   incomplete resumed download through the same pipeline once the network is up.
3. **Shared library persists (`known.met`).** The share list was session-only, so
   uploads forgot their library on every launch. `finish_download` appends each
   verified file to a byte-compatible `known.met` (idempotent by hash; large-file
   header + U64 size past the 32-bit boundary), storing the ACTUAL on-disk name so
   the path rebuilds as `downloads_dir/name`; `start` reloads and re-shares every
   entry whose file still exists (skips ones deleted from Files).
4. **Real upload queueing (OP_QUEUERANKING).** At capacity padMule used to answer
   OP_FILEREQANSNOFIL - lying "no file" about a file it holds. Now
   `share.rs::UploadGate` serves filename/status truthfully and, at
   OP_STARTUPLOADREQ, grants a free slot or QUEUES the peer (bounded,
   UPLOAD_QUEUE_CAP=32), sends its 1-based OP_QUEUERANKING (0x60, exactly 12-byte
   payload per eMule 0.50a - receivers hard-reject any other size), and grants a
   freed slot IN PLACE on the held connection. Rank sent ONLY in reply to the ask
   (eMule flood-bans 3 unsolicited ranks). DELIBERATELY SCOPED to the held
   connection: no cross-connection queue persistence, no slot-grant dial-out, no
   UDP OP_REASKFILEPING - those are always-on desktop-seedbox parts that do not
   fit a foreground-only iOS client. Rank is FIFO (wire-neutral policy; eMule's
   score-ordering can layer on later - `upload_queue.rs` holds that scoring, still
   unwired). Not amuled-differential-testable (the amuled-pull direction is
   blocked); covered padMule-to-padMule.
5-6. **Two "hardening" items turned out to be already faithful** - see
   [[decisions-and-lessons]] (verifying against eMule BEFORE fixing avoided two
   wire-divergence regressions): crypt-bit sanitization (eMule reads the bits raw
   too; predicates byte-identical) and sig-before-pubkey (eMule drops it too).
   Doc corrections only.
7. **Nits:** `KadError::NotReady` (stop overloading `NotDecryptable`); collapse a
   duplicated `verify_ready_parts` branch; the `fetch-complete` size-filter casts
   (min saturates, max omits the 32-bit wire filter over 4 GiB so the client-side
   u64 filter enforces it); drop a redundant `Duration` alias; remove the unused
   `mule-proto` dep from `mule-ffi`; doc-only notes on the ED2Kv2 decompress
   asymmetry, `choose_search_method`, and the iOS-16 `onChange` form.

### Adversarial review round (same day)

A 5-reviewer workflow (one per fix, each finding independently verified) found 8
distinct REAL bugs - several regressions from Fixes 3 and 5 - all fixed and
re-gated (385 tests, clippy/fmt, differential still byte-for-byte):

- **Upload-cap bypass (regression):** OP_REQUESTPARTS streamed data without a
  granted slot, so a peer skipping OP_STARTUPLOADREQ ignored the cap + queue.
  Fixed: parts require a held permit (ungated test/differential path unaffected).
- **Queue-counter leak:** a disconnect while queued skipped the `waiting`
  decrement, ratcheting the count until nobody could queue. Fixed with a RAII
  `WaitTicket` guard.
- **Unbounded serve sessions (regression):** moving the slot check into the
  upload arm left idle pre-upload connections holding a task+fd forever. Fixed
  with a 60s idle-read timeout + a 120s bound on the queued wait.
- **known.met race + torn write:** concurrent finishers lost entries and a torn
  write reset the library. Fixed: serialize with a lock + atomic temp+rename.
- **Stale re-share:** a file replaced at the same on-disk path was served under
  the old hash. Fixed: `load_shared_library` verifies the on-disk size matches.
- **Startup stall:** `resume_fetches` ran serially inline holding the FFI engine
  lock, so dead resumed downloads could delay `pause()` past the iPadOS suspend
  window. Fixed: report Running first, then bound the pass (8s total / 4s each).
- **Rank vs grant order:** documented as best-effort (eMule ranks are advisory
  too), not a code change.
- **fetch-complete max-size filter:** see nit above (folded into Fix 7's fix).

LESSON: the same-day adversarial review paid for itself - it caught cap/queue
bypasses and a persistence race that the 383-test suite and the differential
test (which exercises the DOWNLOAD direction, not serve) both missed. Re-review
any change that reshapes a hot path, and treat "moved the check" as "removed the
check until proven otherwise".

## ENGINE GOES LIVE BEHIND THE UI (2026-07-16)

`Engine::start()` no longer just loads state - it brings the real network up, so
the iPad app is a real client. Live-verified from an EMPTY config dir (exactly
what a fresh install sees):

```
Status("Fetching network lists...")   <- had neither file
Kad { contacts: 133 }                 <- fetched nodes.dat
Status("Opening port...")
Server("Connected to <server> (HighID, id <client-id-hex>)")
Kad { contacts: 21 }                  <- live Kad bootstrap
State(Running) / Status("Connected")
```

Three things worth knowing:

1. **The fresh-install gap.** Nothing fetched `server.met`/`nodes.dat` - they were
   hand-placed on the dev box, so a real install knew NO servers and NO Kad
   contacts and could reach nothing. New `bootstrap.rs` fetches both from
   upd.emule-security.org. We fetch rather than bundle because a bundled list ROTS
   (the 2026-07-13 log records exactly that failure). The HTTP is hand-rolled,
   byte-safe (these files are BINARY - UTF-8 decoding corrupts them) and runs on a
   raw socket, which **sidesteps iOS ATS entirely** (ATS governs URLSession, not
   BSD sockets) - so a cleartext http:// fetch works on-device with no Info.plist
   exemption. Fetches are best effort + validated (an HTML error page must never
   be saved as a server list); a failure means we come up offline, never a crash.
2. **ORDER MATTERS: listener BEFORE login.** The server decides HighID vs LowID by
   connecting back to the port we advertise. Without a listener we got **LowID**;
   binding it first flipped the same code to **HighID** on the next live run. The
   server's probe is a bare TCP connect+close, so merely ACCEPTING passes it.
   `map_port()` additionally tries UPnP ([[mac-toolchain-setup]] n/a; see
   [[net-highid-and-port-forwarding]]) so a real device with no hand-made router
   rule can still earn HighID.
3. **pause/resume now moves real sockets.** pause() drops the Kad UDP socket and
   aborts the listener (freeing 4662); resume() rebinds the port FIRST (same
   HighID reason), re-runs the server handshake, and re-bootstraps Kad - correct
   across an IP change, which is the point on a mobile device. `online_status()`
   is honest: it never claims "Connected" when nothing is.

Testing: the unit suite must never touch the network, so `Engine::set_offline(true)`
suppresses it (the engine tests went 2.67s -> 0.05s, proving they no longer dial
out). The real proof is `engine::live::fresh_install_goes_online_and_bootstraps_kad`
(`#[ignore]`d; run with `--ignored`), which asserts a fresh dir fetches both files,
logs in, and populates Kad. 352 tests.

REMAINING at the time (since landed as rows 8b/8c): search + add-download from
the UI - the engine could already do both; exposing them through the FFI facade
was the 8b work.

## LIVE END-TO-END DOWNLOADS - THREE FILES COMPLETED (2026-07-16)

padMule downloaded THREE real files from the live eD2k network to completion,
one each from a keyword search for `pdf`, `wav`, `txt`, every one verified by
recomputing its ed2k hash and matching the search result:

| search | file | bytes | ed2k hash |
|--------|------|-------|-----------|
| txt | Chicks.txt | 1416 | c0e97d89f3cd58b42c38e15c15f27275 |
| wav | T.I. Feat. Rihanna - Live Your Life ( 2oo8).WAV | 5888780 | df13c362a9f3bc6c4a3b3014819c1462 |
| pdf | ESAMI URINE .pdf | 4232 | 40b3fc7ade0afa2c5b339ee3475192c8 |

(P2P content is uncontrolled; only the technical result - name/size/hash - is
recorded. The .WAV was an MP3 mislabeled by its sharer; padMule's job is a
hash-exact fetch of the named file, which it did.)

Driver: `mule-cli fetch-complete <server.met> <keyword> <out> [max_size]
[min_size]`. It logs in (binding a listener FIRST so the server's HighID
callback succeeds - HighID is what lets us receive LowID callbacks), searches,
catalogs (dedup/rank/trust), then sweeps candidates best-sourced-first and pulls
the first that completes. What it took to actually COMPLETE downloads (each a
real lesson, all client-side, zero wire changes):

1. **HighID is the key that unlocks the LowID source pool.** All three files
   completed only once we were HighID and listening. Two of the three (wav, pdf)
   were delivered by **firewalled LowID sources via OP_CALLBACKREQUEST** - we ask
   the server to tell the LowID peer to dial US; it connects back to our listener
   and streams the file. The wav's entire 5.9 MB arrived this way. See
   [[net-highid-and-port-forwarding]].
2. **Queue fast-bail.** eD2k sources ration upload slots; most answer
   OP_STARTUPLOADREQ with OP_QUEUERANKING (you are queued), not
   OP_ACCEPTUPLOADREQ. Sitting in a queue is dead time for a completion hunt, so
   `run_peer` now returns `TransferError::Queued` the instant it is queued -
   turning a 25 s dead-end into ~2 s and letting the sweep reach a free source
   fast. (A real background client would instead keep the slot and wait.)
3. **Diversity-aware sweeping.** A keyword can be SATURATED by one sharer's
   collection: "wav" returned 200 results that were ALL <100 KB Age-of-Empires
   game sounds from a SINGLE IP. Sweeping them is pointless (same busy peer). The
   fetcher records each HighID source that stalls and skips other files whose only
   source is that dead IP - so the sweep spends its time on DISTINCT sharers.
4. **`min_size` to escape a saturated keyword.** Because the tiny game-sound
   collection filled the server's 200-result cap, no diverse wav could surface.
   Asking the server for `wav` files >= 800 KB filtered the collection out and
   revealed real audio files from other sharers (the T.I. song among them).
5. **Progress-aware callback wait + per-candidate part dirs.** A LowID callback
   can take many seconds to connect and then streams the whole file. A fixed short
   wait abandoned the transfer mid-flight, and a shared `001.part` let the next
   candidate clobber it - which is exactly why an earlier run delivered a full
   5.9 MB file and then LOST it. Fix: each candidate downloads into its own
   directory, and we wait WHILE bytes keep arriving (patient before the first
   byte, bail a few seconds after progress stalls, hard cap 300 s). With that, the
   wav completed on candidate [1] via its own callback.
6. **Size-adaptive transfer config.** Tiny files sweep fast (12 s/peer, 1 round);
   larger files get sustained pulling (40 s/peer, 5 rounds). A partial HighID pull
   (331 KB of a 627 KB pdf before it stalled) confirmed multi-block HighID
   transfer on the live network too.

Files: `crates/mule-engine/src/catalog.rs` (search intelligence + trust),
`crates/mule-cli/src/main.rs::cmd_fetch_complete` (the fetcher + callback
listener), `crates/mule-engine/src/multi_source.rs` (queue fast-bail),
`crates/mule-engine/src/transfer_session.rs` (`TransferError::Queued`).

**Lesson:** completion on eD2k is a source-availability hunt, not a protocol
problem - the wire was already right (Wave 4 differential test). The wins were all
in HOW we pick files and spend time: earn HighID, use callbacks, fast-bail queues,
chase distinct sharers, and never abandon an in-flight callback. Recorded in
[[decisions-and-lessons]].

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
(Wave 4c); the differential vs a local amuled PASSED later the same day (see
the differential-test section above).

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
