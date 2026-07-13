# padMule Design Spec

Date: 2026-07-12
Status: approved design, pre-implementation
Author: Anthony Bufort (with Claude)

## 1. Goal

Port aMule 3.0.1 (a GPL eD2k/Kad P2P client) to run on an iPad Pro 4th gen
(A12Z, iPadOS). The deliverable is a native app that connects to eD2k servers
and the Kad network, searches, and transfers files with full amuled-class
feature parity, using on-disk formats byte-compatible with desktop aMule/eMule.

This is a REWRITE of the engine in Rust, not a port of the C++. Upstream
`amule-3.0.1/` is retained as the behavioral reference oracle for differential
testing, and is never linked or shipped.

Grounding references (read before implementing any subsystem):
- Protocol/format facts: `docs/raw/amule-upstream-reference-2026-07-12.md`,
  indexed by `docs/wiki/protocol-reference.md`.
- Platform constraints: `docs/raw/ipados-constraints-research-2026-07-12.md`,
  indexed by `docs/wiki/ipados-constraints.md`.
- Locked decisions: `docs/wiki/decisions-and-lessons.md`.

## 2. Locked decisions (context for every choice below)

1. Engine = new Rust workspace; C++ tree = oracle only.
2. Deploy = no Mac: engine develops/tests on WSL2 (Linux host target); iOS
   `.a`/XCFramework built on a hosted macOS CI runner; device install via
   AltStore/Sideloadly from Windows with a free Apple ID.
3. v1 scope = full amuled parity (eD2k + Kad, search, multi-source transfers
   with AICH recovery, uploads + credits, source exchange, obfuscation, IP
   filter, UPnP, categories, EC, byte-compatible files).
4. On-disk = byte-compatible with upstream `.met`/`.part`/`nodes.dat`/prefs.
5. Seeding = foreground-only in v1; background = graceful pause; a supported
   "seedbox mode" (screen-on, plugged in) is a v1.1 toggle.

## 3. The single hardest constraint: lifecycle

iPadOS suspends the app roughly 30 s after it is backgrounded. Threads freeze
and ALL TCP/UDP sockets are reclaimed by the kernel (subsequent use returns
EBADF/ECONNABORTED). No supported mechanism keeps custom-protocol sockets alive
across suspension. Therefore the honest engine model is FOREGROUND-ONLY, and
the engine is built around a lifecycle state machine from day one, not as an
afterthought:

- `Foreground`: full engine. Servers connected, Kad live, transfers running.
- `Backgrounding` (willResignActive/didEnterBackground): a `beginBackgroundTask`
  window (~30 s, treat as non-contractual) to flush block buffers, checkpoint
  every `.part.met`, persist Kad `nodes.dat`, and quiesce queues. Then the app
  suspends.
- `Suspended`: engine frozen; on-disk state is the source of truth.
- `Foregrounding` (willEnterForeground): rebuild - new sockets, reconnect
  servers, re-bootstrap/refresh Kad, re-issue source and A4AF requests.

Design rule: every socket is disposable across a lifecycle transition. The code
path for "peer dropped us" and "we were suspended" is the SAME reconnect path.
A dropped socket is a rebuild event, never a fatal error. Kad membership is not
maintained across suspension; it is re-bootstrapped on each foreground return.

**Clean status + clean reactivation are a hard requirement** (full spec:
`docs/wiki/lifecycle-and-reactivation.md`). Two obligations follow from the
suspend model:

- **Honest status to the user.** The engine exposes a rich connection-state
  model (ServerState/KadState, plus a per-transfer state that distinguishes
  lifecycle-Paused from Stalled from Error) as an EVENT STREAM, so the UI never
  shows a stale "Connected" that is actually dead. On foreground return the UI
  shows "Reconnecting..." immediately; a background pause is presented calmly as
  by-design ("padMule pauses when not in the foreground"), never as an error.
- **Clean reactivation.** The UI's scene-phase observer calls explicit engine
  `pause()`/`resume()` over FFI (not implicit socket-death detection).
  `resume()` is idempotent, leak-free, fast/non-blocking, correct on a changed
  network/IP (re-login from scratch since a changed public IP flips
  HighID<->LowID), and progress-safe (resume from the gap list, no re-hash).

This shapes the engine's public API from Wave 3c (the state model + pause/resume
+ event stream are designed in, and the CLI harness exercises a simulated
pause/resume), not just Wave 8's SwiftUI wiring.

## 4. Architecture

A Cargo workspace developed and tested on WSL2, compiling to two surfaces: a
Linux CLI (development + differential tests) and a static aarch64-apple-ios
library the SwiftUI app links in-process. No socket sits between the UI and the
engine; the UI calls Rust directly through UniFFI. EC is built as a parity /
desktop-control feature, NOT as the internal UI boundary.

### 4.1 Crates

| Crate | Responsibility | Depends on |
|-------|----------------|------------|
| `mule-proto` | Pure codec, no I/O: packet framing, tag system, opcodes, MD4 + AICH hashing, search-expression encoding, RC4 obfuscation handshakes, secure-ident (RSA/DH). | crypto crates |
| `mule-files` | Byte-compatible readers/writers: known.met, part.met (+64-bit + gap lists), server.met, nodes.dat, prefs, clients.met, ipfilter.dat. | `mule-proto` |
| `mule-engine` | The reactor: server sessions, per-peer client state machines, download/upload queues, chunk selection, credits, source exchange, corruption black-box, bandwidth throttler. Owns the tokio runtime + the replicated timer cadence. | `mule-proto`, `mule-files` |
| `mule-kad` | Kademlia: 128-bit routing table (zones/bins), UDP listener, obfuscation, search/publish FSM, bootstrap. | `mule-proto` |
| `mule-ec` | External Connections server (framing, zlib, tag tree, MD5-salt auth). | `mule-proto`, `mule-engine` |
| `mule-cli` | Linux binary driving the engine headless; hosts the differential-test harness. | engine, kad, ec |
| `mule-ffi` | UniFFI: Engine/Kad as `Arc` interfaces, async methods, callback interfaces for progress/events. The only iOS-specific crate. | engine, kad |
| `ios/padMule` | SwiftUI app: transfer list, search, server/Kad status, settings; thin ViewModel over `mule-ffi`; lifecycle wiring. | `mule-ffi` xcframework |

`amule-3.0.1/` links nowhere.

### 4.2 Async + FFI model

One tokio multi-thread runtime (modest worker pool) owns all sockets and
timers. `setrlimit(RLIMIT_NOFILE, ...)` is raised at startup (clamped to
`kern.maxfilesperproc` on Darwin) before scaling to many peers. The engine core
keeps aMule's BSD-socket reactor model (a single shared UDP socket for Kad +
many TCP peer sockets); it does NOT use Network.framework (which models UDP as
one-flow-per-endpoint, wrong for a shared Kad socket). Transport is written on
tokio/mio, which sets `SO_NOSIGPIPE` per fd on Apple; `signal(SIGPIPE, SIG_IGN)`
is set once at init only if any raw non-socket fd I/O is added.

FFI: Swift sends commands into the engine and receives snapshots + an event
stream (progress, new source, transfer state change) through UniFFI callback
interfaces - the UI never polls and never blocks on I/O. Large/hot payloads
cross as opaque `Arc` handles pulled lazily, not copied per call. Every
`#[uniffi::export]` entry is panic-safe: catch and convert to a typed error so a
Rust panic never unwinds into Swift. Async methods expose cooperative
cancellation from the start.

## 5. Data flow

Steady state (foreground): SwiftUI action -> ViewModel -> `mule-ffi` command ->
engine posts it onto the runtime -> sockets act -> engine emits events ->
callback interface -> ViewModel `@Published` -> SwiftUI re-render.

A download source progresses (per the upstream reference): locate source
(server OP_GETSOURCES / Kad source search) -> connect + Hello handshake
(optionally obfuscated) -> request file -> receive queue ranking -> get an
upload slot -> request blocks (180 KiB, batched) -> receive OP_SENDINGPART /
OP_COMPRESSEDPART -> write into the `.part` file at the right offset -> update
the gap list in `.part.met`. On completion the file is hashed and, if the AICH
tree is present, verified.

## 6. On-disk layout (iPadOS-specific, from the constraints research)

- In-progress part-files + `.part.met` + Kad `nodes.dat` + prefs live in
  `Library/Application Support/padMule/incomplete/` with `isExcludedFromBackup =
  true` and DEFAULT data protection (class C - writable while the device is
  locked as long as the app is running; do NOT opt into NSFileProtectionComplete
  or the download stalls when the screen locks).
- Completed files: atomic same-volume move into `Documents/` on finish;
  `Documents/` holds only finished files (it is user-deletable).
- Never use `Caches/` or `tmp/` for anything a download must keep (OS purges
  them).
- Free-space guarding is a first-class engine feature: query available capacity
  before preallocating a part-file and while writing; on ENOSPC, pause the
  transfer and surface an error - never crash. (aMule preallocates full-size
  part-files; that preallocation is gated on the free-space check.)
- Files-app exposure: `UIFileSharingEnabled = YES` +
  `LSSupportsOpeningDocumentsInPlace = YES`. No File Provider extension in v1
  (also avoids the blocked App-Groups entitlement).
- Memory: budget ~3 GB on the A12Z (not 6). Stream blocks to disk; cap in-RAM
  structures (source lists, hashsets, up/down buffers) against that budget; wire
  `didReceiveMemoryWarning` into the engine to shed caches. Ship the
  increased-memory-limit entitlement (best-effort; unverified on A12Z).

## 7. Error handling + resilience

- Socket teardown (EBADF/ECONNABORTED after suspension, or ordinary peer drop):
  never fatal; the session transitions to reconnect/re-source. Same path for
  both causes.
- Corruption: port aMule's CorruptionBlackBox. A failed 180 KiB block's part is
  re-hashed, the bad range re-marked missing and attributed to its source; AICH
  recovery repairs from the SHA-1 tree when available.
- Malformed wire data: decoders return `Result`; a bad packet drops that
  peer/message, never the process.
- FFI boundary: panic-safe as in 4.2.
- Free disk: as in section 6.

## 8. Verification (the Karpathy oracle loop)

A subsystem is "done" only when it matches aMule, proven by one or more of:

1. Byte-compat round-trip (`mule-files`): read a real aMule
   known.met/part.met/server.met/nodes.dat/clients.met, re-emit, assert
   bit-identical. Fuzz with files produced by a running amuled.
2. Differential protocol tests (`mule-cli` on Linux): stand up real `amuled`
   built from `amule-3.0.1/` plus a stock client; capture handshakes, searches,
   and a full multi-source transfer; assert `mule-engine` produces
   wire-equivalent exchanges and downloads identical bytes with the identical
   eD2k file hash.
3. Vector tests (`mule-proto`): MD4/AICH against known ed2k-hash vectors,
   ESPECIALLY the exact-multiple-of-PARTSIZE edge case (part count =
   floor(size/PARTSIZE)+1); RC4 obfuscation and secure-ident against captured
   aMule sessions.

CI gate: Linux jobs run `cargo test` + clippy + the differential harness on
every change; a macOS job builds the iOS XCFramework (uniffi-bindgen +
`xcodebuild -create-xcframework`, device + simulator arm64, no lipo, bitcode
off). "Done" requires a green differential run, not just unit tests.

## 9. Known upstream caveat

`amule-3.0.1/` in this repo is a locally MODIFIED tree (the recon flagged
behavioral deltas: GetMaxSlots floor 20, adaptive sub-packet size, zlib level 1,
a global download token bucket, >3-block request batching, async write/hash
threads, ALPHA_QUERY=5 vs classic 3). Wire formats are identical to upstream;
POLICY may differ. Per subsystem, decide whether padMule matches pristine
aMule/eMule behavior or this tree's, and diff against the pristine zip
(`/mnt/c/Users/ajbuf/Downloads/amule-3.0.1.zip`) when it matters. Default:
match pristine upstream behavior unless a modification is clearly an
improvement worth keeping.

## 10. Build order (implementation waves)

Each wave ends at a differential/round-trip gate. Detailed steps go in the
implementation plan (writing-plans).

1. Workspace + `mule-proto` primitives: framing, tags, MD4, AICH, search-expr;
   vector tests incl. the exact-multiple hash case. Gate: hash vectors pass.
2. `mule-files`: byte-compatible known.met/part.met/server.met/nodes.dat.
   Gate: round-trip real files bit-identically.
3. `mule-engine` eD2k core: server login/search/get-sources; single-source
   download to a `.part` file. Gate: download a real file from a real server via
   `mule-cli`, hash matches.
4. Multi-source + upload + queue + credits + source exchange + corruption
   handling. Gate: differential transfer vs amuled.
5. Obfuscation + secure ident. Gate: obfuscated session interop with amuled.
6. `mule-kad`: routing table, bootstrap, keyword + source search/publish.
   Gate: join the real Kad network, resolve a known hash to sources.
7. `mule-ec` + `mule-cli` parity: EC server, IP filter, UPnP, categories.
   Gate: amulegui/amulecmd drives the engine over EC.
8. `mule-ffi` + `ios/padMule`: UniFFI boundary, SwiftUI shell, lifecycle state
   machine, storage plan, CI XCFramework build, sideload. Gate: search +
   download on the physical iPad; background/foreground pause/resume works.
9. (v1.1) seedbox mode toggle.

## 11. Out of scope for v1

Background/screen-off seeding (fragile keepalive); App Store distribution;
share/widget extensions (App Groups blocked); iCloud sync; proxy support
(optional, deferred); Windows/macOS desktop builds of padMule (the engine
stays portable, but no desktop UI is a goal).
