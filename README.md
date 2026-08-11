# padMule

An **eD2k / Kademlia peer-to-peer client for the iPad** - a from-scratch **Rust**
engine behind a native **SwiftUI** interface.

padMule is not a UI reskin of a desktop app. The engine is rewritten from scratch
to run where iPadOS clients cannot, but it stays faithful to the network: it
speaks the real eD2k and Kad protocols and its on-disk formats are byte-compatible
with the desktop clients, so an aMule (or eMule) download and a padMule download
can pick up where the other left off.

wxWidgets (aMule's GUI toolkit) has no usable iOS port, so padMule reimplements
the engine below the UI rather than porting the desktop app.

## Where padMule stands relative to eMule and aMule

padMule is a new implementation of an old, well-established protocol. Getting
that right means being deliberate about *which* existing client answers *which*
question - because on the details they do not always agree.

**eMule 0.50a is the authority for anything that leaves the machine**: packet
layouts, opcodes, tag numbers, on-disk formats, hashing. Most of the live
network runs eMule or a client derived from it, so when padMule and eMule
disagree about a byte, padMule is wrong by definition. Every wire decision in
this repo is traceable to a line of eMule source.

**aMule is the reference padMule can actually run.** It is the client the
differential tests transfer against in both directions - padMule downloading
from a real aMule byte-for-byte, and a real aMule downloading from padMule - and
it is the authority for behaviour that never reaches the wire: queue policy,
retry pacing, how many peers to dial at once. A vendored, unmodified copy of
aMule 3.0.1 lives in `amule-3.0.1/` for exactly this.

**Where they conflict, padMule follows eMule.** This is not hypothetical.
Current aMule development defines a known.met tag at `0x55`, a number eMule
already uses for something else, so padMule keeps eMule's meaning. Current aMule
also raises the in-flight block-request ceiling well past what eMule requests,
citing eMule as precedent for a number eMule does not actually use - so padMule
adopts the part that is genuinely eMule's and treats the rest as aMule's own
choice. Divergences like these are recorded in the local-only `docs/wiki/` with citations on
both sides rather than settled from memory.

The point is not that one project is better. They answer different questions,
and a client that copies whichever source it read most recently ends up
compatible with neither.

padMule also draws on the wider ecosystem, and adds its own:

- **eMule 0.70b** - a community fork mined for features: IP filter, search
  history, wire-side search filters, download categories, file ratings and
  comments, a per-source detail view, and more.
- **eMuleAI** - a modern, actively maintained fork surveyed for ideas; GPL
  compatible, so what is worth borrowing can be.
- **padMule's own** - a Leech-Mode switch that turns uploading off outright,
  client-side download categories, and a padMule-to-padMule enhancement channel.
  A few additions are forced by the platform rather than chosen: HighID over
  *unicast* UPnP, because iOS gives a sideloaded app no multicast, and an honest
  foreground-only transfer model, because iPadOS suspends a backgrounded app and
  reclaims its sockets.

## Status

padMule runs on a real iPad, built with no Apple hardware in the loop (GitHub
Actions produces an unsigned `.ipa`, which is re-signed at install time with a
free Apple ID via Sideloadly - the path proven here; AltStore may also work but
failed for us). What works today, proven on-device:

- **Connect** to live eD2k servers and bootstrap the Kad DHT.
- **Search** the connected server and the Kad network together, deduped and
  ranked into one list, with sort/filter, file-rating badges, and remembered
  recent searches.
- **Download** a file from its sources, **verify** it against its eD2k hash, and
  save it to the Files app (On My iPad > padMule); sort downloads into
  **categories**.
- **Share** completed files back to other peers (with a Leech-Mode toggle to turn
  uploading off), and **rate or comment** your own shared files - served to
  downloaders the way eMule does.
- **Cancel** a download or **unshare** a file (swipe), with an **IP blocklist**
  (`ipfilter.dat` / `.p2p`) filtering both sources and inbound peers.

Reachability follows the usual eD2k rules: a LowID client downloads fine but
cannot receive inbound connections, so a device behind NAT stays LowID unless its
gateway forwards the listening port. padMule asks the gateway to do that over
UPnP (multicast on desktop, unicast on iOS, where multicast is unavailable); this
only earns HighID on a gateway that has UPnP enabled.

The design, protocol notes, and decision history are kept in `docs/wiki/`,
which is a LOCAL-ONLY knowledge base and is deliberately not published - a
clone of this repository will not contain it. The code, its comments, and the
citations in them are the public record.

## Architecture

A Cargo workspace holds the engine; a SwiftUI app sits on top of it through a
UniFFI-generated binding.

| Crate / path | Responsibility |
|---|---|
| `crates/mule-proto` | eD2k wire codec: packet framing, tags, ed2k/MD4 hashing, Kad 128-bit IDs. |
| `crates/mule-files` | Byte-compatible on-disk formats: `server.met`, `known.met`, `part.met`, `nodes.dat`. |
| `crates/mule-kad`   | Kademlia: routing bin-tree, message codecs, UDP obfuscation, the event-driven iterative lookup, and anti-abuse hardening. |
| `crates/mule-engine`| The live engine: server link, peer transfers, multi-source download, uploads, Kad, UPnP/NAT-PMP, and the `Engine` facade the UI drives. |
| `crates/mule-ffi`   | UniFFI seam: wraps `Engine` in a synchronous, FFI-friendly facade and generates the Swift bindings. |
| `crates/mule-cli`   | A command-line harness used to exercise the engine against the real network. |
| `ios/`              | The SwiftUI app and its XcodeGen project spec. |
| `amule-3.0.1/`      | Upstream aMule, vendored unchanged: the runnable oracle the differential tests transfer against, and the reference for wire-neutral behaviour. Never linked or shipped. |

## Building and testing the engine

The Rust workspace builds and tests on any desktop (no Apple toolchain needed):

```bash
cargo build --workspace
cargo test  --workspace
```

`mule-cli` can drive the engine against the live network, for example:

```bash
cargo run -p mule-cli            # prints the command list
cargo run -p mule-cli -- login-any <server.met>
cargo run -p mule-cli -- kad-keyword <nodes.dat> <keyword>
cargo run -p mule-cli -- upnp-unicast 4662   # the port-mapping path the iPad uses
```

## Building for the iPad

There is no Mac in the pipeline. GitHub Actions (a macOS runner) generates the
Xcode project with XcodeGen, builds the Rust static library and its Swift
bindings, and produces an **unsigned** `.ipa` as a build artifact. That artifact
is re-signed and installed on-device with a free Apple ID using **Sideloadly**
(the proven path; AltStore/AltServer failed here with error -22411). The setup
is documented in the local-only `docs/wiki/` knowledge base, which is not part
of this repository.

### Checking that an .ipa matches this source

The build publishes a **SHA-256 digest of the `.ipa`** in two places: the run
summary on the workflow run page, which is readable without downloading
anything, and a `padMule.ipa.sha256` file uploaded next to the `.ipa` in the
build artifact. From the directory holding the downloaded `.ipa`:

```bash
shasum -a 256 -c padMule.ipa.sha256   # macOS
sha256sum -c padMule.ipa.sha256       # Linux
```

The commit is stamped inside the app as well, as `CFBundleVersion` in
`Payload/padMule.app/Info.plist`, so an `.ipa` names its own source commit even
offline.

**What this proves:** the `.ipa` you hold is byte-for-byte the file that run
produced from that commit.

**What it does not prove:** that the build is reproducible - it is not, and
re-running the workflow on the same commit produces a *different* digest (the
zip container stores per-run file mtimes, and the runner image floats the
toolchain versions); that the runner behaved honestly; or that the toolchain was
uncompromised. The digest
is published by the same system that built the artifact, so it is a consistency
check - it catches a swapped, truncated or edited download - and not an
independent attestation. It is worth exactly as much as your trust in that
workflow.

One practical limit: re-signing **rewrites** the `.ipa`. Sideloadly and `zsign`
both produce a new file with a new digest, so the check has to happen on the
unsigned artifact, before it is signed.

## License

padMule is free software licensed **GPL-2.0-or-later**. See `LICENSE` for the
full text and `NOTICE` for the derivation.

padMule is a derivative work in the aMule / eMule lineage: it reimplements and
draws on aMule 3.0.1 (Copyright the aMule Team) and eMule (Copyright the eMule
Team), both GPL-2.0-or-later. The vendored `amule-3.0.1/` tree keeps its own
license and author files intact. Any code adopted from aMule, eMule, or another
fork retains its original notices.

## Responsible use

padMule is a peer-to-peer client for a network that carries uncontrolled,
user-supplied content. It is provided for lawful use only. You are responsible
for complying with the copyright law and terms that apply where you are.

---

Author: Anthony Bufort <ajbufort@ajbconsulting.us>
