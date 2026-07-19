# padMule

An **eD2k / Kademlia peer-to-peer client for the iPad** - a from-scratch **Rust**
engine behind a native **SwiftUI** interface.

padMule is not a UI reskin of a desktop app. The engine is rewritten from scratch
to run where iPadOS clients cannot, but it stays faithful to the network: it
speaks the real eD2k and Kad protocols and its on-disk formats are byte-compatible
with the desktop clients, so an aMule (or eMule) download and a padMule download
can pick up where the other left off.

It draws on the whole lineage of the network's software, and adds its own:

- **aMule 3.0.1** - vendored in-repo as the reference oracle for wire-neutral
  behavior, and the client padMule differential-tests its transfers against.
- **eMule 0.50a** - the authority for the wire protocol and on-disk formats;
  padMule matches its bytes.
- **eMule 0.70b** - a community fork mined for features: IP filter, search
  history, wire-side search filters, download categories, file ratings and
  comments, a per-source detail view, and more.
- **padMule's own** - features that only make sense on an iPad: a Leech-Mode
  upload toggle, client-side categories, HighID over unicast UPnP (iOS blocks the
  multicast kind), and a padMule-to-padMule enhancement channel.

wxWidgets (aMule's GUI toolkit) has no usable iOS port, so padMule reimplements
the engine below the UI rather than porting the desktop app.

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

The design, protocol notes, and every decision are written up in `docs/wiki/`
(start at `docs/wiki/index.md`).

## Architecture

A Cargo workspace holds the engine; a SwiftUI app sits on top of it through a
UniFFI-generated binding.

| Crate / path | Responsibility |
|---|---|
| `crates/mule-proto` | eD2k wire codec: packet framing, tags, ed2k/MD4 hashing, Kad 128-bit IDs. |
| `crates/mule-files` | Byte-compatible on-disk formats: `server.met`, `known.met`, `part.met`, `nodes.dat`. |
| `crates/mule-kad`   | Kademlia routing table and message types. |
| `crates/mule-engine`| The live engine: server link, peer transfers, multi-source download, uploads, Kad, UPnP/NAT-PMP, and the `Engine` facade the UI drives. |
| `crates/mule-ffi`   | UniFFI seam: wraps `Engine` in a synchronous, FFI-friendly facade and generates the Swift bindings. |
| `crates/mule-cli`   | A command-line harness used to exercise the engine against the real network. |
| `ios/`              | The SwiftUI app and its XcodeGen project spec. |
| `amule-3.0.1/`      | Upstream aMule, vendored unchanged as the reference oracle for protocol and format decisions. |

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
is documented in `docs/wiki/mac-toolchain-setup.md`.

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
