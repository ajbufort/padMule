# padMule

A port of **aMule** (the eD2k / Kademlia peer-to-peer client) to the iPad.

padMule keeps aMule's protocol and file-format behavior but replaces everything
iPadOS cannot run: the engine is a **Rust rewrite** and the interface is native
**SwiftUI**. It talks to the real eD2k and Kad networks and is byte-compatible
with aMule's on-disk formats, so an aMule download and a padMule download can pick
up where the other left off.

Upstream aMule is a wxWidgets desktop app, and wxWidgets has no usable iOS port.
padMule reimplements the engine below the UI rather than porting the GUI.

## Status

padMule runs on a real iPad, built with no Apple hardware in the loop (GitHub
Actions produces an unsigned `.ipa`, which is re-signed at install time with a
free Apple ID via Sideloadly or AltStore). What works today, proven on-device:

- **Connect** to live eD2k servers and bootstrap the Kad DHT.
- **Search** the connected server and the Kad network together, deduped and
  ranked into one result list.
- **Download** a file from its sources, **verify** it against its eD2k hash, and
  save it to the Files app (On My iPad > padMule).
- **Share** completed files back to other peers, with a toggle to turn uploading
  off ("download only").
- **Cancel** an in-progress download (swipe to remove).

Reachability follows the usual eD2k rules: a LowID client downloads fine but
cannot receive inbound connections, so a device behind NAT stays LowID unless its
gateway forwards the listening port. padMule asks the gateway to do that over
UPnP (multicast on desktop, unicast on iOS, where multicast is unavailable); this
only earns HighID on a gateway that has UPnP enabled.

The port strategy, protocol notes, and every design decision are written up in
`docs/wiki/` (start at `docs/wiki/index.md`).

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
(or AltStore). The setup is documented in `docs/wiki/mac-toolchain-setup.md`.

## License

padMule is free software licensed **GPL-2.0-or-later**. See `LICENSE` for the
full text and `NOTICE` for the derivation.

It is a port of aMule 3.0.1 (Copyright the aMule Team, GPL-2.0-or-later), which
itself descends from eMule (Copyright the eMule Team, GPL-2.0-or-later). The
vendored `amule-3.0.1/` tree keeps its own license and author files intact. Any
code borrowed from aMule, eMule, or another fork retains its original notices.

## Responsible use

padMule is a peer-to-peer client for a network that carries uncontrolled,
user-supplied content. It is provided for lawful use only. You are responsible
for complying with the copyright law and terms that apply where you are.

---

Author: Anthony Bufort <ajbufort@ajbconsulting.us>
