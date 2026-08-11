# padMule fuzz targets

Why this exists: padMule is a Rust rewrite of a C++ client, so eMule's
historical buffer-overflow and use-after-free classes are structurally absent.
What Rust does instead is turn a memory error into a PANIC - and a panic
reached from a hostile packet is a denial of service, worse if it poisons a
mutex and takes a subsystem down for the process lifetime. **Panics in parse
paths are padMule's realistic remaining attack surface**, and these targets
exist to find them.

## Toolchain

`cargo-fuzz` needs nightly and libFuzzer. The repo's own gate stays on stable
1.96 - nothing here changes that.

```bash
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz --locked
```

This crate is its OWN workspace root (the empty `[workspace]` table in
`fuzz/Cargo.toml`), so `cargo test --workspace`, `cargo clippy --workspace
--all-targets` and `cargo fmt --all` at the repo root neither see it nor build
it. That also means the root gate does NOT lint or format-check these files;
run those two inside `fuzz/` if you touch a target:

```bash
cd fuzz && cargo +nightly fmt && cargo +nightly clippy --all-targets
```

## Running

```bash
source "$HOME/.cargo/env"

# List the targets.
cargo +nightly fuzz list

# Run one, seeding from the checked-in corpus. The FIRST directory is the
# writable corpus libFuzzer grows; later ones are read-only seed input.
# ALWAYS pass fuzz/corpus/<target> FIRST, and create it beforehand - libFuzzer
# errors out if it is missing, and if you pass fuzz/seeds/<target> first it
# WRITES its new units straight into the checked-in seeds (measured: a 60s run
# turned 4 seed files into 254).
mkdir -p fuzz/corpus/kad_udp
cargo +nightly fuzz run kad_udp fuzz/corpus/kad_udp fuzz/seeds/kad_udp \
  -- -max_total_time=300

# Longer, parallel, with a memory ceiling (the default rss limit is 2048 MB):
cargo +nightly fuzz run met_files fuzz/corpus/met_files fuzz/seeds/met_files \
  -- -max_total_time=3600 -jobs=8 -workers=8
```

A crash writes the exact triggering bytes to `fuzz/artifacts/<target>/`.
Replay it deterministically with:

```bash
cargo +nightly fuzz run <target> fuzz/artifacts/<target>/crash-<hash>
cargo +nightly fuzz fmt <target> fuzz/artifacts/<target>/crash-<hash>   # decode
cargo +nightly fuzz tmin <target> fuzz/artifacts/<target>/crash-<hash>  # minimize
```

`fuzz/corpus/`, `fuzz/artifacts/` and `fuzz/target/` are gitignored;
`fuzz/seeds/` is checked in.

## Targets, and what feeds them

| Target | Parsers | Where the bytes come from |
|--------|---------|---------------------------|
| `packet` | `mule_proto::packet` framing + zlib unpack | every byte a peer or server writes on our TCP socket |
| `tag` | `mule_proto::tag` read/write | MET tag lists, inside both wire packets and `.met` files |
| `link` | `mule_proto::link`, `aich_from_base32` | a pasted / opened `ed2k://` or `magnet:` URI |
| `kad_udp` | `mule_kad` obfuscation, framing, message decode, keyword split | a raw UDP datagram from any host - no handshake, no connection |
| `met_files` | `mule_files` server/known/part/nodes/clients/known2/prefs readers | `server.met` and `nodes.dat` are DOWNLOADED from user-configured URLs |
| `ipfilter` | `mule_files::ipfilter` | the blocklist, downloaded from a user-supplied URL |
| `ed2k_peer` | `mule_engine::transfer`, `::peer` payload decoders | any peer in the swarm, in any order |
| `ed2k_server` | `mule_engine::server_messages`, `::search`, `::sources`, `::secure_ident`, `::portmap`, `::upnp` | the eD2k server, source exchange, the LAN gateway's NAT-PMP/IGD replies |

Multiplexed targets (`met_files`, `ed2k_peer`, `ed2k_server`) take a leading
SELECTOR byte that chooses the parser; the rest of the input is the payload.
Keep that in mind when hand-writing a seed - and if you add an arm, append it,
because changing the modulus invalidates the existing corpus mapping.

Every target is deterministic and pure: no sockets, no filesystem, no threads,
no clock. Keys and challenges are fixed constants (or derived from the input)
so a crash always reproduces.

The plumbing was MUTATION-CHECKED once, and should be again if you rework it:
a temporary `assert_ne!` on a parsed opcode was added to `packet`, and the run
found it, wrote `fuzz/artifacts/packet/crash-<hash>` and exited 1. A fuzz
target that reports nothing is indistinguishable from one that cannot report.

## Deliberately NOT fuzzed

- `mule_proto::obf` / `rc4` / `hash` / `kad_id` - fixed-width transforms over
  fixed-size arrays, with no length or count decoding to get wrong.
- `mule_kad::routing` / `::lookup` / `::hardening` - stateful policy over
  ALREADY-parsed contacts, not byte decoders. Worth property-testing, not
  fuzzing bytes at.
- `mule_engine::transfer_session` block reassembly (the `OP_COMPRESSEDPART`
  inflate loop) - it is stateful, keyed on blocks WE requested. Reaching it
  honestly needs a stateful harness, which is a separate task.
- `mule_proto::aich` tree construction - driven by our own file sizes, and
  `read_recovery_data` is worth a follow-up target once someone models the
  part/block state it needs.
- Anything that touches the network or the filesystem.
