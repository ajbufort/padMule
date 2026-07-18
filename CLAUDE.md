# padMule - Operating Manual (CLAUDE.md)

padMule brings **aMule 3.0.1** (eD2k/Kad P2P) to the **iPad Pro 4th gen**
(iPadOS). DECIDED (2026-07-12) and SHIPPED: the engine is a from-scratch **Rust
rewrite** (`crates/`), the UI is **SwiftUI** (`ios/`) over a **UniFFI** seam
(`crates/mule-ffi`). The upstream C++ tree (`amule-3.0.1/`) is a vendored,
read-only REFERENCE ORACLE for differential testing - never linked or shipped.
The app runs on the device today: search (server + Kad merged), hash-verified
downloads saved to Files, uploads with a Leech-Mode toggle, cancel, and HighID
earned by its own unicast-SSDP UPnP.

This file is the **schema layer** for the project: it defines the conventions,
the knowledge-base pattern, and the coding rules. Design decisions live in the
wiki (`docs/wiki/`), not here. Start every deep dive at `docs/wiki/index.md`;
current build state is `docs/wiki/build-progress.md`.

---

## Who / house rules

- The author is **Anthony Bufort** (`ajbufort@ajbconsulting.us`). Never "Alex".
- **ASCII only in files.** No arrow glyphs and no em/en dashes. Use `->` and `-`.
- The working tree is `crates/` + `ios/`. `amule-3.0.1/` is the vendored
  upstream reference (pristine zip at `/mnt/c/Users/ajbuf/Downloads/amule-3.0.1.zip`);
  treat it as read-only.
- aMule is GPL-2.0-or-later; padMule is too (root `LICENSE` + `NOTICE`).
  Anything borrowed from other forks (e.g. eMule AI) stays GPL-compatible.
- The repo is PUBLIC (github.com/ajbufort/padMule). Never commit real public
  IPs, client IDs, MACs, or other personal network identifiers; use
  placeholders like `<public-ip>`.

## Architecture (the working tree)

| Path | Responsibility |
|------|----------------|
| `crates/mule-proto` | Pure codecs + crypto, no I/O: MD4/ed2k hashing, AICH, LE io, MET tags, packet framing + zlib, RC4, Kad128, ed2k/magnet link parsing. |
| `crates/mule-files` | On-disk formats, byte-compatible with upstream: server.met, known.met, part.met (+gaps), clients.met, nodes.dat, preferences. |
| `crates/mule-kad` | Kad2: UDP framing + obfuscation, message codecs, routing bin-tree, iterative lookup, anti-abuse hardening. Offline-testable. |
| `crates/mule-engine` | The live engine: server link, peer transfer, TCP obfuscation, secure ident, credits, Kad node, fetch/search/catalog, share/upload, UPnP + NAT-PMP, and the `Engine` lifecycle facade. |
| `crates/mule-cli` | Dev + live-network harness (20 subcommands: login, listen, peer-*, kad-*, upnp-*, link, fetch-complete, ...). |
| `crates/mule-ffi` | UniFFI seam: sync facade over the async engine; Swift bindings generated in CI from the compiled library. |
| `ios/` | SwiftUI app. XcodeGen `project.yml`; the pbxproj is generated in CI, never committed. |
| `amule-3.0.1/` | Vendored upstream C++ - reference oracle only. `build-oracle/` holds a built amuled for differential tests. |
| `refs/` | Gitignored source oracles: eMule 0.50a (the WIRE authority), eMule 0.70b (community fork), aMule master. |

Authority rule: for WIRE + FILE FORMATS, eMule 0.50a is the source of truth;
aMule for wire-neutral policy. Details: `docs/wiki/decisions-and-lessons.md`,
`docs/wiki/ref-source-trees.md`.

## Platform facts (still in force)

- Target device: iPad Pro 4th gen (2020, A12Z, arm64), iPadOS 26.x.
- Sideload-only distribution (App Store is out for a P2P client). CI builds an
  UNSIGNED `.ipa`; **Sideloadly** on the Windows host installs it with a free
  Apple ID (7-day re-sign). AltStore/AltServer failed here (-22411); do not
  retry it without new evidence.
- iPadOS suspends backgrounded apps and reclaims sockets: v1 is
  foreground-only with clean, honest pause/resume (a HARD requirement - see
  `docs/wiki/lifecycle-and-reactivation.md`).
- The engine/UI seam is in-process FFI (`crates/mule-ffi`); the EC protocol is
  deferred entirely.

## External references

- eMule AI - modern Windows eMule fork, active 2026: <https://github.com/eMuleAI/eMuleAI>
- eMule AI v1.5 release thread: <https://forum.emule-project.net/index.php?showtopic=167175>
- eMule-Board Development section (eMule Development / Bug Reports / Feature
  Requests / Public Beta Tests / eMule Mods): <https://forum.emule-project.net/index.php?showforum=83>
- Official aMule docs (user manual, developer guide, protocol details): <https://amule-org.github.io/docs>

Details and what is portable from them: `docs/wiki/ref-ecosystem.md`.

## Key commands

```bash
source "$HOME/.cargo/env"              # cargo is NOT on the default PATH

cargo build --workspace
cargo test --workspace                 # the unit gate (379 tests, offline)
cargo clippy --workspace --all-targets # must be warning-free
cargo fmt --all -- --check

# Differential oracle (real amuled 3.0.1):
scripts/build-amuled-oracle.sh         # one-time build into build-oracle/
scripts/differential-test.sh           # padMule downloads from real amuled, byte-for-byte

# iOS: push to main (or workflow_dispatch) -> .github/workflows/ios-build.yml
# builds the unsigned padMule.ipa artifact on a macOS runner. No Apple secrets.
```

Gate before every commit: cargo test + clippy + fmt clean, and changed files
ASCII-only. Re-run `scripts/differential-test.sh` after ANY transfer-path
change - it catches what padMule-to-padMule tests cannot.

## Environment (this machine)

WSL2 Ubuntu 24.04; Rust 1.96.1; no Apple toolchain (by design - iOS compiles
happen in CI). Device installs run from the Windows host via Sideloadly.
Network: behind a TP-Link BE9700 edge router (UPnP works); see the
`padmule-dev-box-networking` memory before re-diagnosing anything inbound.

---

## Knowledge base - the LLM Wiki pattern (Karpathy)

Three layers, per <https://gist.github.com/karpathy/442a6bf555914893e9891c11519de94f>:

| Layer | Path | Rule |
|-------|------|------|
| **Raw** | `docs/raw/` | Immutable source material. Read, never edit. |
| **Wiki** | `docs/wiki/` | AI-maintained markdown: summaries, entities, cross-references. |
| **Schema** | this `CLAUDE.md` | Conventions + workflows (you are here). |

Start every deep dive at `docs/wiki/index.md`. Two special files:

- `docs/wiki/index.md` - catalog by category, one line per entry.
- `docs/wiki/log.md` - append-only, timestamped record of ingest/query/lint passes.

### Standing directive: maintain the KB proactively (do NOT wait to be asked)

Keeping the wiki and memory current is **part of every task, not a separate
request.** After any substantive change or decision - a feature landed, an
approach rejected, a build result, a gotcha, a design choice - **ingest it
immediately**: create/update the relevant `docs/wiki/` entry, wire
cross-references, update `index.md`, append to `log.md`, and update
cross-session memory. Before ending a work session, run a quick **Lint** pass
(contradictions, stale claims, orphans, missing concepts). Anthony should never
have to say "update the docs/wiki/memory".

**Three operations:**

- **Ingest** - when new material lands in `docs/raw/` (or a decision is made):
  create or update the relevant `docs/wiki/` entry, wire cross-references
  (`[[entry-name]]`), update `index.md`, append a line to `log.md`.
- **Query** - answer from the wiki first; cite entries. If the answer was worth
  deriving, file it back into the wiki so it compounds.
- **Lint** - periodically health-check: contradictions, stale claims, orphan
  pages, missing concepts. Record the pass in `log.md`.

Entry conventions: kebab-case filenames; keep entries under ~150 lines;
cross-link liberally with `[[name]]`; `## Related` is the last section; bump an
`Updated:` date on edit. A `[[name]]` with no `docs/wiki/` file may point to a
cross-session MEMORY file (the memory index lists them) - that is intentional,
not an orphan. When a milestone supersedes older text in a dated section,
annotate the old text in place rather than rewriting history.

---

## Coding rules (Karpathy guidelines)

Bias toward caution over speed; use judgment on trivial tasks.

1. **Think before coding.** State assumptions; if multiple interpretations
   exist, surface them rather than pick silently; push back when a simpler
   approach exists; if something is unclear, stop and ask.
2. **Simplicity first.** Minimum code that solves the problem. No speculative
   features, abstractions for single-use code, unrequested configurability, or
   error handling for impossible cases. If 200 lines could be 50, rewrite.
3. **Surgical changes.** Touch only what the request requires. Don't refactor
   or reformat adjacent code; match existing style. Never modify `amule-3.0.1/`
   or `refs/` (they are oracles; a modified oracle proves nothing). Remove only
   the orphans your own change created; mention pre-existing dead code, don't
   delete it.
4. **Goal-driven execution.** Turn tasks into verifiable goals ("port module X"
   -> "module X compiles for the target and its tests pass") and loop until
   verified. State a brief plan with a check per step for multi-step work.
