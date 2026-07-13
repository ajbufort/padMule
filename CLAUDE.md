# padMule - Operating Manual (CLAUDE.md)

padMule ports **aMule 3.0.1** (C++ eD2k/Kad P2P client) to run on an **iPad Pro
4th gen** (iPadOS). Upstream is a wxWidgets desktop app; the port keeps the
protocol/engine core and replaces what iPadOS cannot run.

This file is the **schema layer** for the project: it defines the conventions,
the knowledge-base pattern, and the coding rules. Design decisions live in the
wiki (`docs/wiki/`), not here.

---

## Who / house rules

- The author is **Anthony Bufort** (`ajbufort@ajbconsulting.us`). Never "Alex".
- **ASCII only in files.** No arrow glyphs and no em/en dashes. Use `->` and `-`.
- `amule-3.0.1/` is the working tree being ported. The pristine reference is the
  original zip at `/mnt/c/Users/ajbuf/Downloads/amule-3.0.1.zip`; git history is
  the record of every divergence from upstream.
- aMule is GPL-2.0-or-later. The port, and anything borrowed from other forks
  (e.g. eMule AI), stays GPL-compatible.

## Upstream architecture (amule-3.0.1/)

| Path | Responsibility |
|------|----------------|
| `src/` | Engine + wxWidgets GUI in one flat tree (~446 .cpp/.h): sockets (`ClientTCPSocket`, `ClientUDPSocket`), download/upload queues, part/known files, client + server lists, credits, and all GUI dialogs/windows. |
| `src/kademlia/` | Kad DHT (kademlia / net / routing / utils). |
| `src/libs/common` | Shared utility library. |
| `src/libs/ec` | External Connections (EC) protocol - remote control of a running engine; the basis of amulegui/amulecmd/webserver. |
| `unittests/` | Upstream unit tests (CMake `BUILD_TESTING`). |
| `platforms/MacOSX` | The only Apple platform glue upstream ships. |

Build system: CMake. Targets via options: `BUILD_MONOLITHIC` (GUI app, default
ON), `BUILD_DAEMON` (amuled, headless engine), `BUILD_REMOTEGUI` (amulegui over
EC), `BUILD_AMULECMD`, `BUILD_WEBSERVER`. Dependencies: wxWidgets (pervasive -
engine code uses wxString/wxThread and friends, not just the GUI), Crypto++,
zlib, optional UPnP/GeoIP.

## Port constraints (facts to design against)

- Target device: iPad Pro 4th gen (2020, A12Z, arm64) on iPadOS. Native UI means
  SwiftUI/UIKit; wxWidgets has no usable iOS port.
- App Store distribution of a P2P client is effectively out; assume dev-signing /
  sideloading (AltStore or similar).
- iPadOS suspends backgrounded apps and reclaims long-lived sockets; an
  always-on P2P engine needs an explicit lifecycle strategy.
- Building and signing for iPadOS requires an Apple toolchain (Xcode on a Mac,
  or a cross toolchain); this WSL2 box alone cannot deploy to the device.
- The natural seam is amuled (headless engine) + the EC protocol: engine below
  EC, native UI above it. This is a lead, not a decision.

The port approach is NOT yet decided - brainstorm and spec it in the wiki before
writing port code.

## External references

- eMule AI - modern Windows eMule fork, active 2026: <https://github.com/eMuleAI/eMuleAI>
- eMule AI v1.5 release thread: <https://forum.emule-project.net/index.php?showtopic=167175>
- eMule-Board Development section (eMule Development / Bug Reports / Feature
  Requests / Public Beta Tests / eMule Mods): <https://forum.emule-project.net/index.php?showforum=83>
- Official aMule docs (user manual, developer guide, protocol details): <https://amule-org.github.io/docs>

Details and what is portable from them: `docs/wiki/ref-ecosystem.md`.

## Key commands

```bash
# Reference desktop build (upstream-documented; NOT yet verified on this box):
cmake -S amule-3.0.1 -B build -DBUILD_DAEMON=ON -DBUILD_MONOLITHIC=OFF
cmake --build build -j
# Upstream tests: configure with -DBUILD_TESTING=ON, then: ctest --test-dir build
```

Gate before every commit: build + tests for whatever targets currently compile,
and confirm changed files are ASCII-only.

## Environment (this machine)

WSL2 Ubuntu 24.04; gcc 13.3; no Apple toolchain. Device deploys happen elsewhere
(Mac/Xcode) once the port reaches that stage.

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
`Updated:` date on edit.

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
   or reformat adjacent code; match existing style (this matters doubly in a
   port - every gratuitous diff from upstream is merge debt). Remove only the
   orphans your own change created; mention pre-existing dead code, don't
   delete it.
4. **Goal-driven execution.** Turn tasks into verifiable goals ("port module X"
   -> "module X compiles for the target and its tests pass") and loop until
   verified. State a brief plan with a check per step for multi-step work.
