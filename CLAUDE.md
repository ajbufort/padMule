# padMule - Operating Manual (CLAUDE.md)

padMule brings **aMule 3.0.1** (eD2k/Kad P2P) to an **iPad Pro** (iPadOS). DECIDED (2026-07-12) and SHIPPED: the engine is a from-scratch **Rust
rewrite** (`crates/`), the UI is **SwiftUI** (`ios/`) over a **UniFFI** seam
(`crates/mule-ffi`). The upstream C++ tree (`amule-3.0.1/`) is a vendored,
read-only REFERENCE ORACLE for differential testing - never linked or shipped.
The app runs on the device today: search (server + Kad merged), hash-verified
downloads saved to Files that RESUME after a crash or restart, per-file
pause/stop/remove, uploads with a Leech-Mode toggle, browsable shares (off by
default), an Incognito mode that stops padMule declaring itself on the wire, and
HighID earned by its own unicast-SSDP UPnP. Byte correctness with a REAL eMule
is proven in BOTH directions, multi-part, independently verified.

This file is the **schema layer** for the project: it defines the conventions,
the knowledge-base pattern, and the coding rules. Design decisions live in the
wiki (`docs/wiki/`), not here. Start every deep dive at `docs/wiki/index.md`;
current build state is `docs/wiki/build-progress.md`.

---

## Who / house rules

- The author is **Anthony Bufort** (`ajbufort@ajbconsulting.us`). Never "Alex".
- **ASCII only in files.** No arrow glyphs and no em/en dashes. Use `->` and `-`.
- **What you EDIT is `crates/` + `ios/`** (plus `scripts/`, `fuzz/` and the docs
  when the task is theirs). That is a narrower thing than what the tree CONTAINS,
  and the Architecture table below - titled "the working tree" - lists the
  containing set, `amule-3.0.1/` and `refs/` included. **The two are not in
  conflict: this bullet is the WRITE list, the table is the INVENTORY.** Said
  here because the phrase read two ways for weeks.
  `amule-3.0.1/` is the vendored upstream reference (pristine zip at
  `reference-archives/amule-3.0.1.zip`, gitignored); treat it as read-only.
- aMule is GPL-2.0-or-later; padMule is too (root `LICENSE` + `NOTICE`).
  Anything borrowed from other forks (e.g. eMule AI) stays GPL-compatible.
  The compiled BINARY goes further: linking `ring` (Apache-2.0, via rustls, for
  the HTTPS server-list fetch) forces the "or later" option, so a build that
  includes it is conveyed under GPL-3.0-or-later while the SOURCE stays
  GPL-2.0-or-later. `NOTICE` calls that a real constraint on redistribution, not
  a formality - read it before touching dependencies or writing release notes.
- The repo is PUBLIC (github.com/ajbufort/padMule). Never commit real public
  IPs, client IDs, MACs, or other personal network identifiers; use
  placeholders like `<public-ip>`. Private RFC1918 LAN addresses (192.168.x.x,
  10.x.x.x) are FINE - they are non-routable and document the topology; the
  wiki uses them throughout by established convention.
- **COMMIT MESSAGES ARE AS PUBLIC AS THE CODE, and permanent.** A public commit
  message says WHAT CHANGED and why it is correct - never the project's motive,
  strategy, threat-model framing, or who wants a feature and what for. This is
  not hypothetical: on 2026-08-11 a purpose statement went out in a commit
  message while the wiki itself was already being kept private, and a history
  rewrite could remove it from the repo but NOT from public event archives that
  capture push payloads. Gitignoring a file does nothing about the message that
  accompanies the next commit.
- **ALL AGENTIC WORK IS COORDINATED FOR GUARANTEED NON-COLLISION** (standing
  2026-08-09; amended 2026-08-11). Work runs via dispatched agents: the
  coordinator scopes, dispatches and VERIFIES - it does not edit. Coordination
  is not best-effort - non-collision is guaranteed BY CONSTRUCTION, before
  anything is dispatched. Publish an ownership map first: one sole writer per
  path, no path owned twice. Exactly ONE agent may run cargo (concurrent builds
  race `target/`). Two tasks touching one file are one agent's job or two serial
  jobs. The knowledge-base ingest is a SERIAL TAIL, never parallel, and a claim
  whose truth depends on another agent's outcome is held for that tail instead
  of handed to both. Working in place rather than in a worktree removes the
  safety net, so file ownership becomes the only guarantee.

## Architecture - EVERYTHING IN THE TREE, not just what you edit

This is the INVENTORY. The house-rules bullet above names the narrower WRITE
list; `amule-3.0.1/` and `refs/` appear here because they are present and you
will read them, not because they may be modified - they may not.

| Path | Responsibility |
|------|----------------|
| `crates/mule-proto` | Pure codecs + crypto, no I/O: MD4/ed2k hashing, AICH, LE io, MET tags, packet framing + zlib, RC4, Kad128, ed2k/magnet link parsing. |
| `crates/mule-files` | On-disk formats, byte-compatible with upstream: server.met, known.met, part.met (+gaps), known2_64.met (AICH hashsets), clients.met, nodes.dat, preferences, ipfilter.dat/.p2p. Plus `pins` - padMule's own pinned.txt, the one format here with no upstream counterpart. |
| `crates/mule-kad` | Kad2: UDP framing + obfuscation, message codecs, routing bin-tree, iterative lookup, anti-abuse hardening. Offline-testable. |
| `crates/mule-engine` | The live engine: server link, peer transfer, TCP obfuscation, secure ident, credits, Kad node, fetch/search/catalog, share/upload, UPnP + NAT-PMP, and the `Engine` lifecycle facade. |
| `crates/mule-cli` | Dev + live-network harness (31 subcommands: login, listen, peer-*, kad-* incl. `kad-serve`, upnp-*, *-search, offer-*, link, fetch-complete, aich-*, ...). |
| `crates/mule-ffi` | UniFFI seam: sync facade over the async engine; Swift bindings generated in CI from the compiled library. |
| `ios/` | SwiftUI app. XcodeGen `project.yml`; the pbxproj is generated in CI, never committed. |
| `fuzz/` | 8 cargo-fuzz targets over the parse paths (packet, tag, link, kad_udp, met_files, ipfilter, ed2k_peer, ed2k_server). Its OWN workspace root, so `cargo test/clippy/fmt --workspace` never sees it; nightly-only and NOT wired into any CI workflow - run it by hand. |
| `scripts/` | Oracles + the deploy loop: `build-amuled-oracle.sh`/`differential-test.sh`, `amuled-reverse-oracle.sh`, `kad-store-oracle.sh`/`kad-verify-oracle.sh`, `eserver-oracle.sh`, `emule-oracle.sh`, `aich-golden.sh`, `simulate.sh`, `device-timing.sh`, and `ship.sh`. |
| `amule-3.0.1/` | Vendored upstream C++ - reference oracle only. The amuled BUILT from it lands in `/build-oracle/` at the REPO ROOT (gitignored), NOT inside this directory - `build-amuled-oracle.sh:15` sets `BUILD="$REPO/build-oracle"` and `differential-test.sh:15` reads `$REPO/build-oracle/src/amuled`. |
| `refs/` | Gitignored source oracles: eMule 0.50a (the WIRE authority), eMule 0.70b (community fork), aMule master. |

Authority rule, by domain:

| Domain | Authority |
|--------|-----------|
| WIRE + FILE FORMATS | **eMule 0.50a** (`refs/emule-0.50a`) |
| wire-neutral policy | **aMule** (`refs/amule-master`, `amule-3.0.1/`) - and it is the runnable oracle |
| **GUI, Settings, per-file behaviour** | **eMule 0.70b** (`refs/emule-0.70b`) - DECIDED 2026-08-06 by Anthony |

**GREP THE `refs/` TREES WITH `/usr/bin/grep`, NEVER THE BARE `grep`.** On this
box `grep` is a shell function wrapping `ugrep`, and on a file that is not valid
UTF-8 it prints NOTHING to stdout, NOTHING to stderr, and EXITS 1 - there is no
`Binary file matches` warning, so the result is indistinguishable from a genuine
absence. eMule ships Windows-1252, so **25 of 714 source files in
`refs/emule-0.50a` and 20 of 556 in `refs/emule-0.70b` are invisible to it**
(`refs/amule-master`: none). The blind set is the core, not the fringe:
`ListenSocket.cpp` - the ENTIRE eD2k TCP packet dispatch, every `case OP_...` -
plus `PartFile.cpp`, `KnownFile.cpp` and `Preferences.h`. Measured:
`grep -c 'case OP_ASKSHAREDFILES' ListenSocket.cpp` -> empty, exit 1;
`/usr/bin/grep -c` -> 4. `LC_ALL=C` does NOT help; `-a` does.
**THE SECOND HALF, FOUND 2026-08-12 AND WORSE THAN THE FIRST: that same `grep`
honors `.gitignore`, and `refs/` IS GITIGNORED (`.gitignore:5`) - so a
REPO-ROOT sweep does not read the authority AT ALL.** This is not limited to
non-UTF-8 files; it hides all three reference trees and `docs/wiki/` too, and it
EXITS 0, so there is not even the exit-1 tell the encoding half leaves. Measured:
`grep -rl 'OP_ASKSHAREDDENIEDANS' .` -> 9 files, **ZERO** of them under
`refs/emule`; `/usr/bin/grep -rl` -> 62 files, 6 of them eMule. The bare tool
answers a WIRE-AUTHORITY question with padMule's own code plus the committed
`amule-3.0.1/`, and looks like it searched the lot. Name the path
(`grep -r X refs/emule-0.50a/`) and the ignore rule no longer applies - but the
encoding trap still does, so `/usr/bin/grep` remains the only safe form.

A POSITIVE finding survives this, a NEGATIVE one does not - "the authority does
not do X" is exactly what a silent grep manufactures, and that class of claim is
this project's strongest evidence. The 2026-08-12 audit found the KB CLEAN
(no absence-claim is scoped to a blind file, and 59 of 85 citations carry a
line number, which can only come from reading) - the citation-fidelity habit is
what saved it. Keep citing lines.

The 0.70b row is a STANDING directive, not a one-off: from 2026-08-06 on, when
designing a screen, a setting, or how a download should behave (states, queueing,
pause/resume, what the row says), go look at what eMule 0.70b does FIRST and
diverge only deliberately. It does not touch the wire - 0.50a still decides that.
See [[emule-070b-features]] for the mined backlog.

**Where the authorities CONFLICT, follow eMule** - and say so
in the commit + wiki with citations on BOTH sides. This needs active guarding,
because aMule is the one that builds and runs and is vendored in-tree, so there
is constant pull toward treating whatever it does as correct. Two live examples:
aMule master defines `FT_LASTUPLOADED 0x55`, a number eMule already owns as
`FT_MAXSOURCES`; and it clamps in-flight block requests to [3,24] citing "eMule's
own pending range" for a depth eMule never requests. Also remember the vendored
`amule-3.0.1/` oracle can itself hold a bug upstream later fixed (the racy
`known2_64.met` orphan-prune) - check `refs/amule-master/` before transcribing.
Details: `docs/wiki/decisions-and-lessons.md`, `docs/wiki/ref-source-trees.md`,
`docs/wiki/protocol-reference.md` (LANDMINE section).

## Platform facts (still in force)

- Target device: iPad Pro 11-inch, M4 generation - `iPad16,3` / board `J717AP`,
  arm64e, iPadOS 26.6 (was 26.5.2 when verified over USB 2026-08-02; 512GB,
  ~476GB free).
  SUPERSEDES the original target (iPad Pro 4th gen, 2020, A12Z) - constraints
  derived from A12Z (notably the ~3GB RAM budget) are calibrated to the wrong
  machine and are being re-derived; see `docs/wiki/ipados-constraints.md`.
- Sideload-only distribution (App Store is out for a P2P client). CI builds an
  UNSIGNED `.ipa`; **Sideloadly** on the Windows host installs it with a free
  Apple ID (7-day re-sign). AltStore/AltServer failed here (-22411); do not
  retry it without new evidence.
- **SIGNING-PROFILE RENEWAL IS AGENT WORK - do it, do not ask.** Sideload
  profiles live 7 days, so signing and the WebDriverAgent runner lapse
  constantly; renewing one is ordinary maintenance, not a decision to escalate.
  The agent lists and dumps the profiles on the device, verifies one against a
  signing kit, swaps it in, re-signs, installs and verifies the result. **Only
  MINTING a new profile needs Anthony**, because that means authenticating to
  Apple. So the first question on any expiry is never "may I mint one" - it is
  whether the device already holds a newer profile, which it usually does, and
  then nothing is needed from him at all. The kit's profile is the one that
  binds, because that is what gets embedded at signing time. Procedure, the
  pre-checks and the backup discipline: `docs/wiki/ipad-usb-tooling.md`.
- iPadOS suspends backgrounded apps and reclaims sockets, so clean, honest
  pause/resume is a HARD requirement (see `docs/wiki/lifecycle-and-reactivation.md`).
  SUPERSEDED IN PART 2026-08-07 (build-progress 8cj): background SEEDING ships -
  an `audio` keepalive plus `EngineState::Seeding` keeps the listener and server
  login up so peers keep downloading from us, default OFF, device-verified over a
  70-minute soak at a flat ~32MB. Background DOWNLOADING stays unbuilt on purpose.
  [CORRECTED 2026-08-09 (build-progress 8dh): Kad is NO LONGER dropped on the way
  in - the node survives a seed (liveness sweep runs; growth refresh stays
  Running-only); the soak with Kad kept up PASSED the same day (row 8dl):
  72.5 minutes, 65/65 samples alive, a ~51MB plateau against the ~100MB jetsam
  budget, publishing continuing through the seed. QUALIFIED (row 8dm): that
  soak seeded to NOBODY, so 43-51MB is a no-serving-load FLOOR, not a
  full-load figure.] Clean pause/resume is still
  required, because jetsam can end a seed at any moment.
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
cargo test --workspace                 # the unit gate (845 passed / 0 failed / 5 ignored at 086d07e, 2026-08-12, offline; the handoff carries the current count)
# NO SINGLE LINE STATES THE TOTAL - the suite is per-crate and the figure is the
# SUM of 16 `test result: ok` lines. Do not pipe the run through `tail`: that
# reported 80 from 6 surviving lines while the exit status stayed honestly 0.
# -D warnings is NOT optional: bare clippy EXITS 0 on warnings, so a gate without
# it goes GREEN over them (measured 2026-08-11: identical findings, exit 0 vs 101).
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check

# LIVE STRESS HARNESS (dozens of real downloads through the app's own FFI):
#   cargo run --release -p mule-ffi --example stress -- /tmp/cfg /tmp/dl linux 25 480
# Reports how many downloads EVER received a byte, how many are receiving now,
# and search-vs-connected source counts. Reach for it BEFORE theorising about
# transfer behaviour - it is what refuted the queue-bail hypothesis.
#
# It also prints THE FETCH FUNNEL (mule_engine::stats): how far down the eD2k
# request sequence each PEER SESSION got - dial, handshake, filestatus, hashset,
# slot, blocks, bytes - plus every opcode read out of turn and a dial-duration
# histogram. The DROP between two adjacent stages is the loss at that stage,
# including a loss to the per-peer TIMEOUT, which no error value can report.
# This is the instrument that found the missing OP_OUTOFPARTREQS handler; when a
# transfer question starts with "why", read the funnel before writing a theory.

# Differential oracle (real amuled 3.0.1):
scripts/build-amuled-oracle.sh         # one-time build into build-oracle/
scripts/differential-test.sh           # padMule downloads from real amuled, byte-for-byte

# ONTO THE IPAD - the only route. Closed loop: commit -> CI -> verify the artifact
# -> sign -> install -> read CFBundleVersion back OFF the device. Aborts on a dirty
# tree or an unpushed HEAD, and holds an flock so only ONE ship runs at a time.
scripts/ship.sh                        # [--no-install]

# CI: push to main, pull requests, or workflow_dispatch trigger - plus a weekly
# cron on the supply-chain audit, which is the trigger that matters most there:
# a new advisory lands against an UNCHANGED Cargo.lock, so no push would fire it.
#   .github/workflows/rust.yml         - the unit gate above (test+clippy+fmt) on ubuntu
#   .github/workflows/ios-build.yml    - unsigned padMule.ipa artifact (macOS runner)
#   .github/workflows/ios-test.yml     - Swift unit tests on an iPad simulator
#   .github/workflows/supply-chain.yml - cargo-deny: advisories, licenses, sources (policy in deny.toml)
# ship.sh gates on the FIRST THREE only - a supply-chain red does NOT block a ship.
# READING CI EVIDENCE: the `paths:` filters are evaluated over the WHOLE PUSHED
# RANGE and the run is attributed to the TIP sha - so a docs-only PUSH builds
# nothing, but a docs-only COMMIT pushed alongside code commits does (`feedc8e`
# touched only CLAUDE.md; all four ran on it because its push carried
# `56bd47e..feedc8e`). Absent runs for a sha do NOT mean it went untested.
# No Apple secrets anywhere.
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

**THE WIKI IS LOCAL-ONLY AND NOT IN THIS REPOSITORY (2026-08-11).** `docs/wiki/`
is gitignored here and has its OWN git repository with no remote and a
pre-push hook that refuses. It carries design reasoning, threat models and
project strategy that is deliberately not published. A fresh clone of this
repository will NOT have it - obtain it separately, and never add it back to
the public tree.

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

Entry conventions: kebab-case filenames; keep entries under ~150 lines -
EXCEPT append-only ledgers (`log.md`, `decisions-and-lessons`) and archive
entries (`build-history`), which grow by nature; when a ledger's completed
narratives make it unwieldy, split them verbatim into a `*-history` archive
(as build-progress did 2026-08-01) rather than trimming content to fit.
Cross-link liberally with `[[name]]`; `## Related` is the last section; bump an
`Updated:` date on edit. A `[[name]]` with no `docs/wiki/` file may point to a
cross-session MEMORY file (the memory index lists them) - that is intentional,
not an orphan. When a milestone supersedes older text in a dated section,
annotate the old text in place rather than rewriting history.

**A superseded block gets its annotation AT THE MOMENT it is superseded, or it
gets moved out - "later" is not an option.** Annotating later is what left two
disagreeing STATE OF THE TREE blocks in `handoff-for-fable.md` for two days, in
the one document every session reads in full; an un-annotated stale block is
indistinguishable from current text, and only an audit caught it. Closed work
moves VERBATIM into a `*-history` archive - never trimmed, never deleted.
`.claude/hooks/kb-drift-check.sh` ENFORCES this on Stop, not as advice: it
BLOCKS on two un-annotated distinct answers in the handoff (gate figures, device
build shas), and warns on closed work piling up and on oversized entries. It
takes an optional path argument, so it can be run against a copy by hand.

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
5. **A brief is a hypothesis** (padMule's own rule, BINDING since 2026-08-09).
   Verify the premises you were handed - the design, the handoff claim, the
   prior measurement, a line in your own brief - against the code, the
   authority tree, or the artifact BEFORE acting on them. Where the brief and
   the files disagree, THE FILES WIN - say so explicitly. Never implement a
   design whose premise you have refuted; report the refutation and what you
   would do instead. Every report names "what I verified" separately from
   "what I found different", even when everything held. Read each command's
   OWN exit status, never a pipeline's tail. And when DISPATCHING: a brief
   that says "do X" without "verify X still holds, and tell me if it does
   not" is INCOMPLETE - the dispatcher is frequently wrong. The day that
   earned this rule (three refuted premises, one of which would have shipped
   silent data corruption): `docs/wiki/decisions-and-lessons.md`, 2026-08-09.
6. **A REPORT is a hypothesis too** (BINDING since 2026-08-12). Rule 5 governs
   what you are HANDED; this is its symmetric half and governs what comes BACK.
   A subagent's conclusion is a CLAIM, not a fact, until it is verified or
   labeled unverified. **Every claim relayed to Anthony is marked VERIFIED (I
   ran it and read the output) or REPORTED (an agent said so and I have not
   checked); unmarked reads as unverified.** Verify by preference what is
   load-bearing, cheap to check, or about to be repeated to him. Demanding
   verification from an agent and then relaying its answer untested only moves
   the unverified claim one level up. The night that earned this rule
   (2026-08-11) sent five false statements up that path: "both network lists
   bootstrapped over HTTPS" (the URLs are plaintext `http://`), "the container
   is empty" (its contents survived), and "the WDA runner embeds the 08-16
   profile" (it embeds 08-19 - 08-16 was the local kit's ipa, not the installed
   bundle).
7. **No intention without a task.** State no future action in prose. If it is
   real it goes in the session task list; if it is not in the list it does not
   exist. A turn that ends with outstanding work ends by naming it as tracked
   items, not as narrative. Twice on 2026-08-11 an "I'll do X next" died when
   the next message redirected, and Anthony had to ask for work already
   promised. `.claude/hooks/commitment-check.sh` ENFORCES this on Stop, not as
   advice: it blocks when the closing message schedules a future action and the
   session task list was not written in that turn. A promise is not a fix - the
   KB already said an agent may renew a signing profile and permission was
   asked for anyway, because the text read as a capability rather than an
   instruction.
