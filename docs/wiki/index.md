# padMule Wiki - Index

AI-maintained knowledge base. Start here. See `/CLAUDE.md` for the schema and
the Ingest / Query / Lint workflows.

## Architecture
- [[arch-upstream-amule]] - upstream aMule 3.0.1 layout, build targets, dependencies, port seams.

## Protocol
- [[protocol-reference]] - load-bearing aMule constants (framing, PARTSIZE, hashing edge cases, obfuscation, EC, timers); index into the full recon in docs/raw.
- [[protocol-understanding]] - the mental model: eD2k + Kad flows/state machines, interop landmines, capability gating, padMule recommendations. Read before Wave 3/6.

## Platform
- [[ipados-constraints]] - iPadOS/Rust-on-iOS constraints; foreground-only engine, sockets OK, free-team sideload limits, storage plan (verified 2026).

## Reference
- [[ref-ecosystem]] - eMule AI fork, eMule-Board dev forums, official aMule docs site.

## Process
- [[decisions-and-lessons]] - locked decisions, rejected approaches, gotchas.
- [[build-progress]] - wave-by-wave build status; Wave 1 eD2k hashing done.

## Strategy
(Engine = Rust rewrite, decided 2026-07-12, see [[decisions-and-lessons]].
Remaining forks - deploy/signing path, v1 scope, background strategy - being
brainstormed; design spec lands in docs/superpowers/specs/.)
