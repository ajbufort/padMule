# padMule Wiki - Index

AI-maintained knowledge base. Start here. See `/CLAUDE.md` for the schema and
the Ingest / Query / Lint workflows.

## Architecture
- [[arch-upstream-amule]] - upstream aMule 3.0.1 layout, build targets, dependencies, port seams.

## Protocol
- [[protocol-reference]] - load-bearing aMule constants (framing, PARTSIZE, hashing edge cases, obfuscation, EC, timers); index into the full recon in docs/raw.
- [[protocol-understanding]] - the mental model: eD2k + Kad flows/state machines, interop landmines, capability gating, padMule recommendations. The background for any wire work (it informed Waves 3-6).
- [[padmule-enhancement-channel]] - padMule-to-padMule capability channel on a provably-ignored HELLO tag (source-grounded carrier proof); Layer 1 detection DONE + amuled-validated; Layer 2 wire spec'd (opcode 0xD8 on 0xC5).
- [[nat-traversal-design]] - design for connecting two firewalled (LowID) padMule peers (hole punching + QUIC over Kad/buddy rendezvous); confirmed no stock hole punching; reusable Kad primitives; phased plan. Not built.

## Platform
- [[ipados-constraints]] - iPadOS/Rust-on-iOS constraints; foreground-only engine, sockets OK, free-team sideload limits, storage plan (verified 2026).
- [[lifecycle-and-reactivation]] - HARD requirement: honest status notice + clean pause/resume across focus loss; shapes the engine state model from Wave 3c.
- [[mac-toolchain-setup]] - getting padMule onto the iPad (iPadOS 26.5.2). VERIFIED blocker: iPadOS 26 needs Xcode 26 needs macOS Tahoe 26.2, and OCLP has no Tahoe support -> the 2011 mini cannot run it. Escape hatch: padMule is sideload-only (the Xcode-26 mandate is App-Store-only), so CI builds with an older Xcode and Sideloadly installs it (AltStore died on -22411). Path C is the active, proven route.
- [[net-highid-and-port-forwarding]] - HighID validated on the dev box (2026-07-14, 5-link manual chain) AND on the iPad via unicast-SSDP UPnP (2026-07-17); topology since 2026-07-17 is XB8-bridged -> TP-Link BE9700 (real UPnP IGD), which replaced the manual chain.

## Reference
- [[ref-ecosystem]] - eMule AI fork, eMule-Board dev forums, official aMule docs site.
- [[ref-source-trees]] - the reference source oracles under refs/ (eMule 0.50a/0.70b, aMule master); protocol authority + findings.
- [[emule-peer-oracle]] - a SECOND live peer oracle: real eMule on the Windows host (mirrored-mode 127.0.0.1:4663), driven by scripts/emule-oracle.sh; complements the headless amuled differential test and is the faithful other-side for secure-ident (#32). Manual (Anthony launches eMule).
- [[ed2k-server-oracle]] - the SERVER oracle: real Lugdunum eserver 17.15 run LOCALLY + fully ISOLATED (unshare -rn, zero egress), driven by scripts/eserver-oracle.sh. padMule logs in against real eserver; enables #9 global-UDP-search testing. Untrusted binary, gitignored, sha256-verified; i686 build (x86_64 hits the vsyscall trap).

## Process
- [[decisions-and-lessons]] - locked decisions, rejected approaches, gotchas.
- [[build-progress]] - wave-by-wave build status. Engine complete through Kad + multi-source fetch; padMule RUNS on the iPad and does the full search->download->verify->save loop on-device; on-device feature round + search-panel parity + splash/icon DONE by 2026-07-18. Since then (2026-07-19): the 0.70b Tier-1 slices (IP filter, search history, wire filters, categories, ratings/comments read+author, per-source sheet, per-download priority, per-file unshare) and the verified-identity badge (secure-ident redo) landed, plus a real-peer/real-server ORACLE SET ([[emule-peer-oracle]], [[ed2k-server-oracle]]). Repo has LICENSE (GPL v2) + NOTICE + README.

## Backlog / feature ideas
- [[feature-server-hunter]] - discover + verify live eD2k servers (auto-update, health-check, server-graph crawl); NOT literal whole-net scanning. Future work.
- [[emule-070b-features]] - ranked backlog of eMule 0.70b features to adopt (34 items). From the 2026-07-18 dive; Tier 1 is now largely DONE (#1-8 landed, some partial). Remaining Tier-1: #9 global server UDP search (next, testable vs [[ed2k-server-oracle]]) + #10 related search.

## Strategy
(All the big forks are LOCKED and executed - Rust engine rewrite, no-Mac
CI+Sideloadly deploy path, foreground-only v1 - see [[decisions-and-lessons]];
the app is shipped and on-device. Current direction: eMule 0.70b functional
parity - Tier-1 largely landed (see [[emule-070b-features]]); next up is #9
global server UDP search, now testable against a real local server
([[ed2k-server-oracle]]). Wave 9 seedbox mode is the open v1.1 item.)
