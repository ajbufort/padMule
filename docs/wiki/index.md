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

## Process
- [[decisions-and-lessons]] - locked decisions, rejected approaches, gotchas.
- [[build-progress]] - wave-by-wave build status. Engine complete through Kad + multi-source fetch; padMule RUNS on the iPad and does the full search->download->verify->save loop on-device; on-device feature round (uploads + Leech toggle, cancel, Kad-in-search, unicast-SSDP HighID) DONE 2026-07-17; search-panel eMule parity + splash + app icon (8d) MERGED 2026-07-18. Repo has LICENSE (GPL v2) + NOTICE + README.

## Backlog / feature ideas
- [[feature-server-hunter]] - discover + verify live eD2k servers (auto-update, health-check, server-graph crawl); NOT literal whole-net scanning. Future work.
- [[emule-070b-features]] - ranked backlog of eMule 0.70b features to adopt (34 items; Tier 1 do-soon = IP filter, search history, wire-side search filters, verified badge, categories, ratings-read); first-slice recommendation. From the 2026-07-18 dive.

## Strategy
(All the big forks are LOCKED and executed - Rust engine rewrite, no-Mac
CI+Sideloadly deploy path, foreground-only v1 - see [[decisions-and-lessons]];
the app is shipped and on-device. Current direction: GUI + functionality
enhancements toward eMule-community-release (0.70b) functional parity, plus a
code-fix round from the 2026-07-18 lint pass. Wave 9 seedbox mode is the open
v1.1 item.)
