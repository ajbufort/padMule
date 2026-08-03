# padMule Wiki - Index

Updated: 2026-08-02

AI-maintained knowledge base. Start here. See `/CLAUDE.md` for the schema and
the Ingest / Query / Lint workflows.

## Architecture
- [[arch-upstream-amule]] - upstream aMule 3.0.1 layout, build targets, dependencies, port seams.

## Protocol
- [[protocol-reference]] - load-bearing aMule constants (framing, PARTSIZE, hashing edge cases, obfuscation, EC, timers); index into the full recon in docs/raw.
- [[security-model]] - the "bulletproof" release gate: eMule/Kad spec security measures (checklist + status) + non-burdensome additions; RELEASE BLOCKER.
- [[obfuscation-posture]] - what padMule obfuscates (c2c TCP, Kad UDP) vs the deliberate v1 opt-out (server TCP/UDP obf); the documented decision behind the 2 server-obf scorecard rows.
- [[protocol-understanding]] - the mental model: eD2k + Kad flows/state machines, interop landmines, capability gating, padMule recommendations. The background for any wire work (it informed Waves 3-6).
- [[padmule-enhancement-channel]] - padMule-to-padMule capability channel on a provably-ignored HELLO tag (source-grounded carrier proof); Layer 1 detection DONE + amuled-validated; Layer 2 wire spec'd (opcode 0xD8 on 0xC5).
- [[nat-traversal-design]] - design for connecting two firewalled (LowID) padMule peers (hole punching + QUIC over Kad/buddy rendezvous); confirmed no stock hole punching; reusable Kad primitives; phased plan. Not built.

## Platform
- [[ipados-constraints]] - iPadOS/Rust-on-iOS constraints; foreground-only engine, sockets OK, free-team sideload limits, storage plan (verified 2026).
- [[lifecycle-and-reactivation]] - HARD requirement: honest status notice + clean pause/resume across focus loss; shapes the engine state model from Wave 3c.
- [[mac-toolchain-setup]] - getting padMule onto the iPad (iPadOS 26.5.2). VERIFIED blocker: iPadOS 26 needs Xcode 26 needs macOS Tahoe 26.2, and OCLP has no Tahoe support -> the 2011 mini cannot run it. Escape hatch: padMule is sideload-only (the Xcode-26 mandate is App-Store-only), so CI builds with an older Xcode and Sideloadly installs it (AltStore died on -22411). Path C is the active, proven route.
- [[ipad-usb-tooling]] - give this WSL2 box direct USB access to the iPad (usbipd-win + pymobiledevice3): live syslog, screenshots, install. Written 2026-08-02, NOT yet run end to end; the tunnel-based screenshot phase is the uncertain part.
- [[on-device-test-checklist]] - the human on-glass pass after a Sideloadly install; the engine side of every item is coverable by the hands-on FFI simulation (scripts/simulate.sh).
- [[net-highid-and-port-forwarding]] - HighID validated on the dev box (2026-07-14, 5-link manual chain) AND on the iPad via unicast-SSDP UPnP (2026-07-17); topology since 2026-07-17 is XB8-bridged -> TP-Link BE9700 (real UPnP IGD), which replaced the manual chain.

## Reference
- [[ref-ecosystem]] - eMule AI fork, eMule-Board dev forums, official aMule docs site.
- [[ref-source-trees]] - the reference source oracles under refs/ (eMule 0.50a/0.70b, aMule master); protocol authority + findings.
- [[ed2k-protocol-archaeology]] - historical study materials (Gosling 2003 GIAC paper, dtool.pl, oldversion.com MetaMachine binaries); cross-confirm padMule's wire + leads for the Lugdunum project.
- [[emule-peer-oracle]] - a SECOND live peer oracle: real eMule on the Windows host (mirrored-mode 127.0.0.1:4663), driven by scripts/emule-oracle.sh; complements the headless amuled differential test and is the faithful other-side for secure-ident (#32). Manual (Anthony launches eMule).
- [[ed2k-server-oracle]] - the SERVER oracle: real Lugdunum eserver 17.15 run LOCALLY + fully ISOLATED (unshare -rn, zero egress), driven by scripts/eserver-oracle.sh. padMule logs in against real eserver; enables #9 global-UDP-search testing. Untrusted binary, gitignored, sha256-verified; i686 build (x86_64 hits the vsyscall trap).
- [[kad-verify-oracle]] - the REVERSE-Kad oracle: a log-patched real amuled 3.0.1 (logging-only patch on a build copy; pristine tree untouched) that proves a real node marks padMule IP-VERIFIED via the v8 HELLO_RES_ACK handshake. The wave-10 send-side terminal proof (2026-08-02). scripts/kad-verify-oracle.sh.

## Process
- [[decisions-and-lessons]] - locked decisions, rejected approaches, gotchas.
- [[build-history]] - archive: the completed-milestone narratives (code-fix rounds, live milestones, differential-test history, wave notes) split verbatim out of [[build-progress]] on 2026-08-01.
- [[build-progress]] - wave-by-wave build status. Engine complete through Kad + multi-source fetch; padMule RUNS on the iPad and does the full search->download->verify->save loop on-device; 0.70b Tier 1 COMPLETE + 9 Tier-2 items ([[emule-070b-features]]). Since 2026-07-20: the v1 readiness audit (8z), the reanalysis lint + Rust CI (8aa), the bulletproof security batch (8ab), the reverse peer oracle + multipacket serve (8ad/8ae), serve-side secure-ident + the full credit system (8af-8ah), the per-source corruption ban (8ai), and wave 10 Kad hard-verify (send-side keys + v8 handshake DONE and terminal-proven via [[kad-verify-oracle]]; Batch B enforcement pending), plus the 8aj/8ak reanalysis lint + fix round (doc drift, Kad key capture, nodes.dat v3, load gate, serve-path faithfulness, harness). Repo has LICENSE (GPL v2) + NOTICE + README.

## Backlog / feature ideas
- [[feature-server-hunter]] - discover + verify live eD2k servers (auto-update, health-check, server-graph crawl); NOT literal whole-net scanning. Partially shipped (the auto-update/merge + prune landed as the 8y server manager; the status probe as the 8x Servers screen); the gossip crawl remains future work.
- [[emule-070b-features]] - ranked backlog of eMule 0.70b features to adopt. From the 2026-07-18 dive; Tier 1 is COMPLETE (#1-10), and 9 Tier-2 items landed too (#11, 13, 14, 17-21, 30, 32-throttle); the rest of Tier 2+ is open backlog.

## Strategy
(All the big forks are LOCKED and executed - Rust engine rewrite, no-Mac
CI+Sideloadly deploy path, foreground-only v1 - see [[decisions-and-lessons]];
the app is shipped and on-device, and 0.70b Tier-1 parity is done
([[emule-070b-features]]). Current direction: the BULLETPROOF security release
gate - close the [[security-model]] scorecard (22 operational / 2 partial / 2
documented opt-outs as of 2026-08-02). Serve-side secure-ident, the full credit
system (store + reweight + accrual), and per-source corruption attribution + ban
all landed 2026-08-02 ([[build-progress]] 8af-8ai); server-obf is a documented v1
opt-out ([[obfuscation-posture]]). The Kad hard-verify send-side is DONE,
terminal-proven (a log-patched real amuled verifies padMule via the v8
HELLO_RES_ACK handshake, [[kad-verify-oracle]]) and now key-capture-complete
(8ak). The ONLY protocol item left for the gate is wave-10 Batch B: verified-bit
ENFORCEMENT in routing, flag-gated and offline-provable. Wave 9 seedbox mode is
the open v1.1 item.)
