# padMule Wiki - Index

Updated: 2026-08-03

AI-maintained knowledge base. Start here. See `/CLAUDE.md` for the schema and
the Ingest / Query / Lint workflows.

## START HERE
- [[handoff-next-session]] - the living handoff: current state, open tasks, the top next action, and what was proven vs assumed. Replace wholesale each session.

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
- [[portability-audit]] - usability for people NOT on the dev's network: the Tier-1/2/3 findings from the 2026-08-03 audit (UDP-blocked networks grey out every server, the splash clears before the engine is ready, a disconnected user is told the FILE is missing, no cellular/metered awareness). The Tier-1 slice (all four findings) LANDED and was annotated in place 2026-08-03; Tier 2/3 remain open.
- [[ipados-constraints]] - iPadOS/Rust-on-iOS constraints; foreground-only engine, sockets OK, free-team sideload limits, storage plan (verified 2026).
- [[lifecycle-and-reactivation]] - HARD requirement: honest status notice + clean pause/resume across focus loss; shapes the engine state model from Wave 3c.
- [[mac-toolchain-setup]] - getting padMule onto the iPad (iPadOS 26.5.2). VERIFIED blocker: iPadOS 26 needs Xcode 26 needs macOS Tahoe 26.2, and OCLP has no Tahoe support -> the 2011 mini cannot run it. Escape hatch: padMule is sideload-only (the Xcode-26 mandate is App-Store-only), so CI builds with an older Xcode and Sideloadly installs it (AltStore died on -22411). Path C is the active, proven route.
- [[ipad-usb-tooling]] - give this WSL2 box direct USB access to the iPad (usbipd-win + pymobiledevice3): screenshots, install, syslog, and TOUCH CONTROL via WebDriverAgent (2026-08-02: run end to end; the agent can now drive the app itself - go-ios proved unnecessary). The syslog claim below was corrected 2026-08-03: the engine now logs to os_log (subsystem us.ajbconsulting.padMule, category padMule.engine), device-verified via idevicesyslog capturing a readable boot/pause/resume/Stop narrative from app-authored lines.
- [[on-device-test-checklist]] - the human on-glass pass after a Sideloadly install; the engine side of every item is coverable by the hands-on FFI simulation (scripts/simulate.sh).
- [[net-highid-and-port-forwarding]] - HighID mechanics + the VPN setup (a VPN REPLACES padMule's UPnP path, so it all hinges on provider port forwarding; AirVPN researched and its port 4662 proven UNOBTAINABLE, which is what made the now-shipped port override a prerequisite rather than a nicety - plus the iOS kill-switch gap and padMule's public-address-change guard). HighID validated on the dev box (2026-07-14, 5-link manual chain) AND on the iPad via unicast-SSDP UPnP (2026-07-17); topology since 2026-07-17 is XB8-bridged -> TP-Link BE9700 (real UPnP IGD), which replaced the manual chain.

## Reference
- [[ref-ecosystem]] - eMule AI fork, eMule-Board dev forums, official aMule docs site.
- [[ref-source-trees]] - the reference source oracles under refs/ (eMule 0.50a/0.70b, aMule master); protocol authority + findings.
- [[ed2k-protocol-archaeology]] - historical study materials (Gosling 2003 GIAC paper, dtool.pl, oldversion.com MetaMachine binaries); cross-confirm padMule's wire + leads for the Lugdunum project.
- [[emule-peer-oracle]] - a SECOND live peer oracle: real eMule on the Windows host (mirrored-mode 127.0.0.1:4663), driven by scripts/emule-oracle.sh; complements the headless amuled differential test and is the faithful other-side for secure-ident (#32). Manual (Anthony launches eMule).
- [[ed2k-server-oracle]] - the SERVER oracle: real Lugdunum eserver 17.15 run LOCALLY + fully ISOLATED (unshare -rn, zero egress), driven by scripts/eserver-oracle.sh. padMule logs in against real eserver; enables #9 global-UDP-search testing. Untrusted binary, gitignored, sha256-verified; i686 build (x86_64 hits the vsyscall trap).
- [[kad-verify-oracle]] - the REVERSE-Kad oracle: a log-patched real amuled 3.0.1 (logging-only patch on a build copy; pristine tree untouched) that proves a real node marks padMule IP-VERIFIED via the v8 HELLO_RES_ACK handshake. The wave-10 send-side terminal proof (2026-08-02). scripts/kad-verify-oracle.sh.

## Process
- [[decisions-and-lessons]] - locked decisions, rejected approaches, gotchas.
- [[log]] - append-only, timestamped ledger of every ingest/work session; the
  only complete record of the 2026-08-03 session narrative.
- [[build-history]] - archive: the completed-milestone narratives (code-fix rounds, live milestones, differential-test history, wave notes) split verbatim out of [[build-progress]] on 2026-08-01.
- [[build-progress]] - wave-by-wave build status. Engine complete through Kad + multi-source fetch; padMule RUNS on the iPad and does the full search->download->verify->save loop on-device; 0.70b Tier 1 COMPLETE + 10 Tier-2 items ([[emule-070b-features]]). Since 2026-07-20: the v1 readiness audit (8z), the reanalysis lint + Rust CI (8aa), the bulletproof security batch (8ab), the reverse peer oracle + multipacket serve (8ad/8ae), serve-side secure-ident + the full credit system (8af-8ah), the per-source corruption ban (8ai), and wave 10 Kad hard-verify (send-side keys + v8 handshake DONE and terminal-proven via [[kad-verify-oracle]]; Batch B enforcement DONE 2026-08-02, see 8al-8au below), plus the 8aj/8ak reanalysis lint + fix round (doc drift, Kad key capture, nodes.dat v3, load gate, serve-path faithfulness, harness), rows 8al-8au (outbound crypt-dial policy, source exchange wired, the function strip, wave-10 Batch B verified-bit enforcement, research-pass fixes incl. SO_REUSEADDR + free-space guard + serve request scoring, part.met .bak recovery, the aMule-master delta review + IGD:2 UPnP fix, the status-line fix, the Kad checkpoint/set_kad/periodic-checkpoint work, the explicit Stop action), and the 2026-08-03 session: the portability audit + Tier-1 slice, Settings Tier 0, gzip/zip server lists, os_log, agent-drivable device control (8av-8ay), the OP_GETSERVERLIST ask that made the gossip harvest live (8az), the RECURSIVE UDP crawl + server names (8ba), the USAGE-FEEDBACK ROUND that turned Anthony's first extended session into seven confirmed bugs (8bb - resume only worked when Kad was BROKEN; deleted files were still advertised as COMPLETE), the UPnP mapping retry (8bc), VPN READINESS (8bd/8be - configurable listen-vs-ADVERTISED ports, a UPnP toggle, and a public-address-change guard that pauses sharing because stock iOS has no kill switch), and the on-glass round (8bf-8bh: port fields that fought the user, the strip reorder, a real QuickLook Open for finished downloads, a toolbar Stop/Start, a How-to-use screen, and the title-bar escaping). Repo has LICENSE (GPL v2) + NOTICE + README.

## Backlog / feature ideas
- [[feature-server-hunter]] - discover + verify live eD2k servers (auto-update, health-check, server-graph crawl); NOT literal whole-net scanning. Partially shipped (the auto-update/merge + prune landed as the 8y server manager; the status probe as the 8x Servers screen). Part 1 (server-list URLs) extended to a full multi-URL list 2026-08-03 (Settings Tier 0), gzip/zip-wrapped list unwrap shipped the same day, and part 3's gossip harvest-on-connect landed as a FIRST CUT the same day too - initially INERT (a device pass proved modern servers do not volunteer OP_SERVERLIST on connect), then made LIVE by the OP_GETSERVERLIST ask (also 2026-08-03): a fresh login now asks, both authorities' send site, live-proven (a real public server answered 33 servers). The RECURSIVE UDP crawl then shipped too (2026-08-03, build-progress 8ba): OP_SERVER_LIST_REQ2 asked over UDP of servers we are NOT connected to, recursing - a deliberate deviation, since neither authority ever sends it, justified by probing live servers first. Device-verified: 10 seeds -> 35 servers, 32 of them named. So all four parts are SHIPPED; whole-net scanning stays out of scope.
- [[emule-070b-features]] - ranked backlog of eMule 0.70b features to adopt. From the 2026-07-18 dive; Tier 1 is COMPLETE (#1-10), and 10 Tier-2 items landed too (#11, 13, 14, 17-21, 30, 32-throttle); the rest of Tier 2+ is open backlog.

## Strategy
(All the big forks are LOCKED and executed - Rust engine rewrite, no-Mac
CI+Sideloadly deploy path, foreground-only v1 - see [[decisions-and-lessons]];
the app is shipped and on-device, and 0.70b Tier-1 parity is done
([[emule-070b-features]]). Current direction: the BULLETPROOF security release
gate - the [[security-model]] scorecard now reads 23 operational / 1 partial / 2
documented opt-outs (2026-08-02), and there is NO protocol work left in it. Serve-side secure-ident, the full credit
system (store + reweight + accrual), and per-source corruption attribution + ban
all landed 2026-08-02 ([[build-progress]] 8af-8ai); server-obf is a documented v1
opt-out ([[obfuscation-posture]]). The Kad hard-verify send-side is DONE,
terminal-proven (a log-patched real amuled verifies padMule via the v8
HELLO_RES_ACK handshake, [[kad-verify-oracle]]), key-capture-complete (8ak), and
wave-10 Batch B LANDED (8ao) - the Kad verified bit is now ENFORCED in routing.
AICH block recovery - the single remaining PARTIAL - SHIPPED 2026-08-03 as wave
11 (row 8bj), live-proven against real amuled, so the scorecard is 24/0/2 with no
PARTIAL rows left. Wave 9 seedbox mode is the open v1.1 item.)
