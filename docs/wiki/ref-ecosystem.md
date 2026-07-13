# eMule/aMule Ecosystem References

Updated: 2026-07-12

References Anthony supplied on 2026-07-12, summarized after fetching.

## eMule AI (modern Windows fork)

<https://github.com/eMuleAI/eMuleAI> - GPL-2.0-or-later, ~3 years of
development, v1.5 released 2026-07 (release thread:
<https://forum.emule-project.net/index.php?showtopic=167175>).

Notable v1.5 work, some of it portable in concept:

- Heavy operations moved off the UI thread; parallel loading of large datasets
  at startup (known.met etc.).
- Upload bandwidth optimization + slot recycling.
- VPN Guard (bind/guard connections to a VPN).
- QUIC transport for faster LowID transfers.
- MediaInfoLib for media metadata.

Caveats: Windows/Visual Studio codebase, desktop UI; config compat note -
known.met / StoredSearches.met become incompatible after updating.

## eMule-Board Development section

<https://forum.emule-project.net/index.php?showforum=83> - subforums: eMule
Development, Bug Reports, Feature Requests, Public Beta Tests, eMule Mods.
Active as of 2026-07; recent items: open-source ed2k server with server-side
NAT traversal coordination; "cherrypick a code within aMule pull requests"
(2026-05); eMule 0.72 public beta test (2026-07).

## eMule-Security.org (test fixtures + Kad bootstrap)

<https://www.emule-security.org> - maintenance resources, not a download hub.
Offers a real versioned `ipfilter.dat`, an Ip-To-Country DB, a real Kad
`nodes.dat`, and an indexed safe server list (no direct server.met). Value to
padMule: golden fixtures for the byte-compat readers and real data to exercise
the live network - `ipfilter.dat` for the Wave-7 IP filter, `nodes.dat` for the
Wave-2 format round-trip AND as actual Wave-6 Kad bootstrap contacts. Fetch
these when those waves start; do not vendor them into the repo (they change).

## Official aMule docs site

<https://amule-org.github.io/docs> - Quick Start, User Manual, Developer
Guide, P2P network protocol details, Contributing. Confirms the modular
amule/amuled/amulegui/amuleweb/amulecmd architecture, EC as the "full remote
control" foundation, and native ARM64 packages on desktop OSes.

## Related

- [[arch-upstream-amule]]
