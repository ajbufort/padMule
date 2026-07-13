# padMule Wiki - Log

Append-only, timestamped record of Ingest / Query / Lint passes.

- 2026-07-12 Ingest: project bootstrapped. Extracted upstream amule-3.0.1 zip,
  surveyed layout/build options, wrote [[arch-upstream-amule]]. Ingested
  Anthony's references (eMuleAI GitHub, eMule-Board threads, aMule docs site)
  into [[ref-ecosystem]]. FinalWord-style system installed: CLAUDE.md schema,
  kb-reflect Stop hook, seeded memory.
- 2026-07-12 Ingest: locked decision - engine strategy = Rust rewrite (SwiftUI shell, aMule C++ as reference oracle); wrote [[decisions-and-lessons]], updated index.
- 2026-07-12 Ingest: iPadOS constraints research (2 workflows, adversarially verified) -> docs/raw/ipados-constraints-research-2026-07-12.md + wiki [[ipados-constraints]]. Load-bearing: foreground-only engine, sockets fine, free-team sideload limits, part-file storage plan.
- 2026-07-12 Ingest: upstream recon workflow (5 subsystems, 2.4M tokens, all high-confidence) -> docs/raw/amule-upstream-reference-2026-07-12.md (1746 lines) + wiki [[protocol-reference]]. Key: PARTSIZE 9728000, eD2k part count floor+1 (not ceil), kad UDP overhead 16B, clients.met 119B, ports 4662/4672/4712, this tree is a MODIFIED aMule (wire=upstream, policy may differ).
- 2026-07-12 Ingest: Wave 1 landed - mule-proto crate + verified ed2k_hash (single/multi-part + exact-multiple edge case), 7 tests green. Wrote [[build-progress]]. Design spec + Wave-1 plan committed.
