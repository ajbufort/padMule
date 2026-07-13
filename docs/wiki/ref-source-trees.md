# Reference Source Trees (oracles)

Updated: 2026-07-13

Read-only reference source, extracted under `refs/` (gitignored - do NOT commit
the bulk source; curated findings go in the KB). Anthony supplied these on
2026-07-13 to disambiguate our tree and give protocol authority.

| Tree | Path | Role |
|------|------|------|
| aMule 3.0.1 (our port target) | `amule-3.0.1/` (repo root, committed) | Primary oracle; the version being ported. |
| eMule 0.50a | `refs/emule-0.50a/eMule0.50a-Sources/srchybrid/` | Canonical mainline eMule = de-facto eD2k/Kad protocol authority. |
| eMule 0.70b | `refs/emule-0.70b/eMule0.70b-Sources/srchybrid/` | Community-fixed/altered eMule; check for protocol fixes. |
| aMule mainline (master, v3.0.1-dev) | `refs/amule-master/amule-master/src/` | Pristine aMule dev branch; diff to see what (if anything) our tree changed. |

eMule source lives in `srchybrid/` (opcodes.h, Packet.cpp, SafeFile.cpp,
kademlia/, EncryptedDatagramSocket.cpp, ClientCredits.cpp, ...). aMule master
mirrors our tree's `src/` layout.

## Findings so far (2026-07-13)

- **"Modified tree" caveat RETIRED.** Our `amule-3.0.1` is faithful aMule.
  GetMaxSlots N_FLOOR=20 (with its exact comment) and ALPHA_QUERY=5 (with the
  "cascade" comment) are byte-identical in aMule master. These are aMule design,
  NOT local hacks. They are aMule-vs-eMule POLICY (wire-neutral). See
  [[protocol-reference]].
- **aMule vs eMule confirmed differences (policy, wire-neutral):**
  ALPHA_QUERY = 5 (aMule) vs 3 (eMule 0.50a/0.70b). SEARCHTOLERANCE = 16777216
  in all three (canonical). aMule has GetMaxSlots; eMule structures upload slots
  differently.
- **Wire/format landmines CONFIRMED canonical in eMule 0.50a:** userhash
  `[5]=14, [14]=111` (Preferences.cpp:656); `CRYPT_HEADER_WITHOUTPADDING=8`,
  `MAGICVALUE_UDP_SYNC_CLIENT=0x395F2EC1` (EncryptedDatagramSocket.cpp); Kad
  `CUInt128::SetValueBE` exists (UInt128.h). So the [[protocol-understanding]]
  interop rules match the protocol authority, not just aMule.

## How to use these

- For a WIRE or FILE-FORMAT question: eMule 0.50a is authority (0.70b for any
  later fix). Confirm byte layouts here before implementing crypto (Wave 5) and
  Kad (Wave 6) - esp. cryptkey.dat RSA/DER, the BOM/doubled-string-tag behavior,
  and the exact SetValueBE byte order.
- For "is our tree standard aMule?": diff against `refs/amule-master`.
- For POLICY (queues, slots, alpha, scoring): match aMule (our tree); it is
  wire-neutral either way.
- Verify claims adversarially against the source (the same discipline as the
  original recon); record corrections in the KB.

## Related

- [[protocol-reference]]
- [[protocol-understanding]]
- [[decisions-and-lessons]]
