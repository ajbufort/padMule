# eMule 0.70b Feature Backlog (mined for padMule)

Updated: 2026-07-19 (Tier-1 largely done incl. #9 global UDP search; codec+CLI, engine/app integration a follow-up)

**DONE so far:** #1 IP filter, #2 search history, #3 wire-side search filters,
#4 verified badge (BOTH the encryption lock AND the identity checkmark - the
secure-ident redo works inline with the download and verified a real aMule
source), #5 categories, #6 ratings/comments (server rating + OP_FILEDESC comment
READ), #7 per-download priority (Low/Normal/High; Auto deferred), #20 authoring
your OWN rating/comment + serving it (OP_FILEDESC write), #21 per-source detail
sheet, #8 (partial: per-file unshare). See [[build-progress]].

A ranked proposal of features padMule could adopt from eMule 0.70b, from a
4-surveyor + synthesis dive over `refs/emule-0.70b`. Scope: GUI/feature-level
items BEYOND the 2026-07-15 engine pass (which already took ed2k/magnet link
parsing, Kad anti-abuse hardening, and the "Automatic" search method). Ranked by
(value to a touch iPad P2P user) x feasibility, penalizing poor platform fit
(foreground-only, small screen, sideloaded) and wire/interop risk. See
[[replicate-then-improve]] discipline: client-side/UX beats format changes.

## Tier 1 - do soon (high value, mostly safe)

1. **IP filter** - DONE (2026-07-18). `mule-files::ipfilter` parses ipfilter.dat +
   .p2p (format-faithful to aMule), blocks ranges with level < 127; engine gates
   outbound sources + inbound peers (after handshake, so the server's HighID
   probe is never filtered). FFI count + Status row; `mule-cli ipfilter`.
2. **Search history / autocomplete** - DONE (2026-07-18). UserDefaults-backed MRU
   (12, case-insensitive de-dupe) as a "Recent" section, tap-to-rerun,
   swipe-to-delete. Swift-only.
3. **Push filters into the search PACKET** - DONE (2026-07-18). SearchParams
   min_sources -> FT_SOURCES `> N-1` (universal op); size min/max on the wire
   (max > 4 GiB omitted, enforced client-side). FFI SearchFilters +
   "Complete sources only" toggle + size preset menus. Type stays client-side.
4. **Verified-identity badge + obfuscation glyph** - DONE (2026-07-19, redo;
   commit 1bd4e00). BOTH the encryption LOCK (per-source `obfuscated`) and the
   identity CHECKMARK are live. The redo fixes the deadlock the first attempt
   (d401ec6, reverted dbfecad) hit: it advertises SecureIdent v1 in the fetch
   HELLO (`HelloInfo::with_secident`, sec_ident=1) so a real uploader INITIATES;
   `run_peer` threads a `SecIdentCtx`, builds the dual-role `SecureIdentSession`
   (RESPONDER, not the initiator-only `run_secure_ident`), proactively sends ONE
   OP_SECIDENTSTATE, and handles the 3 secure-ident opcodes INLINE in its four
   read loops (`handle_aux_packet`) - riding on packets the transfer reads anyway,
   NEVER waiting, so a silent peer just stays unverified (no deadlock, no delay).
   note_source_verified -> the SourcesView blue seal (already wired). VALIDATED
   against a faithful other-side (the lesson from the revert, [[interop-test-fidelity]]):
   a unit test with a mock uploader that INITIATES secure-ident + serves, AND the
   amuled differential test - padMule verified a REAL aMule 3.0.1 source
   ("verified: true") AND transferred byte-for-byte. Design blueprint was a
   source-cited eMule 0.50a study (BaseClient.cpp:2251-2261 gates the exchange on
   the peer's advertised support). Live confirmation vs real eMule: the
   [[emule-peer-oracle]] path.
5. **Download categories + transfer filter chips** - DONE (2026-07-18). Color
   buckets + a filter-chip row + a per-download context menu. CLIENT-SIDE
   (definitions + hash->category in UserDefaults, NOT part.met - zero wire risk;
   a deliberate simplification since padMule does not sync part files).
6. **Ratings/comments READ + display** - DONE (2026-07-19). BOTH channels:
   (a) the SERVER rating (FT_FILERATING 0xF7, masked `(v&0xF)/3`, aMule-averaged)
   badges search rows + flags rating-1 Fake; (b) a source's COMMENT + per-source
   rating (OP_FILEDESC 0x61, post-connect - padMule already advertised
   AcceptCommentVer=1) is recorded per source, averaged onto the download row,
   and shown in the per-source sheet (#21). Authoring your own (#20) is now DONE
   (see the Tier-2 row). Still TODO: Kad notes (#22).
7. **Per-download priority (Low/Normal/High)** - DONE (2026-07-19). Set from the
   transfer-row context menu (a Priority submenu + an up/down row glyph).
   HONESTLY honored, not cosmetic: the fetch manager reads priority live every
   round, so High contacts more sources at once (Low 2 / Normal 4 / High 6
   concurrent peers) and sweeps more rounds (6/8/12); resume_fetches finds
   sources for high-priority parts first. Persisted byte-faithfully to part.met
   (both FT_DLPRIORITY 0x18 + legacy FT_OLDDLPRIORITY 0x13 as UINT32, same value,
   as aMule writes them PartFile.cpp:928-933; unknown/PR_AUTO clamps to Normal).
   AUTO deferred: it needs a periodic source-count recompute loop the engine does
   not have (source-finding is one-shot per download today).
8. **Transfer-list management** - PARTIAL (2026-07-18). Per-file UNSHARE done
   (swipe on the Shared screen; removes from library + known.met, keeps the
   file). Dropped clear-completed (finished downloads already auto-remove;
   swipe-cancel covers a stuck one); rename deferred (on-disk rename + known.met
   rewrite; keep IsValidEd2kString rules for a re-advertised name).
9. **Global server UDP search** - DONE (2026-07-19, codec + CLI harness; commit
   1d0b81e). build_global_search_udp = the SAME search tree as the TCP request
   (shared write_search_tree) wrapped as OP_GLOBSEARCHREQ 0x98 (the universal
   fallback; 0x92/0x90 large-file opcodes deferred). parse_global_search_res
   walks the chained [0xE3][0x99] records (NO count field, unlike TCP). CLI
   `global-search <server.met|host:port> <keyword>` fans out to each server's UDP
   port = TCP port + 4 (the landmine, [[padmule-protocol-landmines]]), paced,
   anti-spoof allow-list, dedupe by hash, zlib-packed reply handled. VALIDATED:
   SEND interoperates with the local isolated eserver ([[ed2k-server-oracle]]);
   full SEND+PARSE round-trip proven against LIVE public eservers (real
   OP_GLOBSEARCHRES -> correct filenames+hashes). Engine/FFI/app integration +
   OP_OFFERFILES (so the local eserver returns hits) are follow-ups.
10. **Related-files search** (small, low risk). Long-press -> "Find related" via
    a `related::`+md4(hash) query, gated by the server's RELATEDSEARCH flag;
    degrade gracefully when absent.

## Tier 2 - do later (real value, bigger or nichey)

| # | Feature | Effort | Wire risk |
|---|---------|--------|-----------|
| 11 | Corruption black box + dynamic client ban | med | none |
| 12 | A4AF cross-download source reassignment | med | none |
| 13 | "Load more results" paging (OP_QUERY_MORE_RESULT) | small | low |
| 14 | Statistics tab (Swift Charts: rate history, totals, ratios) | med | none |
| 15 | Learning spam filter over results (heuristics + mark-as-spam) | med | none |
| 16 | Static up/down speed caps + anti-leech ratio guard | small | none |
| 17 | Preview / open incomplete files (AVPlayer; first+last chunk bias) | med | low |
| 18 | Server manager (priority, pin, prune, auto-update from URL) | med | low |
| 19 | Live server status ping (OP_GLOBSERVSTATREQ) | med | medium |
| 20 | Author your own rating/comment + serve it back - DONE 2026-07-19 (Shared-screen editor -> known.met -> OP_FILEDESC, byte-faithful to aMule SendCommentInfo) | med | medium |
| 21 | Per-peer / per-source detail sheet - DONE 2026-07-19 (SourcesView) | small | none |
| 22 | Kad notes search (ratings by hash, no connected source needed) | large | high |
| 23 | Friend list + grant friend-slot + browse shares | med | low |
| 24 | One-at-a-time download manager | small | none |
| 25 | Auto-categorization rules | small | none |
| 26 | Per-file upload priority (Release + Auto) | small | none |
| 27 | Collections (.emulecollection): open + add-all | med | high |
| 28 | Connection limits + new-connection-rate throttle | small | none |
| 29 | Protocol-overhead accounting | med | none |
| 30 | Boolean search expression (AND/OR/NOT) | med | medium |
| 31 | Kad network visibility tab (routing/keyspace/lookup viz) | large | low |

## Tier 3 - skip (poor platform fit)

- **32 Client-to-client chat (OP_MESSAGE):** foreground-only means missed
  messages + a spam funnel; only adopt for a concrete need, and only with a local
  spam layer.
- **33 Dynamic upload throttling (USS):** the faithful design needs raw
  ICMP/traceroute, which the iOS sandbox blocks. Static caps (#16) instead.
- **34 Time-of-day scheduler:** a suspended app can't fire rules; the premise
  (unattended overnight) is gutted. Only "while running" remains, ~= static caps.

## Recommended first slice (ALL LANDED 2026-07-19)

The Tier-1 items that are safe AND make padMule feel complete on day one:
**IP filter (#1)**, **search history (#2)**, **wire-side search filters (#3)**,
and the **verified badge (#4)** - all small, three of four wire-neutral or
low-risk, no format changes. Ratings-read (#6) and categories (#5) were the next
step up in value. ALL of these have since shipped (this was the plan; kept for the
rationale). Remaining Tier-1: #9 (global UDP search), #10 (related search).

## Related

- [[protocol-reference]] - tag/opcode byte layouts for the wire-touching items.
- [[decisions-and-lessons]] - replicate-wire / improve-internals boundary.
- [[ref-source-trees]] - refs/emule-0.70b as the reference tree.
- [[build-progress]] - what is already built (do not re-propose).
