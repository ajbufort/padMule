# eMule 0.70b Feature Backlog (mined for padMule)

Updated: 2026-07-18 (first slice landed)

**First slice DONE (2026-07-18):** #1 IP filter, #2 search history, #3 wire-side
search filters (availability + size). See the code-fix-round-adjacent commits +
[[build-progress]]. #4 verified-identity badge is deferred - it needs a
per-source detail sheet (#21) to render on, which does not exist yet.

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
4. **Verified-identity badge + obfuscation glyph** (small, no wire). padMule
   already runs secure-ident (`credits`/`identity.rs`) but shows no badge; a
   verified checkmark + a lock glyph are pure presentation of held state.
5. **Download categories + transfer filter chips** (medium, no wire). Named
   color buckets + a state/type chip row over the flat transfer list. On-disk
   only (category index in part.met, never exchanged). Foundational for #24/#25.
6. **Ratings/comments READ + display** (medium, medium risk). Parse
   TAG_FILECOMMENT 0xF6 / TAG_FILERATING 0xF7 from source filename-answers, badge
   the row red "Fake" / green "Excellent". The top pre-download quality signal;
   dodge a bad file before spending a session on it. (Authoring = #20, Kad = #22.)
7. **Per-download priority (Low/Normal/High) + Auto** (small, no wire).
   Auto self-tunes by source count; local (FT_DLPRIORITY in part.met).
8. **Transfer-list management** (small, low risk): rename, clear-completed,
   per-file unshare. Local; only wire edge is re-advertising a renamed shared
   file (keep IsValidEd2kString rules).
9. **Global server UDP search** (medium, medium risk). Query the whole
   serverlist, not just the connected server - the biggest widening of the result
   set. padMule already owns the UDP socket + serverlist + search expression;
   delta is a paced timer + per-server UDP opcode + dedupe. Ship with a spam
   filter (#15) since global results are noisy. Heed the server-UDP +4 landmine
   ([[padmule-protocol-landmines]]).
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
| 20 | Author your own rating/comment + serve it back | med | medium |
| 21 | Per-peer / per-source detail sheet | small | none |
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

## Recommended first slice

The Tier-1 items that are safe AND make padMule feel complete on day one:
**IP filter (#1)**, **search history (#2)**, **wire-side search filters (#3)**,
and the **verified badge (#4)** - all small, three of four wire-neutral or
low-risk, no format changes. Ratings-read (#6) and categories (#5) are the next
step up in value once those land.

## Related

- [[protocol-reference]] - tag/opcode byte layouts for the wire-touching items.
- [[decisions-and-lessons]] - replicate-wire / improve-internals boundary.
- [[ref-source-trees]] - refs/emule-0.70b as the reference tree.
- [[build-progress]] - what is already built (do not re-propose).
