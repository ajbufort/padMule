# Kad routing lifecycle - the two tables, and who maintains them

Updated: 2026-08-07 (row 8ch: ALPHA is a CONCURRENCY parameter and padMule used
it as a batch size - see "How much a lookup costs" below, which changes what
every Kad timeout in the tree means. Row 8cf: keyword SEARCH added - three
pieces, two of them missing since Wave 6, including the expression tree. Created
2026-08-06 by the reanalysis pass, [[build-progress]] 8ce)

Where Kad contacts live, how they get there, what survives a pause, and which of
eMule's maintenance duties padMule performs. This entry exists because its
absence cost a misdiagnosis: the 2026-08-05 "resume threw the Kad table away"
finding named the wrong table, and the fix that followed addressed the bootstrap
DIAL LIST rather than the table it was written about (row 8cd -> corrected in
8ce).

## THERE ARE TWO TABLES. This is the whole point of the entry.

| | `Engine::routing` | `KadNode::routing` |
|---|---|---|
| Type | `mule_kad::RoutingTable` | `mule_kad::RoutingTable` |
| Lifetime | the whole process | ONE `start_kad` call - destroyed on pause/stop |
| Fed by | nodes.dat at `start()`, plus `absorb_kad_routing` folding the live table in on every `set_kad` | **SEEDED from the gated contact list**, then the bootstrap response, then every lookup answer |
| Used for | the bootstrap DIAL LIST, and the nodes.dat checkpoint | **every lookup** - `closest_to` reads THIS one |
| Monotonic? | YES - nothing ever removes a contact | rebuilt on every `start_kad`, but no longer from empty |

`maintain_kad`'s size guard reads the SECOND. **`Engine::kad_contacts()` also
reads the second now** (falling back to the first only while Kad is down) - it
used to read the first unconditionally while the `Kad` EVENT carried the second,
so one UI field meant two things. Fixed 2026-08-06, [[build-progress]] 8ce.

## What used to happen on a resume, and why it looked like a loss

1. `pause()` -> `set_kad(None)` -> `absorb_kad_routing()` folds the live table
   into `Engine::routing`. Nothing is lost HERE.
2. `resume()` -> `start_kad()`.
3. `KadNode::bind_with_identity` constructs `RoutingTable::new(kad_id)` -
   **EMPTY** (kad_live.rs:176).
4. `bootstrap_any` walks the gated dial list and **returns on the FIRST
   success** (kad_live.rs:416-418).
5. `bootstrap_from` adds the responder plus the ~20 contacts its BOOTSTRAP_RES
   names (kad_live.rs:389-402).

So the live table after any `start_kad` was about 21 contacts. **That is where
the "21" in the 2026-08-05 syslog came from** - a table being BUILT, not one
being discarded. `Engine::routing` was never reduced: `start_kad` only ever calls
`load_nodes`, which merges.

Worse for lookups: `closest_to` is verified-only (`enforce_verified`, ON by
default, routing.rs:377 - eMule `CRoutingBin::GetClosestTo` RoutingBin.cpp:244),
and of those ~21 exactly ONE was verified (the responder proved its IP by echoing
our key; the contacts it NAMED are added unverified). **The seed set for the
first lookup after a bootstrap was one contact.** Lookups still converged,
because `Lookup` expands from its own wire answers rather than re-reading the
table and each responder becomes verified via `note_responder` - but the table
the user was shown had nothing to do with the table the lookups ran on.

The union added in 8cd improved WHICH contact answers first, not how many end up
in the live table.

**FIXED 2026-08-06 (8ce):** `KadNode::seed_routing` fills the fresh node from the
same gated contact list, called from `start_kad` BEFORE the bootstrap - so a
bootstrap that fails outright still leaves a usable table, and `maintain_kad`
(guarded on `contacts_known() > 0`) can still run. The seeding goes through the
gated `add_contact`, and carries the VERIFIED bit and the stored verify key
across: without the bit the seeds would inflate `contacts_known()` while staying
invisible to `closest_to`, which is worse than not seeding at all, because the
number would then claim the problem was solved.

## How much a lookup COSTS - alpha is concurrency, not a batch size

Until 2026-08-07 every lookup in `kad_live.rs` did this:

```rust
let batch = lookup.next_queries(ALPHA_QUERY, K);
for node in &batch { self.find_node(node, target, per_query).await }
```

`ALPHA_QUERY`'s own doc comment says "concurrent queries in flight (eMule
`ALPHA_QUERY`)", and eMule's `CSearch` does keep three requests outstanding and
reacts to whichever answers first. padMule took three and then **blocked on each
in turn**, so a round cost `ALPHA_QUERY * KAD_PER_QUERY` instead of
`KAD_PER_QUERY`:

| Call | Structural worst case BEFORE | AFTER | Its budget |
|---|---|---|---|
| `resolve_keyword` | 12x3x750ms lookup + 10x750ms keyword = **34.5s** | 12x750ms + 4x750ms = **12s** | `KAD_SEARCH_WAIT` 15s |
| `resolve_sources` | same shape = **34.5s** | **12s** | 6-15s per caller |
| `refresh_routing` | 4x3x750ms = **9s** | 4x750ms = **3s** | `KAD_MAINTENANCE_BUDGET` 3s |

Consequences that were being read as other problems:

- **The search cap WAS the search cost.** `KAD_SEARCH_WAIT` looked like a safety
  bound and was the actual duration of every search, because the work beneath it
  could not finish inside it. The device-measured 10.3s submit-to-results was
  the Kad arm running until it was cut off, with the server arm having answered
  in under a second and `tokio::join!` waiting for the slower one.
- **Kad maintenance never completed a round.** 9s of work under a 3s deadline
  got through about four of its twelve queries, every 120 seconds, which is a
  large part of why the table grows as slowly as it does.

**ONE SOCKET IS WHY IT WAS SERIAL, and it is the real difficulty.**
`UdpSocket::recv_from` hands each datagram to exactly one waiter, and the old
`request` loop DISCARDED anything not from its own destination - so two
concurrent requests would silently eat each other's replies. The fix is a batch
demultiplexer (`KadNode::request_batch`): send the whole batch, then run ONE
receive loop that matches each datagram to the slot waiting on it. A datagram
that used to be dropped as "not mine" now reaches the peer in this batch that
wants it. Matching is by EXACT address, falling back to the old IP-only rule,
because `MAX_CONTACTS_PER_IP` permits two contacts on one address in a batch.

Wire-identical: same datagrams, same keys, same peers, same obfuscation. Only
the order of our own waiting changed - and concurrent alpha is what eMule does,
so this is closer to the authority, not further from it.

`request` is now a batch of one, so there is exactly ONE receive loop in the
file. The sender-key capture (`note_responder`) moved OUT of the request helpers
and into the callers, because the batch collects with `&self`; the two tests that
pin that capture were rewritten to drive `resolve_sources` / `resolve_keyword`
rather than the helpers, or they would have passed with the production call site
deleted.

## Which eMule maintenance duties padMule performs

eMule runs two timers on each routing zone. padMule implements one of them.

| eMule | What it does | padMule |
|---|---|---|
| `CRoutingZone::OnBigTimer` (RoutingZone.cpp:807) -> `RandomLookup` (:925) | random-target FIND_NODE **per zone**, target = zone prefix XOR self | `Engine::maintain_kad` -> `KadNode::refresh_routing`, ONE **globally** random target every 120s |
| `CRoutingZone::OnSmallTimer` (:858-920) | expire type-4 contacts past `m_tExpires` when not `InUse`; HELLO-ping the OLDEST contact in each bin | **NONE** |

Consequences of the missing half:

- `mule_kad::Contact` carries no timestamp and `RoutingTable` has **no removal
  path at all** - `Zone::add` only pushes, refreshes in place, or drops the
  INCOMING contact (routing.rs:106-161). A contact verified once stays verified
  and reachable-looking forever.
- Dead contacts accumulate in `Engine::routing` (monotonic) and are persisted
  into nodes.dat, where they cost bootstrap attempts on the next launch.
- `KAD_TABLE_TARGET`'s comment "Refresh resumes if the table shrinks"
  (engine.rs:211) describes something that cannot happen.

The per-zone vs global random target is a deliberate padMule choice, argued in
`refresh_routing`'s doc comment: keyword targets are uniform over the keyspace,
so a uniform refresh matches the query distribution. Wire-neutral policy, so
[[decisions-and-lessons]]'s eMule-wins rule does not bind - but it does mean the
NEAR bins are never refreshed on purpose, which is what serving other people's
lookups depends on. Unmeasured either way.

## nodes.dat: what gets written, and what gets dropped

`checkpoint()` -> `checkpoint_contacts(persisted, live)` -> `write_nodes_dat`,
capped at `MAX_NODES = 200` (nodes_dat.rs:17, matching aMule's
`GetBootstrapContacts(200)`).

The cap is faithful; **the SELECTION is not.**

- padMule: `routing_to_nodes` walks the zone tree in order (closest half first),
  `checkpoint_contacts` preserves persisted-first ordering, and the writer takes
  the first 200. Newly-learned contacts sort LAST and are the first dropped.
- eMule: `GetBootstrapContacts` -> `TopDepth(LOG_BASE_EXPONENT = 4)`
  (RoutingZone.cpp:687-698) descends four levels and then takes ONE **RANDOM**
  bin per subtree - an explicitly SPREAD sample, described in its own comment as
  "a very nice sample of contacts to save".

This did not bite before 2026-08-05 because `Engine::routing` rarely exceeded
200. `maintain_kad` now feeds it, so it does.

## A failed bootstrap is unrecoverable within a foreground session

`start_kad` runs only from `start()` and `resume()`. `maintain_kad` returns early
at `contacts_known() == 0` ("nothing to walk from"). So a bootstrap that misses -
an offline moment, a VPN reconnect - leaves Kad dead until the user backgrounds
the app and returns. Nothing retries it.

## Keyword SEARCH: three pieces, and two of them were missing until 2026-08-07

Kad indexes one entry **per word**, never per phrase. A search therefore has
three parts, all specified in `docs/raw/wave6-kad-research-2026-07-14.md` line
246 and none of them implemented until row 8cf:

1. **Tokenise** on `INV_KAD_KEYWORD_CHARS`, keep tokens of UTF-8 byte-length
   >= 3, lowercase, de-duplicate by moving a repeat to the BACK, and drop a
   trailing 3-char/3-byte token as a presumed file extension - unless the string
   ended in a delimiter, which suppresses that rule (upstream still iterates on
   the empty token and zeroes the counters the rule reads).
2. **Hash ONE word** - the first survivor (`m_listWords.front()`) - as the
   lookup target. Hashing the phrase targets a hash nobody publishes to, and the
   lookup converges perfectly on empty space rather than failing.
3. **Attach a search-expression tree** so the STORING NODE filters before it
   chooses what to return. Without it a common first word ("yes") yields a
   bounded sample of an enormous pool, and the wanted file is never in the
   sample. **Local filtering cannot recover what was never sampled** - which is
   why pieces 1 and 2 alone still returned zero for "Yes Prime Minister".

Expression wire format (decoded 2026-08-07; Wave 6 had it as "UNSURE - not
byte-decoded"), `SEARCH_KEY_REQ` = `target 16 | (start_pos | 0x8000) u16 |
expression`, expression in PREFIX order:

| Byte | Node |
|---|---|
| `0x00` | boolean - then op `0x00` AND / `0x01` OR / `0x02` NOT, then LEFT, then RIGHT |
| `0x01` | string term - u16-length-prefixed UTF-8, lowercased |
| `0x02` | meta tag - value string, then u16 name length, then name |
| `0x03` / `0x08` | numeric relation, 32- / 64-bit |

The restrictive flag rides in the **top bit of the start-position word**, not a
field of its own; the receiver masks it with `& 0x7FFF`. **Depth limit 24** -
exceed it and the far end discards the whole expression and answers unfiltered,
which looks like the feature silently not working.

## padMule PUBLISHES NOTHING to Kad (2026-08-07)

Opcodes `0x43`-`0x45` are not defined in `message.rs` and there is no call site.
padMule reads the DHT and writes nothing, so **its shared files are invisible to
every other client searching Kad**. Nothing records this as a deliberate
deferral; it was simply never built. Wave 6 captured the opcode TABLE and never
decoded the payloads, which is why nothing flagged the gap.

The payloads, decoded 2026-08-07 from eMule `CSearch::StorePacket`
(Search.cpp) so the research gap is closed even before the feature is built:

| Opcode | | Payload |
|---|---|---|
| `0x43` | `PUBLISH_KEY_REQ` | `keyword_target 16 \| count u16 \| [ fileID 16 \| taglist ] x count` |
| `0x44` | `PUBLISH_SOURCE_REQ` | `file_target 16 \| our_client_hash 16 \| taglist` |
| `0x45` | `PUBLISH_NOTES_REQ` | `file_target 16 \| our_kad_id 16 \| taglist` |
| `0x4B` | `PUBLISH_RES` | load factor back from the storing node |
| `0x4C` | `PUBLISH_RES_ACK` | null |

- **Keyword taglist** (`PreparePacketForTags`): `TAG_FILENAME` str,
  `TAG_FILESIZE` (uint, or BSOB-8 above 4 GB), `TAG_SOURCES` uint,
  `TAG_FILETYPE` str when the ed2k type is non-empty, `TAG_KADAICHHASHPUB` only
  for a v9+ target holding an AICH hash. Batched **50 files per packet, 150
  total** per keyword.
- **Source taglist**: `TAG_SOURCETYPE` (1 HighID / 6 firewalled-with-direct-
  callback), `TAG_SOURCEPORT`, `TAG_SOURCEUPORT`, `TAG_FILESIZE`, plus the
  crypt byte - the same shape padMule already PARSES out of `SEARCH_RES`.
- **Republish clocks** (`opcodes.h:76-78`): sources every **5 h**
  (`KADEMLIA REPUBLISHTIMES`), keywords and notes every **24 h**. Entries age out
  against those, so publishing that stops is forgotten rather than retracted.

Building this is a genuine feature, not a bug fix: it changes what padMule puts
on the network. It needs the codecs AND a publish lookup driver AND a scheduler,
together - codecs alone would be dead code, which is the [[build-progress]] 8by
mistake (`build_out_of_part_reqs` unreachable outside tests).

## Reading the instruments honestly

- **"Kad contacts" now means the LIVE table** (`Engine::kad_contacts()` reads the
  node when there is one, the persisted table only while Kad is down), and every
  `EngineEvent::Kad` emit site carries the same quantity. So the number CAN fall,
  and a fall is real information.
- **Before 2026-08-06 it could not.** The poll returned `Engine::routing.len()` -
  monotonic, no removal path anywhere - while the event carried the LIVE count
  from `start_kad` and `maintain_kad`, and both wrote the same `kadContacts`
  field. A drop in the `kad contacts: N` syslog line from that era is an
  entry-path change, not a loss. Do not read old captures as if they meant what
  the same line means now.
- It is still not a full picture: `closest_to` hands out only the VERIFIED
  subset, so a table of N contacts can offer far fewer than N lookup candidates.
  A count that looks healthy while searches stay thin is that gap.

## Related

- [[build-progress]] - rows 8cd (the maintenance + reseed work) and 8ce (this
  audit and what it corrects).
- [[padmule-kad-notes]] - byte-exact Kad wire/format facts (memory).
- [[an-event-is-not-state]] - the two-measurements-one-field defect is instance 7
  (memory).
- [[verify-before-reporting]] - a citation proves a mechanism exists, not that it
  fired; 8cd's stated cause is the current example (memory).
- [[lifecycle-and-reactivation]] - what pause/resume is required to preserve.
- [[protocol-reference]] / [[security-model]] - the verified-bit enforcement this
  entry leans on.
