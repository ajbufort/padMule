# Kad routing lifecycle - the two tables, and who maintains them

Updated: 2026-08-08 (row 8cn: **THE LOOKUP IS NO LONGER ROUND-BASED.** eMule's
event-driven `CSearch` shipped - per-request deadlines, alpha kept in flight,
value asks interleaved, no value phase - so every section below that measures or
reasons about ROUNDS is a BEFORE-figure, annotated in place rather than deleted,
because it is the evidence that bought the rewrite. Row 8ck/8cl: padMule ANSWERS
on Kad. Row 8ch: ALPHA is a CONCURRENCY parameter and padMule used it as a batch
size. Row 8cf: keyword SEARCH added - three pieces, two of them missing since
Wave 6, including the expression tree. Created 2026-08-06 by the reanalysis pass,
[[build-progress]] 8ce)

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

## HOW A LOOKUP RUNS TODAY - the event-driven CSearch (2026-08-08, row 8cn)

**Read this before the two sections below it.** Those sections measure a lookup
shape that no longer exists in the tree; they are kept because they are the
evidence that bought this rewrite, not because they describe the code.

The pure state machine is `mule_kad::lookup::CSearch` (no sockets, no timers);
the driver is `KadNode::drive_lookup` (kad_live.rs). `resolve_keyword`,
`resolve_sources` and `refresh_routing` all sit on top of it and kept their
signatures.

| | round-based (until 2026-08-08) | event-driven `CSearch` (now) |
|---|---|---|
| unit of progress | a ROUND of `ALPHA_QUERY` requests | ONE request |
| deadline | per-ROUND window; the round ends when the SLOWEST member answers or the window expires | **per-REQUEST**; each races its own `per_query` |
| a silent peer costs | the whole round (57% of rounds, avg 601ms of a 750ms cap - row 8cm) | only its own slot |
| next hop fires | after the round barrier | INSIDE the response handler, for a contact closer than its responder that makes the top-alpha `best` set (Search.cpp:508) |
| value asks | a separate PHASE after the iteration | INTERLEAVED, strict closest-first, while FIND_NODEs are still outstanding - **there is no value phase** |
| termination | rounds exhausted or the cap | enough results, candidates exhausted, or the overall deadline |

Budgets are UNCHANGED on purpose - 36 FIND_NODEs, `K` value asks, an overall
deadline of `LOOKUP_DEADLINE_QUERIES` (16) x `per_query`. **The rewrite changes
WHEN requests go out, not how many.**

Four things worth knowing that are not obvious from the table:

- **The FRONTIER and the ROUTING TABLE are fed by separate paths.** eMule's
  `Process_KADEMLIA2_RES` hands every acceptable contact to
  `RoutingZone::AddUnfiltered` (KademliaUDPListener.cpp:846) BEFORE `CSearch`
  sees the list; only the search's copy faces the per-answer rules. padMule fed
  one filtered list to both, so putting the new subnet cap where the old dedupe
  lived would have STARVED the table - working directly against the serve loop's
  purpose. `absorb_find_answer` keeps the two apart, pinned by a test that puts
  four contacts from one /24 in the table while the frontier sees two.
- **New per-answer rule: at most 2 contacts per public /24** within ONE answer,
  the responder's own subnet pre-seeded at 1, LAN exempt. eMule's comment at
  Search.cpp:457 says "/28"; the mask is `0xFFFFFF00`, a /24. The code is right,
  the comment is wrong, and `frontier_filter` says so.
- **Only a node that ANSWERED a FIND_NODE is ever value-asked.** The old code
  asked non-responders too. eMule's walk erases tried-unresponded entries unasked.
- **`CSearch` carries a `failed` set eMule does not have.** eMule has no
  per-request deadline and infers death from 3s of silence in JumpStart; padMule
  gives every request its own deadline, so death is an explicit event and the
  walk never has to guess whether the closest entry is dead or still in flight.

Deliberate divergences from eMule, all stated: the walk runs after every state
change rather than only on the 3s-gated JumpStart tick (that tick would put a ~3s
floor under time-to-first-result and erase the win; it remains as stall
recovery); an over-long answer is dropped EVERYWHERE, where eMule's table keeps
it; a timed-out request refills the in-flight set at once, where eMule recovers
one dead peer per 3s tick. SKIPPED deliberately: JumpStart's "best FIND_VALUE
nodes all dead -> re-ask" recovery (Search.cpp:291-322) - it exists because
eMule requests only 2 contacts per hop on a value lookup and can starve on
duplicates of dead nodes, and padMule requests 11 on every hop.

**The instrument was replaced in the same change.** `stats::kad_report` counted
ROUNDS, which stopped existing; leaving it would have produced a panel that reads
plausibly and means nothing. It now reports time-to-first-result and
time-to-completion per value lookup, requests sent / answered / timed out per
kind, a reply-RTT histogram with **TIMEOUT as its own row** (folding timeouts
into a top bucket would let a dead network read as merely slow), and the
in-flight high-water mark. The row-8cm before-figures are preserved verbatim in
`stats.rs`, the FFI doc and [[build-progress]] so the A/B survives the rewrite.

**Fixed en route:** a stale-slot hazard. `KAD_SEARCH_WAIT` and
`KAD_MAINTENANCE_BUDGET` CANCEL these futures, and a cancelled future never runs
its trailing withdraw, so a pending slot outlived its lookup and would swallow
the next reply from that peer. `SlotGuard` withdraws on drop. **The same hazard
remains on `request_batch`'s OWN cancellation path** (bootstrap/hello only) and
is recorded rather than silently carried.

## How much a lookup COSTS - alpha is concurrency, not a batch size

> **[SUPERSEDED 2026-08-08 by row 8cn - see the section above.]** Everything
> below this line describes the ROUND-BASED lookup and the 8ch batching fix that
> preceded the event-driven rewrite. It is kept verbatim because it is the
> measurement that justified the rewrite, and because the A/B against it is how
> the rewrite gets judged. Do not read it as current behaviour.

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

**THE WORST CASE IS NOT THE TYPICAL GAIN, and the table above is worst cases.**
A/B measured 2026-08-07 on this box, old binary vs new, ALTERNATING runs against
the live network so drift hits both (`mule-cli kad-keyword`, per_query 1400ms,
"yes prime minister"):

| pair | before | after | delta |
|---|---|---|---|
| 1 | 6.12s | 3.42s | -44% |
| 2 | 6.73s | 5.02s | -25% |
| 3 | 8.17s | 6.11s | -25% |

New won all three pairs; median 6.73s -> 5.02s, about **-25%**, NOT the 3x the
arithmetic suggests. The reason is that the arithmetic assumes every query costs
the full `KAD_PER_QUERY`, and most queried nodes ANSWER within an RTT - so a
serial round of three cost roughly 3 RTTs, and batching saves 2 RTTs rather than
2 timeouts. The 3x only materialises when the queried nodes are DEAD. Quote the
worst case as a worst case; the expected gain is a quarter to a half.

## What the round barrier actually costs - measured 2026-08-07

`stats::kad_report` counts, per FIND_NODE round, whether the batch window ended
because the last member ANSWERED or because a member never did. Read live off
this box (`mule-cli kad-keyword`, per_query 1400ms):

| | "yes prime minister" | "hedda hopper" |
|---|---|---|
| rounds run | 5 | 6 |
| rounds with a SILENT peer | 2 (**40%**) | 3 (**50%**) |
| requests sent / answered | 13 / 11 | 14 / 11 |
| avg round | 814 ms | 815 ms |
| value windows | 1 | 4 |
| windows with a SILENT peer | 0 (0%) | 3 (**75%**) |
| avg window | 515 ms | 1150 ms |

**ON THE DEVICE IT IS WORSE, and that is the reading that decides it.** Same
panel, read on the iPad over AirVPN (build 19d06d0, per_query **750ms**), after
six searches:

| | dev box (1400ms) | iPad over AirVPN (750ms) |
|---|---|---|
| rounds run | 5-6 per lookup | 29 over 6 lookups (~4.8 each) |
| rounds with a SILENT peer | 40-50% | **62%** |
| requests answered | 11/13, 11/14 (**85%**) | 54/80 (**67%**) |
| avg round | 814ms of 1400ms (58%) | **633ms of 750ms (84%)** |
| value windows with a silent peer | 0-75% | **87%**, avg 699ms of 750ms (93%) |

**Nearly every round and nearly every value window runs to the full deadline.**
The answer rate is what drives it - at 67% the barrier predicts
`1 - 0.67^3 = 70%` of rounds having a silent member, against 62% observed - and
the device's rate is materially worse than the dev box's, which is exactly the
condition padMule ships into.

This also explains a comparison that would otherwise look like a regression:
searches on 19d06d0 measured 7.27 / 8.13 / 7.42s against 4.58-6.38s for 7d1b349
the same day. The Kad search path is byte-identical between those two commits
(`git diff` shows only counter increments and a timer), so the difference is the
swarm answering 67% of the time instead of 85%. **That is the instrument earning
its place on its first reading: "the app feels slower today" became a number.**

**Two corrections to the model this entry carried.**

1. **A lookup runs 5-6 rounds, not 12.** `next_queries` empties once the frontier
   is exhausted, so the `0..12` bound is a safety cap that is never reached. Any
   estimate multiplying by 12 is wrong by a factor of two.
2. **A 15% silence rate poisons ~45% of ROUNDS**, because a round is only as fast
   as its slowest member. That is the arithmetic signature of a barrier and it
   matches exactly: `1 - 0.85^3 = 38.6%` predicted, 40% and 50% observed. The
   answer rate is HIGH; the round-level cost is high anyway.

So the average round costs 814ms against a ~250ms round trip, and the value phase
- which is not overlapped at all - added four more windows at 1150ms for the
second query. **This is the evidence for eMule's event-driven `CSearch`** (no
rounds; a response immediately fires the next request, and value requests
interleave with the lookup, Search.cpp:278-350): it would cut each hop from
"slowest of three, or the deadline" to "as soon as this one answered", and remove
the separate value phase entirely. Estimated on these numbers at roughly 2-3x on
the Kad arm - which is the search's remaining cost.

> **[BUILT 2026-08-08, row 8cn, AND NOW MEASURED - see "What the rewrite
> actually bought" below.]** The 2-3x above was an ESTIMATE derived from this
> table. The measured answer is **-69% on an abundant keyword and -38% on a rare
> one**, and the spread is the interesting part: the estimate only ever counted
> the round barrier, and missed that removing the value PHASE is the bigger win
> whenever a search has enough results to stop early.

## What the rewrite actually bought - measured 2026-08-08 (off-device A/B)

Old binary (`main` @ `54384f2`, round-based) vs new (`kad-csearch` @ `eb7ee3c`,
event-driven), **alternating** runs against the live network so swarm drift hits
both arms, same `nodes-fresh.dat` seed for every run (`kad-keyword` only READS
it), CLI `per_query` 1400ms in both. `bootstrap_any` / `request_batch` are
byte-identical between the two commits, so **bootstrap is a CONTROL** - and it
tracked within ~1s inside every pair, which is what says the two arms met
comparable network conditions.

| keyword | hits | old median SEARCH | new median SEARCH | delta | pairs won by new |
|---|---|---|---|---|---|
| "yes prime minister" | 50-55 | 8.26s | **2.56s** | **-69%** (3.2x) | 5 of 5 |
| "hedda hopper" | 4 | 9.12s | **5.64s** | **-38%** (1.6x) | 4 of 4 |

**9 of 9 pairs won by the new lookup**, and the RESULT COUNTS are the same in
both arms (50-55 and 4) - so it is not winning by returning less, which was the
first thing to rule out.

**Why the two keywords differ, and this is the finding:**

- "yes prime minister" has plenty of hits, so BOTH arms terminate on the
  "enough results" leg (`want` = 30 in the CLI). The new lookup reaches it fast
  because value asks are **interleaved** - the closest responded in-tolerance
  node is asked while FIND_NODEs are still outstanding. The old one had to finish
  its FIND_NODE iteration before the value PHASE started at all.
- "hedda hopper" has 4 hits network-wide, so `want` is never reached and the
  lookup runs to candidate exhaustion or the overall deadline in both arms. The
  only saving left is the round barrier itself - and -38% lands squarely in the
  "quarter to a half" the 8ch batching A/B produced, which is a good consistency
  check on both measurements.

So the honest one-liner is **"1.6x when the lookup must run to exhaustion, 3.2x
when it can stop early"**, not a flat multiplier.

**What this does NOT establish.** This is the DEV BOX, at `per_query` 1400ms,
with no VPN. The device runs 750ms over AirVPN and answered only 67% of requests
against this box's 85% (see the table above). A worse answer rate is exactly the
condition where a round barrier costs most, so the device figure could land
either side of these - **it is not predicted here, it has to be measured.** n=5
and n=4. Bootstrap drifted from 1.4s to ~11s across the runs, so absolute times
are not comparable BETWEEN pairs; the pairing is what controls for it.

Raw logs: `$CLAUDE_JOB_DIR/tmp/ab-ypm.log`, `ab-hh.log`, driver `ab.py`.

### And on the DEVICE - measured 2026-08-08 (row 8co)

The dev-box A/B deliberately predicted nothing about the device. Here is the
device, build `cadace2` (round-based) vs `c656555` (CSearch), both arms
warm-disk / fresh-counters / foreground / HighID to the same eMule Sunrise over
AirVPN:

| | before (rounds) | after (CSearch) |
|---|---|---|
| search submit-to-first-results (n=5) | 6.84 / 6.89 / 6.78 / 6.13 / 6.79, median **6.79s** | 3.32 / 2.68 / 4.48 / 3.35 / 2.70, median **3.32s** |
| | | **-51%** |
| `Longest poll gap` | 1.0s | **1.1s** - no regression, matches 8cm |
| FIND_NODE answered | 71/138 = **51%** | 40/77 = **52%** |
| Kad time-to-first-result | the old panel had no such field | **1939 ms** avg, 5 of 5 lookups |
| Kad lookup completion | avg ROUND 673ms x 50-54 rounds | **1992 ms** avg per value lookup |

**THE ANSWER RATE IS THE CONTROL, and it is why this attribution holds.** 51%
before, 52% after: the swarm behaved identically in both arms, so a halved
search cannot be a lucky hour. That control is doing real work here, because the
device arms were **SEQUENTIAL, not alternating** - you cannot cheaply reinstall
back and forth - so drift is otherwise uncontrolled. Note also how much worse
the device is than the dev box (51% answered against 85%), which is exactly the
condition the round barrier punished hardest.

**-51% IS THE JOINED NUMBER.** The device search runs the server and Kad arms in
one `tokio::join!`, so the server arm sets a floor and this understates the Kad
change. The Kad arm's own figure is the 1939ms TTFR. Do not quote -51% as the
Kad speedup.

Caveats: n=5 per arm, one query, one server, one session.

Consequences that were being read as other problems:

- **The search cap WAS the search cost.** `KAD_SEARCH_WAIT` looked like a safety
  bound and was the actual duration of every search, because the work beneath it
  could not finish inside it. The device-measured 10.3s submit-to-results was
  the Kad arm running until it was cut off, with the server arm having answered
  in under a second and `tokio::join!` waiting for the slower one.
- **Kad maintenance never completed a round.** 9s of work under a 3s deadline
  got through about four of its twelve queries, every 120 seconds, which is a
  large part of why the table grows as slowly as it does. **[8ch cut the 9s to
  3s; 8cn removed rounds entirely. Note the two clocks now COINCIDE:
  `KAD_MAINTENANCE_BUDGET` is 3s and `REFRESH_DEADLINE_QUERIES` x
  `KAD_PER_QUERY` is 4 x 750ms = 3s, so for a refresh that runs its full length
  the outer `timeout` and the lookup's own deadline fire together and
  cancellation is the NORMAL path, not the exceptional one. `SlotGuard` is what
  makes that safe - it is load-bearing here, not a belt-and-braces extra.]**

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

> **[SUPERSEDED IN PART, 2026-08-07 (8ck) and 2026-08-08 (8cn).]** The batch
> demultiplexer was the right answer to "who reads the socket", and it was then
> generalised twice. 8ck moved the demux into ONE owning read loop that runs for
> the node's LIFE (`run_read_loop`), so a datagram is delivered to the pending
> request it answers, answered as an inbound request via `kad_serve`, or dropped
> - which is what let padMule start answering at all. 8cn then took LOOKUPS off
> `request_batch` entirely: they now register slots one at a time through
> `begin_request` and park each reply-or-deadline future in a `JoinSet`.
> `request_batch` survives for BOOTSTRAP and HELLO only, and it is the one path
> still carrying the stale-slot-on-cancel hazard.

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

## padMule ANSWERS NOTHING either - it is a pure client (2026-08-07)

> **[CLOSED the same day - see [[build-progress]] 8ck.]** One task now owns the
> Kad socket and answers PING, HELLO, FIND_NODE and BOOTSTRAP, plus the inbound
> HELLO_RES_ACK that completes the three-way verification handshake. A search and
> a publish still get SILENCE, and that is faithful rather than lazy: eMule stays
> silent too when it holds nothing (`CIndexed::SendValidKeywordResult`,
> Indexed.cpp:696, emits only inside `if (m_mapKeyword.Lookup(...))`), and since
> padMule stores nothing it would otherwise emit a packet no stock client sends
> on nearly every search reaching it - a padMule fingerprint.
> **[SUPERSEDED 2026-08-08. The paragraph below was true when written on
> 2026-08-07 and both of its caveats were closed within a day; annotated in
> place rather than rewritten, per the ledger rule.] The external proof RAN and
> PASSED (row 8cl): a real amuled EVICTED a silent control padMule and KEPT the
> answering one in the same sweep ([[kad-verify-oracle]]). The device pass ran
> too (row 8cm): no regression, `Longest poll gap` 1.1s.**
>
> ~~Offline-verified only: no device pass, and the external proof the spec names
> - does a real amuled KEEP padMule across a ping cycle ([[kad-verify-oracle]]) -
> has NOT been run.~~ So "we answer" is true of the code and NOW proven against
> another implementation. The section below stays as the record of what was
> broken and why it mattered.

Bigger than the publish gap below, and previously unrecorded. The Kad socket is
touched in exactly THREE production places: `request_batch`'s `send_to` and its
single `recv_from`, plus `send_hello_res_ack`. **There is no listener task, no
inbound dispatch, and no request opcode is handled anywhere.**

So the socket is read ONLY while padMule is waiting for a reply to its own
request. The rest of the time nothing reads it and inbound datagrams sit in the
kernel buffer until they are dropped; and even mid-batch, a datagram from a peer
not in the current batch is discarded by the demux.

| | a real eMule node | padMule |
|---|---|---|
| entries indexed FOR others | thousands (7,700+ observed on Anthony's Acer, 2026-08-07) | 0 - nothing is ever stored |
| answers FIND_NODE / HELLO / PING / SEARCH | yes | **never** |
| publishes its own shares | yes | never (below) |

Consequences, in order of how much they cost:

1. **Other clients evict padMule.** eMule's `OnSmallTimer` HELLO-pings the oldest
   contact in each bin and drops what does not answer (RoutingZone.cpp:858-920).
   padMule never answers, so it ages out of every routing table that learns it.
   It cannot be found as a Kad source, and any future buddy/rendezvous scheme
   ([[nat-traversal-design]]) depends on exactly the reachability this removes.
2. **It contributes nothing to a volunteer network** while taking from it. That
   is a POLICY position padMule has never actually chosen - it fell out of never
   building the serve side - and it is worth choosing deliberately before a
   community release ([[security-model]] is about not being harmful; this is
   about not being a freeloader).
3. It cannot be one of the nodes a keyword search converges on, so padMule users
   help each other not at all through Kad.

NOT a defect in padMule's own downloads: a pure client works, because the network
tolerates silent nodes by evicting them. This is about what padMule gives back,
and about being findable.

Building it needs an inbound dispatch loop on the same socket - which the
`request_batch` demux now makes structurally awkward, since one reader owns the
socket for the duration of a batch. The honest shape is a single owning read
loop that routes datagrams either to a waiting request or to a request handler,
which is the SAME restructure the event-driven `CSearch` design needs. **The two
should be designed together, not one after the other.**

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
