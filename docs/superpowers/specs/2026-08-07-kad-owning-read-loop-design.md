# padMule: one owning Kad read loop - routing serve + event-driven lookup

Date: 2026-08-07
Status: DESIGN, not started

Two changes that need the same restructure, so they are specified together and
built in two verifiable steps. Doing them separately would mean doing the
restructure twice - which is the explicit reason this spec exists.

## The problem, measured not assumed

**1. The lookup pays a barrier cost.** Since row 8ch a lookup round sends its
`ALPHA_QUERY` requests together and waits ONE window (`request_batch`). The
window ends when the last member answers, or at the full `KAD_PER_QUERY`
deadline if any member never does. Measured on device (build 19d06d0, over
AirVPN, `per_query` 750ms, six searches) by `stats::kad_report`:

| | dev box (1400ms) | iPad over AirVPN (750ms) |
|---|---|---|
| rounds run | 5-6 per lookup | 29 over 6 lookups |
| rounds with a SILENT peer | 40-50% | **62%** |
| requests answered | 85% | **67%** |
| avg round | 58% of cap | **84% of cap (633 of 750ms)** |
| value windows with a silent peer | 0-75% | **87%**, 93% of cap |

Nearly every round and value window runs to the deadline. The barrier IS the
remaining cost of a search, and the device is worse than the dev box - which is
the condition padMule ships into.

**2. padMule answers nothing.** The Kad socket has three production call sites:
`request_batch`'s `send_to` and its single `recv_from`, plus
`send_hello_res_ack`. No listener, no inbound dispatch, no request opcode
handled anywhere. padMule reads the socket ONLY while awaiting its own reply, so
it never answers a HELLO, PING or FIND_NODE. eMule's `OnSmallTimer`
(`kademlia/routing/RoutingZone.cpp`:858-920, verified 2026-08-07) pings the oldest contact per bin and evicts what stays
silent, so **padMule ages out of every routing table that learns it** - costing
findability as a Kad source now, and breaking any future buddy/rendezvous scheme
([[nat-traversal-design]]), which depends on exactly that reachability.

Both are one root cause: **nothing owns the socket.**

## Decisions taken before this spec

- **Serve scope: ROUTING ANSWERS ONLY.** No index, no storage, no publish.
  Rationale, which is padMule-specific: it is foreground-only, so answering
  routing queries is stateless and a node that vanishes is precisely what the
  network's eviction already handles - a pure win. STORING published data would
  take other clients' keywords and sources and then disappear on a background,
  making padMule a black hole in its keyspace region with no signal to the
  publisher. That is arguably worse for the network than not storing at all.
- **Sequencing: serve loop FIRST (step 1), event-driven lookup SECOND (step 2).**
  Step 1 carries the structural risk and has an unambiguous external success
  test. Step 2 is then a pure policy change on proven plumbing, measured by an
  instrument that already exists.
- **Publishing our own shares (0x43-0x45) is OUT OF SCOPE** here. It is a
  separate feature with its own scheduler and republish clocks; payloads are
  already decoded and banked in [[kad-routing-lifecycle]].

---

# Step 1 - the owning read loop and the routing serve

## Architecture

One task owns the `UdpSocket` for the node's life and runs a single receive loop:

```
recv_from -> deobfuscate (our kad_id + udp_key + sender ip) -> unpack -> (op, payload)
  |
  |-- a pending request is waiting on this address?  -> deliver via its oneshot
  |-- op is a REQUEST opcode?                        -> handle + answer inline
  |-- otherwise                                      -> drop
```

Lookups stop touching the socket. They submit `(target_id, dest, frame, expect,
deadline)` over an mpsc channel and await a oneshot reply.

**`request_batch`'s demux is preserved, not rewritten.** Its exact-address-first
matching with the IP-only fallback, and both of its mutation-checked tests, move
into the reply-routing half of the loop. The reasons behind that matching are
unchanged: `MAX_CONTACTS_PER_IP` permits two contacts on one address, and a
reply may arrive from a different source port than was dialled.

**The routing table becomes `Arc<Mutex<RoutingTable>>`** (a `std` mutex, short
critical sections, NEVER held across an await - the pattern `public_ip` and
`harvested_servers` already use). The handler reads it to answer `FIND_NODE` and
writes it to record requesters; lookups read it to seed and write it on
responses.

**THIS IS THE MAIN CORRECTNESS SURFACE AND WHERE THE TESTS GO.** Chosen over
moving lookups into the actor because it keeps step 1 small; step 2 may drop the
lock if lookups migrate inside.

**Lifecycle:** the task is owned by `KadNode` and dropped with it, so
`pause()` -> `set_kad(None)` still closes the socket and `resume()` rebinds. The
existing `SO_REUSEADDR` on the Kad socket exists for exactly this cycle and is
unchanged.

## What padMule answers

| Inbound | Response | Notes |
|---|---|---|
| `KADEMLIA2_HELLO_REQ` | `HELLO_RES` with misc-option `0x04` | matches eMule `SendMyDetails`; asks for the ACK so the peer verifies us. Adds/refreshes the sender. |
| `KADEMLIA2_HELLO_RES_ACK` | none | marks the sender IP-verified. eMule hard-drops this opcode on an invalid receiver key - match that. |
| `KADEMLIA2_PING` | `KADEMLIA2_PONG` | this is the one that stops the eviction. |
| `KADEMLIA2_REQ` | `KADEMLIA2_RES` with the closest contacts | capped at the REQUESTED count; never the requester itself; verified-only, since `closest_to` already is. |
| `KADEMLIA2_BOOTSTRAP_REQ` | `BOOTSTRAP_RES` | rate-limited harder - see amplification. |
| `KADEMLIA2_SEARCH_KEY_REQ` / `SEARCH_SOURCE_REQ` | **empty `SEARCH_RES`** | DELIBERATE DEVIATION - see below. |
| `KADEMLIA2_PUBLISH_*` | ignored | we store nothing; answering "stored" would be a lie. |
| `FIREWALLED*` / `FINDBUDDY*` / `CALLBACK` | ignored | NAT traversal, its own design. |

Every response builder already exists in `mule-kad::message` (`build_hello_res`,
`build_kad2_res`, `build_bootstrap_res`, `build_search_res`), written for the
codec tests. Step 1 is wiring, not new wire code.

### The empty SEARCH_RES - a deliberate, documented deviation

padMule stores nothing, so it has no results. It answers an EMPTY `SEARCH_RES`
rather than staying silent.

Justification: silence costs the searcher a full per-query timeout, which is
exactly the cost we measured on OURSELVES (62% of rounds, 84% of the cap). An
empty answer is wire-legal, is the same courtesy padMule wants from others, and
is strictly cheaper for the network than being one more silent node.

Decided by Anthony 2026-08-07 with the deviation understood as irrelevant here.
It is recorded as a deviation regardless, with the 0.50a behaviour to be checked
and cited during implementation, following the precedent of the recursive UDP
server crawl (`OP_SERVER_LIST_REQ2`, [[feature-server-hunter]]) - a deviation
neither authority performs, shipped with its reasoning written down.

## Security

- **`FloodTracker` gets its first production call site.** It is exported from
  `mule-kad` and has never been called, because there was no inbound path. One
  tracker PER REQUEST TYPE, keyed by source IP, ignore-then-ban - which is the
  eMule 0.70b behaviour it was built to model.
- Inbound-learned contacts pass the SAME gates as wire-learned ones today:
  `is_acceptable_contact`, the DNS-port-53 legacy guard, the user ipfilter, and
  the anti-sybil per-IP//24 caps. No new insert path may bypass `add_contact`.
- Never answer a request whose source is unroutable or private.
- **AMPLIFICATION, stated rather than assumed:** a `BOOTSTRAP_RES` carrying ~20
  contacts is far larger than the request that triggers it, and UDP source
  addresses are spoofable - so padMule would be deliberately creating a
  reflector. eMule carries the same exposure, but "eMule does it" is not
  sufficient for this class of risk. Bootstrap answers get a tighter per-IP rate
  limit than the other opcodes, and the ratio is recorded in
  [[security-model]].

## Testing

Unit (offline, mock peers on loopback - the established `kad_live` test shape):

1. HELLO both directions: a mock sends `HELLO_REQ`, padMule answers `HELLO_RES`
   with the `0x04` option; the mock sends `HELLO_RES_ACK`; padMule marks it
   verified.
2. `FIND_NODE` answered from a seeded table: capped at the requested count,
   requester excluded, verified-only.
3. **A reply and an inbound request in flight AT THE SAME TIME.** This is the
   regression one shared socket makes possible and the reason the loop exists;
   it must be a test, not an argument.
4. Flood limiter: N requests from one IP get ignored, then banned.
5. An inbound contact that fails the ipfilter/sybil gates never enters the table.

**The external oracle, which is the real success test:** extend
[[kad-verify-oracle]] (the log-patched real amuled) to show a real node KEEPS
padMule in its routing table across a ping cycle. That is a fact about another
implementation's behaviour rather than our code agreeing with itself - the
distinction [[interop-test-fidelity]] exists to enforce.

---

# Step 2 - the event-driven lookup

Only after step 1 is device-verified.

## What changes

eMule's `CSearch` has no phases and no rounds (Search.cpp:278-350). `JumpStart`
walks `m_mapPossible` (sorted by XOR distance) and for the closest contact:
already tried AND responded -> `StorePacket()` (the value request); not tried ->
`SendFindValue()` and break. In `ProcessResponse` (:478-508) any returned
contact closer than its responder that lands in the top-`ALPHA_QUERY`
`m_mapBest` gets `SendFindValue` IMMEDIATELY, inside the response handler.
`JumpStart` is only stall recovery - it returns early if any response arrived in
the last 3 seconds (:281).

padMule adopts that shape:

- Maintain an in-flight set capped at `ALPHA_QUERY`, with a per-request deadline
  instead of a per-round window.
- On each response: record the responder, add its contacts, and immediately
  issue the next request to any closer node in the top-alpha.
- Interleave the value request: the closest already-responded in-tolerance node
  gets its `SEARCH_KEY_REQ` / `SEARCH_SOURCE_REQ` while other `FIND_NODE`s are
  still outstanding. **There is no separate value phase.**
- Terminate on: enough results, candidates exhausted, or the overall deadline.

Expected: cost becomes lookup DEPTH in round trips rather than round count times
a barrier window. On the device numbers above, roughly 2-3x on the Kad arm.

## The instrument must change with it

`stats::kad_report` counts ROUNDS and "rounds with a silent peer". After step 2
neither exists. Leaving it would produce a panel that reads plausibly and means
nothing - the exact failure this project keeps catching.

Replaced by:

- **time to first result** and time to completion, per lookup;
- a per-request RTT histogram, with timeouts as their own bucket;
- in-flight high-water mark;
- requests sent / answered (kept - it is the input to everything else).

The before/after comparison is preserved by taking a final reading with the old
panel immediately before step 2 lands, recorded in [[build-progress]].

---

## Non-goals

- Storing published data, publishing our own shares, notes, buddies, firewall
  checks, NAT traversal.
- Any change to the wire beyond ANSWERING what we already parse. No new opcode
  is invented.
- Changing `KAD_PER_QUERY`, `ALPHA_QUERY` or `K`. If the rewrite works those
  become tunable on evidence; changing them at the same time would confound it.

## Risks

| Risk | Mitigation |
|---|---|
| Rewriting the layer fixed and device-verified today | Two steps, each device-verified; step 1 keeps today's lookup semantics unchanged |
| The routing-table lock is the new shared-state surface | `std` mutex, never across an await; concurrency test (4) above targets it |
| Answering makes padMule a reflector | Per-IP per-type flood limits; tighter cap on bootstrap; recorded in the security model |
| Step 2 invalidates the instrument that justified it | Panel reshaped in the same change; final old-panel reading captured first |
| A search regression is confounded by the serve loop | Exactly why serve is step 1 and lookup is step 2 |

## Verification

- Gate per step: `cargo test --workspace`, clippy `-D warnings`, fmt, ASCII.
- Step 1 on device: padMule stays in a real amuled's routing table across a ping
  cycle (the oracle); no regression in search timings or the Kad panel.
- Step 2 on device: search submit-to-results against the step-1 baseline, and
  the new panel's time-to-first-result.
- Both: `Longest poll gap` stays ~1s, confirming nothing re-enters the engine
  lock path.
