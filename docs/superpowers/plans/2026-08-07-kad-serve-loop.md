# Kad Owning Read Loop, Step 1: Routing-Only Serve - Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make padMule answer inbound Kad routing requests, so it stops ageing out of other clients' routing tables, by giving one task ownership of the Kad UDP socket.

**Architecture:** One task owns the `UdpSocket` and runs a single `recv_from` loop for the node's life. Each datagram either satisfies a pending outbound request (the existing `request_batch` demux, moved) or is an inbound request answered by a pure handler. The routing table moves behind `Arc<Mutex<RoutingTable>>` so both sides can reach it.

**Tech Stack:** Rust, tokio (`UdpSocket`, `mpsc`, `oneshot`), existing `mule-kad` codecs.

**Scope:** Step 1 of `docs/superpowers/specs/2026-08-07-kad-owning-read-loop-design.md`. **Step 2 (the event-driven lookup) gets its own plan after Step 1 is device-verified** - that sequencing is the whole point of the spec, and this plan ships working software on its own.

---

## File Structure

| File | Responsibility |
|---|---|
| `crates/mule-kad/src/message.rs` (modify) | Add `build_pong` and `build_ping`. Wire codecs only. (`parse_search_key_req` / `parse_search_source_req` were dropped by AMENDMENT 1 - we never parse a search request now.) |
| `crates/mule-engine/src/kad_serve.rs` (create) | PURE inbound-request handling: given an opcode, payload and a view of our table, return the answer. No sockets, no locks, no I/O - so every rule is unit-testable. |
| `crates/mule-engine/src/kad_live.rs` (modify) | Owns the socket task, routes replies to waiters, calls `kad_serve` for requests, holds the table behind a mutex. |
| `crates/mule-engine/src/lib.rs` (modify) | Declare `mod kad_serve;`. |

`kad_serve.rs` is deliberately separate and pure: the answering RULES (who gets a reply, what it contains, when the ACK bit is set) are the part worth testing exhaustively, and they must not need a socket to test.

---

## AMENDMENTS (2026-08-07, from the pre-execution review of this plan)

Three findings from checking this plan's code against the real APIs and the spec.
Each is folded into the task it affects; recorded here so the change is visible
rather than silently absorbed.

**AMENDMENT 1 - SEARCH_KEY_REQ / SEARCH_SOURCE_REQ: STAY SILENT, do not answer
empty.** The spec deferred "the 0.50a behaviour to be checked during
implementation"; the check was run and it REVERSES the deviation. eMule's
`CIndexed::SendValidKeywordResult` (`Indexed.cpp:696`) sends a packet only inside
`if (m_mapKeyword.Lookup(...))` - no entry, no packet, and there is no
empty-`SEARCH_RES` path in stock eMule anywhere. Since padMule stores nothing it
would answer empty to nearly every search reaching it, and no stock client emits
that packet, so each one is a padMule fingerprint. Anthony decided on that
evidence: match eMule. **Effect:** Task 1 loses `parse_search_key_req` and
`parse_search_source_req` (only `build_pong` and `build_ping` are new); Task 5
loses its two empty-answer tests and gains silence tests; padMule never parses an
attacker-supplied search payload or expression tree at all.

**AMENDMENT 2 - do NOT start the read loop in `bind_with_identity`.** Task 7 Step
4 said to. But `start_kad` configures the node AFTER binding it, in this order:
`bind_with_identity` -> `set_advertised_udp_port` -> `set_ip_filter` ->
`set_public_ip` -> `seed_routing` -> `bootstrap_any`. A loop spawned at bind
captures `ip_filter: None` and `advertised_udp_port: None`, which would mean (a)
inbound-learned contacts BYPASS the user's IP blocklist - silently regressing the
"ipfilter Kad UDP coverage" row in [[security-model]] from OPERATIONAL - and (b)
our HELLO_RES and BOOTSTRAP_RES would advertise the BOUND port rather than the
ADVERTISED one, so behind a VPN remote-to-local forward we would answer peers
with a port nobody forwards. That is worse than not answering: we would be in
their table at a dead address. This is the "moved the check == removed the check"
class ([[decisions-and-lessons]] 2026-07-18). **Effect:** the loop reads its
configuration through SHARED handles rather than captured copies -
`ip_filter: Arc<std::sync::Mutex<Option<Arc<IpFilter>>>>` and
`advertised_udp_port: Arc<AtomicU32>` (0 = "advertise what we bound"), both
written by the existing setters and read by the loop each time it answers. The
routing table is already becoming an `Arc<Mutex<..>>` in Task 6, so this is the
same move applied to the other two. Spawn point stays in `bind_with_identity`;
what changes is that nothing is captured by value.

**AMENDMENT 3 - handle inbound `KADEMLIA2_HELLO_RES_ACK` (new Task 7b).** The
spec's table requires it ("marks the sender IP-verified; eMule hard-drops this
opcode on an invalid receiver key - match that") and NO task implemented it.
`parse_hello_res_ack` already exists and is unused on the receive side. This is
not optional polish: Task 3 makes padMule SET the `0x04` bit that ASKS peers for
an ACK, so without this we would ask for something we then ignore - the Wave-4d
"advertise no capability you do not honour" lesson in a new place. Worse, since
`closest_to` is verified-only (row 8ao), a peer that proves its IP to us and is
never recorded as verified can never appear in any answer we give, so the whole
handshake would be thrown away.

---

### Task 1: Wire codecs the serve path needs

Three codecs are missing. `parse_kad2_req`, `parse_hello`, `parse_hello_res_ack`, `build_hello_res`, `build_kad2_res`, `build_bootstrap_res` and `build_search_res` all already exist and are NOT to be rewritten.

**Files:**
- Modify: `crates/mule-kad/src/message.rs`
- Test: `crates/mule-kad/src/message.rs` (its `#[cfg(test)] mod tests`)

- [ ] **Step 1: Write the failing tests**

Add inside `mod tests`:

```rust
#[test]
fn pong_carries_the_requesters_udp_port() {
    // eMule Process_KADEMLIA2_PING (KademliaUDPListener.cpp:1970-1977) writes
    // ONE u16 - the port it received the ping from - because a PONG's only
    // current use is telling the peer its own external port. An empty PONG
    // would parse as malformed at the far end.
    let (op, payload) = build_pong(4672);
    assert_eq!(op, OP_PONG);
    assert_eq!(payload, vec![0x40, 0x12]);
}

#[test]
fn search_key_req_target_round_trips() {
    let t = kad_keyword_target("minister");
    let (_, plain) = build_search_key_req(&t, 0);
    assert_eq!(parse_search_key_req(&plain).unwrap(), t);
    // The restrictive form carries an expression after the flags; the target
    // must still be readable, because that is all the serve path needs.
    let (_, rich) =
        build_search_key_req_restrictive(&t, 0, &["prime".to_string(), "minister".to_string()]);
    assert_eq!(parse_search_key_req(&rich).unwrap(), t);
    // Too short to hold a target + flags.
    assert!(parse_search_key_req(&plain[..17]).is_err());
}

#[test]
fn search_source_req_target_round_trips() {
    let t = Kad128::from_hash(&[0x77; 16]);
    let (_, p) = build_search_source_req(&t, 0, 9_728_000);
    assert_eq!(parse_search_source_req(&p).unwrap(), t);
    assert!(parse_search_source_req(&p[..17]).is_err());
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `source "$HOME/.cargo/env" && cargo test -p mule-kad pong_carries search_key_req_target search_source_req_target`
Expected: FAIL - `cannot find function build_pong` / `parse_search_key_req` / `parse_search_source_req`.

- [ ] **Step 3: Write the implementation**

Add to `crates/mule-kad/src/message.rs`, next to the other builders:

```rust
/// A KADEMLIA2_PONG, carrying the UDP port we received the ping FROM.
///
/// Not empty, and the payload is not ours: eMule's own comment is that a ping
/// "is however only used to determine ones external port"
/// (`Process_KADEMLIA2_PING`, KademliaUDPListener.cpp:1970-1977), so the port
/// echoed here is how the pinging peer learns its own external port.
pub fn build_pong(requester_udp_port: u16) -> (u8, Vec<u8>) {
    let mut w = Writer::new();
    w.write_u16(requester_udp_port);
    (OP_PONG, w.into_inner())
}

/// The keyword target out of a KADEMLIA2_SEARCH_KEY_REQ.
///
/// Only the target is read. The trailing flags word and any search-expression
/// tree are IGNORED on purpose: padMule stores nothing, so it has no results to
/// filter, and parsing an attacker-supplied expression tree would be work done
/// on behalf of a stranger for no benefit.
pub fn parse_search_key_req(payload: &[u8]) -> Result<Kad128, IoError> {
    let mut r = Reader::new(payload);
    let target = Kad128::from_wire(&r.read_array16()?);
    r.read_u16()?; // flags (+ restrictive bit) - deliberately unused
    Ok(target)
}

/// The file target out of a KADEMLIA2_SEARCH_SOURCE_REQ. As above, only the
/// target is read; the start position and file size are not needed to answer
/// with no results.
pub fn parse_search_source_req(payload: &[u8]) -> Result<Kad128, IoError> {
    let mut r = Reader::new(payload);
    let target = Kad128::from_wire(&r.read_array16()?);
    r.read_u16()?; // start position
    Ok(target)
}
```

If `Reader` has no `read_array16`, use the same accessor the neighbouring
`parse_kad2_req` uses to read a 16-byte wire id, and match its style exactly.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `source "$HOME/.cargo/env" && cargo test -p mule-kad pong_carries search_key_req_target search_source_req_target`
Expected: PASS, 3 tests.

- [ ] **Step 5: Export the new symbols**

In `crates/mule-kad/src/lib.rs`, add `build_pong`, `parse_search_key_req` and `parse_search_source_req` to the existing `pub use message::{...}` list, keeping it alphabetical if it already is.

- [ ] **Step 6: Gate and commit**

```bash
source "$HOME/.cargo/env"
cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --all -- --check
git add crates/mule-kad/src/message.rs crates/mule-kad/src/lib.rs
git commit -m "feat(kad): the three codecs the serve path needs

build_pong carries the REQUESTER's udp port, not an empty payload - eMule's
Process_KADEMLIA2_PING says a ping's only current use is telling the peer its
external port, so an empty PONG would be malformed at the far end.

parse_search_key_req / parse_search_source_req read ONLY the target. The flags,
expression tree, start position and file size are deliberately ignored: padMule
stores nothing, so it has no results to filter, and parsing an attacker-supplied
expression tree would be work done for a stranger with no benefit."
```

---

### Task 2: The pure serve handler - PING first

Smallest end-to-end slice: one opcode, so the module's shape is settled before the rules pile up.

**Files:**
- Create: `crates/mule-engine/src/kad_serve.rs`
- Modify: `crates/mule-engine/src/lib.rs`
- Test: `crates/mule-engine/src/kad_serve.rs` (its own `#[cfg(test)] mod tests`)

- [ ] **Step 1: Write the failing test**

Create `crates/mule-engine/src/kad_serve.rs` with ONLY this test module plus the imports it needs:

```rust
//! Answering inbound Kad requests - the RULES, with no I/O.
//!
//! padMule answers ROUTING queries only: HELLO, PING, FIND_NODE and BOOTSTRAP,
//! plus the v8 verification ACK. It stores nothing, publishes nothing, and says
//! so honestly rather than staying silent (see `answer_request`).
//!
//! Pure on purpose. The socket loop lives in `kad_live`; everything decided
//! here - who gets a reply, what it contains, when the ACK bit is set - is a
//! rule that must be testable without a socket, because those are the rules a
//! remote peer's behaviour depends on.

use mule_kad::{
    build_bootstrap_res, build_hello_res, build_kad2_res, build_pong, build_search_res,
    parse_hello, parse_kad2_req, parse_search_key_req, parse_search_source_req, WireContact,
    OP_BOOTSTRAP_REQ, OP_HELLO_REQ, OP_KAD2_REQ, OP_PING, OP_SEARCH_KEY_REQ, OP_SEARCH_SOURCE_REQ,
};
use mule_proto::Kad128;

#[cfg(test)]
mod tests {
    use super::*;

    fn me() -> ServeIdentity {
        ServeIdentity {
            kad_id: Kad128::from_hash(&[0x01; 16]),
            tcp_port: 4662,
            advertised_udp_port: 4672,
        }
    }

    /// A PING must be answered with the REQUESTER's port, which is how the peer
    /// learns its own external port - and answering at all is what stops eMule
    /// evicting us on its OnSmallTimer sweep.
    #[test]
    fn a_ping_is_answered_with_the_requesters_port() {
        let a = answer_request(OP_PING, &[], 5000, &me(), |_, _| Vec::new())
            .expect("a ping must be answered");
        assert_eq!(a.opcode, mule_kad::OP_PONG);
        assert_eq!(a.payload, vec![0x88, 0x13]); // 5000 LE
    }

    /// An opcode we do not serve produces NO answer - and must not panic. This
    /// is most of the protocol (publish, notes, buddies, firewall checks).
    #[test]
    fn an_unserved_opcode_is_silently_ignored() {
        assert!(answer_request(0x43, &[], 5000, &me(), |_, _| Vec::new()).is_none());
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `source "$HOME/.cargo/env" && cargo test -p mule-engine kad_serve`
Expected: FAIL to compile - `cannot find type ServeIdentity` / `function answer_request`.

- [ ] **Step 3: Write the minimal implementation**

Insert above the test module in `crates/mule-engine/src/kad_serve.rs`:

```rust
/// What we tell a peer about ourselves when answering.
pub struct ServeIdentity {
    pub kad_id: Kad128,
    pub tcp_port: u16,
    /// The port peers should dial - the ADVERTISED one, which differs from the
    /// bound port behind a VPN remote-to-local forward.
    pub advertised_udp_port: u16,
}

/// One outbound answer.
pub struct ServeAnswer {
    pub opcode: u8,
    pub payload: Vec<u8>,
    /// True when the peer must be asked for a verification ACK. Set only where
    /// eMule sets it - see the HELLO arm.
    pub request_ack: bool,
}

impl ServeAnswer {
    fn plain(op: u8, payload: Vec<u8>) -> Option<Self> {
        Some(ServeAnswer {
            opcode: op,
            payload,
            request_ack: false,
        })
    }
}

/// Decide the answer to one inbound request, or `None` to stay silent.
///
/// `closest` yields our routing table's closest VERIFIED contacts to a target,
/// passed as a closure so this stays free of the table's lock.
pub fn answer_request(
    op: u8,
    payload: &[u8],
    from_udp_port: u16,
    me: &ServeIdentity,
    closest: impl FnOnce(&Kad128, usize) -> Vec<WireContact>,
) -> Option<ServeAnswer> {
    let _ = (payload, me, closest);
    match op {
        OP_PING => {
            let (o, p) = build_pong(from_udp_port);
            ServeAnswer::plain(o, p)
        }
        _ => None,
    }
}
```

Add `mod kad_serve;` to `crates/mule-engine/src/lib.rs` beside the other module
declarations, matching their visibility style (`pub mod` if `stats` is `pub mod`).

- [ ] **Step 4: Run the tests to verify they pass**

Run: `source "$HOME/.cargo/env" && cargo test -p mule-engine kad_serve`
Expected: PASS, 2 tests.

- [ ] **Step 5: Commit**

```bash
source "$HOME/.cargo/env"
cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --all -- --check
git add crates/mule-engine/src/kad_serve.rs crates/mule-engine/src/lib.rs
git commit -m "feat(kad): a pure inbound-request handler, starting with PING

The answering RULES live apart from the socket on purpose: who gets a reply,
what it contains and when the ACK bit is set are what a remote peer's behaviour
depends on, so they must be testable without a socket."
```

---

### Task 3: HELLO_REQ, with the CONDITIONAL ack bit

**Files:**
- Modify: `crates/mule-engine/src/kad_serve.rs`

- [ ] **Step 1: Write the failing tests**

Add to `mod tests`:

```rust
/// eMule asks for a verification ACK only when it has NOT already proved the
/// sender's IP: `bAddedOrUpdated && !bValidReceiverKey`
/// (KademliaUDPListener.cpp:601). Asking a peer that already verified us is
/// pointless traffic, and the first draft of the spec said "always".
#[test]
fn the_ack_is_requested_only_when_the_senders_ip_is_not_yet_proven() {
    let peer = Kad128::from_hash(&[0x55; 16]);
    let (_, hello) = mule_kad::build_hello_req(&peer, 4662, Some(4672), None);

    let unproven = answer_hello(&hello, 5000, &me(), /*valid_receiver_key=*/ false).unwrap();
    assert!(unproven.request_ack, "an unverified sender must be asked");

    let proven = answer_hello(&hello, 5000, &me(), /*valid_receiver_key=*/ true).unwrap();
    assert!(!proven.request_ack, "a sender that already proved its IP must not be");
}

/// The response must be a HELLO_RES carrying OUR details, and the udp port in
/// it must be the ADVERTISED one - behind a VPN forward the bound port is not
/// the port peers can reach.
#[test]
fn the_hello_response_advertises_our_reachable_port() {
    let peer = Kad128::from_hash(&[0x55; 16]);
    let (_, hello) = mule_kad::build_hello_req(&peer, 4662, Some(4672), None);
    let a = answer_hello(&hello, 5000, &me(), false).unwrap();
    assert_eq!(a.opcode, mule_kad::OP_HELLO_RES);
    let parsed = parse_hello(&a.payload).unwrap();
    assert_eq!(parsed.id, me().kad_id);
    assert_eq!(parsed.source_udp_port, Some(4672));
}

/// A malformed HELLO is dropped, not answered.
#[test]
fn a_malformed_hello_is_not_answered() {
    assert!(answer_hello(&[0u8; 4], 5000, &me(), false).is_none());
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `source "$HOME/.cargo/env" && cargo test -p mule-engine kad_serve`
Expected: FAIL - `cannot find function answer_hello`.

- [ ] **Step 3: Implement**

Add to `kad_serve.rs`:

```rust
/// The misc-options bit that asks the peer for a HELLO_RES_ACK (eMule
/// `SendMyDetails`, KademliaUDPListener.cpp:106-140).
const MISC_REQUEST_ACK: u8 = 0x04;

/// Answer a KADEMLIA2_HELLO_REQ. `valid_receiver_key` is eMule's
/// `bValidReceiverKey` - whether the request echoed back the verify key we
/// issue for this address, which PROVES the sender receives at that IP.
pub fn answer_hello(
    payload: &[u8],
    from_udp_port: u16,
    me: &ServeIdentity,
    valid_receiver_key: bool,
) -> Option<ServeAnswer> {
    let _ = (parse_hello(payload).ok()?, from_udp_port);
    // Ask for the ACK only when the sender's IP is NOT already proven. eMule:
    // `bAddedOrUpdated && !bValidReceiverKey`.
    let request_ack = !valid_receiver_key;
    let (o, p) = build_hello_res(
        &me.kad_id,
        me.tcp_port,
        Some(me.advertised_udp_port),
        request_ack.then_some(MISC_REQUEST_ACK),
    );
    Some(ServeAnswer {
        opcode: o,
        payload: p,
        request_ack,
    })
}
```

Then route it from `answer_request` by replacing the `_ => None` arm's
neighbours - the match becomes:

```rust
    match op {
        OP_PING => {
            let (o, p) = build_pong(from_udp_port);
            ServeAnswer::plain(o, p)
        }
        OP_HELLO_REQ => answer_hello(payload, from_udp_port, me, false),
        _ => None,
    }
```

(The `false` is a placeholder ONLY until Task 8 threads the real receiver-key
verdict through; Task 8's test is what proves it stops being a placeholder.)

- [ ] **Step 4: Run to verify they pass**

Run: `source "$HOME/.cargo/env" && cargo test -p mule-engine kad_serve`
Expected: PASS, 5 tests.

- [ ] **Step 5: Commit**

```bash
source "$HOME/.cargo/env"
cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --all -- --check
git add crates/mule-engine/src/kad_serve.rs
git commit -m "feat(kad): answer HELLO_REQ, with the ACK bit set CONDITIONALLY

eMule sets bRequestAckPackage as (bAddedOrUpdated && !bValidReceiverKey) - only
when the sender's IP is not already proven. The design spec said 'always', which
would beg an ACK from peers that had already verified us; corrected by reading
SendMyDetails rather than trusting the summary."
```

---

### Task 4: KADEMLIA2_REQ - the FIND_NODE answer

**Files:**
- Modify: `crates/mule-engine/src/kad_serve.rs`

- [ ] **Step 1: Write the failing tests**

```rust
fn contact(seed: u8, ip: u32) -> WireContact {
    WireContact {
        id: Kad128::from_hash(&[seed; 16]),
        ip,
        udp_port: 4672,
        tcp_port: 4662,
        version: 8,
    }
}

/// A FIND_NODE is answered from our table, capped at what the requester asked
/// for - eMule rejects an over-long answer (Search.cpp:377), so sending one
/// would get us ignored by the very node we are trying to stay known to.
#[test]
fn find_node_is_answered_and_capped_at_the_requested_count() {
    let target = Kad128::from_hash(&[0x33; 16]);
    let receiver = me().kad_id;
    let (_, req) = mule_kad::build_kad2_req(mule_kad::KAD_FIND_NODE, &target, &receiver);
    let pool: Vec<WireContact> = (1..=20).map(|i| contact(i, 0x0A00_0000 + i as u32)).collect();

    let a = answer_request(OP_KAD2_REQ, &req, 5000, &me(), |t, want| {
        assert_eq!(*t, target, "the table must be asked for the REQUESTED target");
        pool.iter().take(want).cloned().collect()
    })
    .expect("a find_node must be answered");

    assert_eq!(a.opcode, mule_kad::OP_KAD2_RES);
    let res = mule_kad::parse_kad2_res(&a.payload).unwrap();
    assert_eq!(res.target, target);
    assert!(
        res.contacts.len() <= KAD_FIND_NODE_ANSWER_CAP,
        "answered {} contacts, over the cap", res.contacts.len()
    );
}

/// A request addressed to a DIFFERENT node's id is not ours to answer. The
/// receiver field exists precisely so a contact can tell it reached the right
/// node (eMule calls it a safety net when sending).
#[test]
fn a_request_addressed_to_another_node_is_ignored() {
    let target = Kad128::from_hash(&[0x33; 16]);
    let someone_else = Kad128::from_hash(&[0xEE; 16]);
    let (_, req) = mule_kad::build_kad2_req(mule_kad::KAD_FIND_NODE, &target, &someone_else);
    assert!(answer_request(OP_KAD2_REQ, &req, 5000, &me(), |_, _| vec![contact(1, 1)]).is_none());
}

/// A malformed request is dropped rather than answered.
#[test]
fn a_malformed_find_node_is_not_answered() {
    assert!(answer_request(OP_KAD2_REQ, &[0u8; 5], 5000, &me(), |_, _| Vec::new()).is_none());
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `source "$HOME/.cargo/env" && cargo test -p mule-engine kad_serve`
Expected: FAIL - `cannot find value KAD_FIND_NODE_ANSWER_CAP`, and the FIND_NODE arm is missing.

- [ ] **Step 3: Implement**

```rust
/// The most contacts we put in a KADEMLIA2_RES.
///
/// eMule requests 11 (KAD_FIND_NODE) and REJECTS an answer longer than what it
/// asked for (Search.cpp:377), so an over-long answer is not generosity - it
/// gets the whole response discarded by the node we want to stay known to.
pub const KAD_FIND_NODE_ANSWER_CAP: usize = 11;
```

and the match arm:

```rust
        OP_KAD2_REQ => {
            let req = parse_kad2_req(payload).ok()?;
            // The receiver field is the sender's check that it reached the node
            // it meant to. If it names someone else, this is not ours.
            if req.receiver != me.kad_id {
                return None;
            }
            let contacts = closest(&req.target, KAD_FIND_NODE_ANSWER_CAP);
            let (o, p) = build_kad2_res(&req.target, &contacts);
            ServeAnswer::plain(o, p)
        }
```

- [ ] **Step 4: Run to verify they pass**

Run: `source "$HOME/.cargo/env" && cargo test -p mule-engine kad_serve`
Expected: PASS, 8 tests.

- [ ] **Step 5: Commit**

```bash
source "$HOME/.cargo/env"
cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --all -- --check
git add crates/mule-engine/src/kad_serve.rs
git commit -m "feat(kad): answer FIND_NODE from our table, capped and addressed

Capped at 11 because eMule REJECTS an answer longer than it requested
(Search.cpp:377) - an over-long response is not generosity, it gets the whole
answer discarded by the node we are trying to stay known to. A request whose
receiver field names another node is ignored: that field is the sender's check
that it reached the node it meant to."
```

---

### Task 5: BOOTSTRAP_REQ and the honest empty SEARCH_RES

**Files:**
- Modify: `crates/mule-engine/src/kad_serve.rs`

- [ ] **Step 1: Write the failing tests**

```rust
/// A bootstrap answer carries our details plus contacts - it is how a cold node
/// enters the network.
#[test]
fn bootstrap_is_answered_with_our_details_and_contacts() {
    let pool: Vec<WireContact> = (1..=30).map(|i| contact(i, 0x0A00_0000 + i as u32)).collect();
    let a = answer_request(OP_BOOTSTRAP_REQ, &[], 5000, &me(), |_, want| {
        pool.iter().take(want).cloned().collect()
    })
    .expect("bootstrap must be answered");
    assert_eq!(a.opcode, mule_kad::OP_BOOTSTRAP_RES);
    let res = mule_kad::parse_bootstrap_res(&a.payload).unwrap();
    assert_eq!(res.id, me().kad_id);
    assert_eq!(res.tcp_port, 4662);
    assert!(
        res.contacts.len() <= KAD_BOOTSTRAP_ANSWER_CAP,
        "a bootstrap answer is the biggest thing we emit for the smallest request \
         - it is an amplification vector and must stay capped"
    );
}

/// padMule stores nothing, so it answers an EMPTY result rather than staying
/// silent. Silence costs the searcher a full per-query timeout, which is exactly
/// the cost measured on padMule itself (62% of its own lookup rounds were held
/// open by a peer that never answered).
#[test]
fn a_keyword_search_gets_an_honest_empty_answer() {
    let t = mule_kad::kad_keyword_target("minister");
    let (_, req) = mule_kad::build_search_key_req(&t, 0);
    let a = answer_request(OP_SEARCH_KEY_REQ, &req, 5000, &me(), |_, _| Vec::new())
        .expect("an empty answer is still an answer");
    assert_eq!(a.opcode, mule_kad::OP_SEARCH_RES);
    let res = mule_kad::parse_search_res(&a.payload).unwrap();
    assert_eq!(res.target, t, "the answer must name the target asked about");
    assert_eq!(res.responder, me().kad_id);
    assert!(res.results.is_empty());
}

#[test]
fn a_source_search_gets_an_honest_empty_answer() {
    let t = Kad128::from_hash(&[0x77; 16]);
    let (_, req) = mule_kad::build_search_source_req(&t, 0, 9_728_000);
    let a = answer_request(OP_SEARCH_SOURCE_REQ, &req, 5000, &me(), |_, _| Vec::new()).unwrap();
    let res = mule_kad::parse_search_res(&a.payload).unwrap();
    assert_eq!(res.target, t);
    assert!(res.results.is_empty());
}

/// We store nothing, so claiming a publish was stored would be a lie.
#[test]
fn a_publish_is_ignored_rather_than_falsely_acknowledged() {
    for op in [0x43u8, 0x44, 0x45] {
        assert!(answer_request(op, &[0u8; 40], 5000, &me(), |_, _| Vec::new()).is_none());
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `source "$HOME/.cargo/env" && cargo test -p mule-engine kad_serve`
Expected: FAIL - `KAD_BOOTSTRAP_ANSWER_CAP` undefined and the arms are missing.

- [ ] **Step 3: Implement**

```rust
/// Contacts in a BOOTSTRAP_RES.
///
/// AMPLIFICATION, deliberately capped: this is the largest response padMule
/// emits for the smallest request (a bodiless BOOTSTRAP_REQ), and UDP source
/// addresses are spoofable - so answering makes padMule a reflector. eMule
/// carries the same exposure, which is not a sufficient reason to match it
/// exactly. 20 contacts is ~500 bytes against a ~30-byte request; Task 8's
/// tighter per-IP limit on this opcode is the other half of the mitigation.
pub const KAD_BOOTSTRAP_ANSWER_CAP: usize = 20;
```

and the arms:

```rust
        OP_BOOTSTRAP_REQ => {
            let contacts = closest(&me.kad_id, KAD_BOOTSTRAP_ANSWER_CAP);
            let (o, p) = build_bootstrap_res(
                &me.kad_id,
                me.tcp_port,
                mule_kad::KADEMLIA_VERSION,
                &contacts,
            );
            ServeAnswer::plain(o, p)
        }
        OP_SEARCH_KEY_REQ | OP_SEARCH_SOURCE_REQ => {
            // We store nothing, so we have nothing to return - and we say so
            // rather than staying silent. A DELIBERATE DEVIATION, justified by
            // what silence costs the other side: a full per-query timeout, the
            // exact cost measured on padMule itself.
            let target = if op == OP_SEARCH_KEY_REQ {
                parse_search_key_req(payload).ok()?
            } else {
                parse_search_source_req(payload).ok()?
            };
            let (o, p) = build_search_res(&me.kad_id, &target, &[]);
            ServeAnswer::plain(o, p)
        }
```

If `mule_kad::KADEMLIA_VERSION` is not exported, use the same constant
`build_hello_req` writes as its version byte, and export it alongside.

- [ ] **Step 4: Run to verify they pass**

Run: `source "$HOME/.cargo/env" && cargo test -p mule-engine kad_serve`
Expected: PASS, 12 tests.

- [ ] **Step 5: Commit**

```bash
source "$HOME/.cargo/env"
cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --all -- --check
git add crates/mule-engine/src/kad_serve.rs
git commit -m "feat(kad): bootstrap answers, and an honest empty SEARCH_RES

padMule stores nothing, so a search gets an EMPTY result rather than silence - a
deliberate deviation, justified by what silence costs the far end: a full
per-query timeout, which is precisely the cost measured on padMule itself (62%
of its own rounds held open by a peer that never answered). A publish is ignored
instead, because acknowledging a store we did not do would be a lie.

The bootstrap answer is capped at 20 contacts and labelled for what it is: the
largest response we emit for the smallest request, on a protocol with spoofable
source addresses. eMule has the same exposure; that is not a reason to match it
without a limit."
```

---

### Task 6: The routing table moves behind a mutex

The handler needs the table, and so do lookups. This is the change the spec
names as the main correctness surface.

**Files:**
- Modify: `crates/mule-engine/src/kad_live.rs`

- [ ] **Step 1: Write the failing test**

Add to `kad_live.rs`'s `mod tests`:

```rust
/// The table is reachable from two places once the socket loop exists - the
/// request handler reads it, lookups write it - so it lives behind a lock. This
/// pins that the lock is never held across an await: a closure that takes it,
/// clones what it needs and drops the guard is the only allowed shape.
#[tokio::test]
async fn the_routing_table_is_shared_and_readable_while_a_lookup_holds_the_node() {
    let node = KadNode::bind_with_identity(
        "127.0.0.1:0".parse().unwrap(),
        4662,
        Kad128::from_words([2, 2, 2, 2]),
        0x4321,
    )
    .await
    .unwrap();
    node.with_routing(|t| t.add(Kad128::from_hash(&[9; 16]), 0x0A00_0001, 4672, 4662, 8, true));
    assert_eq!(node.contacts_known(), 1);
    let closest = node.closest_wire_contacts(&Kad128::from_hash(&[9; 16]), 5);
    assert_eq!(closest.len(), 1);
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `source "$HOME/.cargo/env" && cargo test -p mule-engine the_routing_table_is_shared`
Expected: FAIL - `no method named with_routing` / `closest_wire_contacts`.

- [ ] **Step 3: Implement**

In `kad_live.rs`, change the field and add the two accessors:

```rust
    routing: std::sync::Arc<std::sync::Mutex<RoutingTable>>,
```

```rust
    /// Run `f` against the routing table.
    ///
    /// A `std` mutex held for the length of one table operation and NEVER
    /// across an await - the same discipline `Engine::public_ip` and
    /// `harvested_servers` already follow. The table is now reached from two
    /// directions (the inbound handler reads it, lookups write it), which is
    /// why it needs a lock at all.
    pub(crate) fn with_routing<R>(&self, f: impl FnOnce(&mut RoutingTable) -> R) -> R {
        let mut g = self.routing.lock().expect("routing table lock poisoned");
        f(&mut g)
    }

    /// The closest VERIFIED contacts to `target`, as wire contacts. Clones out
    /// of the lock so callers never hold it while doing I/O.
    pub(crate) fn closest_wire_contacts(&self, target: &Kad128, want: usize) -> Vec<WireContact> {
        self.with_routing(|t| {
            t.closest_to(target, want)
                .into_iter()
                .map(|c| WireContact {
                    id: c.id,
                    ip: c.ip,
                    udp_port: c.udp_port,
                    tcp_port: c.tcp_port,
                    version: c.version,
                })
                .collect()
        })
    }
```

Then update every existing `self.routing.` use in the file to go through
`with_routing`. There are uses in `add_contact`, `note_responder`,
`seed_routing`, `contacts_known`, `routing()`, `find_node_batch` (the
`is_acceptable_answer` filter) and the three lookup seeders. `routing()`
returns `&RoutingTable` today and cannot with a lock - replace its callers with
`with_routing` or `closest_wire_contacts`, and delete it if it ends up unused.

- [ ] **Step 4: Run the whole engine suite**

Run: `source "$HOME/.cargo/env" && cargo test -p mule-engine`
Expected: PASS. Any failure here is a real find - the lookup tests exercise the
same table the handler will.

- [ ] **Step 5: Commit**

```bash
source "$HOME/.cargo/env"
cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --all -- --check
git add crates/mule-engine/src/kad_live.rs
git commit -m "refactor(kad): the routing table moves behind a lock

It is about to be reached from two directions - the inbound request handler
reads it, lookups write it. A std mutex held for one table operation and never
across an await, matching the discipline public_ip and harvested_servers already
follow. closest_wire_contacts clones out of the lock so no caller can hold it
while doing I/O."
```

---

### Task 7: The owning read loop

**Files:**
- Modify: `crates/mule-engine/src/kad_live.rs`

- [ ] **Step 1: Write the failing test - the one the whole design is for**

```rust
/// THE REGRESSION ONE SHARED SOCKET MAKES POSSIBLE: an inbound request arriving
/// while an outbound request is waiting for its reply. Before the owning loop,
/// the only reader was the reply collector and it DISCARDED anything it was not
/// waiting for - so a peer's PING was dropped on the floor, and worse, a reply
/// could be consumed by the wrong waiter. Both must work at once.
#[tokio::test]
async fn an_inbound_request_is_answered_while_a_reply_is_outstanding() {
    let node = KadNode::bind_with_identity(
        "127.0.0.1:0".parse().unwrap(),
        4662,
        Kad128::from_words([5, 5, 5, 5]),
        0x1234,
    )
    .await
    .unwrap();
    let ours = node.local_addr();

    // A peer that PINGS us while our own request to it is in flight.
    let peer_id = Kad128::from_hash(&[0x66; 16]);
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer_addr = peer.local_addr().unwrap();

    let mock = tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        // 1. our BOOTSTRAP_REQ arrives
        let (n, from) = peer.recv_from(&mut buf).await.unwrap();
        let dec = kad_deobfuscate(&buf[..n], &peer_id, 0, ip_u32(&from)).unwrap();
        // 2. before answering, PING the node - this is the interleaving
        let (po, pp) = mule_kad::build_ping();
        let dg = kad_obfuscate_request(&pack_kad(po, pp), &Kad128::from_words([5, 5, 5, 5]),
                                       0x1111, 0, 0, 0x40);
        peer.send_to(&dg, ours).await.unwrap();
        // 3. now answer the bootstrap
        let (ro, rp) = build_bootstrap_res(&peer_id, 4662, 8, &[]);
        let ack = kad_obfuscate_response(&pack_kad(ro, rp), 0x2468, dec.sender_vk, 0, 0x80);
        peer.send_to(&ack, from).await.unwrap();
        // 4. and read OUR pong
        let (n2, _) = peer.recv_from(&mut buf).await.unwrap();
        n2 > 0
    });

    let res = node
        .bootstrap_from(&test_contact(peer_id, peer_addr), Duration::from_secs(3))
        .await;
    assert!(res.is_ok(), "the reply must reach its waiter despite the interleaved request");
    assert!(mock.await.unwrap(), "the inbound PING must have been answered");
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `source "$HOME/.cargo/env" && cargo test -p mule-engine an_inbound_request_is_answered`
Expected: FAIL - `no method named local_addr`, `build_ping` missing, and the PING is never answered.

- [ ] **Step 3: Add `build_ping` to `mule-kad`**

```rust
/// A KADEMLIA2_PING. Bodiless, like the bootstrap request.
pub fn build_ping() -> (u8, Vec<u8>) {
    (OP_PING, Vec::new())
}
```

Export it from `crates/mule-kad/src/lib.rs`.

- [ ] **Step 4: Implement the loop**

In `kad_live.rs`, restructure so the socket is owned by a task:

- Wrap the socket in `Arc<UdpSocket>` so the loop task and the senders share it.
- Add `pending: Arc<Mutex<Vec<PendingSlot>>>` where a slot is
  `{ dest: SocketAddr, dest_ip: u32, sender_vk: u32, expect: u8, tx: oneshot::Sender<...> }`.
- `spawn_read_loop()` runs forever: `recv_from` -> `kad_deobfuscate` with the
  SENDER's ip -> `unpack_kad`. If a pending slot matches by exact address (else
  by IP, the existing fallback), and its `expect` matches the opcode, send the
  payload down its oneshot and remove it. Otherwise call
  `kad_serve::answer_request` and, on `Some(answer)`, obfuscate with
  `kad_obfuscate_response` and `send_to` the sender.
- `request_batch` keeps its signature but now REGISTERS slots and awaits their
  oneshots with `tokio::time::timeout`, instead of reading the socket itself.
  **Its matching rules and both mutation-checked tests are preserved verbatim.**
- Add `pub(crate) fn local_addr(&self) -> SocketAddr`.
- Start the loop in `bind_with_identity` so every `KadNode` has it.

Keep `send_hello_res_ack` as-is; it is fire-and-forget and needs no slot.

- [ ] **Step 5: Run the full engine suite**

Run: `source "$HOME/.cargo/env" && cargo test -p mule-engine`
Expected: PASS, including `a_batch_of_silent_peers_costs_one_window_not_one_per_peer`
and `a_batch_matches_each_reply_to_the_peer_that_sent_it`, which must survive the
move unchanged.

- [ ] **Step 6: Re-run the two mutation checks from row 8ch**

Confirm the preserved demux still fails when broken:

```bash
# 1. re-serialise the batch -> the timing test must fail near 3x the window
# 2. drop the exact-address match -> two peers on one IP must swap answers
```

Apply each mutation by hand, run the named test, confirm RED, restore.

- [ ] **Step 7: Commit**

```bash
source "$HOME/.cargo/env"
cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --all -- --check
git add crates/mule-engine/src/kad_live.rs crates/mule-kad/src/message.rs crates/mule-kad/src/lib.rs
git commit -m "feat(kad): one task owns the socket, so padMule can answer at last

The socket was read ONLY while awaiting our own reply, so an inbound request was
dropped on the floor - padMule answered nothing and aged out of every routing
table that learned it. One loop now owns the socket: a datagram either satisfies
a pending request or is answered by kad_serve.

request_batch's demux is preserved rather than rewritten, including the
exact-address-then-IP matching and both mutation-checked tests, which were
re-verified against their mutations after the move."
```

---

### Task 8: The receiver-key verdict, and the flood limiter

**Files:**
- Modify: `crates/mule-engine/src/kad_live.rs`

- [ ] **Step 1: Write the failing tests**

```rust
/// The ACK bit must reflect the REAL receiver-key verdict, not the `false`
/// Task 3 wired as a placeholder. A peer that echoed our verify key has proved
/// its IP and must not be asked to prove it again.
#[tokio::test]
async fn a_verified_hello_sender_is_not_asked_for_an_ack() { /* drive a HELLO_REQ
    carrying a valid receiver key at the node, parse the HELLO_RES, and assert
    misc_options does NOT contain 0x04; then repeat with a bogus key and assert
    it DOES. */ }

/// eMule 0.70b: too many requests of one type from one IP get ignored, then the
/// source is banned. FloodTracker has existed unused since it was written -
/// this is its first call site.
#[tokio::test]
async fn a_flood_of_requests_from_one_ip_is_ignored_then_banned() { /* send
    soft_limit+1 pings from one address, assert the last is unanswered. */ }
```

Write these out in full when implementing - the shapes above name exactly what
each must assert.

- [ ] **Step 2: Run to verify they fail**

Run: `source "$HOME/.cargo/env" && cargo test -p mule-engine a_verified_hello_sender a_flood_of_requests`
Expected: FAIL - the ACK is always requested; the flood is always answered.

- [ ] **Step 3: Implement**

- In the read loop, `kad_deobfuscate` already yields `receiver_vk`; compare it
  to `udp_verify_key(self.udp_key, sender_ip)` and pass the boolean into
  `answer_hello`. Replace Task 3's `false` in `answer_request` by threading the
  verdict through as a parameter.
- Hold one `FloodTracker` per served opcode in a `Mutex<HashMap<u8, FloodTracker>>`.
  Before answering, consult it with the sender IP; `Ignore` and `Ban` both mean
  send nothing. Give `OP_BOOTSTRAP_REQ` a tighter limit than the rest - it is the
  amplification arm.
- Record the requester through the existing gated `add_contact` so an inbound
  contact faces the ipfilter, DNS-port and anti-sybil rules like any other.

- [ ] **Step 4: Run to verify they pass**

Run: `source "$HOME/.cargo/env" && cargo test -p mule-engine`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
source "$HOME/.cargo/env"
cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --all -- --check
git add crates/mule-engine/src/kad_live.rs
git commit -m "feat(kad): real receiver-key verdict, and FloodTracker's first call site

FloodTracker was written for eMule 0.70b's ignore-then-ban hardening and has had
no consumer since, because padMule had no inbound path. One tracker per served
opcode keyed by source IP, with a tighter limit on BOOTSTRAP_REQ, which is the
amplification arm. The HELLO ACK bit now carries the real bValidReceiverKey
verdict instead of the placeholder Task 3 wired."
```

---

### Task 9: Prove it against a real client

**Files:**
- Modify: `scripts/kad-verify-oracle.sh`
- Modify: `docs/wiki/kad-verify-oracle.md`

- [ ] **Step 1: Extend the oracle**

The log-patched amuled already proves a real node marks padMule IP-VERIFIED.
Extend the run so it then PINGS padMule on its `OnSmallTimer` sweep and keeps it
in its routing table. Capture the amuled log lines showing the contact surviving
a sweep it would previously have been evicted by.

- [ ] **Step 2: Run it**

Run: `scripts/kad-verify-oracle.sh`
Expected: padMule present in the real amuled's routing table AFTER a ping cycle.

- [ ] **Step 3: Record the result and commit**

Update `docs/wiki/kad-verify-oracle.md` with what the run showed, and add a
build-progress row. This is the success test the spec names - a fact about
ANOTHER implementation's behaviour, not our code agreeing with itself.

```bash
git add scripts/kad-verify-oracle.sh docs/wiki/
git commit -m "test(kad): the oracle now proves a real amuled KEEPS padMule

Being verified once was never the question - staying in the table was. The
oracle now runs past a ping sweep, which is the only evidence that answering
actually stopped the eviction."
```

---

### Task 10: Device pass and KB

- [ ] **Step 1: Build, sign, install** - `gh workflow run "iOS build (unsigned IPA)" --ref <branch>`, verify `headSha` == `git rev-parse HEAD` and `CFBundleVersion` inside a FRESH extraction, deliver to `/mnt/c/Users/ajbuf/Downloads`, stage for Anthony's zsign, then `pymobiledevice3 apps install`.
- [ ] **Step 2: Confirm the build on device** - Settings > This device > Build. Never by spotting a UI change.
- [ ] **Step 3: Take the readings** - search submit-to-results (probe by CONTENT, re-find the field each run - see [[handoff-next-session]]), Refresh server list, Stats -> Longest poll gap (must stay ~1s), and the Kad panel. **No regression is the bar here; the speed work is Step 2 of the spec.**
- [ ] **Step 4: KB** - build-progress row, `kad-routing-lifecycle` (the serve section becomes DONE), `security-model` (the amplification cap and its ratio), `index.md`, `log.md`, and memory. Then commit.

---

## Self-Review

**Spec coverage:** architecture (Tasks 6, 7); every served opcode (2, 3, 4, 5); the conditional ACK (3, 8); empty SEARCH_RES (5); PUBLISH ignored (5); FloodTracker (8); contact gates (8); amplification cap (5, 8); lifecycle (7 - the loop is owned by the node, so the existing `set_kad(None)` drop still closes it); all five unit tests (2-8); the oracle (9); verification (10).

**Placeholders:** Task 8's two tests are described by their assertions rather than written out, because their exact shape depends on the pending-slot type Task 7 introduces. That is the one place this plan asks the implementer to write test code from a specification rather than copy it - flagged rather than hidden. Task 3 deliberately introduces a `false` placeholder and Task 8 removes it; Task 8's first test is what proves it was removed.

**Type consistency:** `ServeIdentity`, `ServeAnswer`, `answer_request`, `answer_hello`, `KAD_FIND_NODE_ANSWER_CAP`, `KAD_BOOTSTRAP_ANSWER_CAP`, `with_routing`, `closest_wire_contacts`, `local_addr`, `build_ping`, `build_pong`, `parse_search_key_req`, `parse_search_source_req` are each defined once and used consistently.

**Known risk carried forward:** Task 6 touches every `self.routing.` site in `kad_live.rs`. If that file has grown unwieldy by then, splitting the lookup half into `kad_lookup.rs` is a reasonable addition - but not before Step 2, which rewrites it anyway.
