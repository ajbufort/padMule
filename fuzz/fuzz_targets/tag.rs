//! MET tag decoding (`mule_proto::tag`).
//!
//! Attacker input: tag lists ride inside almost every eD2k packet
//! (OP_SEARCHRESULT, OP_SERVERIDENT, OP_OFFERFILES, OP_SERVER_DESC_RES) AND
//! inside every .met file on disk. `read_tag` is therefore the single most
//! reached decoder in the tree.
//!
//! The writer is fuzzed on the same bytes on purpose: a tag read off the wire
//! gets written back into known.met / part.met, so `write_tag` is reachable
//! from hostile input too. No round-trip equality is asserted - a 1-byte
//! `TagName::Str` is deliberately unrepresentable on write (see tag.rs), so
//! equality would be a harness bug, not a finding.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mule_proto::{read_tag, write_tag, Reader, Writer};

fuzz_target!(|data: &[u8]| {
    let mut r = Reader::new(data);
    let mut w = Writer::new();
    // Read tags until the bytes run out or one is malformed, which is what
    // every MET taglist loop in the tree does.
    while let Ok(tag) = read_tag(&mut r) {
        write_tag(&mut w, &tag);
    }
});
