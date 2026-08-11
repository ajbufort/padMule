//! ed2k:// and magnet: link parsing, plus AICH base32 decoding
//! (`mule_proto::link`, `mule_proto::aich`).
//!
//! Attacker input: a link is pasted, opened from Safari, or arrives inside a
//! server message; the AICH base32 decoder reads the `h=` field of a magnet.
//! Both take a `&str` that padMule never wrote.
//!
//! Non-UTF-8 bytes are folded with `from_utf8_lossy` rather than skipped, so no
//! fuzz iteration is wasted - the parsers only ever see a `&str` in production
//! anyway, and lossy conversion still produces the odd shapes (embedded NULs,
//! replacement chars, lone separators) that the grammar has to survive.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mule_proto::{aich_from_base32, parse_link};

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    let _ = parse_link(&s);
    let _ = aich_from_base32(&s);
});
