//! eD2k/eMule TCP packet framing plus the zlib unpack path
//! (`mule_proto::packet`).
//!
//! Attacker input: every byte a peer or server writes on our TCP socket. The
//! engine's read loop calls `read_packet` on the accumulated buffer, drops the
//! consumed prefix, and unpacks a 0xD4/0xE5/0xF5 body with `decompress`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mule_proto::packet::PROT_ED2KV2_PACKED;
use mule_proto::{decompress, read_packet, PROT_KAD_PACKED, PROT_PACKED};

/// Inflation cap. The real read loop passes MAX_PACKET_SIZE (2 MB); a smaller
/// bound here keeps a single fuzz iteration fast without changing which code
/// paths run - the size check is the last thing `decompress` does.
const MAX_INFLATE: usize = 1 << 20;

fuzz_target!(|data: &[u8]| {
    // Drain the buffer exactly as the socket read loop does. The iteration cap
    // is a harness guard only: every accepted frame consumes at least 6 bytes,
    // so it cannot be reached before the input runs out at the default 4 KB
    // max_len - raise it if you fuzz with -max_len far above that.
    let mut rest = data;
    for _ in 0..1024 {
        match read_packet(rest) {
            Ok(Some((p, consumed))) => {
                if matches!(
                    p.protocol,
                    PROT_PACKED | PROT_KAD_PACKED | PROT_ED2KV2_PACKED
                ) {
                    let _ = decompress(&p, MAX_INFLATE);
                }
                rest = &rest[consumed..];
            }
            // Ok(None) = need more bytes; Err = malformed header. Both end the
            // loop, matching the engine (which drops the connection on Err).
            _ => break,
        }
    }
});
