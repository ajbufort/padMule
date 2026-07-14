//! The 128-bit Kademlia ID (`CUInt128`) and its XOR distance metric. See
//! docs/raw/wave6-kad-research-2026-07-14.md section 0.
//!
//! # The encoding landmine
//!
//! eMule stores a Kad ID as four 32-bit words, word 0 = most significant. On
//! disk AND on the wire the bytes are the RAW little-endian dwords (MSW first),
//! so a canonical hash `H[0..15]` serialises as:
//!
//! ```text
//! H3 H2 H1 H0 | H7 H6 H5 H4 | H11 H10 H9 H8 | H15 H14 H13 H12
//! ```
//!
//! i.e. each 4-byte group is byte-reversed, but the group order is preserved.
//! Reading the raw hash bytes as a Kad ID (or vice versa) targets the WRONG node,
//! the single most common Kad interop bug. This type keeps the canonical hash and
//! the wire form strictly separate: [`Kad128::from_hash`] / [`Kad128::to_hash`]
//! take the canonical MD4/SHA form, while [`Kad128::from_wire`] / [`Kad128::to_wire`]
//! take the serialised form.

/// A 128-bit Kademlia ID: four u32 words, word 0 most significant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Kad128 {
    /// words[0] holds bits 127..96 (the most significant), words[3] the least.
    words: [u32; 4],
}

impl Kad128 {
    /// Build from the four words directly (words[0] most significant).
    pub const fn from_words(words: [u32; 4]) -> Self {
        Kad128 { words }
    }

    pub const fn words(&self) -> [u32; 4] {
        self.words
    }

    /// Word `i` (chunk 0 = the top 32 bits). Underpins the tolerance test.
    pub const fn chunk(&self, i: usize) -> u32 {
        self.words[i]
    }

    /// Build a Kad ID from a CANONICAL 16-byte hash (MD4 of a keyword, or a
    /// file's ed2k hash). This is eMule's `SetValueBE`: word `i` is the
    /// big-endian value of hash bytes `[4i .. 4i+4)`.
    pub fn from_hash(hash: &[u8; 16]) -> Self {
        let mut words = [0u32; 4];
        for (i, w) in words.iter_mut().enumerate() {
            *w = u32::from_be_bytes([
                hash[4 * i],
                hash[4 * i + 1],
                hash[4 * i + 2],
                hash[4 * i + 3],
            ]);
        }
        Kad128 { words }
    }

    /// Recover the canonical 16-byte hash (eMule `ToByteArray`).
    pub fn to_hash(&self) -> [u8; 16] {
        let mut out = [0u8; 16];
        for (i, w) in self.words.iter().enumerate() {
            out[4 * i..4 * i + 4].copy_from_slice(&w.to_be_bytes());
        }
        out
    }

    /// Build from the 16 RAW bytes as they appear on disk / on the wire (each
    /// dword little-endian, MSW-first).
    pub fn from_wire(bytes: &[u8; 16]) -> Self {
        let mut words = [0u32; 4];
        for (i, w) in words.iter_mut().enumerate() {
            *w = u32::from_le_bytes([
                bytes[4 * i],
                bytes[4 * i + 1],
                bytes[4 * i + 2],
                bytes[4 * i + 3],
            ]);
        }
        Kad128 { words }
    }

    /// Serialise to the 16 RAW disk/wire bytes.
    pub fn to_wire(&self) -> [u8; 16] {
        let mut out = [0u8; 16];
        for (i, w) in self.words.iter().enumerate() {
            out[4 * i..4 * i + 4].copy_from_slice(&w.to_le_bytes());
        }
        out
    }

    /// XOR distance to another ID (the Kademlia metric).
    pub fn distance(&self, other: &Kad128) -> Kad128 {
        Kad128 {
            words: [
                self.words[0] ^ other.words[0],
                self.words[1] ^ other.words[1],
                self.words[2] ^ other.words[2],
                self.words[3] ^ other.words[3],
            ],
        }
    }

    /// Bit `n` counting from the MOST significant (bit 0 = MSB of the whole 128).
    /// Returns 0 for `n > 127`, matching eMule `GetBitNumber`.
    pub fn bit(&self, n: u32) -> u8 {
        if n > 127 {
            return 0;
        }
        let word = (n / 32) as usize;
        let shift = 31 - (n % 32);
        ((self.words[word] >> shift) & 1) as u8
    }

    /// True if this DISTANCE lies within the self/tolerance region: the top 32
    /// bits (chunk 0) are <= 0x0100_0000, i.e. the distance is under 2^120
    /// (eMule's `distance.Get32BitChunk(0) <= SELF_TOLERANCE`).
    pub fn within_tolerance(&self) -> bool {
        self.words[0] <= 0x0100_0000
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The fixture's first contact, canonical vs raw wire form (from the spec's
    // decode of crates/mule-files/tests/fixtures/nodes.dat).
    const WIRE: [u8; 16] = [
        0x5c, 0xd0, 0xb8, 0x8f, 0x27, 0xb7, 0x34, 0x93, 0x09, 0xef, 0xb1, 0xee, 0x28, 0xf9, 0x6e,
        0xe8,
    ];
    const CANONICAL: [u8; 16] = [
        0x8f, 0xb8, 0xd0, 0x5c, 0x93, 0x34, 0xb7, 0x27, 0xee, 0xb1, 0xef, 0x09, 0xe8, 0x6e, 0xf9,
        0x28,
    ];

    #[test]
    fn wire_and_canonical_are_byte_reversed_per_dword() {
        let id = Kad128::from_wire(&WIRE);
        assert_eq!(id.to_hash(), CANONICAL);
        assert_eq!(id.to_wire(), WIRE);
        // from_hash of the canonical form yields the same ID.
        assert_eq!(Kad128::from_hash(&CANONICAL), id);
    }

    #[test]
    fn round_trips_both_ways() {
        let id = Kad128::from_wire(&WIRE);
        assert_eq!(Kad128::from_wire(&id.to_wire()), id);
        assert_eq!(Kad128::from_hash(&id.to_hash()), id);
    }

    #[test]
    fn top_word_is_the_most_significant() {
        let id = Kad128::from_wire(&WIRE);
        // Canonical bytes 8f b8 d0 5c -> word0 = 0x8fb8d05c.
        assert_eq!(id.chunk(0), 0x8fb8_d05c);
        assert_eq!(id.chunk(3), 0xe86e_f928);
    }

    #[test]
    fn xor_distance_to_self_is_zero() {
        let id = Kad128::from_wire(&WIRE);
        assert_eq!(id.distance(&id), Kad128::default());
        // XOR is symmetric.
        let other = Kad128::from_hash(&[0x11; 16]);
        assert_eq!(id.distance(&other), other.distance(&id));
    }

    #[test]
    fn bit_zero_is_the_msb() {
        // word0 = 0x8fb8d05c = 1000 1111 ... MSB is 1.
        let id = Kad128::from_wire(&WIRE);
        assert_eq!(id.bit(0), 1);
        assert_eq!(id.bit(1), 0); // 0
        assert_eq!(id.bit(2), 0);
        assert_eq!(id.bit(3), 0);
        assert_eq!(id.bit(4), 1); // 8f = 1000 1111
                                  // A one-bit-set ID: only bit `n` is 1.
        let one = Kad128::from_words([0x8000_0000, 0, 0, 0]);
        assert_eq!(one.bit(0), 1);
        assert_eq!(one.bit(32), 0);
        // Out of range.
        assert_eq!(one.bit(128), 0);
        assert_eq!(one.bit(999), 0);
    }

    #[test]
    fn tolerance_is_two_to_the_120() {
        // chunk0 == 0x01000000 is exactly the boundary (within); one more is out.
        assert!(Kad128::from_words([0x0100_0000, 0, 0, 0]).within_tolerance());
        assert!(Kad128::from_words([0x00FF_FFFF, 0xFFFF_FFFF, 0, 0]).within_tolerance());
        assert!(!Kad128::from_words([0x0100_0001, 0, 0, 0]).within_tolerance());
        // Zero distance (ourselves) is trivially within tolerance.
        assert!(Kad128::default().within_tolerance());
    }

    #[test]
    fn ordering_is_by_most_significant_word_first() {
        let small = Kad128::from_words([1, 0, 0, 0]);
        let big = Kad128::from_words([2, 0, 0, 0]);
        assert!(small < big);
        // A difference only in a lower word is subordinate to the top word.
        let a = Kad128::from_words([1, 0xFFFF_FFFF, 0, 0]);
        let b = Kad128::from_words([2, 0, 0, 0]);
        assert!(a < b);
    }
}
