//! RC4 stream cipher - the core of eMule/aMule protocol obfuscation.
//!
//! This is textbook RC4 (KSA + PRGA). The only eMule-specific wrinkle is that
//! the TCP obfuscation layer discards the first 1024 keystream bytes after
//! keying (`Rc4::new_discard(key, 1024)`), while the UDP layer discards none.
//! The obfuscation key itself is always a 16-byte MD5 digest (see
//! `crate::obf_key`).
//!
//! RC4 is cryptographically broken and used here ONLY because the eMule wire
//! protocol mandates it for obfuscation; it is not a security feature, it is an
//! interop requirement.

/// An RC4 keystream generator / cipher. The keystream is stateful: each byte is
/// consumed exactly once, so encrypt and decrypt must run over the same byte
/// positions with the same key.
#[derive(Clone)]
pub struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    /// Key an RC4 cipher (KSA) with no keystream discard.
    pub fn new(key: &[u8]) -> Self {
        let mut s = [0u8; 256];
        for (i, b) in s.iter_mut().enumerate() {
            *b = i as u8;
        }
        let mut j = 0u8;
        for i in 0..256 {
            // key.len() is never 0 in practice (always a 16-byte digest), but
            // guard so an empty key cannot divide by zero.
            let k = if key.is_empty() {
                0
            } else {
                key[i % key.len()]
            };
            j = j.wrapping_add(s[i]).wrapping_add(k);
            s.swap(i, j as usize);
        }
        Rc4 { s, i: 0, j: 0 }
    }

    /// Key an RC4 cipher and discard the first `n` keystream bytes. eMule TCP
    /// obfuscation uses `n = 1024`; UDP uses `n = 0`.
    pub fn new_discard(key: &[u8], n: usize) -> Self {
        let mut c = Rc4::new(key);
        c.discard(n);
        c
    }

    /// Advance the keystream by `n` bytes without producing output.
    pub fn discard(&mut self, n: usize) {
        for _ in 0..n {
            self.next_byte();
        }
    }

    fn next_byte(&mut self) -> u8 {
        self.i = self.i.wrapping_add(1);
        self.j = self.j.wrapping_add(self.s[self.i as usize]);
        self.s.swap(self.i as usize, self.j as usize);
        let t = self.s[self.i as usize].wrapping_add(self.s[self.j as usize]);
        self.s[t as usize]
    }

    /// XOR `data` in place with the next keystream bytes (encrypt == decrypt).
    pub fn apply(&mut self, data: &mut [u8]) {
        for b in data.iter_mut() {
            *b ^= self.next_byte();
        }
    }

    /// Return `n` keystream bytes (for tests / key-material derivation).
    pub fn keystream(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next_byte()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Standard RC4 test vectors (RFC 6229 / the classic "Key"/"Wiki" cases),
    // so the primitive is pinned against a known-good implementation, not just
    // itself.
    #[test]
    fn rfc_style_vector_key() {
        // key="Key", plaintext="Plaintext" -> ciphertext BBF316E8D940AF0AD3
        let mut c = Rc4::new(b"Key");
        let mut data = b"Plaintext".to_vec();
        c.apply(&mut data);
        assert_eq!(hex::encode_upper(&data), "BBF316E8D940AF0AD3");
    }

    #[test]
    fn vector_wiki() {
        // key="Wiki", plaintext="pedia" -> 1021BF0420
        let mut c = Rc4::new(b"Wiki");
        let mut data = b"pedia".to_vec();
        c.apply(&mut data);
        assert_eq!(hex::encode_upper(&data), "1021BF0420");
    }

    #[test]
    fn vector_secret() {
        // key="Secret", plaintext="Attack at dawn" -> 45A01F645FC35B383552544B9BF5
        let mut c = Rc4::new(b"Secret");
        let mut data = b"Attack at dawn".to_vec();
        c.apply(&mut data);
        assert_eq!(hex::encode_upper(&data), "45A01F645FC35B383552544B9BF5");
    }

    #[test]
    fn encrypt_then_decrypt_round_trips() {
        let key = [0x11u8, 0x22, 0x33, 0x44, 0x55];
        let orig = b"the quick brown fox jumps over the lazy dog".to_vec();
        let mut enc = orig.clone();
        Rc4::new(&key).apply(&mut enc);
        assert_ne!(enc, orig);
        let mut dec = enc.clone();
        Rc4::new(&key).apply(&mut dec);
        assert_eq!(dec, orig);
    }

    #[test]
    fn discard_advances_the_keystream() {
        let key = [0xAAu8; 16];
        // A cipher that discards 10 bytes produces the same output as one that
        // generated and threw away 10 bytes first.
        let ks_full = Rc4::new(&key).keystream(20);
        let ks_discard = Rc4::new_discard(&key, 10).keystream(10);
        assert_eq!(&ks_full[10..20], &ks_discard[..]);
    }

    #[test]
    fn discard_1024_is_the_tcp_obfuscation_case() {
        let key = [0x42u8; 16];
        let a = Rc4::new_discard(&key, 1024).keystream(4);
        let mut b = Rc4::new(&key);
        b.discard(1024);
        assert_eq!(a, b.keystream(4));
    }

    #[test]
    fn empty_key_does_not_panic() {
        let mut c = Rc4::new(&[]);
        let mut d = [0u8; 4];
        c.apply(&mut d); // must not divide by zero
    }
}
