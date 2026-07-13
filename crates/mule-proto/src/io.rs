//! Little-endian byte I/O primitives, mirroring aMule's CFileDataIO/SafeFile.
//! All eD2k multi-byte integers are little-endian. Strings are a u16 length
//! prefix followed by raw bytes, with no NUL terminator. See
//! docs/wiki/protocol-reference.md.

use core::fmt;

/// Errors from reading or decoding eD2k byte streams.
#[derive(Debug, PartialEq, Eq)]
pub enum IoError {
    /// Ran out of input while reading.
    UnexpectedEof,
    /// A tag (or other structure) was malformed. Carries the offending value.
    BadTag(u8),
}

impl fmt::Display for IoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IoError::UnexpectedEof => write!(f, "unexpected end of input"),
            IoError::BadTag(t) => write!(f, "malformed tag (type/marker 0x{t:02x})"),
        }
    }
}

impl std::error::Error for IoError {}

/// A cursor over a byte slice that reads little-endian eD2k primitives.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Wrap `buf`, starting at offset 0.
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    /// Bytes not yet consumed.
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], IoError> {
        let end = self.pos.checked_add(n).ok_or(IoError::UnexpectedEof)?;
        if end > self.buf.len() {
            return Err(IoError::UnexpectedEof);
        }
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    /// Read one byte.
    pub fn read_u8(&mut self) -> Result<u8, IoError> {
        Ok(self.take(1)?[0])
    }

    /// Read a little-endian u16.
    pub fn read_u16(&mut self) -> Result<u16, IoError> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    /// Read a little-endian u32.
    pub fn read_u32(&mut self) -> Result<u32, IoError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Read a little-endian u64.
    pub fn read_u64(&mut self) -> Result<u64, IoError> {
        let b = self.take(8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    /// Read exactly `n` raw bytes.
    pub fn read_bytes(&mut self, n: usize) -> Result<Vec<u8>, IoError> {
        Ok(self.take(n)?.to_vec())
    }

    /// Read a u16-length-prefixed byte string (raw bytes, no decoding).
    pub fn read_string_u16(&mut self) -> Result<Vec<u8>, IoError> {
        let len = self.read_u16()? as usize;
        self.read_bytes(len)
    }
}

/// A growable little-endian eD2k byte writer.
#[derive(Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    /// A new empty writer.
    pub fn new() -> Self {
        Writer { buf: Vec::new() }
    }

    /// Consume the writer, returning the written bytes.
    pub fn into_inner(self) -> Vec<u8> {
        self.buf
    }

    /// Current written bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    /// Write one byte.
    pub fn write_u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    /// Write a little-endian u16.
    pub fn write_u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Write a little-endian u32.
    pub fn write_u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Write a little-endian u64.
    pub fn write_u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Write raw bytes.
    pub fn write_bytes(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }

    /// Write a u16-length-prefixed byte string.
    pub fn write_string_u16(&mut self, b: &[u8]) {
        self.write_u16(b.len() as u16);
        self.write_bytes(b);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn le_round_trip_all_widths() {
        let mut w = Writer::new();
        w.write_u8(0x12);
        w.write_u16(0x3456);
        w.write_u32(0x789abcde);
        w.write_u64(0x0123456789abcdef);
        let bytes = w.into_inner();
        let mut r = Reader::new(&bytes);
        assert_eq!(r.read_u8().unwrap(), 0x12);
        assert_eq!(r.read_u16().unwrap(), 0x3456);
        assert_eq!(r.read_u32().unwrap(), 0x789abcde);
        assert_eq!(r.read_u64().unwrap(), 0x0123456789abcdef);
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn u32_is_little_endian_on_the_wire() {
        let mut w = Writer::new();
        w.write_u32(0x12345678);
        assert_eq!(w.into_inner(), vec![0x78, 0x56, 0x34, 0x12]);
    }

    #[test]
    fn string_u16_round_trips() {
        let mut w = Writer::new();
        w.write_string_u16(b"abc");
        let bytes = w.into_inner();
        assert_eq!(bytes, vec![0x03, 0x00, b'a', b'b', b'c']);
        let mut r = Reader::new(&bytes);
        assert_eq!(r.read_string_u16().unwrap(), b"abc".to_vec());
    }

    #[test]
    fn underrun_errors() {
        let mut r = Reader::new(&[0x01, 0x02]);
        assert_eq!(r.read_u32(), Err(IoError::UnexpectedEof));
    }
}
