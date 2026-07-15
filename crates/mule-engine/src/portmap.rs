//! NAT-PMP port mapping (RFC 6886) - ask the gateway to open our listening port
//! so we get a HighID without a manual router forward. This is the lightweight
//! cousin of UPnP-IGD (which needs SSDP discovery + SOAP/XML); NAT-PMP is a tiny
//! binary UDP protocol to the gateway on port 5351. Many consumer routers speak
//! one or the other, so a real client tries both - this covers NAT-PMP.
//!
//! Request:  `[ver=0][op][reserved u16=0][internal port u16 BE][requested
//!            external port u16 BE][lifetime u32 BE]` (op 1 = UDP, 2 = TCP).
//! Response: `[ver=0][op+128][result u16 BE][epoch u32 BE][internal port u16 BE]
//!            [mapped external port u16 BE][lifetime u32 BE]`.
//! All multi-byte fields are network byte order (big-endian).

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

/// NAT-PMP protocol version (always 0).
const NATPMP_VERSION: u8 = 0;
/// Gateway UDP port.
pub const NATPMP_PORT: u16 = 5351;

/// Which transport to map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Udp,
    Tcp,
}

impl Proto {
    fn opcode(self) -> u8 {
        match self {
            Proto::Udp => 1,
            Proto::Tcp => 2,
        }
    }
}

/// Build a NAT-PMP map request (12 bytes).
pub fn build_map_request(
    proto: Proto,
    internal_port: u16,
    external_port: u16,
    lifetime_secs: u32,
) -> [u8; 12] {
    let mut b = [0u8; 12];
    b[0] = NATPMP_VERSION;
    b[1] = proto.opcode();
    // b[2..4] reserved = 0
    b[4..6].copy_from_slice(&internal_port.to_be_bytes());
    b[6..8].copy_from_slice(&external_port.to_be_bytes());
    b[8..12].copy_from_slice(&lifetime_secs.to_be_bytes());
    b
}

/// A parsed NAT-PMP map response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapResponse {
    /// 0 = success; nonzero = a NAT-PMP result code.
    pub result: u16,
    pub internal_port: u16,
    /// The external port the gateway actually mapped.
    pub mapped_external_port: u16,
    pub lifetime_secs: u32,
}

/// Parse a NAT-PMP map response (>= 16 bytes). `None` if malformed or not a
/// response to a map request.
pub fn parse_map_response(proto: Proto, buf: &[u8]) -> Option<MapResponse> {
    if buf.len() < 16 || buf[0] != NATPMP_VERSION || buf[1] != proto.opcode() + 128 {
        return None;
    }
    Some(MapResponse {
        result: u16::from_be_bytes([buf[2], buf[3]]),
        // buf[4..8] = epoch (seconds since the gateway's port map table reset)
        internal_port: u16::from_be_bytes([buf[8], buf[9]]),
        mapped_external_port: u16::from_be_bytes([buf[10], buf[11]]),
        lifetime_secs: u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]),
    })
}

/// Errors from a live NAT-PMP exchange.
#[derive(Debug)]
pub enum PortMapError {
    Io(std::io::Error),
    Timeout,
    /// Gateway responded but the mapping failed (carries the result code).
    Failed(u16),
    /// The response was malformed.
    BadResponse,
}

impl std::fmt::Display for PortMapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PortMapError::Io(e) => write!(f, "io: {e}"),
            PortMapError::Timeout => write!(f, "gateway did not answer (no NAT-PMP?)"),
            PortMapError::Failed(c) => write!(f, "gateway refused the mapping (result {c})"),
            PortMapError::BadResponse => write!(f, "malformed NAT-PMP response"),
        }
    }
}

impl From<std::io::Error> for PortMapError {
    fn from(e: std::io::Error) -> Self {
        PortMapError::Io(e)
    }
}

/// Request a port mapping from `gateway` (its LAN IP). Returns the external port
/// the gateway mapped on success. Best-effort: a `Timeout` most likely means the
/// gateway does not speak NAT-PMP (try UPnP, or a manual forward).
pub async fn map_port(
    gateway: IpAddr,
    proto: Proto,
    internal_port: u16,
    lifetime_secs: u32,
    wait: Duration,
) -> Result<u16, PortMapError> {
    let socket = UdpSocket::bind((IpAddr::from([0u8, 0, 0, 0]), 0)).await?;
    let dest = SocketAddr::new(gateway, NATPMP_PORT);
    let req = build_map_request(proto, internal_port, internal_port, lifetime_secs);
    socket.send_to(&req, dest).await?;

    let mut buf = [0u8; 64];
    let n = match timeout(wait, socket.recv_from(&mut buf)).await {
        Ok(r) => r?.0,
        Err(_) => return Err(PortMapError::Timeout),
    };
    let resp = parse_map_response(proto, &buf[..n]).ok_or(PortMapError::BadResponse)?;
    if resp.result != 0 {
        return Err(PortMapError::Failed(resp.result));
    }
    Ok(resp.mapped_external_port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_request_is_well_formed() {
        let r = build_map_request(Proto::Tcp, 4662, 4662, 3600);
        assert_eq!(r[0], 0); // version
        assert_eq!(r[1], 2); // TCP opcode
        assert_eq!(&r[2..4], &[0, 0]); // reserved
        assert_eq!(u16::from_be_bytes([r[4], r[5]]), 4662);
        assert_eq!(u16::from_be_bytes([r[6], r[7]]), 4662);
        assert_eq!(u32::from_be_bytes([r[8], r[9], r[10], r[11]]), 3600);
    }

    #[test]
    fn parse_a_success_response() {
        // ver 0, op 130 (TCP resp), result 0, epoch, internal 4662, external 4662, lifetime 3600
        let mut b = vec![0u8, 130, 0, 0, 0, 0, 0, 10];
        b.extend_from_slice(&4662u16.to_be_bytes());
        b.extend_from_slice(&4662u16.to_be_bytes());
        b.extend_from_slice(&3600u32.to_be_bytes());
        let r = parse_map_response(Proto::Tcp, &b).unwrap();
        assert_eq!(r.result, 0);
        assert_eq!(r.internal_port, 4662);
        assert_eq!(r.mapped_external_port, 4662);
        assert_eq!(r.lifetime_secs, 3600);
    }

    #[test]
    fn parse_rejects_wrong_opcode_and_short() {
        let good_len = vec![0u8, 129, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        // Asking for a TCP response (op 130) but this is a UDP response (op 129).
        assert!(parse_map_response(Proto::Tcp, &good_len).is_none());
        assert!(parse_map_response(Proto::Udp, &good_len).is_some());
        assert!(parse_map_response(Proto::Udp, &[0, 129, 0]).is_none());
    }
}
