//! UPnP-IGD port mapping - ask the gateway to open our listening port so the
//! device becomes HighID. This is the heavier cousin of [`crate::portmap`]
//! (NAT-PMP): UPnP needs SSDP discovery, an HTTP GET of the device description,
//! then a SOAP/XML control call. Many consumer gateways (incl. the dev box's
//! Xfinity gateway) speak UPnP but NOT NAT-PMP, so a real client tries both.
//!
//! # Discovery: multicast on desktop, UNICAST on iOS
//!
//! Standard SSDP discovery multicasts M-SEARCH to 239.255.255.250. iOS SILENTLY
//! DROPS multicast without the restricted `com.apple.developer.networking.
//! multicast` entitlement, which is unreachable for a free-signed sideloaded app.
//! So on-device we discover by UNICAST M-SEARCH aimed straight at the inferred
//! gateway ([`discover_unicast`]) - same UPnP protocol, no multicast, no
//! entitlement. [`map_port`] tries multicast first, then falls back to unicast,
//! so the SAME binary earns HighID on both a desktop and the iPad. The catch is
//! that iOS exposes no default-gateway API, so the gateway is inferred from our
//! own LAN /24 ([`gateway_candidates`]).
//!
//! Hand-rolled with zero new dependencies (tokio sockets + minimal HTTP/XML
//! extraction), the same dependency-light style as `link.rs`/`portmap.rs`, so it
//! cross-compiles cleanly to iOS. The parsing/SOAP-building is pure and unit
//! tested; the unicast discovery path is tested against a mock gateway over
//! loopback, and the live network calls are exercised via `mule-cli upnp`.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

/// The SSDP multicast endpoint (all IGDs listen here).
const SSDP_ADDR: &str = "239.255.255.250:1900";

/// Device/service targets we search for, most-specific first. A gateway answers
/// on whichever it implements; the description XML then names the WAN service.
const SEARCH_TARGETS: &[&str] = &[
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
    "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
];

/// The two WAN connection service types that expose AddPortMapping.
const WAN_SERVICES: &[&str] = &[
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
];

#[derive(Debug)]
pub enum UpnpError {
    /// No IGD answered the SSDP search.
    NoGateway,
    /// The device description lacked a usable WAN connection service.
    NoWanService,
    /// A network step failed (connect / read / write / timeout).
    Io(String),
    /// The gateway returned an HTTP/SOAP error (status line or fault text).
    Gateway(String),
    /// A response could not be parsed.
    BadResponse,
}

impl fmt::Display for UpnpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UpnpError::NoGateway => write!(
                f,
                "no UPnP gateway answered (try NAT-PMP or a manual forward)"
            ),
            UpnpError::NoWanService => write!(f, "gateway has no WANIP/PPP connection service"),
            UpnpError::Io(e) => write!(f, "network error: {e}"),
            UpnpError::Gateway(e) => write!(f, "gateway refused: {e}"),
            UpnpError::BadResponse => write!(f, "malformed gateway response"),
        }
    }
}

impl std::error::Error for UpnpError {}

/// A discovered WAN connection service: where to POST SOAP control actions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WanService {
    /// Absolute control URL (SOAP endpoint).
    pub control_url: String,
    /// The service type string (goes in the SOAPAction header + XML namespace).
    pub service_type: String,
}

/// L3 protocol for a mapping (UPnP spells these "TCP"/"UDP").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    fn as_str(self) -> &'static str {
        match self {
            Proto::Tcp => "TCP",
            Proto::Udp => "UDP",
        }
    }
}

// ---- pure helpers (unit tested) -------------------------------------------

/// Split an `http://host:port/path` URL into `(host, port, path)`. Only the http
/// scheme is used by UPnP device descriptions. `None` if it is not parseable.
pub fn split_http_url(url: &str) -> Option<(String, u16, String)> {
    let rest = url.strip_prefix("http://")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().ok()?),
        None => (authority.to_string(), 80u16),
    };
    if host.is_empty() {
        return None;
    }
    Some((host, port, path.to_string()))
}

/// Read the text of the FIRST `<tag>...</tag>` (namespace-insensitive on the
/// local name) at any depth. Used to pull single fields out of small SOAP/desc
/// XML without a full parser.
pub fn xml_tag(xml: &str, local: &str) -> Option<String> {
    // Match the local name after an optional `prefix:`; scan every '<'.
    let mut i = 0;
    let bytes = xml.as_bytes();
    while let Some(off) = xml[i..].find('<') {
        let start = i + off + 1;
        // opening tag only (skip '/' and '?')
        if bytes.get(start) == Some(&b'/') || bytes.get(start) == Some(&b'?') {
            i = start;
            continue;
        }
        let tail = &xml[start..];
        // strip a namespace prefix if present
        let name_region = tail.split(['>', ' ', '\t', '\r', '\n', '/']).next()?;
        let local_name = name_region.rsplit(':').next().unwrap_or(name_region);
        if local_name.eq_ignore_ascii_case(local) {
            let open_end = start + tail.find('>')?;
            let content_start = open_end + 1;
            let close = xml[content_start..].find("</")?;
            return Some(xml[content_start..content_start + close].to_string());
        }
        i = start;
    }
    None
}

/// Resolve a possibly-relative controlURL against the description's base URL.
pub fn resolve_url(base_url: &str, control_url: &str) -> String {
    if control_url.starts_with("http://") {
        return control_url.to_string();
    }
    let (host, port, _) = match split_http_url(base_url) {
        Some(v) => v,
        None => return control_url.to_string(),
    };
    let path = if control_url.starts_with('/') {
        control_url.to_string()
    } else {
        format!("/{control_url}")
    };
    format!("http://{host}:{port}{path}")
}

/// From an IGD device-description XML + the URL it was fetched from, find the
/// first WANIP/PPP connection service and its absolute control URL.
pub fn parse_wan_service(desc_xml: &str, desc_url: &str) -> Option<WanService> {
    for svc_type in WAN_SERVICES {
        // Find a <service> block whose <serviceType> is this type, then its
        // <controlURL>. Services are small blocks; scan block by block.
        let mut search_from = 0;
        while let Some(rel) = desc_xml[search_from..].find("<service") {
            let blk_start = search_from + rel;
            let blk_end = desc_xml[blk_start..]
                .find("</service>")
                .map(|e| blk_start + e)
                .unwrap_or(desc_xml.len());
            let block = &desc_xml[blk_start..blk_end];
            if let Some(t) = xml_tag(block, "serviceType") {
                if t.trim() == *svc_type {
                    if let Some(ctrl) = xml_tag(block, "controlURL") {
                        return Some(WanService {
                            control_url: resolve_url(desc_url, ctrl.trim()),
                            service_type: svc_type.to_string(),
                        });
                    }
                }
            }
            search_from = blk_end + 1;
            if search_from >= desc_xml.len() {
                break;
            }
        }
    }
    None
}

/// Build the SOAP envelope for an AddPortMapping action.
pub fn add_port_mapping_body(
    service_type: &str,
    external_port: u16,
    proto: Proto,
    internal_port: u16,
    internal_client: Ipv4Addr,
    description: &str,
    lease_secs: u32,
) -> String {
    format!(
        "<?xml version=\"1.0\"?>\r\n\
<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\
<s:Body>\
<u:AddPortMapping xmlns:u=\"{svc}\">\
<NewRemoteHost></NewRemoteHost>\
<NewExternalPort>{ext}</NewExternalPort>\
<NewProtocol>{proto}</NewProtocol>\
<NewInternalPort>{int}</NewInternalPort>\
<NewInternalClient>{client}</NewInternalClient>\
<NewEnabled>1</NewEnabled>\
<NewPortMappingDescription>{desc}</NewPortMappingDescription>\
<NewLeaseDuration>{lease}</NewLeaseDuration>\
</u:AddPortMapping>\
</s:Body>\
</s:Envelope>",
        svc = service_type,
        ext = external_port,
        proto = proto.as_str(),
        int = internal_port,
        client = internal_client,
        desc = description,
        lease = lease_secs,
    )
}

/// Build the SOAP envelope for a GetExternalIPAddress action.
pub fn external_ip_body(service_type: &str) -> String {
    format!(
        "<?xml version=\"1.0\"?>\r\n\
<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\
<s:Body><u:GetExternalIPAddress xmlns:u=\"{svc}\"></u:GetExternalIPAddress></s:Body>\
</s:Envelope>",
        svc = service_type
    )
}

// ---- network (live tested via CLI) ----------------------------------------

/// Our LAN IP as seen toward `gateway` - the value AddPortMapping's
/// NewInternalClient must carry. Uses a connected UDP socket (no packets sent).
async fn local_ip_toward(gateway: IpAddr) -> Result<Ipv4Addr, UpnpError> {
    let sock = UdpSocket::bind(("0.0.0.0", 0))
        .await
        .map_err(|e| UpnpError::Io(e.to_string()))?;
    sock.connect(SocketAddr::new(gateway, 1900))
        .await
        .map_err(|e| UpnpError::Io(e.to_string()))?;
    match sock
        .local_addr()
        .map_err(|e| UpnpError::Io(e.to_string()))?
    {
        SocketAddr::V4(a) => Ok(*a.ip()),
        _ => Err(UpnpError::BadResponse),
    }
}

/// Build an SSDP M-SEARCH request. `mx` (max wait, seconds) is included only for
/// MULTICAST discovery, where it spreads responses over time; a UNICAST search
/// aimed at one gateway omits it (UPnP 1.1 unicast M-SEARCH). `host` is the HOST
/// header value - the multicast group for multicast, the gateway for unicast.
fn msearch_message(host: &str, st: &str, mx: Option<u32>) -> String {
    let mx_line = match mx {
        Some(mx) => format!("MX: {mx}\r\n"),
        None => String::new(),
    };
    format!(
        "M-SEARCH * HTTP/1.1\r\n\
HOST: {host}\r\n\
MAN: \"ssdp:discover\"\r\n\
{mx_line}\
ST: {st}\r\n\r\n"
    )
}

/// The likely default-gateway addresses for the /24 that `local` sits on: the
/// `.1` and `.254` hosts, which cover the overwhelming majority of home
/// gateways. A heuristic, used ONLY because iOS exposes no default-gateway API
/// (the alternative is parsing the BSD routing table via sysctl). `local` itself
/// is never returned.
pub fn gateway_candidates(local: Ipv4Addr) -> Vec<Ipv4Addr> {
    let o = local.octets();
    [1u8, 254]
        .into_iter()
        .map(|host| Ipv4Addr::new(o[0], o[1], o[2], host))
        .filter(|cand| *cand != local)
        .collect()
}

/// The device's own LAN IPv4, learned by asking the OS which source address it
/// would use to reach a public host. No packet is sent - `connect` on a UDP
/// socket only selects the route - so this needs no traffic, just a bound socket.
async fn local_lan_ip() -> Option<Ipv4Addr> {
    let sock = UdpSocket::bind(("0.0.0.0", 0)).await.ok()?;
    sock.connect("8.8.8.8:53").await.ok()?;
    match sock.local_addr().ok()? {
        SocketAddr::V4(a) => Some(*a.ip()),
        _ => None,
    }
}

/// SSDP-discover an IGD: multicast M-SEARCH, take the first response with a
/// LOCATION, GET its description, and pull out a WAN connection service.
pub async fn discover(search_timeout: Duration) -> Result<(WanService, IpAddr), UpnpError> {
    let sock = UdpSocket::bind(("0.0.0.0", 0))
        .await
        .map_err(|e| UpnpError::Io(e.to_string()))?;
    let ssdp: SocketAddr = SSDP_ADDR.parse().unwrap();

    for st in SEARCH_TARGETS {
        let msg = msearch_message(SSDP_ADDR, st, Some(2));
        sock.send_to(msg.as_bytes(), ssdp)
            .await
            .map_err(|e| UpnpError::Io(e.to_string()))?;
    }

    let deadline = tokio::time::Instant::now() + search_timeout;
    let mut buf = vec![0u8; 4096];
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(UpnpError::NoGateway);
        }
        let (n, from) = match timeout(remaining, sock.recv_from(&mut buf)).await {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => return Err(UpnpError::Io(e.to_string())),
            Err(_) => return Err(UpnpError::NoGateway),
        };
        let resp = String::from_utf8_lossy(&buf[..n]);
        let Some(location) = header_value(&resp, "LOCATION") else {
            continue;
        };
        // Fetch + parse the device description; keep searching on failure.
        if let Ok(desc) = http_get(&location).await {
            if let Some(svc) = parse_wan_service(&desc, &location) {
                return Ok((svc, from.ip()));
            }
        }
    }
}

/// Discover an IGD by UNICAST M-SEARCH aimed straight at each candidate gateway,
/// bypassing multicast entirely - which iOS silently drops without the
/// restricted `com.apple.developer.networking.multicast` entitlement (see
/// ios/project.yml). This is what earns a HighID on the device. Returns the
/// first candidate that answers with a usable WAN service; `per` bounds the wait
/// per candidate. Only replies from the queried address are trusted.
pub async fn discover_unicast(
    candidates: &[SocketAddr],
    per: Duration,
) -> Result<(WanService, IpAddr), UpnpError> {
    let sock = UdpSocket::bind(("0.0.0.0", 0))
        .await
        .map_err(|e| UpnpError::Io(e.to_string()))?;
    for gw in candidates {
        let host = format!("{}:{}", gw.ip(), gw.port());
        for st in SEARCH_TARGETS {
            let msg = msearch_message(&host, st, None);
            let _ = sock.send_to(msg.as_bytes(), gw).await;
        }
        let deadline = tokio::time::Instant::now() + per;
        let mut buf = vec![0u8; 4096];
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            let (n, from) = match timeout(remaining, sock.recv_from(&mut buf)).await {
                Ok(Ok(v)) => v,
                _ => break,
            };
            // Trust only the gateway we asked - a stray reply proves nothing.
            if from.ip() != gw.ip() {
                continue;
            }
            let resp = String::from_utf8_lossy(&buf[..n]);
            let Some(location) = header_value(&resp, "LOCATION") else {
                continue;
            };
            if let Ok(desc) = http_get(&location).await {
                if let Some(svc) = parse_wan_service(&desc, &location) {
                    return Ok((svc, from.ip()));
                }
            }
        }
    }
    Err(UpnpError::NoGateway)
}

/// Discover the IGD and map `port` (TCP) to this device, returning the gateway's
/// external IP on success. `lease_secs = 0` requests a permanent mapping.
///
/// Tries MULTICAST discovery first (works on desktop), then falls back to
/// UNICAST M-SEARCH aimed at the inferred gateway - the only route that works on
/// iOS, where multicast is silently dropped. So a real device still earns HighID.
pub async fn map_port(
    port: u16,
    description: &str,
    lease_secs: u32,
) -> Result<Ipv4Addr, UpnpError> {
    let (svc, gateway) = match discover(Duration::from_secs(3)).await {
        Ok(v) => v,
        Err(_) => {
            let candidates = unicast_candidates().await;
            discover_unicast(&candidates, Duration::from_secs(2)).await?
        }
    };
    let client = local_ip_toward(gateway).await?;
    soap_add_mapping(
        &svc,
        port,
        Proto::Tcp,
        port,
        client,
        description,
        lease_secs,
    )
    .await?;
    external_ip(&svc).await
}

/// Map `port` using ONLY the unicast path (skip multicast entirely). Same result
/// as [`map_port`] on iOS, but callable on a desktop to prove the unicast route
/// works against a real gateway before trusting it on a device you cannot debug.
pub async fn map_port_unicast(
    port: u16,
    description: &str,
    lease_secs: u32,
) -> Result<Ipv4Addr, UpnpError> {
    let (svc, gateway) =
        discover_unicast(&unicast_candidates().await, Duration::from_secs(2)).await?;
    let client = local_ip_toward(gateway).await?;
    soap_add_mapping(
        &svc,
        port,
        Proto::Tcp,
        port,
        client,
        description,
        lease_secs,
    )
    .await?;
    external_ip(&svc).await
}

/// The gateway `ip:1900` endpoints to try a unicast M-SEARCH against, inferred
/// from our own LAN address. Empty if we cannot even determine our LAN IP.
async fn unicast_candidates() -> Vec<SocketAddr> {
    match local_lan_ip().await {
        Some(ip) => gateway_candidates(ip)
            .into_iter()
            .map(|gw| SocketAddr::new(IpAddr::V4(gw), 1900))
            .collect(),
        None => Vec::new(),
    }
}

/// POST an AddPortMapping SOAP action.
pub async fn soap_add_mapping(
    svc: &WanService,
    external_port: u16,
    proto: Proto,
    internal_port: u16,
    client: Ipv4Addr,
    description: &str,
    lease_secs: u32,
) -> Result<(), UpnpError> {
    let body = add_port_mapping_body(
        &svc.service_type,
        external_port,
        proto,
        internal_port,
        client,
        description,
        lease_secs,
    );
    let (status, resp) =
        http_soap(&svc.control_url, &svc.service_type, "AddPortMapping", &body).await?;
    if status == 200 {
        Ok(())
    } else {
        Err(UpnpError::Gateway(
            xml_tag(&resp, "errorDescription").unwrap_or_else(|| format!("HTTP {status}")),
        ))
    }
}

/// POST a GetExternalIPAddress SOAP action and parse the address.
pub async fn external_ip(svc: &WanService) -> Result<Ipv4Addr, UpnpError> {
    let body = external_ip_body(&svc.service_type);
    let (status, resp) = http_soap(
        &svc.control_url,
        &svc.service_type,
        "GetExternalIPAddress",
        &body,
    )
    .await?;
    if status != 200 {
        return Err(UpnpError::Gateway(format!("HTTP {status}")));
    }
    xml_tag(&resp, "NewExternalIPAddress")
        .and_then(|s| s.trim().parse().ok())
        .ok_or(UpnpError::BadResponse)
}

// ---- minimal HTTP/1.1 over tokio TCP ---------------------------------------

/// Case-insensitive HTTP-header lookup in a raw response/request string.
fn header_value(text: &str, name: &str) -> Option<String> {
    text.lines()
        .find_map(|l| {
            l.split_once(':')
                .filter(|(k, _)| k.trim().eq_ignore_ascii_case(name))
        })
        .map(|(_, v)| v.trim().to_string())
}

/// Split an HTTP response into (status_code, body).
fn parse_http_response(raw: &str) -> Option<(u16, String)> {
    let (head, body) = raw
        .split_once("\r\n\r\n")
        .or_else(|| raw.split_once("\n\n"))?;
    let status = head
        .lines()
        .next()?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()?;
    Some((status, body.to_string()))
}

async fn http_roundtrip(host: &str, port: u16, request: &str) -> Result<String, UpnpError> {
    let mut stream = timeout(Duration::from_secs(5), TcpStream::connect((host, port)))
        .await
        .map_err(|_| UpnpError::Io("connect timeout".into()))?
        .map_err(|e| UpnpError::Io(e.to_string()))?;
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| UpnpError::Io(e.to_string()))?;
    let mut buf = Vec::new();
    timeout(Duration::from_secs(5), stream.read_to_end(&mut buf))
        .await
        .map_err(|_| UpnpError::Io("read timeout".into()))?
        .map_err(|e| UpnpError::Io(e.to_string()))?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

async fn http_get(url: &str) -> Result<String, UpnpError> {
    let (host, port, path) = split_http_url(url).ok_or(UpnpError::BadResponse)?;
    let req = format!(
        "GET {path} HTTP/1.1\r\nHOST: {host}:{port}\r\nConnection: close\r\nAccept: text/xml\r\n\r\n"
    );
    let raw = http_roundtrip(&host, port, &req).await?;
    let (status, body) = parse_http_response(&raw).ok_or(UpnpError::BadResponse)?;
    if status == 200 {
        Ok(body)
    } else {
        Err(UpnpError::Gateway(format!(
            "HTTP {status} fetching description"
        )))
    }
}

async fn http_soap(
    control_url: &str,
    service_type: &str,
    action: &str,
    body: &str,
) -> Result<(u16, String), UpnpError> {
    let (host, port, path) = split_http_url(control_url).ok_or(UpnpError::BadResponse)?;
    let req = format!(
        "POST {path} HTTP/1.1\r\n\
HOST: {host}:{port}\r\n\
CONTENT-TYPE: text/xml; charset=\"utf-8\"\r\n\
SOAPACTION: \"{service_type}#{action}\"\r\n\
Connection: close\r\n\
CONTENT-LENGTH: {len}\r\n\r\n{body}",
        len = body.len()
    );
    let raw = http_roundtrip(&host, port, &req).await?;
    parse_http_response(&raw).ok_or(UpnpError::BadResponse)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_http_urls() {
        assert_eq!(
            split_http_url("http://192.168.0.1:5000/rootDesc.xml"),
            Some(("192.168.0.1".to_string(), 5000, "/rootDesc.xml".to_string()))
        );
        assert_eq!(
            split_http_url("http://10.0.0.1/desc"),
            Some(("10.0.0.1".to_string(), 80, "/desc".to_string()))
        );
        assert_eq!(
            split_http_url("http://host"),
            Some(("host".to_string(), 80, "/".to_string()))
        );
        assert_eq!(split_http_url("ftp://x/y"), None);
    }

    #[test]
    fn extracts_xml_tags_namespace_insensitive() {
        let xml = "<root><a:NewExternalIPAddress>203.0.113.5</a:NewExternalIPAddress></root>";
        assert_eq!(
            xml_tag(xml, "NewExternalIPAddress"),
            Some("203.0.113.5".into())
        );
        assert_eq!(xml_tag("<x>hi</x>", "x"), Some("hi".into()));
        assert_eq!(xml_tag("<x>hi</x>", "y"), None);
        // A closing/pi tag before the real one must not confuse the scan.
        assert_eq!(
            xml_tag("<?xml v?><outer><Z>ok</Z></outer>", "Z"),
            Some("ok".into())
        );
    }

    #[test]
    fn resolves_relative_control_urls() {
        let base = "http://192.168.0.1:5000/rootDesc.xml";
        assert_eq!(
            resolve_url(base, "/ctl/IPConn"),
            "http://192.168.0.1:5000/ctl/IPConn"
        );
        assert_eq!(
            resolve_url(base, "ctl/IPConn"),
            "http://192.168.0.1:5000/ctl/IPConn"
        );
        assert_eq!(
            resolve_url(base, "http://192.168.0.1:5000/abs"),
            "http://192.168.0.1:5000/abs"
        );
    }

    #[test]
    fn finds_wan_service_and_control_url() {
        // Two services; only the WANIPConnection one is a valid target.
        let desc = "<root><device><serviceList>\
<service><serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType>\
<controlURL>/ignore</controlURL></service>\
<service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>\
<controlURL>/ctl/IPConn</controlURL></service>\
</serviceList></device></root>";
        let svc = parse_wan_service(desc, "http://192.168.0.1:5000/rootDesc.xml").unwrap();
        assert_eq!(svc.control_url, "http://192.168.0.1:5000/ctl/IPConn");
        assert_eq!(
            svc.service_type,
            "urn:schemas-upnp-org:service:WANIPConnection:1"
        );
    }

    #[test]
    fn no_wan_service_returns_none() {
        let desc = "<root><service><serviceType>urn:schemas-upnp-org:service:WLANConfiguration:1\
</serviceType><controlURL>/x</controlURL></service></root>";
        assert!(parse_wan_service(desc, "http://192.168.0.1/d").is_none());
    }

    #[test]
    fn add_port_mapping_body_is_wellformed_soap() {
        let body = add_port_mapping_body(
            "urn:schemas-upnp-org:service:WANIPConnection:1",
            4662,
            Proto::Tcp,
            4662,
            Ipv4Addr::new(10, 0, 0, 33),
            "padMule",
            0,
        );
        assert!(body.contains(
            "<u:AddPortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">"
        ));
        assert!(body.contains("<NewExternalPort>4662</NewExternalPort>"));
        assert!(body.contains("<NewProtocol>TCP</NewProtocol>"));
        assert!(body.contains("<NewInternalClient>10.0.0.33</NewInternalClient>"));
        assert!(body.contains("<NewLeaseDuration>0</NewLeaseDuration>"));
    }

    #[test]
    fn parses_http_status_and_body() {
        let raw = "HTTP/1.1 200 OK\r\nServer: x\r\nContent-Length: 2\r\n\r\nhi";
        assert_eq!(parse_http_response(raw), Some((200, "hi".to_string())));
        let err = "HTTP/1.1 500 Internal Server Error\r\n\r\n<fault/>";
        assert_eq!(
            parse_http_response(err),
            Some((500, "<fault/>".to_string()))
        );
    }

    #[test]
    fn header_lookup_is_case_insensitive() {
        let resp = "HTTP/1.1 200 OK\r\nLOCATION: http://192.168.0.1:5000/d.xml\r\n\r\n";
        assert_eq!(
            header_value(resp, "location"),
            Some("http://192.168.0.1:5000/d.xml".into())
        );
        assert_eq!(header_value(resp, "missing"), None);
    }

    #[test]
    fn parses_external_ip_from_soap_response() {
        // Shape of a real GetExternalIPAddress reply.
        let resp = "<s:Envelope><s:Body><u:GetExternalIPAddressResponse>\
<NewExternalIPAddress>203.0.113.5</NewExternalIPAddress>\
</u:GetExternalIPAddressResponse></s:Body></s:Envelope>";
        assert_eq!(
            xml_tag(resp, "NewExternalIPAddress")
                .unwrap()
                .parse::<Ipv4Addr>()
                .unwrap(),
            Ipv4Addr::new(203, 0, 113, 5)
        );
    }

    #[test]
    fn gateway_candidates_are_the_dot_one_and_dot_254_of_the_24() {
        assert_eq!(
            gateway_candidates(Ipv4Addr::new(10, 0, 0, 33)),
            vec![Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 254)]
        );
        // The device's own address is never proposed as its gateway.
        assert_eq!(
            gateway_candidates(Ipv4Addr::new(192, 168, 1, 1)),
            vec![Ipv4Addr::new(192, 168, 1, 254)]
        );
        assert_eq!(
            gateway_candidates(Ipv4Addr::new(192, 168, 0, 254)),
            vec![Ipv4Addr::new(192, 168, 0, 1)]
        );
    }

    #[test]
    fn unicast_msearch_omits_mx_and_targets_the_gateway() {
        let uni = msearch_message("192.168.1.1:1900", "urn:x:1", None);
        assert!(uni.contains("HOST: 192.168.1.1:1900\r\n"));
        assert!(uni.contains("MAN: \"ssdp:discover\"\r\n"));
        assert!(uni.contains("ST: urn:x:1\r\n"));
        assert!(!uni.contains("MX:"), "unicast M-SEARCH must not send MX");

        // Multicast form still carries MX (it spreads responses over time).
        let multi = msearch_message(SSDP_ADDR, "urn:x:1", Some(2));
        assert!(multi.contains("MX: 2\r\n"));
        assert!(multi.contains(&format!("HOST: {SSDP_ADDR}\r\n")));
    }

    // The unicast discovery path end-to-end over loopback: a mock UDP "gateway"
    // that answers M-SEARCH with a LOCATION, and a mock TCP server that serves
    // the device description there. Proves everything except talking to a real
    // IGD - the piece that earns HighID on iOS, where multicast is impossible.
    #[tokio::test]
    async fn discover_unicast_against_a_mock_gateway() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        // Mock IGD description server (the LOCATION target).
        let http = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_addr = http.local_addr().unwrap();
        let location = format!("http://{http_addr}/rootDesc.xml");
        let desc = "<root><device><serviceList>\
<service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>\
<controlURL>/ctl</controlURL></service></serviceList></device></root>"
            .to_string();
        tokio::spawn(async move {
            let (mut s, _) = http.accept().await.unwrap();
            let mut b = vec![0u8; 4096];
            let _ = s.read(&mut b).await.unwrap();
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                desc.len(),
                desc
            );
            s.write_all(resp.as_bytes()).await.unwrap();
            s.shutdown().await.unwrap();
        });

        // Mock UDP gateway: answers the first M-SEARCH with the LOCATION.
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let gw_addr = udp.local_addr().unwrap();
        let loc = location.clone();
        tokio::spawn(async move {
            let mut b = vec![0u8; 2048];
            let (n, from) = udp.recv_from(&mut b).await.unwrap();
            assert!(String::from_utf8_lossy(&b[..n]).starts_with("M-SEARCH"));
            let reply = format!(
                "HTTP/1.1 200 OK\r\nLOCATION: {loc}\r\n\
ST: urn:schemas-upnp-org:service:WANIPConnection:1\r\n\r\n"
            );
            udp.send_to(reply.as_bytes(), from).await.unwrap();
        });

        let (svc, gw) = discover_unicast(&[gw_addr], Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(gw, gw_addr.ip());
        assert_eq!(
            svc.service_type,
            "urn:schemas-upnp-org:service:WANIPConnection:1"
        );
        assert_eq!(svc.control_url, format!("http://{http_addr}/ctl"));
    }

    // Integration test of the real HTTP+SOAP network path (everything except SSDP
    // multicast, which needs a live gateway) against a mock IGD over a loopback
    // socket. This exercises http_get, parse_wan_service, http_soap and the
    // response parsing end-to-end - the framing most likely to hide a bug.
    #[tokio::test]
    async fn http_soap_flow_against_a_mock_igd() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let base = format!("http://{addr}/rootDesc.xml");

        // Mock IGD: GET -> device description (control URL points back at us);
        // POST AddPortMapping -> 200 empty; POST GetExternalIPAddress -> 200 + IP.
        let ctl = format!("http://{addr}/ctl");
        let desc = "<root><device><serviceList>\
<service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>\
<controlURL>/ctl</controlURL></service></serviceList></device></root>"
            .to_string();
        tokio::spawn(async move {
            for _ in 0..3 {
                let (mut s, _) = listener.accept().await.unwrap();
                let mut buf = vec![0u8; 8192];
                let n = s.read(&mut buf).await.unwrap();
                let req = String::from_utf8_lossy(&buf[..n]);
                let body = if req.starts_with("GET") {
                    desc.clone()
                } else if req.contains("GetExternalIPAddress") {
                    "<s:Envelope><s:Body><u:GetExternalIPAddressResponse>\
<NewExternalIPAddress>203.0.113.5</NewExternalIPAddress>\
</u:GetExternalIPAddressResponse></s:Body></s:Envelope>"
                        .to_string()
                } else {
                    "<s:Envelope><s:Body><u:AddPortMappingResponse></u:AddPortMappingResponse>\
</s:Body></s:Envelope>"
                        .to_string()
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                s.write_all(resp.as_bytes()).await.unwrap();
                s.shutdown().await.unwrap();
            }
        });

        // GET + parse the description.
        let xml = http_get(&base).await.unwrap();
        let svc = parse_wan_service(&xml, &base).unwrap();
        assert_eq!(svc.control_url, ctl);

        // AddPortMapping over a real socket.
        soap_add_mapping(
            &svc,
            4662,
            Proto::Tcp,
            4662,
            Ipv4Addr::new(10, 0, 0, 33),
            "padMule",
            0,
        )
        .await
        .unwrap();

        // GetExternalIPAddress round-trips + parses.
        let ip = external_ip(&svc).await.unwrap();
        assert_eq!(ip, Ipv4Addr::new(203, 0, 113, 5));
    }
}
