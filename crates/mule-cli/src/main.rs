//! mule-cli: the headless dev + live-network harness for the engine on Linux.
//! 20 subcommands across the whole surface: server login + lifecycle (login,
//! login-any, listen), hashing + serving (hash-file, serve-file), peer
//! transfer + diagnostics (peer-download, peer-probe, sec-ident), the full
//! Kad surface (kad-bootstrap, kad-search, kad-fetch, kad-keyword), links
//! (link), port mapping (upnp, upnp-unicast, upnp-query, upnp-unmap, natpmp),
//! and the completion-optimized fetchers (search-download, fetch-complete).
//! Run with no arguments for usage; the match in `main` is the authoritative
//! list.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::time::Duration;

use mule_engine::peer::HelloInfo;
use mule_engine::search::{
    build_global_search_udp, build_search_request, parse_global_search_res, parse_search_result,
    SearchParams, OP_GLOBSEARCHRES,
};
use mule_engine::server_messages::{LoginRequest, DEFAULT_SERVER_FLAGS};
use mule_engine::sources::{build_callback_request, build_get_sources, parse_found_sources};
use mule_engine::{
    catalog, connect_peer, connect_peer_obf, connect_server, download_file, download_from_peer,
    download_from_peer_at, fetch_from_sources, login_handshake, obf_accept, peer_handshake_inbound,
    serve, Download, FramedStream, Identity, KadNode, ManagerConfig, ObfDetect, PartStore,
    SecIdentCtx, ServedFile, ServerEvent, ServerLink, ServerState, SourceRegistry,
};
use mule_files::{read_nodes_dat, read_server_met};
use mule_proto::{ed2k_hash, Kad128};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::time::timeout;

/// A demo userhash carrying the eMule marker bytes (byte[5]=14, byte[14]=111).
/// A real client persists a random one; this is only for the smoke test.
fn demo_user_hash() -> [u8; 16] {
    let mut h = [0x42u8; 16];
    h[5] = 14;
    h[14] = 111;
    h
}

fn demo_login() -> LoginRequest {
    LoginRequest {
        user_hash: demo_user_hash(),
        client_id: 0,
        tcp_port: 4662,
        nick: "padMule".to_string(),
        server_flags: DEFAULT_SERVER_FLAGS,
    }
}

/// Decode a server.met IP uint32 (first octet in the low byte) to an Ipv4Addr.
fn ip_from_met_u32(ip: u32) -> Ipv4Addr {
    Ipv4Addr::new(
        ip as u8,
        (ip >> 8) as u8,
        (ip >> 16) as u8,
        (ip >> 24) as u8,
    )
}

/// Print server events from `rx` until the channel closes.
fn spawn_event_printer(mut rx: mpsc::Receiver<ServerEvent>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(ev) = rx.recv().await {
            match ev {
                ServerEvent::State(s) => println!("  [state] {s:?}"),
                ServerEvent::Message(m) => println!("  [message] {m}"),
                ServerEvent::Status { users, files } => {
                    println!("  [status] {users} users, {files} files")
                }
                ServerEvent::ServerList(list) => {
                    println!("  [serverlist] {} servers", list.len())
                }
            }
        }
    })
}

async fn cmd_login(addr: SocketAddr) {
    println!("connecting to {addr} ...");
    let (tx, rx) = mpsc::channel(64);
    let printer = spawn_event_printer(rx);
    let mut link = ServerLink::new(addr, demo_login(), tx);

    match timeout(Duration::from_secs(10), link.connect()).await {
        Ok(Ok(state)) => {
            println!("login result: {state:?}");
            // Demonstrate the lifecycle.
            println!("pausing (simulating background) ...");
            link.pause().await;
            println!("resuming ...");
            match timeout(Duration::from_secs(10), link.resume()).await {
                Ok(Ok(s)) => println!("resume result: {s:?}"),
                Ok(Err(e)) => println!("resume failed: {e}"),
                Err(_) => println!("resume timed out"),
            }
            link.disconnect().await;
        }
        Ok(Err(e)) => println!("login failed: {e}"),
        Err(_) => println!("login timed out"),
    }
    drop(link);
    let _ = printer.await;
}

/// global-search <server.met|host:port> <keyword>: fan a GLOBAL server UDP
/// search across the serverlist (or one server, for testing). Each server's UDP
/// port is its TCP port + 4 (the eD2k landmine); the request is OP_GLOBSEARCHREQ
/// carrying the normal search tree, and OP_GLOBSEARCHRES replies (one chained
/// record set each) are collected - honoring only IPs we actually asked
/// (anti-spoof), deduped by hash.
async fn cmd_global_search(target: &str, keyword: &str) {
    use std::collections::HashSet;
    use std::sync::Arc;
    use tokio::net::UdpSocket;
    use tokio::sync::Mutex;

    // A `host:port` targets one server (its TCP port); otherwise it is a server.met.
    let servers: Vec<(Ipv4Addr, u16)> = if let Ok(SocketAddr::V4(sa)) = target.parse() {
        vec![(*sa.ip(), sa.port())]
    } else {
        match std::fs::read(target)
            .ok()
            .and_then(|b| read_server_met(&b).ok())
        {
            Some(m) => m
                .servers
                .iter()
                .filter(|s| s.ip != 0 && s.port != 0)
                .map(|s| (ip_from_met_u32(s.ip), s.port))
                .collect(),
            None => {
                eprintln!("cannot read a server.met or a host:port from: {target}");
                return;
            }
        }
    };
    let params = SearchParams {
        keyword: keyword.to_string(),
        ..Default::default()
    };
    let pkt = build_global_search_udp(&params);
    // UDP wire = [protocol][opcode][payload] (2-byte header, no length field).
    let mut req = vec![pkt.protocol, pkt.opcode];
    req.extend_from_slice(&pkt.payload);

    let sock = match UdpSocket::bind(("0.0.0.0", 0u16)).await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            eprintln!("udp bind failed: {e}");
            return;
        }
    };
    let asked: Arc<Mutex<HashSet<Ipv4Addr>>> = Arc::new(Mutex::new(HashSet::new()));
    let hits: Arc<Mutex<Vec<(Ipv4Addr, mule_engine::search::SearchResultFile)>>> =
        Arc::new(Mutex::new(Vec::new()));

    let (rsock, rasked, rhits) = (Arc::clone(&sock), Arc::clone(&asked), Arc::clone(&hits));
    let recv = tokio::spawn(async move {
        let mut buf = [0u8; 16 * 1024];
        loop {
            let (n, src) = match rsock.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => break,
            };
            if n < 2 {
                continue;
            }
            let IpAddr::V4(sip) = src.ip() else { continue };
            // Anti-spoof: only accept a reply from a server we sent a request to.
            if !rasked.lock().await.contains(&sip) {
                continue;
            }
            // eMule/aMule drop any UDP datagram whose protocol byte is not 0xE3
            // before dispatch (UDPSocket.cpp:181; ServerUDPSocket.cpp:92) - server
            // UDP is never zlib-packed (that is a TCP-only path), so only a plain
            // OP_GLOBSEARCHRES is a valid reply.
            let (prot, op, payload) = (buf[0], buf[1], &buf[2..n]);
            let files = if prot == mule_proto::PROT_EDONKEY && op == OP_GLOBSEARCHRES {
                parse_global_search_res(payload).unwrap_or_default()
            } else {
                Vec::new()
            };
            let mut h = rhits.lock().await;
            for f in files {
                if !h.iter().any(|(_, x)| x.hash == f.hash) {
                    h.push((sip, f));
                }
            }
        }
    });

    let mut sent = 0usize;
    for (ip, tcp_port) in &servers {
        // UDP port = TCP port + 4 (the landmine); guard the u16 add so a corrupt
        // server.met entry near 65535 skips instead of overflowing.
        let Some(udp_port) = tcp_port.checked_add(4) else {
            eprintln!("   skipping {ip}:{tcp_port}: no valid +4 UDP port");
            continue;
        };
        asked.lock().await.insert(*ip);
        let dst = SocketAddr::new(IpAddr::V4(*ip), udp_port);
        match sock.send_to(&req, dst).await {
            Ok(_) => {
                println!("-> OP_GLOBSEARCHREQ to {dst} (server {ip}:{tcp_port})");
                sent += 1;
            }
            Err(e) => eprintln!("   send to {dst} failed: {e}"),
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    println!("sent {sent} request(s); collecting replies ...");
    tokio::time::sleep(Duration::from_secs(4)).await;
    recv.abort();

    let h = hits.lock().await;
    println!("=== {} unique file(s) via global UDP search ===", h.len());
    for (src, f) in h.iter() {
        let name = f
            .tags
            .iter()
            .find_map(|t| match (&t.name, &t.value) {
                (mule_proto::TagName::Id(0x01), mule_proto::TagValue::Str(s)) => {
                    Some(String::from_utf8_lossy(s).into_owned())
                }
                _ => None,
            })
            .unwrap_or_default();
        println!("  {name}  hash={} (from server {src})", hex16(&f.hash));
    }
}

async fn cmd_login_any(met_path: &str) {
    let bytes = match std::fs::read(met_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("cannot read {met_path}: {e}");
            return;
        }
    };
    let met = match read_server_met(&bytes) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("cannot parse server.met: {e}");
            return;
        }
    };
    println!("{} servers in {met_path}", met.servers.len());

    for (i, srv) in met.servers.iter().enumerate() {
        let addr = SocketAddr::new(IpAddr::V4(ip_from_met_u32(srv.ip)), srv.port);
        print!("[{}/{}] {addr} ... ", i + 1, met.servers.len());
        let (tx, rx) = mpsc::channel(64);
        let printer = spawn_event_printer(rx);
        let mut link = ServerLink::new(addr, demo_login(), tx);
        match timeout(Duration::from_secs(8), link.connect()).await {
            Ok(Ok(ServerState::Connected { id, low_id })) => {
                println!("CONNECTED (id={id:#x}, low_id={low_id})");
                link.disconnect().await;
                drop(link);
                let _ = printer.await;
                println!("done: logged in successfully.");
                return;
            }
            Ok(Ok(other)) => println!("{other:?}"),
            Ok(Err(e)) => println!("failed: {e}"),
            Err(_) => println!("timeout"),
        }
        drop(link);
        let _ = printer.await;
    }
    println!("no server accepted a login.");
}

/// Bind an inbound peer listener and report every connection. Any TCP connect
/// that reaches us (e.g. an external port-checker, a server HighID callback, or
/// a real peer) proves the port forward works; a full peer then completes the
/// hello handshake.
async fn cmd_listen(port: u16) {
    let bind = format!("0.0.0.0:{port}");
    let listener = match TcpListener::bind(&bind).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("cannot bind {bind}: {e}");
            return;
        }
    };
    println!("listening for inbound peers on {bind}");
    println!("(with WSL mirrored mode this is reachable on the Windows host IP)");
    println!("validate the forward: point an external port checker at <public-ip>:{port}");
    let me = HelloInfo::baseline(demo_user_hash(), 0, port, 4672, "padMule");
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                println!("inbound connection from {peer}");
                let me = me.clone();
                tokio::spawn(async move {
                    let mut fs = FramedStream::new(stream);
                    match timeout(
                        Duration::from_secs(10),
                        peer_handshake_inbound(&mut fs, &me),
                    )
                    .await
                    {
                        Ok(Ok(ph)) => println!(
                            "  handshake OK: peer hash={} port={}",
                            hex16(&ph.user_hash),
                            ph.tcp_port
                        ),
                        Ok(Err(e)) => {
                            println!(
                                "  connection reached us (forward works); handshake ended: {e}"
                            )
                        }
                        Err(_) => {
                            println!("  connection reached us (forward works); handshake timed out")
                        }
                    }
                });
            }
            Err(e) => {
                eprintln!("accept error: {e}");
                break;
            }
        }
    }
}

fn hex16(b: &[u8; 16]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn parse_hex16(s: &str) -> Option<[u8; 16]> {
    let s = s.trim();
    if s.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// Differential test of SECURE IDENTIFICATION against a real peer (amuled).
/// Connects (optionally obfuscated), advertises secure-ident support in the
/// hello, runs the mutual RSA challenge/response, and reports whether we verified
/// the peer's identity (and completed our half so the peer can verify us).
async fn cmd_sec_ident(addr: SocketAddr, obf: Option<[u8; 16]>) {
    use mule_engine::peer::baseline_misc_options1;
    use mule_engine::secure_ident::{OP_PUBLICKEY, OP_SECIDENTSTATE, OP_SIGNATURE};
    use mule_engine::{Identity, SecureIdentSession};

    let id = Identity::generate();
    let mut me = HelloInfo::baseline(demo_user_hash(), 0, 4662, 4672, "padMule");
    me.misc_options1 = baseline_misc_options1(1); // advertise SecureIdent v1

    let (peer, mut fs) = match match obf {
        Some(th) => connect_peer_obf(addr, &me, &th).await,
        None => connect_peer(addr, &me).await,
    } {
        Ok(v) => v,
        Err(e) => {
            eprintln!("connect/handshake failed: {e}");
            return;
        }
    };
    let peer_secident = peer.capabilities().map(|c| c.sec_ident).unwrap_or(0);
    println!(
        "handshake OK with {} (peer advertises secure-ident v{}){}",
        hex16(&peer.user_hash),
        peer_secident,
        if fs.is_obfuscated() {
            " [obfuscated]"
        } else {
            ""
        }
    );
    if peer_secident == 0 {
        eprintln!("peer does not support secure identification");
        return;
    }

    let mut session = SecureIdentSession::new(&id);
    if let Err(e) = fs.write_packet(&session.start()).await {
        eprintln!("failed to send our challenge: {e}");
        return;
    }
    loop {
        match timeout(Duration::from_secs(15), fs.read_packet_unpacked()).await {
            Ok(Ok(p)) => {
                if matches!(p.opcode, OP_SECIDENTSTATE | OP_PUBLICKEY | OP_SIGNATURE) {
                    println!(
                        "  <- secure-ident opcode=0x{:02x} len={} bytes={}",
                        p.opcode,
                        p.payload.len(),
                        p.payload
                            .iter()
                            .map(|b| format!("{b:02x}"))
                            .collect::<String>()
                    );
                    match session.on_packet(&id, p.opcode, &p.payload) {
                        Ok(replies) => {
                            for r in replies {
                                let _ = fs.write_packet(&r).await;
                            }
                        }
                        Err(e) => {
                            eprintln!("  bad secure-ident packet: {e:?}");
                            return;
                        }
                    }
                    if session.is_complete() {
                        break;
                    }
                }
                // ignore any non-secure-ident traffic
            }
            Ok(Err(e)) => {
                eprintln!("connection ended: {e}");
                break;
            }
            Err(_) => {
                eprintln!("timed out waiting for secure-ident packets");
                break;
            }
        }
    }

    if session.peer_verified() {
        println!("OK: the peer PASSED secure identification (it proved it owns its userhash)");
    } else {
        println!("FAILED: the peer did not pass secure identification");
    }
}

/// Diagnostic: send a raw OP_HELLO, then dump EVERY packet the peer sends back
/// (protocol/opcode/len, unfiltered, in order) so we can see exactly what a real
/// aMule does - including the order of OP_HELLOANSWER vs OP_EMULEINFO and any
/// secure-ident packets - and when it closes. Optionally sends file requests.
async fn cmd_peer_probe(addr: SocketAddr, hash: [u8; 16]) {
    use mule_engine::peer::build_hello;
    use mule_engine::transfer::{
        build_request_filename_ext, build_set_req_file_id, build_start_upload_req,
    };
    let stream = match tokio::net::TcpStream::connect(addr).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("tcp connect failed: {e}");
            return;
        }
    };
    let mut fs = FramedStream::new(stream);
    let me = HelloInfo::baseline(demo_user_hash(), 0, 4662, 4672, "padMule");
    println!("-> OP_HELLO");
    if let Err(e) = fs.write_packet(&build_hello(&me)).await {
        eprintln!("write hello failed: {e}");
        return;
    }

    let mut seen_helloanswer = false;
    let mut sent_requests = false;
    let mut sent_upload = false;
    loop {
        match timeout(Duration::from_secs(6), fs.read_packet()).await {
            Ok(Ok(p)) => {
                println!(
                    "  <- proto=0x{:02x} opcode=0x{:02x} len={}",
                    p.protocol,
                    p.opcode,
                    p.payload.len()
                );
                if p.opcode == 0x4C {
                    seen_helloanswer = true; // OP_HELLOANSWER
                }
                // Once the handshake answer is in, send the file request.
                if seen_helloanswer && !sent_requests {
                    sent_requests = true;
                    println!("  -> OP_REQUESTFILENAME + OP_SETREQFILEID");
                    let _ = fs.write_packet(&build_request_filename_ext(&hash)).await;
                    let _ = fs.write_packet(&build_set_req_file_id(&hash)).await;
                }
                if p.opcode == 0x50 && !sent_upload {
                    sent_upload = true; // OP_FILESTATUS -> ask for a slot
                    println!("  -> OP_STARTUPLOADREQ");
                    let _ = fs.write_packet(&build_start_upload_req(&hash)).await;
                }
            }
            Ok(Err(e)) => {
                println!("  connection ended: {e}");
                return;
            }
            Err(_) => {
                println!("  (no packet for 6s - stopping)");
                return;
            }
        }
    }
}

/// Print a file's ed2k hash and size, so the differential-test script can ask a
/// peer for exactly this file.
fn cmd_hash_file(path: &str) {
    match std::fs::read(path) {
        Ok(data) => println!("{} {}", hex16(&ed2k_hash(&data)), data.len()),
        Err(e) => eprintln!("cannot read {path}: {e}"),
    }
}

/// The eD2k per-part hashset (MD4 of each PARTSIZE chunk), including the trailing
/// empty-MD4 sentinel for an exact multiple of PARTSIZE - the same rule
/// `ed2k_hash` folds, so `md4(concat(parts)) == file hash`.
fn part_hashes(data: &[u8]) -> Vec<[u8; 16]> {
    use mule_proto::{md4, PARTSIZE};
    let ps = PARTSIZE as usize;
    let mut hs: Vec<[u8; 16]> = data.chunks(ps).map(md4).collect();
    if data.is_empty() || data.len().is_multiple_of(ps) {
        hs.push(md4(b""));
    }
    hs
}

/// Serve `path` to inbound peers on `port` (padMule as the UPLOADER). Used for
/// the reverse differential test: a real amuled downloads this file from us.
/// Serves every connection until killed.
async fn cmd_serve_file(port: u16, path: &str) {
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("cannot read {path}: {e}");
            return;
        }
    };
    let hash = ed2k_hash(&data);
    // A single-part file needs no hashset; a multi-part one does.
    let phs = if data.len() as u64 > mule_proto::PARTSIZE {
        part_hashes(&data)
    } else {
        Vec::new()
    };
    let name = Path::new(path)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file.bin".into());

    let listener = match TcpListener::bind(("0.0.0.0", port)).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("cannot bind 0.0.0.0:{port}: {e}");
            return;
        }
    };
    println!(
        "serving {} ({} bytes, {} part-hashes) as {} on 0.0.0.0:{port}",
        hex16(&hash),
        data.len(),
        phs.len(),
        name
    );
    println!(
        "ed2k link for a downloader:\ned2k://|file|{}|{}|{}|/|sources,127.0.0.1:{port}|/",
        name,
        data.len(),
        hex16(&hash)
    );

    let me = HelloInfo::baseline(demo_user_hash(), 0, port, 4672, "padMule");
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("accept error: {e}");
                return;
            }
        };
        println!("inbound peer {peer}");
        let me = me.clone();
        let phs = phs.clone();
        let data = data.clone();
        let name = name.clone();
        tokio::spawn(async move {
            let mut stream = stream;
            // Auto-detect obfuscation (real aMule requests it by default) keyed
            // off our own userhash, then run the hello handshake.
            let mut fs = match obf_accept(&mut stream, &me.user_hash).await {
                Ok(ObfDetect::Obfuscated(c)) => {
                    println!("  [obfuscated]");
                    FramedStream::obfuscated(stream, *c)
                }
                Ok(ObfDetect::Plaintext { first }) => {
                    FramedStream::plaintext_with_prefix(stream, &[first])
                }
                Err(e) => {
                    eprintln!("  obf detect failed: {e}");
                    return;
                }
            };
            if let Err(e) = peer_handshake_inbound(&mut fs, &me).await {
                eprintln!("  handshake failed: {e}");
                return;
            }
            let f = ServedFile {
                hash,
                name: name.as_bytes(),
                data: &data,
                part_hashes: &phs,
                available: None,
            };
            match serve(&mut fs, &f).await {
                Ok(()) => println!("  peer {peer} done"),
                Err(e) => eprintln!("  serve ended: {e}"),
            }
        });
    }
}

/// Download `hash` (`size` bytes) from a single peer at `addr` into `out`, driving
/// the real multi-source path (disk-backed PartStore, hashset exchange, block
/// receive incl. compressed parts, and verification against the peer's hashset).
/// This is the padMule side of the amuled differential test.
async fn cmd_peer_download(
    addr: SocketAddr,
    hash: [u8; 16],
    size: u64,
    out: &str,
    obf_target: Option<[u8; 16]>,
) {
    println!(
        "connecting to peer {addr} for {} ({size} bytes){} ...",
        hex16(&hash),
        if obf_target.is_some() {
            " [obfuscated]"
        } else {
            ""
        }
    );
    // Advertise client id 0 (LowID/unregistered): we have no server-assigned
    // HighID, and a non-LowID id that does not match our real source IP trips
    // aMule's ParanoidFilter (ClientTCPSocket.cpp:300). Advertise SecureIdent so
    // the peer initiates secure-ident toward us - this makes the differential
    // test exercise the real exchange against a live aMule/eMule.
    let me = HelloInfo::baseline(demo_user_hash(), 0, 4662, 4672, "padMule").with_secident();
    let connect = async {
        match obf_target {
            Some(th) => connect_peer_obf(addr, &me, &th).await,
            None => connect_peer(addr, &me).await,
        }
    };
    let (peer, mut fs) = match connect.await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("peer connect/handshake failed: {e}");
            return;
        }
    };
    println!(
        "handshake OK with {} (port {}){}",
        hex16(&peer.user_hash),
        peer.tcp_port,
        if fs.is_obfuscated() {
            " [obfuscated session]"
        } else {
            ""
        }
    );

    let dir = Path::new(out).parent().unwrap_or(Path::new("."));
    let name = Path::new(out)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "download.bin".into());
    let store = match PartStore::create(dir, 1, hash, size, name.as_bytes()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("cannot create .part in {}: {e}", dir.display());
            return;
        }
    };
    let dl = Download::new(store);

    // Register the source so a secure-ident verification (and any rating/comment)
    // is recorded against it - the engine's fetch_one does this; the CLI must too.
    let low_id = peer.client_id < 0x0100_0000;
    dl.note_source(peer.client_software(), addr, obf_target.is_some(), low_id)
        .await;

    // Secure-ident: carry a fresh RSA identity and run the exchange inline. The
    // peer initiates because we advertised support; we also proactively verify it.
    let identity = std::sync::Arc::new(Identity::generate());
    let peer_supports = peer
        .capabilities()
        .map(|c| c.sec_ident != 0)
        .unwrap_or(false);
    let sec = Some(SecIdentCtx {
        identity,
        peer_supports,
    });

    match timeout(
        Duration::from_secs(120),
        download_from_peer_at(&mut fs, &dl, false, Some(addr), sec),
    )
    .await
    {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            eprintln!("download failed: {e:?}");
            return;
        }
        Err(_) => {
            eprintln!("download timed out (missing {} bytes)", dl.missing().await);
            return;
        }
    }

    // Report whether we cryptographically verified the source's identity.
    let verified = dl.sources().await.iter().any(|s| s.verified);
    println!("source identity verified (secure-ident): {verified}");

    if !dl.is_complete().await {
        eprintln!(
            "peer ran out of blocks; still missing {} bytes",
            dl.missing().await
        );
        return;
    }
    if let Err(e) = dl.verify_ready_parts().await {
        eprintln!("verification error: {e}");
        return;
    }
    let mut store = match dl.into_store().await {
        Some(s) => s,
        None => {
            eprintln!("internal: could not reclaim the part store");
            return;
        }
    };
    let corrupt = store.pf.corrupted().to_vec();
    if !corrupt.is_empty() {
        eprintln!("FAILED verification against the peer hashset: corrupt parts {corrupt:?}");
        return;
    }
    // Sanity-check the assembled bytes' ed2k hash before moving the file.
    let assembled = (0..mule_engine::data_part_count(size))
        .map(|p| store.read_part(p))
        .collect::<std::io::Result<Vec<_>>>();
    match assembled {
        Ok(parts) => {
            let whole: Vec<u8> = parts.concat();
            let got = ed2k_hash(&whole);
            if got != hash {
                eprintln!(
                    "FAILED: assembled ed2k hash {} != requested {}",
                    hex16(&got),
                    hex16(&hash)
                );
                return;
            }
        }
        Err(e) => {
            eprintln!("cannot read back parts: {e}");
            return;
        }
    }
    if let Err(e) = store.finish(Path::new(out)) {
        eprintln!("cannot move finished file to {out}: {e}");
        return;
    }
    println!("OK: downloaded + verified {size} bytes -> {out} (hash matches, hashset verified)");
}

/// Wave-6 live gate: load a nodes.dat, then send obfuscated BOOTSTRAP_REQs to
/// its contacts until one answers - proving the Kad UDP framing, obfuscation,
/// and message codecs against a real node. On success, follow with a HELLO.
async fn cmd_kad_bootstrap(nodes_path: &str) {
    let bytes = match std::fs::read(nodes_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("cannot read {nodes_path}: {e}");
            return;
        }
    };
    let parsed = match read_nodes_dat(&bytes) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("bad nodes.dat: {e:?}");
            return;
        }
    };
    println!(
        "loaded {} contacts (nodes.dat v{})",
        parsed.contacts.len(),
        parsed.version
    );
    // Only Kad2 contacts (version >= 2) are reachable with this protocol.
    let contacts: Vec<_> = parsed
        .contacts
        .into_iter()
        .filter(|c| c.version >= 2)
        .collect();

    let bind: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 4672);
    let mut node = match KadNode::bind(bind, 4662).await {
        Ok(n) => n,
        Err(e) => {
            eprintln!("bind failed: {e}");
            return;
        }
    };
    println!(
        "bound Kad UDP on {bind}; our KadID {:08x?}",
        node.kad_id().words()
    );
    println!(
        "trying BOOTSTRAP_REQ against up to {} contacts...",
        contacts.len().min(40)
    );

    match node
        .bootstrap_any(&contacts, Duration::from_millis(1200), 40)
        .await
    {
        Ok((i, res)) => {
            println!(
                "BOOTSTRAP_RES from contact #{i}: responder version {}, tcp {}, {} contacts returned",
                res.version,
                res.tcp_port,
                res.contacts.len()
            );
            println!("routing table now holds {} contacts", node.contacts_known());
            // Follow up with a HELLO to the same contact to exercise 6b's HELLO
            // path (request an ACK).
            let responder = &contacts[i];
            match node.hello(responder, Duration::from_millis(1500)).await {
                Ok(h) => println!(
                    "HELLO_RES: id {:08x?}, tcp {}, version {}, udp_port {:?}",
                    h.id.words(),
                    h.tcp_port,
                    h.version,
                    h.source_udp_port
                ),
                Err(e) => println!("HELLO after bootstrap: {e}"),
            }
        }
        Err(e) => {
            eprintln!("no contact answered a BOOTSTRAP_REQ: {e}");
            eprintln!("(nodes.dat may be stale, or UDP {} is blocked)", 4672);
        }
    }
}

/// Wave-6 GOAL: bootstrap into Kad, then resolve an ed2k file hash to sources
/// (iterative FIND_NODE lookup toward the hash, then SEARCH_SOURCE_REQ).
async fn cmd_kad_search(nodes_path: &str, hash: [u8; 16], size: u64) {
    let bytes = match std::fs::read(nodes_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("cannot read {nodes_path}: {e}");
            return;
        }
    };
    let parsed = match read_nodes_dat(&bytes) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("bad nodes.dat: {e:?}");
            return;
        }
    };
    let contacts: Vec<_> = parsed
        .contacts
        .into_iter()
        .filter(|c| c.version >= 2)
        .collect();

    let bind: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 4672);
    let mut node = match KadNode::bind(bind, 4662).await {
        Ok(n) => n,
        Err(e) => {
            eprintln!("bind failed: {e}");
            return;
        }
    };
    println!(
        "bootstrapping into Kad ({} contacts to try)...",
        contacts.len()
    );
    if let Err(e) = node
        .bootstrap_any(&contacts, Duration::from_millis(1200), 40)
        .await
    {
        eprintln!("bootstrap failed: {e}");
        return;
    }
    println!(
        "bootstrapped; routing table holds {} contacts",
        node.contacts_known()
    );

    // The ed2k file hash becomes the Kad target via the canonical (SetValueBE)
    // form, matching eMule's CUInt128(fileHash).
    let target = Kad128::from_hash(&hash);
    println!(
        "resolving sources for ed2k hash {} (size {size})...",
        hex16(&hash)
    );

    match node
        .resolve_sources(&target, size, 5, Duration::from_millis(1400))
        .await
    {
        Ok(out) => {
            println!(
                "lookup: {}/{} FIND_NODE answered, closest node shares {} bits with the hash; \
                 routing table now {} contacts",
                out.find_node_responses,
                out.nodes_queried,
                out.closest_prefix_bits,
                node.contacts_known()
            );
            println!(
                "search: {}/{} in-tolerance nodes returned a SEARCH_RES",
                out.search_responses, out.nodes_searched
            );
            if out.sources.is_empty() {
                println!(
                    "no sources for this hash right now (protocol works: lookup converged and \
                     searches got live responses). Try a hash with current Kad seeders."
                );
            } else {
                println!("RESOLVED {} source(s):", out.sources.len());
                for s in &out.sources {
                    let ip = s.ip.map(Ipv4Addr::from);
                    println!(
                        "  type={} ip={:?} tcp={:?} udp={:?} clienthash={:08x?}",
                        s.source_type,
                        ip,
                        s.tcp_port,
                        s.udp_port,
                        s.client_hash.words()
                    );
                }
            }
        }
        Err(e) => eprintln!("resolve failed: {e}"),
    }
}

/// Wave-7 end-to-end: bootstrap Kad, resolve an ed2k hash to sources, and
/// download the file from a connectable (HighID) source - "give a hash, get the
/// file" in one driver. Firewalled Kad sources (the common case for an arbitrary
/// hash) are not directly connectable and are reported as such.
async fn cmd_kad_fetch(nodes_path: &str, hash: [u8; 16], size: u64, out: &str) {
    let bytes = match std::fs::read(nodes_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("cannot read {nodes_path}: {e}");
            return;
        }
    };
    let parsed = match read_nodes_dat(&bytes) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("bad nodes.dat: {e:?}");
            return;
        }
    };
    let contacts: Vec<_> = parsed
        .contacts
        .into_iter()
        .filter(|c| c.version >= 2)
        .collect();

    let bind: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 4672);
    let mut node = match KadNode::bind(bind, 4662).await {
        Ok(n) => n,
        Err(e) => {
            eprintln!("bind failed: {e}");
            return;
        }
    };
    println!("bootstrapping into Kad...");
    if let Err(e) = node
        .bootstrap_any(&contacts, Duration::from_millis(1200), 40)
        .await
    {
        eprintln!("bootstrap failed: {e}");
        return;
    }

    let target = Kad128::from_hash(&hash);
    println!("resolving sources for {} (size {size})...", hex16(&hash));
    let outcome = match node
        .resolve_sources(&target, size, 20, Duration::from_millis(1400))
        .await
    {
        Ok(o) => o,
        Err(e) => {
            eprintln!("resolve failed: {e}");
            return;
        }
    };

    let mut reg = SourceRegistry::new();
    let connectable = reg.add_kad(&outcome.sources);
    println!(
        "found {} source(s), {connectable} directly connectable (HighID)",
        outcome.sources.len()
    );
    if reg.is_empty() {
        println!(
            "no connectable source for this hash (all firewalled / none published). \
             Discovery + orchestration are wired; there is just no HighID seeder to pull from."
        );
        return;
    }

    let dir = std::path::Path::new(out)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let name = std::path::Path::new(out)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "out.bin".into());
    let store = match PartStore::create(&dir, 1, hash, size, name.as_bytes()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("cannot create part store in {}: {e}", dir.display());
            return;
        }
    };
    let dl = Download::new(store);
    let me = HelloInfo::baseline(demo_user_hash(), 0, 4662, 4672, "padMule");

    println!("downloading from {} connectable source(s)...", reg.len());
    let fetched = fetch_from_sources(&dl, reg.sources(), &me, Duration::from_secs(60), None).await;
    println!(
        "connected to {}/{} sources; {} / {size} bytes present; complete={}",
        fetched.peers_connected, fetched.sources_tried, fetched.bytes_present, fetched.completed
    );
    if fetched.completed {
        println!("OK: fetched {} -> {out}", hex16(&hash));
    } else {
        println!("incomplete (sources did not serve the full file)");
    }
}

/// Pull a string tag (by eD2k tag id) out of a search result's tags.
fn result_str(tags: &[mule_proto::Tag], id: u8) -> Option<String> {
    tags.iter().find_map(|t| match (&t.name, &t.value) {
        (mule_proto::TagName::Id(n), mule_proto::TagValue::Str(s)) if *n == id => {
            Some(String::from_utf8_lossy(s).into_owned())
        }
        _ => None,
    })
}

/// Pull an integer tag (u32/u64) out of a search result's tags.
fn result_u64(tags: &[mule_proto::Tag], id: u8) -> Option<u64> {
    tags.iter().find_map(|t| match (&t.name, &t.value) {
        (mule_proto::TagName::Id(n), mule_proto::TagValue::U32(v)) if *n == id => Some(*v as u64),
        (mule_proto::TagName::Id(n), mule_proto::TagValue::U64(v)) if *n == id => Some(*v),
        _ => None,
    })
}

/// Read packets from `fs` until one with opcode `want` arrives or the deadline
/// passes, printing any server messages seen along the way.
async fn read_until(
    fs: &mut FramedStream<tokio::net::TcpStream>,
    want: u8,
    wait: Duration,
) -> Option<mule_proto::Packet> {
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return None;
        }
        match timeout(remaining, fs.read_packet_unpacked()).await {
            Ok(Ok(pkt)) if pkt.opcode == want => return Some(pkt),
            Ok(Ok(_)) => continue, // some other server packet; keep waiting
            _ => return None,
        }
    }
}

/// Live end-to-end over a server: search a keyword, take the first matching
/// result, get its sources, and download it - the eD2k-network counterpart of
/// kad-fetch.
async fn cmd_search_download(met_path: &str, keyword: &str, out: &str) {
    // Cap the download so a test never pulls a huge file.
    const MAX_SIZE: u64 = 64 * 1024 * 1024;

    let bytes = match std::fs::read(met_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("cannot read {met_path}: {e}");
            return;
        }
    };
    let met = match read_server_met(&bytes) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("bad server.met: {e}");
            return;
        }
    };

    // Connect + login to the first server that answers.
    let login = LoginRequest {
        user_hash: demo_user_hash(),
        client_id: 0,
        tcp_port: 4662,
        nick: "padMule".to_string(),
        server_flags: DEFAULT_SERVER_FLAGS,
    };
    let (tx, rx) = mpsc::channel(64);
    let printer = spawn_event_printer(rx);
    let mut fs = None;
    for srv in met.servers.iter().take(8) {
        let addr = SocketAddr::new(IpAddr::V4(ip_from_met_u32(srv.ip)), srv.port);
        print!("connecting {addr} ... ");
        let mut stream = match connect_server(addr).await {
            Ok(s) => s,
            Err(_) => {
                println!("no");
                continue;
            }
        };
        match timeout(
            Duration::from_secs(10),
            login_handshake(&mut stream, &login, &tx),
        )
        .await
        {
            Ok(Ok(state)) => {
                println!("logged in ({state:?})");
                fs = Some(stream);
                break;
            }
            _ => println!("login failed"),
        }
    }
    drop(tx);
    let _ = printer.await;
    let mut fs = match fs {
        Some(f) => f,
        None => {
            eprintln!("no server accepted a login");
            return;
        }
    };

    // Search.
    let params = SearchParams {
        keyword: keyword.to_string(),
        file_type: None,
        min_size: Some(1),
        max_size: Some(MAX_SIZE as u32),
        min_sources: None,
        extension: Some(keyword.to_string()),
    };
    println!("searching for '{keyword}' ...");
    if fs
        .write_packet(&build_search_request(&params))
        .await
        .is_err()
    {
        eprintln!("failed to send search");
        return;
    }
    let result_pkt = match read_until(
        &mut fs,
        mule_engine::search::OP_SEARCHRESULT,
        Duration::from_secs(20),
    )
    .await
    {
        Some(p) => p,
        None => {
            eprintln!("no search results");
            return;
        }
    };
    let files = match parse_search_result(&result_pkt.payload) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("cannot parse search results: {e:?}");
            return;
        }
    };
    println!("{} results", files.len());

    // Candidate .<keyword> files with a size, ranked by advertised source count
    // (TAG_SOURCES 0x15) - popular files are the ones with a reachable HighID
    // seeder, and the point is to actually pull bytes.
    let mut candidates: Vec<([u8; 16], u64, String, u64)> = files
        .iter()
        .filter_map(|f| {
            let name = result_str(&f.tags, 0x01)?;
            let size = result_u64(&f.tags, 0x02)?;
            (size > 0 && size <= MAX_SIZE && name.to_lowercase().ends_with(&format!(".{keyword}")))
                .then(|| (f.hash, size, name, result_u64(&f.tags, 0x15).unwrap_or(0)))
        })
        .collect();
    candidates.sort_by_key(|c| std::cmp::Reverse(c.3));
    if candidates.is_empty() {
        eprintln!("no result was a downloadable .{keyword} under {MAX_SIZE} bytes");
        return;
    }
    println!(
        "{} .{keyword} candidates; probing sources (most-seeded first)...",
        candidates.len()
    );

    // Probe get-sources on each candidate until one has a connectable source.
    let mut chosen: Option<([u8; 16], u64, String, SourceRegistry)> = None;
    for (hash, size, name, srcs) in candidates.into_iter().take(15) {
        if fs
            .write_packet(&build_get_sources(&hash, size, false))
            .await
            .is_err()
        {
            eprintln!("failed to send get-sources");
            return;
        }
        let found = match read_until(
            &mut fs,
            mule_engine::sources::OP_FOUNDSOURCES,
            Duration::from_secs(12),
        )
        .await
        {
            Some(p) => parse_found_sources(&p.payload, false)
                .map(|(_, s)| s)
                .unwrap_or_default(),
            None => Vec::new(),
        };
        let mut reg = SourceRegistry::new();
        reg.add_found(&found);
        println!(
            "  '{}' ({} B, ~{srcs} srcs): {} found, {} connectable",
            name,
            size,
            found.len(),
            reg.len()
        );
        if !reg.is_empty() {
            chosen = Some((hash, size, name, reg));
            break;
        }
    }
    let (hash, size, name, reg) = match chosen {
        Some(v) => v,
        None => {
            println!("no candidate had a connectable HighID source (all LowID/firewalled).");
            println!("Search + get-sources work end to end; there was just no HighID seeder to pull from.");
            return;
        }
    };
    println!("picked '{name}' ({size} bytes) hash {}", hex16(&hash));

    // Download.
    let dir = std::path::Path::new(out)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let store = match PartStore::create(&dir, 1, hash, size, name.as_bytes()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("cannot create part store: {e}");
            return;
        }
    };
    let dl = Download::new(store);
    let me = HelloInfo::baseline(demo_user_hash(), 0, 4662, 4672, "padMule");
    let mut reg = reg;

    // The download manager pulls in parallel and rides out upload-queue
    // rationing across reconnects; between passes we refresh the source set from
    // the server (peers ration slots, so more sources + retries accumulate the
    // file - the .part persists progress).
    for pass in 0..3 {
        if dl.is_complete().await {
            break;
        }
        println!(
            "pass {}: {} source(s), {} / {size} bytes so far...",
            pass + 1,
            reg.len(),
            size - dl.missing().await
        );
        let cfg = ManagerConfig::Fixed {
            parallel: 4,
            per_peer: Duration::from_secs(45),
            rounds: 3,
        };
        let out = download_file(&dl, reg.sources(), &me, cfg, None).await;
        println!(
            "  {} / {size} bytes; complete={}",
            out.bytes_present, out.completed
        );
        if out.completed {
            break;
        }
        // Ask the server for more sources for the next pass.
        if fs
            .write_packet(&build_get_sources(&hash, size, false))
            .await
            .is_ok()
        {
            if let Some(p) = read_until(
                &mut fs,
                mule_engine::sources::OP_FOUNDSOURCES,
                Duration::from_secs(10),
            )
            .await
            {
                if let Ok((_, more)) = parse_found_sources(&p.payload, false) {
                    reg.add_found(&more);
                }
            }
        }
    }

    if dl.is_complete().await {
        // Move the finished .part into place and verify the ed2k hash.
        drop(dl);
        let part = dir.join("001.part");
        match std::fs::read(&part) {
            Ok(data) if ed2k_hash(&data) == hash => {
                let _ = std::fs::rename(&part, out);
                let _ = std::fs::remove_file(dir.join("001.part.met"));
                println!(
                    "OK: downloaded + verified '{name}' -> {out} ({} bytes)",
                    data.len()
                );
            }
            Ok(data) => println!(
                "downloaded {} bytes but the ed2k hash did NOT match - corrupt",
                data.len()
            ),
            Err(e) => println!("complete but cannot read the .part: {e}"),
        }
    } else {
        let present = size - dl.missing().await;
        println!(
            "incomplete: {present} / {size} bytes ({:.0}%). Real bytes transferred from a live \
             peer; the source(s) queued/dropped us before the full file.",
            100.0 * present as f64 / size as f64
        );
    }
}

/// Serverless keyword search over Kad: bootstrap, then resolve a keyword to
/// files (iterative FIND_NODE toward the keyword hash, then SEARCH_KEY_REQ).
async fn cmd_kad_keyword(nodes_path: &str, keyword: &str) {
    let bytes = match std::fs::read(nodes_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("cannot read {nodes_path}: {e}");
            return;
        }
    };
    let parsed = match read_nodes_dat(&bytes) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("bad nodes.dat: {e:?}");
            return;
        }
    };
    let contacts: Vec<_> = parsed
        .contacts
        .into_iter()
        .filter(|c| c.version >= 2)
        .collect();
    let bind: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 4672);
    let mut node = match KadNode::bind(bind, 4662).await {
        Ok(n) => n,
        Err(e) => {
            eprintln!("bind failed: {e}");
            return;
        }
    };
    println!("bootstrapping into Kad...");
    if let Err(e) = node
        .bootstrap_any(&contacts, Duration::from_millis(1200), 40)
        .await
    {
        eprintln!("bootstrap failed: {e}");
        return;
    }
    println!("searching Kad for keyword '{keyword}' (no server)...");
    match node
        .resolve_keyword(keyword, 30, Duration::from_millis(1400))
        .await
    {
        Ok(files) if files.is_empty() => {
            println!("no files published under '{keyword}' in Kad right now.");
        }
        Ok(files) => {
            println!("found {} file(s):", files.len());
            for f in files.iter().take(30) {
                println!(
                    "  {}  {:>12} B  ~{} srcs  {}",
                    hex16(&f.hash),
                    f.size,
                    f.sources,
                    f.name
                );
            }
        }
        Err(e) => eprintln!("keyword search failed: {e}"),
    }
}

/// Attempt a NAT-PMP port mapping against the gateway - opens our port for
/// HighID without a manual forward (on routers that speak NAT-PMP).
async fn cmd_natpmp(gateway: &str, port: u16) {
    let gw: std::net::IpAddr = match gateway.parse() {
        Ok(ip) => ip,
        Err(_) => {
            eprintln!("bad gateway IP: {gateway}");
            return;
        }
    };
    println!("requesting NAT-PMP TCP+UDP map of :{port} from gateway {gw}...");
    for proto in [mule_engine::Proto::Tcp, mule_engine::Proto::Udp] {
        match mule_engine::map_port(gw, proto, port, 3600, Duration::from_secs(3)).await {
            Ok(ext) => println!("  {proto:?}: mapped external port {ext}"),
            Err(e) => println!("  {proto:?}: {e}"),
        }
    }
}

/// Discover a UPnP-IGD gateway and map our listening port, for on-device HighID.
/// Unlike NAT-PMP this needs no gateway IP - SSDP finds it.
async fn cmd_upnp(port: u16) {
    println!("UPnP: discovering gateway and mapping TCP :{port} ...");
    match mule_engine::upnp::map_port(port, "padMule", 0).await {
        Ok(ext_ip) => {
            println!("  mapped :{port} TCP; gateway external IP = {ext_ip}");
            println!("  (point an external port checker at {ext_ip}:{port} to confirm HighID)");
        }
        Err(e) => println!("  UPnP failed: {e}"),
    }
}

/// Ask the gateway which internal device currently holds a TCP port (unicast).
/// A port already mapped to a DIFFERENT device is why a second device stays LowID.
async fn cmd_upnp_query(port: u16) {
    println!("UPnP: who holds TCP :{port} on the gateway (unicast) ...");
    match mule_engine::upnp::who_maps_unicast(port).await {
        Ok(Some(client)) => println!("  :{port} -> {client}"),
        Ok(None) => println!("  :{port} is NOT mapped (free to claim)"),
        Err(e) => println!("  query failed: {e}"),
    }
}

/// Delete a TCP port mapping on the gateway (unicast), freeing it. Use it to clear
/// a stale mapping so another device can claim the port and earn HighID.
async fn cmd_upnp_unmap(port: u16) {
    println!("UPnP: deleting the TCP :{port} mapping (unicast) ...");
    match mule_engine::upnp::unmap_port_unicast(port).await {
        Ok(()) => println!("  :{port} mapping removed (or was already gone)"),
        Err(e) => println!("  unmap failed: {e}"),
    }
}

/// UNICAST-only UPnP mapping: the exact path the iPad uses (multicast skipped).
/// Run this on the dev box to prove the on-device route works against the real
/// gateway before trusting it on a device with no debugger.
async fn cmd_upnp_unicast(port: u16) {
    println!(
        "UPnP (unicast, the iOS path): M-SEARCH straight at the gateway, mapping TCP :{port} ..."
    );
    match mule_engine::upnp::map_port_unicast(port, "padMule", 0).await {
        Ok(ext_ip) => {
            println!("  mapped :{port} TCP via unicast; gateway external IP = {ext_ip}");
            println!("  this is the route the iPad takes - if it works here, it should work there");
        }
        Err(e) => println!("  unicast UPnP failed: {e}"),
    }
}

/// Parse an ed2k:// or magnet: link and show what it contains; for a file link
/// with embedded sources and an out path, download it from those sources.
/// Load an ipfilter.dat/.p2p list, report how many ranges block, and optionally
/// test whether a given IP is blocked.
fn cmd_ipfilter(path: &str, test_ip: Option<&str>) {
    // Bytes + lossy, not read_to_string: community lists carry Latin-1 bytes in
    // the description; strict UTF-8 would reject the whole file.
    let text = match std::fs::read(path) {
        Ok(b) => String::from_utf8_lossy(&b).into_owned(),
        Err(e) => {
            eprintln!("cannot read {path}: {e}");
            return;
        }
    };
    let filter = mule_files::IpFilter::parse(&text, mule_files::DEFAULT_IPFILTER_LEVEL);
    println!(
        "loaded {} blocking range(s) at level {}",
        filter.len(),
        mule_files::DEFAULT_IPFILTER_LEVEL
    );
    if let Some(ip) = test_ip {
        match ip.parse::<std::net::Ipv4Addr>() {
            Ok(addr) => println!(
                "{addr} is {}",
                if filter.is_blocked(addr) {
                    "BLOCKED"
                } else {
                    "allowed"
                }
            ),
            Err(_) => eprintln!("bad IP: {ip}"),
        }
    }
}

async fn cmd_link(link: &str, out: Option<&str>) {
    let parsed = match mule_proto::parse_link(link) {
        Some(p) => p,
        None => {
            eprintln!("not a recognizable ed2k:// or magnet: link");
            return;
        }
    };
    match parsed {
        mule_proto::Ed2kLink::File(f) => {
            println!("file: {}", f.name);
            println!("  size:   {} bytes", f.size);
            println!("  ed2k:   {}", hex16(&f.hash));
            if let Some(a) = f.aich {
                let hx: String = a.iter().map(|b| format!("{b:02x}")).collect();
                println!("  aich:   {hx}");
            }
            if f.sources.is_empty() {
                println!("  sources: none embedded");
                println!(
                    "  -> to fetch via Kad: kad-fetch <nodes.dat> {} {} <out>",
                    hex16(&f.hash),
                    f.size
                );
                return;
            }
            println!("  sources: {:?}", f.sources);
            let Some(out) = out else {
                println!("  (pass an <out> path to download from these sources)");
                return;
            };
            let sources: Vec<_> = f
                .sources
                .iter()
                .map(|&addr| mule_engine::PeerSource {
                    addr,
                    user_hash: None,
                    origin: mule_engine::SourceOrigin::PeerExchange,
                })
                .collect();
            let dir = std::path::Path::new(out)
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .map(std::path::Path::to_path_buf)
                .unwrap_or_else(|| std::path::PathBuf::from("."));
            let store = match PartStore::create(&dir, 1, f.hash, f.size, f.name.as_bytes()) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("cannot create part store: {e}");
                    return;
                }
            };
            let dl = Download::new(store);
            let me = HelloInfo::baseline(demo_user_hash(), 0, 4662, 4672, "padMule");
            println!("downloading from {} embedded source(s)...", sources.len());
            let cfg = ManagerConfig::Fixed {
                parallel: 4,
                per_peer: Duration::from_secs(60),
                rounds: 6,
            };
            let o = download_file(&dl, &sources, &me, cfg, None).await;
            println!(
                "{} / {} bytes; complete={}",
                o.bytes_present, f.size, o.completed
            );
        }
        mule_proto::Ed2kLink::Server { host, port } => println!("server: {host}:{port}"),
        mule_proto::Ed2kLink::ServerList { url } => println!("server list: {url}"),
        mule_proto::Ed2kLink::Search { term } => {
            println!("search: '{term}'");
            println!("  -> run: kad-keyword <nodes.dat> {term}   (or search-download)");
        }
    }
}

/// Completion-optimized fetch: search a keyword, catalog + rank the results,
/// then try SMALL trusted candidates (smallest first - a source serves a burst
/// then queues us, so small files finish in one shot) until one downloads to
/// completion and its ed2k hash verifies. Prints the file that completed.
async fn cmd_fetch_complete(
    met_path: &str,
    keyword: &str,
    out: &str,
    max_size: u64,
    min_size: u64,
) {
    let bytes = match std::fs::read(met_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("cannot read {met_path}: {e}");
            return;
        }
    };
    let met = match read_server_met(&bytes) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("bad server.met: {e}");
            return;
        }
    };
    // Bind our TCP port and accept inbound handshakes, so (a) the server's HighID
    // callback during login SUCCEEDS (a HighID gets far better upload-queue
    // treatment than a LowID) and (b) LowID sources we asked the server to poke
    // can connect back to us. Any inbound peer is fed into the ACTIVE download,
    // so a called-back LowID source delivers just like a HighID one.
    let active: std::sync::Arc<tokio::sync::Mutex<Option<std::sync::Arc<Download>>>> =
        std::sync::Arc::new(tokio::sync::Mutex::new(None));
    if let Ok(listener) = TcpListener::bind(("0.0.0.0", 4662)).await {
        let me_in = HelloInfo::baseline(demo_user_hash(), 0, 4662, 4672, "padMule");
        let active_l = active.clone();
        tokio::spawn(async move {
            loop {
                if let Ok((stream, _)) = listener.accept().await {
                    let me = me_in.clone();
                    let active_l = active_l.clone();
                    tokio::spawn(async move {
                        let mut fs = FramedStream::new(stream);
                        if timeout(Duration::from_secs(8), peer_handshake_inbound(&mut fs, &me))
                            .await
                            .is_ok()
                        {
                            let dl = active_l.lock().await.clone();
                            if let Some(dl) = dl {
                                if let Ok(Ok(bytes)) = timeout(
                                    Duration::from_secs(60),
                                    download_from_peer(&mut fs, &dl, false),
                                )
                                .await
                                {
                                    if bytes > 0 {
                                        eprintln!("  [callback] a called-back peer delivered {bytes} bytes");
                                    }
                                }
                            }
                        }
                    });
                }
            }
        });
    }

    let login = LoginRequest {
        user_hash: demo_user_hash(),
        client_id: 0,
        tcp_port: 4662,
        nick: "padMule".to_string(),
        server_flags: DEFAULT_SERVER_FLAGS,
    };
    let (tx, rx) = mpsc::channel(64);
    let printer = spawn_event_printer(rx);
    let mut fs = None;
    for srv in met.servers.iter().take(10) {
        let addr = SocketAddr::new(IpAddr::V4(ip_from_met_u32(srv.ip)), srv.port);
        let mut stream = match connect_server(addr).await {
            Ok(s) => s,
            Err(_) => continue,
        };
        match timeout(
            Duration::from_secs(12),
            login_handshake(&mut stream, &login, &tx),
        )
        .await
        {
            Ok(Ok(state)) => {
                println!("logged in to {addr}: {state:?}");
                fs = Some(stream);
                break;
            }
            _ => continue,
        }
    }
    drop(tx);
    let _ = printer.await;
    let mut fs = match fs {
        Some(f) => f,
        None => {
            eprintln!("no server accepted a login");
            return;
        }
    };

    let params = SearchParams {
        keyword: keyword.to_string(),
        file_type: None,
        // The server-side size filter is 32-bit. For min, clamping to u32::MAX
        // only widens the filter (safe). For max, clamping would DROP every file
        // in (4 GiB, max_size] the user asked for, so instead omit the wire max
        // and let the client-side u64 filter enforce the real bound.
        min_size: Some(min_size.clamp(1, u32::MAX as u64) as u32),
        max_size: (max_size <= u32::MAX as u64).then_some(max_size as u32),
        min_sources: None,
        extension: Some(keyword.to_string()),
    };
    println!("searching '{keyword}' ({min_size}..={max_size} bytes) ...");
    if fs
        .write_packet(&build_search_request(&params))
        .await
        .is_err()
    {
        eprintln!("search send failed");
        return;
    }
    let files = match read_until(
        &mut fs,
        mule_engine::search::OP_SEARCHRESULT,
        Duration::from_secs(20),
    )
    .await
    {
        Some(p) => parse_search_result(&p.payload).unwrap_or_default(),
        None => Vec::new(),
    };
    println!("{} raw results", files.len());

    // Catalog: dedup by hash, rank, trust. Keep trusted .<keyword> files with a
    // real size <= max, smallest first (most likely to finish in a burst).
    let mut cands: Vec<_> = catalog(&files)
        .into_iter()
        .filter(|r| {
            r.is_trusted()
                && r.size >= min_size.max(1)
                && r.size <= max_size
                && r.name.to_lowercase().ends_with(&format!(".{keyword}"))
        })
        .collect();
    // Best-sourced first (more sources -> better odds one grants a slot), then
    // smallest (finishes in fewer bursts once served).
    cands.sort_by(|a, b| b.sources.cmp(&a.sources).then(a.size.cmp(&b.size)));
    println!(
        "{} trusted .{keyword} candidates (best-sourced first)",
        cands.len()
    );
    if cands.is_empty() {
        eprintln!("no suitable candidate");
        return;
    }

    let dir = std::path::Path::new(out)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let me = HelloInfo::baseline(demo_user_hash(), 0, 4662, 4672, "padMule");

    // HighID source addresses we have already watched stall (queue us / go
    // silent). Used to skip other files whose only source is that same busy peer.
    let mut dead: std::collections::HashSet<std::net::SocketAddr> =
        std::collections::HashSet::new();
    for (i, r) in cands.iter().take(80).enumerate() {
        // Ask for sources.
        if fs
            .write_packet(&build_get_sources(&r.hash, r.size, false))
            .await
            .is_err()
        {
            return;
        }
        let found = match read_until(
            &mut fs,
            mule_engine::sources::OP_FOUNDSOURCES,
            Duration::from_secs(10),
        )
        .await
        {
            Some(p) => parse_found_sources(&p.payload, false)
                .map(|(_, s)| s)
                .unwrap_or_default(),
            None => Vec::new(),
        };
        let mut reg = SourceRegistry::new();
        reg.add_found(&found);
        // LowID sources (their "ip" field is really a LowID client id < 0x01000000)
        // cannot accept our connection - we ask the SERVER to have them call US
        // back (we are HighID + listening).
        let lowids: Vec<u32> = found
            .iter()
            .filter(|s| s.ip != 0 && s.ip < 0x0100_0000 && s.port != 0)
            .map(|s| s.ip)
            .collect();
        if reg.is_empty() && lowids.is_empty() {
            continue; // no usable source at all
        }
        let hi_addrs: Vec<std::net::SocketAddr> = reg.sources().iter().map(|s| s.addr).collect();
        // Skip files whose only source(s) are peers we already saw stall, unless
        // there is a LowID callback still worth trying.
        if lowids.is_empty() && !hi_addrs.is_empty() && hi_addrs.iter().all(|a| dead.contains(a)) {
            continue;
        }
        let hi_ips: Vec<String> = hi_addrs.iter().map(|a| a.to_string()).collect();
        println!(
            "[{}] '{}' {} B - {} HighID {:?} + {} LowID(callback) source(s)",
            i + 1,
            r.name,
            r.size,
            reg.len(),
            hi_ips,
            lowids.len()
        );

        // Each candidate gets its OWN part directory. A LowID callback can keep
        // delivering into a Download after we would otherwise move on; a shared
        // 001.part would let the next candidate clobber an in-flight transfer.
        let cdir = dir.join(format!(".dl{i}"));
        let _ = std::fs::remove_dir_all(&cdir);
        let _ = std::fs::create_dir_all(&cdir);
        let store = match PartStore::create(&cdir, 1, r.hash, r.size, r.name.as_bytes()) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("part store: {e}");
                continue;
            }
        };
        let dl = Download::new(store);
        // Route callback peers into this download, then poke the LowID sources.
        *active.lock().await = Some(dl.clone());
        for id in &lowids {
            let _ = fs.write_packet(&build_callback_request(*id)).await;
        }
        // Size-adaptive: a tiny file finishes in one burst, so sweep fast (12s,
        // one round) to hunt across many thin sources. A larger file needs
        // sustained multi-source pulling, so give each source more time and
        // re-sweep its sources several rounds.
        let cfg = if r.size <= 1_000_000 {
            ManagerConfig::Fixed {
                parallel: 6,
                per_peer: Duration::from_secs(12),
                rounds: 1,
            }
        } else {
            ManagerConfig::Fixed {
                parallel: 8,
                per_peer: Duration::from_secs(40),
                rounds: 5,
            }
        };
        // Direct HighID sources (each bails in ~2s if it queues us rather than
        // granting a slot, so this whole call is fast when nobody is free)...
        download_file(&dl, reg.sources(), &me, cfg, None).await;
        // ...then, if we asked LowID sources to call back, wait WHILE they keep
        // delivering. A callback can take many seconds to connect and then streams
        // the whole file, so a fixed short wait would abandon an in-flight
        // transfer. Be patient before the first byte (connect latency), then bail
        // a few seconds after progress stalls, with a hard cap.
        if !lowids.is_empty() {
            let start = dl.missing().await;
            let mut last = start;
            let mut idle = 0u32;
            let mut total = 0u32;
            loop {
                if dl.is_complete().await {
                    break;
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
                total += 2;
                let now = dl.missing().await;
                if now < last {
                    last = now;
                    idle = 0;
                } else {
                    idle += 2;
                    // Patient before the first delivered byte, strict afterwards.
                    let limit = if last == start { 30 } else { 12 };
                    if idle >= limit || total >= 300 {
                        break;
                    }
                }
            }
        }
        *active.lock().await = None; // stop feeding this download
        let have = r.size - dl.missing().await;
        if dl.is_complete().await {
            drop(dl);
            let part = cdir.join("001.part");
            if let Ok(data) = std::fs::read(&part) {
                if ed2k_hash(&data) == r.hash {
                    let _ = std::fs::rename(&part, out);
                    let _ = std::fs::remove_dir_all(&cdir);
                    println!(
                        "COMPLETE + VERIFIED: '{}' ({} bytes) -> {out}",
                        r.name,
                        data.len()
                    );
                    return;
                }
                println!("completed but hash mismatch - corrupt, trying next");
            }
            let _ = std::fs::remove_dir_all(&cdir);
        } else {
            println!(
                "  got {have}/{} bytes; source stalled, next candidate",
                r.size
            );
            // Nothing arrived - remember these peers as busy so we don't retry the
            // rest of the same sharer's collection.
            if have == 0 {
                for a in &hi_addrs {
                    dead.insert(*a);
                }
            }
            let _ = std::fs::remove_dir_all(&cdir);
        }
    }
    println!("no candidate completed (sources uncooperative). Search + selection worked.");
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("login") if args.len() == 4 => {
            let hostport = format!("{}:{}", args[2], args[3]);
            match hostport.to_socket_addrs().ok().and_then(|mut it| it.next()) {
                Some(addr) => cmd_login(addr).await,
                None => eprintln!("cannot resolve {hostport}"),
            }
        }
        Some("login-any") if args.len() == 3 => cmd_login_any(&args[2]).await,
        Some("global-search") if args.len() == 4 => cmd_global_search(&args[2], &args[3]).await,
        Some("listen") => {
            let port: u16 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(4662);
            cmd_listen(port).await;
        }
        // sec-ident <host> <port> [obf-peer-hash]
        Some("sec-ident") if args.len() == 4 || args.len() == 5 => {
            let hostport = format!("{}:{}", args[2], args[3]);
            let addr = hostport.to_socket_addrs().ok().and_then(|mut it| it.next());
            let obf = args.get(4).map(|s| parse_hex16(s));
            match (addr, obf) {
                (_, Some(None)) => eprintln!("bad obfuscation peer-hash: {}", args[4]),
                (Some(addr), obf) => cmd_sec_ident(addr, obf.flatten()).await,
                (None, _) => eprintln!("cannot resolve {hostport}"),
            }
        }
        Some("hash-file") if args.len() == 3 => cmd_hash_file(&args[2]),
        Some("serve-file") if args.len() == 4 => match args[2].parse::<u16>() {
            Ok(port) => cmd_serve_file(port, &args[3]).await,
            Err(_) => eprintln!("bad port: {}", args[2]),
        },
        Some("peer-probe") if args.len() == 5 => {
            let hostport = format!("{}:{}", args[2], args[3]);
            match (
                hostport.to_socket_addrs().ok().and_then(|mut it| it.next()),
                parse_hex16(&args[4]),
            ) {
                (Some(addr), Some(hash)) => cmd_peer_probe(addr, hash).await,
                (None, _) => eprintln!("cannot resolve {hostport}"),
                (_, None) => eprintln!("bad hash: {}", args[4]),
            }
        }
        // peer-download <host> <port> <hash> <size> <out> [obfuscate-peer-hash]
        Some("peer-download") if args.len() == 7 || args.len() == 8 => {
            let hostport = format!("{}:{}", args[2], args[3]);
            let addr = hostport.to_socket_addrs().ok().and_then(|mut it| it.next());
            let hash = parse_hex16(&args[4]);
            let size: Option<u64> = args[5].parse().ok();
            // Optional 8th arg: the peer's userhash -> obfuscate the connection.
            let obf = args.get(7).map(|s| parse_hex16(s));
            match (addr, hash, size, obf) {
                (_, _, _, Some(None)) => eprintln!("bad obfuscation peer-hash: {}", args[7]),
                (Some(addr), Some(hash), Some(size), obf) => {
                    cmd_peer_download(addr, hash, size, &args[6], obf.flatten()).await
                }
                (None, ..) => eprintln!("cannot resolve {hostport}"),
                (_, None, ..) => eprintln!("bad hash (need 32 hex chars): {}", args[4]),
                (_, _, None, _) => eprintln!("bad size: {}", args[5]),
            }
        }
        Some("kad-bootstrap") if args.len() == 3 => cmd_kad_bootstrap(&args[2]).await,
        Some("kad-search") if args.len() == 5 => {
            match (parse_hex16(&args[3]), args[4].parse::<u64>()) {
                (Some(hash), Ok(size)) => cmd_kad_search(&args[2], hash, size).await,
                (None, _) => eprintln!("bad hash (need 32 hex chars): {}", args[3]),
                (_, Err(_)) => eprintln!("bad size: {}", args[4]),
            }
        }
        Some("kad-keyword") if args.len() == 4 => cmd_kad_keyword(&args[2], &args[3]).await,
        Some("link") if args.len() == 3 || args.len() == 4 => {
            cmd_link(&args[2], args.get(3).map(String::as_str)).await
        }
        Some("ipfilter") if args.len() == 3 || args.len() == 4 => {
            cmd_ipfilter(&args[2], args.get(3).map(String::as_str))
        }
        Some("upnp") if args.len() == 3 => match args[2].parse::<u16>() {
            Ok(port) => cmd_upnp(port).await,
            Err(_) => eprintln!("bad port: {}", args[2]),
        },
        Some("upnp-unicast") if args.len() == 3 => match args[2].parse::<u16>() {
            Ok(port) => cmd_upnp_unicast(port).await,
            Err(_) => eprintln!("bad port: {}", args[2]),
        },
        Some("upnp-query") if args.len() == 3 => match args[2].parse::<u16>() {
            Ok(port) => cmd_upnp_query(port).await,
            Err(_) => eprintln!("bad port: {}", args[2]),
        },
        Some("upnp-unmap") if args.len() == 3 => match args[2].parse::<u16>() {
            Ok(port) => cmd_upnp_unmap(port).await,
            Err(_) => eprintln!("bad port: {}", args[2]),
        },
        Some("natpmp") if args.len() == 4 => match args[3].parse::<u16>() {
            Ok(port) => cmd_natpmp(&args[2], port).await,
            Err(_) => eprintln!("bad port: {}", args[3]),
        },
        Some("kad-fetch") if args.len() == 6 => {
            match (parse_hex16(&args[3]), args[4].parse::<u64>()) {
                (Some(hash), Ok(size)) => cmd_kad_fetch(&args[2], hash, size, &args[5]).await,
                (None, _) => eprintln!("bad hash (need 32 hex chars): {}", args[3]),
                (_, Err(_)) => eprintln!("bad size: {}", args[4]),
            }
        }
        Some("search-download") if args.len() == 5 => {
            cmd_search_download(&args[2], &args[3], &args[4]).await
        }
        Some("fetch-complete") if (5..=7).contains(&args.len()) => {
            let max = args
                .get(5)
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(8_000_000);
            let min = args.get(6).and_then(|s| s.parse::<u64>().ok()).unwrap_or(1);
            cmd_fetch_complete(&args[2], &args[3], &args[4], max, min).await
        }
        _ => {
            eprintln!("usage:");
            eprintln!("  mule-cli login <host> <port>");
            eprintln!("  mule-cli login-any <server.met>");
            eprintln!("  mule-cli listen [port]");
            eprintln!("  mule-cli hash-file <path>");
            eprintln!("  mule-cli serve-file <port> <path>");
            eprintln!("  mule-cli peer-download <host> <port> <hash> <size> <out> [obf-peer-hash]");
            eprintln!("  mule-cli peer-probe <host> <port> <hash> <size>");
            eprintln!("  mule-cli sec-ident <host> <port> [obf-peer-hash]");
            eprintln!("  mule-cli kad-bootstrap <nodes.dat>");
            eprintln!("  mule-cli kad-search <nodes.dat> <ed2k-hash-hex> <size>");
            eprintln!("  mule-cli kad-fetch <nodes.dat> <ed2k-hash-hex> <size> <out>");
            eprintln!("  mule-cli kad-keyword <nodes.dat> <keyword>");
            eprintln!("  mule-cli link <ed2k-or-magnet-link> [out]");
            eprintln!("  mule-cli ipfilter <ipfilter.dat|.p2p> [test-ip]");
            eprintln!("  mule-cli search-download <server.met> <keyword> <out>");
            eprintln!(
                "  mule-cli fetch-complete <server.met> <keyword> <out> [max_size] [min_size]"
            );
            eprintln!("  mule-cli upnp <port>");
            eprintln!(
                "  mule-cli upnp-unicast <port>   (the iOS path: unicast M-SEARCH at the gateway)"
            );
            eprintln!("  mule-cli upnp-query <port>");
            eprintln!("  mule-cli upnp-unmap <port>");
            eprintln!("  mule-cli natpmp <gateway-ip> <port>");
        }
    }
}
