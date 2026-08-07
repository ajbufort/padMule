//! mule-cli: the headless dev + live-network harness for the engine on Linux.
//! 26 subcommands across the whole surface: server login + lifecycle (login,
//! login-any, listen), server search + offers (global-search, server-search,
//! related-search, offer-search, offer-hold), hashing + serving (hash-file,
//! serve-file), peer transfer + diagnostics (peer-download, peer-probe,
//! sec-ident), the full Kad surface (kad-bootstrap, kad-search, kad-fetch,
//! kad-keyword), links + filters (link, ipfilter), port mapping (upnp,
//! upnp-unicast, upnp-query, upnp-unmap, natpmp), and the completion-optimized
//! fetchers (search-download, fetch-complete). Run with no arguments for
//! usage; the match in `main` is the authoritative list.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::time::Duration;

use mule_engine::peer::HelloInfo;
use mule_engine::search::{
    build_global_search_udp, build_search_request, parse_global_search_res, parse_search_result,
    related_keyword, SearchParams, OP_GLOBSEARCHRES,
};
use mule_engine::server_messages::{LoginRequest, DEFAULT_SERVER_FLAGS};
use mule_engine::sources::{build_callback_request, build_get_sources, parse_found_sources};
use mule_engine::{
    catalog, connect_peer, connect_peer_obf, connect_server, download_file, download_from_peer,
    download_from_peer_at, fetch_from_sources, login_handshake, obf_accept, peer_handshake_inbound,
    serve_shared, Download, FramedStream, Identity, KadNode, ManagerConfig, ObfDetect, PartStore,
    SecIdentCtx, ServerEvent, ServerLink, ServerState, SharedFile, SourceRegistry,
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

/// login <host> <port>: connect + log in to one server, ask it for ITS server
/// list (OP_GETSERVERLIST - the live check for the gossip harvest), then
/// exercise the pause/resume lifecycle. Events (MOTD, status, the ServerList
/// answer) print as they arrive.
async fn cmd_login(addr: SocketAddr) {
    println!("connecting to {addr} ...");
    let (tx, rx) = mpsc::channel(64);
    let printer = spawn_event_printer(rx);
    let mut link = ServerLink::new(addr, demo_login(), tx);

    match timeout(Duration::from_secs(10), link.connect()).await {
        Ok(Ok(state)) => {
            println!("login result: {state:?}");
            // Ask for the server's own server list and give the answer a moment
            // to arrive; poll_incoming drains it (and any MOTD) to the printer.
            println!("asking for the server's server list (OP_GETSERVERLIST) ...");
            if let Err(e) = link.request_server_list().await {
                println!("ask failed: {e}");
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
            let _ = link.poll_incoming().await;
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

/// server-search <host> <port> <query>: log in and send a TCP OP_SEARCHREQUEST
/// for <query> (a boolean expression: implicit-AND words, AND/OR/NOT, parens,
/// "quoted phrases"), then print the hits. Used to prove a real server accepts
/// padMule's boolean search tree (a clean request/response exchange), against the
/// isolated eserver oracle or a live server.
async fn cmd_server_search(host: &str, port: u16, query: &str) {
    let Some(addr) = format!("{host}:{port}")
        .to_socket_addrs()
        .ok()
        .and_then(|mut i| i.next())
    else {
        eprintln!("cannot resolve {host}:{port}");
        return;
    };
    let (tx, rx) = mpsc::channel(64);
    let printer = spawn_event_printer(rx);
    let mut link = ServerLink::new(addr, demo_login(), tx);
    match link.connect().await {
        Ok(ServerState::Connected { id, low_id, .. }) => {
            println!("logged in (id={id:#x}, low_id={low_id})");
        }
        other => {
            eprintln!("login failed: {other:?}");
            return;
        }
    }
    println!("-> OP_SEARCHREQUEST '{query}'");
    let params = SearchParams {
        keyword: query.to_string(),
        ..Default::default()
    };
    match link.search(&params, Duration::from_secs(5)).await {
        Ok(files) => {
            println!("server ACCEPTED the search tree; {} hit(s):", files.len());
            for f in &files {
                let nm = f
                    .tags
                    .iter()
                    .find_map(|t| match (&t.name, &t.value) {
                        (mule_proto::TagName::Id(0x01), mule_proto::TagValue::Str(s)) => {
                            Some(String::from_utf8_lossy(s).into_owned())
                        }
                        _ => None,
                    })
                    .unwrap_or_default();
                println!("  <- {nm}  hash={}", hex16(&f.hash));
            }
        }
        Err(e) => eprintln!("search failed: {e}"),
    }
    link.disconnect().await;
    drop(link);
    let _ = printer.await;
}

/// related-search <host> <port> <hash>: log in, report whether the server
/// advertises SRV_TCPFLG_RELATEDSEARCH, then send the true `related::<hash>`
/// query over TCP and print the hits. This is what padMule's app does when the
/// server supports it; the Lugdunum eserver oracle is how to prove it live.
async fn cmd_related_search(host: &str, port: u16, hash: [u8; 16]) {
    let Some(addr) = format!("{host}:{port}")
        .to_socket_addrs()
        .ok()
        .and_then(|mut i| i.next())
    else {
        eprintln!("cannot resolve {host}:{port}");
        return;
    };
    let (tx, rx) = mpsc::channel(64);
    let printer = spawn_event_printer(rx);
    let mut link = ServerLink::new(addr, demo_login(), tx);
    let (id, low_id) = match link.connect().await {
        Ok(ServerState::Connected { id, low_id, .. }) => (id, low_id),
        other => {
            eprintln!("login failed: {other:?}");
            return;
        }
    };
    println!("logged in (id={id:#x}, low_id={low_id})");
    println!(
        "server related-search support: {}",
        link.related_search_supported()
    );

    let keyword = related_keyword(&hash);
    println!("-> OP_SEARCHREQUEST '{keyword}'");
    let params = SearchParams {
        keyword,
        ..Default::default()
    };
    match link.search(&params, Duration::from_secs(5)).await {
        Ok(files) if !files.is_empty() => {
            println!("{} related file(s):", files.len());
            for f in &files {
                let nm = f
                    .tags
                    .iter()
                    .find_map(|t| match (&t.name, &t.value) {
                        (mule_proto::TagName::Id(0x01), mule_proto::TagValue::Str(s)) => {
                            Some(String::from_utf8_lossy(s).into_owned())
                        }
                        _ => None,
                    })
                    .unwrap_or_default();
                println!("  <- {nm}  hash={}", hex16(&f.hash));
            }
        }
        Ok(_) => println!("no related files returned (server may not support it, or none indexed)"),
        Err(e) => eprintln!("search failed: {e}"),
    }
    link.disconnect().await;
    drop(link);
    let _ = printer.await;
}

/// offer-search <host> <port> <name>: log into a server, OFFER a synthetic
/// complete file named <name> (OP_OFFERFILES), then GLOBAL-SEARCH the server for
/// a keyword from it - proving OP_OFFERFILES makes our shares findable (the
/// deterministic local-eserver oracle loop). The TCP login is held open across
/// the UDP search so the server keeps the file indexed.
async fn cmd_offer_search(host: &str, port: u16, name: &str) {
    use mule_engine::server_messages::{OfferedFile, FILE_COMPLETE_ID, FILE_COMPLETE_PORT};
    use tokio::net::UdpSocket;

    let Some(addr) = format!("{host}:{port}")
        .to_socket_addrs()
        .ok()
        .and_then(|mut i| i.next())
    else {
        eprintln!("cannot resolve {host}:{port}");
        return;
    };
    let (tx, rx) = mpsc::channel(64);
    let printer = spawn_event_printer(rx);
    let mut link = ServerLink::new(addr, demo_login(), tx);
    let (id, low_id) = match link.connect().await {
        Ok(ServerState::Connected { id, low_id, .. }) => (id, low_id),
        other => {
            eprintln!("login failed: {other:?}");
            return;
        }
    };
    println!("logged in (id={id:#x}, low_id={low_id})");

    let hash = ed2k_hash(name.as_bytes()); // deterministic, recognizable
    let file = OfferedFile {
        hash,
        name,
        size: 1_234_567,
    };
    // All our shares are complete: use the marker id/port (faithful to aMule
    // against a compression-advertising server; no public-IP leak).
    let (cid, cport) = (FILE_COMPLETE_ID, FILE_COMPLETE_PORT);
    if let Err(e) = link.offer_files(&[file], cid, cport).await {
        eprintln!("offer failed: {e}");
        return;
    }
    println!("offered '{name}' (hash {}) to the server", hex16(&hash));
    tokio::time::sleep(Duration::from_millis(500)).await; // let the server index it

    // Global UDP search the same server (port+4) for the first keyword of <name>.
    let keyword = name.split_whitespace().next().unwrap_or(name);
    let params = SearchParams {
        keyword: keyword.to_string(),
        ..Default::default()
    };
    let pkt = build_global_search_udp(&params);
    let mut req = vec![pkt.protocol, pkt.opcode];
    req.extend_from_slice(&pkt.payload);
    let Ok(sock) = UdpSocket::bind(("0.0.0.0", 0u16)).await else {
        eprintln!("udp bind failed");
        return;
    };
    let Some(udp_port) = port.checked_add(4) else {
        return;
    };
    let dst = SocketAddr::new(addr.ip(), udp_port);
    let _ = sock.send_to(&req, dst).await;
    println!("-> OP_GLOBSEARCHREQ '{keyword}' to {dst}");

    let mut found = false;
    let mut buf = [0u8; 16 * 1024];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match timeout(remaining, sock.recv_from(&mut buf)).await {
            Ok(Ok((n, src))) if n >= 2 && src.ip() == addr.ip() => {
                if buf[0] == mule_proto::PROT_EDONKEY && buf[1] == OP_GLOBSEARCHRES {
                    for f in parse_global_search_res(&buf[2..n]).unwrap_or_default() {
                        let nm = f
                            .tags
                            .iter()
                            .find_map(|t| match (&t.name, &t.value) {
                                (mule_proto::TagName::Id(0x01), mule_proto::TagValue::Str(s)) => {
                                    Some(String::from_utf8_lossy(s).into_owned())
                                }
                                _ => None,
                            })
                            .unwrap_or_default();
                        println!("  <- {nm}  hash={}", hex16(&f.hash));
                        if f.hash == hash {
                            found = true;
                        }
                    }
                }
            }
            Ok(Ok(_)) => {}
            _ => break,
        }
    }
    if found {
        println!("PASS: the offered file came back via global UDP search (OP_OFFERFILES works).");
    } else {
        println!("NOT FOUND: the offered file did not come back (see the search output above).");
    }
    link.disconnect().await;
    drop(link);
    let _ = printer.await;
}

/// offer-hold <host> <port> <name[|name...]> [seconds]: log in, OFFER one or more
/// synthetic complete files (a '|'-separated <name> list is one shared library on
/// a single connection), and HOLD the connection so the server keeps them indexed
/// (for inspecting the server's share count, or searching from another client).
async fn cmd_offer_hold(host: &str, port: u16, name: &str, seconds: u64) {
    use mule_engine::server_messages::{OfferedFile, FILE_COMPLETE_ID, FILE_COMPLETE_PORT};
    let Some(addr) = format!("{host}:{port}")
        .to_socket_addrs()
        .ok()
        .and_then(|mut i| i.next())
    else {
        eprintln!("cannot resolve {host}:{port}");
        return;
    };
    let (tx, rx) = mpsc::channel(64);
    let printer = spawn_event_printer(rx);
    let mut link = ServerLink::new(addr, demo_login(), tx);
    match link.connect().await {
        Ok(ServerState::Connected { .. }) => {}
        other => {
            eprintln!("login failed: {other:?}");
            return;
        }
    }
    // `name` may be a '|'-separated list, so ONE client can offer a small shared
    // library (multiple files in a single OP_OFFERFILES) - the demo user hash is
    // fixed, so several separate seeders would collide as one client on the server.
    let offers: Vec<OfferedFile> = name
        .split('|')
        .filter(|s| !s.is_empty())
        .map(|n| OfferedFile {
            hash: ed2k_hash(n.as_bytes()),
            name: n,
            size: 1_234_567,
        })
        .collect();
    if offers.is_empty() {
        eprintln!("no file names given");
        return;
    }
    // All our shares are complete: use the marker id/port (faithful to aMule
    // against a compression-advertising server; no public-IP leak).
    let (cid, cport) = (FILE_COMPLETE_ID, FILE_COMPLETE_PORT);
    if let Err(e) = link.offer_files(&offers, cid, cport).await {
        eprintln!("offer failed: {e}");
        return;
    }
    for o in &offers {
        println!("offered '{}' (hash {})", o.name, hex16(&o.hash));
    }
    println!("holding {seconds}s");
    tokio::time::sleep(Duration::from_secs(seconds)).await;
    link.disconnect().await;
    drop(link);
    let _ = printer.await;
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
            Ok(Ok(ServerState::Connected { id, low_id, .. })) => {
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
/// Serves every connection until killed. With the optional
/// `<eserver-host> <eserver-port>` pair it also logs into that server and
/// OP_OFFERFILES the file, so the server can relay us as a source.
/// aich-hash <path> [entry-out.bin]: compute a file's AICH tree; print the
/// ed2k hash, size and master root, and optionally write the known2_64.met
/// ENTRY bytes so an oracle can byte-compare them against real amuled's store.
fn cmd_aich_hash(path: &str, out: Option<&str>) {
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("cannot read {path}: {e}");
            std::process::exit(1);
        }
    };
    let Some(tree) = mule_proto::AichTree::from_file_data(&data) else {
        eprintln!("cannot hash (empty file?)");
        std::process::exit(1);
    };
    let (Some(root), Some(leaves)) = (tree.master_hash(), tree.leaves()) else {
        eprintln!("tree incomplete");
        std::process::exit(1);
    };
    println!("ed2k={}", hex16(&ed2k_hash(&data)));
    println!("size={}", data.len());
    println!("blocks={}", leaves.len());
    let hx: String = root.iter().map(|b| format!("{b:02x}")).collect();
    println!("aich_root_hex={hx}");
    println!("aich_root_b32={}", mule_proto::aich_base32(&root));
    if let Some(out) = out {
        let entry = mule_files::known2_entry_bytes(&root, &leaves);
        if let Err(e) = std::fs::write(out, &entry) {
            eprintln!("cannot write {out}: {e}");
            std::process::exit(1);
        }
        println!("entry_bytes={} -> {out}", entry.len());
    }
}

/// aich-probe <addr> <ed2k-hash> <size> <part>: the LIVE differential check of
/// the AICH exchange against a real peer (amuled sharing the file): ask its
/// master root (0x9E/0x9D), then part recovery data (0x9B/0x9C), and verify
/// the payload against that root with the SAME code the engine runs. Exits
/// non-zero unless the recovery data verifies.
async fn cmd_aich_probe(addr: SocketAddr, hash: [u8; 16], size: u64, part: u16) {
    use mule_engine::transfer::{
        build_aich_file_hash_req, build_aich_request, parse_aich_answer, parse_aich_file_hash_ans,
        AichAnswer, OP_AICHANSWER, OP_AICHFILEHASHANS,
    };
    let me = HelloInfo::baseline(demo_user_hash(), 0, 4662, 4672, "padMule");
    let (_peer, mut fs) = match connect_peer(addr, &me).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("connect/handshake failed: {e}");
            std::process::exit(1);
        }
    };
    println!("handshake OK with {addr}");
    let deadline = Duration::from_secs(15);

    // Root ask.
    if fs
        .write_packet(&build_aich_file_hash_req(&hash))
        .await
        .is_err()
    {
        eprintln!("cannot send 0x9E");
        std::process::exit(1);
    }
    let root = tokio::time::timeout(deadline, async {
        loop {
            let pkt = fs.read_packet_unpacked().await.ok()?;
            if pkt.opcode == OP_AICHFILEHASHANS {
                if let Ok((h, root)) = parse_aich_file_hash_ans(&pkt.payload) {
                    if h == hash {
                        return Some(root);
                    }
                }
            }
        }
    })
    .await;
    let Ok(Some(root)) = root else {
        eprintln!("no OP_AICHFILEHASHANS (peer refused or timed out)");
        std::process::exit(1);
    };
    let hx: String = root.iter().map(|b| format!("{b:02x}")).collect();
    println!("peer aich root = {hx}");

    // Recovery ask for the requested part, verified against that root.
    if fs
        .write_packet(&build_aich_request(&hash, part, &root))
        .await
        .is_err()
    {
        eprintln!("cannot send 0x9B");
        std::process::exit(1);
    }
    let outcome = tokio::time::timeout(deadline, async {
        loop {
            let pkt = fs.read_packet_unpacked().await.ok()?;
            if pkt.opcode == OP_AICHANSWER {
                return parse_aich_answer(&pkt.payload).ok();
            }
        }
    })
    .await;
    match outcome {
        Ok(Some(AichAnswer::Recovery {
            hash: h,
            part: p,
            root: r,
            recovery,
        })) if h == hash && p == part && r == root => {
            let verified = mule_proto::AichTree::with_master(size, root)
                .filter(|_| u64::from(part) * mule_proto::PARTSIZE < size)
                .map(|mut t| {
                    t.read_recovery_data(u64::from(part) * mule_proto::PARTSIZE, &recovery)
                })
                .unwrap_or(false);
            if verified {
                println!(
                    "recovery data verified against the root ({} bytes)",
                    recovery.len()
                );
                println!("AICH_PROBE=PASS");
            } else {
                eprintln!("recovery data did NOT verify against the announced root");
                std::process::exit(1);
            }
        }
        Ok(Some(AichAnswer::Failure(_))) => {
            eprintln!("peer sent the 16-byte refusal (hashset unavailable?)");
            std::process::exit(1);
        }
        _ => {
            eprintln!("no valid OP_AICHANSWER (mismatch or timeout)");
            std::process::exit(1);
        }
    }
}

async fn cmd_serve_file(port: u16, path: &str, eserver: Option<(String, u16)>) {
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
    // AICH: compute the tree and stage it in a scratch known2_64.met store, so
    // a real downloader can learn our root (multipacket / OP_AICHFILEHASHREQ)
    // and pull recovery data (OP_AICHREQUEST) - the serve half the reverse
    // oracle validates against real amuled.
    let aich_dir = std::env::temp_dir().join(format!("padmule-serve-aich-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&aich_dir);
    let known2 = Arc::new(mule_engine::Known2Store::load(&aich_dir));
    let aich_root = mule_proto::AichTree::from_file_data(&data).and_then(|t| {
        let root = t.master_hash()?;
        known2.append(&root, &t.leaves()?).ok()?;
        println!("aich root {}", mule_proto::aich_base32(&root));
        Some(root)
    });

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

    // Optionally log into a server and OFFER this file, advertising our serve
    // port, so a downloader connected to the same server discovers us as a
    // source and dials us (the reliable server-relayed path, vs a flaky
    // link-embedded source). The offer is held for the life of the process.
    if let Some((esrv_host, esrv_port)) = eserver {
        use mule_engine::server_messages::{OfferedFile, FILE_COMPLETE_ID, FILE_COMPLETE_PORT};
        let name = name.clone();
        let size = data.len() as u64;
        let mut login = demo_login();
        login.tcp_port = port; // advertise our SERVE port (HighID callback + index)
        tokio::spawn(async move {
            let esrv = format!("{esrv_host}:{esrv_port}");
            let Some(addr) = esrv.to_socket_addrs().ok().and_then(|mut i| i.next()) else {
                eprintln!("cannot resolve eserver {esrv}");
                return;
            };
            let (tx, rx) = mpsc::channel(64);
            let printer = spawn_event_printer(rx);
            let mut link = ServerLink::new(addr, login, tx);
            match link.connect().await {
                Ok(ServerState::Connected { id, low_id, .. }) => {
                    println!("logged into eserver {esrv} (id={id:#x}, low_id={low_id})");
                }
                other => {
                    eprintln!("eserver login failed: {other:?}");
                    return;
                }
            }
            let offer = OfferedFile {
                hash,
                name: &name,
                size,
            };
            if let Err(e) = link
                .offer_files(&[offer], FILE_COMPLETE_ID, FILE_COMPLETE_PORT)
                .await
            {
                eprintln!("offer failed: {e}");
                return;
            }
            println!(
                "offered '{name}' (hash {}) to the eserver; holding",
                hex16(&hash)
            );
            tokio::time::sleep(Duration::from_secs(3600)).await;
            printer.abort();
        });
    }

    use mule_engine::share::{classify_inbound, InboundKind, ServeSec};
    use mule_engine::{Identity, SecureIdentSession};
    use std::sync::Arc;
    use std::time::Duration;
    // Advertise secure-ident so a downloader (real amuled) challenges us - the
    // precondition for verifying it - and drive our half of the exchange.
    let me = HelloInfo::baseline(demo_user_hash(), 0, port, 4672, "padMule").with_secident();
    let identity = Arc::new(Identity::generate());
    let size = data.len() as u64;
    let path_buf = std::path::PathBuf::from(path);
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
        let identity = Arc::clone(&identity);
        let phs = phs.clone();
        let name = name.clone();
        let path_buf = path_buf.clone();
        let known2 = Arc::clone(&known2);
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
            let (peer_secident, peer_aich) = match peer_handshake_inbound(&mut fs, &me).await {
                Ok(h) => h
                    .capabilities()
                    .map(|c| (c.sec_ident, c.aich))
                    .unwrap_or((0, 0)),
                Err(e) => {
                    eprintln!("  handshake failed: {e}");
                    return;
                }
            };
            // Serve through the SAME production path a real inbound peer hits on
            // the device: classify_inbound (draining any secure-ident prefix) then
            // serve_shared. This makes the reverse oracle exercise the real listener
            // classifier + serve loop, not a bespoke demo path.
            let sec = (peer_secident > 0).then(|| {
                ServeSec::new(
                    SecureIdentSession::new(&identity),
                    Arc::clone(&identity),
                    Box::new(|_| println!("identity verified (secure-ident): true")),
                )
            });
            let (first, sec) = match classify_inbound(&mut fs, sec, Duration::from_secs(3)).await {
                InboundKind::Leecher { first, sec } => (first, sec),
                InboundKind::Other => {
                    eprintln!("  peer {peer} did not issue a file request; closing");
                    return;
                }
                InboundKind::Source => {
                    eprintln!("  peer {peer} stayed silent (a source, not a leecher); closing");
                    return;
                }
            };
            let shared = vec![SharedFile {
                hash,
                size,
                name: name.into_bytes(),
                part_hashes: phs,
                path: path_buf,
                rating: 0,
                comment: String::new(),
                aich_root,
            }];
            match serve_shared(
                &mut fs,
                &shared,
                Some(first),
                None,
                0,
                mule_engine::ServeSession {
                    sec,
                    peer: Some(peer),
                    peer_aich,
                    aich: Some(Arc::clone(&known2)),
                    ..Default::default()
                },
            )
            .await
            {
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
    // The CLI dials an address given on the command line, so there is no
    // discovery channel behind it; Server is the honest default for a
    // hand-supplied peer (it is how a server-found source reaches us too).
    dl.note_source(
        peer.client_software(),
        addr,
        obf_target.is_some(),
        low_id,
        mule_engine::SourceOrigin::Server,
    )
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
        download_from_peer_at(
            &mut fs,
            &dl,
            false,
            Some(addr),
            mule_engine::PeerSession {
                sec,
                ..Default::default()
            },
        ),
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
/// Deliberately unfiltered beyond the version check below (no ipfilter, no
/// private/loopback/DNS-port exclusion): this is a developer diagnostic against
/// a file you hand it, not the engine's bootstrap path.
async fn cmd_kad_bootstrap(nodes_path: &str, bind_ip: Option<&str>) {
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

    // Optional explicit bind IP: on a multi-homed / isolated-namespace test box the
    // UNSPECIFIED source can be wrong (the kernel picks the peer's own subnet
    // address for a local dest); pinning the source IP fixes the oracle topology.
    let bind_addr: IpAddr = match bind_ip {
        Some(s) => match s.parse() {
            Ok(ip) => ip,
            Err(e) => {
                eprintln!("bad bind IP {s}: {e}");
                return;
            }
        },
        None => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    };
    let bind: SocketAddr = SocketAddr::new(bind_addr, 4672);
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

/// Live end-to-end over a server: search a term, take the first matching
/// result, get its sources, and download it - the eD2k-network counterpart of
/// kad-fetch. NB: the term is used BOTH as the search keyword AND as a
/// file-extension filter (results must end in `.<term>`), so pass an
/// extension-like token (`pdf`, `wav`, `txt`), not a free keyword.
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
        let out = download_file(&dl, reg.sources(), &me, cfg, None, None, None).await;
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
    // The lookup profile for the search just run. Same block the app shows under
    // Stats -> Kad lookup; printed here so it can be read without a device.
    print!("\nKAD LOOKUP\n{}", mule_engine::stats::kad_report());
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

/// server-crawl <server.met> [rounds]: run the RECURSIVE UDP server crawl - ask
/// the servers in the list for the servers THEY know (OP_SERVER_LIST_REQ2),
/// then ask those, for `rounds` hops - and merge the safe survivors back into
/// the list. The live harness for the Server Hunter discovery engine.
///
/// Copies the .met into a scratch config dir so a harness run never edits the
/// file you point it at; prints the before/after count and where the result is.
/// Most servers do NOT implement the request and simply stay silent - that is
/// normal, not a failure.
async fn cmd_server_crawl(met_path: &str, rounds: u32) {
    let bytes = match std::fs::read(met_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("cannot read {met_path}: {e}");
            return;
        }
    };
    let before = match mule_files::read_server_met(&bytes) {
        Ok(m) => m.servers.len(),
        Err(e) => {
            eprintln!("not a server.met: {e:?}");
            return;
        }
    };
    let dir = std::env::temp_dir().join(format!("padmule-crawl-{}", std::process::id()));
    if let Err(e) = std::fs::create_dir_all(&dir) {
        eprintln!("cannot create {}: {e}", dir.display());
        return;
    }
    if let Err(e) = std::fs::write(dir.join("server.met"), &bytes) {
        eprintln!("cannot seed the scratch dir: {e}");
        return;
    }
    let (mut engine, mut rx) = match mule_engine::Engine::new(&dir) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("engine: {e}");
            return;
        }
    };
    let printer = tokio::spawn(async move {
        while let Some(ev) = rx.recv().await {
            if let mule_engine::EngineEvent::Server(t) = ev {
                println!("  [server] {t}");
            }
        }
    });

    println!("crawling from {before} known server(s), {rounds} round(s) ...");
    let added = engine.crawl_servers(rounds).await;
    let after = std::fs::read(dir.join("server.met"))
        .ok()
        .and_then(|b| mule_files::read_server_met(&b).ok())
        .map(|m| m.servers.len())
        .unwrap_or(before);
    println!("added {added} new server(s): {before} -> {after}");
    // Then probe, exactly as the app does after a crawl: the status ping also
    // carries the description request, so servers discovered as bare ip:port
    // learn their NAME here (and it is persisted into server.met).
    println!("probing for status + names ...");
    let probed = engine.probe_server_list().await;
    let named = probed.iter().filter(|e| !e.name.is_empty()).count();
    println!("{named}/{} server(s) now have a name:", probed.len());
    for e in probed.iter().take(40) {
        let name = if e.name.is_empty() {
            "(no name)".to_string()
        } else {
            e.name.clone()
        };
        let stat = match (e.alive, e.users) {
            (true, Some(u)) => format!("alive, {u} users"),
            (true, None) => "alive".to_string(),
            _ => "no reply".to_string(),
        };
        println!("   {:<38} {name}  [{stat}]", e.addr.to_string());
    }
    println!("result: {}", dir.join("server.met").display());
    drop(engine);
    let _ = tokio::time::timeout(Duration::from_millis(200), printer).await;
}

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

/// Parse an ed2k:// or magnet: link and show what it contains; for a file link
/// with embedded sources and an out path, download it from those sources.
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
                    crypt: None,
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
            // A link-carried AICH root is part of the file's IDENTITY: VERIFIED
            // outright (eMule PartFile.cpp:197-201), enabling block recovery
            // with no source vote needed.
            if let Some(root) = f.aich {
                dl.set_aich_master_verified(root);
            }
            let me = HelloInfo::baseline(demo_user_hash(), 0, 4662, 4672, "padMule");
            println!("downloading from {} embedded source(s)...", sources.len());
            let cfg = ManagerConfig::Fixed {
                parallel: 4,
                per_peer: Duration::from_secs(60),
                rounds: 6,
            };
            let o = download_file(&dl, &sources, &me, cfg, None, None, None).await;
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

/// Completion-optimized fetch: search a term, catalog + rank the results, then
/// try trusted candidates BEST-SOURCED first (size ascending as the tiebreak)
/// until one downloads to completion and its ed2k hash verifies. Prints the
/// file that completed. NB: like search-download, the term is used BOTH as the
/// search keyword AND as a file-extension filter - pass `pdf`/`wav`/`txt`-style
/// tokens.
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
        download_file(&dl, reg.sources(), &me, cfg, None, None, None).await;
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
        Some("offer-search") if args.len() == 5 => match args[3].parse::<u16>() {
            Ok(port) => cmd_offer_search(&args[2], port, &args[4]).await,
            Err(_) => eprintln!("bad port: {}", args[3]),
        },
        Some("related-search") if args.len() == 5 => {
            match (args[3].parse::<u16>(), parse_hex16(&args[4])) {
                (Ok(port), Some(hash)) => cmd_related_search(&args[2], port, hash).await,
                (Err(_), _) => eprintln!("bad port: {}", args[3]),
                (_, None) => eprintln!("bad hash (need 32 hex chars): {}", args[4]),
            }
        }
        Some("server-search") if args.len() == 5 => match args[3].parse::<u16>() {
            Ok(port) => cmd_server_search(&args[2], port, &args[4]).await,
            Err(_) => eprintln!("bad port: {}", args[3]),
        },
        Some("offer-hold") if args.len() == 5 || args.len() == 6 => {
            let secs = args.get(5).and_then(|s| s.parse().ok()).unwrap_or(15);
            match args[3].parse::<u16>() {
                Ok(port) => cmd_offer_hold(&args[2], port, &args[4], secs).await,
                Err(_) => eprintln!("bad port: {}", args[3]),
            }
        }
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
        Some("serve-file") if args.len() == 4 || args.len() == 6 => match args[2].parse::<u16>() {
            Ok(port) => {
                // Optional [eserver-host eserver-port]: also log in + offer the file.
                let eserver = if args.len() == 6 {
                    match args[5].parse::<u16>() {
                        Ok(ep) => Some((args[4].clone(), ep)),
                        Err(_) => {
                            eprintln!("bad eserver port: {}", args[5]);
                            return;
                        }
                    }
                } else {
                    None
                };
                cmd_serve_file(port, &args[3], eserver).await
            }
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
        Some("kad-bootstrap") if args.len() == 3 => cmd_kad_bootstrap(&args[2], None).await,
        Some("kad-bootstrap") if args.len() == 4 => {
            cmd_kad_bootstrap(&args[2], Some(&args[3])).await
        }
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
        Some("server-crawl") if args.len() == 3 || args.len() == 4 => {
            let rounds = args.get(3).and_then(|r| r.parse::<u32>().ok()).unwrap_or(2);
            cmd_server_crawl(&args[2], rounds).await
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
        Some("aich-hash") if args.len() == 3 || args.len() == 4 => {
            cmd_aich_hash(&args[2], args.get(3).map(String::as_str))
        }
        Some("aich-probe") if args.len() == 7 => {
            let hostport = format!("{}:{}", args[2], args[3]);
            let addr = hostport.to_socket_addrs().ok().and_then(|mut it| it.next());
            match (
                addr,
                parse_hex16(&args[4]),
                args[5].parse::<u64>(),
                args[6].parse::<u16>(),
            ) {
                (Some(addr), Some(hash), Ok(size), Ok(part)) => {
                    cmd_aich_probe(addr, hash, size, part).await
                }
                (None, ..) => eprintln!("cannot resolve {hostport}"),
                (_, None, ..) => eprintln!("bad hash (need 32 hex chars): {}", args[4]),
                (_, _, Err(_), _) => eprintln!("bad size: {}", args[5]),
                (_, _, _, Err(_)) => eprintln!("bad part: {}", args[6]),
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
            eprintln!("  mule-cli serve-file <port> <path> [eserver-host eserver-port]");
            eprintln!("  mule-cli peer-download <host> <port> <hash> <size> <out> [obf-peer-hash]");
            eprintln!("  mule-cli peer-probe <host> <port> <hash>");
            eprintln!("  mule-cli sec-ident <host> <port> [obf-peer-hash]");
            eprintln!("  mule-cli global-search <server.met|host:port> <keyword>");
            eprintln!("  mule-cli server-search <host> <port> <boolean-query>");
            eprintln!("  mule-cli related-search <host> <port> <ed2k-hash-hex>");
            eprintln!("  mule-cli offer-search <host> <port> <name>");
            eprintln!("  mule-cli offer-hold <host> <port> <name[|name2|...]> [secs]");
            eprintln!("  mule-cli kad-bootstrap <nodes.dat> [bind-ip]");
            eprintln!("  mule-cli kad-search <nodes.dat> <ed2k-hash-hex> <size>");
            eprintln!("  mule-cli kad-fetch <nodes.dat> <ed2k-hash-hex> <size> <out>");
            eprintln!("  mule-cli kad-keyword <nodes.dat> <keyword>");
            eprintln!("  mule-cli aich-hash <path> [entry-out.bin]");
            eprintln!(
                "  mule-cli aich-probe <host> <port> <hash> <size> <part>   (live 0x9E/0x9B check)"
            );
            eprintln!("  mule-cli link <ed2k-or-magnet-link> [out]");
            eprintln!("  mule-cli ipfilter <ipfilter.dat|.p2p> [test-ip]");
            eprintln!(
                "  mule-cli server-crawl <server.met> [rounds]   (recursive UDP server discovery)"
            );
            eprintln!("  mule-cli search-download <server.met> <ext-keyword> <out>");
            eprintln!(
                "  mule-cli fetch-complete <server.met> <ext-keyword> <out> [max_size] [min_size]"
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
