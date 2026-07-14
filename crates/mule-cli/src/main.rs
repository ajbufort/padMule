//! mule-cli: a headless harness for driving the engine on Linux. This wave
//! exercises the eD2k server login handshake and the pause/resume lifecycle.
//!
//! Usage:
//!   mule-cli login <host> <port>          connect + login to one server, then
//!                                         demonstrate pause/resume
//!   mule-cli login-any <server.met>       try each server in a server.met until
//!                                         one logs in
//!   mule-cli listen [port]                bind an inbound peer listener (default
//!                                         4662) and report connections - used to
//!                                         validate HighID port forwarding
//!   mule-cli hash-file <path>             print a file's ed2k hash and size
//!   mule-cli peer-download <host> <port> <hash-hex> <size> <out>
//!                                         download a file from ONE peer (used for
//!                                         the differential test against amuled)

use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::time::Duration;

use mule_engine::peer::HelloInfo;
use mule_engine::server_messages::{LoginRequest, DEFAULT_SERVER_FLAGS};
use mule_engine::{
    connect_peer, download_from_peer, peer_handshake_inbound, Download, FramedStream, PartStore,
    ServerEvent, ServerLink, ServerState,
};
use mule_files::read_server_met;
use mule_proto::ed2k_hash;
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

/// Download `hash` (`size` bytes) from a single peer at `addr` into `out`, driving
/// the real multi-source path (disk-backed PartStore, hashset exchange, block
/// receive incl. compressed parts, and verification against the peer's hashset).
/// This is the padMule side of the amuled differential test.
async fn cmd_peer_download(addr: SocketAddr, hash: [u8; 16], size: u64, out: &str) {
    println!(
        "connecting to peer {addr} for {} ({size} bytes) ...",
        hex16(&hash)
    );
    // Advertise client id 0 (LowID/unregistered): we have no server-assigned
    // HighID, and a non-LowID id that does not match our real source IP trips
    // aMule's ParanoidFilter (ClientTCPSocket.cpp:300).
    let me = HelloInfo::baseline(demo_user_hash(), 0, 4662, 4672, "padMule");
    let (peer, mut fs) = match connect_peer(addr, &me).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("peer connect/handshake failed: {e}");
            return;
        }
    };
    println!(
        "handshake OK with {} (port {})",
        hex16(&peer.user_hash),
        peer.tcp_port
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

    match timeout(Duration::from_secs(120), download_from_peer(&mut fs, &dl)).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            eprintln!("download failed: {e:?}");
            return;
        }
        Err(_) => {
            eprintln!("download timed out (missing {} bytes)", dl.missing().await);
            return;
        }
    }

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
        Some("listen") => {
            let port: u16 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(4662);
            cmd_listen(port).await;
        }
        Some("hash-file") if args.len() == 3 => cmd_hash_file(&args[2]),
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
        Some("peer-download") if args.len() == 7 => {
            let hostport = format!("{}:{}", args[2], args[3]);
            let addr = hostport.to_socket_addrs().ok().and_then(|mut it| it.next());
            let hash = parse_hex16(&args[4]);
            let size: Option<u64> = args[5].parse().ok();
            match (addr, hash, size) {
                (Some(addr), Some(hash), Some(size)) => {
                    cmd_peer_download(addr, hash, size, &args[6]).await
                }
                (None, _, _) => eprintln!("cannot resolve {hostport}"),
                (_, None, _) => eprintln!("bad hash (need 32 hex chars): {}", args[4]),
                (_, _, None) => eprintln!("bad size: {}", args[5]),
            }
        }
        _ => {
            eprintln!("usage:");
            eprintln!("  mule-cli login <host> <port>");
            eprintln!("  mule-cli login-any <server.met>");
            eprintln!("  mule-cli listen [port]");
            eprintln!("  mule-cli hash-file <path>");
            eprintln!("  mule-cli peer-download <host> <port> <hash-hex> <size> <out>");
        }
    }
}
