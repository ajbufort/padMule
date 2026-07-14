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

use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::time::Duration;

use mule_engine::peer::HelloInfo;
use mule_engine::server_messages::{LoginRequest, DEFAULT_SERVER_FLAGS};
use mule_engine::{peer_handshake_inbound, FramedStream, ServerEvent, ServerLink, ServerState};
use mule_files::read_server_met;
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
        _ => {
            eprintln!("usage:");
            eprintln!("  mule-cli login <host> <port>");
            eprintln!("  mule-cli login-any <server.met>");
            eprintln!("  mule-cli listen [port]");
        }
    }
}
