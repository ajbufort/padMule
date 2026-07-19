//! End-to-end fetch orchestration over loopback (Wave 7): a serving peer holds a
//! real file; the fetch orchestrator connects to it as a discovered source and
//! downloads the file, and the ed2k hash verifies. This proves the orchestration
//! (connect -> download -> complete) that ties the discovery backends to the
//! download machinery, without depending on live network sources.

use std::net::SocketAddr;
use std::time::Duration;

use mule_engine::peer::HelloInfo;
use mule_engine::{
    download_file, fetch_from_sources, peer_handshake_inbound, serve_file, Download, FramedStream,
    ManagerConfig, PartStore, PeerSource, SourceOrigin,
};
use mule_proto::ed2k_hash;
use tokio::net::TcpListener;

fn user_hash() -> [u8; 16] {
    let mut h = [0x42u8; 16];
    h[5] = 14;
    h[14] = 111;
    h
}

/// Serve `data` (single-part, complete) to exactly one inbound peer.
async fn spawn_server(data: Vec<u8>, name: Vec<u8>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hash = ed2k_hash(&data);
    let me = HelloInfo::baseline(user_hash(), 0, addr.port(), 4672, "server");
    tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            let mut fs = FramedStream::new(stream);
            if peer_handshake_inbound(&mut fs, &me).await.is_ok() {
                let _ = serve_file(&mut fs, &hash, &name, &data).await;
            }
        }
    });
    addr
}

#[tokio::test]
async fn fetch_downloads_a_file_from_a_discovered_source() {
    // A single-part file (< PARTSIZE, so no hashset needed).
    let data: Vec<u8> = (0..120_000u32)
        .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
        .collect();
    let hash = ed2k_hash(&data);
    let server_addr = spawn_server(data.clone(), b"loopback.bin".to_vec()).await;

    // A download backed by a temp part store.
    let dir = std::env::temp_dir().join(format!("padmule-fetch-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let store = PartStore::create(&dir, 1, hash, data.len() as u64, b"loopback.bin").unwrap();
    let dl = Download::new(store);

    // The server presented as a plaintext (no-userhash) discovered source.
    let sources = vec![PeerSource {
        addr: server_addr,
        user_hash: None,
        origin: SourceOrigin::PeerExchange,
    }];
    let me = HelloInfo::baseline(user_hash(), 0, 4662, 4672, "padMule");

    let outcome = fetch_from_sources(&dl, &sources, &me, Duration::from_secs(20), None).await;

    assert_eq!(outcome.sources_tried, 1);
    assert_eq!(outcome.peers_connected, 1);
    assert!(outcome.completed, "the file must be complete");
    assert_eq!(outcome.bytes_present, data.len() as u64);

    // The reassembled bytes on disk verify against the ed2k hash.
    drop(dl); // close the .part file handle
    let got = std::fs::read(dir.join("001.part")).unwrap();
    assert_eq!(got.len(), data.len());
    assert_eq!(
        ed2k_hash(&got),
        hash,
        "downloaded bytes must match the ed2k hash"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn download_manager_completes_from_multiple_parallel_peers() {
    // Three peers each hold the file; the manager runs them concurrently against
    // one Download. Block reservation keeps the parallel workers from colliding,
    // and the reassembled bytes verify.
    let data: Vec<u8> = (0..300_000u32)
        .map(|i| (i.wrapping_mul(48271) >> 11) as u8)
        .collect();
    let hash = ed2k_hash(&data);
    let mut sources = Vec::new();
    for _ in 0..3 {
        let addr = spawn_server(data.clone(), b"multi.bin".to_vec()).await;
        sources.push(PeerSource {
            addr,
            user_hash: None,
            origin: SourceOrigin::PeerExchange,
        });
    }

    let dir = std::env::temp_dir().join(format!("padmule-mgr-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let store = PartStore::create(&dir, 1, hash, data.len() as u64, b"multi.bin").unwrap();
    let dl = Download::new(store);
    let me = HelloInfo::baseline(user_hash(), 0, 4662, 4672, "padMule");

    let cfg = ManagerConfig::Fixed {
        parallel: 3,
        per_peer: Duration::from_secs(20),
        rounds: 4,
    };
    let outcome = download_file(&dl, &sources, &me, cfg, None).await;

    assert!(outcome.completed, "the manager must complete the file");
    assert_eq!(outcome.bytes_present, data.len() as u64);
    assert!(outcome.peers_connected >= 1);

    drop(dl);
    let got = std::fs::read(dir.join("001.part")).unwrap();
    assert_eq!(ed2k_hash(&got), hash, "parallel download must verify");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn fetch_skips_a_dead_source_and_reports_no_completion() {
    // A source address nobody is listening on: the fetch must not hang or panic,
    // and must report the file incomplete.
    let data = vec![7u8; 5000];
    let hash = ed2k_hash(&data);
    let dir = std::env::temp_dir().join(format!("padmule-fetch-dead-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let store = PartStore::create(&dir, 1, hash, data.len() as u64, b"x.bin").unwrap();
    let dl = Download::new(store);

    // Reserve then drop a listener to get an almost-certainly-closed port.
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead = l.local_addr().unwrap();
    drop(l);

    let sources = vec![PeerSource {
        addr: dead,
        user_hash: None,
        origin: SourceOrigin::Server,
    }];
    let me = HelloInfo::baseline(user_hash(), 0, 4662, 4672, "padMule");
    let outcome = fetch_from_sources(&dl, &sources, &me, Duration::from_millis(800), None).await;

    assert_eq!(outcome.sources_tried, 1);
    assert_eq!(outcome.peers_connected, 0);
    assert!(!outcome.completed);
    let _ = std::fs::remove_dir_all(&dir);
}
