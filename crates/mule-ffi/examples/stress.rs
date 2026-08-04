//! STRESS HARNESS: dozens of simultaneous downloads, driven through the SAME
//! FFI the app uses, on the real network.
//!
//! Written for Anthony's 2026-08-04 report - "many files partially download and
//! then either stop or slow to a crawl" - after the root cause turned out to be
//! the idle-retry sweep starving every download but one (build-progress 8br).
//! A single download can never show that bug; it only appears at N>1 with equal
//! priority, which is why it survived every test and every manual check.
//!
//! It drives `MuleEngine` exactly as `EngineModel` does - `heartbeat()` plus the
//! lock-free polls once a second - so what it measures is what the app does, not
//! a shortcut around it.
//!
//! WHAT IT MEASURES, and why each number is here:
//!   - how many downloads EVER received a byte  -> the starvation signal. Under
//!     the old sweep this pinned at 1 no matter how many were queued.
//!   - how many are receiving RIGHT NOW          -> the amber-row signal.
//!   - per-download bytes over time              -> progress, not just liveness.
//!   - source counts per channel                 -> the cross-tab question:
//!     these are the SAME numbers the Transfers badge shows, so they can be
//!     compared against what the Search tab claimed.
//!
//! Usage:
//!   cargo run --release -p mule-ffi --example stress -- [config] [dl] [keyword] [n] [secs]

use mule_ffi::{MuleEngine, SearchFilters, SearchOutcome};
use std::collections::{BTreeMap, HashSet};
use std::thread::sleep;
use std::time::{Duration, Instant};

fn filters() -> SearchFilters {
    SearchFilters {
        complete_only: false,
        min_size: 0,
        max_size: 0,
        global: false,
    }
}

/// Reject anything whose NAME suggests adult or otherwise inappropriate
/// content. eD2k search results are noisy regardless of the query, so the
/// keyword choice alone is not enough - this is the belt to that braces. It errs
/// heavily toward rejecting: a false reject costs one test file, a false accept
/// downloads something that has no business here.
fn name_is_acceptable(name: &str) -> bool {
    let n = name.to_lowercase();
    const BLOCK: &[&str] = &[
        "xxx", "porn", "porno", "sex", "sexo", "erotic", "erotik", "adult", "nude", "naked",
        "hentai", "milf", "teen", "lolita", "incest", "rape", "fetish", "anal", "orgy", "escort",
        "webcam", "onlyfans", "playboy", "brazzers", "hardcore", "softcore", "18+", "nsfw",
    ];
    !BLOCK.iter().any(|b| n.contains(b))
}

fn mb(n: u64) -> String {
    format!("{:.1}MB", n as f64 / 1_048_576.0)
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let config = a
        .get(1)
        .cloned()
        .unwrap_or_else(|| "/tmp/stress-cfg".into());
    let dldir = a.get(2).cloned().unwrap_or_else(|| "/tmp/stress-dl".into());
    let keyword = a.get(3).cloned().unwrap_or_else(|| "linux".into());
    let want: usize = a.get(4).and_then(|s| s.parse().ok()).unwrap_or(30);
    let secs: u64 = a.get(5).and_then(|s| s.parse().ok()).unwrap_or(600);
    let _ = std::fs::create_dir_all(&config);
    let _ = std::fs::create_dir_all(&dldir);

    let engine = match MuleEngine::new(config.clone(), dldir.clone()) {
        Ok(e) => e,
        Err(e) => {
            println!("engine failed: {e}");
            return;
        }
    };
    println!("== BOOT ==  config={config}");
    engine.start();
    for _ in 0..5 {
        sleep(Duration::from_secs(1));
        engine.heartbeat();
        let _ = engine.drain_events();
    }

    // Connect to a live server, exactly as the Servers screen makes the user do.
    println!("== SERVERS ==");
    let servers = engine.server_list();
    let live: Vec<_> = servers.iter().filter(|s| s.alive).collect();
    println!("  {} known, {} answering", servers.len(), live.len());
    let Some(best) = live.iter().max_by_key(|s| s.users) else {
        println!("  no live server - cannot stress a real download run");
        return;
    };
    println!("  -> connecting to {} ({} users)", best.addr, best.users);
    engine.connect_to_server(best.addr.clone());
    for _ in 0..15 {
        sleep(Duration::from_secs(1));
        engine.heartbeat();
        let _ = engine.drain_events();
    }
    match engine.server_info() {
        Some(s) => println!("  connected: {} lowid={}", s.addr, s.low_id),
        None => println!("  NOT connected - results will be Kad-only"),
    }

    // Fill the queue. Several keywords, because one keyword's results are often
    // one sharer's collection - the diversity lesson from the three-file run.
    println!("== QUEUE {want} DOWNLOADS ==");
    let mut queued: Vec<(String, String, u64, u32)> = Vec::new(); // hash,name,size,srcs
    let mut seen: HashSet<String> = HashSet::new();
    // Deliberately narrow, safe keywords: Blender's open movies and similar
    // freely-distributable material. A bare "video" query on eD2k returns a
    // great deal that has no place in a technical test, so the queries name
    // known content rather than trawling.
    for kw in [
        keyword.clone(),
        format!("{keyword} pdf"),
        format!("{keyword} guide"),
        "ubuntu".to_string(),
        "debian".to_string(),
        "tutorial".to_string(),
    ] {
        if queued.len() >= want {
            break;
        }
        let hits = match engine.search(kw.clone(), filters()) {
            SearchOutcome::Results { hits, .. } => hits,
            SearchOutcome::Throttled { wait_secs } => {
                sleep(Duration::from_secs(u64::from(wait_secs) + 1));
                continue;
            }
        };
        println!("  '{kw}': {} hit(s)", hits.len());
        for h in hits {
            if queued.len() >= want || !seen.insert(h.hash.clone()) {
                continue;
            }
            if !name_is_acceptable(&h.name) {
                continue;
            }
            // Skip the enormous ones: this measures BREADTH of progress, and a
            // 2GB ISO cannot show progress inside the window.
            // Videos are the point of this run, so the ceiling is generous.
            // Still bounded: a 4GB file cannot show progress in the window and
            // would just soak sources.
            if h.size > 300 * 1_048_576 {
                continue;
            }
            engine.add_download(h.hash.clone(), h.size, h.name.clone());
            queued.push((h.hash, h.name, h.size, h.sources));
        }
        for _ in 0..3 {
            sleep(Duration::from_secs(1));
            engine.heartbeat();
        }
    }
    println!("  queued {} download(s)", queued.len());
    // The SEARCH-tab source count, kept so it can be compared with what the
    // engine actually connects to - Anthony's cross-tab question.
    let search_srcs: BTreeMap<String, u32> =
        queued.iter().map(|(h, _, _, s)| (h.clone(), *s)).collect();

    println!("== RUN {secs}s ==");
    let start = Instant::now();
    let mut ever_received: HashSet<String> = HashSet::new();
    let mut last_report = Instant::now();
    while start.elapsed() < Duration::from_secs(secs) {
        sleep(Duration::from_secs(1));
        engine.heartbeat();
        let _ = engine.drain_events();
        let dls = engine.downloads();
        for d in &dls {
            if d.have > 0 {
                ever_received.insert(d.hash.clone());
            }
        }
        if last_report.elapsed() >= Duration::from_secs(30) {
            last_report = Instant::now();
            let receiving = dls.iter().filter(|d| d.receiving).count();
            let total: u64 = dls.iter().map(|d| d.have).sum();
            println!(
                "  t+{:>4}s  rows={:<3} everReceived={:<3} nowReceiving={:<3} total={}",
                start.elapsed().as_secs(),
                dls.len(),
                ever_received.len(),
                receiving,
                mb(total)
            );
        }
    }

    println!("== RESULT ==");
    let dls = engine.downloads();
    let progressed = dls.iter().filter(|d| d.have > 0).count();
    println!(
        "  queued={}  rows={}  EVER received bytes={}  still zero={}",
        queued.len(),
        dls.len(),
        ever_received.len(),
        dls.len() - progressed
    );
    println!("  (under the OLD sweep this pinned near 1 regardless of how many were queued)");
    println!();
    println!("  per-download - and the CROSS-TAB comparison:");
    println!(
        "  {:<34} {:>9} {:>7} {:>5} {:>16}",
        "name", "have", "recv", "search", "connected(e/k/x)"
    );
    let mut rows: Vec<_> = dls.iter().collect();
    rows.sort_by_key(|d| std::cmp::Reverse(d.have));
    for d in rows.iter().take(40) {
        let n: String = d.name.chars().take(34).collect();
        println!(
            "  {:<34} {:>9} {:>7} {:>5} {:>4}/{:>4}/{:>4}",
            n,
            mb(d.have),
            if d.receiving { "yes" } else { "-" },
            search_srcs.get(&d.hash).copied().unwrap_or(0),
            d.sources_server,
            d.sources_kad,
            d.sources_exchange
        );
    }
    println!();
    println!("  NOTE on the cross-tab columns: 'search' is what the SERVER INDEX");
    println!("  claimed at search time (aggregate, often stale); the connected");
    println!("  triple is what padMule actually reached. They measure different");
    println!("  things, so a gap is expected - a gap of 'search says 20, we reach");
    println!("  0, repeatedly' is the interesting case.");
    engine.shutdown();
}
