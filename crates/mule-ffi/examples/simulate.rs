//! Hands-on APP SIMULATION: drive the REAL `MuleEngine` FFI object through the
//! same call sequence the SwiftUI `EngineModel` makes, rendering each "screen" as
//! text. It is a hands-on review of the on-device experience WITHOUT a device -
//! the iPad shell is a thin layer over exactly these FFI calls, so exercising them
//! against a live server/oracle reproduces what a user would see and do.
//!
//! Usage:
//!   cargo run -p mule-ffi --example simulate -- <config_dir> <downloads_dir> <keyword>
//!
//! `config_dir` should hold a `server.met` (+ optional `nodes.dat`) so the engine
//! connects to a real eD2k/Kad backend; see `scripts/simulate.sh`.

use mule_ffi::{
    AddOutcome, DownloadInfo, EngineEventFfi, EngineStateFfi, MuleEngine, SearchFilters, SearchHit,
};
use std::thread::sleep;
use std::time::Duration;

fn screen(title: &str) {
    println!("\n================= {title} =================");
}

fn mib(bytes: u64) -> String {
    format!("{:.2} MiB", bytes as f64 / (1024.0 * 1024.0))
}

fn state_str(s: EngineStateFfi) -> &'static str {
    match s {
        EngineStateFfi::Stopped => "Stopped",
        EngineStateFfi::Running => "Running",
        EngineStateFfi::Paused => "Paused",
    }
}

/// Drain + print the event log, exactly what the app's notice/status rows show.
fn drain(engine: &MuleEngine) {
    for e in engine.drain_events() {
        match e {
            EngineEventFfi::State { state } => println!("   [event] state -> {}", state_str(state)),
            EngineEventFfi::Status { text } => println!("   [event] status: {text}"),
            EngineEventFfi::Server { text } => println!("   [event] server: {text}"),
            EngineEventFfi::ServerDropped { addr } => {
                println!("   [event] SERVER DROPPED: {addr}")
            }
            EngineEventFfi::Kad { contacts } => println!("   [event] kad: {contacts} contacts"),
            EngineEventFfi::Progress { hash, have, total } => println!(
                "   [event] progress {}: {} / {}",
                &hash[..8.min(hash.len())],
                mib(have),
                mib(total)
            ),
        }
    }
}

/// The Status screen: the durable connection snapshot the app polls every second.
fn render_status(engine: &MuleEngine) {
    println!("state:   {}", state_str(engine.state()));
    match engine.server_info() {
        Some(s) => println!(
            "server:  {} ({}){}",
            s.addr,
            if s.low_id { "LowID" } else { "HighID" },
            if s.related_search {
                "  [related-search supported]"
            } else {
                ""
            }
        ),
        None => println!("server:  not connected"),
    }
    println!("kad:     {} contacts", engine.kad_contacts());
    println!(
        "sharing: {}",
        if engine.is_sharing() {
            "ON"
        } else {
            "OFF (Leech Mode)"
        }
    );
}

fn render_hit(i: usize, h: &SearchHit) {
    println!(
        "  {:>2}. {}\n      {} | {} src{} | type={} | {}{}",
        i + 1,
        h.name,
        mib(h.size),
        h.sources,
        if h.complete_sources > 0 {
            format!(" ({} complete)", h.complete_sources)
        } else {
            String::new()
        },
        if h.file_type.is_empty() {
            "?"
        } else {
            &h.file_type
        },
        if h.trusted { "ok" } else { "SUSPECT" },
        if h.warning.is_empty() {
            String::new()
        } else {
            format!(" ({})", h.warning)
        },
    );
}

fn render_transfer(d: &DownloadInfo) {
    let pct = if d.size > 0 {
        (d.have as f64 / d.size as f64) * 100.0
    } else {
        0.0
    };
    let prio = ["Low", "Normal", "High"]
        .get(d.priority as usize)
        .copied()
        .unwrap_or("?");
    println!(
        "  {} - {}/{} ({:.1}%) prio={}{}{}",
        d.name,
        mib(d.have),
        mib(d.size),
        pct,
        prio,
        if d.complete { " [COMPLETE]" } else { "" },
        if d.preview {
            format!(" [preview, {} playable]", mib(d.contiguous_prefix))
        } else {
            String::new()
        },
    );
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let config = a
        .get(1)
        .cloned()
        .unwrap_or_else(|| "/tmp/sim-config".into());
    let downloads = a.get(2).cloned().unwrap_or_else(|| "/tmp/sim-dl".into());
    let keyword = a.get(3).cloned().unwrap_or_else(|| "ubuntu".into());
    let _ = std::fs::create_dir_all(&config);
    let _ = std::fs::create_dir_all(&downloads);

    screen("BOOT (EngineModel.boot)");
    let engine = match MuleEngine::new(config.clone(), downloads.clone()) {
        Ok(e) => e,
        Err(e) => {
            println!("engine failed to construct: {e}");
            return;
        }
    };
    let id = engine.identity();
    println!("userhash: {}", id.userhash);
    println!("kad id:   {}", id.kad_id);
    println!("config:   {config}");

    screen("START (no auto-connect - eMule behavior)");
    engine.start();
    for tick in 1..=4 {
        sleep(Duration::from_secs(1));
        drain(&engine);
        if tick == 4 {
            render_status(&engine);
        }
    }

    screen("SERVERS (probe server.met, then user-picks a live one)");
    let servers = engine.server_list();
    println!("{} server(s):", servers.len());
    for s in servers.iter().take(8) {
        println!(
            "  {}  users={} files={} alive={} connected={}",
            if s.name.is_empty() {
                s.addr.clone()
            } else {
                s.name.clone()
            },
            s.users,
            s.files,
            s.alive,
            s.connected
        );
    }
    if let Some(live) = servers.iter().find(|s| s.alive) {
        println!("-> connecting to the live server {} ...", live.addr);
        let ok = engine.connect_to_server(live.addr.clone());
        sleep(Duration::from_secs(1));
        drain(&engine);
        println!("connect_to_server={ok}");
        render_status(&engine);
    } else {
        println!("(no live server answered the probe)");
    }

    let filters = || SearchFilters {
        complete_only: false,
        min_size: 0,
        max_size: 0,
        global: false,
    };

    screen(&format!("SEARCH \"{keyword}\" (server + Kad)"));
    let hits = engine.search(keyword.clone(), filters());
    println!("{} result(s):", hits.len());
    for (i, h) in hits.iter().take(6).enumerate() {
        render_hit(i, h);
    }

    // Boolean expression: the keyword is parsed into an AND/OR/NOT tree for the
    // SERVER query (Kad matches the raw keyword string), end to end here.
    let bexpr = format!("{keyword} NOT zzqnomatch");
    screen(&format!("BOOLEAN SEARCH \"{bexpr}\""));
    println!("{} result(s)", engine.search(bexpr, filters()).len());

    // Global search: also fan the query across the whole serverlist over UDP.
    screen(&format!(
        "GLOBAL SEARCH \"{keyword}\" (filters.global = true)"
    ));
    let gfilters = SearchFilters {
        global: true,
        ..filters()
    };
    println!(
        "{} result(s)",
        engine.search(keyword.clone(), gfilters).len()
    );

    // Full transfer journey on the top hit: Get -> preview bias -> watch it grow
    // -> snapshot -> stats -> priority -> related -> cancel.
    if let Some(h) = hits.first() {
        screen("GET + PREVIEW BIAS (add_download, set_preview early)");
        match engine.add_download(h.hash.clone(), h.size, h.name.clone()) {
            AddOutcome::Started => println!("add_download: Started"),
            AddOutcome::AlreadyAdded => println!("add_download: AlreadyAdded"),
            AddOutcome::NoSources => println!("add_download: NoSources"),
            AddOutcome::NoServer => println!("add_download: NoServer"),
            AddOutcome::Rejected { reason } => println!("add_download: Rejected ({reason})"),
        }
        // Preview ON from the start -> sequential block bias -> a contiguous head
        // to snapshot. Watch it accumulate over ~18s.
        engine.set_preview(h.hash.clone(), true);
        for tick in 1..=18 {
            sleep(Duration::from_secs(1));
            drain(&engine);
            if tick % 6 == 0 {
                println!("-- tick {tick} --");
                for d in &engine.downloads() {
                    render_transfer(d);
                }
            }
        }

        screen("PREVIEW SNAPSHOT (real bytes off the growing .part)");
        let ext = h
            .name
            .rsplit('.')
            .next()
            .filter(|e| e.len() <= 5)
            .unwrap_or("dat");
        let snap = format!("{downloads}/preview-sim.{ext}");
        let n = engine.preview_snapshot(h.hash.clone(), snap.clone());
        let on_disk = std::fs::metadata(&snap).map(|m| m.len()).unwrap_or(0);
        println!(
            "snapshot wrote {} ({on_disk} bytes on disk) to {snap}",
            mib(n)
        );

        screen("STATISTICS (real transfer totals)");
        let st = engine.transfer_stats();
        println!("down: {}   up: {}", mib(st.total_down), mib(st.total_up));

        screen("PRIORITY (set High, verify on the row)");
        engine.set_download_priority(h.hash.clone(), 2);
        for d in &engine.downloads() {
            render_transfer(d);
        }

        screen("RELATED SEARCH (server related:: feature)");
        let related = engine.related_search(h.hash.clone());
        println!(
            "{} related result(s) (empty with no server / a server that lacks it)",
            related.len()
        );

        screen("CANCEL (remove the download, verify it is gone)");
        let ok = engine.cancel_download(h.hash.clone());
        sleep(Duration::from_secs(1));
        drain(&engine);
        println!(
            "cancel_download={ok}; {} active download(s) now",
            engine.downloads().len()
        );
    }

    screen("LEECH MODE (set_sharing toggle)");
    engine.set_sharing(false);
    println!(
        "after set_sharing(false): sharing = {}",
        engine.is_sharing()
    );
    engine.set_sharing(true);
    println!(
        "after set_sharing(true):  sharing = {}",
        engine.is_sharing()
    );

    screen("LIFECYCLE (pause -> resume, the iPadOS backgrounding path)");
    engine.pause();
    drain(&engine);
    println!("after pause():  state = {}", state_str(engine.state()));
    engine.resume();
    for _ in 0..3 {
        sleep(Duration::from_secs(1));
        drain(&engine);
    }
    println!("after resume(): state = {}", state_str(engine.state()));
    render_status(&engine);

    screen("SHUTDOWN");
    engine.shutdown();
    println!("state = {}", state_str(engine.state()));
    println!("\nSimulation complete - every screen above was driven through the real FFI seam.");
}
