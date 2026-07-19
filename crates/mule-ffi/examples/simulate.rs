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

    screen("START + CONNECT (poll like the 1s timer)");
    engine.start();
    for tick in 1..=6 {
        sleep(Duration::from_secs(1));
        println!("-- tick {tick} --");
        drain(&engine);
        render_status(&engine);
    }

    screen(&format!("SEARCH \"{keyword}\" (server + Kad)"));
    let filters = SearchFilters {
        complete_only: false,
        min_size: 0,
        max_size: 0,
        global: false,
    };
    let hits = engine.search(keyword.clone(), filters);
    println!("{} result(s):", hits.len());
    for (i, h) in hits.iter().take(8).enumerate() {
        render_hit(i, h);
    }

    // Drive the download + transfers + stats + preview + related flows on the top
    // hit, exactly as tapping a result would.
    if let Some(h) = hits.first() {
        screen("GET (add_download) + TRANSFERS");
        match engine.add_download(h.hash.clone(), h.size, h.name.clone()) {
            AddOutcome::Started => println!("add_download: Started"),
            AddOutcome::AlreadyAdded => println!("add_download: AlreadyAdded"),
            AddOutcome::NoSources => println!("add_download: NoSources"),
            AddOutcome::NoServer => println!("add_download: NoServer"),
            AddOutcome::Rejected { reason } => println!("add_download: Rejected ({reason})"),
        }
        for tick in 1..=4 {
            sleep(Duration::from_secs(1));
            println!("-- tick {tick} --");
            drain(&engine);
            let dls = engine.downloads();
            if dls.is_empty() {
                println!("  (no active transfers)");
            }
            for d in &dls {
                render_transfer(d);
            }
        }

        screen("PREVIEW (set_preview + snapshot)");
        let on = engine.set_preview(h.hash.clone(), true);
        let snap = format!("{downloads}/preview-sim.dat");
        let n = engine.preview_snapshot(h.hash.clone(), snap.clone());
        println!("set_preview={on}; snapshot wrote {} to {snap}", mib(n));
        engine.set_preview(h.hash.clone(), false);

        screen("RELATED SEARCH (server related:: feature)");
        let related = engine.related_search(h.hash.clone());
        println!(
            "{} related result(s) (empty if the server lacks related-search)",
            related.len()
        );
        for (i, r) in related.iter().take(5).enumerate() {
            render_hit(i, r);
        }
    }

    screen("STATISTICS (transfer_stats)");
    let st = engine.transfer_stats();
    println!("down: {}   up: {}", mib(st.total_down), mib(st.total_up));

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
