import Charts
import SwiftUI
import UIKit  // UIPasteboard - the report has to be able to LEAVE the device

/// One per-second sample of transfer rate (bytes/sec), the unit StatsView charts.
struct RatePoint: Identifiable {
    let id: Int
    let down: Double
    let up: Double
}

/// Session transfer statistics: a live down/up rate chart over the last ~60s,
/// the session byte totals, and the up:down ratio. Everything is derived
/// client-side by sampling the engine's monotonic byte totals each poll (see
/// EngineModel.sampleStats) - the engine only counts bytes, zero wire risk.
struct StatsView: View {
    @EnvironmentObject var model: EngineModel

    private var currentDown: Double { model.rateHistory.last?.down ?? 0 }
    private var currentUp: Double { model.rateHistory.last?.up ?? 0 }

    var body: some View {
        List {
            Section("Transfer rate") {
                if model.rateHistory.count < 2 {
                    Text("Waiting for transfer activity...")
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, alignment: .center)
                        .padding(.vertical, 24)
                } else {
                    // `ratePlot`, not `rateHistory`: a fixed 60-point span with
                    // the newest sample pinned to the right edge, so the trace
                    // uses the whole width instead of being scaled to whatever
                    // few samples happen to be buffered.
                    Chart(model.ratePlot) { p in
                        LineMark(x: .value("Time", p.id), y: .value("Rate", p.down))
                            .foregroundStyle(by: .value("Direction", "Down"))
                        LineMark(x: .value("Time", p.id), y: .value("Rate", p.up))
                            .foregroundStyle(by: .value("Direction", "Up"))
                    }
                    .chartForegroundStyleScale(["Down": Color.blue, "Up": Color.green])
                    .chartXScale(domain: 0...(EngineModel.rateWindow - 1))
                    .chartXAxis(.hidden)
                    .chartPlotStyle { plot in
                        plot.frame(maxWidth: .infinity)
                    }
                    .chartYAxis {
                        AxisMarks { value in
                            AxisGridLine()
                            AxisValueLabel {
                                if let bytes = value.as(Double.self) {
                                    Text(rateText(bytes))
                                }
                            }
                        }
                    }
                    .frame(height: 180)

                    HStack {
                        rateBadge("Down", currentDown, .blue)
                        Spacer()
                        rateBadge("Up", currentUp, .green)
                    }
                }
            }

            Section("Session totals") {
                statRow("Downloaded", byteText(model.totalDown))
                statRow("Uploaded", byteText(model.totalUp))
                statRow("Ratio (up:down)", ratioText)
            }

            // THE FETCH FUNNEL. A transfer that shows sources but moves nothing
            // is the one problem this app cannot explain from its own screens -
            // the row says "20 sources" and 0 bytes, and there is nowhere to see
            // WHY. This panel is that missing view: how far down the eD2k
            // request sequence each peer session got, so a stall can be
            // attributed to a stage instead of guessed at.
            //
            // It stays live without a refresh button because the 1s stats poll
            // republishes `rateHistory`, re-rendering this body; the engine side
            // is lock-free, so reading it never queues behind a busy engine.
            Section("UI responsiveness") {
                Text(
                    "The status poll is lock-free; the heartbeat needs the engine lock. During a long operation (a search) the first should keep climbing and the second should stall - that gap IS the contention, visible without guessing."
                )
                .font(.caption)
                .foregroundStyle(.secondary)
                LabeledContent("Status polls (lock-free)", value: "\(model.uiPollTicks)")
                LabeledContent("Heartbeats (takes the lock)", value: "\(model.heartbeatTicks)")
                // THE ONE THE COUNTS CANNOT GIVE YOU. Their queue is serial, so a
                // poll that blocks does not lose its ticks - they queue up and all
                // land at once, and the total over any window that outlasts the
                // stall is unchanged. Read this row, not the counts, to answer
                // "did the poll actually keep running": near 1s means it did.
                LabeledContent(
                    "Longest poll gap",
                    value: String(format: "%.1fs", model.uiPollMaxGapSecs))
            }

            // THE KAD LOOKUP PROFILE. A search's remaining cost is the Kad arm,
            // and the arm's cost is one of two things: the round trips a lookup
            // genuinely needs, or batch windows held open by peers that never
            // answer. Those call for opposite responses - the first is
            // irreducible, the second is fixed by removing the round barrier -
            // and from outside they look identical. This panel tells them apart.
            Section("Kad lookup") {
                Text(
                    "A lookup round ends when its last peer answers, or at the per-query deadline if one never does. If \"with a SILENT peer\" is most of \"rounds run\", the rounds are paying full timeouts and the barrier is the cost; if it is small, the cost is the round trips the lookup genuinely needs."
                )
                .font(.caption)
                .foregroundStyle(.secondary)

                Text(model.kadReport)
                    .font(.system(.caption2, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }

            Section("Fetch diagnostics") {
                Text(
                    "Where peer sessions die on the way to bytes. Counts are cumulative since launch, or since you last reset them."
                )
                .font(.caption)
                .foregroundStyle(.secondary)

                Text(model.fetchReport)
                    .font(.system(.caption2, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)

                HStack {
                    Button {
                        // BOTH panels. They share one Reset, so a report carrying
                        // only half of what that Reset cleared would be read as
                        // covering the whole experiment.
                        UIPasteboard.general.string =
                            "KAD LOOKUP\n\(model.kadReport)\nFETCH FUNNEL\n\(model.fetchReport)"
                        model.notice = "Diagnostic report copied to the clipboard."
                    } label: {
                        Label("Copy report", systemImage: "doc.on.doc")
                    }
                    Spacer()
                    Button {
                        model.resetFetchStats()
                    } label: {
                        Label("Reset counters", systemImage: "arrow.counterclockwise")
                    }
                }
                .buttonStyle(.borderless)
                .font(.callout)
            }
        }
    }

    private var ratioText: String {
        guard model.totalDown > 0 else { return "-" }
        let r = Double(model.totalUp) / Double(model.totalDown)
        return String(format: "%.2f : 1", r)
    }

    private func rateBadge(_ label: String, _ bytesPerSec: Double, _ color: Color) -> some View {
        HStack(spacing: 6) {
            Circle().fill(color).frame(width: 8, height: 8)
            Text(label).foregroundStyle(.secondary)
            Text(rateText(bytesPerSec)).monospacedDigit()
        }
        .font(.callout)
    }

    private func statRow(_ k: String, _ v: String) -> some View {
        HStack {
            Text(k).foregroundStyle(.secondary)
            Spacer()
            Text(v).monospacedDigit()
        }
        .font(.callout)
    }

    private func byteText(_ bytes: UInt64) -> String {
        // clamping: a hostile size > Int64.max would TRAP a plain Int64() init.
        ByteCountFormatter.string(fromByteCount: Int64(clamping: bytes), countStyle: .file)
    }

    private func rateText(_ bytesPerSec: Double) -> String {
        // Guard NaN/Inf and the out-of-range case (Double(Int64.max) rounds UP and
        // traps), so a degenerate rate cannot crash the UI. 9e18 is well under max.
        let clamped = bytesPerSec.isFinite ? min(max(bytesPerSec, 0), 9.0e18) : 0
        let b = Int64(clamped)
        return ByteCountFormatter.string(fromByteCount: b, countStyle: .file) + "/s"
    }
}
