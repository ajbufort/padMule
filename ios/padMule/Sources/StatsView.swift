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
                    Chart(model.rateHistory) { p in
                        LineMark(x: .value("Time", p.id), y: .value("Rate", p.down))
                            .foregroundStyle(by: .value("Direction", "Down"))
                        LineMark(x: .value("Time", p.id), y: .value("Rate", p.up))
                            .foregroundStyle(by: .value("Direction", "Up"))
                    }
                    .chartForegroundStyleScale(["Down": Color.blue, "Up": Color.green])
                    .chartXAxis(.hidden)
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
                        UIPasteboard.general.string = model.fetchReport
                        model.notice = "Fetch report copied to the clipboard."
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
