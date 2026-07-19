import Charts
import SwiftUI

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
        ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .file)
    }

    private func rateText(_ bytesPerSec: Double) -> String {
        let b = max(0, Int64(bytesPerSec))
        return ByteCountFormatter.string(fromByteCount: b, countStyle: .file) + "/s"
    }
}
