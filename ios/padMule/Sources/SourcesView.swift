// The per-source detail for one download: who we are pulling it from, and what
// each source told us - client software, whether the link is encrypted, its
// HighID/LowID, whether we verified its identity, and its rating/comment.

import SwiftUI

struct SourcesView: View {
    @EnvironmentObject var model: EngineModel
    @Environment(\.dismiss) private var dismiss
    let download: DownloadInfo
    @State private var sources: [SourceInfoFfi] = []

    var body: some View {
        NavigationStack {
            List {
                if sources.isEmpty {
                    Text("No sources connected yet. Sources appear as padMule reaches them.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(sources, id: \.addr) { s in
                        sourceRow(s)
                    }
                }
            }
            .navigationTitle("Sources")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                // Refresh is an action, not a cancel/dismiss - keep it out of the
                // leading .cancellationAction slot (that role reads as "Cancel").
                ToolbarItem(placement: .navigationBarLeading) {
                    Button {
                        reload()
                    } label: {
                        Label("Refresh", systemImage: "arrow.clockwise")
                    }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
            .onAppear(perform: reload)
        }
    }

    private func sourceRow(_ s: SourceInfoFfi) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack(spacing: 6) {
                Text(s.software.isEmpty ? "Unknown client" : s.software)
                    .font(.callout)
                if s.obfuscated {
                    Image(systemName: "lock.fill").font(.caption2).foregroundStyle(.green)
                }
                if s.verified {
                    Image(systemName: "checkmark.seal.fill").font(.caption2).foregroundStyle(.blue)
                }
                if s.lowId {
                    Text("LowID").font(.caption2).foregroundStyle(.orange)
                }
                Spacer()
                if s.rating > 0 { ratingPill(s.rating) }
            }
            Text(s.addr).font(.caption).foregroundStyle(.secondary)
            if let queue = SourcesView.queueRankLabel(
                rank: s.queueRank, ageSecs: s.queueRankAgeSecs)
            {
                Text(queue).font(.caption).foregroundStyle(.secondary)
            }
            if !s.comment.isEmpty {
                Text("\u{201C}\(s.comment)\u{201D}")
                    .font(.caption)
                    .italic()
                    .foregroundStyle(.secondary)
            }
        }
    }

    /// The queue-position line for one source, or nil when there is nothing
    /// honest to say. PURE (pinned by `QueueRankLabelTests`) so the rule and
    /// the row cannot drift.
    ///
    /// eMule 0.70b shows "QR: n" beside a source while we sit on its queue
    /// (DownloadListCtrl.cpp:513-518), and can say it PRESENT-TENSE because it
    /// separately guarantees the number is fresh: every on-queue source is
    /// re-asked at FILEREASKTIME = 29 minutes (Opcodes.h:64) or dropped from
    /// the list. padMule's fetch sweep makes no such promise - a rank can be
    /// captured at bail time and never refreshed - so the invariant crosses
    /// over instead of the surface: the label names the snapshot's age, and
    /// past eMule's own freshness horizon it says nothing at all, because by
    /// then eMule would have refreshed the number or given up on the source,
    /// and showing it would claim knowledge we no longer have.
    ///
    /// Rank 0 is "never told / cleared" - eMule's own unknown encoding, which
    /// it also renders as nothing.
    static func queueRankLabel(rank: UInt16, ageSecs: UInt32) -> String? {
        guard rank > 0, ageSecs < 29 * 60 else { return nil }
        let when = ageSecs < 60 ? "just now" : "\(ageSecs / 60)m ago"
        return "In queue: #\(rank) (\(when))"
    }

    private func ratingPill(_ rating: UInt8) -> some View {
        let (label, color): (String, Color) = {
            switch rating {
            case 1: return ("Fake", .red)
            case 2: return ("Poor", .orange)
            case 3: return ("Fair", .yellow)
            case 4: return ("Good", .green)
            default: return ("Excellent", .green)
            }
        }()
        return Text(label)
            .font(.caption2)
            .padding(.horizontal, 5).padding(.vertical, 1)
            .background(color.opacity(0.2)).foregroundStyle(color)
            .clipShape(Capsule())
    }

    private func reload() {
        model.sources(for: download.hash) { sources = $0 }
    }
}

/// The hash identifies a download uniquely - enough for an item-based sheet.
extension DownloadInfo: Identifiable {
    public var id: String { hash }
}
