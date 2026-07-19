import SwiftUI
import UIKit

/// Full detail for one search hit: every field, the ed2k link, and actions.
struct SearchDetailView: View {
    @EnvironmentObject var model: EngineModel
    @Environment(\.dismiss) private var dismiss
    let hit: SearchHit

    private var ed2kLink: String {
        "ed2k://|file|\(hit.name)|\(hit.size)|\(hit.hash)|/"
    }

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Text(hit.name).font(.headline)
                    row("Type", hit.fileType)
                    row("Size", ByteCountFormatter.string(fromByteCount: Int64(hit.size), countStyle: .file))
                    row("Sources", "\(hit.sources)"
                        + (hit.completeSources > 0 ? " (\(hit.completeSources) complete)" : ""))
                    if hit.rating > 0 { row("Rating", ratingText(hit.rating)) }
                    if hit.lengthSecs > 0 { row("Length", "\(hit.lengthSecs)s") }
                    if hit.bitrate > 0 { row("Bitrate", "\(hit.bitrate) kbps") }
                    if !hit.codec.isEmpty { row("Codec", hit.codec) }
                    if !hit.artist.isEmpty { row("Artist", hit.artist) }
                    if !hit.album.isEmpty { row("Album", hit.album) }
                    if !hit.title.isEmpty { row("Title", hit.title) }
                    row("Hash", hit.hash)
                    if !hit.trusted {
                        Label(hit.warning, systemImage: "exclamationmark.triangle")
                            .foregroundStyle(.orange).font(.caption)
                    }
                }
                Section {
                    Button {
                        UIPasteboard.general.string = ed2kLink
                    } label: { Label("Copy ed2k link", systemImage: "doc.on.doc") }
                    Button {
                        model.download(hit)
                        dismiss()
                    } label: { Label("Download", systemImage: "arrow.down.circle") }
                    Button {
                        model.relatedSearch(hit)
                        dismiss()
                    } label: { Label("Search related", systemImage: "magnifyingglass") }
                }
            }
            .navigationTitle("Details")
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
        }
    }

    private func ratingText(_ rating: UInt8) -> String {
        switch rating {
        case 1: return "Fake / Invalid"
        case 2: return "Poor"
        case 3: return "Fair"
        case 4: return "Good"
        default: return "Excellent"
        }
    }

    private func row(_ k: String, _ v: String) -> some View {
        HStack {
            Text(k).foregroundStyle(.secondary)
            Spacer()
            Text(v).multilineTextAlignment(.trailing)
        }
        .font(.callout)
    }
}
