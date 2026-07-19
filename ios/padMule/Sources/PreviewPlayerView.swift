import AVKit
import SwiftUI

/// One incomplete-file preview: a snapshot of the contiguous-from-start prefix on
/// disk, the display name, and the download hash (so we can turn preview mode off
/// again on dismiss). Identifiable so it drives a `.sheet(item:)`.
struct PreviewItem: Identifiable {
    let id = UUID()
    let url: URL
    let name: String
    let hash: String
}

/// Plays a snapshot of an incomplete download with AVPlayer. The snapshot is a
/// finite copy of the bytes downloaded so far, so playback simply ends where the
/// data ends; re-opening Preview snapshots more of the (still-growing) file.
struct PreviewPlayerView: View {
    @EnvironmentObject var model: EngineModel
    @Environment(\.dismiss) private var dismiss
    let item: PreviewItem
    @State private var player: AVPlayer
    @State private var message: String?

    init(item: PreviewItem) {
        self.item = item
        _player = State(initialValue: AVPlayer(url: item.url))
    }

    var body: some View {
        NavigationStack {
            ZStack {
                VideoPlayer(player: player)
                    .ignoresSafeArea(edges: .bottom)
                if let message {
                    Text(message)
                        .multilineTextAlignment(.center)
                        .padding()
                        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 12))
                        .padding()
                }
            }
            .navigationTitle(item.name)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
            .onAppear { player.play() }
            .onDisappear {
                player.pause()
                // Revert to rarest-first block selection once previewing stops, so
                // a single Preview tap doesn't disable it for the whole session.
                model.stopPreview(item.hash)
            }
            .task {
                // If the snapshot is not yet a playable container (e.g. a
                // non-faststart file whose moov atom is at the END and not
                // downloaded yet), AVPlayer's item goes to .failed - tell the user
                // rather than leave a black screen.
                for _ in 0..<12 {
                    try? await Task.sleep(nanoseconds: 300_000_000)
                    if player.currentItem?.status == .failed {
                        message = "Not enough of this file has downloaded to play yet. "
                            + "Preview keeps downloading it from the start - try again shortly."
                        break
                    }
                }
            }
        }
    }
}
