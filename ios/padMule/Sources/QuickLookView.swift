// QuickLook preview for a finished download.
//
// This is the "open it in the appropriate app" affordance. iOS will NOT let an
// app hand a `file://` URL to `UIApplication.open`, so there are only two real
// routes for a downloaded file: the share sheet (ShareLink - "send it
// somewhere") and QuickLook (open it HERE, in the system viewer). QuickLook is
// the one that matches what a user means by "open": it renders video, audio,
// PDF, images, text, archives and iWork/Office documents natively, and its own
// toolbar carries the share button for handing off to a specific app.
//
// QLPreviewController is UIKit, so it needs a representable wrapper - there is
// no SwiftUI equivalent on the iOS 16 deployment target.

import QuickLook
import SwiftUI
import UIKit

/// One file to preview. Identifiable so it can drive a `.sheet(item:)`.
struct QuickLookItem: Identifiable {
    let id: String
    let url: URL
}

struct QuickLookView: UIViewControllerRepresentable {
    let url: URL

    func makeCoordinator() -> Coordinator { Coordinator(url: url) }

    func makeUIViewController(context: Context) -> QLPreviewController {
        let c = QLPreviewController()
        c.dataSource = context.coordinator
        return c
    }

    func updateUIViewController(_ controller: QLPreviewController, context: Context) {
        // The URL is fixed for the lifetime of one sheet; reload only if the
        // coordinator was handed a different file (cheap, and keeps the
        // controller honest if SwiftUI reuses it).
        if context.coordinator.url != url {
            context.coordinator.url = url
            controller.reloadData()
        }
    }

    final class Coordinator: NSObject, QLPreviewControllerDataSource {
        var url: URL
        init(url: URL) { self.url = url }

        func numberOfPreviewItems(in controller: QLPreviewController) -> Int { 1 }

        func previewController(
            _ controller: QLPreviewController, previewItemAt index: Int
        ) -> QLPreviewItem {
            url as NSURL
        }
    }
}
