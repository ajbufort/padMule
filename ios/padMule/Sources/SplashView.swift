import SwiftUI
import UIKit

/// The launch splash: the pre-stroked padMule image centered on a clean field.
/// Loads from the app bundle (an explicit path is more robust than name lookup
/// for a loose resource). If the asset is missing, only the background shows -
/// the splash is never load-bearing.
struct SplashView: View {
    var body: some View {
        ZStack {
            Color(.systemBackground).ignoresSafeArea()
            if let image = Self.bundled {
                Image(uiImage: image)
                    .resizable()
                    .scaledToFit()
                    .frame(maxWidth: 360)
            }
        }
    }

    private static let bundled: UIImage? = {
        guard let path = Bundle.main.path(forResource: "splash", ofType: "png") else { return nil }
        return UIImage(contentsOfFile: path)
    }()
}
