// padMule - the iPad shell over the Rust eD2k/Kad engine.
//
// The load-bearing bit here is ScenePhase -> engine pause()/resume(). iPadOS
// suspends a backgrounded app and reclaims its sockets, so the engine is
// foreground-only by design and we drive that transition explicitly rather than
// pretending transfers continue. See docs/wiki/lifecycle-and-reactivation.md.

import SwiftUI

@main
struct PadMuleApp: App {
    @StateObject private var model = EngineModel()
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(model)
                .onAppear { model.boot() }
        }
        .onChange(of: scenePhase) { phase in
            switch phase {
            case .active:
                model.resume()
            case .background:
                // Only on .background - .inactive fires for transient things
                // (app switcher, a notification) and tearing down there would
                // thrash the connection.
                model.pause()
            default:
                break
            }
        }
    }
}
