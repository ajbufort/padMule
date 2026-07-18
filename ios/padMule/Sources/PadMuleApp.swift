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
    @State private var showSplash = true

    var body: some Scene {
        WindowGroup {
            ZStack {
                ContentView()
                    .environmentObject(model)
                    .onAppear { model.boot() }
                if showSplash {
                    SplashView().transition(.opacity)
                }
            }
            .task {
                // The engine boots underneath, so these 7 seconds are not dead time.
                try? await Task.sleep(nanoseconds: 7_000_000_000)
                withAnimation(.easeOut(duration: 0.35)) { showSplash = false }
            }
        }
        // Single-parameter onChange is deprecated in iOS 17 but is the correct
        // form for our iOS 16 deployment target; the two-parameter overload does
        // not exist on 16. Keep as-is until the target moves past 16.
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
