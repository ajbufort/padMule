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
                // Hold the splash until the engine is actually READY, not for a
                // fixed 7s. The original intent was to cover the boot; the bug was
                // that boot takes 12-30s (two HTTP fetches, the always-failing
                // multicast SSDP probe, unicast + SOAP, then Kad), so a fixed
                // delay reliably cleared EARLY and left a live-looking, inert UI.
                //
                // Bounded on both sides: a MINIMUM so the brand does not flash past
                // on a warm start, and a CEILING so a hung boot or a boot FAILURE
                // can never trap the user behind the splash - past it the
                // "Starting padMule..." banner takes over the explaining.
                let start = Date()
                let minimum: TimeInterval = 2.5
                let ceiling: TimeInterval = 20
                while Date().timeIntervalSince(start) < ceiling {
                    if model.ready || model.bootError != nil,
                       Date().timeIntervalSince(start) >= minimum {
                        break
                    }
                    try? await Task.sleep(nanoseconds: 150_000_000)
                }
                withAnimation(.easeOut(duration: 0.35)) { showSplash = false }
            }
        }
        // Single-parameter onChange is deprecated in iOS 17 but is the correct
        // form for our iOS 16 deployment target; the two-parameter overload does
        // not exist on 16. Keep as-is until the target moves past 16.
        .onChange(of: scenePhase) { phase in
            switch phase {
            case .active:
                // Retry a failed cold-boot on foreground (no-op once booted), THEN
                // resume; without the boot() a transient launch failure was terminal.
                model.boot()
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
