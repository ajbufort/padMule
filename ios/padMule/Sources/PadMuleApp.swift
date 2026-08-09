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
    @StateObject private var network = NetworkWatcher()
    @Environment(\.scenePhase) private var scenePhase
    @State private var showSplash = true
    /// Read HERE, at the root, so the pinned scheme covers the splash and every
    /// sheet - Settings, the search detail, QuickLook - rather than only the
    /// screen that happens to declare it. @AppStorage re-renders on change, so
    /// flipping the switch in Settings repaints the app immediately.
    @AppStorage(SettingsKey.darkMode) private var darkMode = false

    init() {
        // Register setting DEFAULTS before any view reads them, so a first launch
        // behaves as intended (sharing on, metered-pause on) rather than as the
        // false/zero UserDefaults returns for absent keys.
        SettingsDefaults.register()
    }

    var body: some Scene {
        WindowGroup {
            ZStack {
                ContentView()
                    .environmentObject(model)
                    .onAppear { model.boot() }
                    // Feed the metered verdict in, so sharing can pause on a
                    // cellular/hotspot/Low-Data link. onChange also fires for the
                    // first value the monitor delivers.
                    .onChange(of: network.isMetered) { metered in
                        model.setMetered(metered)
                    }
                    // Same pattern for the VPN verdict: the watcher owns the
                    // path facts, the model owns what the UI does about them.
                    // onChange also delivers the monitor's FIRST value, so the
                    // badge is correct on a launch that starts with a VPN up.
                    .onChange(of: network.vpnActive) { active in
                        model.setVpnActive(active)
                    }
                if showSplash {
                    SplashView().transition(.opacity)
                }
            }
            // PINNED, never `nil`. `nil` would inherit the system appearance,
            // which means padMule could flip to dark by itself in the middle of
            // a long transfer when the iPad crosses a scheduled sunset. An app
            // designed to sit open and on screen for hours should look the way
            // the user last set it and stay that way. Light unless chosen.
            .preferredColorScheme(darkMode ? .dark : .light)
            .task {
                // Hold the splash until the engine is actually READY, not for a
                // fixed 7s. The original intent was to cover the boot; the bug is
                // that boot time is too variable for any fixed delay - a warm
                // boot with lists on disk is ~1s, while a cold or blocked network
                // can run the boot timeouts (two HTTP fetches, the always-failing
                // multicast SSDP probe, unicast + SOAP, then Kad) out to a 12-30s
                // SUM. (That figure is the sum of the timeouts, not a
                // measurement.) So a fixed delay drags on the fast case and
                // clears early on the slow one, leaving a live-looking, inert UI.
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
                model.leaveBackground()
                // A tunnel that collapsed while padMule was suspended produces
                // no path callback we were awake to hear, and "the VPN dropped
                // while you were away" is exactly the case worth catching.
                network.refreshVpn()
            case .background:
                // Only on .background - .inactive fires for transient things
                // (app switcher, a notification) and tearing down there would
                // thrash the connection.
                // Either keep serving under a keepalive or pause honestly -
                // enterBackground() decides, and never claims the first while
                // getting the second.
                model.enterBackground()
            default:
                break
            }
        }
    }
}
