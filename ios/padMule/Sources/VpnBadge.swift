import SwiftUI

/// The VPN indicator in the navigation bar's leading slot.
///
/// Extracted from `ContentView` on 2026-08-07 so it can be RENDERED IN A TEST.
/// It was a private computed property reading `model.vpnActive`, which meant the
/// only way to see either state was to have a tunnel in that state on a real
/// device - and the OFF state had therefore never been looked at.
///
/// padMule is a P2P client whose user has deliberately put it behind a tunnel,
/// and "no badge" is a terrible way to learn the tunnel is gone.
///
/// Word order is ON/OFF FIRST, as specified - it is the part that changed, so it
/// reads first.
///
/// NOT a safety guarantee: it reports a tunnel INTERFACE, not that padMule's
/// packets traverse it (see `NetworkWatcher.vpnIsUp`). The real leak defence is
/// the public-address-change guard.
struct VpnBadge: View {
    let on: Bool

    private var tint: Color { on ? Color.vpnBlue : Color.vpnRed }

    var body: some View {
        HStack(spacing: 3) {
            Text(on ? "ON" : "OFF")
            Text("VPN").strikethrough(!on, color: tint)
        }
        .font(.system(size: 11, weight: .bold, design: .rounded))
        .kerning(0.5)
        // BOTH WORDS TRUNCATED TO "..." ON DEVICE (2026-08-07, seen on glass:
        // the badge read ". . .   . . ." inside its border). A ToolbarItem is
        // free to propose its content a width smaller than the ideal one, and
        // two short Texts are exactly what it will squeeze to nothing rather
        // than push anything else around. `fixedSize` refuses that proposal;
        // `lineLimit(1)` states the intent that it is one line, so a future
        // longer label wraps nowhere silently.
        //
        // THE ACCESSIBILITY LABEL WAS CORRECT THE WHOLE TIME, which is why
        // nothing automated noticed: the tree said "VPN on" while the screen
        // said nothing of the kind. Only a human eye caught it, and only a
        // RENDER can guard it - see VpnBadgeTests.
        .lineLimit(1)
        .fixedSize()
        .foregroundStyle(tint)
        .padding(.horizontal, 4)
        .padding(.vertical, 1)
        .overlay(
            RoundedRectangle(cornerRadius: 3)
                .stroke(tint, lineWidth: 1.5)
        )
        .accessibilityLabel(on ? "VPN on" : "VPN off")
    }
}

// Both states, side by side, plus both under a DELIBERATELY TIGHT proposal -
// which is the condition that broke it. A preview of the badge on its own can
// never show the defect, because on its own it is always offered its ideal size.
#Preview("VPN badge - both states") {
    VStack(alignment: .leading, spacing: 16) {
        VpnBadge(on: true)
        VpnBadge(on: false)
        Divider()
        Text("squeezed to 20pt - must look identical to the pair above")
            .font(.caption2)
        VpnBadge(on: true).frame(width: 20)
        VpnBadge(on: false).frame(width: 20)
    }
    .padding()
}

#Preview("VPN badge - in a real toolbar") {
    NavigationStack {
        Text("content")
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) { VpnBadge(on: false) }
            }
    }
}
