import SwiftUI
import XCTest

@testable import padMule

/// Layout guard for the VPN badge, and a rendered record of BOTH states.
///
/// WHY A RENDER TEST AT ALL. On 2026-08-07 the badge shipped reading
/// ". . .   . . ." - "ON" and "VPN" each truncated to an ellipsis - and nothing
/// automated saw it, because its accessibility label read "VPN on" the whole
/// time. Every assertion padMule had was against the accessibility tree, and the
/// tree was correct while the screen was wrong. Only a human eye caught it.
///
/// WHY RENDERING THE BADGE ALONE WOULD BE VACUOUS, which is the part worth
/// keeping. `fixedSize()` only does anything when the parent proposes a width
/// SMALLER than the ideal one. Rendered on its own the badge is always offered
/// its ideal size, so a lone snapshot passes with the fix deleted - the exact
/// green-test-that-cannot-fail this project keeps running into. The defect lives
/// in the PROPOSAL, so the test has to make one: `ImageRenderer.proposedSize` is
/// precisely the mechanism a ToolbarItem uses to squeeze its content, so the
/// squeeze is reproduced rather than imitated.
final class VpnBadgeTests: XCTestCase {
    /// Render `view` under a width proposal and return the resulting size.
    /// `nil` width means "propose nothing", i.e. let it take its ideal size.
    @MainActor
    private func renderedSize<V: View>(_ view: V, proposedWidth: CGFloat?) -> CGSize {
        let renderer = ImageRenderer(content: view)
        renderer.scale = 1
        renderer.proposedSize = ProposedViewSize(width: proposedWidth, height: nil)
        return renderer.uiImage?.size ?? .zero
    }

    /// Attach a PNG of each state to the test results, so CI carries a visual
    /// record of what the badge actually looks like on every run. An assertion
    /// says a number is right; this says what a person would see.
    @MainActor
    private func attach<V: View>(_ view: V, named name: String) {
        let renderer = ImageRenderer(content: view)
        renderer.scale = 3
        guard let image = renderer.uiImage, let png = image.pngData() else {
            XCTFail("could not render \(name)")
            return
        }
        let a = XCTAttachment(data: png, uniformTypeIdentifier: "public.png")
        a.name = name
        a.lifetime = .keepAlways
        add(a)
    }

    /// THE GUARD. Under a proposal far narrower than it needs, the badge must
    /// still take its ideal width - that is what `fixedSize()` buys, and the
    /// toolbar makes exactly this proposal.
    ///
    /// MUTATION CHECK: delete `.fixedSize()` from `VpnBadge` and the squeezed
    /// width collapses toward 20, failing here. Both states are checked because
    /// "OFF VPN" is the wider string and therefore the one with more to lose.
    @MainActor
    func testTheBadgeRefusesToBeSqueezedBelowItsIdealWidth() {
        for on in [true, false] {
            let state = on ? "ON" : "OFF"
            let ideal = renderedSize(VpnBadge(on: on), proposedWidth: nil)
            let squeezed = renderedSize(VpnBadge(on: on), proposedWidth: 20)

            XCTAssertGreaterThan(
                ideal.width, 20,
                "\(state): the badge's ideal width is under the squeeze width, so "
                    + "this test cannot discriminate - pick a narrower proposal")
            XCTAssertEqual(
                squeezed.width, ideal.width, accuracy: 1.0,
                "\(state): squeezed to 20pt the badge rendered \(squeezed.width)pt "
                    + "against an ideal \(ideal.width)pt - it accepted the proposal "
                    + "and its text will truncate, which is how it shipped reading "
                    + "'... ...' in the toolbar")
        }
    }

    /// "OFF VPN" is one character longer than "ON VPN", so it must render WIDER.
    /// If both states ever report the same width, the label has stopped driving
    /// the layout - which is what a collapsed or truncated badge looks like.
    @MainActor
    func testTheOffStateIsWiderBecauseItsLabelIsLonger() {
        let onWidth = renderedSize(VpnBadge(on: true), proposedWidth: nil).width
        let offWidth = renderedSize(VpnBadge(on: false), proposedWidth: nil).width
        XCTAssertGreaterThan(
            offWidth, onWidth,
            "\"OFF VPN\" (\(offWidth)pt) is not wider than \"ON VPN\" (\(onWidth)pt), "
                + "so the text is no longer setting the badge's size")
    }

    /// BOTH STATES, RENDERED, on every CI run - including inside a real toolbar,
    /// which is the context the defect actually appeared in. No assertion: this
    /// is the visual record, and it is here because the OFF state had never once
    /// been looked at (it needs a tunnel to be DOWN on a real device to appear).
    @MainActor
    func testRenderBothStatesForTheRecord() {
        attach(VpnBadge(on: true).padding(8), named: "vpn-badge-ON")
        attach(VpnBadge(on: false).padding(8), named: "vpn-badge-OFF")
        attach(
            NavigationStack {
                Text("content")
                    .toolbar {
                        ToolbarItem(placement: .navigationBarLeading) { VpnBadge(on: false) }
                    }
            }
            .frame(width: 500, height: 120),
            named: "vpn-badge-OFF-in-toolbar")
    }
}
