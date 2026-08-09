// How to use padMule - the whole app in one scrollable screen.
//
// Written to be READ, not skimmed past: the one rule first (padMule only runs
// while it is open), then the shortest path to a downloaded file, then a
// section per screen, then the things that surprise people. Every claim here
// is behaviour the app actually has - if something changes, this changes with
// it, because a help screen that lies is worse than none.

import SwiftUI

struct HelpView: View {
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Text("padMule connects to the eD2k network - the same network as eMule and aMule - to find and download files, and to share the ones you have finished.")
                } header: {
                    Text("What it is")
                }

                Section {
                    Text("padMule only runs while it is open and on screen. iPadOS suspends apps you switch away from, so transfers pause when you leave and pick up when you come back. One exception: with \"Background seeding\" on in Settings, uploads keep going for a while after you leave - downloads still pause.")
                    Text("Leave padMule in the foreground while downloading. \"Keep screen awake while transferring\" in Settings stops the display sleeping mid-transfer, which would otherwise suspend the app.")
                } header: {
                    Text("The one rule")
                }

                Section {
                    label(1, "Servers", "Tap a server to connect. padMule does not auto-connect - you choose. If the list looks thin, use Discover more servers.")
                    label(2, "Status", "Check it says Connected, and look at ID (see below).")
                    label(3, "Search", "Type a word and search. Results come from the connected server and from Kad at the same time.")
                    label(4, "Get", "Tap Get on a result. It appears in Transfers.")
                    label(5, "Downloaded", "Finished files land here, and the folder button at the top opens the same files in the Files app.")
                } header: {
                    Text("Getting a file, start to finish")
                }

                Section {
                    Text("A transfer row turns amber while it is ACTUALLY receiving bytes. A row with no tint is registered but moving nothing right now - it may be waiting in a queue, hunting for sources, or simply have none online. That is normal on eD2k and not a fault; padMule keeps retrying.")
                } header: {
                    Text("Reading the Transfers list")
                }

                Section {
                    Text("Tapping a finished file PREVIEWS it inside padMule. padMule stays running, so anything still downloading keeps going.")
                    Text("Open hands the file to another app instead - a video opens in a video app, a PDF in a reader - full screen, as if you had opened it from the Files app. iOS has no notion of a default app per file type, so it asks which app to use; if only one can open that kind of file, that is the only choice offered.")
                    Text("Because that other app comes to the front, padMule goes to the BACKGROUND, and iPadOS pauses your transfers until you come back to it. That is the same rule as leaving padMule for any other reason - nothing is lost, and progress is saved - but it is worth knowing before you open a film halfway through a download.")
                    Text("Sharing a file to another app or service is still available from the preview's own share button.")
                } header: {
                    Text("Preview vs Open")
                }

                Section {
                    Text("Stop disconnects, saves your progress, and hands the forwarded port back to your router. Start brings padMule back without relaunching it.")
                    Text("Why it matters: iPadOS gives an app no way to quit itself, so closing padMule from the app switcher can leave the router port forwarded to a device that is no longer listening. That stale forward is what stops the port working next time. Stop first and the port is released cleanly.")
                    Text("Your downloads are always saved either way - Stop is about leaving the network tidily, not about protecting progress.")
                } header: {
                    Text("Stop and Start")
                }

                Section {
                    Text("HighID means other peers can reach you directly. Downloads are faster and you can connect to anyone.")
                    Text("LowID means they cannot, so you rely on the server to introduce you, and two LowID peers can never connect at all. It is not broken - just slower and more limited.")
                    Text("HighID needs one port open to the internet. At home padMule asks your router for it automatically (UPnP). Behind a VPN, the provider forwards a port instead - set it under Settings > Network / VPN and turn UPnP off.")
                } header: {
                    Text("HighID and LowID")
                }

                Section {
                    Text("Sharing your finished files is on by default. Peers give better queue positions to clients that share, so sharing makes your own downloads faster.")
                    Text("padMule pauses sharing on its own in two cases: on a cellular or metered network, so it does not spend your data; and if it sees your public address change, which usually means a VPN tunnel dropped. Both tell you why, and both wait for you to turn it back on. Seeing the change needs a HighID login - if a tunnel drop also costs you HighID, padMule can only warn, and the warning has a Pause sharing button for exactly that.")
                    Text("Leech Mode is simply sharing turned off.")
                } header: {
                    Text("Sharing")
                }

                Section {
                    Text("There are two networks and padMule uses both at once. Servers (eD2k) need you to connect to one. Kad has no servers - it finds peers directly, and keeps working even when no server will have you.")
                    Text("Status shows the health of each separately.")
                } header: {
                    Text("Two networks")
                }

                Section {
                    row("Transfers", "What is downloading now. Swipe to remove, long-press to set priority or preview a video before it finishes.")
                    row("Shared", "What you are serving to others. You can rate and comment on your own files, or unshare one without deleting it.")
                    row("Stats", "Transfer rates and session totals.")
                    row("Settings", "Sharing, server lists, ports and VPN, background seeding, default priority, keep-awake.")
                } header: {
                    Text("The other screens")
                }

                Section {
                    Text("Finished files are saved where the Files app can see them: On My iPad > padMule. They stay there if you delete padMule's entry from Shared - unsharing stops serving a file, it does not remove it.")
                    Text("If you delete a finished file in the Files app, padMule notices and stops offering it to peers.")
                } header: {
                    Text("Where your files are")
                }
            }
            .navigationTitle("How to use padMule")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
        }
    }

    /// A numbered step in the walkthrough.
    private func label(_ n: Int, _ title: String, _ body: String) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Text("\(n)")
                .font(.caption.monospacedDigit())
                .foregroundStyle(.secondary)
                .frame(width: 16, alignment: .trailing)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).fontWeight(.semibold)
                Text(body).font(.caption).foregroundStyle(.secondary)
            }
        }
    }

    /// A screen name and what it is for.
    private func row(_ title: String, _ body: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title).fontWeight(.semibold)
            Text(body).font(.caption).foregroundStyle(.secondary)
        }
    }
}
