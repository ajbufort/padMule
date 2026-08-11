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
                    Text("padMule only runs while it is open and on screen. iPadOS suspends apps you switch away from, so transfers pause when you leave and pick up when you come back. One exception: with \"Keep sharing in the background\" on in Settings, uploads keep going for a while after you leave - downloads still pause.")
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
                    Text("A row can also carry a badge. Done means finished and verified. Paused means you paused it. Stopped means you stopped it - the difference is explained below. Queued means it is waiting for a download slot, because you have set a limit on how many run at once.")
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
                } footer: {
                    Text("")
                }

                Section {
                    Text("Long-press a transfer for Pause, Stop and Priority. Swipe it for Remove. The three are not the same thing and the difference matters.")
                    Text("Pause simply halts the download. It keeps everything, including the peers it already found, and picks up where it left off.")
                    Text("Stop halts it AND lets go of those peers, so padMule stops asking the network about that file. Your progress is kept - Stop is not Remove. Use it when you want a download to go quiet without losing it.")
                    Text("Remove deletes the download and the partly-downloaded data with it. That cannot be undone.")
                } header: {
                    Text("Pause, Stop and Remove")
                }

                Section {
                    Text("Your progress is saved as it arrives, not only when a download finishes. If padMule is closed, crashes, or the iPad restarts, the next start picks up where it left off instead of starting the file again.")
                    Text("padMule plays a short sound when a download finishes, verifies and is saved. You can turn it off in Settings.")
                } header: {
                    Text("Progress is saved")
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
                    Text("On the Shared screen, swipe a file for Unshare or Delete. Unshare stops serving it and leaves the file on your iPad. Delete removes it from your iPad as well, and asks first.")
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
                    Text("Incognito stops padMule identifying itself to other clients. It is ON by default. padMule already reports itself as aMule 3.0.1, and Incognito removes what is left: a padMule marker in the handshake, and the default nickname.")
                    Text("It does NOT make you anonymous, and it is not a VPN. It hides what padMule says about itself, not how it behaves - anyone looking closely can still tell. Your address is as visible as it always was.")
                    Text("Who can see your shared files controls whether another client can list everything you share just by asking. It is set to Nobody by default, which is what eMule defaults to as well. Downloads still in progress are never listed either way.")
                    Text("Both are in Settings, under Privacy.")
                } header: {
                    Text("Privacy")
                }

                Section {
                    row("Transfers", "What is downloading now. Swipe to remove, long-press to pause or resume a file, set priority, or preview a video before it finishes.")
                    row("Shared", "What you are serving to others. Swipe a file to Unshare or Delete it; tap it to rate and comment, which downloaders can see.")
                    row("Stats", "Transfer rates and session totals.")
                    row("Settings", "Sharing and privacy, server lists, ports and VPN, background seeding, default priority, how many downloads run at once, and the finish sound.")
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
