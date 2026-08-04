// The Settings screen - padMule's first. A single scrolling Form, not eMule's
// 16-page property sheet: iOS convention, and half of eMule's pages are Windows
// chrome that does not exist here (docs/wiki/portability-audit.md lists what is
// deliberately not ported). Everything here is TIER 0 - it persists locally and
// drives calls the engine already exposes; the settings that need new engine work
// (bandwidth caps, ports, obfuscation policy) are tracked in the audit, not here.

import SwiftUI

struct SettingsView: View {
    @EnvironmentObject var model: EngineModel
    @Environment(\.dismiss) private var dismiss

    // @AppStorage binds each control straight to UserDefaults, so a change is
    // persisted the instant it is made - the whole point of this screen, since
    // NOTHING survived a relaunch before.
    @AppStorage(SettingsKey.shareUploads) private var shareUploads = true
    @AppStorage(SettingsKey.pauseSharingOnCellular) private var pauseOnCellular = true
    @AppStorage(SettingsKey.keepAwakeWhileTransferring) private var keepAwake = true
    @AppStorage(SettingsKey.updateServerListAtLaunch) private var updateAtLaunch = false
    @AppStorage(SettingsKey.askServersForServers) private var askServers = true
    @AppStorage(SettingsKey.defaultPriority) private var defaultPriority = 1
    @AppStorage(SettingsKey.rememberSearchFilters) private var rememberFilters = true
    @AppStorage(SettingsKey.upnpEnabled) private var upnpEnabled = true

    @State private var newUrl = ""

    var body: some View {
        NavigationStack {
            Form {
                sharingSection
                serverListSection
                networkSection
                downloadsSection
                deviceSection
                identitySection
            }
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
        }
    }

    // MARK: - Sharing

    private var sharingSection: some View {
        Section {
            Toggle("Share uploads", isOn: Binding(
                get: { shareUploads },
                set: { shareUploads = $0; model.setSharing($0) }
            ))
            Toggle("Pause sharing on cellular / metered networks", isOn: Binding(
                get: { pauseOnCellular },
                set: { pauseOnCellular = $0; model.applyEffectiveSharing() }
            ))
        } header: {
            Text("Sharing")
        } footer: {
            // Say the current EFFECTIVE state, and why, so a user whose sharing
            // was auto-paused does not think the toggle is broken.
            if model.sharingPausedForMeteredLink {
                Text("Sharing is paused right now because you are on a metered network. It resumes automatically on Wi-Fi. This pauses uploading only - downloads continue and still use data.")
            } else if shareUploads {
                Text("padMule serves your finished files to other peers while it is open. Sharing earns you better standing in their queues, so your own downloads go faster.")
            } else {
                Text("Leech Mode: downloading only. padMule is not serving any files to peers.")
            }
        }
    }

    // MARK: - Server lists

    private var serverListSection: some View {
        Section {
            ForEach(model.serverListUrls, id: \.self) { url in
                Text(url).font(.caption).lineLimit(1).truncationMode(.middle)
            }
            .onDelete { idx in
                for i in idx { model.removeServerListUrl(model.serverListUrls[i]) }
            }
            HStack {
                TextField("Add a server.met URL", text: $newUrl)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .keyboardType(.URL)
                Button("Add") {
                    model.addServerListUrl(newUrl)
                    newUrl = ""
                }
                .disabled(newUrl.isEmpty)
            }
            Toggle("Update all lists at launch", isOn: $updateAtLaunch)
            Toggle("Ask connected servers for more servers", isOn: Binding(
                get: { askServers },
                set: { askServers = $0; model.applyAskServersForServers() }
            ))
            Button {
                model.updateAllServerLists()
            } label: {
                if model.loadingServers {
                    HStack { ProgressView(); Text("Updating...") }
                } else {
                    Text("Update all lists now")
                }
            }
            .disabled(model.loadingServers)
        } header: {
            Text("Server lists")
        } footer: {
            Text("padMule merges every list, so adding more sources builds one comprehensive server list rather than replacing it. server.met is a single shared format - lists published for eMule and for aMule are the same files and both work. With \"Ask connected servers\" on, every server you connect to is also asked for the servers it knows - discovering servers no published list carries.")
        }
    }

    // MARK: - Network / VPN
    //
    // Why "advertised" is separate from "listening": a VPN (e.g. AirVPN) REPLACES
    // the router-forwarding padMule normally relies on - the provider forwards an
    // assigned remote port into the tunnel, so (a) UPnP on the LAN router
    // accomplishes nothing and its failure line is misleading, and (b) the
    // provider may forward that remote port to a DIFFERENT local port, in which
    // case peers must be told the EXTERNAL port while padMule actually listens on
    // the local one. Kept behind a disclosure group so the default experience -
    // a normal home user who should never touch this - stays a single toggle.

    private var networkSection: some View {
        Section {
            Toggle("Use UPnP port mapping", isOn: Binding(
                get: { upnpEnabled },
                set: { upnpEnabled = $0; model.applyPortSettings() }
            ))
            DisclosureGroup("Advanced (behind a VPN)") {
                HStack {
                    Text("Listening port (TCP)")
                    Spacer()
                    TextField("4662", text: portBinding(SettingsKey.listenPort, defaultPort: 4662))
                        .keyboardType(.numberPad)
                        .multilineTextAlignment(.trailing)
                        .frame(maxWidth: 100)
                        .onSubmit { model.applyPortSettings() }
                }
                HStack {
                    Text("Port peers are told (advertised)")
                    Spacer()
                    TextField(
                        "4662", text: portBinding(SettingsKey.advertisedPort, defaultPort: 4662)
                    )
                    .keyboardType(.numberPad)
                    .multilineTextAlignment(.trailing)
                    .frame(maxWidth: 100)
                    .onSubmit { model.applyPortSettings() }
                }
                HStack {
                    Text("Kad port (UDP)")
                    Spacer()
                    TextField("4672", text: portBinding(SettingsKey.kadPort, defaultPort: 4672))
                        .keyboardType(.numberPad)
                        .multilineTextAlignment(.trailing)
                        .frame(maxWidth: 100)
                        .onSubmit { model.applyPortSettings() }
                }
            }
        } header: {
            Text("Network / VPN")
        } footer: {
            Text("Most people should leave these alone. Behind a VPN, the provider forwards a port into the tunnel: turn UPnP off above, and set the advertised port to the one the provider assigned you (and the listening port to whatever local port it actually forwards to, if different from that). Changes take effect the next time padMule starts.")
        }
    }

    /// A text-field binding for one port setting, reading/writing UserDefaults
    /// directly (not through @AppStorage, so it can reject a bad keystroke
    /// without losing the field's current valid value). Non-digit characters
    /// are stripped; a value over 65535 is ignored outright; a blank or zero
    /// entry restores `defaultPort`.
    private func portBinding(_ key: String, defaultPort: Int) -> Binding<String> {
        Binding<String>(
            get: { String(UserDefaults.standard.integer(forKey: key)) },
            set: { newValue in
                let digits = newValue.filter { $0.isNumber }
                guard let n = Int(digits), n <= 65535 else {
                    if digits.isEmpty { UserDefaults.standard.set(defaultPort, forKey: key) }
                    return
                }
                UserDefaults.standard.set(n == 0 ? defaultPort : n, forKey: key)
            }
        )
    }

    // MARK: - Downloads

    private var downloadsSection: some View {
        Section {
            Picker("Default priority for new downloads", selection: $defaultPriority) {
                Text("Low").tag(0)
                Text("Normal").tag(1)
                Text("High").tag(2)
            }
            Toggle("Remember search filters", isOn: $rememberFilters)
        } header: {
            Text("Downloads and search")
        } footer: {
            Text("New downloads start at this priority; you can still change any download individually. Remembering filters keeps your size and type choices between launches - useful because iPadOS suspends and relaunches padMule often.")
        }
    }

    // MARK: - Device

    private var deviceSection: some View {
        Section {
            Toggle("Keep screen awake while transferring", isOn: Binding(
                get: { keepAwake },
                set: { keepAwake = $0; model.applyKeepAwake() }
            ))
        } header: {
            Text("Device")
        } footer: {
            Text("padMule only transfers while it is open and on screen (iPadOS suspends background apps). Keeping the screen awake during an active transfer stops it pausing when the display would otherwise sleep. It only holds the screen on while bytes are actually moving - a stalled transfer with no sources will not keep the screen on.")
        }
    }

    // MARK: - Identity (read-only)

    private var identitySection: some View {
        Section {
            if let id = model.identity {
                LabeledContent("User hash", value: String(id.userhash.prefix(16)) + "...")
                    .font(.caption)
                LabeledContent("Kad ID", value: String(id.kadId.prefix(16)) + "...")
                    .font(.caption)
            }
            LabeledContent("Kad contacts", value: "\(model.kadContacts)")
            LabeledContent("IP filter", value: model.ipFilterRanges == 0
                ? "off" : "\(model.ipFilterRanges) ranges")
        } header: {
            Text("This device")
        } footer: {
            Text("Your identity is generated on first launch and kept on device. It is never shown to peers as-is and never leaves the iPad.")
        }
    }
}
