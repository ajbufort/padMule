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
    // Must agree with the registered default (false). Background running costs
    // battery, so the honest default for something that runs while the user is
    // not looking is off.
    @AppStorage(SettingsKey.backgroundSeeding) private var backgroundSeeding = false
    // MUST AGREE with the registered default (true) or the toggle shows one
    // state while the engine is in the other - the drift SettingsDefaults warns
    // about, and on a PRIVACY control it is the dangerous direction: the switch
    // would read OFF while padMule was actually disguised, or vice versa.
    @AppStorage(SettingsKey.incognito) private var incognito = true
    // Must agree with the registered default (false = Nobody), which is also
    // eMule's own default.
    @AppStorage(SettingsKey.allowBrowse) private var allowBrowse = false
    @AppStorage(SettingsKey.beepOnDownloadComplete) private var beepOnComplete = true
    @AppStorage(SettingsKey.updateServerListAtLaunch) private var updateAtLaunch = false
    @AppStorage(SettingsKey.askServersForServers) private var askServers = true
    @AppStorage(SettingsKey.defaultPriority) private var defaultPriority = 1
    // Must agree with SettingsDefaults.register() (0 = unlimited).
    @AppStorage(SettingsKey.maxActiveDownloads) private var maxActiveDownloads = 0
    @AppStorage(SettingsKey.rememberSearchFilters) private var rememberFilters = true
    // Must agree with the registered default in Settings.register (false):
    // this initializer is what SwiftUI uses when no default is registered, and
    // a disagreement shows the toggle in one state while the engine is in the
    // other.
    @AppStorage(SettingsKey.upnpEnabled) private var upnpEnabled = false
    // Same agreement rule as upnpEnabled above: false here must match the
    // registered default, or the switch renders on while the app is light.
    @AppStorage(SettingsKey.darkMode) private var darkMode = false

    @State private var newUrl = ""

    // Port fields edit LOCAL buffers, seeded on appear and validated once at
    // commit - never written through on each keystroke (see loadPortText).
    @State private var listenText = ""
    @State private var advertisedText = ""
    @State private var kadText = ""
    @State private var kadAdvertisedText = ""
    @FocusState private var focusedPort: PortField?

    // The nickname edits a LOCAL buffer for the same reason the ports do: a
    // write-through field would substitute the default the moment you cleared
    // it to type a new name. Committed on focus loss and on the way out.
    @State private var nicknameText = ""
    @FocusState private var nicknameFocused: Bool

    var body: some View {
        NavigationStack {
            Form {
                appearanceSection
                sharingSection
                // Privacy sits directly under Sharing: what you expose and what
                // you tell people about yourself are the same question.
                privacySection
                serverListSection
                networkSection
                downloadsSection
                deviceSection
                identitySection
            }
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.inline)
            .onAppear {
                loadPortText()
                nicknameText = storedNickname
            }
            // Commit whenever focus LEAVES a port field, and once more on the
            // way out: .numberPad has no Return key, so there is no onSubmit.
            .onChange(of: focusedPort) { _ in commitPorts() }
            .onChange(of: nicknameFocused) { focused in
                if !focused { commitNickname() }
            }
            .onDisappear {
                commitPorts()
                commitNickname()
            }
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
                ToolbarItemGroup(placement: .keyboard) {
                    Spacer()
                    // Clears whichever field is up. The nickname's keyboard has
                    // a Return key (so .onSubmit covers it too), but this bar
                    // shows for it as well and a Done that dismissed nothing
                    // would read as a stuck keyboard.
                    Button("Done") {
                        focusedPort = nil
                        nicknameFocused = false
                    }
                }
            }
        }
    }

    // MARK: - Appearance

    /// FIRST section on the screen (Anthony, 2026-08-05). It is the setting a
    /// user is most likely to come here for and the only one whose effect is
    /// visible the instant it is flipped, so it earns the top slot over
    /// Sharing.
    ///
    /// padMule PINS its appearance rather than following the system. Light
    /// unless this is on - see `PadMuleApp`, where the scheme is applied. The
    /// alternative, `.preferredColorScheme(nil)`, would inherit iPadOS's
    /// setting and mean the app could go dark by itself partway through a long
    /// transfer because the iPad crossed a scheduled sunset. An explicit choice
    /// that stays put is the better behaviour for an app that is meant to sit
    /// open and on screen for hours.
    private var appearanceSection: some View {
        Section {
            Toggle("Dark Mode", isOn: $darkMode)
        } header: {
            Text("Appearance")
        } footer: {
            Text("padMule starts in Light Mode unless you turn this on. It does not follow the iPad's system appearance, so it will not change on its own while a transfer is running.")
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
            Toggle("Keep sharing in the background", isOn: $backgroundSeeding)
                .disabled(!shareUploads)
        } header: {
            Text("Sharing")
        } footer: {
            // Say the current EFFECTIVE state, and why, so a user whose sharing
            // was auto-paused does not think the toggle is broken.
            if model.sharingPausedForMeteredLink {
                Text("Sharing is paused right now because you are on a metered network. It resumes automatically on Wi-Fi. This pauses uploading only - downloads continue and still use data.")
            } else if shareUploads {
                // Two paragraphs, because they answer different questions: what
                // sharing buys, and what the background option costs. The second
                // is deliberately blunt about the limits - a user who thinks
                // this is a guarantee will conclude the app is broken the first
                // time iOS reclaims it, which it can do at any moment.
                // ONE view, not two. A Section footer built from two sibling
                // Texts renders only the FIRST - confirmed by screenshot on
                // device 2026-08-07, where the background-seeding caveat simply
                // was not on screen while the source clearly contained it. The
                // accessibility tree agreed with the screen and neither agreed
                // with the code, so nothing but a picture could have caught it.
                // A VStack makes the grouping explicit and both paragraphs show.
                VStack(alignment: .leading, spacing: 6) {
                Text("padMule serves your finished files to other peers while it is open. Sharing earns you better standing in their queues, so your own downloads go faster.")
                Text(
                    backgroundSeeding
                        ? "padMule will keep serving after you switch away, so you keep earning standing while you are not looking. It uses more battery, and downloads still stop - only uploads continue. iPadOS can still reclaim the app at any time; when it does, padMule pauses cleanly and resumes when you come back."
                        : "With this off, padMule stops the moment you switch away, and other peers stop being able to download from you until you open it again."
                )
                }
            } else {
                Text("Leech Mode: downloading only. padMule is not serving any files to peers.")
            }
        }
    }

    /// A full identity value, wrapped and selectable rather than elided.
    ///
    /// It used to render `String(value.prefix(16)) + "..."`, which defeated the
    /// purpose: an identifier exists to be COMPARED, and half of one compares
    /// nothing. Anthony asked for the complete IDs.
    private func identityRow(_ title: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title)
            Text(value)
                .font(.caption.monospaced())
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
                .lineLimit(2)
                .minimumScaleFactor(0.7)
        }
    }

    // MARK: - Privacy

    /// The footer text, as ONE literal.
    ///
    /// It was a chain of `+` concatenations and the Swift type-checker gave up
    /// on it: "unable to type-check this expression in reasonable time",
    /// failing the iOS build. A long concatenation is an inference problem, not
    /// a formatting choice - so the prose lives here as a single string and the
    /// view just renders it.
    private static let privacyFooter = """
        Stops padMule identifying itself to other clients. It is on by default. \
        padMule already reports itself as aMule 3.0.1, so this removes what is \
        left: a padMule marker in the handshake, and the default nickname.

        Two things it does NOT do. It turns OFF padMule-to-padMule features, \
        because other padMules recognize each other by exactly that marker. \
        And it hides what padMule SAYS about itself, not how it behaves - \
        timing, packet order and which requests it answers can still identify \
        it to anyone looking closely. This is not anonymity, and it is not a VPN.

        "Who can see your shared files" controls whether another client can \
        list everything you share just by asking. Nobody is the default, and is \
        what eMule defaults to as well. Downloads still in progress are never \
        listed either way.
        """

    private var privacySection: some View {
        Section {
            Toggle("Incognito", isOn: $incognito)
                // iOS 16 single-parameter form: the project targets 16.0 and
                // the two-parameter onChange(of:initial:_:) is 17+.
                .onChange(of: incognito) { on in model.setIncognito(on) }
            Picker("Who can see your shared files", selection: $allowBrowse) {
                Text("Nobody").tag(false)
                Text("Everybody").tag(true)
            }
            .onChange(of: allowBrowse) { on in model.setAllowBrowse(on) }
        } header: {
            Text("Privacy")
        } footer: {
            // BOTH limits, on the switch itself. A privacy control that
            // over-promises is worse than none, because it changes what the
            // user risks doing while believing they are covered.
            Text(Self.privacyFooter).font(.caption)
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

    /// Which port field the keyboard is in. `.numberPad` has no Return key, so
    /// there is no `.onSubmit` to rely on - the commit happens when focus LEAVES
    /// a field (including via the keyboard's Done button) and when the screen
    /// goes away.
    private enum PortField: Hashable { case listen, advertised, kad, kadAdvertised }

    private var networkSection: some View {
        Section {
            Toggle("Use UPnP port mapping", isOn: Binding(
                get: { upnpEnabled },
                set: { upnpEnabled = $0; model.applyPortSettings() }
            ))
            DisclosureGroup("Advanced (behind a VPN)") {
                portRow("Listening port (TCP)", text: $listenText, field: .listen, hint: "5999")
                portRow(
                    "Port peers are told (advertised)", text: $advertisedText,
                    field: .advertised, hint: "5999")
                portRow("Kad port (UDP)", text: $kadText, field: .kad, hint: "5999")
                portRow(
                    "Kad port peers are told (advertised)", text: $kadAdvertisedText,
                    field: .kadAdvertised, hint: "5999")
            }
        } header: {
            Text("Network / VPN")
        } footer: {
            Text("Most people should leave these alone. Behind a VPN, the provider forwards a port into the tunnel: turn UPnP off above, and set all four ports to the one the provider assigned you. The two \"advertised\" fields only differ from their listening counterparts when the provider forwards its port to a DIFFERENT local port - then padMule must listen locally but tell peers the provider's number. Tap Done, or tap outside a field, to apply. Changes take effect the next time padMule starts.")
        }
    }

    private func portRow(
        _ label: String, text: Binding<String>, field: PortField, hint: String
    ) -> some View {
        HStack {
            Text(label)
            Spacer()
            TextField(hint, text: text)
                .keyboardType(.numberPad)
                .multilineTextAlignment(.trailing)
                .frame(maxWidth: 100)
                .focused($focusedPort, equals: field)
        }
    }

    /// Seed the editable buffers from what is stored. The fields edit LOCAL
    /// state, not UserDefaults: the first version wrote on every keystroke and
    /// re-read the stored value to redraw, so clearing a field instantly wrote
    /// the default back and the old number kept reasserting itself while you
    /// typed. Editing is now unconstrained; validation happens once, at commit.
    private func loadPortText() {
        let d = UserDefaults.standard
        listenText = String(d.integer(forKey: SettingsKey.listenPort))
        advertisedText = String(d.integer(forKey: SettingsKey.advertisedPort))
        kadText = String(d.integer(forKey: SettingsKey.kadPort))
        kadAdvertisedText = String(d.integer(forKey: SettingsKey.kadAdvertisedPort))
    }

    /// A port is 1-65535; anything else (including an empty field) falls back to
    /// the eD2k default rather than being stored as junk or as port 0.
    private func sanitizedPort(_ text: String, fallback: Int) -> Int {
        let digits = text.filter { $0.isNumber }
        guard let n = Int(digits), (1...65535).contains(n) else { return fallback }
        return n
    }

    /// Store all three, then write back what was ACTUALLY stored so a rejected
    /// entry visibly snaps to the value in force instead of lying about it.
    private func commitPorts() {
        let l = sanitizedPort(listenText, fallback: 5999)
        let a = sanitizedPort(advertisedText, fallback: 5999)
        let k = sanitizedPort(kadText, fallback: 5999)
        let ka = sanitizedPort(kadAdvertisedText, fallback: k)
        let d = UserDefaults.standard
        d.set(l, forKey: SettingsKey.listenPort)
        d.set(a, forKey: SettingsKey.advertisedPort)
        d.set(k, forKey: SettingsKey.kadPort)
        d.set(ka, forKey: SettingsKey.kadAdvertisedPort)
        listenText = String(l)
        advertisedText = String(a)
        kadText = String(k)
        kadAdvertisedText = String(ka)
        model.applyPortSettings()
    }

    // MARK: - Downloads

    private var downloadsSection: some View {
        Section {
            Picker("Default priority for new downloads", selection: $defaultPriority) {
                Text("Low").tag(0)
                Text("Normal").tag(1)
                Text("High").tag(2)
            }
            Stepper(
                maxActiveDownloads == 0
                    ? "Active downloads: unlimited"
                    : "Active downloads: at most \(maxActiveDownloads)",
                value: $maxActiveDownloads, in: 0...20
            )
            .onChange(of: maxActiveDownloads) { _ in
                model.pushMaxActiveDownloads()
            }
            Toggle("Remember search filters", isOn: $rememberFilters)
        } header: {
            Text("Downloads and search")
        } footer: {
            Text("New downloads start at this priority; you can still change any download individually. With an active-downloads cap, extra downloads wait as Queued and start automatically when a slot frees. Remembering filters keeps your size and type choices between launches - useful because iPadOS suspends and relaunches padMule often.")
        }
    }

    // MARK: - Device

    private var deviceSection: some View {
        Section {
            Toggle("Keep screen awake while transferring", isOn: Binding(
                get: { keepAwake },
                set: { keepAwake = $0; model.applyKeepAwake() }
            ))
            // Play it on the way IN as well, so the choice is auditioned rather
            // than taken on trust - the toggle is otherwise silent until the
            // next download happens to finish.
            Toggle("Beep when a download finishes", isOn: Binding(
                get: { beepOnComplete },
                set: { beepOnComplete = $0; if $0 { EngineModel.playFinishedSound() } }
            ))
        } header: {
            Text("Device")
        } footer: {
            Text("padMule only transfers while it is open and on screen (iPadOS suspends background apps). Keeping the screen awake during an active transfer stops it pausing when the display would otherwise sleep. It only holds the screen on while bytes are actually moving - a stalled transfer with no sources will not keep the screen on.\n\nThe finish sound plays once per file, after it has been hash-verified and saved. It follows the silent switch.")
        }
    }

    // MARK: - Identity

    /// eMule's nickname length cap, and the same number the engine enforces:
    /// `CPreferences::GetMaxUserNickLength() {return 50;}` (eMule 0.70b
    /// Preferences.h:690; 0.50a Preferences.h:661 agrees). eMule applies it AT
    /// THE EDIT CONTROL (`SetLimitText`, PPgGeneral.cpp:115) so an over-long
    /// name cannot be typed in the first place, which is what the cap in
    /// `sanitizedNickname` reproduces.
    static let maxNicknameLength = 50

    /// The nickname currently stored, as the field should show it.
    private var storedNickname: String {
        EngineModel.nicknameToPush(
            stored: UserDefaults.standard.string(forKey: SettingsKey.nickname))
    }

    /// Clean a typed nickname for STORAGE and DISPLAY.
    ///
    /// Deliberately a copy of `mule_engine::sanitize_nick`, not a call into it.
    /// The engine's copy is the enforcing one - it writes the bytes, and it runs
    /// whatever this produces through the same rules again - but the field needs
    /// the answer synchronously so a rejected entry SNAPS to what will actually
    /// be announced instead of showing something else (the `commitPorts`
    /// pattern). The two are kept in step by asserting the same table on both
    /// sides: `engine::tests::an_empty_or_oversized_or_control_laden_nickname_is_repaired`
    /// and `NicknameTests` here.
    ///
    /// DISCLOSED LIMIT: this counts Characters (grapheme clusters) and the
    /// engine counts Unicode scalars, so a name built from multi-scalar
    /// graphemes (an emoji with a skin-tone modifier, say) can be trimmed
    /// slightly further by the engine than by this field. Both caps are 50 and
    /// the engine's is the one on the wire.
    static func sanitizedNickname(_ text: String) -> String {
        // `.controlCharacters` is Unicode category Cc - the same set Rust's
        // `char::is_control()` covers, which is what the engine filters on.
        let cleaned = text.components(separatedBy: .controlCharacters).joined()
        let capped = String(
            cleaned.trimmingCharacters(in: .whitespacesAndNewlines).prefix(maxNicknameLength))
        let nick = capped.trimmingCharacters(in: .whitespacesAndNewlines)
        return nick.isEmpty ? EngineModel.defaultNickname : nick
    }

    /// Store the cleaned name, push it to the engine, and write back what was
    /// ACTUALLY stored - so an entry the rules changed visibly snaps to the name
    /// in force rather than lying about it (same rule as `commitPorts`).
    private func commitNickname() {
        let clean = Self.sanitizedNickname(nicknameText)
        UserDefaults.standard.set(clean, forKey: SettingsKey.nickname)
        nicknameText = clean
        model.pushNickname()
    }

    private var identitySection: some View {
        Section {
            // "Nickname" is eMule's own word for it (Options -> General, the
            // IDC_NICK field), and it is what Anthony asked for. Autocorrect off
            // - a nickname is not a word and correcting it would be silent
            // vandalism - but capitalization left on, because most people type a
            // name here.
            HStack {
                Text("Nickname")
                Spacer()
                TextField(EngineModel.defaultNickname, text: $nicknameText)
                    .multilineTextAlignment(.trailing)
                    .autocorrectionDisabled()
                    .focused($nicknameFocused)
                    .onSubmit { commitNickname() }
            }
            // WHAT PEERS ACTUALLY SEE. With Incognito on and the nickname left
            // at its default, the wire carries aMule's default instead - so this
            // field alone said "padMule" while every peer saw something else.
            // Anthony hit exactly that, hunting for his own client in eMule's
            // list and not finding it. Shown only when the two DIFFER: an
            // always-on row would be noise, and the whole point is the mismatch.
            if !model.wireNickname.isEmpty && model.wireNickname != nicknameText {
                Text("Other clients see \"\(model.wireNickname)\" - Incognito is "
                    + "replacing your default nickname. Set your own above to "
                    + "use it instead.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            if let id = model.identity {
                // IN FULL, and selectable. These are 32 hex characters - the
                // truncated form was unusable for the one thing they are for:
                // telling this client apart from another, which needs the WHOLE
                // value. `.textSelection` lets them be copied out; monospaced
                // digits so a mistyped character is visible.
                identityRow("User hash", id.userhash)
                identityRow("Kad ID", id.kadId)
            }
            LabeledContent("Kad contacts", value: "\(model.kadContacts)")
            LabeledContent("IP filter", value: model.ipFilterRanges == 0
                ? "off" : "\(model.ipFilterRanges) ranges")
            LabeledContent("Build", value: Self.buildId)
                .textSelection(.enabled)
        } header: {
            Text("This device")
        } footer: {
            // Blunt about WHEN it applies. The server login and any download
            // padMule starts pick the name up on their next connection, but the
            // inbound listener builds its greeting once when it binds - so a
            // peer that dials US sees the old name until the engine is
            // restarted. Saying "changes apply immediately" would be the kind of
            // small lie that reads as a broken setting.
            Text("Your nickname is the name other peers and servers see - up to 50 characters, the same limit eMule uses. Leave it empty to go back to \"padMule\". Servers and your own downloads pick up a new nickname the next time they connect; peers connecting TO you see it after you Stop and Start padMule.\n\nYour identity is generated on first launch and kept on device. It is never shown to peers as-is and never leaves the iPad.")
        }
    }

    /// "1.0 (621092b)" - the marketing version and the GIT SHA this build was
    /// made from, stamped into CFBundleVersion by CI.
    ///
    /// It exists because until 2026-08-05 nothing on the device could say WHICH
    /// build was running: CFBundleVersion was the XcodeGen default of `1` in
    /// every build ever shipped, so a fresh install was confirmed by spotting a
    /// UI change and remembering which round it came from. That is guesswork
    /// aimed at exactly the question a bug report has to answer first.
    ///
    /// Selectable on purpose - it belongs in a report, and the alternative is
    /// transcribing it off a photograph.
    ///
    /// Falls back to "dev" for a local or simulator build, where nothing stamps
    /// it and CFBundleVersion is still XcodeGen's default.
    static var buildId: String {
        let info = Bundle.main.infoDictionary
        return buildLabel(
            short: info?["CFBundleShortVersionString"] as? String ?? "?",
            build: info?["CFBundleVersion"] as? String ?? "?"
        )
    }

    /// The formatting rule alone, so it can be tested without a bundle - the
    /// only interesting part is the unstamped fallback, and asserting that
    /// through `Bundle.main` would be asserting how CI happened to build the
    /// test host.
    static func buildLabel(short: String, build: String) -> String {
        build == UNSTAMPED_BUILD ? "\(short) (dev)" : "\(short) (\(build))"
    }
}

/// XcodeGen's default CFBundleVersion, which is what an un-stamped build has.
/// CI replaces it with the git short sha (.github/workflows/ios-build.yml).
private let UNSTAMPED_BUILD = "1"
