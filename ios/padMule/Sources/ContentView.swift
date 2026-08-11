// padMule's main screen. An eMule-style FUNCTION STRIP sits under the title and
// switches a single content area between seven screens (Search, Transfers,
// Downloaded, Servers, Shared, Statistics, Status), instead of one long scroll. Each
// function shows its icon ABOVE its name, the way eMule's toolbar does - but
// sized and tinted for iOS rather than copied: a ~19pt hierarchical SF Symbol
// over an 11pt caption, selection carried by the accent tint plus a soft rounded
// fill, no borders or gradients. The title stays INLINE so it never collapses
// out of view the way a large title does.
//
// The three HARD lifecycle requirements from docs/wiki/lifecycle-and-reactivation.md
// survive the split: (1) an honest status notice (we do NOT transfer in the
// background) lives on the Transfers screen; (2) the Reconnecting banner shows
// above every screen; (3) each transfer row carries a Paused badge when paused.

import SwiftUI

/// The top-toolbar destinations. Each is one eD2k function, one icon.
enum Screen: String, CaseIterable, Identifiable {
    // Order is Anthony's: the strip reads left-to-right as the order you
    // actually use them - pick a server, check you are on it, search, watch
    // what is moving, see what arrived, then the two reference screens.
    // Transfers sits BEFORE Downloads (Anthony, 2026-08-04): a queued file is
    // watched far more often than a finished one is opened, so the tab you
    // return to should be nearer the tab you left.
    // NOTE: this drives the strip order via `allCases`. The raw values are
    // unchanged, and nothing persists them, so reordering is display-only.
    case servers, status, search, transfers, downloaded, shared, stats
    var id: String { rawValue }

    var title: String {
        switch self {
        case .search: return "Search"
        case .transfers: return "Transfers"
        case .downloaded: return "Downloaded"
        case .servers: return "Servers"
        case .shared: return "Shared"
        case .stats: return "Statistics"
        case .status: return "Status"
        }
    }

    /// The name shown UNDER the icon in the function strip. Mostly `title`, but
    /// "Statistics" and "Downloaded" are abbreviated so seven labels sit
    /// comfortably side by side.
    var shortTitle: String {
        switch self {
        case .stats: return "Stats"
        case .downloaded: return "Downloads"
        default: return title
        }
    }

    /// SF Symbol for the function strip. All ship with iOS 16 (the deployment
    /// target), so none silently renders as a blank square on the iPad. A `.fill`
    /// variant reads as "selected" where the symbol has one; elsewhere the accent
    /// tint alone carries selection.
    ///
    /// Chosen to say what the function DOES, taking eMule's toolbar as the cue:
    /// its Transfers icon shows both directions (padMule uploads as well as
    /// downloads), and its Status/"Server info" pane is about connectivity, which
    /// `network` states more plainly than a bare gauge.
    func icon(selected: Bool) -> String {
        switch self {
        case .search: return "magnifyingglass"
        case .transfers:
            return selected ? "arrow.up.arrow.down.circle.fill" : "arrow.up.arrow.down.circle"
        case .downloaded: return selected ? "tray.and.arrow.down.fill" : "tray.and.arrow.down"
        case .servers: return "server.rack"
        case .shared: return selected ? "folder.fill" : "folder"
        // No .fill variant exists for these; the accent tint marks selection.
        case .stats: return "chart.xyaxis.line"
        case .status: return "network"
        }
    }
}

/// One function in the strip: icon above name, tapped to switch screens.
private struct FunctionButton: View {
    let screen: Screen
    let selected: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            VStack(spacing: 3) {
                Image(systemName: screen.icon(selected: selected))
                    .font(.system(size: 19, weight: .regular))
                    .symbolRenderingMode(.hierarchical)
                    .frame(height: 22)
                Text(screen.shortTitle)
                    .font(.caption2)
                    .fontWeight(selected ? .semibold : .regular)
                    .lineLimit(1)
            }
            .foregroundStyle(selected ? Color.accentColor : Color.secondary)
            .frame(maxWidth: .infinity)
            .padding(.vertical, 6)
            .background(
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .fill(selected ? Color.accentColor.opacity(0.12) : Color.clear)
            )
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityLabel(screen.title)
        .accessibilityAddTraits(selected ? [.isSelected] : [])
    }
}

struct ContentView: View {
    @EnvironmentObject var model: EngineModel
    /// Read here so the Transfers notice can tell the TRUTH about leaving the
    /// app: with background seeding armed, "leaving stops the transfer" is
    /// false for uploads. Honest status is a hard requirement (lifecycle rule
    /// 1), and this text asserted the pre-seeding rule unconditionally until
    /// 2026-08-09.
    @AppStorage(SettingsKey.backgroundSeeding) private var backgroundSeedingOn = false
    // Servers, not Search: padMule deliberately does not auto-connect, so
    // picking a server IS the first thing to do - landing on Search offered a
    // box that could not answer yet.
    @State private var screen: Screen = .servers
    /// The finished file being previewed, if any (the Downloaded tab's Open).
    @State private var quickLook: QuickLookItem?
    // Dismissal for the three STATE-driven banners. They cannot be cleared by
    // clearing a value the way `notice` and `bootError` can, so each hides until
    // its condition next changes (see the .onChange resets below) - "I have read
    // this", not "never show it again".
    @State private var hidReconnecting = false
    @State private var hidSharingPaused = false
    @State private var hidStarting = false
    // Both search option groups start COLLAPSED - the point of the roll-up. Not
    // persisted: a collapsed group whose label names its active options costs
    // nothing to reopen, and one more UserDefaults key earns nothing.
    @State private var showSearchOptions = false
    @State private var showRefine = false
    @State private var query = ""
    @State private var serverListUrl = EngineModel.defaultServerListUrl
    @State private var detail: SearchHit?
    /// Whether the "Results (N)" header is on screen. Drives the floating Top
    /// button: the old one lived IN that header, so it scrolled away exactly
    /// when it became useful.
    @State private var resultsHeaderVisible = true
    @State private var showAddCategory = false
    @State private var newCategoryName = ""
    @State private var sourcesFor: DownloadInfo?
    @State private var ratingFor: SharedFileInfo?
    /// The shared file a Delete swipe is asking about. Delete is the only
    /// irreversible action on the Shared screen, so it is confirmed; Unshare
    /// beside it is not, because the file survives it.
    @State private var deleteCandidate: SharedFileInfo?
    /// Guards the explicit Stop: it drops connections and releases the router
    /// port, so it asks first.
    @State private var confirmStop = false
    @State private var showSettings = false
    @State private var showHelp = false

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                // The function strip: every screen is one tap away, named, always
                // in the same place (eMule's toolbar habit, which is why its users
                // never hunt for a feature).
                functionStrip

                statusBanners

                // The selected screen fills the rest.
                switch screen {
                case .search: searchScreen
                case .transfers: transfersScreen
                case .downloaded: downloadedScreen
                case .servers: serversScreen
                case .shared: sharedScreen
                case .stats: StatsView().environmentObject(model)
                case .status: statusScreen
                }
            }
            .toolbar {
                // UPPER LEFT (Anthony, 2026-08-05): a VPN indicator, shown only
                // while a tunnel is up. Absent rather than greyed-out when there
                // is none - an always-present badge would be one more thing to
                // read past, and the question it answers ("am I covered right
                // now?") is a yes/no that a missing badge answers just as well.
                vpnToolbarItem
                // Stop/Start FIRST in the trailing group (Anthony, 2026-08-04),
                // so it is the leftmost icon of the cluster rather than third.
                // Trailing items render in declaration order, left to right.
                //
                // Reachable from ANY screen, not only Status: it is the thing to
                // do before closing padMule, and hunting for the right tab first
                // is exactly when people skip it. Same icons and the same
                // confirmation as the Status control, so the two read as one
                // feature in two places.
                ToolbarItem(placement: .navigationBarTrailing) {
                    if model.state == .stopped {
                        Button {
                            model.startEngine()
                        } label: {
                            Image(systemName: "play.circle")
                                .foregroundStyle(.blue)
                        }
                        .disabled(model.stopping)
                        .accessibilityLabel("Start padMule")
                    } else {
                        Button {
                            confirmStop = true
                        } label: {
                            Image(systemName: "stop.circle")
                                .foregroundStyle(.red)
                        }
                        .disabled(model.stopping)
                        .accessibilityLabel("Stop padMule")
                    }
                }
                // Straight to the finished files. `folder` is the Files app's
                // own visual language (its icon is a folder), and it matches the
                // outline weight of the other toolbar glyphs rather than the
                // filled variant.
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button {
                        model.openDownloadsInFiles()
                    } label: {
                        Image(systemName: "folder")
                    }
                    .accessibilityLabel("Open downloads in the Files app")
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button {
                        showSettings = true
                    } label: {
                        Image(systemName: "gearshape")
                    }
                    .accessibilityLabel("Settings")
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button {
                        showHelp = true
                    } label: {
                        Image(systemName: "questionmark.circle")
                    }
                    .accessibilityLabel("How to use padMule")
                }
            }
            // Re-arm each dismissed banner when its condition next CHANGES, so
            // dismissing means "I have read this" rather than silencing the
            // warning permanently. A second reconnect, or sharing pausing again
            // later, must be able to speak.
            .onChange(of: model.reconnecting) { on in
                if !on { hidReconnecting = false }
            }
            .onChange(of: model.sharingPausedForIpChange) { paused in
                if !paused { hidSharingPaused = false }
            }
            .onChange(of: model.ready) { ready in
                if !ready { hidStarting = false }
            }
            .sheet(isPresented: $showSettings) {
                SettingsView().environmentObject(model)
            }
            .sheet(isPresented: $showHelp) {
                HelpView()
            }
            // At the ROOT, not on the Status screen: the toolbar Stop button is
            // reachable from every tab, and a confirmationDialog only presents
            // if its host view is on screen - attached to statusScreen it would
            // silently do nothing from anywhere else. Wording says "from the
            // toolbar or the Status screen" for the same reason.
            .confirmationDialog(
                "Stop padMule?", isPresented: $confirmStop, titleVisibility: .visible
            ) {
                Button("Stop", role: .destructive) { model.stop() }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text(model.portMapped
                     ? "Transfers stop and the router port is released. Your progress is saved, and you can start again from the toolbar or the Status screen."
                     : "Transfers stop. Your progress is saved, and you can start again from the toolbar or the Status screen.")
            }
            // Text(verbatim:) NOT a string literal: .navigationTitle("...")
            // takes a LocalizedStringKey, which performs escape processing and
            // swallowed the leading backslash on device.
            .navigationTitle(Text(verbatim: "\\__ p a d M u l e __/"))
            .navigationBarTitleDisplayMode(.inline)
            .sheet(item: $detail) { hit in
                SearchDetailView(hit: hit).environmentObject(model)
            }
            .alert("New Category", isPresented: $showAddCategory) {
                TextField("Name", text: $newCategoryName)
                Button("Add") {
                    model.addCategory(newCategoryName)
                    newCategoryName = ""
                }
                Button("Cancel", role: .cancel) { newCategoryName = "" }
            }
            .sheet(item: $sourcesFor) { dl in
                SourcesView(download: dl).environmentObject(model)
            }
            .sheet(item: $model.preview) { item in
                PreviewPlayerView(item: item).environmentObject(model)
            }
            .sheet(item: $quickLook) { item in
                QuickLookView(url: item.url).ignoresSafeArea()
            }
            .alert(
                "Disconnected from server",
                isPresented: Binding(
                    get: { model.serverKick != nil },
                    set: { if !$0 { model.serverKick = nil } }
                )
            ) {
                Button("OK", role: .cancel) { model.serverKick = nil }
            } message: {
                Text(
                    model.serverKick.map {
                        "The server \($0) closed the connection. "
                            + "Pick another live server from the Servers tab to reconnect."
                    } ?? ""
                )
            }
            .alert(
                "VPN or network changed",
                isPresented: $model.publicAddressAlert
            ) {
                Button("OK", role: .cancel) { model.publicAddressAlert = false }
            } message: {
                // Deliberately no IP address anywhere in this text - see
                // EngineModel's .publicAddressChanged case for why.
                Text(
                    "padMule's public address changed. This usually means a VPN tunnel dropped "
                        + "or the device switched networks. Sharing has been paused automatically "
                        + "so files are not served from the new address. Check your VPN, then turn "
                        + "sharing back on when you're ready."
                )
            }
            // The VPN INTERFACE went away. Distinct from the alert above, and
            // the pair is deliberate: this one is LOCAL and fast (the tunnel
            // vanished from the interface list, noticed within a second), while
            // the address-change alert is authoritative but late (it needs the
            // network to report a different public address back, which may not
            // happen until the next server login).
            //
            // It does NOT auto-pause sharing, and the text says so rather than
            // implying protection that did not happen. Auto-pausing on this
            // signal would be wrong: the detection is a heuristic that can fire
            // on a non-VPN `utun` interface, and stopping a user's uploads on a
            // false positive is a real cost. The engine's address-change guard
            // is what actually pauses, on evidence rather than inference - but
            // that guard is gated on a HighID login, and a tunnel drop that
            // also costs HighID hides the change from it (found on glass,
            // 2026-08-08). DECIDED 2026-08-09 (Anthony): give the warning a
            // one-tap "Pause sharing now" instead of auto-pausing - no false
            // positives, and the user is looking at this alert anyway.
            .alert("VPN appears to have dropped", isPresented: $model.vpnWentDown) {
                Button("Pause sharing now", role: .destructive) {
                    model.setSharing(false)
                    model.vpnWentDown = false
                }
                Button("Keep sharing", role: .cancel) { model.vpnWentDown = false }
            } message: {
                Text(
                    "padMule can no longer see a VPN tunnel on this device. If you rely on a VPN, "
                        + "your traffic may no longer be going through it.\n\n"
                        + "Sharing has NOT been paused by this warning - padMule pauses "
                        + "automatically only once it confirms its public address actually "
                        + "changed, and a drop that also costs HighID can hide that change. "
                        + "\"Pause sharing now\" stops serving files immediately; turn Share "
                        + "uploads back on once the tunnel is up."
                )
            }
            .sheet(item: $ratingFor) { f in
                RatingEditorView(hash: f.hash, name: f.name, rating: f.rating, comment: f.comment) { rating, comment in
                    model.setFileRating(f.hash, rating: rating, comment: comment)
                }
            }
            .confirmationDialog(
                "Delete this file from your iPad?",
                isPresented: Binding(
                    get: { deleteCandidate != nil },
                    set: { if !$0 { deleteCandidate = nil } }),
                titleVisibility: .visible
            ) {
                Button("Delete", role: .destructive) {
                    if let f = deleteCandidate { model.deleteShared(f.hash) }
                    deleteCandidate = nil
                }
                Button("Cancel", role: .cancel) { deleteCandidate = nil }
            } message: {
                // Name the file: a swipe on the wrong row is the likeliest way
                // to reach this dialog, and the name is what catches it.
                Text(
                    (deleteCandidate?.name ?? "")
                        + "\n\nThis removes it from your shared files AND deletes it "
                        + "from the device. It cannot be undone.")
            }
        }
    }

    // MARK: - Categories

    /// The filter-chip row: All, each category (colored, long-press to delete),
    /// and a "+" to add one. Selecting a chip filters the transfer list.
    private var categoryChips: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 8) {
                // "All" + the category chips only make sense once a category
                // exists; the "+" is ALWAYS shown so the very first category can
                // be created (otherwise the whole feature is unreachable).
                if !model.categories.isEmpty {
                    chip("All", color: .secondary, selected: model.categoryFilter == nil) {
                        model.categoryFilter = nil
                    }
                    ForEach(model.categories) { cat in
                        chip(cat.name, color: cat.color, selected: model.categoryFilter == cat.id) {
                            model.categoryFilter = cat.id
                        }
                        .contextMenu {
                            Button(role: .destructive) {
                                model.removeCategory(cat.id)
                            } label: {
                                Label("Delete \"\(cat.name)\"", systemImage: "trash")
                            }
                        }
                    }
                }
                Button {
                    showAddCategory = true
                } label: {
                    Label("Add category", systemImage: "plus.circle")
                        .font(.caption)
                        .padding(.horizontal, 10)
                        .padding(.vertical, 4)
                        .background(Color.secondary.opacity(0.15))
                        .foregroundStyle(.secondary)
                        .clipShape(Capsule())
                }
                .buttonStyle(.borderless)
                .accessibilityLabel("Add category")
            }
            .padding(.vertical, 2)
        }
        .listRowInsets(EdgeInsets(top: 6, leading: 16, bottom: 6, trailing: 16))
    }

    private func chip(_ label: String, color: Color, selected: Bool, tap: @escaping () -> Void) -> some View {
        Button(action: tap) {
            Text(label)
                .font(.caption)
                .padding(.horizontal, 10)
                .padding(.vertical, 4)
                .background((selected ? color : color.opacity(0.15)))
                .foregroundStyle(selected ? .white : color)
                .clipShape(Capsule())
        }
        .buttonStyle(.borderless)
    }

    /// A context-menu picker to move a download into a category (or clear it).
    /// The current choice gets a checkmark.
    @ViewBuilder
    private func categoryMenu(for hash: String) -> some View {
        let current = model.category(for: hash)?.id
        Button {
            model.assignCategory(nil, to: hash)
        } label: {
            if current == nil {
                Label("No category", systemImage: "checkmark")
            } else {
                Text("No category")
            }
        }
        ForEach(model.categories) { cat in
            Button {
                model.assignCategory(cat.id, to: hash)
            } label: {
                if current == cat.id {
                    Label(cat.name, systemImage: "checkmark")
                } else {
                    Text(cat.name)
                }
            }
        }
    }

    /// A context-menu submenu to set a download's priority. High makes padMule
    /// contact more sources at once; Low fewer. The current level is checkmarked.
    @ViewBuilder
    private func priorityMenu(for dl: DownloadInfo) -> some View {
        Menu {
            priorityButton("High", 2, dl)
            priorityButton("Normal", 1, dl)
            priorityButton("Low", 0, dl)
        } label: {
            Label("Priority", systemImage: "arrow.up.arrow.down")
        }
    }

    @ViewBuilder
    private func priorityButton(_ name: String, _ value: UInt8, _ dl: DownloadInfo) -> some View {
        Button {
            model.setPriority(dl.hash, priority: value)
        } label: {
            if dl.priority == value {
                Label(name, systemImage: "checkmark")
            } else {
                Text(name)
            }
        }
    }

    /// A small glyph for a non-Normal priority (High = up, Low = down); nothing
    /// for Normal, to keep the common case uncluttered.
    @ViewBuilder
    private func priorityIcon(_ priority: UInt8) -> some View {
        switch priority {
        case 2:
            Image(systemName: "arrow.up.circle.fill")
                .font(.caption2)
                .foregroundStyle(.orange)
        case 0:
            Image(systemName: "arrow.down.circle")
                .font(.caption2)
                .foregroundStyle(.secondary)
        default:
            EmptyView()
        }
    }

    // MARK: - Function strip

    /// The seven functions, icon over name, evenly spread across the width. Sits
    /// directly under the navigation title and above the banners, so the app's
    /// shape is visible at a glance on a screen with no window chrome.
    private var functionStrip: some View {
        VStack(spacing: 0) {
            HStack(spacing: 4) {
                ForEach(Screen.allCases) { s in
                    FunctionButton(screen: s, selected: screen == s) {
                        screen = s
                    }
                }
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            Divider()
        }
        .background(.bar)
    }

    // MARK: - Search screen

    private var searchScreen: some View {
        ScrollViewReader { proxy in
            List {
                Section("Search") {
                    HStack {
                        TextField("Search the eD2k network", text: $query)
                            .textInputAutocapitalization(.never)
                            .disableAutocorrection(true)
                            .onSubmit { model.search(query) }
                            .submitLabel(.search)
                        if model.searching {
                            ProgressView()
                        } else if !query.isEmpty {
                            Button {
                                query = ""
                                model.clearSearch()
                            } label: {
                                Image(systemName: "xmark.circle.fill")
                                    .foregroundStyle(.secondary)
                                    .accessibilityLabel("Clear search")
                            }
                            .buttonStyle(.plain)
                        }
                    }
                    if model.searching {
                        Text("Searching... the server can take a few seconds.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    searchOptionsGroup
                    if model.searched && !model.results.isEmpty {
                        HStack {
                            Menu {
                                Picker("Sort", selection: $model.sortKey) {
                                    ForEach(SortKey.allCases) { Text($0.rawValue).tag($0) }
                                }
                                Toggle("Ascending", isOn: $model.sortAscending)
                            } label: {
                                Label("Sort: \(model.sortKey.rawValue)", systemImage: "arrow.up.arrow.down")
                                    .font(.caption)
                            }
                            Spacer()
                            Menu {
                                Button("All types") { model.typeFilter = nil }
                                ForEach(["Video", "Audio", "Archive", "Document", "Image", "Program"], id: \.self) { t in
                                    Button(t) { model.typeFilter = t }
                                }
                            } label: {
                                Label(model.typeFilter ?? "All types", systemImage: "line.3.horizontal.decrease.circle")
                                    .font(.caption)
                            }
                        }
                        refineGroup
                        // An honest count (client-side filters can hide rows,
                        // so show both numbers when they differ), plus a way
                        // back to the top once the list is long enough to need one.
                        Text(model.presentedResults.count == model.results.count
                             ? "Results (\(model.results.count))"
                             : "Results (\(model.presentedResults.count) of \(model.results.count))")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            // The trigger for the floating Top button below: once
                            // this header scrolls off, there is something to go
                            // back TO. Cheaper and steadier than reading scroll
                            // offset, and it works on iOS 16 (onScrollGeometryChange
                            // is 18+).
                            .onAppear { resultsHeaderVisible = true }
                            .onDisappear { resultsHeaderVisible = false }
                    }
                    ForEach(Array(model.presentedResults.enumerated()), id: \.element.hash) { idx, hit in
                        resultRow(hit, number: idx + 1)
                            .contentShape(Rectangle())
                            .onTapGesture { detail = hit }
                    }
                    if model.searched, !model.searching {
                        if model.results.isEmpty {
                            // "No results" is only true if we actually ASKED someone.
                            // With no server and no Kad contacts the honest answer is
                            // about the connection - and this is the screen a new user
                            // lands on, so it is where they will meet the problem.
                            Text(model.canDiscover
                                 ? "No results."
                                 : "Not connected yet, so there was nobody to ask. Pick a server on the Servers tab, or give Kad a moment to find contacts.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        } else if model.presentedResults.isEmpty {
                            // Hits came back but the client-side filters hid them all -
                            // say so, instead of leaving a blank gap under the filters.
                            Text("No matches for these filters.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                    // The server said it has more pages (#13): fetch the next one and
                    // merge it into this same list. Hidden once the server is tapped out.
                    if model.moreAvailable, !model.searching {
                        Button {
                            model.loadMore()
                        } label: {
                            Label("Load more results", systemImage: "arrow.down.circle")
                        }
                        .font(.callout)
                    }
                }
                .id("results-top")

                // Recent queries: shown when the box is empty, so you can re-run a
                // search with one tap instead of retyping. Swipe a row to forget it.
                if query.isEmpty, !model.recentSearches.isEmpty {
                    Section("Recent") {
                        ForEach(model.recentSearches, id: \.self) { q in
                            Button {
                                query = q
                                model.search(q)
                            } label: {
                                Label(q, systemImage: "clock.arrow.circlepath")
                                    .foregroundStyle(.primary)
                            }
                            .swipeActions(edge: .trailing) {
                                Button(role: .destructive) {
                                    model.removeRecent(q)
                                } label: {
                                    Label("Delete", systemImage: "trash")
                                }
                            }
                        }
                    }
                }
            }
            // A way back to the top that is THERE when you need it. Apple's own
            // convention is the status-bar tap (verified working here), but it
            // is invisible to anyone who does not already know it, so this is
            // the familiar long-feed affordance on top of it - not instead of
            // it. Deliberately ONE floating control rather than a button per
            // row: a 351-result list would otherwise repeat the same chrome 351
            // times, competing with Get on every single row.
            .overlay(alignment: .bottomTrailing) {
                if !resultsHeaderVisible, model.presentedResults.count > 20 {
                    Button {
                        withAnimation { proxy.scrollTo("results-top", anchor: .top) }
                    } label: {
                        Label("Top", systemImage: "arrow.up.to.line")
                            .font(.caption.weight(.semibold))
                            .padding(.horizontal, 14)
                            .padding(.vertical, 10)
                            .background(.regularMaterial, in: Capsule())
                            .overlay(Capsule().stroke(.quaternary))
                            .shadow(radius: 6, y: 2)
                    }
                    .buttonStyle(.plain)
                    .padding(.trailing, 20)
                    .padding(.bottom, 24)
                    .transition(.opacity.combined(with: .scale))
                }
            }
            .animation(.easeInOut(duration: 0.18), value: resultsHeaderVisible)
        }
    }

    // MARK: - Transfers screen

    private var transfersScreen: some View {
        List {
            // Always shown: with no categories yet it is just the "+" so the
            // first one can be created (the add button used to be hidden here).
            categoryChips
            Section("Transfers") {
                let shown = model.presentedDownloads
                if shown.isEmpty {
                    Text(model.categoryFilter == nil ? "No transfers" : "None in this category")
                        .foregroundStyle(.secondary)
                } else {
                    HStack {
                        Menu {
                            Picker("Sort", selection: $model.transferSortKey) {
                                ForEach(TransferSortKey.allCases) { Text($0.rawValue).tag($0) }
                            }
                            Toggle("Ascending", isOn: $model.transferSortAscending)
                        } label: {
                            Label("Sort: \(model.transferSortKey.rawValue)", systemImage: "arrow.up.arrow.down")
                                .font(.caption)
                        }
                        Spacer()
                    }
                    ForEach(shown, id: \.hash) { dl in
                        transferRow(dl)
                            // ACTUALLY receiving bytes right now, as opposed to
                            // registered-and-hopeful. A row can hold sources and
                            // move nothing, and nothing on screen said so.
                            // Amber rather than green: this is "working", not
                            // "done", and Done is already green.
                            .listRowBackground(
                                dl.receiving
                                    ? Color.yellow.opacity(0.16)
                                    : Color.clear)
                            .swipeActions(edge: .trailing) {
                                Button(role: .destructive) {
                                    model.cancel(dl.hash)
                                } label: {
                                    Label("Remove", systemImage: "trash")
                                }
                            }
                            .contextMenu {
                                Button {
                                    sourcesFor = dl
                                } label: {
                                    Label("View sources", systemImage: "person.2")
                                }
                                if !dl.complete && model.isPreviewable(dl.name) {
                                    Button {
                                        model.startPreview(dl)
                                    } label: {
                                        Label("Preview", systemImage: "play.rectangle")
                                    }
                                }
                                // eMule 0.70b's per-file Pause/Resume, one
                                // slot: which one shows follows the flag.
                                if !dl.complete {
                                    if dl.paused {
                                        Button {
                                            model.resumeDownload(dl.hash)
                                        } label: {
                                            Label("Resume", systemImage: "play.fill")
                                        }
                                    } else {
                                        Button {
                                            model.pauseDownload(dl.hash)
                                        } label: {
                                            Label("Pause", systemImage: "pause.fill")
                                        }
                                    }
                                    // eMule 0.70b's StopFile, which it keeps
                                    // DISTINCT from Pause: stop also drops
                                    // every source and refuses new ones. The
                                    // bytes stay - this is not Remove.
                                    if !dl.paused {
                                        Button {
                                            model.stop(dl.hash)
                                        } label: {
                                            Label("Stop", systemImage: "stop.fill")
                                        }
                                    }
                                }
                                Divider()
                                priorityMenu(for: dl)
                                categoryMenu(for: dl.hash)
                            }
                    }
                }
            }

            Section {
                // The honest notice (requirement 1). iPadOS reclaims sockets from
                // a backgrounded app; saying otherwise would be a lie.
                Label(
                    backgroundSeedingOn && model.sharing
                        ? "padMule downloads only while it is open and on screen. "
                            + "With background seeding on, uploads keep going for a while "
                            + "after you leave; downloads pause and resume when you return. "
                            + "Progress is always saved."
                        : "padMule only transfers while it is open and on screen. "
                            + "iPadOS suspends background apps, so leaving stops the transfer. "
                            + "Progress is always saved, and it restarts when you come back - "
                            + "though a transfer that can't find sources again may need a nudge.",
                    systemImage: "info.circle"
                )
                .font(.footnote)
                .foregroundStyle(.secondary)
                Label(
                    "Finished downloads are verified against their eD2k hash and saved "
                        + "to the Files app, under On My iPad > padMule.",
                    systemImage: "folder"
                )
                .font(.footnote)
                .foregroundStyle(.secondary)
            }
        }
    }

    // MARK: - Downloaded screen

    /// Finished files exactly as they sit in Documents (On My iPad > padMule),
    /// read straight off the filesystem by EngineModel.loadDownloadedFiles - so,
    /// unlike the Shared screen's library, a file the user unshared still shows
    /// up here as long as its bytes are still on disk. The ShareLink on each row
    /// is the "Open" affordance: it hands the file to any other app that can
    /// take it.
    private var downloadedScreen: some View {
        List {
            Section(model.downloadedFiles.isEmpty
                    ? "Downloaded"
                    : "Downloaded (\(model.downloadedFiles.count))") {
                if model.downloadedFiles.isEmpty {
                    Text("No finished downloads yet. Finished files are saved to the Files app, "
                         + "under On My iPad > padMule.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else {
                    // Same sort idiom as Transfers, so the two lists behave alike.
                    HStack {
                        Menu {
                            Picker("Sort", selection: $model.downloadedSortKey) {
                                ForEach(DownloadedSortKey.allCases) { Text($0.rawValue).tag($0) }
                            }
                            Toggle("Ascending", isOn: $model.downloadedSortAscending)
                        } label: {
                            Label(
                                "Sort: \(model.downloadedSortKey.rawValue)",
                                systemImage: "arrow.up.arrow.down")
                                .font(.caption)
                        }
                        Spacer()
                    }
                    ForEach(model.presentedDownloadedFiles) { file in
                        HStack {
                            // Tapping the row OPENS the file in the system
                            // viewer (video, audio, PDF, images, documents).
                            // iOS refuses to hand a file:// URL to another app
                            // via UIApplication.open, so QuickLook is the real
                            // "open" - and its own toolbar carries the share
                            // button for handing off to a specific app.
                            Button {
                                quickLook = QuickLookItem(id: file.id, url: file.url)
                            } label: {
                                HStack {
                                    Image(systemName: "doc")
                                        .foregroundStyle(.secondary)
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(file.name).lineLimit(1)
                                            .foregroundStyle(.primary)
                                        Text("\(bytes(file.size)) - \(file.modified.formatted(date: .abbreviated, time: .shortened))")
                                            .font(.caption)
                                            .foregroundStyle(.secondary)
                                    }
                                    Spacer()
                                }
                            }
                            .buttonStyle(.plain)
                            .accessibilityLabel("Preview \(file.name)")
                            // TWO different intents, and the labels now say so.
                            // The row PREVIEWS inside padMule (QuickLook); this
                            // hands the file to another app entirely - a video
                            // opens in a video app, full screen - which
                            // backgrounds padMule and therefore pauses
                            // transfers. Sharing is still reachable from
                            // QuickLook's own toolbar, so nothing is lost by
                            // replacing the share arrow with the clearer action.
                            Button("Open") { model.openInAnotherApp(file) }
                                .buttonStyle(.borderless)
                                .accessibilityLabel("Open \(file.name) in another app")
                        }
                    }
                }
            }
        }
        .onAppear { model.loadDownloadedFiles() }
        .refreshable { model.loadDownloadedFiles() }
    }

    // MARK: - Servers screen

    private var serversScreen: some View {
        List {
            // Server news lives HERE, not above every screen. It is often a
            // dozen-line MOTD and it persists, so parked globally it pushed the
            // actual content down on tabs it had nothing to do with. Dismissable,
            // because a MOTD has been read once.
            if let news = model.serverNotice {
                Section {
                    HStack(alignment: .top, spacing: 8) {
                        Image(systemName: "info.circle")
                        Text(news).font(.footnote)
                        Spacer(minLength: 8)
                        Button {
                            model.serverNotice = nil
                        } label: {
                            Image(systemName: "xmark.circle.fill")
                        }
                        .buttonStyle(.borderless)
                        .accessibilityLabel("Dismiss server message")
                    }
                    .foregroundStyle(.white)
                    // Same #000066 as every other banner - this is the SERVER
                    // NEWS banner, and it was the one Anthony picked the
                    // treatment from originally, so it must not be the one left
                    // behind on the old bright blue.
                    //
                    // Rectangle().fill(...) because listRowBackground needs a
                    // VIEW, not a ShapeStyle.
                    .listRowBackground(Rectangle().fill(Color.bannerBlue))
                }
            }
            Section {
                if let s = model.server {
                    HStack {
                        Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
                        VStack(alignment: .leading, spacing: 2) {
                            // NAME (addr), exactly as the Status screen's Server
                            // row renders it (Anthony, 2026-08-04). The bare
                            // address made the connected row the only place in
                            // the app that identified a server by number when it
                            // had a name - and the name is what the user picked
                            // it by in the list directly below.
                            Text("Connected to " + serverLabel(s)).font(.callout)
                            Text(s.lowId ? "LowID" : "HighID")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Button("Disconnect", role: .destructive) { model.disconnectServer() }
                            .buttonStyle(.borderless)
                    }
                } else {
                    Text("Not connected. padMule does not auto-connect - pick a live server below.")
                        .font(.callout).foregroundStyle(.secondary)
                }
                Button {
                    model.loadServers()
                } label: {
                    HStack {
                        Label(
                            model.loadingServers ? "Probing servers..." : "Refresh server list",
                            systemImage: "arrow.clockwise")
                        Spacer()
                        if model.serverOp == .probing { ProgressView() }
                    }
                }
                .disabled(model.loadingServers)

                // Auto-update the list from a public URL (#18): fetch + MERGE, so
                // existing servers are kept and only new ones added.
                HStack {
                    TextField("Server list URL", text: $serverListUrl)
                        .textInputAutocapitalization(.never)
                        .disableAutocorrection(true)
                        .font(.caption)
                    Button {
                        model.updateServerList(serverListUrl)
                    } label: {
                        HStack(spacing: 4) {
                            Text("Update")
                            if model.serverOp == .updating { ProgressView() }
                        }
                    }
                    .buttonStyle(.borderless)
                    .disabled(model.loadingServers)
                }
                // Prune: drop every dead, unpinned server (pinned stars survive).
                Button(role: .destructive) {
                    model.pruneDeadServers()
                } label: {
                    HStack {
                        Label("Prune dead servers", systemImage: "trash")
                        Spacer()
                        if model.serverOp == .pruning { ProgressView() }
                    }
                }
                .disabled(model.loadingServers)

                // Crawl: ask known servers for the servers THEY know. Most stay
                // silent, so this is a slow trickle, not a guaranteed find.
                Button {
                    model.crawlServers()
                } label: {
                    HStack {
                        Label("Discover more servers", systemImage: "antenna.radiowaves.left.and.right")
                        Spacer()
                        if model.serverOp == .crawling { ProgressView() }
                    }
                }
                .disabled(model.loadingServers)
            }

            Section("Servers (\(model.servers.count))") {
                // Tappable column headers, the table convention: tap to sort by
                // that column, tap the active one again to reverse it. The arrow
                // shows on the active column only, so the current order is
                // readable at a glance rather than remembered.
                HStack {
                    serverHeader(.name, width: nil, alignment: .leading)
                    serverHeader(.users, width: 70, alignment: .trailing)
                    serverHeader(.files, width: 84, alignment: .trailing)
                }
                .font(.caption2).foregroundStyle(.secondary)

                if model.servers.isEmpty {
                    Text(model.loadingServers ? "Probing..." : "No server list on disk.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                // Index-keyed: server.met is not deduped, so addresses are not a
                // unique identity (duplicate rows would collide on \.addr).
                ForEach(Array(model.presentedServers.enumerated()), id: \.offset) { _, srv in
                    serverRow(srv)
                }
            }
        }
        // The list is loaded on APP OPEN now (EngineModel.boot), so this is only
        // a fallback for the case where boot's own load found nothing - it must
        // not re-probe on every visit to the tab.
        .onAppear { if model.servers.isEmpty && model.ready { model.loadServers() } }
    }

    /// One tappable column header. Tapping the ACTIVE column reverses it, which
    /// is what a second tap means in every table users have met.
    @ViewBuilder
    private func serverHeader(
        _ key: ServerSortKey, width: CGFloat?, alignment: Alignment
    ) -> some View {
        Button {
            if model.serverSortKey == key {
                model.serverSortAscending.toggle()
            } else {
                model.serverSortKey = key
                // Names read naturally A-Z; counts are most useful biggest-first.
                model.serverSortAscending = (key == .name)
            }
        } label: {
            HStack(spacing: 2) {
                if alignment == .trailing { Spacer(minLength: 0) }
                Text(key.rawValue)
                if model.serverSortKey == key {
                    Image(systemName: model.serverSortAscending ? "chevron.up" : "chevron.down")
                        .font(.system(size: 8, weight: .bold))
                }
                if alignment == .leading { Spacer(minLength: 0) }
            }
        }
        .buttonStyle(.plain)
        .foregroundStyle(model.serverSortKey == key ? Color.accentColor : .secondary)
        .frame(maxWidth: width == nil ? .infinity : nil, alignment: alignment)
        .frame(width: width)
        .accessibilityLabel("Sort by \(key.rawValue)")
    }

    /// One server row: name/address, live user/file counts, and connection state.
    /// A live (probe-answering) server is black + selectable to connect; a dead
    /// one is greyed out and disabled, matching eMule's server list.
    ///
    /// The connected treatment (green semibold name, checkmark, tinted row) is
    /// keyed on the LIVE login via `EngineModel.serverRowConnected`, NEVER on
    /// `srv.connected` - that flag is a snapshot stamped at probe time, and
    /// after toolbar Stop it kept the previous server styled connected while
    /// Status honestly read "Not connected" (on glass 2026-08-09). The tap
    /// DECISION lives in `EngineModel.connectServer` (the pure
    /// `serverTapAction`), which composes that same live answer: the
    /// already-connected row's tap is swallowed there, and a tap while the
    /// engine is stopped STARTS it before dialing - on glass the same day, a
    /// bare dial while stopped logged in with the listener down, earning a
    /// stuck LowID under a Status screen that read Stopped.
    private func serverRow(_ srv: ServerEntryFfi) -> some View {
        let connectedNow = EngineModel.serverRowConnected(
            rowAddr: srv.addr, state: model.state, liveServerAddr: model.server?.addr)
        return HStack {
            // Pin star: independently tappable even on an offline row (a pin
            // protects a temporarily-down favorite from Prune). Borderless so its
            // tap does not trigger the connect button beside it.
            Button {
                model.togglePin(srv.addr)
            } label: {
                Image(systemName: srv.pinned ? "star.fill" : "star")
                    .foregroundStyle(srv.pinned ? .yellow : .secondary)
            }
            .buttonStyle(.borderless)
            .accessibilityLabel(srv.pinned ? "Unpin server" : "Pin server")

            Button {
                // The lifecycle decision (already connected? engine stopped?)
                // is connectServer's, in ONE place.
                //
                // NO `srv.alive` GATE. It used to be here, and it made every
                // "no reply" row's tap silently inert - 44ba972 made the rows
                // SELECTABLE and left the gate behind, so the row invited a
                // tap and then did nothing. THE PROBE IS UDP AND THE LOGIN IS
                // TCP: "no reply" means the status ping went unanswered, which
                // plenty of networks and filters cause on their own, and says
                // nothing about whether a TCP login would succeed. The status
                // column already tells the user the ping failed; refusing the
                // tap on top of that decides for them.
                //
                // It also BLOCKED A SECURITY TEST (handoff 15, promoted
                // 2026-08-11): verifying 35f's server-probe exemption needs the
                // server's own /24 blocklisted, which filters that server's UDP
                // status reply - so the row never went alive, its tap did
                // nothing, and the login the test depends on was never
                // attempted. The gate disabled the only control that could
                // start the exercise.
                model.connectServer(srv.addr)
            } label: {
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(srv.name.isEmpty ? srv.addr : srv.name)
                            .font(.callout)
                            .fontWeight(connectedNow ? .semibold : .regular)
                            .foregroundStyle(connectedNow ? .green : (srv.alive ? .primary : .secondary))
                            .lineLimit(1)
                        if !srv.name.isEmpty {
                            Text(srv.addr).font(.caption2).foregroundStyle(.secondary)
                        }
                    }
                    Spacer()
                    if srv.alive {
                        Text(srv.users.formatted())
                            .font(.caption).monospacedDigit()
                            .frame(width: 70, alignment: .trailing)
                        Text(srv.files.formatted())
                            .font(.caption).monospacedDigit()
                            .frame(width: 84, alignment: .trailing)
                    } else {
                        // THREE states, not two. "no reply" not "offline": the
                        // probe is a UDP status ping, and plenty of networks
                        // block outbound UDP while passing the TCP the actual
                        // login uses - saying "offline" asserted more than we
                        // know. And "checking..." not "no reply" for a server
                        // that has simply never answered YET: the probe's memory
                        // is per-launch, so on a cold start every server is in
                        // that state after one silent round, and calling them
                        // all dead is a verdict from one datum. Proven live on
                        // 2026-08-05 - padMule showed a server as "no reply" and
                        // logged into it with HighID moments later.
                        Text(srv.checking ? "checking..." : "no reply")
                            .font(.caption).foregroundStyle(.secondary)
                            .frame(width: 154, alignment: .trailing)
                    }
                    if model.connectingTo == srv.addr {
                        ProgressView()
                    } else if connectedNow {
                        Image(systemName: "checkmark.circle.fill")
                            .foregroundStyle(.green)
                    }
                }
            }
            .buttonStyle(.borderless)
            // A server that did not answer the UDP probe stays SELECTABLE. It used
            // to be disabled, which made padMule unusable on any network that
            // blocks outbound UDP - every row greyed out, no manual-address field,
            // nothing to tap - even though the TCP login would likely have worked.
            .disabled(model.connectingTo != nil)
            .foregroundStyle(.primary)
        }
        .listRowBackground(connectedNow ? Color.green.opacity(0.08) : Color.clear)
    }

    // MARK: - Shared screen

    private var sharedScreen: some View {
        List {
            Section("Sharing") {
                Toggle("Share uploads", isOn: Binding(
                    get: { model.sharing },
                    set: { model.setSharing($0) }
                ))
                // Say the current EFFECTIVE state, and why, so a user whose
                // sharing was auto-paused does not think the toggle is broken -
                // same reasoning as SettingsView's sharingPausedForMeteredLink
                // footer, checked first for the same reason: it overrides
                // whatever the toggle itself reads.
                if model.sharingPausedForIpChange {
                    Text("Sharing is paused because your public address changed (likely a VPN drop or a network switch). Turn sharing back on when you're ready.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else {
                    Text(model.sharing
                        ? "padMule serves these files to other peers while it's open. Sharing earns you better standing in their queues, so your own downloads go faster."
                        : "Leech Mode: downloading only. padMule is not serving any files to peers.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            Section(model.sharedFiles.isEmpty ? "Library" : "Library (\(model.sharedFiles.count))") {
                if model.sharedFiles.isEmpty {
                    Text("Nothing shared yet. Files you finish downloading are shared automatically.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(model.sharedFiles, id: \.hash) { f in
                        VStack(alignment: .leading, spacing: 3) {
                            HStack {
                                Image(systemName: "doc")
                                    .foregroundStyle(.secondary)
                                Text(f.name.isEmpty ? String(f.hash.prefix(16)) : f.name)
                                    .lineLimit(1)
                                if f.rating > 0 { sharedRatingPill(f.rating) }
                                Spacer()
                                Text(bytes(f.size))
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                            if !f.comment.isEmpty {
                                Text("\u{201C}\(f.comment)\u{201D}")
                                    .font(.caption)
                                    .italic()
                                    .foregroundStyle(.secondary)
                                    .lineLimit(2)
                            }
                        }
                        .contentShape(Rectangle())
                        .onTapGesture { ratingFor = f }
                        .swipeActions(edge: .leading) {
                            // Rate / comment this file; served to downloaders.
                            Button {
                                ratingFor = f
                            } label: {
                                Label("Rate", systemImage: "star")
                            }
                            .tint(.blue)
                        }
                        .swipeActions(edge: .trailing) {
                            // DELETE removes the file from the device as well as
                            // from the library. It sits behind a confirmation
                            // because it is the only irreversible action on this
                            // screen - Unshare beside it is not.
                            Button(role: .destructive) {
                                deleteCandidate = f
                            } label: {
                                Label("Delete", systemImage: "trash")
                            }
                            // Stop serving this file; the file stays in your Files.
                            Button {
                                model.unshare(f.hash)
                            } label: {
                                Label("Unshare", systemImage: "xmark.circle")
                            }
                            .tint(.orange)
                        }
                    }
                }
            }
        }
    }

    // MARK: - Status screen

    private var statusScreen: some View {
        List {
            // At-a-glance health for the two networks padMule depends on,
            // answered directly rather than making the user infer it from the
            // Status/Server rows below - eD2k and Kad are independent, and a
            // user with one up and the other down needs to see that at a
            // glance instead of reading through connection prose.
            Section("Network") {
                networkHealthRow("eD2k network", ed2kHealth)
                networkHealthRow("Kad network", kadHealth)
            }

            Section("Status") {
                row("State", String(describing: model.state))
                // A pure connectivity verdict (EngineModel.connectionSummary),
                // not the engine's free-text status - that used to duplicate
                // the Server row below in different words ("Connected to X
                // (HighID)" here AND "X" there). The Server row now carries
                // the identity; this row only answers "are we connected".
                row("Status", model.connectionSummary)
                // NO "Activity" row. It was meant to preserve the engine's
                // transient text ("Fetching network lists...", "Opening
                // port..."), but its guard compared against the SUMMARY
                // ("Connected") while the engine's string is the full sentence
                // ("Connected to X (addr)") - so once connected it always
                // differed, and rendered a verbatim duplicate of Server below.
                // Nothing is lost: Paused/Stopped/Reconnecting are already the
                // Status verdict, and the boot-time messages happen behind the
                // splash and the "Starting padMule..." banner.
                // The ID type decides whether peers can reach us at all, so it
                // gets its own row instead of riding on the status line, where a
                // later event would overwrite it.
                if let srv = model.server {
                    // Identity only - name (address) - now that Status above
                    // no longer repeats "Connected to". Shares `serverLabel`
                    // with the Servers tab so the two cannot drift apart.
                    row("Server", serverLabel(srv))
                    HStack {
                        Text("ID").foregroundStyle(.secondary)
                        Spacer()
                        Text(srv.lowId ? "LowID" : "HighID")
                            .foregroundStyle(srv.lowId ? .orange : .green)
                    }
                    .font(.callout)
                }
                row("Kad contacts", "\(model.kadContacts)")
                // The port-mapping result: the direct answer to "why am I LowID?"
                // when the router should have opened the port.
                row("Port mapping", model.upnpStatus ?? "checking...")
                row("IP filter", model.ipFilterRanges == 0
                    ? "off"
                    : "\(model.ipFilterRanges) ranges blocked")
                if let id = model.identity {
                    // IN FULL: an identifier exists to be COMPARED, and half
                    // of one compares nothing. Stacked rather than in the
                    // key/value row, which would cram 32 hex characters against
                    // a label; selectable so it can be copied out.
                    idRow("User hash", id.userhash)
                    idRow("Kad ID", id.kadId)
                }
            }

            // The closest thing iOS allows to eMule's Exit. iOS has no app-quit an
            // app may call, so this stops the ENGINE cleanly and tells the user
            // they can now close the app; the alternative was leaving the port
            // mapping and connections behind on every exit.
            Section {
                if model.stopping {
                    HStack(spacing: 10) {
                        ProgressView()
                        Text(model.state == .stopped ? "Starting..." : "Stopping...")
                            .foregroundStyle(.secondary)
                    }
                } else if model.state == .stopped {
                    Button {
                        model.startEngine()
                    } label: {
                        Label("Start padMule", systemImage: "play.circle")
                    }
                } else {
                    Button(role: .destructive) {
                        confirmStop = true
                    } label: {
                        Label("Stop padMule", systemImage: "stop.circle")
                    }
                }
            } footer: {
                Text(stopFooter)
            }
        }
    }

    /// "eD2k network" row content: green connected+HighID, orange
    /// connected-but-LowID (peers cannot reach us directly), red not
    /// connected. Independent of Kad - the two networks can be up or down on
    /// their own, which is exactly what a user asking "is Kad working" needs
    /// to see without inferring it from the Server/Kad-contacts rows.
    private var ed2kHealth: (color: Color, text: String) {
        guard let srv = model.server else { return (.red, "Not connected") }
        if srv.lowId {
            return (.orange, "Connected, LowID - peers cannot reach you directly")
        }
        // serverLabel, not a third naming voice: it centralizes the
        // "Name (ip:port)" rule and guards the empty-name case.
        return (.green, "Connected - \(serverLabel(srv)), HighID")
    }

    /// "Kad network" row content. The rule lives in `kadRowHealth` (pinned by
    /// `KadHealthTests`); the row calls THAT, so rule and row cannot drift.
    private var kadHealth: (color: Color, text: String) {
        ContentView.kadRowHealth(state: model.state, contacts: model.kadContacts)
    }

    /// The rule alone: "Stopped" only when the Kad node is actually down,
    /// else red/amber/green by contact count.
    ///
    /// `.seeding` counts as UP, same as `.running` - the 2026-08-09 engine
    /// change keeps the Kad node alive while background seeding: it still
    /// answers inbound requests, publishes, and runs the liveness sweep; only
    /// the growth refresh is suspended. This row said "Stopped" there, which
    /// was honest before that change and dishonest status after it (lifecycle
    /// requirement 1). Any FUTURE engine state stays "Stopped" - the direction
    /// that never overclaims.
    ///
    /// The amber band exists because a freshly-started Kad table climbs from 0
    /// over tens of seconds - "Not connected" would read as broken during a
    /// normal warm-up. Its copy is "Low contacts (n)", a plain count, not the
    /// old "Bootstrapping": a seeding node with its growth refresh suspended
    /// is not bootstrapping, and the count is true in both states.
    static func kadRowHealth(
        state: EngineStateFfi, contacts: UInt32
    ) -> (color: Color, text: String) {
        guard state == .running || state == .seeding else {
            return (.secondary, "Stopped")
        }
        if contacts == 0 { return (.red, "Not connected") }
        if contacts < 10 { return (.orange, "Low contacts (\(contacts))") }
        return (.green, "OK (\(contacts) contacts)")
    }

    /// One network-health row: a small colored dot (echoing `statusDot`'s
    /// vocabulary of a plain SF Symbol circle) plus the label and its verdict.
    private func networkHealthRow(_ label: String, _ health: (color: Color, text: String)) -> some View {
        HStack {
            Image(systemName: "circle.fill")
                .font(.caption2)
                .foregroundStyle(health.color)
            Text(label)
            Spacer()
            Text(health.text)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.trailing)
        }
        .font(.callout)
    }

    /// The Stop section's explanation, which must never describe work that did
    /// not happen. Plenty of users have NO port mapping to hand back - on
    /// cellular, behind CGNAT, or on a router without UPnP the mapping never
    /// succeeded - so the router sentence appears only when one is actually held
    /// (`model.portMapped`, read from the engine's own `has_port_mapping`, not
    /// guessed from the status text).
    private var stopFooter: String {
        if model.state == .stopped {
            // Deliberately silent about the port: a successful release sets
            // portMapped back to false, so this state cannot distinguish "released
            // one" from "never had one" - and it does not need to, because the
            // "Port mapping" row directly above already reads "UPnP: released
            // port 4662" when that happened. Say the one thing that row cannot.
            return "Stopped. Nothing is connected - it is safe to close padMule from the app switcher."
        }
        // Running: this is a PROMISE about what Stop will do, so it is conditioned
        // on whether a mapping is actually held right now.
        return model.portMapped
            ? "Disconnects, saves your progress and hands the forwarded port back to the router. Do this before closing padMule so it does not leave a port mapping behind."
            : "Disconnects and saves your progress, so padMule stops cleanly. Do this before closing it from the app switcher."
    }

    // MARK: - Rows and helpers

    /// One search hit: a status dot, the name, a metadata line (type + media when
    /// present), and the size/sources/complete stats. Tapping the row opens the
    /// detail sheet; the trailing Get button starts a download directly.
    /// Result-name color, following eMule's `GetSearchItemColor`
    /// (SearchListCtrl.cpp:1596): green when we already have the file, red when it
    /// has NO sources (unavailable - it cannot be downloaded), else the normal text
    /// color. eMule also shades new results by a source-count availability
    /// gradient; padMule keeps the clear binary (0-source = red) and lets the
    /// status dot carry the have/downloading state.
    private func resultColor(_ hit: SearchHit) -> Color {
        if model.liveStatus(for: hit) == .have { return .green }
        if hit.sources == 0 { return .red }
        return .primary
    }

    private func resultRow(_ hit: SearchHit, number: Int) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Text("\(number)")
                .font(.caption2)
                .monospacedDigit()
                .foregroundStyle(.secondary)
                .frame(minWidth: 18, alignment: .trailing)
                .padding(.top, 5)
            statusDot(model.liveStatus(for: hit))
                .padding(.top, 5)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(hit.name).lineLimit(2)
                        .foregroundStyle(resultColor(hit))
                    ratingBadge(hit.rating)
                }
                if let meta = metaLine(hit) {
                    HStack(spacing: 6) {
                        Text(meta)
                        originBadge(hit.origin)
                    }
                    .font(.caption)
                    .foregroundStyle(.secondary)
                } else {
                    originBadge(hit.origin)
                }
                HStack(spacing: 6) {
                    Text(bytes(hit.size))
                    Text("-")
                    Text("\(hit.sources) src\(hit.sources == 1 ? "" : "s")"
                        + (hit.completeSources > 0 ? " (\(hit.completeSources) full)" : ""))
                    if !hit.trusted {
                        Text(hit.warning).foregroundStyle(.orange)
                    }
                }
                .font(.caption)
                .foregroundStyle(.secondary)
            }
            Spacer()
            if model.adding.contains(hit.hash) {
                ProgressView()
            } else {
                // Only offer Get for a NEW hit; a file already downloading or
                // owned shows that state instead of a live button that does
                // nothing useful (it contradicts the status dot otherwise).
                switch model.liveStatus(for: hit) {
                case .have:
                    Text("Have").foregroundStyle(.green)
                case .downloading:
                    Text("Downloading").foregroundStyle(.orange)
                case .new:
                    Button("Get") { model.download(hit) }
                        .buttonStyle(.borderless)
                }
            }
        }
    }

    /// The eMule-style state indicator: green check if we have it, orange arrow
    /// if it is downloading, an empty circle if new.
    @ViewBuilder
    private func statusDot(_ s: HitStatusFfi) -> some View {
        switch s {
        case .have:
            Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
        case .downloading:
            Image(systemName: "arrow.down.circle.fill").foregroundStyle(.orange)
        case .new:
            Image(systemName: "circle").foregroundStyle(.secondary)
        }
    }

    /// A colored rating pill (server FT_FILERATING). Hidden when unrated (0).
    @ViewBuilder
    private func ratingBadge(_ rating: UInt8) -> some View {
        if rating > 0 {
            let (label, color) = ratingStyle(rating)
            Text(label)
                .font(.caption2)
                .padding(.horizontal, 5)
                .padding(.vertical, 1)
                .background(color.opacity(0.2))
                .foregroundStyle(color)
                .clipShape(Capsule())
        }
    }

    /// A subtle provenance caption ("kad", "server", "server + kad") next to
    /// the meta line - metadata, not the headline, so it is a plain secondary
    /// caption rather than a colored pill like the rating badge above.
    @ViewBuilder
    private func originBadge(_ origin: String) -> some View {
        if !origin.isEmpty {
            Text(origin)
                .font(.caption2)
                .foregroundStyle(.secondary)
                .padding(.horizontal, 5)
                .padding(.vertical, 1)
                .background(Color.secondary.opacity(0.12))
                .clipShape(Capsule())
        }
    }

    private func ratingStyle(_ rating: UInt8) -> (String, Color) {
        switch rating {
        case 1: return ("Fake", .red)
        case 2: return ("Poor", .orange)
        case 3: return ("Fair", .yellow)
        case 4: return ("Good", .green)
        default: return ("Excellent", .green)
        }
    }

    /// Type + media summary, only when there is something to show.
    private func metaLine(_ hit: SearchHit) -> String? {
        var parts: [String] = []
        if !hit.fileType.isEmpty && hit.fileType != "Other" { parts.append(hit.fileType) }
        if hit.lengthSecs > 0 { parts.append(duration(hit.lengthSecs)) }
        if hit.bitrate > 0 { parts.append("\(hit.bitrate) kbps") }
        if !hit.artist.isEmpty { parts.append(hit.artist) }
        return parts.isEmpty ? nil : parts.joined(separator: "  -  ")
    }

    private func duration(_ secs: UInt32) -> String {
        let s = Int(secs)
        let h = s / 3600
        let m = (s % 3600) / 60
        let sec = s % 60
        return h > 0
            ? String(format: "%d:%02d:%02d", h, m, sec)
            : String(format: "%d:%02d", m, sec)
    }

    private func transferRow(_ dl: DownloadInfo) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                if let cat = model.category(for: dl.hash) {
                    Circle().fill(cat.color).frame(width: 8, height: 8)
                }
                Text(dl.name.isEmpty ? String(dl.hash.prefix(16)) : dl.name)
                    .lineLimit(1)
                priorityIcon(dl.priority)
                ratingBadge(dl.rating)
                if dl.hasComment {
                    Image(systemName: "text.bubble")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                if let badge = TransferRowState.badge(
                    complete: dl.complete,
                    engineStopped: TransferRowState.engineStopped(model.state),
                    fileStopped: dl.stopped,
                    filePaused: dl.paused,
                    queued: dl.queued)
                {
                    // Per-transfer state badge (requirement 3, eMule 0.70b's
                    // row vocabulary + padMule's Queued). The precedence lives
                    // in TransferRowState - pinned by its tests, and the row
                    // calls THAT, so rule and caller cannot drift. Any
                    // non-running engine state counts as stopped - seeding
                    // included: downloads halt there; uploads and the Kad
                    // node keep going.
                    if badge == .done {
                        Text(badge.label).font(.caption).foregroundStyle(.green)
                    } else {
                        Text(badge.label)
                            .font(.caption2)
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(Color.secondary.opacity(0.2))
                            .clipShape(Capsule())
                    }
                }
            }
            ProgressView(value: fraction(dl))
            HStack(spacing: 6) {
                Text("\(bytes(dl.have)) / \(bytes(dl.size))")
                Text("\(Int(fraction(dl) * 100))%")
                if let origins = sourceOrigins(dl) {
                    Text(origins)
                        .accessibilityLabel("Sources: \(origins)")
                }
                // Orange, because unlike the other numbers on this row it is not
                // progress - it is the reason there may not BE any.
                if let gap = missingParts(dl) {
                    Text(gap)
                        .foregroundStyle(.orange)
                        .accessibilityLabel(gap)
                }
            }
            .font(.caption)
            .foregroundStyle(.secondary)
        }
    }

    private func fraction(_ dl: DownloadInfo) -> Double {
        dl.size == 0 ? 0 : Double(dl.have) / Double(dl.size)
    }

    /// Connected sources by DISCOVERY CHANNEL, e.g. "4 ed2k / 2 kad" - which
    /// channel is actually feeding this transfer. Invisible otherwise, and it is
    /// the first question when one file flies and another crawls. Channels with
    /// no sources are omitted rather than shown as zeros.
    ///
    /// When NOTHING is connected it falls back to describing the POOL instead of
    /// going quiet, because silence there was unreadable - see `idlePool`.
    private func sourceOrigins(_ dl: DownloadInfo) -> String? {
        var parts: [String] = []
        if dl.sourcesServer > 0 { parts.append("\(dl.sourcesServer) ed2k") }
        if dl.sourcesKad > 0 { parts.append("\(dl.sourcesKad) kad") }
        // Source exchange is a THIRD channel, not a flavour of the other two -
        // naming it "sx" keeps the badge honest rather than folding peer-learned
        // sources into the server count.
        if dl.sourcesExchange > 0 { parts.append("\(dl.sourcesExchange) sx") }
        return parts.isEmpty ? idlePool(dl) : parts.joined(separator: " / ")
    }

    /// The VPN indicator as a toolbar item, with the bar's own SHARED BACKGROUND
    /// suppressed (Anthony, 2026-08-05: "you need its surroundings to be
    /// transparent so it blends seamlessly into the light or dark background").
    ///
    /// iPadOS 26 puts every toolbar item inside a shared glass capsule, which is
    /// right for the tappable cluster on the trailing side and wrong here: this
    /// is an INDICATOR, not a control, and the capsule drew a visible disc
    /// around it in both appearances. `sharedBackgroundVisibility(.hidden)` opts
    /// this one item out. Availability-gated because the deployment target is
    /// still iOS 16, where the capsule does not exist and nothing is needed.
    @ToolbarContentBuilder private var vpnToolbarItem: some ToolbarContent {
        if #available(iOS 26.0, *) {
            ToolbarItem(placement: .navigationBarLeading) { vpnBadge }
                .sharedBackgroundVisibility(.hidden)
        } else {
            ToolbarItem(placement: .navigationBarLeading) { vpnBadge }
        }
    }

    /// The VPN indicator: **ON VPN** in blue, or **OFF VPN** in red with VPN
    /// struck through (Anthony, 2026-08-05).
    ///
    /// Always present, in both states. An indicator that only appears when
    /// things are GOOD cannot be trusted to mean anything - its absence reads
    /// identically to "padMule has not looked", which is the failure mode this
    /// whole class of row keeps producing. Saying OFF out loud is the point.
    ///
    /// The VIEW lives in `VpnBadge.swift` so it can be rendered in a test
    /// without a device and without a tunnel in the wanted state - see
    /// `VpnBadgeTests`, which is what now guards its layout.
    private var vpnBadge: some View {
        VpnBadge(on: model.vpnActive)
    }

    /// What a row with ZERO connected sources should say.
    ///
    /// This used to say nothing at all, and the blank was the problem: "no
    /// sources exist" and "sources exist and not one can be reached" are
    /// opposite situations with opposite responses, and both rendered as an
    /// empty line under a 0% progress bar. On 2026-08-05 a 312 MB file sat at
    /// Zero KB for ten minutes while its own search row read "15 srcs (14 full)"
    /// and five siblings ran at hundreds of KB/s - nothing on the transfer row
    /// could account for the difference.
    ///
    /// The LowID split is the part that actually explains it. A LowID source is
    /// dropped from the dial pool outright (`PeerSource::from_found` - it cannot
    /// accept an incoming connection) and can only reach us by being poked
    /// through the server, so "12 awaiting callback" is a completely different
    /// prognosis from "12 sources we are dialing" while looking identical.
    private func idlePool(_ dl: DownloadInfo) -> String? {
        ContentView.idlePoolLabel(found: dl.sourcesFound, callback: dl.sourcesCallback)
    }

    /// The rule alone, so the three branches can be tested. They are the whole
    /// point of the line and each one means something different to the user.
    static func idlePoolLabel(found: UInt32, callback: UInt32) -> String? {
        if found == 0 && callback == 0 { return "no sources found" }
        var parts: [String] = []
        if found > 0 { parts.append("0 of \(found) connected") }
        if callback > 0 { parts.append("\(callback) awaiting callback") }
        return parts.joined(separator: ", ")
    }

    /// Statuses that must have been sampled before the gap is worth showing.
    ///
    /// Below this the claim is too weak to make: from one or two peers, "13
    /// parts nobody has" really means "the one peer we found lacks 13 parts",
    /// which is ordinary and says nothing about the swarm. Four is where a
    /// unanimous gap starts to be interesting rather than anecdotal.
    private static let minStatusesForGap: UInt32 = 4

    /// "13 parts missing from all 22 peer reports" - parts still needed that NOT
    /// ONE sampled peer offered.
    ///
    /// This is the difference between a slow tail and an impossible one, which
    /// look identical on a row reading "90%, 86 sources, not moving": either
    /// padMule is failing to ASK for the remainder, or the swarm does not HAVE
    /// it. The SAMPLE SIZE is named in the text on purpose - the first version
    /// said "N parts nobody has" from a one-source sample, which overstated a
    /// real measurement into a claim about the whole network.
    ///
    /// ...and it said "sources" until 2026-08-05, which overstated it a second
    /// time in the same way. `partStatusReports` counts peer SESSIONS that read
    /// a file status (`Download::note_status`), and `download_file` re-dials the
    /// same pool every round - nothing evicts a source - so three peers dialled
    /// eight times each rendered as "all 24 sources". "Peer reports" is what the
    /// number actually is. The gap itself was never wrong; only its denominator.
    private func missingParts(_ dl: DownloadInfo) -> String? {
        guard dl.partsUnavailable > 0,
              dl.partStatusReports >= Self.minStatusesForGap
        else { return nil }
        let n = dl.partsUnavailable
        let seen = dl.partStatusReports
        // `seen` >= minStatusesForGap (4) past the guard, so the plural is
        // unconditional - a "1 peer report" arm here was unreachable.
        return n == 1
            ? "1 part missing from all \(seen) peer reports"
            : "\(n) parts missing from all \(seen) peer reports"
    }

    private func bytes(_ n: UInt64) -> String {
        // clamping: a hostile size > Int64.max would TRAP a plain Int64() init.
        ByteCountFormatter.string(fromByteCount: Int64(clamping: n), countStyle: .file)
    }

    /// The eMule rating scale (1 Fake .. 5 Excellent) as a small colored pill.
    private func sharedRatingPill(_ rating: UInt8) -> some View {
        let (label, color): (String, Color) = {
            switch rating {
            case 1: return ("Fake", .red)
            case 2: return ("Poor", .orange)
            case 3: return ("Fair", .yellow)
            case 4: return ("Good", .green)
            default: return ("Excellent", .green)
            }
        }()
        return Text(label)
            .font(.caption2)
            .padding(.horizontal, 5).padding(.vertical, 1)
            .background(color.opacity(0.2)).foregroundStyle(color)
            .clipShape(Capsule())
    }

    /// A full identity value: stacked, monospaced and selectable.
    private func idRow(_ k: String, _ v: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(k).foregroundStyle(.secondary)
            Text(v)
                .font(.caption.monospaced())
                .textSelection(.enabled)
                .lineLimit(2)
                .minimumScaleFactor(0.7)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func row(_ k: String, _ v: String) -> some View {
        HStack {
            Text(k).foregroundStyle(.secondary)
            Spacer()
            Text(v).multilineTextAlignment(.trailing)
        }
        .font(.callout)
    }

    /// A size-preset menu (megabytes; 0 = "Any") for the pre-search size bounds.
    /// PRE-search options, rolled up (Anthony, 2026-08-05: "too many option rows
    /// in that Search tab"). These five controls sat permanently open above the
    /// results and cost most of a screen before a single hit was visible.
    ///
    /// Collapsed by default, and its own `@ViewBuilder` for the reason row 8bw
    /// paid for: a handful of conditional controls inline in an already-long
    /// VStack is what pushed Swift's type-checker over its limit last time.
    @ViewBuilder private var searchOptionsGroup: some View {
        DisclosureGroup(isExpanded: $showSearchOptions) {
            // The server applies these to what it RETURNS, so the capped result
            // set fills with matches instead of junk.
            Toggle("Complete sources only", isOn: $model.wireCompleteOnly)
                .font(.caption)
            Toggle("Search all servers (global)", isOn: $model.wireGlobal)
                .font(.caption)
            HStack {
                Text("Size").font(.caption).foregroundStyle(.secondary)
                Spacer()
                sizeMenu("Min", selection: $model.wireMinSizeMb)
                Text("-").foregroundStyle(.secondary)
                sizeMenu("Max", selection: $model.wireMaxSizeMb)
            }
            .font(.caption)
        } label: {
            Label(Self.optionSummary(prefix: "Search options", active: activeSearchOptions),
                  systemImage: "slider.horizontal.3")
                .font(.caption)
        }
    }

    /// POST-search refinements, rolled up the same way. Sort and type stay OUT of
    /// the disclosure: they are one compact row and the two most-reached-for
    /// controls on the screen.
    @ViewBuilder private var refineGroup: some View {
        DisclosureGroup(isExpanded: $showRefine) {
            HStack {
                Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                TextField("Filter these results", text: $model.nameFilter)
                    .textInputAutocapitalization(.never)
                    .disableAutocorrection(true)
            }
            .font(.caption)
            Toggle("Trusted only", isOn: $model.trustedOnly).font(.caption)
            Toggle("Hide ones I have", isOn: $model.hideHave).font(.caption)
        } label: {
            Label(Self.optionSummary(prefix: "Refine results", active: activeRefinements),
                  systemImage: "line.3.horizontal.decrease")
                .font(.caption)
        }
    }

    private var activeSearchOptions: [String] {
        var on: [String] = []
        if model.wireCompleteOnly { on.append("complete only") }
        if model.wireGlobal { on.append("global") }
        if model.wireMinSizeMb > 0 || model.wireMaxSizeMb > 0 { on.append("size") }
        return on
    }

    private var activeRefinements: [String] {
        var on: [String] = []
        if !model.nameFilter.isEmpty { on.append("\"\(model.nameFilter)\"") }
        if model.trustedOnly { on.append("trusted only") }
        if model.hideHave { on.append("hiding have") }
        return on
    }

    /// The collapsed label must NAME what is switched on, or the roll-up trades
    /// clutter for a worse problem: a user staring at thin results with no way
    /// to see that "trusted only" is filtering them, behind a closed triangle.
    /// Hiding a control is fine; hiding STATE is not.
    static func optionSummary(prefix: String, active: [String]) -> String {
        active.isEmpty ? prefix : "\(prefix): \(active.joined(separator: ", "))"
    }

    private func sizeMenu(_ label: String, selection: Binding<UInt64>) -> some View {
        let presets: [UInt64] = [0, 1, 10, 100, 700, 1024, 4096]
        return Menu {
            ForEach(presets, id: \.self) { mb in
                Button(mb == 0 ? "Any" : sizeLabel(mb)) { selection.wrappedValue = mb }
            }
        } label: {
            Text(selection.wrappedValue == 0 ? "\(label): Any" : "\(label): \(sizeLabel(selection.wrappedValue))")
        }
    }

    private func sizeLabel(_ mb: UInt64) -> String {
        mb >= 1024 ? "\(mb / 1024) GB" : "\(mb) MB"
    }

    /// Global status banners - visible on every screen, and ALL of them
    /// closeable. The three driven by engine STATE (reconnect, sharing-paused,
    /// starting) cannot be cleared by clearing a value, so each carries its own
    /// "hidden" flag that RE-ARMS when its condition next changes (see the
    /// .onChange resets) - dismissing means "I have read this", not "pretend it
    /// never happened".
    ///
    /// Its own @ViewBuilder rather than inline in the body: the conditional
    /// banners (five when this split was made; six now), each with a trailing
    /// closure, pushed the enclosing VStack past what Swift's type-checker
    /// will solve, and CI failed with "unable to type-check this expression
    /// in reasonable time". Splitting a view is the standard cure, and it
    /// costs nothing at runtime.
    @ViewBuilder private var statusBanners: some View {
        if model.reconnecting && !hidReconnecting {
            banner("Reconnecting...", systemImage: "arrow.clockwise", tint: .orange) {
                hidReconnecting = true
            }
        }
        // Persistent (not just the one-shot alert): the user may dismiss the
        // alert and move to another screen, and sharing stays paused until they
        // turn it back on - this keeps that state visible the whole time.
        if model.sharingPausedForIpChange && !hidSharingPaused {
            banner(
                "Sharing paused: your public address changed. Turn sharing back on to clear this.",
                systemImage: "wifi.exclamationmark", tint: .orange
            ) { hidSharingPaused = true }
        }
        if let err = model.bootError {
            banner("Engine failed: " + err, systemImage: "exclamationmark.triangle", tint: .red) {
                model.clearBootError()
            }
        }
        // EVERY control silently no-ops until boot finishes, and saying so is the
        // difference between "starting" and "broken". (This used to claim boot
        // takes 12-30s; the portability audit corrected that - it was the SUM of
        // the timeouts, not a measurement. A warm boot with lists already on disk
        // is ~1s. The banner still earns its place on a cold, slow or blocked
        // network, where those timeouts really do elapse.)
        if !model.ready && model.bootError == nil && !hidStarting {
            banner(
                "Starting padMule... searching and downloading will work in a moment.",
                systemImage: "hourglass", tint: .orange
            ) { hidStarting = true }
        }
        // Action feedback stays global - it must appear where the user is.
        // Server NEWS (MOTD, discovery) is Servers-only; see serverNotice.
        if let notice = model.notice {
            banner(notice, systemImage: "info.circle", tint: .bannerBlue) {
                model.notice = nil
            }
        }
        // The started-download feedback, BOUND to the row's live state rather
        // than captured as a string - a captured "Downloading X" kept asserting
        // the download was running after it was paused (on glass 2026-08-09;
        // the an-event-is-not-state shape). The model stores only WHICH row;
        // the words come from the row's current badge, so pause, cancel,
        // completion, engine stop, and queue demotion all take the claim down
        // without anyone remembering to clear it. Dismiss drops the pointer;
        // the next Get re-arms it.
        if let text = EngineModel.downloadBannerText(
            hash: model.downloadNoticeHash,
            downloads: model.downloads,
            engineStopped: TransferRowState.engineStopped(model.state))
        {
            banner(text, systemImage: "arrow.down.circle", tint: .bannerBlue) {
                model.downloadNoticeHash = nil
            }
        }
    }

    /// How a connected server is named ANYWHERE it is shown: "Name (ip:port)",
    /// falling back to the bare address when server.met carried no name.
    ///
    /// One function so the Servers tab and the Status screen cannot drift apart
    /// again - the Servers row printed a bare address while Status printed the
    /// name, which is the same fact in two voices.
    private func serverLabel(_ s: ServerInfoFfi) -> String {
        guard let name = s.name, !name.isEmpty else { return s.addr }
        return "\(name) (\(s.addr))"
    }

    /// A full-width status banner. Solid tint with white text - the treatment
    /// Anthony picked out on the server-message banner - rather than the washed
    /// 15%-opacity fill these used to have, which was legible only in the blue
    /// case. The COLOUR still carries meaning (blue informational, orange needs
    /// attention, red broken); only the weight changed.
    ///
    /// EVERY banner takes a dismiss action (Anthony, 2026-08-04): a banner the
    /// user cannot close is a permanent strip of lost screen, and on the Status
    /// and Transfers screens these sit directly over the content being read.
    private func banner(
        _ text: String, systemImage: String, tint: Color, dismiss: @escaping () -> Void
    ) -> some View {
        HStack(spacing: 8) {
            Label(text, systemImage: systemImage)
                .frame(maxWidth: .infinity, alignment: .leading)
            Button(action: dismiss) {
                Image(systemName: "xmark.circle.fill")
            }
            .buttonStyle(.plain)
            .accessibilityLabel("Dismiss")
        }
        .font(.footnote)
        .foregroundStyle(.white)
        .padding(.horizontal, 10)
        .padding(.vertical, 8)
        // FLAT, not `.gradient`. A gradient lightens the top of the tint, so the
        // colour named at the call site was never the colour rendered - which is
        // exactly why the banner blue had to be specified three times. A solid
        // fill is also what this function's doc above has always described.
        .background(tint)
    }
}

/// padMule's informational banner blue: **#000066**, specified exactly by
/// Anthony (2026-08-04) after two rounds of "that is not the blue I asked for".
///
/// Written as the hex components over 255 rather than as pre-divided decimals,
/// so the literal can be checked against the hex by eye and cannot drift from it
/// through a rounding edit.
///
/// This is the third attempt at the shade, and the reason the first two missed
/// is worth keeping: banners were drawn with `.gradient`, which lightens the top
/// of whatever tint it is given - so the colour named in the code was never the
/// colour on the glass. The gradient is gone (see `banner`), which is also what
/// that function's own doc always claimed it did ("solid tint with white text").
extension Color {
    static let bannerBlue = Color(red: 0x00 / 255.0, green: 0x00 / 255.0, blue: 0x66 / 255.0)

    /// The VPN badge blue. NOT `bannerBlue` (#000066): that navy is chosen to
    /// carry white text on a filled bar, and as a thin stroke plus 11pt letters
    /// on the toolbar's light background it reads as near-black. This is a
    /// legible mid-blue for the badge's opposite job - dark ink on a light
    /// ground. It is also the one padMule colour that must stay recognisable in
    /// BOTH appearances now that Dark Mode exists.
    static let vpnBlue = Color(red: 0x00 / 255.0, green: 0x66 / 255.0, blue: 0xCC / 255.0)

    /// The VPN badge red, for the OFF state. Picked to the same brief as
    /// `vpnBlue`: legible as a thin stroke and 11pt letters on BOTH the light
    /// and dark toolbar, rather than the system red, which goes muddy against
    /// dark chrome at this weight.
    static let vpnRed = Color(red: 0xCC / 255.0, green: 0x22 / 255.0, blue: 0x22 / 255.0)
}

/// The hex hash uniquely identifies a hit - enough for SwiftUI's item-based sheet.
extension SearchHit: Identifiable {
    public var id: String { hash }
}
