// padMule's main screen. eMule-style function icons live in the top toolbar and
// switch a single content area between four screens (Search, Transfers, Shared,
// Status), instead of one long scroll. The title is INLINE so it never collapses
// out of view the way a large title does.
//
// The three HARD lifecycle requirements from docs/wiki/lifecycle-and-reactivation.md
// survive the split: (1) an honest status notice (we do NOT transfer in the
// background) lives on the Transfers screen; (2) the Reconnecting banner shows
// above every screen; (3) each transfer row carries a Paused badge when paused.

import SwiftUI

/// The top-toolbar destinations. Each is one eD2k function, one icon.
enum Screen: String, CaseIterable, Identifiable {
    case search, transfers, servers, shared, stats, status
    var id: String { rawValue }

    var title: String {
        switch self {
        case .search: return "Search"
        case .transfers: return "Transfers"
        case .servers: return "Servers"
        case .shared: return "Shared"
        case .stats: return "Statistics"
        case .status: return "Status"
        }
    }

    /// SF Symbol for the toolbar (all available on the iOS 16 target). A `.fill`
    /// variant reads as "selected" where one exists; elsewhere the accent tint
    /// carries selection.
    func icon(selected: Bool) -> String {
        switch self {
        case .search: return "magnifyingglass"
        case .transfers: return selected ? "arrow.down.circle.fill" : "arrow.down.circle"
        case .servers: return "server.rack"
        case .shared: return selected ? "folder.fill" : "folder"
        case .stats: return selected ? "chart.xyaxis.line" : "chart.xyaxis.line"
        case .status: return "gauge"
        }
    }
}

struct ContentView: View {
    @EnvironmentObject var model: EngineModel
    @State private var screen: Screen = .search
    @State private var query = ""
    @State private var serverListUrl = EngineModel.defaultServerListUrl
    @State private var detail: SearchHit?
    @State private var showAddCategory = false
    @State private var newCategoryName = ""
    @State private var sourcesFor: DownloadInfo?
    @State private var ratingFor: SharedFileInfo?

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                // Global status banners - visible on every screen.
                if model.reconnecting {
                    banner("Reconnecting...", systemImage: "arrow.clockwise", tint: .orange)
                }
                if let err = model.bootError {
                    banner("Engine failed: \(err)", systemImage: "exclamationmark.triangle", tint: .red)
                }
                if let notice = model.notice {
                    banner(notice, systemImage: "info.circle", tint: .blue)
                }

                // The selected screen fills the rest.
                switch screen {
                case .search: searchScreen
                case .transfers: transfersScreen
                case .servers: serversScreen
                case .shared: sharedScreen
                case .stats: StatsView().environmentObject(model)
                case .status: statusScreen
                }
            }
            .navigationTitle("padMule")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                // .navigationBarTrailing (not .topBarTrailing, which is iOS 17+)
                // keeps the icon row valid on the iOS 16 deployment target.
                ToolbarItemGroup(placement: .navigationBarTrailing) {
                    ForEach(Screen.allCases) { s in
                        Button {
                            screen = s
                        } label: {
                            Image(systemName: s.icon(selected: screen == s))
                                .symbolRenderingMode(.hierarchical)
                                .foregroundStyle(screen == s ? Color.accentColor : .secondary)
                        }
                        .accessibilityLabel(s.title)
                    }
                }
            }
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
            .sheet(item: $ratingFor) { f in
                RatingEditorView(hash: f.hash, name: f.name, rating: f.rating, comment: f.comment) { rating, comment in
                    model.setFileRating(f.hash, rating: rating, comment: comment)
                }
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
                        .labelStyle(.iconOnly)
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

    // MARK: - Search screen

    private var searchScreen: some View {
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
                // Pre-search filters: the server applies these to what it returns,
                // so the capped result set fills with matches instead of junk.
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
                    HStack {
                        Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                        TextField("Filter these results", text: $model.nameFilter)
                            .textInputAutocapitalization(.never)
                            .disableAutocorrection(true)
                    }
                    .font(.caption)
                    Toggle("Trusted only", isOn: $model.trustedOnly).font(.caption)
                    Toggle("Hide ones I have", isOn: $model.hideHave).font(.caption)
                }
                ForEach(model.presentedResults, id: \.hash) { hit in
                    resultRow(hit)
                        .contentShape(Rectangle())
                        .onTapGesture { detail = hit }
                }
                if model.searched, !model.searching {
                    if model.results.isEmpty {
                        Text("No results.")
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
    }

    // MARK: - Transfers screen

    private var transfersScreen: some View {
        List {
            // Always shown: with no categories yet it is just the "+" so the
            // first one can be created (the add button used to be hidden here).
            categoryChips
            Section("Transfers") {
                let shown = model.filteredDownloads
                if shown.isEmpty {
                    Text(model.categoryFilter == nil ? "No transfers" : "None in this category")
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(shown, id: \.hash) { dl in
                        transferRow(dl)
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
                    "padMule only transfers while it is open and on screen. "
                        + "iPadOS suspends background apps, so transfers pause when you "
                        + "leave and resume when you come back.",
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

    // MARK: - Servers screen

    private var serversScreen: some View {
        List {
            Section {
                if let s = model.server {
                    HStack {
                        Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Connected to \(s.addr)").font(.callout)
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
                    Label(
                        model.loadingServers ? "Probing servers..." : "Refresh server list",
                        systemImage: "arrow.clockwise")
                }
                .disabled(model.loadingServers)

                // Auto-update the list from a public URL (#18): fetch + MERGE, so
                // existing servers are kept and only new ones added.
                HStack {
                    TextField("Server list URL", text: $serverListUrl)
                        .textInputAutocapitalization(.never)
                        .disableAutocorrection(true)
                        .font(.caption)
                    Button("Update") { model.updateServerList(serverListUrl) }
                        .buttonStyle(.borderless)
                        .disabled(model.loadingServers)
                }
                // Prune: drop every dead, unpinned server (pinned stars survive).
                Button(role: .destructive) {
                    model.pruneDeadServers()
                } label: {
                    Label("Prune dead servers", systemImage: "trash")
                }
                .disabled(model.loadingServers)
            }

            Section("Servers (\(model.servers.count))") {
                HStack {
                    Text("Server").frame(maxWidth: .infinity, alignment: .leading)
                    Text("Users").frame(width: 70, alignment: .trailing)
                    Text("Files").frame(width: 84, alignment: .trailing)
                }
                .font(.caption2).foregroundStyle(.secondary)

                if model.servers.isEmpty {
                    Text(model.loadingServers ? "Probing..." : "No server list on disk.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                // Index-keyed: server.met is not deduped, so addresses are not a
                // unique identity (duplicate rows would collide on \.addr).
                ForEach(Array(model.servers.enumerated()), id: \.offset) { _, srv in
                    serverRow(srv)
                }
            }
        }
        .onAppear { if model.servers.isEmpty { model.loadServers() } }
    }

    /// One server row: name/address, live user/file counts, and connection state.
    /// A live (probe-answering) server is black + selectable to connect; a dead
    /// one is greyed out and disabled, matching eMule's server list.
    private func serverRow(_ srv: ServerEntryFfi) -> some View {
        HStack {
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
                if srv.alive && !srv.connected { model.connectServer(srv.addr) }
            } label: {
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(srv.name.isEmpty ? srv.addr : srv.name)
                            .font(.callout)
                            .foregroundStyle(srv.alive ? .primary : .secondary)
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
                        Text("offline")
                            .font(.caption).foregroundStyle(.secondary)
                            .frame(width: 154, alignment: .trailing)
                    }
                    if srv.connected {
                        Image(systemName: "checkmark.circle.fill")
                            .foregroundStyle(.green)
                    }
                }
            }
            .buttonStyle(.borderless)
            .disabled(!srv.alive || srv.connected)
            .foregroundStyle(.primary)
        }
    }

    // MARK: - Shared screen

    private var sharedScreen: some View {
        List {
            Section("Sharing") {
                Toggle("Share uploads", isOn: Binding(
                    get: { model.sharing },
                    set: { model.setSharing($0) }
                ))
                Text(model.sharing
                    ? "padMule serves these files to other peers while it's open. Sharing earns you better standing in their queues, so your own downloads go faster."
                    : "Leech Mode: downloading only. padMule is not serving any files to peers.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
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
            Section("Status") {
                row("State", String(describing: model.state))
                row("Status", model.status)
                // The ID type decides whether peers can reach us at all, so it
                // gets its own row instead of riding on the status line, where a
                // later event would overwrite it.
                if let srv = model.server {
                    row("Server", srv.addr)
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
                    row("User hash", String(id.userhash.prefix(16)) + "...")
                    row("Kad ID", String(id.kadId.prefix(16)) + "...")
                }
            }
        }
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
        if hit.status == .have { return .green }
        if hit.sources == 0 { return .red }
        return .primary
    }

    private func resultRow(_ hit: SearchHit) -> some View {
        HStack(alignment: .top, spacing: 8) {
            statusDot(hit.status)
                .padding(.top, 5)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(hit.name).lineLimit(2)
                        .foregroundStyle(resultColor(hit))
                    ratingBadge(hit.rating)
                }
                if let meta = metaLine(hit) {
                    Text(meta).font(.caption).foregroundStyle(.secondary)
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
                switch hit.status {
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
                if dl.complete {
                    Text("Done").font(.caption).foregroundStyle(.green)
                } else if model.state == .paused {
                    // Per-transfer Paused badge (requirement 3).
                    Text("Paused")
                        .font(.caption2)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(Color.secondary.opacity(0.2))
                        .clipShape(Capsule())
                }
            }
            ProgressView(value: fraction(dl))
            Text("\(bytes(dl.have)) / \(bytes(dl.size))")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    private func fraction(_ dl: DownloadInfo) -> Double {
        dl.size == 0 ? 0 : Double(dl.have) / Double(dl.size)
    }

    private func bytes(_ n: UInt64) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(n), countStyle: .file)
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

    private func row(_ k: String, _ v: String) -> some View {
        HStack {
            Text(k).foregroundStyle(.secondary)
            Spacer()
            Text(v).multilineTextAlignment(.trailing)
        }
        .font(.callout)
    }

    /// A size-preset menu (megabytes; 0 = "Any") for the pre-search size bounds.
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

    private func banner(_ text: String, systemImage: String, tint: Color) -> some View {
        Label(text, systemImage: systemImage)
            .font(.footnote)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(8)
            .background(tint.opacity(0.15))
    }
}

/// The hex hash uniquely identifies a hit - enough for SwiftUI's item-based sheet.
extension SearchHit: Identifiable {
    public var id: String { hash }
}
