// The first real padMule screen. Deliberately plain - its job is to prove the
// seam end to end (engine identity, Kad, transfers) and to satisfy the three
// HARD lifecycle requirements from docs/wiki/lifecycle-and-reactivation.md:
//   1. an honest status notice (we do NOT transfer in the background),
//   2. a Reconnecting banner while resuming,
//   3. a Paused badge per transfer when the engine is paused.

import SwiftUI

struct ContentView: View {
    @EnvironmentObject var model: EngineModel
    @State private var query = ""
    @State private var detail: SearchHit?

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                if model.reconnecting {
                    banner("Reconnecting...", systemImage: "arrow.clockwise", tint: .orange)
                }
                if let err = model.bootError {
                    banner("Engine failed: \(err)", systemImage: "exclamationmark.triangle", tint: .red)
                }
                if let notice = model.notice {
                    banner(notice, systemImage: "info.circle", tint: .blue)
                }
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
                                }
                                .buttonStyle(.plain)
                            }
                        }
                        if model.searching {
                            Text("Searching... the server can take a few seconds.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
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
                        if model.searched, model.results.isEmpty, !model.searching {
                            Text("No results.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }

                    Section("Status") {
                        row("State", String(describing: model.state))
                        row("Status", model.status)
                        // The ID type decides whether peers can reach us at all,
                        // so it gets its own row instead of riding on the status
                        // line, where a later event would overwrite it.
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
                        // The port-mapping result: the direct answer to "why am I
                        // LowID?" when the router should have opened the port.
                        row("Port mapping", model.upnpStatus ?? "checking...")
                        if let id = model.identity {
                            row("User hash", String(id.userhash.prefix(16)) + "...")
                            row("Kad ID", String(id.kadId.prefix(16)) + "...")
                        }
                    }

                    Section("Sharing") {
                        Toggle("Share uploads", isOn: Binding(
                            get: { model.sharing },
                            set: { model.setSharing($0) }
                        ))
                        Text(model.sharing
                            ? "padMule serves files you've downloaded to other peers while it's open. Sharing earns you better standing in their queues, so your own downloads go faster."
                            : "Leech Mode: downloading only. padMule is not serving any files to peers.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }

                    Section("Transfers") {
                        if model.downloads.isEmpty {
                            Text("No transfers").foregroundStyle(.secondary)
                        } else {
                            ForEach(model.downloads, id: \.hash) { dl in
                                transferRow(dl)
                                    .swipeActions(edge: .trailing) {
                                        Button(role: .destructive) {
                                            model.cancel(dl.hash)
                                        } label: {
                                            Label("Remove", systemImage: "trash")
                                        }
                                    }
                            }
                        }
                    }

                    Section {
                        // The honest notice. iPadOS reclaims sockets from a
                        // backgrounded app; saying otherwise would be a lie.
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
            .navigationTitle("padMule")
            .sheet(item: $detail) { hit in
                SearchDetailView(hit: hit).environmentObject(model)
            }
        }
    }

    /// One search hit: a status dot, the name, a metadata line (type + media when
    /// present), and the size/sources/complete stats. Tapping the row opens the
    /// detail sheet; the trailing Get button starts a download directly.
    private func resultRow(_ hit: SearchHit) -> some View {
        HStack(alignment: .top, spacing: 8) {
            statusDot(hit.status)
                .padding(.top, 5)
            VStack(alignment: .leading, spacing: 2) {
                Text(hit.name).lineLimit(2)
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
                Button("Get") { model.download(hit) }
                    .buttonStyle(.borderless)
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
                Text(dl.name.isEmpty ? String(dl.hash.prefix(16)) : dl.name)
                    .lineLimit(1)
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

    private func row(_ k: String, _ v: String) -> some View {
        HStack {
            Text(k).foregroundStyle(.secondary)
            Spacer()
            Text(v).multilineTextAlignment(.trailing)
        }
        .font(.callout)
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
