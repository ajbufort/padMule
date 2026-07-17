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
                        ForEach(model.results, id: \.hash) { hit in
                            resultRow(hit)
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
        }
    }

    /// One search hit. Tapping Get starts it; the row reports what the catalog
    /// knows rather than hiding a suspect file - the user decides.
    private func resultRow(_ hit: SearchHit) -> some View {
        HStack(alignment: .top) {
            VStack(alignment: .leading, spacing: 2) {
                Text(hit.name).lineLimit(2)
                HStack(spacing: 6) {
                    Text(bytes(hit.size))
                    Text("-")
                    Text("\(hit.sources) source\(hit.sources == 1 ? "" : "s")")
                }
                .font(.caption)
                .foregroundStyle(.secondary)
                if !hit.trusted {
                    Label(hit.warning, systemImage: "exclamationmark.triangle")
                        .font(.caption2)
                        .foregroundStyle(.orange)
                }
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
