// The first real padMule screen. Deliberately plain - its job is to prove the
// seam end to end (engine identity, Kad, transfers) and to satisfy the three
// HARD lifecycle requirements from docs/wiki/lifecycle-and-reactivation.md:
//   1. an honest status notice (we do NOT transfer in the background),
//   2. a Reconnecting banner while resuming,
//   3. a Paused badge per transfer when the engine is paused.

import SwiftUI

struct ContentView: View {
    @EnvironmentObject var model: EngineModel

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                if model.reconnecting {
                    banner("Reconnecting...", systemImage: "arrow.clockwise", tint: .orange)
                }
                if let err = model.bootError {
                    banner("Engine failed: \(err)", systemImage: "exclamationmark.triangle", tint: .red)
                }
                List {
                    Section("Status") {
                        row("State", String(describing: model.state))
                        row("Status", model.status)
                        row("Kad contacts", "\(model.kadContacts)")
                        if let id = model.identity {
                            row("User hash", String(id.userhash.prefix(16)) + "...")
                            row("Kad ID", String(id.kadId.prefix(16)) + "...")
                        }
                    }

                    Section("Transfers") {
                        if model.downloads.isEmpty {
                            Text("No transfers").foregroundStyle(.secondary)
                        } else {
                            ForEach(model.downloads, id: \.hash) { dl in
                                transferRow(dl)
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
                    }
                }
            }
            .navigationTitle("padMule")
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
