// Editor for the local user's OWN rating + comment on a file they share. What
// you set here is persisted to known.met and served to downloaders via
// OP_FILEDESC (the same packet eMule/aMule send). The rating scale matches
// eMule: 0 None, 1 Fake, 2 Poor, 3 Fair, 4 Good, 5 Excellent.

import SwiftUI

struct RatingEditorView: View {
    let hash: String
    let name: String
    let onSave: (UInt8, String) -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var rating: Int
    @State private var comment: String

    /// Index i is the label for rating i (0-5).
    static let labels = ["None", "Fake", "Poor", "Fair", "Good", "Excellent"]
    /// eMule caps the comment at 50 characters (MAXFILECOMMENTLEN); the engine
    /// truncates too, but we stop the user here so what they see is what ships.
    static let maxComment = 50

    init(hash: String, name: String, rating: UInt8, comment: String,
         onSave: @escaping (UInt8, String) -> Void) {
        self.hash = hash
        self.name = name
        self.onSave = onSave
        _rating = State(initialValue: Int(rating))
        _comment = State(initialValue: comment)
    }

    var body: some View {
        NavigationStack {
            Form {
                Section("File") {
                    Text(name.isEmpty ? String(hash.prefix(16)) : name)
                        .lineLimit(2)
                }
                Section("Your rating") {
                    Picker("Rating", selection: $rating) {
                        ForEach(0..<Self.labels.count, id: \.self) { i in
                            Text(Self.labels[i]).tag(i)
                        }
                    }
                    .pickerStyle(.menu)
                }
                Section {
                    TextField("Comment (optional)", text: $comment, axis: .vertical)
                        .lineLimit(1...3)
                        .onChange(of: comment) { newValue in
                            if newValue.count > Self.maxComment {
                                comment = String(newValue.prefix(Self.maxComment))
                            }
                        }
                } header: {
                    Text("Your comment")
                } footer: {
                    Text("Downloaders see this rating and comment. Up to \(Self.maxComment) characters; both are optional.")
                }
            }
            .navigationTitle("Rate File")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        onSave(UInt8(rating), comment.trimmingCharacters(in: .whitespacesAndNewlines))
                        dismiss()
                    }
                }
            }
        }
    }
}

/// The hash identifies a shared file uniquely - enough for an item-based sheet.
extension SharedFileInfo: Identifiable {
    public var id: String { hash }
}
