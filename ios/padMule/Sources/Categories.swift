// Download categories - a CLIENT-SIDE organization layer over the transfer list.
// Deliberately not written to part.met or exchanged on the wire (padMule is not
// syncing part files with desktop aMule): a category is a user-named, colored
// bucket plus a hash -> category assignment, both persisted in UserDefaults.

import SwiftUI

/// One category: a stable id, a name, and an index into `Category.palette`.
struct Category: Codable, Identifiable, Hashable {
    var id: String
    var name: String
    var colorIndex: Int

    /// The fixed color palette. Storing an index (not a Color) keeps Category
    /// Codable; the UI maps it back with `color`.
    static let palette: [Color] = [
        .blue, .green, .orange, .purple, .pink, .red, .teal, .indigo,
    ]

    var color: Color {
        Category.palette[colorIndex % Category.palette.count]
    }
}

/// Loads/saves the category list and the hash -> category assignment. Held by
/// EngineModel; all access is on the main actor.
enum CategoryStore {
    private static let listKey = "padMule.categories"
    private static let assignKey = "padMule.categoryAssignment"

    static func loadCategories() -> [Category] {
        guard let data = UserDefaults.standard.data(forKey: listKey),
              let list = try? JSONDecoder().decode([Category].self, from: data)
        else { return [] }
        return list
    }

    static func saveCategories(_ list: [Category]) {
        if let data = try? JSONEncoder().encode(list) {
            UserDefaults.standard.set(data, forKey: listKey)
        }
    }

    static func loadAssignment() -> [String: String] {
        UserDefaults.standard.dictionary(forKey: assignKey) as? [String: String] ?? [:]
    }

    static func saveAssignment(_ map: [String: String]) {
        UserDefaults.standard.set(map, forKey: assignKey)
    }
}
