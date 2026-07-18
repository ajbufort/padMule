import Foundation

/// The factors a user can sort search results by. Raw values are the menu labels.
enum SortKey: String, CaseIterable, Identifiable {
    case sources = "Sources"
    case completeSources = "Complete"
    case size = "Size"
    case name = "Name"
    case type = "Type"
    case length = "Length"
    case bitrate = "Bitrate"
    var id: String { rawValue }
}

/// A pure, order-preserving filter over the fetched hits, then a stable sort.
/// The UI holds the inputs; this has no SwiftUI or engine dependency, so its
/// behavior is obvious from reading it and cheap to run on every input change
/// (a search yields at most a few hundred hits).
func present(
    _ hits: [SearchHit],
    sort: SortKey,
    ascending: Bool,
    nameFilter: String,
    typeFilter: String?,  // nil = all types
    trustedOnly: Bool,
    hideHave: Bool
) -> [SearchHit] {
    let needle = nameFilter.trimmingCharacters(in: .whitespaces).lowercased()
    var xs = hits.filter { h in
        (needle.isEmpty || h.name.lowercased().contains(needle))
            && (typeFilter == nil || h.fileType == typeFilter)
            && (!trustedOnly || h.trusted)
            && (!hideHave || h.status != .have)
    }
    xs.sort { a, b in
        let asc: Bool
        switch sort {
        case .sources: asc = a.sources < b.sources
        case .completeSources: asc = a.completeSources < b.completeSources
        case .size: asc = a.size < b.size
        case .name: asc = a.name.localizedCaseInsensitiveCompare(b.name) == .orderedAscending
        case .type: asc = a.fileType < b.fileType
        case .length: asc = a.lengthSecs < b.lengthSecs
        case .bitrate: asc = a.bitrate < b.bitrate
        }
        return ascending ? asc : !asc
    }
    return xs
}
