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
        let cmp: ComparisonResult
        switch sort {
        case .sources: cmp = threeWay(a.sources, b.sources)
        case .completeSources: cmp = threeWay(a.completeSources, b.completeSources)
        case .size: cmp = threeWay(a.size, b.size)
        case .name: cmp = a.name.localizedCaseInsensitiveCompare(b.name)
        case .type: cmp = threeWay(a.fileType, b.fileType)
        case .length: cmp = threeWay(a.lengthSecs, b.lengthSecs)
        case .bitrate: cmp = threeWay(a.bitrate, b.bitrate)
        }
        // A STRICT weak ordering in both directions: descending compares the
        // other way (`orderedDescending`), NOT `!(a < b)` - which returns true for
        // equal elements and breaks the ordering contract `sort(by:)` requires.
        return ascending ? cmp == .orderedAscending : cmp == .orderedDescending
    }
    return xs
}

/// Three-way comparison for any Comparable, so the sort has a proper strict weak
/// ordering (equal elements are `.orderedSame`, never "increasing") in both
/// directions.
private func threeWay<T: Comparable>(_ a: T, _ b: T) -> ComparisonResult {
    if a < b { return .orderedAscending }
    if b < a { return .orderedDescending }
    return .orderedSame
}
