//! pinned.txt: padMule's server-pin side store. NOT an eMule/aMule format - it is
//! padMule-specific, deliberately kept OUT of server.met so pinning a server
//! leaves server.met byte-identical to what was fetched (and unreadable pins
//! never corrupt the shared file). One canonical "ip:port" key per line, ASCII.

/// Parse pinned.txt into its pin keys, in file order. Blank lines and surrounding
/// whitespace are ignored; duplicates are preserved for the caller to dedupe.
pub fn read_pins(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect()
}

/// Serialize pin keys to pinned.txt: one key per line, each newline-terminated.
pub fn write_pins(keys: &[String]) -> String {
    let mut s = String::new();
    for k in keys {
        s.push_str(k);
        s.push('\n');
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_ignores_blanks() {
        let text = "127.0.0.1:4661\n  10.0.0.2:5000  \n\n";
        let pins = read_pins(text);
        assert_eq!(pins, vec!["127.0.0.1:4661", "10.0.0.2:5000"]);
        // write -> read is stable.
        assert_eq!(read_pins(&write_pins(&pins)), pins);
        // empty set -> empty file -> empty set.
        assert!(read_pins(&write_pins(&[])).is_empty());
    }
}
