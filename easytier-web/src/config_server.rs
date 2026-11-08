//! Concrete endpoint protocols advertised to clients; `both` is server-only.
pub fn protocols(protocol: &str) -> &'static [&'static str] {
    match protocol {
        "both" => &["udp", "tcp"],
        "udp" => &["udp"],
        "tcp" => &["tcp"],
        "ws" => &["ws"],
        _ => &[],
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn advertised_protocols_are_concrete_and_preserve_legacy_default() {
        assert_eq!(super::protocols("both"), &["udp", "tcp"]);
        for protocol in ["udp", "tcp", "ws"] {
            assert_eq!(super::protocols(protocol), &[protocol]);
        }
        assert!(super::protocols("invalid").is_empty());
    }
}
