use bytesize::ByteSize;

/// Parse human-readable bandwidth rate limit strings (e.g. "10MB", "1.5GiB", "100KB", "10MBps", "10MB/s").
/// An empty string, "none", or "unlimited" means unlimited (`None`).
pub fn parse_bandwidth_limit(input: &str) -> Result<Option<u64>, String> {
    let mut trimmed = input.trim();
    if trimmed.is_empty()
        || trimmed.eq_ignore_ascii_case("none")
        || trimmed.eq_ignore_ascii_case("unlimited")
    {
        return Ok(None);
    }

    if let Ok(size) = trimmed.parse::<ByteSize>() {
        if size.as_u64() == u64::MAX {
            return Ok(None);
        }
        return Ok(Some(size.as_u64()));
    }

    // Support e.g. "10MB/s" or "10MBps"
    if trimmed.ends_with("/s")
        || trimmed.ends_with("/S")
        || ((trimmed.ends_with("ps")
            || trimmed.ends_with("PS")
            || trimmed.ends_with("Ps")
            || trimmed.ends_with("pS"))
            && !trimmed.eq_ignore_ascii_case("bps"))
    {
        trimmed = &trimmed[..trimmed.len() - 2];
    }

    if let Ok(size) = trimmed.parse::<ByteSize>() {
        if size.as_u64() == u64::MAX {
            return Ok(None);
        }
        return Ok(Some(size.as_u64()));
    }

    if let Ok(bytes) = trimmed.parse::<u64>() {
        if bytes == u64::MAX {
            return Ok(None);
        }
        return Ok(Some(bytes));
    }

    Err(format!("invalid bandwidth rate limit: {input}"))
}

/// Format a byte count into a clean human-readable bandwidth rate limit string without loss of precision.
pub fn format_bandwidth_limit(bytes: u64) -> String {
    if bytes == 0 {
        return "0B".to_string();
    }
    const GIB: u64 = 1024 * 1024 * 1024;
    const GB: u64 = 1000 * 1000 * 1000;
    const MIB: u64 = 1024 * 1024;
    const MB: u64 = 1000 * 1000;
    const KIB: u64 = 1024;
    const KB: u64 = 1000;

    if bytes.is_multiple_of(GIB) {
        format!("{}GiB", bytes / GIB)
    } else if bytes.is_multiple_of(GB) {
        format!("{}GB", bytes / GB)
    } else if bytes.is_multiple_of(MIB) {
        format!("{}MiB", bytes / MIB)
    } else if bytes.is_multiple_of(MB) {
        format!("{}MB", bytes / MB)
    } else if bytes.is_multiple_of(KIB) {
        format!("{}KiB", bytes / KIB)
    } else if bytes.is_multiple_of(KB) {
        format!("{}KB", bytes / KB)
    } else {
        format!("{}B", bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_bandwidth_limit() {
        assert_eq!(parse_bandwidth_limit("").unwrap(), None);
        assert_eq!(parse_bandwidth_limit("none").unwrap(), None);
        assert_eq!(parse_bandwidth_limit("Unlimited").unwrap(), None);
        assert_eq!(parse_bandwidth_limit("18446744073709551615").unwrap(), None);

        assert_eq!(parse_bandwidth_limit("0").unwrap(), Some(0));
        assert_eq!(parse_bandwidth_limit("0B").unwrap(), Some(0));
        assert_eq!(parse_bandwidth_limit("1024").unwrap(), Some(1024));
        assert_eq!(parse_bandwidth_limit("1KB").unwrap(), Some(1000));
        assert_eq!(parse_bandwidth_limit("1KiB").unwrap(), Some(1024));
        assert_eq!(parse_bandwidth_limit("10MB").unwrap(), Some(10_000_000));
        assert_eq!(parse_bandwidth_limit("10MiB").unwrap(), Some(10_485_760));
        assert_eq!(parse_bandwidth_limit("10MB/s").unwrap(), Some(10_000_000));
        assert_eq!(parse_bandwidth_limit("10MBps").unwrap(), Some(10_000_000));
        assert_eq!(parse_bandwidth_limit("1.5GB").unwrap(), Some(1_500_000_000));

        assert!(parse_bandwidth_limit("invalid_limit").is_err());
    }

    #[test]
    fn test_format_bandwidth_limit_roundtrip() {
        let test_cases = [0, 1024, 1000, 10_000_000, 10_485_760, 1_500_000_000, 12345];
        for bytes in test_cases {
            let formatted = format_bandwidth_limit(bytes);
            let parsed = parse_bandwidth_limit(&formatted).unwrap().unwrap();
            assert_eq!(
                parsed, bytes,
                "roundtrip failed for {bytes} (formatted as {formatted})"
            );
        }
    }
}
