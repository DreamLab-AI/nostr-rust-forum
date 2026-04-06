//! SSRF (Server-Side Request Forgery) protection.
//!
//! Validates target URLs to block requests to private, loopback, link-local,
//! cloud metadata, and other internal addresses.

use worker::Url;

/// Returns `true` if the URL resolves to a private, loopback, link-local,
/// metadata, or otherwise internal address that should not be fetched.
pub(crate) fn is_private_url(raw_url: &str) -> bool {
    let parsed = match Url::parse(raw_url) {
        Ok(u) => u,
        Err(_) => return true, // unparseable -> block
    };

    // Only allow HTTP(S)
    match parsed.scheme() {
        "http" | "https" => {}
        _ => return true,
    }

    let hostname: String = match parsed.host_str() {
        Some(h) => h.to_lowercase(),
        None => return true,
    };

    // Block non-standard IP obfuscation (integer/hex) that may bypass
    // the dotted-decimal regex on URL implementations that don't normalize them.
    if !hostname.is_empty() && hostname.chars().all(|c: char| c.is_ascii_digit()) {
        return true; // pure integer (e.g., 2130706433 = 127.0.0.1)
    }
    if let Some(rest) = hostname.strip_prefix("0x") {
        if !rest.is_empty() && rest.chars().all(|c: char| c.is_ascii_hexdigit()) {
            return true; // pure hex (e.g., 0x7f000001)
        }
    }

    // Loopback / localhost
    if hostname == "localhost" || hostname.ends_with(".localhost") {
        return true;
    }

    // Cloud metadata endpoints
    if hostname == "169.254.169.254"
        || hostname == "metadata.google.internal"
        || hostname == "metadata.goog"
    {
        return true;
    }

    // Plain IPv4 -- block private, loopback, and link-local ranges
    if let Some(octets) = parse_ipv4(&hostname) {
        return is_private_ipv4(octets);
    }

    // IPv6 patterns (may have brackets from URL parsing)
    let host: &str = hostname
        .strip_prefix('[')
        .and_then(|s: &str| s.strip_suffix(']'))
        .unwrap_or(&hostname);

    // IPv6 loopback
    if host == "::1" {
        return true;
    }

    // ULA fc00::/7
    if host.starts_with("fc") || host.starts_with("fd") {
        return true;
    }

    // Link-local fe80::/10
    if host.starts_with("fe80") {
        return true;
    }

    // IPv4-mapped IPv6 (::ffff:a.b.c.d) -- check embedded IPv4
    if let Some(rest) = host.strip_prefix("::ffff:") {
        if let Some(octets) = parse_ipv4(rest) {
            return is_private_ipv4(octets);
        }
        // Hex-form mapped addresses that didn't match dotted-decimal above
        // Block since we can't reliably parse hex octets without a full IPv6 parser
        return true;
    }

    false
}

fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut octets = [0u8; 4];
    for (i, part) in parts.iter().enumerate() {
        octets[i] = part.parse().ok()?;
    }
    Some(octets)
}

fn is_private_ipv4(octets: [u8; 4]) -> bool {
    let [a, b, _, _] = octets;
    if a == 10 {
        return true;
    } // 10.0.0.0/8
    if a == 127 {
        return true;
    } // 127.0.0.0/8 loopback
    if a == 172 && (16..=31).contains(&b) {
        return true;
    } // 172.16.0.0/12
    if a == 192 && b == 168 {
        return true;
    } // 192.168.0.0/16
    if a == 169 && b == 254 {
        return true;
    } // 169.254.0.0/16 link-local
    if a == 0 {
        return true;
    } // 0.0.0.0/8
    if a >= 240 {
        return true;
    } // 240.0.0.0/4 reserved
    false
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // SSRF protection tests
    #[test]
    fn blocks_non_http_protocols() {
        assert!(is_private_url("ftp://example.com/file"));
        assert!(is_private_url("file:///etc/passwd"));
        assert!(is_private_url("gopher://localhost"));
    }

    #[test]
    fn blocks_integer_ip() {
        assert!(is_private_url("http://2130706433/")); // 127.0.0.1
    }

    #[test]
    fn blocks_hex_ip() {
        assert!(is_private_url("http://0x7f000001/"));
    }

    #[test]
    fn blocks_localhost() {
        assert!(is_private_url("http://localhost/"));
        assert!(is_private_url("http://sub.localhost/"));
    }

    #[test]
    fn blocks_metadata_endpoints() {
        assert!(is_private_url("http://169.254.169.254/latest/meta-data/"));
        assert!(is_private_url("http://metadata.google.internal/"));
        assert!(is_private_url("http://metadata.goog/"));
    }

    #[test]
    fn blocks_private_ipv4() {
        assert!(is_private_url("http://10.0.0.1/"));
        assert!(is_private_url("http://127.0.0.1/"));
        assert!(is_private_url("http://172.16.0.1/"));
        assert!(is_private_url("http://172.31.255.255/"));
        assert!(is_private_url("http://192.168.1.1/"));
        assert!(is_private_url("http://169.254.0.1/"));
        assert!(is_private_url("http://0.0.0.0/"));
        assert!(is_private_url("http://240.0.0.1/"));
    }

    #[test]
    fn allows_public_ipv4() {
        assert!(!is_private_url("http://8.8.8.8/"));
        assert!(!is_private_url("http://93.184.216.34/"));
    }

    #[test]
    fn blocks_ipv6_loopback() {
        assert!(is_private_url("http://[::1]/"));
    }

    #[test]
    fn blocks_ipv6_ula() {
        assert!(is_private_url("http://[fc00::1]/"));
        assert!(is_private_url("http://[fd12::1]/"));
    }

    #[test]
    fn blocks_ipv6_link_local() {
        assert!(is_private_url("http://[fe80::1]/"));
    }

    #[test]
    fn blocks_ipv4_mapped_ipv6_private() {
        assert!(is_private_url("http://[::ffff:127.0.0.1]/"));
        assert!(is_private_url("http://[::ffff:10.0.0.1]/"));
        assert!(is_private_url("http://[::ffff:192.168.1.1]/"));
    }

    #[test]
    fn blocks_ipv4_mapped_ipv6_hex_form() {
        assert!(is_private_url("http://[::ffff:7f00:1]/"));
    }

    #[test]
    fn allows_public_urls() {
        assert!(!is_private_url("https://example.com/"));
        assert!(!is_private_url("https://google.com/search?q=test"));
    }

    #[test]
    fn blocks_unparseable() {
        assert!(is_private_url("not a url at all"));
    }

    // IPv4 parser tests
    #[test]
    fn parses_valid_ipv4() {
        assert_eq!(parse_ipv4("192.168.1.1"), Some([192, 168, 1, 1]));
        assert_eq!(parse_ipv4("0.0.0.0"), Some([0, 0, 0, 0]));
        assert_eq!(parse_ipv4("255.255.255.255"), Some([255, 255, 255, 255]));
    }

    #[test]
    fn rejects_invalid_ipv4() {
        assert_eq!(parse_ipv4("not.an.ip"), None);
        assert_eq!(parse_ipv4("256.1.1.1"), None);
        assert_eq!(parse_ipv4("1.2.3"), None);
        assert_eq!(parse_ipv4("1.2.3.4.5"), None);
    }
}
