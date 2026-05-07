//! SSRF (Server-Side Request Forgery) protection.
//!
//! Validates target URLs to block requests to private, loopback, link-local,
//! cloud metadata, and other internal addresses, and provides a fetch
//! wrapper that disables auto-redirects and re-validates SSRF on every hop.

use worker::{Fetch, Headers, Method, Request, RequestInit, RequestRedirect, Response, Url};

/// Maximum number of HTTP redirects we will follow per outbound request.
pub const MAX_REDIRECTS: usize = 3;

/// Maximum response body size (bytes) we will read into memory. Bodies larger
/// than this are truncated; callers should treat truncation as a fetch failure
/// because OG/oEmbed parsers depend on a complete document.
pub const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;

/// Errors emitted by the SSRF-aware fetch helper.
#[derive(Debug)]
pub enum SsrfFetchError {
    /// Target (or a redirect target) failed the SSRF policy.
    Blocked(String),
    /// Followed more than [`MAX_REDIRECTS`] redirects.
    TooManyRedirects,
    /// Underlying worker fetch error.
    Worker(worker::Error),
    /// Response body exceeded [`MAX_BODY_BYTES`].
    BodyTooLarge,
    /// Non-2xx final status.
    HttpStatus(u16),
}

impl From<worker::Error> for SsrfFetchError {
    fn from(e: worker::Error) -> Self {
        SsrfFetchError::Worker(e)
    }
}

impl std::fmt::Display for SsrfFetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SsrfFetchError::Blocked(u) => write!(f, "blocked by SSRF policy: {u}"),
            SsrfFetchError::TooManyRedirects => write!(f, "too many redirects"),
            SsrfFetchError::Worker(e) => write!(f, "fetch error: {e:?}"),
            SsrfFetchError::BodyTooLarge => {
                write!(f, "response body exceeds {MAX_BODY_BYTES} bytes")
            }
            SsrfFetchError::HttpStatus(s) => write!(f, "HTTP {s}"),
        }
    }
}

/// Build a request with manual redirect handling so we can re-run the SSRF
/// policy on each `Location` target rather than letting the runtime follow
/// 3xx silently to a private address.
fn build_request(url: &str, headers: &Headers, method: Method) -> worker::Result<Request> {
    let mut init = RequestInit::new();
    init.with_method(method);
    init.with_headers(headers.clone());
    init.with_redirect(RequestRedirect::Manual);
    Request::new_with_init(url, &init)
}

/// SSRF-aware fetch that:
///   1. Re-validates the SSRF policy on every hop, including redirects.
///   2. Caps total redirects at [`MAX_REDIRECTS`].
///   3. Returns the final non-redirect response without following past the
///      cap.
///
/// Note: the caller is still responsible for body-size enforcement when
/// reading text/JSON from the response — see [`read_text_capped`].
pub async fn ssrf_fetch_with_redirects(
    initial_url: &str,
    headers: &Headers,
) -> Result<Response, SsrfFetchError> {
    let mut current_url = initial_url.to_string();
    for _ in 0..=MAX_REDIRECTS {
        if is_private_url(&current_url) {
            return Err(SsrfFetchError::Blocked(current_url));
        }
        let req = build_request(&current_url, headers, Method::Get)?;
        let response = Fetch::Request(req).send().await?;
        let status = response.status_code();
        if !(300..400).contains(&status) {
            return Ok(response);
        }
        // 3xx: extract Location, re-run SSRF, loop.
        let location = response
            .headers()
            .get("Location")
            .ok()
            .flatten()
            .ok_or_else(|| SsrfFetchError::Blocked("redirect missing Location".into()))?;
        // Resolve relative redirects against the current URL.
        let next = match Url::parse(&location) {
            Ok(u) => u.to_string(),
            Err(_) => match Url::parse(&current_url).and_then(|base| base.join(&location)) {
                Ok(u) => u.to_string(),
                Err(_) => return Err(SsrfFetchError::Blocked(location)),
            },
        };
        current_url = next;
    }
    Err(SsrfFetchError::TooManyRedirects)
}

/// Read the response body as text, rejecting bodies that exceed
/// [`MAX_BODY_BYTES`]. workers-rs `Response::text()` does not expose a
/// streaming reader, so we read the bytes and check the size before UTF-8
/// decoding.
pub async fn read_text_capped(mut response: Response) -> Result<String, SsrfFetchError> {
    let bytes = response.bytes().await?;
    if bytes.len() > MAX_BODY_BYTES {
        return Err(SsrfFetchError::BodyTooLarge);
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

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

    // ── Redirect-target SSRF tests ─────────────────────────────────────
    //
    // We can't drive a real fetch in unit tests, so the redirect policy is
    // exercised at the function `is_private_url` level. The redirect loop
    // in `ssrf_fetch_with_redirects` calls this on every hop.

    #[test]
    fn redirect_target_to_metadata_blocked() {
        // Simulates: external 3xx -> http://169.254.169.254/
        let next = "http://169.254.169.254/latest/";
        assert!(
            is_private_url(next),
            "redirect targets to AWS metadata must be blocked"
        );
    }

    #[test]
    fn redirect_target_to_loopback_blocked() {
        let next = "http://127.0.0.1:8080/admin";
        assert!(is_private_url(next));
    }

    #[test]
    fn redirect_target_to_private_ipv4_blocked() {
        let next = "http://192.168.1.1/secret";
        assert!(is_private_url(next));
    }

    #[test]
    fn redirect_target_to_link_local_ipv6_blocked() {
        let next = "http://[fe80::1]/";
        assert!(is_private_url(next));
    }

    #[test]
    fn ssrf_constants_safe() {
        assert!(MAX_REDIRECTS <= 5, "redirect cap must remain small");
        assert!(
            MAX_BODY_BYTES <= 5 * 1024 * 1024,
            "body cap must remain small"
        );
    }
}
