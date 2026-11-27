//! SSRF (Server-Side Request Forgery) protection.
//!
//! Validates target URLs to block requests to private, loopback, link-local,
//! cloud metadata, and other internal addresses, and provides a fetch
//! wrapper that disables auto-redirects and re-validates SSRF on every hop.
//!
//! ## Cloudflare Workers runtime limitation (DNS-rebinding)
//!
//! The string/hostname denylist below validates only the *hostname text* of a
//! URL. On a native client we would resolve the hostname to an IP and pin that
//! IP for the actual connection (resolve-then-pin), closing the
//! time-of-check/time-of-use gap. The Cloudflare Workers runtime exposes **no
//! raw socket and no `getaddrinfo`**, so we cannot pin the resolved IP: the
//! runtime resolves the hostname again at `fetch` time. An attacker domain
//! (`rebind.attacker.com`) that passes the string denylist but resolves to
//! `127.0.0.1` / `169.254.169.254` / an RFC1918 address will still connect
//! internally. The denylist therefore reduces, but does not eliminate, SSRF.
//!
//! **The real mitigation in this runtime is the egress allowlist**
//! ([`AllowList`], env var `PREVIEW_ALLOWED_HOSTS`). When set, only fetches to
//! hosts matching the allowlist are permitted, so a rebinding attacker domain
//! is rejected up front regardless of what it resolves to.
//!
//! ## Fail closed ([`EgressPolicy`])
//!
//! When `PREVIEW_ALLOWED_HOSTS` is unset or blank the worker **fails closed**:
//! every outbound fetch is refused and `/preview` and `/ascii` answer 503. The
//! hardened denylist on its own (rebind-vulnerable by construction) is reachable
//! only through the explicit development opt-out `PREVIEW_ALLOW_ANY_HOST =
//! "true"`, which must never be set on an internet-facing deployment.

use futures_util::TryStreamExt;
use worker::{
    Fetch, Headers, Method, Request, RequestInit, RequestRedirect, Response, ResponseBody, Url,
};

/// Maximum number of HTTP redirects we will follow per outbound request.
pub const MAX_REDIRECTS: usize = 3;

/// Maximum response body size (bytes) we will read into memory. Bodies larger
/// than this are truncated; callers should treat truncation as a fetch failure
/// because OG/oEmbed parsers depend on a complete document.
pub const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;

/// Maximum image body size (bytes) we will read into memory for ASCII
/// rendering. Larger than [`MAX_BODY_BYTES`] because image payloads are bigger
/// than HTML documents, but still capped to keep the worker within its memory
/// and CPU budget (the decoder additionally guards decoded pixel area).
pub const MAX_IMAGE_BYTES: usize = 10 * 1024 * 1024;

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
        }
    }
}

/// Egress allowlist of permitted preview hosts.
///
/// Populated from the `PREVIEW_ALLOWED_HOSTS` env var (comma/whitespace
/// separated). An entry matches a host exactly, or — when the entry begins
/// with a leading dot (`.example.com`) — matches that domain and any subdomain
/// (`a.example.com`, `b.a.example.com`). Bare `example.com` matches the apex
/// and its subdomains too (`www.example.com`).
///
/// When the allowlist is **non-empty** it is authoritative: only matching hosts
/// are fetchable, which is the robust mitigation for DNS rebinding in the CF
/// Workers runtime (see module docs). An empty allowlist never opens the
/// worker; see [`EgressPolicy::from_vars`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AllowList {
    hosts: Vec<String>,
}

impl AllowList {
    /// Parse an allowlist from a raw `PREVIEW_ALLOWED_HOSTS` string.
    /// Splits on commas and ASCII whitespace; lowercases and trims each entry.
    pub fn parse(raw: &str) -> Self {
        let hosts = raw
            .split([',', ' ', '\t', '\n', '\r'])
            .map(|s| s.trim().trim_start_matches('.').to_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        AllowList { hosts }
    }

    /// `true` when no entries were configured.
    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty()
    }

    /// `true` if `host` is permitted by this allowlist. A configured entry
    /// matches the host exactly or as a parent domain suffix.
    pub fn allows(&self, host: &str) -> bool {
        let host = host.to_lowercase();
        let host = host
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .unwrap_or(&host);
        self.hosts
            .iter()
            .any(|entry| host == entry || host.ends_with(&format!(".{entry}")))
    }
}

/// Env var holding the egress allowlist (comma/whitespace separated hosts).
pub const ALLOWED_HOSTS_VAR: &str = "PREVIEW_ALLOWED_HOSTS";

/// Development-only opt-out: when exactly `"true"` and no allowlist is set, the
/// worker runs on the hardened denylist alone (DNS-rebinding exposed).
pub const ALLOW_ANY_HOST_VAR: &str = "PREVIEW_ALLOW_ANY_HOST";

/// Outbound fetch policy, derived once per request from the worker's vars.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressPolicy {
    /// Only hosts on the allowlist are fetchable (and the denylist still
    /// applies to them). The production mode.
    AllowList(AllowList),
    /// Any public host passes the hardened denylist. Rebind-vulnerable; only
    /// reachable through [`ALLOW_ANY_HOST_VAR`] for local development.
    DenylistOnly,
    /// No allowlist and no opt-out: every outbound fetch is refused.
    Closed,
}

impl EgressPolicy {
    /// Derive the policy from the raw [`ALLOWED_HOSTS_VAR`] and
    /// [`ALLOW_ANY_HOST_VAR`] values (`None` when unset).
    ///
    /// A non-empty parsed allowlist always wins. A blank allowlist (`""`,
    /// whitespace, bare separators) counts as unset. Without an allowlist the
    /// worker is [`EgressPolicy::Closed`] unless the opt-out is exactly `true`
    /// (surrounding whitespace ignored), so a typo or `"1"` never opens it.
    pub fn from_vars(allowed_hosts: Option<&str>, allow_any_host: Option<&str>) -> Self {
        let list = AllowList::parse(allowed_hosts.unwrap_or(""));
        if !list.is_empty() {
            EgressPolicy::AllowList(list)
        } else if allow_any_host.map(str::trim) == Some("true") {
            EgressPolicy::DenylistOnly
        } else {
            EgressPolicy::Closed
        }
    }

    /// `true` when every outbound fetch is refused.
    pub fn is_closed(&self) -> bool {
        matches!(self, EgressPolicy::Closed)
    }
}

/// Process-global egress policy consulted by [`is_private_url`].
///
/// Kept global (rather than threaded through every call site) so the redirect
/// loop in [`ssrf_fetch_with_redirects`] and the OG/oEmbed fetchers re-check
/// every hop against the same policy without signature changes.
///
/// Initialised lazily from the process environment (effective for native
/// builds and tests); with nothing set that is [`EgressPolicy::Closed`]. The
/// CF Workers WASM runtime injects vars via the JS `Env` object instead, so the
/// worker entry point calls [`set_policy`] on every request.
static POLICY: std::sync::OnceLock<std::sync::RwLock<EgressPolicy>> = std::sync::OnceLock::new();

fn policy_cell() -> &'static std::sync::RwLock<EgressPolicy> {
    POLICY.get_or_init(|| {
        let allowed = std::env::var(ALLOWED_HOSTS_VAR).ok();
        let any = std::env::var(ALLOW_ANY_HOST_VAR).ok();
        std::sync::RwLock::new(EgressPolicy::from_vars(allowed.as_deref(), any.as_deref()))
    })
}

/// Install the egress policy for all subsequent SSRF checks.
///
/// The worker entry point derives the policy from its JS `Env` and calls this
/// on every request (cheap: one `RwLock` write), so no state from an earlier
/// request or deployment can linger.
pub fn set_policy(policy: EgressPolicy) {
    if let Ok(mut guard) = policy_cell().write() {
        *guard = policy;
    }
}

/// Snapshot the current global policy for a single validation pass. A
/// poisoned lock yields [`EgressPolicy::Closed`].
fn current_policy() -> EgressPolicy {
    policy_cell()
        .read()
        .map(|g| g.clone())
        .unwrap_or(EgressPolicy::Closed)
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
/// [`MAX_BODY_BYTES`]. Streaming responses are consumed incrementally and
/// aborted as soon as the cap is crossed, so a hostile origin cannot force an
/// unbounded allocation before rejection.
pub async fn read_text_capped(mut response: Response) -> Result<String, SsrfFetchError> {
    let bytes = read_response_capped(&mut response, MAX_BODY_BYTES).await?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Read the response body as raw bytes, rejecting bodies that exceed
/// `max_bytes`. Mirrors [`read_text_capped`] but returns the undecoded bytes —
/// used by the ASCII route, which needs the binary image payload rather than a
/// UTF-8 document. Callers should pass [`MAX_IMAGE_BYTES`].
pub async fn read_bytes_capped(
    mut response: Response,
    max_bytes: usize,
) -> Result<Vec<u8>, SsrfFetchError> {
    read_response_capped(&mut response, max_bytes).await
}

async fn read_response_capped(
    response: &mut Response,
    max_bytes: usize,
) -> Result<Vec<u8>, SsrfFetchError> {
    if let Some(content_length) = response
        .headers()
        .get("Content-Length")
        .ok()
        .flatten()
        .and_then(|value| value.parse::<usize>().ok())
    {
        if content_length > max_bytes {
            return Err(SsrfFetchError::BodyTooLarge);
        }
    }

    if matches!(response.body(), ResponseBody::Stream(_)) {
        let mut bytes = Vec::with_capacity(max_bytes.min(64 * 1024));
        let mut stream = response.stream()?;
        while let Some(chunk) = stream.try_next().await? {
            let remaining = max_bytes.saturating_sub(bytes.len());
            if chunk.len() > remaining {
                return Err(SsrfFetchError::BodyTooLarge);
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    } else {
        let bytes = response.bytes().await?;
        if bytes.len() > max_bytes {
            return Err(SsrfFetchError::BodyTooLarge);
        }
        Ok(bytes)
    }
}

/// Returns `true` if the URL should be blocked: the egress policy is closed,
/// the host fails the egress allowlist, the URL uses a non-http(s) scheme, carries userinfo, uses
/// a non-standard port, or its hostname text matches a private, loopback,
/// link-local, metadata, `.local`, or otherwise internal address.
///
/// **DNS rebinding caveat:** the hostname checks operate on the URL *string*,
/// not the IP the CF runtime resolves at fetch time (see module docs). The
/// allowlist is the authoritative mitigation; the denylist below is hardened
/// best-effort and is rebind-vulnerable under [`EgressPolicy::DenylistOnly`].
pub(crate) fn is_private_url(raw_url: &str) -> bool {
    is_private_url_with(raw_url, &current_policy())
}

/// Policy-explicit core of [`is_private_url`]. Kept pure (no global reads) so
/// it can be unit-tested deterministically without mutating process state.
pub(crate) fn is_private_url_with(raw_url: &str, policy: &EgressPolicy) -> bool {
    refusal_with(raw_url, policy).is_some()
}

/// Why a URL is refused, so the answer can say which rule refused it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// A private, loopback, link-local, metadata or otherwise internal
    /// address, a non-http(s) scheme, userinfo, a non-standard port, or the
    /// egress policy is closed.
    Private,
    /// A public host that is not on the egress allowlist.
    NotOnAllowList,
}

impl Refusal {
    /// The `error` text of the 400 answer for this refusal.
    pub(crate) fn message(self) -> &'static str {
        match self {
            Refusal::Private => "URL not allowed (private or internal address)",
            Refusal::NotOnAllowList => {
                "URL not allowed (this site is not on the forum's preview allow-list)"
            }
        }
    }
}

/// Why [`is_private_url`] refuses `raw_url` under the current policy, or
/// `None` when it may be fetched.
pub(crate) fn refusal(raw_url: &str) -> Option<Refusal> {
    refusal_with(raw_url, &current_policy())
}

/// Policy-explicit core of [`refusal`]. The denylist is judged first so an
/// internal address outside the allowlist is still reported as private; both
/// are checks on the URL text before any fetch, so the order changes only the
/// message, never what is blocked.
pub(crate) fn refusal_with(raw_url: &str, policy: &EgressPolicy) -> Option<Refusal> {
    if policy.is_closed() || denylisted(raw_url) {
        return Some(Refusal::Private);
    }
    // Egress allowlist (authoritative when configured): the robust
    // DNS-rebinding mitigation available in the CF Workers runtime.
    if let EgressPolicy::AllowList(allowlist) = policy {
        let host = Url::parse(raw_url)
            .ok()
            .and_then(|u| u.host_str().map(str::to_lowercase));
        if !host.is_some_and(|h| allowlist.allows(&h)) {
            return Some(Refusal::NotOnAllowList);
        }
    }
    None
}

/// The policy-independent denylist: scheme, userinfo, port and the
/// private/internal hostname checks.
fn denylisted(raw_url: &str) -> bool {
    let parsed = match Url::parse(raw_url) {
        Ok(u) => u,
        Err(_) => return true, // unparseable -> block
    };

    // Only allow HTTP(S)
    match parsed.scheme() {
        "http" | "https" => {}
        _ => return true,
    }

    // Reject embedded credentials (`user:pass@host`) — a classic way to
    // disguise the real authority and confuse downstream parsers.
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return true;
    }

    // Restrict to the standard web ports. An explicit port other than 80/443
    // is a strong signal of an attempt to reach an internal service.
    if let Some(port) = parsed.port() {
        if port != 80 && port != 443 {
            return true;
        }
    }

    let hostname: String = match parsed.host_str() {
        Some(h) => h.to_lowercase(),
        None => return true,
    };

    // Reject mDNS / internal `.local` TLD (RFC 6762) — never publicly routable.
    if hostname == "local" || hostname.ends_with(".local") {
        return true;
    }

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

    // Parse as a real IPv6 address so every textual form is covered, not just a
    // handful of known prefixes. Crucially, the IPv4-in-IPv6 transition forms
    // embed an internal IPv4 that a prefix match misses — e.g. NAT64
    // `[64:ff9b::7f00:1]` (127.0.0.1), 6to4 `[2002:7f00:1::]`, and
    // IPv4-compatible `[::a9fe:a9fe]` (169.254.169.254). Extract the embedded
    // IPv4 and re-check it against the private ranges.
    if let Ok(v6) = host.parse::<std::net::Ipv6Addr>() {
        if v6.is_loopback() || v6.is_unspecified() {
            return true;
        }
        let seg = v6.segments();
        // ULA fc00::/7, link-local fe80::/10, deprecated site-local fec0::/10.
        if (seg[0] & 0xfe00) == 0xfc00 || (seg[0] & 0xffc0) == 0xfe80 || (seg[0] & 0xffc0) == 0xfec0
        {
            return true;
        }
        let embedded_v4 = |hi: u16, lo: u16| {
            is_private_ipv4([
                (hi >> 8) as u8,
                (hi & 0xff) as u8,
                (lo >> 8) as u8,
                (lo & 0xff) as u8,
            ])
        };
        // 6to4 2002::/16 — IPv4 in segments 1..2.
        if seg[0] == 0x2002 {
            return embedded_v4(seg[1], seg[2]);
        }
        // NAT64 64:ff9b::/96 — IPv4 in the low 32 bits.
        if seg[0] == 0x0064 && seg[1] == 0xff9b {
            return embedded_v4(seg[6], seg[7]);
        }
        // IPv4-mapped (::ffff:a.b.c.d) and IPv4-compatible (::a.b.c.d): high 80
        // bits zero, segment 5 either 0 (compat) or 0xffff (mapped).
        if seg[0] == 0
            && seg[1] == 0
            && seg[2] == 0
            && seg[3] == 0
            && seg[4] == 0
            && (seg[5] == 0 || seg[5] == 0xffff)
        {
            return embedded_v4(seg[6], seg[7]);
        }
        // Any other global-scope IPv6 literal is not in our private set.
        return false;
    }

    // Fallback for inputs `Ipv6Addr` could not parse (should not occur after URL
    // host normalization): keep the conservative textual prefix checks.
    if host == "::1" || host.starts_with("fc") || host.starts_with("fd") || host.starts_with("fe80")
    {
        return true;
    }
    if let Some(rest) = host.strip_prefix("::ffff:") {
        if let Some(octets) = parse_ipv4(rest) {
            return is_private_ipv4(octets);
        }
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

    /// Denylist checks under the dev opt-out policy, independent of the
    /// process-global policy (which fails closed when nothing is configured).
    fn is_private_url(raw_url: &str) -> bool {
        is_private_url_with(raw_url, &EgressPolicy::DenylistOnly)
    }

    // SSRF protection tests
    #[test]
    fn blocks_non_http_protocols() {
        assert!(is_private_url("ftp://example.com/file"));
        assert!(is_private_url("file:///etc/passwd"));
        assert!(is_private_url("gopher://localhost"));
    }

    #[test]
    fn blocks_ipv6_transition_forms_embedding_internal_ipv4() {
        // NAT64 64:ff9b::/96 embedding 127.0.0.1 and 169.254.169.254.
        assert!(is_private_url("http://[64:ff9b::7f00:1]/"));
        assert!(is_private_url("http://[64:ff9b::a9fe:a9fe]/"));
        // IPv4-compatible ::a.b.c.d (low 32 bits) embedding loopback / metadata.
        assert!(is_private_url("http://[::7f00:1]/"));
        assert!(is_private_url("http://[::a9fe:a9fe]/"));
        // 6to4 2002::/16 embedding 127.0.0.1.
        assert!(is_private_url("http://[2002:7f00:1::]/"));
        // Deprecated site-local fec0::/10.
        assert!(is_private_url("http://[fec0::1]/"));
    }

    #[test]
    fn allows_public_ipv6_literal() {
        // A genuine global-scope IPv6 address must NOT be treated as private.
        assert!(!is_private_url("http://[2606:4700:4700::1111]/"));
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

    // ── P1-7 hardening: userinfo / ports / .local ──────────────────────

    #[test]
    fn blocks_userinfo_in_authority() {
        // `user:pass@host` disguises the real authority.
        assert!(is_private_url("http://attacker@example.com/"));
        assert!(is_private_url("https://user:pass@example.com/"));
        // A bare public host without userinfo is still allowed.
        assert!(!is_private_url("https://example.com/"));
    }

    #[test]
    fn blocks_non_standard_ports() {
        assert!(is_private_url("http://example.com:8080/"));
        assert!(is_private_url("https://example.com:22/"));
        // Standard ports remain allowed.
        assert!(!is_private_url("http://example.com:80/"));
        assert!(!is_private_url("https://example.com:443/"));
    }

    #[test]
    fn blocks_mdns_local_tld() {
        assert!(is_private_url("http://printer.local/"));
        assert!(is_private_url("http://local/"));
    }

    // ── Egress policy (allow-list, fail closed) ────────────────────────
    //
    // Exercised through the pure `is_private_url_with(url, &policy)` core and
    // `EgressPolicy::from_vars` so tests never touch the process-global policy
    // and cannot race each other.

    #[test]
    fn allowlist_parse_matches_apex_and_subdomains() {
        let list = AllowList::parse("example.com, .images.example.org");
        assert!(!list.is_empty());
        assert!(list.allows("example.com")); // apex
        assert!(list.allows("www.example.com")); // subdomain of bare entry
        assert!(list.allows("images.example.org")); // apex of dotted entry
        assert!(list.allows("cdn.images.example.org")); // subdomain
        assert!(!list.allows("evil.com"));
        assert!(!list.allows("notexample.com")); // suffix must be a label boundary
    }

    #[test]
    fn policy_unset_fails_closed() {
        assert_eq!(EgressPolicy::from_vars(None, None), EgressPolicy::Closed);
    }

    #[test]
    fn policy_blank_allowlist_counts_as_unset() {
        // Set-but-blank must not silently open the worker.
        for raw in ["", "   ", ",,", " , \t\n"] {
            assert_eq!(
                EgressPolicy::from_vars(Some(raw), None),
                EgressPolicy::Closed,
                "blank PREVIEW_ALLOWED_HOSTS {raw:?} must fail closed"
            );
        }
    }

    #[test]
    fn policy_opt_out_requires_exact_true() {
        assert_eq!(
            EgressPolicy::from_vars(None, Some("true")),
            EgressPolicy::DenylistOnly
        );
        assert_eq!(
            EgressPolicy::from_vars(Some(" "), Some(" true ")),
            EgressPolicy::DenylistOnly
        );
        for raw in ["", "false", "1", "yes", "TRUE", "on"] {
            assert_eq!(
                EgressPolicy::from_vars(None, Some(raw)),
                EgressPolicy::Closed,
                "PREVIEW_ALLOW_ANY_HOST={raw:?} must not open the worker"
            );
        }
    }

    #[test]
    fn policy_allowlist_wins_over_opt_out() {
        let p = EgressPolicy::from_vars(Some("example.com"), Some("true"));
        assert_eq!(p, EgressPolicy::AllowList(AllowList::parse("example.com")));
        assert!(!p.is_closed());
    }

    #[test]
    fn closed_policy_blocks_every_url() {
        let closed = EgressPolicy::Closed;
        assert!(closed.is_closed());
        assert!(is_private_url_with("https://example.com/", &closed));
        assert!(is_private_url_with(
            "https://www.youtube.com/watch?v=x",
            &closed
        ));
        assert!(is_private_url_with("http://127.0.0.1/", &closed));
    }

    #[test]
    fn denylist_only_allows_public_and_blocks_private() {
        let open = EgressPolicy::DenylistOnly;
        assert!(!is_private_url_with("https://example.com/", &open));
        assert!(!is_private_url_with("https://other.com/", &open));
        assert!(is_private_url_with("http://127.0.0.1/", &open));
    }

    #[test]
    fn allowlist_enforced_when_set() {
        let list = EgressPolicy::from_vars(Some("example.com"), None);
        // Allowlisted apex + subdomain pass.
        assert!(!is_private_url_with("https://example.com/", &list));
        assert!(!is_private_url_with("https://www.example.com/", &list));
        // Anything outside the allowlist is blocked BEFORE any DNS resolution —
        // the real DNS-rebinding mitigation in the CF Workers runtime.
        assert!(
            is_private_url_with("https://rebind.attacker.com/", &list),
            "host outside allowlist must be blocked regardless of resolution"
        );
        assert!(is_private_url_with("https://other.com/", &list));
    }

    #[test]
    fn allowlist_redirect_hop_to_private_host_rejected() {
        // Even when the initial host is allowlisted, a redirect hop to a host
        // outside the allowlist is rejected: the redirect loop re-runs the same
        // validation on every `Location` target.
        let list = EgressPolicy::from_vars(Some("example.com"), None);
        assert!(is_private_url_with("http://169.254.169.254/latest/", &list));
        assert!(is_private_url_with("http://192.168.1.1/secret", &list));
    }

    #[test]
    fn allowlisted_host_still_subject_to_denylist() {
        // An operator who lists an IP literal or `.local` name by mistake does
        // not reopen the internal ranges.
        let list = EgressPolicy::from_vars(Some("127.0.0.1, printer.local"), None);
        assert!(is_private_url_with("http://127.0.0.1/", &list));
        assert!(is_private_url_with("http://printer.local/", &list));
    }

    #[test]
    fn a_public_host_off_the_allowlist_gets_its_own_refusal() {
        let list = EgressPolicy::from_vars(Some("example.com"), None);
        for url in ["https://other.com/", "https://news.bbc.co.uk/article"] {
            assert_eq!(
                refusal_with(url, &list),
                Some(Refusal::NotOnAllowList),
                "{url}"
            );
        }
        assert_eq!(refusal_with("https://www.example.com/", &list), None);
        assert!(Refusal::NotOnAllowList
            .message()
            .contains("this site is not on the forum's preview allow-list"));
        assert!(!Refusal::NotOnAllowList.message().contains("private"));
    }

    #[test]
    fn a_private_host_keeps_the_private_refusal_on_or_off_the_allowlist() {
        let list = EgressPolicy::from_vars(Some("example.com, 127.0.0.1"), None);
        for url in [
            "http://127.0.0.1/",              // listed by mistake
            "http://169.254.169.254/latest/", // not listed
            "http://192.168.1.1/secret",
            "http://localhost/",
            "http://printer.local/",
        ] {
            assert_eq!(refusal_with(url, &list), Some(Refusal::Private), "{url}");
        }
        assert_eq!(
            refusal_with("http://10.0.0.1/", &EgressPolicy::DenylistOnly),
            Some(Refusal::Private)
        );
        assert!(Refusal::Private
            .message()
            .contains("private or internal address"));
    }

    #[test]
    fn refusal_agrees_with_is_private_url() {
        let list = EgressPolicy::from_vars(Some("example.com"), None);
        for policy in [&list, &EgressPolicy::DenylistOnly, &EgressPolicy::Closed] {
            for url in [
                "https://example.com/",
                "https://other.com/",
                "http://127.0.0.1/",
                "ftp://example.com/",
                "https://example.com:8443/",
                "not a url",
            ] {
                assert_eq!(
                    refusal_with(url, policy).is_some(),
                    is_private_url_with(url, policy),
                    "{url} under {policy:?}"
                );
            }
        }
    }

    #[test]
    fn ssrf_constants_safe() {
        const { assert!(MAX_REDIRECTS <= 5, "redirect cap must remain small") };
        const {
            assert!(
                MAX_BODY_BYTES <= 5 * 1024 * 1024,
                "body cap must remain small"
            )
        };
    }
}
