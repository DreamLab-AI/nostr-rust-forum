//! Base-path discipline and `returnTo` validation (ADR-090).
//!
//! The forum is deployed under a compile-time `FORUM_BASE` prefix (production
//! `/community`, development empty). The invariant the ADR fixes is that every
//! internal path handled by the app is **base-relative** — the prefix is added
//! in exactly two places (`<Router base=>` and `base_href`) and
//! removed in exactly one ([`app_path`]).
//!
//! Everything in this module is pure and free of `web_sys`, so it compiles and
//! unit-tests natively as well as for `wasm32-unknown-unknown`.
//!
//! # Why segment-aware stripping
//!
//! The previous implementation removed the base with a plain textual
//! `strip_prefix`, which conflates two different things:
//!
//! - `/communityfoo` merely *begins with the same characters* as the base
//!   `/community`; it is a sibling route, not a route inside the base. A
//!   textual strip mangles it into `/foo`.
//! - `/community/community-notes` *is* inside the base and must lose only the
//!   leading occurrence, never the inner one.
//!
//! [`strip_base`] therefore only strips when the character following the base
//! is a path-segment boundary (`/`, `?`, `#`) or the string ends there.
//!
//! # Why `returnTo` needs its own validator
//!
//! `returnTo` is attacker-controllable (it arrives in the query string of a
//! link anyone can send). Feeding it to `use_navigate` or `location.href`
//! without validation is a textbook open redirect, and a `javascript:` /
//! `data:` payload would additionally be script execution. [`sanitise_return_to`]
//! accepts app-internal relative paths only and falls back to a safe default
//! for everything else.

/// Longest `returnTo` we will honour. Anything longer is a probe, not a route.
const MAX_RETURN_TO_LEN: usize = 512;

/// Maximum percent-decoding rounds applied when checking for smuggled
/// separators (`%252f` → `%2f` → `/`). Four rounds is far beyond any honest
/// link and bounds the work done on hostile input.
const MAX_DECODE_ROUNDS: usize = 4;

// -- Base handling ------------------------------------------------------------

/// Normalise a configured base prefix: no trailing slash, empty means "root".
///
/// `""`, `"/"` → `""`; `"/community/"` → `"/community"`.
pub fn normalise_base(base: &str) -> &str {
    let trimmed = base.trim_end_matches('/');
    if trimmed == "/" {
        ""
    } else {
        trimmed
    }
}

/// Remove the base prefix from a browser path, **only** on a proper
/// path-segment boundary.
///
/// Returns `None` when `pathname` is not inside the base — including the
/// prefix-collision case (`base = "/community"`, `pathname = "/communityfoo"`),
/// which must be left alone rather than mangled.
///
/// An exact match on the base (`/community`, `/community/`) yields `"/"`.
pub fn strip_base<'a>(base: &str, pathname: &'a str) -> Option<&'a str> {
    let base = normalise_base(base);
    if base.is_empty() {
        return Some(pathname);
    }
    let rest = pathname.strip_prefix(base)?;
    match rest.as_bytes().first() {
        // Exactly the base: the app root.
        None => Some("/"),
        // A genuine segment boundary (or the start of a query / fragment).
        Some(b'/') | Some(b'?') | Some(b'#') => Some(rest),
        // Same leading characters, different route — not inside the base.
        Some(_) => None,
    }
}

/// Whether `pathname` lies inside `base` (segment-aware).
pub fn is_inside_base(base: &str, pathname: &str) -> bool {
    strip_base(base, pathname).is_some() && !normalise_base(base).is_empty()
}

/// Convert a browser path into the base-relative app path.
///
/// `app_path("/community", "/community/forums")` → `"/forums"`.
/// `app_path("/community", "/communityfoo")` → `"/communityfoo"` (untouched —
/// it is not inside the base).
/// `app_path("", p)` is the identity (modulo guaranteeing a leading `/`).
///
/// The result always starts with `/`.
pub fn app_path(base: &str, pathname: &str) -> String {
    let stripped = strip_base(base, pathname).unwrap_or(pathname);
    if stripped.is_empty() {
        "/".to_string()
    } else if stripped.starts_with('/') {
        stripped.to_string()
    } else {
        format!("/{stripped}")
    }
}

/// Segment-aware prefix test for routes.
///
/// `path_has_prefix("/login", "/login")` and `path_has_prefix("/login?x=1",
/// "/login")` are true; `path_has_prefix("/loginhelp", "/login")` is false.
/// A textual `starts_with` gets that last case wrong and would bounce a
/// legitimate route.
pub fn path_has_prefix(path: &str, prefix: &str) -> bool {
    match path.strip_prefix(prefix) {
        None => false,
        Some(rest) => matches!(
            rest.as_bytes().first(),
            None | Some(b'/') | Some(b'?') | Some(b'#')
        ),
    }
}

// -- `returnTo` validation ----------------------------------------------------

/// Why a `returnTo` candidate was refused. Returned by
/// [`validate_return_to`] so call sites (and tests) can distinguish the
/// classes rather than only seeing the fallback route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReturnToError {
    /// Empty, or longer than `MAX_RETURN_TO_LEN`.
    Empty,
    /// Too long to be an honest internal route.
    TooLong,
    /// Does not start with `/` — an absolute URL, a scheme (`javascript:`,
    /// `data:`, `http:`) or a bare relative path. Also covers a colon or
    /// backslash appearing inside an otherwise slash-anchored path.
    NotRelative,
    /// Scheme-relative (`//evil.example`) or backslash authority (`/\evil`).
    ProtocolRelative,
    /// Contains a character no route of ours can contain: whitespace, a
    /// control character, or anything outside printable ASCII (zero-width and
    /// bidirectional Unicode included).
    IllegalCharacter,
    /// Carries a fragment. Fragments are never part of an internal redirect
    /// target here and have been used to smuggle secrets (ADR-098).
    HasFragment,
    /// Malformed percent-encoding.
    BadEncoding,
    /// Encoded (or literal) traversal / separator smuggling — `..`, `%2e%2e`,
    /// `%2f%2f`, empty segments.
    Traversal,
    /// Still base-prefixed after one strip — the ADR-090 rule 4 case
    /// (`/community/community/forums`).
    EscapesBase,
    /// Resolves to the app root, which is the fallback's job, not a redirect
    /// target.
    Root,
    /// Lands on a blocked route (`/login`, `/signup`, …) and would loop.
    BlockedRoute,
}

/// Validate an attacker-controllable `returnTo` and reduce it to a
/// base-relative app path.
///
/// Accepts **only** app-internal relative paths. Rejected, in every case
/// falling back to the caller's default route via [`sanitise_return_to`]:
///
/// - absolute URLs (`https://evil.example/x`) and any scheme
///   (`javascript:alert(1)`, `data:text/html,…`, `mailto:`) — they do not
///   start with `/`;
/// - scheme-relative `//evil.example` and the backslash variants `/\evil`,
///   `\\evil` (browsers normalise `\` to `/` in URLs);
/// - control characters and whitespace (`/%0a/…`, tab-splitting tricks) —
///   browsers strip these during URL parsing, so a value containing them does
///   not mean what it reads as;
/// - fragments;
/// - percent-encoded traversal and separator smuggling, checked over repeated
///   decoding rounds so `%252f%252fevil` is caught as well as `%2f%2fevil`;
/// - anything that, after one base strip, is still inside the base
///   (ADR-090 rule 4);
/// - the app root and the caller's blocked routes (`/login`, `/signup`, …),
///   which would produce a redirect loop.
///
/// `base` is the deployment prefix (`FORUM_BASE`). Query strings survive
/// intact; the returned value is safe to hand to `use_navigate`, which
/// re-applies the base itself.
pub fn validate_return_to(
    base: &str,
    raw: &str,
    blocked: &[&str],
) -> Result<String, ReturnToError> {
    if raw.is_empty() {
        return Err(ReturnToError::Empty);
    }
    if raw.len() > MAX_RETURN_TO_LEN {
        return Err(ReturnToError::TooLong);
    }

    // -- Structural checks on the value exactly as received -------------------
    if !raw.starts_with('/') {
        return Err(ReturnToError::NotRelative);
    }
    if matches!(raw.as_bytes().get(1), Some(b'/') | Some(b'\\')) {
        return Err(ReturnToError::ProtocolRelative);
    }
    for ch in raw.chars() {
        if ch == '#' {
            return Err(ReturnToError::HasFragment);
        }
        if ch == '\\' || ch.is_control() || ch.is_whitespace() {
            return Err(ReturnToError::IllegalCharacter);
        }
    }

    // -- Decode-and-recheck the path portion ----------------------------------
    // A query value may legitimately percent-encode almost anything, so the
    // decoding rounds apply to the path only; the structural pass above has
    // already cleared the query of raw control characters and backslashes.
    let (path_part, _query) = split_query(raw);
    check_path_shape(path_part)?;

    let mut decoded = path_part.to_string();
    for _ in 0..MAX_DECODE_ROUNDS {
        match percent_decode(&decoded)? {
            None => break,
            Some(next) => {
                check_path_shape(&next)?;
                decoded = next;
            }
        }
    }

    // -- Reduce to a base-relative app path -----------------------------------
    let stripped = app_path(base, raw);
    // ADR-090 rule 4: after stripping, a value still inside the base was
    // double-prefixed (or is deliberately trying to escape). Refuse it.
    if is_inside_base(base, &stripped) {
        return Err(ReturnToError::EscapesBase);
    }
    // The strip must not have produced something that fails the structural
    // rules (a base of `/community` and a path of `/community//evil` would).
    if matches!(stripped.as_bytes().get(1), Some(b'/') | Some(b'\\')) {
        return Err(ReturnToError::ProtocolRelative);
    }
    check_path_shape(split_query(&stripped).0)?;

    // -- Route policy ---------------------------------------------------------
    // The root is the fallback's job, with or without a query attached.
    if split_query(&stripped).0.trim_end_matches('/').is_empty() {
        return Err(ReturnToError::Root);
    }
    for blocked_route in blocked {
        if path_has_prefix(&stripped, blocked_route) {
            return Err(ReturnToError::BlockedRoute);
        }
    }

    Ok(stripped)
}

/// [`validate_return_to`] with a safe default for every rejection.
///
/// This is the form call sites use: an invalid or hostile `returnTo` silently
/// becomes `fallback` rather than an open redirect.
pub fn sanitise_return_to(base: &str, raw: &str, fallback: &str, blocked: &[&str]) -> String {
    validate_return_to(base, raw, blocked).unwrap_or_else(|_| fallback.to_string())
}

/// Compute a `/login?returnTo=…` target from a raw browser pathname.
///
/// Returns `None` when the user is already on an auth route, so the caller
/// skips the navigation entirely instead of overwriting a good `returnTo`
/// with a self-referential one. The pathname is reduced to a base-relative app
/// path first, so the guards match in production builds where the browser path
/// carries the `FORUM_BASE` prefix.
pub fn login_redirect_for(base: &str, pathname: &str, auth_routes: &[&str]) -> Option<String> {
    let path = app_path(base, pathname);
    for route in auth_routes {
        if path_has_prefix(&path, route) {
            return None;
        }
    }
    // The pathname comes from the router, but it is still reduced through the
    // same validator so a hostile `location.pathname` can never be reflected
    // into the query string.
    match validate_return_to(base, &path, auth_routes) {
        Ok(safe) => Some(format!("/login?returnTo={safe}")),
        Err(_) => Some("/login".to_string()),
    }
}

// -- Internals ----------------------------------------------------------------

/// Split a relative reference into its path and its query (including `?`).
fn split_query(raw: &str) -> (&str, &str) {
    match raw.find('?') {
        Some(idx) => (&raw[..idx], &raw[idx..]),
        None => (raw, ""),
    }
}

/// Structural rules for the path portion of an internal route.
///
/// Every route this app owns is ASCII (hex ids, hashed slugs, invite codes,
/// fixed words), so the path is restricted to printable ASCII minus the
/// characters that create parser disagreements. That single rule disposes of
/// control characters, every flavour of whitespace, zero-width and
/// bidirectional Unicode, and non-ASCII homographs in one place.
fn check_path_shape(path: &str) -> Result<(), ReturnToError> {
    if !path.starts_with('/') {
        return Err(ReturnToError::NotRelative);
    }
    if matches!(path.as_bytes().get(1), Some(b'/') | Some(b'\\')) {
        return Err(ReturnToError::ProtocolRelative);
    }
    for ch in path.chars() {
        if ch == '#' {
            return Err(ReturnToError::HasFragment);
        }
        // No app route contains a colon. Refusing it removes the whole class of
        // "is this a scheme or a path?" parser disagreements.
        if ch == ':' || ch == '\\' {
            return Err(ReturnToError::NotRelative);
        }
        // Printable ASCII only (U+0021..U+007E). Space, DEL, C0/C1 controls,
        // U+FEFF and every non-ASCII code point fall out here.
        if !matches!(ch, '\u{21}'..='\u{7e}') {
            return Err(ReturnToError::IllegalCharacter);
        }
    }
    if path == "/" {
        return Ok(());
    }
    // `/a//b`, `/a/./b`, `/a/../b` — empty and dot segments never appear in a
    // real route and are the traversal primitives. One trailing slash is
    // tolerated (`/forums/`), so it is trimmed before the segment walk.
    let body = path.trim_end_matches('/');
    if body.is_empty() {
        // `//`, `///`, … — already caught above, but keep the invariant local.
        return Err(ReturnToError::ProtocolRelative);
    }
    for segment in body.split('/').skip(1) {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(ReturnToError::Traversal);
        }
    }
    Ok(())
}

/// One round of percent-decoding.
///
/// `Ok(None)` when there was nothing to decode, `Ok(Some(s))` for the decoded
/// string, `Err(BadEncoding)` for a malformed escape or a decoding that does
/// not yield valid UTF-8 (both are hostile-input signatures, never honest
/// links).
fn percent_decode(input: &str) -> Result<Option<String>, ReturnToError> {
    if !input.contains('%') {
        return Ok(None);
    }
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err(ReturnToError::BadEncoding);
            }
            let hi = hex_val(bytes[i + 1]).ok_or(ReturnToError::BadEncoding)?;
            let lo = hex_val(bytes[i + 2]).ok_or(ReturnToError::BadEncoding)?;
            out.push(hi * 16 + lo);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out)
        .map(Some)
        .map_err(|_| ReturnToError::BadEncoding)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "/community";
    const BLOCKED: &[&str] = &["/login", "/signup", "/setup"];

    // -- normalise_base -------------------------------------------------------

    #[test]
    fn normalise_base_strips_trailing_slash() {
        assert_eq!(normalise_base("/community/"), "/community");
        assert_eq!(normalise_base("/community"), "/community");
        assert_eq!(normalise_base("/"), "");
        assert_eq!(normalise_base(""), "");
    }

    // -- strip_base / app_path ------------------------------------------------

    #[test]
    fn strip_base_is_identity_when_base_empty() {
        assert_eq!(strip_base("", "/forums"), Some("/forums"));
        assert_eq!(app_path("", "/forums"), "/forums");
        assert_eq!(app_path("", "/"), "/");
    }

    #[test]
    fn strip_base_removes_only_the_leading_occurrence() {
        // The inner `/community-notes` must survive untouched.
        assert_eq!(
            app_path(BASE, "/community/community-notes"),
            "/community-notes"
        );
        assert_eq!(
            app_path(BASE, "/community/forums/community/board"),
            "/forums/community/board"
        );
    }

    #[test]
    fn strip_base_refuses_prefix_collisions() {
        // `/communityfoo` merely begins with the same characters; it is a
        // sibling route and must not be mangled into `/foo`.
        assert_eq!(strip_base(BASE, "/communityfoo"), None);
        assert_eq!(app_path(BASE, "/communityfoo"), "/communityfoo");
        assert_eq!(app_path(BASE, "/community-notes"), "/community-notes");
        assert_eq!(app_path(BASE, "/communities"), "/communities");
    }

    #[test]
    fn strip_base_handles_exact_and_trailing_forms() {
        assert_eq!(app_path(BASE, "/community"), "/");
        assert_eq!(app_path(BASE, "/community/"), "/");
        assert_eq!(app_path(BASE, "/community?tab=1"), "/?tab=1");
    }

    #[test]
    fn strip_base_leaves_foreign_paths_alone() {
        assert_eq!(app_path(BASE, "/forums"), "/forums");
        assert_eq!(app_path(BASE, "/"), "/");
    }

    #[test]
    fn app_path_always_starts_with_slash() {
        assert!(app_path(BASE, "forums").starts_with('/'));
        assert!(app_path("", "").starts_with('/'));
    }

    // -- path_has_prefix ------------------------------------------------------

    #[test]
    fn path_prefix_matches_only_on_segment_boundaries() {
        assert!(path_has_prefix("/login", "/login"));
        assert!(path_has_prefix("/login/", "/login"));
        assert!(path_has_prefix("/login?returnTo=/x", "/login"));
        assert!(!path_has_prefix("/loginhelp", "/login"));
        assert!(!path_has_prefix("/log", "/login"));
    }

    // -- returnTo: happy path -------------------------------------------------

    #[test]
    fn return_to_accepts_plain_internal_paths() {
        assert_eq!(
            validate_return_to("", "/forums", BLOCKED),
            Ok("/forums".to_string())
        );
        assert_eq!(
            validate_return_to("", "/join/ABC123", BLOCKED),
            Ok("/join/ABC123".to_string())
        );
    }

    #[test]
    fn return_to_preserves_query_strings() {
        assert_eq!(
            validate_return_to("", "/admin?tab=channels", BLOCKED),
            Ok("/admin?tab=channels".to_string())
        );
        // Percent-encoding inside the QUERY is fine — only the path is decoded
        // and re-checked.
        assert_eq!(
            validate_return_to("", "/search?q=a%20b", BLOCKED),
            Ok("/search?q=a%20b".to_string())
        );
    }

    #[test]
    fn return_to_strips_a_legacy_base_prefixed_value() {
        assert_eq!(
            validate_return_to(BASE, "/community/forums", BLOCKED),
            Ok("/forums".to_string())
        );
    }

    #[test]
    fn return_to_keeps_prefix_collision_routes_intact() {
        assert_eq!(
            validate_return_to(BASE, "/community/community-notes", BLOCKED),
            Ok("/community-notes".to_string())
        );
    }

    // -- returnTo: open-redirect adversarial cases ----------------------------

    #[test]
    fn return_to_rejects_absolute_urls() {
        for hostile in [
            "https://evil.example/x",
            "http://evil.example",
            "HTTPS://evil.example",
            "ftp://evil.example",
            "//evil.example",
            "///evil.example",
            "https:/evil.example",
        ] {
            assert!(
                validate_return_to("", hostile, BLOCKED).is_err(),
                "accepted absolute URL {hostile}"
            );
            assert_eq!(
                sanitise_return_to("", hostile, "/forums", BLOCKED),
                "/forums"
            );
        }
    }

    #[test]
    fn return_to_rejects_scheme_relative_and_backslash_authority() {
        for hostile in [
            "//evil.example/path",
            "/\\evil.example",
            "/\\\\evil.example",
            "\\\\evil.example",
            "\\/evil.example",
            "/foo\\..\\bar",
        ] {
            assert!(
                validate_return_to("", hostile, BLOCKED).is_err(),
                "accepted {hostile}"
            );
        }
    }

    #[test]
    fn return_to_rejects_scheme_payloads() {
        for hostile in [
            "javascript:alert(1)",
            "JaVaScRiPt:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "mailto:a@b.example",
            "vbscript:msgbox(1)",
            "blob:https://evil.example/x",
            "file:///etc/passwd",
        ] {
            assert_eq!(
                validate_return_to("", hostile, BLOCKED),
                Err(ReturnToError::NotRelative),
                "accepted scheme payload {hostile}"
            );
        }
    }

    #[test]
    fn return_to_rejects_a_scheme_hidden_behind_a_leading_slash() {
        // `/javascript:alert(1)` is technically a path, but the colon makes it
        // ambiguous to some parsers; no real route contains one.
        assert!(validate_return_to("", "/javascript:alert(1)", BLOCKED).is_err());
        assert!(validate_return_to("", "/a/data:x", BLOCKED).is_err());
    }

    #[test]
    fn return_to_rejects_control_characters_and_whitespace() {
        for hostile in [
            "/for\nums",
            "/for\rums",
            "/for\tums",
            "/for ums",
            "/\u{0}forums",
            "/for\u{7f}ums",
            "/\u{feff}forums",
        ] {
            assert!(
                validate_return_to("", hostile, BLOCKED).is_err(),
                "accepted control/whitespace {hostile:?}"
            );
        }
    }

    #[test]
    fn return_to_rejects_newline_split_javascript() {
        // The browser strips \n and \t while parsing a URL, so this reads as
        // `javascript:alert(1)` once parsed.
        assert!(validate_return_to("", "/\njavascript:alert(1)", BLOCKED).is_err());
        assert!(validate_return_to("", "/java\tscript:alert(1)", BLOCKED).is_err());
    }

    #[test]
    fn return_to_rejects_fragments() {
        assert_eq!(
            validate_return_to("", "/forums#k=nsec1abc", BLOCKED),
            Err(ReturnToError::HasFragment)
        );
        assert!(validate_return_to("", "/#/evil", BLOCKED).is_err());
    }

    #[test]
    fn return_to_rejects_encoded_separator_smuggling() {
        for hostile in [
            "/%2f%2fevil.example",
            "/%2F%2Fevil.example",
            "/%2f/evil.example",
            "/%252f%252fevil.example",
            "/%5cevil.example",
            "/%5C%5Cevil.example",
            "/%09javascript:alert(1)",
            "/%00",
        ] {
            assert!(
                validate_return_to("", hostile, BLOCKED).is_err(),
                "accepted encoded smuggling {hostile}"
            );
        }
    }

    #[test]
    fn return_to_rejects_traversal() {
        for hostile in [
            "/../etc/passwd",
            "/forums/../../x",
            "/%2e%2e/x",
            "/%2E%2E%2Fx",
            "/%252e%252e/x",
            "/./forums",
            "/forums//x",
        ] {
            assert!(
                validate_return_to("", hostile, BLOCKED).is_err(),
                "accepted traversal {hostile}"
            );
        }
    }

    #[test]
    fn return_to_rejects_malformed_encoding() {
        for hostile in ["/%zz", "/%2", "/%", "/forums%g0"] {
            assert!(
                validate_return_to("", hostile, BLOCKED).is_err(),
                "accepted malformed encoding {hostile}"
            );
        }
    }

    #[test]
    fn return_to_rejects_values_that_stay_inside_the_base() {
        // ADR-090 rule 4: after one strip it must no longer be base-prefixed.
        assert_eq!(
            validate_return_to(BASE, "/community/community/forums", BLOCKED),
            Err(ReturnToError::EscapesBase)
        );
    }

    #[test]
    fn return_to_rejects_root_and_blocked_routes() {
        assert_eq!(
            validate_return_to("", "/", BLOCKED),
            Err(ReturnToError::Root)
        );
        assert_eq!(
            validate_return_to(BASE, "/community/", BLOCKED),
            Err(ReturnToError::Root)
        );
        for looping in ["/login", "/login?returnTo=/x", "/signup", "/setup/step2"] {
            assert_eq!(
                validate_return_to("", looping, BLOCKED),
                Err(ReturnToError::BlockedRoute),
                "accepted looping route {looping}"
            );
        }
        // …but a route that merely starts with the same characters is fine.
        assert_eq!(
            validate_return_to("", "/loginhelp", BLOCKED),
            Ok("/loginhelp".to_string())
        );
    }

    #[test]
    fn return_to_rejects_prefixed_blocked_routes_in_production_builds() {
        assert_eq!(
            validate_return_to(BASE, "/community/login", BLOCKED),
            Err(ReturnToError::BlockedRoute)
        );
    }

    #[test]
    fn return_to_rejects_empty_and_oversized() {
        assert_eq!(
            validate_return_to("", "", BLOCKED),
            Err(ReturnToError::Empty)
        );
        let long = format!("/{}", "a".repeat(MAX_RETURN_TO_LEN));
        assert_eq!(
            validate_return_to("", &long, BLOCKED),
            Err(ReturnToError::TooLong)
        );
    }

    #[test]
    fn sanitise_always_yields_a_usable_route() {
        for hostile in [
            "https://evil.example",
            "//evil.example",
            "javascript:alert(1)",
            "/../../x",
            "/login",
            "/",
            "",
        ] {
            let out = sanitise_return_to(BASE, hostile, "/forums", BLOCKED);
            assert_eq!(out, "/forums", "unexpected sanitised value for {hostile}");
        }
    }

    #[test]
    fn sanitised_output_is_never_base_prefixed() {
        // The router re-applies the base, so a surviving prefix would produce
        // `/community/community/forums` (ADR-090 bug #1).
        for candidate in [
            "/community/forums",
            "/forums",
            "/community/community-notes",
            "https://evil.example",
        ] {
            let out = sanitise_return_to(BASE, candidate, "/forums", BLOCKED);
            assert!(!is_inside_base(BASE, &out), "leaked base in {out}");
            assert!(out.starts_with('/'));
            assert!(!out.starts_with("//"));
        }
    }

    // -- login_redirect_for ---------------------------------------------------

    #[test]
    fn login_redirect_skips_auth_routes() {
        assert_eq!(login_redirect_for("", "/login", BLOCKED), None);
        assert_eq!(login_redirect_for("", "/signup", BLOCKED), None);
        assert_eq!(login_redirect_for(BASE, "/community/login", BLOCKED), None);
        assert_eq!(
            login_redirect_for(BASE, "/community/signup?x=1", BLOCKED),
            None
        );
    }

    #[test]
    fn login_redirect_stores_a_base_relative_target() {
        assert_eq!(
            login_redirect_for(BASE, "/community/forums", BLOCKED),
            Some("/login?returnTo=/forums".to_string())
        );
        assert_eq!(
            login_redirect_for("", "/forums", BLOCKED),
            Some("/login?returnTo=/forums".to_string())
        );
    }

    #[test]
    fn login_redirect_falls_back_to_bare_login_for_root_or_junk() {
        assert_eq!(
            login_redirect_for(BASE, "/community", BLOCKED),
            Some("/login".to_string())
        );
        assert_eq!(
            login_redirect_for("", "/", BLOCKED),
            Some("/login".to_string())
        );
        assert_eq!(
            login_redirect_for("", "/foo\\bar", BLOCKED),
            Some("/login".to_string())
        );
    }

    #[test]
    fn login_redirect_does_not_bounce_lookalike_routes() {
        assert_eq!(
            login_redirect_for("", "/loginhelp", BLOCKED),
            Some("/login?returnTo=/loginhelp".to_string())
        );
    }
}
