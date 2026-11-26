//! Sign-in links and sheet QR payloads (ADR-098, root form).
//!
//! A recovery / sign-in sheet carries ONE QR code whose payload is the link
//! `{origin}{FORUM_BASE}/#k=<nsec1…>`. Scanning it with a phone camera opens
//! the forum root. The forum root exists as a real file on every static host,
//! so no 404 page or SPA redirect step runs. That matters: a GitHub Pages
//! style `404.html` that copies `location.hash` into a `?__p=` query sends the
//! key to the host. The secret stays in the URL *fragment*, which browsers
//! never transmit. The legacy `{base}/connect#k=` form is still accepted.
//!
//! This module owns:
//! * [`connect_url`]: the one place a sign-in link is built (recovery sheet,
//!   device tear-off).
//! * [`take_pending_key`]: the one-shot hand-off from the early capture
//!   script in `index.html` (which strips the fragment from the address bar
//!   before the WASM bundle has even downloaded), with a WASM fallback that
//!   reads and strips `location.hash` itself.
//! * [`stash`] / [`take_stashed`]: a thread-local slot that carries the key
//!   from `App()` (which runs before the router) to the connect page.
//! * [`parse_sheet_payload`]: strict validation of a payload decoded by the
//!   in-app scanner.
//!
//! No function here logs a key or a payload. Keys travel as
//! [`Zeroizing<String>`] so the heap copy is wiped on drop.

use std::cell::RefCell;

use zeroize::Zeroizing;

/// Name of the one-shot getter the `index.html` capture script installs on
/// `window`. It returns the captured key once, then deletes itself.
const CAPTURE_GETTER: &str = "__nbbsTakeConnectKey";

/// Fragment prefix that marks a sign-in key.
const FRAGMENT_PREFIX: &str = "#k=";

/// Bech32 data alphabet (BIP-173), used for the cheap shape check.
const BECH32_CHARSET: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// Build the root-form sign-in link `{origin}{base}/#k={nsec}`.
///
/// `base` is the forum mount path (`""` or `/community`); a trailing slash is
/// tolerated. Pure: callers pass the live origin or a configured one.
pub fn connect_url(origin: &str, base: &str, nsec: &str) -> String {
    format!(
        "{}{}/{FRAGMENT_PREFIX}{nsec}",
        origin.trim_end_matches('/'),
        base.trim_end_matches('/')
    )
}

/// Cheap shape check for a key carried in a link: `nsec1` + 58 bech32 chars,
/// or 64 lowercase hex. The full checksum + curve validation happens at
/// import, in `AuthStore::login_with_local_key`. Must match the regex in
/// `index.html` (`tests::capture_regex_matches_index_html`).
pub fn is_wellformed_link_key(key: &str) -> bool {
    if let Some(rest) = key.strip_prefix("nsec1") {
        rest.len() == 58 && rest.chars().all(|c| BECH32_CHARSET.contains(c))
    } else {
        key.len() == 64
            && key
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }
}

/// A valid nsec: shape plus bech32 checksum plus secp256k1 range, via the
/// kit's NIP-19 decoder (never hand-rolled).
fn is_valid_nsec(key: &str) -> bool {
    key.starts_with("nsec1")
        && is_wellformed_link_key(key)
        && nostr_bbs_core::decode_nsec(key).map(Zeroizing::new).is_ok()
}

/// Extract the key from a raw fragment string: `#k=<key>` (canonical) or
/// the legacy bare `#<key>`. `None` when it is not a well-formed key.
pub fn key_from_fragment(hash: &str) -> Option<Zeroizing<String>> {
    let rest = hash.strip_prefix('#')?;
    let key = rest.strip_prefix("k=").unwrap_or(rest);
    is_wellformed_link_key(key).then(|| Zeroizing::new(key.to_string()))
}

/// Whether a fragment must be scrubbed from the address bar: anything that
/// looks like it might carry a key, well-formed or not. Mirrors the test in
/// the `index.html` capture script.
pub fn fragment_needs_scrub(hash: &str) -> bool {
    hash.starts_with(FRAGMENT_PREFIX) || hash.contains("nsec1")
}

/// Whether `pathname` is a page allowed to import a sign-in key: the forum
/// root or `/connect` under `base`. A key fragment on any other path (say, a
/// thread link with an attacker's `#k=` appended) is scrubbed and discarded,
/// never imported.
pub fn is_import_path(pathname: &str, base: &str) -> bool {
    let base = base.trim_end_matches('/');
    let Some(rest) = pathname.strip_prefix(base) else {
        return false;
    };
    matches!(rest, "" | "/" | "/connect" | "/connect/")
}

/// Why a scanned payload was refused. Messages are user-facing (UK English)
/// and never echo the payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayloadError {
    /// A link, but not to this forum (other origin, other base, other path).
    OtherSite,
    /// Not a link and not a recovery key.
    NotSignInCode,
    /// The right shape but the key itself is invalid (checksum / range).
    BadKey,
}

impl std::fmt::Display for PayloadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::OtherSite => "That code links to a different site, so it wasn't used. Scan the code on your sign-in sheet for this forum.",
            Self::NotSignInCode => "That isn't a sign-in code. Scan the large code on your sign-in sheet.",
            Self::BadKey => "That code looks damaged. Try again, or type the key from the manual recovery box.",
        })
    }
}

/// Validate a payload decoded from a sheet QR and return its key.
///
/// Accepted, and nothing else:
/// * `{origin}{base}/#k=<key>` (current sheets),
/// * `{origin}{base}#k=<key>` and `{origin}{base}/connect#k=<key>` (legacy),
/// * a bare `nsec1…` (the older sheet's separate recovery-key QR).
///
/// `<key>` in a link is an nsec or 64-hex; a bare payload must be an nsec (a
/// bare 64-hex string is just as likely an event id). Links to any other
/// origin, base or path are refused and never followed.
pub fn parse_sheet_payload(
    payload: &str,
    origin: &str,
    base: &str,
) -> Result<Zeroizing<String>, PayloadError> {
    let payload = payload.trim();
    if payload.starts_with("nsec1") {
        return if is_valid_nsec(payload) {
            Ok(Zeroizing::new(payload.to_string()))
        } else {
            Err(PayloadError::BadKey)
        };
    }
    let lower = payload.to_ascii_lowercase();
    if !(lower.starts_with("https://") || lower.starts_with("http://")) {
        return Err(PayloadError::NotSignInCode);
    }
    let prefix = format!(
        "{}{}",
        origin.trim_end_matches('/'),
        base.trim_end_matches('/')
    );
    // Case-insensitive on scheme + host + base only; the key keeps its case.
    if lower.len() < prefix.len() || !lower[..prefix.len()].eq_ignore_ascii_case(&prefix) {
        return Err(PayloadError::OtherSite);
    }
    let rest = &payload[prefix.len()..];
    let frag = ["/#", "#", "/connect#"]
        .iter()
        .find_map(|p| rest.strip_prefix(p).map(|r| format!("#{r}")))
        .ok_or(PayloadError::OtherSite)?;
    let frag = Zeroizing::new(frag);
    let key = key_from_fragment(&frag).ok_or(PayloadError::BadKey)?;
    if key.starts_with("nsec1") && !is_valid_nsec(&key) {
        return Err(PayloadError::BadKey);
    }
    Ok(key)
}

/// The x-only hex pubkey a link key (nsec or 64-hex) signs as, without
/// importing it. Used to compare against identities already on the device
/// before anything is replaced. `None` for an invalid key.
pub fn pubkey_for_key(key: &str) -> Option<String> {
    let hex_sk = if key.starts_with("nsec1") {
        Zeroizing::new(nostr_bbs_core::decode_nsec(key).ok()?)
    } else {
        Zeroizing::new(key.to_string())
    };
    let bytes = Zeroizing::new(hex::decode(hex_sk.as_str()).ok()?);
    let arr: Zeroizing<[u8; 32]> = Zeroizing::new(bytes.as_slice().try_into().ok()?);
    nostr_bbs_core::keys::pubkey_hex(&arr).ok()
}

thread_local! {
    static PENDING: RefCell<Option<Zeroizing<String>>> = const { RefCell::new(None) };
}

/// Put a captured key in the one-shot slot (replacing any earlier one).
pub fn stash(key: Zeroizing<String>) {
    PENDING.with(|p| *p.borrow_mut() = Some(key));
}

/// Take the key out of the one-shot slot. Second and later calls get `None`.
pub fn take_stashed() -> Option<Zeroizing<String>> {
    PENDING.with(|p| p.borrow_mut().take())
}

/// Take a sign-in key delivered by the current page load, if any.
///
/// 1. The `index.html` capture script's one-shot getter. The script has
///    already scrubbed the fragment from the address bar while the bundle
///    was downloading, and hands over the raw fragment for validation here.
/// 2. Fallback for a deployment that replaced `index.html`: read
///    `location.hash` and scrub it with `replaceState` straight away when it
///    might carry a key ([`fragment_needs_scrub`]).
///
/// The key is returned only when it is well-formed AND the page is an
/// import path ([`is_import_path`] under `base`); otherwise it is dropped
/// (and zeroised) after the scrub.
pub fn take_pending_key(base: &str) -> Option<Zeroizing<String>> {
    let window = web_sys::window()?;
    let raw = match take_from_capture_getter(&window) {
        Some(raw) => raw,
        None => {
            let hash = Zeroizing::new(window.location().hash().ok()?);
            if !fragment_needs_scrub(&hash) {
                return None;
            }
            strip_fragment(&window);
            hash
        }
    };
    let path = window.location().pathname().ok()?;
    if !is_import_path(&path, base) {
        return None;
    }
    key_from_fragment(&raw)
}

fn take_from_capture_getter(window: &web_sys::Window) -> Option<Zeroizing<String>> {
    use wasm_bindgen::JsCast;
    let getter = js_sys::Reflect::get(window, &CAPTURE_GETTER.into()).ok()?;
    let func = getter.dyn_into::<js_sys::Function>().ok()?;
    let value = func.call0(window).ok()?;
    Some(Zeroizing::new(value.as_string()?))
}

/// Rewrite the current history entry to the same path and query without the
/// fragment. Uses `replaceState`, so no new entry holds the key.
fn strip_fragment(window: &web_sys::Window) {
    let loc = window.location();
    let clean = format!(
        "{}{}",
        loc.pathname().unwrap_or_default(),
        loc.search().unwrap_or_default()
    );
    if let Ok(history) = window.history() {
        let _ = history.replace_state_with_url(&wasm_bindgen::JsValue::NULL, "", Some(&clean));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Synthetic test key (never used anywhere real): secret = 0x01 * 32.
    fn synthetic_nsec() -> String {
        nostr_bbs_core::encode_nsec(&"01".repeat(32)).unwrap()
    }

    const ORIGIN: &str = "https://forum.example";
    const BASE: &str = "/community";

    #[test]
    fn connect_url_root_form() {
        let n = synthetic_nsec();
        assert_eq!(
            connect_url(ORIGIN, BASE, &n),
            format!("https://forum.example/community/#k={n}")
        );
        assert_eq!(
            connect_url("https://forum.example/", "", &n),
            format!("https://forum.example/#k={n}")
        );
        assert_eq!(
            connect_url(ORIGIN, "/community/", &n),
            format!("https://forum.example/community/#k={n}")
        );
    }

    #[test]
    fn link_key_shapes() {
        let n = synthetic_nsec();
        assert!(is_wellformed_link_key(&n));
        assert!(is_wellformed_link_key(&"ab".repeat(32)));
        assert!(!is_wellformed_link_key(&"AB".repeat(32)));
        assert!(!is_wellformed_link_key(&n[..62]));
        assert!(!is_wellformed_link_key(&n.to_uppercase()));
        assert!(!is_wellformed_link_key(&format!("{n}x")));
        assert!(!is_wellformed_link_key("npub1qqqq"));
        assert!(!is_wellformed_link_key(""));
        // 'b', 'i', 'o' and '1' are not in the bech32 data alphabet.
        let bad = format!("nsec1{}", "b".repeat(58));
        assert!(!is_wellformed_link_key(&bad));
    }

    #[test]
    fn fragment_extraction() {
        let n = synthetic_nsec();
        assert_eq!(
            key_from_fragment(&format!("#k={n}"))
                .as_deref()
                .map(String::as_str),
            Some(n.as_str())
        );
        // Legacy bare form, as the old /connect page accepted.
        assert_eq!(
            key_from_fragment(&format!("#{n}"))
                .as_deref()
                .map(String::as_str),
            Some(n.as_str())
        );
        assert!(key_from_fragment(&format!("k={n}")).is_none());
        assert!(key_from_fragment(&format!("#K={n}")).is_none());
        assert!(key_from_fragment("#k=").is_none());
        assert!(key_from_fragment("#section-2").is_none());
        assert!(key_from_fragment(&format!("#k={n}&x=1")).is_none());
    }

    #[test]
    fn accepts_this_forums_links_and_bare_nsec() {
        let n = synthetic_nsec();
        for p in [
            format!("{ORIGIN}{BASE}/#k={n}"),
            format!("{ORIGIN}{BASE}#k={n}"),
            format!("{ORIGIN}{BASE}/connect#k={n}"),
            format!("HTTPS://FORUM.EXAMPLE{BASE}/#k={n}"),
            format!("  {ORIGIN}{BASE}/#k={n}\n"),
            n.clone(),
        ] {
            let got = parse_sheet_payload(&p, ORIGIN, BASE).expect("accepted");
            assert_eq!(got.as_str(), n);
        }
        let hex = "02".repeat(32);
        assert_eq!(
            parse_sheet_payload(&format!("{ORIGIN}{BASE}/#k={hex}"), ORIGIN, BASE)
                .unwrap()
                .as_str(),
            hex
        );
        // Root-mounted forum.
        assert!(parse_sheet_payload(&format!("{ORIGIN}/#k={n}"), ORIGIN, "").is_ok());
    }

    #[test]
    fn refuses_everything_else() {
        let n = synthetic_nsec();
        let other = [
            format!("https://evil.example{BASE}/#k={n}"),
            format!("https://forum.example.evil.example{BASE}/#k={n}"),
            format!("http://forum.example{BASE}/#k={n}"),
            format!("{ORIGIN}/other/#k={n}"),
            format!("{ORIGIN}{BASE}/forums#k={n}"),
            format!("{ORIGIN}{BASE}/?k={n}"),
            format!("{ORIGIN}{BASE}x/#k={n}"),
        ];
        for p in other {
            assert_eq!(
                parse_sheet_payload(&p, ORIGIN, BASE),
                Err(PayloadError::OtherSite),
                "{p}"
            );
        }
        assert_eq!(
            parse_sheet_payload("hello", ORIGIN, BASE),
            Err(PayloadError::NotSignInCode)
        );
        assert_eq!(
            parse_sheet_payload(&"03".repeat(32), ORIGIN, BASE),
            Err(PayloadError::NotSignInCode)
        );
        assert_eq!(
            parse_sheet_payload("javascript:alert(1)", ORIGIN, BASE),
            Err(PayloadError::NotSignInCode)
        );
        // Corrupt checksum: flip the last character.
        let mut bad = n.clone();
        let last = bad.pop().unwrap();
        bad.push(if last == 'q' { 'p' } else { 'q' });
        assert_eq!(
            parse_sheet_payload(&bad, ORIGIN, BASE),
            Err(PayloadError::BadKey)
        );
        assert_eq!(
            parse_sheet_payload(&format!("{ORIGIN}{BASE}/#k={bad}"), ORIGIN, BASE),
            Err(PayloadError::BadKey)
        );
        assert_eq!(
            parse_sheet_payload(&format!("{ORIGIN}{BASE}/#k=short"), ORIGIN, BASE),
            Err(PayloadError::BadKey)
        );
    }

    #[test]
    fn error_messages_never_echo_payload() {
        for e in [
            PayloadError::OtherSite,
            PayloadError::NotSignInCode,
            PayloadError::BadKey,
        ] {
            let s = e.to_string();
            assert!(!s.contains("nsec1") && !s.contains("#k="));
        }
    }

    #[test]
    fn pubkey_for_nsec_and_hex_agree() {
        let n = synthetic_nsec();
        let from_nsec = pubkey_for_key(&n).expect("nsec");
        let from_hex = pubkey_for_key(&"01".repeat(32)).expect("hex");
        assert_eq!(from_nsec, from_hex);
        assert_eq!(from_nsec.len(), 64);
        assert!(pubkey_for_key("nsec1garbage").is_none());
        assert!(
            pubkey_for_key(&"00".repeat(32)).is_none(),
            "zero is not a valid secret"
        );
    }

    #[test]
    fn slot_is_one_shot() {
        assert!(take_stashed().is_none());
        stash(Zeroizing::new("x".into()));
        assert_eq!(take_stashed().as_deref().map(String::as_str), Some("x"));
        assert!(take_stashed().is_none());
    }

    #[test]
    fn scrub_rule() {
        let n = synthetic_nsec();
        assert!(fragment_needs_scrub(&format!("#k={n}")));
        assert!(fragment_needs_scrub("#k=garbage"));
        assert!(fragment_needs_scrub(&format!("#{n}")));
        assert!(fragment_needs_scrub(&format!("#x={n}&y")));
        assert!(!fragment_needs_scrub("#section-2"));
        assert!(!fragment_needs_scrub(""));
    }

    #[test]
    fn import_paths_only_root_and_connect() {
        for (p, b) in [
            ("/community", "/community"),
            ("/community/", "/community"),
            ("/community/connect", "/community"),
            ("/community/connect/", "/community/"),
            ("/", ""),
            ("/connect", ""),
        ] {
            assert!(is_import_path(p, b), "{p} under {b:?}");
        }
        for (p, b) in [
            ("/community/forums/x/y", "/community"),
            ("/community/connectx", "/community"),
            ("/community/connect/x", "/community"),
            ("/communityx/", "/community"),
            ("/other/", "/community"),
            ("/forums", ""),
            ("/minimoonoir", ""),
        ] {
            assert!(!is_import_path(p, b), "{p} under {b:?}");
        }
    }

    /// The index.html capture script must scrub on the same rule as
    /// `fragment_needs_scrub` and install the getter this module reads.
    #[test]
    fn index_html_capture_script_in_sync() {
        let html = include_str!("../../index.html");
        assert!(html.contains("h.slice(0, 3) === '#k=' || h.indexOf('nsec1') !== -1"));
        assert!(html.contains(&format!("'{CAPTURE_GETTER}'")));
        assert!(html.contains("Object.defineProperty(window"));
        // The capture script runs after the __p pickup restores a fragment.
        let pickup = html.find("q.get('__p')").expect("pickup script");
        let capture = html.find(CAPTURE_GETTER).expect("capture script");
        assert!(pickup < capture);
    }
}
