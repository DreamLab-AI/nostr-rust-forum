//! Onboarding modal — post-first-login profile capture.
//!
//! ## Current flow (operator simplification, 2026-06)
//!
//! The modal no longer asks the user to *claim a username* / mint a
//! `username@host` NIP-05 handle — the operator found that flow confusing.
//! It now captures two plain fields after first login:
//!
//! - **Display name** (public) — published to the user's kind-0 profile as
//!   both `name` and `display_name`.
//! - **Real name** (private, admin-only) — POSTed NIP-98-authed to
//!   `POST /api/profile/real-name` (handler `handle_set_own_real_name`). Never
//!   published to a relay; only admins can read it.
//!
//! A short line points the user at **Settings** to download their keys +
//! identity data (the existing recovery / `/connect` device-onboarding surface
//! that produces the printable identity sheet — see
//! `components/recovery_sheet.rs`). This modal does NOT reimplement that PDF;
//! it only links to it.
//!
//! ## Dormant (still compiled & exported) — DO NOT remove
//!
//! The username-claim / NIP-05 helpers below
//! (`claimed_username_cached`, `cache_claimed_username`, `nip05_for`,
//! `username_from_nip05`, `release_username`, the `ClaimedUsername` context,
//! `use_claimed_username`, `NIP05_HOST`) are retained because other modules
//! (`app.rs` kind-0 auto-whitelist, `pages/settings.rs`) still import and call
//! them. They are NOT exercised by the modal UI any more, but the kind-0
//! `nip05` probe-suppression still consumes them so a user who claimed a
//! handle on a previous build is not re-prompted.
//!
//! ## Auto-open gating (preserved)
//!
//! The component self-gates via localStorage flags keyed on the first 8 chars
//! of the pubkey:
//!
//! - `nostr_bbs_username_claimed_{pubkey8}` — a legacy/remote handle exists;
//!   never re-prompt (still honoured for back-compat)
//! - `nostr_bbs_username_skipped_until_{pubkey8}` — UNIX-ms timestamp; suppress
//!   until it elapses
//! - `nostrbbs:onboarded` — legacy v1 flag; once set the modal never
//!   auto-pops. A successful profile submit (or "I'll do this later") sets it.
//!
//! All network errors are surfaced as a graceful inline error string so the
//! page never crashes when the worker has not yet been deployed.

use leptos::prelude::*;

use crate::auth::nip98::fetch_with_nip98_post_signer;
use crate::auth::use_auth;
use crate::utils::relay_url::auth_api_base;

// -- localStorage helpers -----------------------------------------------------

/// Legacy v1 onboarding flag — also used as the "onboarding complete" marker
/// so the modal stops auto-popping once the user has submitted (or deferred).
const LEGACY_ONBOARDED_KEY: &str = "nostrbbs:onboarded";
/// Suppress duration when user clicks "I'll do this later" (7 days, ms).
const SKIP_DURATION_MS: f64 = 7.0 * 24.0 * 60.0 * 60.0 * 1000.0;
/// Maximum real-name length (mirrors the auth-worker `REAL_NAME_MAX_LEN` rule;
/// the server is authoritative — this is only a friendly client-side cap).
const REAL_NAME_MAX_LEN: usize = 100;
/// Maximum display-name length (kind-0 `name`/`display_name`).
const DISPLAY_NAME_MAX_LEN: usize = 50;
/// NIP-05 host that backs legacy claimed usernames. Baked at build time from
/// `NOSTR_BBS_NIP05_DOMAIN`; placeholder only for un-configured local builds.
/// Retained for the dormant `nip05_for` / `username_from_nip05` helpers and the
/// kind-0 probe — never surfaced in the modal UI any more.
const NIP05_HOST: &str = match option_env!("NOSTR_BBS_NIP05_DOMAIN") {
    Some(d) => d,
    None => "example.test",
};

fn local_storage() -> Option<web_sys::Storage> {
    web_sys::window().and_then(|w| w.local_storage().ok().flatten())
}

fn pubkey8(pubkey: &str) -> String {
    pubkey.chars().take(8).collect()
}

fn claimed_key(pubkey: &str) -> String {
    format!("nostr_bbs_username_claimed_{}", pubkey8(pubkey))
}

fn skipped_key(pubkey: &str) -> String {
    format!("nostr_bbs_username_skipped_until_{}", pubkey8(pubkey))
}

/// Has the user already claimed a legacy handle (locally cached)?
fn has_claimed_locally(pubkey: &str) -> bool {
    claimed_username_cached(pubkey).is_some()
}

/// Read the locally-cached claimed username (the legacy claim flow stored the
/// username string as the flag value).
///
/// Dormant in the modal UI but still consumed by `app.rs` (kind-0
/// auto-whitelist) and `pages/settings.rs`.
pub fn claimed_username_cached(pubkey: &str) -> Option<String> {
    local_storage()
        .and_then(|s| s.get_item(&claimed_key(pubkey)).ok().flatten())
        .filter(|v| !v.is_empty())
}

/// Mark the username as claimed locally so we never re-prompt this user.
/// Retained for the dormant `cache_claimed_username` write-through.
fn mark_claimed_locally(pubkey: &str, username: &str) {
    if let Some(s) = local_storage() {
        let _ = s.set_item(&claimed_key(pubkey), username);
    }
}

/// Clear the local claim cache (used on `release_username`).
fn clear_claimed_locally(pubkey: &str) {
    if let Some(s) = local_storage() {
        let _ = s.remove_item(&claimed_key(pubkey));
    }
}

/// Set the device-wide "onboarding complete" marker so the modal never
/// auto-pops again for any pubkey on this device.
fn mark_onboarded() {
    if let Some(s) = local_storage() {
        let _ = s.set_item(LEGACY_ONBOARDED_KEY, "1");
    }
}

/// Read the "skip until" timestamp from localStorage, returning `true`
/// if the user has skipped recently and the suppression has not expired.
fn is_skipping(pubkey: &str) -> bool {
    let Some(s) = local_storage() else {
        return false;
    };
    let Some(raw) = s.get_item(&skipped_key(pubkey)).ok().flatten() else {
        return false;
    };
    raw.parse::<f64>()
        .map(|until| js_sys::Date::now() < until)
        .unwrap_or(false)
}

fn set_skipped(pubkey: &str) {
    if let Some(s) = local_storage() {
        let until = js_sys::Date::now() + SKIP_DURATION_MS;
        let _ = s.set_item(&skipped_key(pubkey), &format!("{:.0}", until));
        // ALSO set the legacy "onboarded" flag so the modal stops auto-popping
        // for any pubkey on this device. Clicking "I'll do this later" should
        // mean "stop pestering me", not "ask again in 7 days". Users can still
        // edit their profile from Settings any time.
        let _ = s.set_item(LEGACY_ONBOARDED_KEY, "1");
    }
}

fn clear_skipped(pubkey: &str) {
    if let Some(s) = local_storage() {
        let _ = s.remove_item(&skipped_key(pubkey));
    }
}

// -- Dormant username/NIP-05 helpers (still compiled & exported) --------------

/// Client-side regex check matching the auth-worker rule
/// `^[a-z0-9][a-z0-9_-]{2,29}$`. Length 3..=30, lowercase alnum + `_` + `-`,
/// no leading hyphen/underscore.
///
/// Dormant: kept for back-compat and unit-test coverage of the legacy rule;
/// the modal no longer prompts for a username.
#[allow(dead_code)]
fn is_valid_format(name: &str) -> bool {
    let len = name.chars().count();
    if !(3..=30).contains(&len) {
        return false;
    }
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

/// Minimal URI-encoder for query-string values (RFC 3986 unreserved set).
/// Dormant; retained for unit-test coverage and any future query use.
#[allow(dead_code)]
fn urlencoding_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

// -- Component context types --------------------------------------------------

/// Optional pre-fill — used by the Settings "Edit profile" flow.
///
/// `initial` carries the current display name to seed the field when the modal
/// is force-opened from Settings.
#[derive(Clone, Copy, Debug)]
pub struct OnboardingPrefill {
    pub initial: RwSignal<Option<String>>,
    pub force_open: RwSignal<bool>,
}

/// Reactive holder for the user's legacy CLAIMED username / NIP-05 handle.
///
/// Dormant in the modal but still provided and read by `pages/settings.rs`.
/// Deliberately separate from `AuthState::nickname` (the kind-0 display name):
/// a profile nickname must never be presented as a claimed handle.
#[derive(Clone, Copy, Debug)]
pub struct ClaimedUsername(pub RwSignal<Option<String>>);

/// Provide an `OnboardingPrefill` context so other pages (Settings) can
/// open the modal pre-filled, plus the shared (dormant) `ClaimedUsername`
/// signal.
pub fn provide_onboarding_prefill() {
    provide_context(OnboardingPrefill {
        initial: RwSignal::new(None),
        force_open: RwSignal::new(false),
    });
    provide_context(ClaimedUsername(RwSignal::new(None)));
}

/// Read the shared claimed-username signal (None outside the app tree).
/// Dormant in the modal; consumed by Settings.
pub fn use_claimed_username() -> Option<ClaimedUsername> {
    use_context::<ClaimedUsername>()
}

/// Write-through to the localStorage claim cache (no context access, safe
/// to call from relay callbacks). Dormant in the modal; called by `app.rs`.
pub fn cache_claimed_username(pubkey: &str, username: &str) {
    mark_claimed_locally(pubkey, username);
}

/// Format the NIP-05 identifier for a claimed username.
/// Dormant in the modal; consumed by `app.rs` kind-0 auto-whitelist.
pub fn nip05_for(username: &str) -> String {
    format!("{}@{}", username, NIP05_HOST)
}

/// Extract `name` from a kind-0 `nip05` value when it belongs to our host.
/// Dormant in the modal UI; still used by the kind-0 probe below and Settings.
pub fn username_from_nip05(nip05: &str) -> Option<String> {
    nip05
        .strip_suffix(&format!("@{}", NIP05_HOST))
        .filter(|n| !n.is_empty())
        .map(|n| n.to_string())
}

// -- Removed: dead OnboardingModal component ----------------------------------
//
// The onboarding modal (display-name capture) and its Settings "Edit profile"
// entry point were never mounted anywhere in the app tree, so the modal UI,
// its auto-open Effect, the `open_onboarding_with_prefill` opener, and the
// `probe_remote_claim` relay probe that only fed that Effect were all dead
// code. They have been removed (#wire-settings).
//
// The username/NIP-05 helpers and shared context above
// (`provide_onboarding_prefill`, `use_claimed_username`,
// `claimed_username_cached`, `cache_claimed_username`, `nip05_for`,
// `username_from_nip05`, `release_username`, `ClaimedUsername`,
// `OnboardingPrefill`) are RETAINED — `app.rs` (kind-0 auto-whitelist) and
// `pages/settings.rs` still import and call them.

#[cfg(any())]
fn _removed_onboarding_modal() {}

/// Public helper used by the Settings "Release username" button.
///
/// Dormant relative to the onboarding modal but still called by
/// `pages/settings.rs`. Sends a NIP-98 authed `POST /api/username/release`
/// with no body. On success the local claim flag is cleared and the shared
/// `ClaimedUsername` signal is reset. Errors are surfaced via the `Result`.
pub async fn release_username() -> Result<(), String> {
    let auth = use_auth();
    let pubkey = auth
        .pubkey()
        .get_untracked()
        .ok_or_else(|| "Not authenticated".to_string())?;
    // Route through the Signer trait so NIP-07 / hardware-bunker backends can
    // release. PRF-derived keys still work transparently.
    let signer = auth
        .get_signer()
        .ok_or_else(|| "No signer available — please sign in again.".to_string())?;

    let url = format!("{}/api/username/release", auth_api_base());
    let body = "{}".to_string();
    // Capture the claimed-username signal before the await so the context
    // lookup happens while the reactive owner is still current.
    let claimed_sig = use_claimed_username();
    let result = fetch_with_nip98_post_signer(&url, &body, signer.as_ref()).await;
    match result {
        Ok(_) => {
            clear_claimed_locally(&pubkey);
            // Clear the claimed handle only — the kind-0 display name
            // (nickname/avatar) is a separate concern and stays intact.
            if let Some(claimed) = claimed_sig {
                claimed.0.set(None);
            }
            Ok(())
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("HTTP") {
                Err(format!("Server rejected the request ({})", msg))
            } else {
                Err(
                    "Username service is temporarily unavailable. Please try again later."
                        .to_string(),
                )
            }
        }
    }
}

// -- Icons --------------------------------------------------------------------

fn handle_icon() -> impl IntoView {
    view! {
        <svg class="w-6 h-6 text-amber-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
            <circle cx="12" cy="12" r="9" stroke-linecap="round" stroke-linejoin="round"/>
            <path d="M16 9a4 4 0 11-4-4M16 9v3a2 2 0 002 2"
                stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
    }
}

// -- Tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_format_basic() {
        assert!(is_valid_format("alice"));
        assert!(is_valid_format("alice_99"));
        assert!(is_valid_format("a-b-c"));
        assert!(is_valid_format("0xb33f"));
        assert!(is_valid_format("abc")); // min length 3
        assert!(is_valid_format(&"a".repeat(30))); // max length 30
    }

    #[test]
    fn invalid_format_too_short_or_long() {
        assert!(!is_valid_format(""));
        assert!(!is_valid_format("ab"));
        assert!(!is_valid_format(&"a".repeat(31)));
    }

    #[test]
    fn invalid_format_uppercase() {
        assert!(!is_valid_format("Alice"));
        assert!(!is_valid_format("ALICE"));
    }

    #[test]
    fn invalid_format_leading_special() {
        assert!(!is_valid_format("-alice"));
        assert!(!is_valid_format("_alice"));
    }

    #[test]
    fn invalid_format_disallowed_chars() {
        assert!(!is_valid_format("alice!"));
        assert!(!is_valid_format("alice.bob"));
        assert!(!is_valid_format("alice bob"));
        assert!(!is_valid_format("alice@bob"));
    }

    #[test]
    fn url_encode_passthrough() {
        assert_eq!(urlencoding_encode("alice"), "alice");
        assert_eq!(urlencoding_encode("a_b-c.d"), "a_b-c.d");
    }

    #[test]
    fn url_encode_special() {
        assert_eq!(urlencoding_encode("a b"), "a%20b");
        assert_eq!(urlencoding_encode("a+b"), "a%2Bb");
        assert_eq!(urlencoding_encode("a/b"), "a%2Fb");
    }

    #[test]
    fn pubkey8_truncates() {
        assert_eq!(pubkey8("0123456789abcdef"), "01234567");
        assert_eq!(pubkey8("abc"), "abc");
    }

    #[test]
    fn claimed_key_format() {
        assert_eq!(
            claimed_key("0123456789abcdef"),
            "nostr_bbs_username_claimed_01234567"
        );
    }

    #[test]
    fn skipped_key_format() {
        assert_eq!(
            skipped_key("0123456789abcdef"),
            "nostr_bbs_username_skipped_until_01234567"
        );
    }

    #[test]
    fn nip05_for_uses_host() {
        // Dormant helper still produces a host-qualified handle.
        assert_eq!(nip05_for("alice"), format!("alice@{}", NIP05_HOST));
    }

    #[test]
    fn username_from_nip05_roundtrip() {
        let n = nip05_for("bob");
        assert_eq!(username_from_nip05(&n), Some("bob".to_string()));
        assert_eq!(username_from_nip05("carol@other.example"), None);
    }
}
