//! NIP-42 AUTH: pure verification + gating logic for the relay Durable Object.
//!
//! PRD-010 G4 promotes NIP-42 AUTH from an *advertised-but-unenforced* handshake
//! to the **universal write gate**:
//!
//!   - every EVENT (write) path requires an authenticated session;
//!   - reads of the public kinds (0, 1, 3, 7, and most of 30000-39999) stay
//!     open to everyone, including unauthenticated sockets;
//!   - reads of the protected set `{4, 13, 14, 1059, 30910-30916}` require AUTH
//!     (encrypted / sealed DMs and moderation events — the "except moderation"
//!     carve-out from the otherwise-open 30000-39999 range).
//!
//! The pre-existing pubkey **allowlist** does not disappear: it moves from being
//! the *authentication* mechanism (a signed event's pubkey happening to be
//! whitelisted) to being the *authorisation* layer applied AFTER a session has
//! authenticated. A member who authenticates but is not on the allowlist is
//! rejected with NIP-42's `restricted:` reason, distinct from `auth-required:`.
//!
//! Every decision here is a PURE function of its inputs (no `Env`, `WebSocket`,
//! or DO storage), mirroring [`super::session::recovered_challenge`], so the
//! whole state machine is unit-testable without a Workers runtime. The DO
//! handlers (`handle_auth`, `handle_event`, `handle_req`, `handle_count`) call
//! these and perform the side effects (session mutation, wire frames, D1).

use super::filter::{self, NostrFilter};
use nostr_bbs_core::event::NostrEvent;

/// Kind number of the NIP-42 AUTH response event (an ephemeral kind-22242).
pub const KIND_AUTH: u64 = 22242;

/// Maximum clock skew, in seconds, permitted between the relay and a client's
/// AUTH event `created_at`. NIP-42 recommends roughly ten minutes; a wider
/// window would enlarge the replay surface for a captured (but still
/// challenge-bound) AUTH event.
pub const AUTH_MAX_SKEW_SECS: u64 = 600;

/// Event kinds whose READS require an authenticated session (PRD-010 G4).
///
/// Public kinds (metadata 0, notes 1, contacts 3, reactions 7, and the bulk of
/// the 30000-39999 addressable range) stay readable by anyone. This protected
/// set is the exception: encrypted DMs (4), seals (13), private DMs (14), gift
/// wraps (1059), and the moderation events (30910-30916) — the "except
/// moderation" carve-out from the open addressable range.
pub const PROTECTED_READ_KINDS: &[u64] = &[
    4, 13, 14, 1059, 30910, 30911, 30912, 30913, 30914, 30915, 30916,
];

/// Whether reads of `kind` require an authenticated session (PRD-010 G4).
pub fn is_protected_read_kind(kind: u64) -> bool {
    PROTECTED_READ_KINDS.contains(&kind)
}

/// The protected kinds that are *correspondence*: readable only by the parties
/// to them, never merely by anyone who has authenticated.
///
/// The distinction matters because the two halves of [`PROTECTED_READ_KINDS`]
/// have different rules. A moderation event (30910-30916) is protected from
/// anonymous readers but is legitimately readable by the membership. A DM is
/// not: authenticating as *someone* does not make you a party to *this*
/// conversation.
pub fn is_correspondence_kind(kind: u64) -> bool {
    matches!(kind, 4 | 13 | 14 | 1059)
}

/// Whether a protected-kind event may be delivered to this viewer.
///
/// This is the **per-event** gate, deliberately duplicating policy the
/// filter-level gates already express, because those gates decide from what a
/// filter *names*: `protected_read_blocked` and `gate_kind_1059_filters` both
/// inspect `filter.kinds`, and a Nostr filter that omits `kinds` matches every
/// kind while naming none. A `REQ ["sub", {}]` therefore sailed past both and
/// `query_events` returned sealed DMs to anyone (deepsec-gate, auth-bypass,
/// HIGH). A per-event decision cannot be dodged by declining to mention the
/// kind, because by then the kind is a property of the event in hand.
///
/// - **Correspondence** (4, 13, 14, 1059): the viewer must be authenticated and
///   be either the author or a `p`-tagged recipient. Mode-independent, matching
///   the existing design note that "DM privacy never depends on `AUTH_MODE`".
///   Admin is **not** an exemption: an operator role is not a party to someone
///   else's conversation.
/// - **Moderation** (30910-30916): the viewer must be authenticated when the
///   relay is in `Nip42` mode, exactly mirroring `protected_read_blocked`, so
///   legacy `Allowlist` deployments keep their current read behaviour.
/// - Everything else is not protected and passes through untouched.
pub fn protected_read_permitted(
    kind: u64,
    author: &str,
    recipients: &[String],
    session_pubkey: Option<&str>,
    mode: AuthMode,
) -> bool {
    if !is_protected_read_kind(kind) {
        return true;
    }
    if is_correspondence_kind(kind) {
        let Some(viewer) = session_pubkey else {
            return false;
        };
        return viewer.eq_ignore_ascii_case(author)
            || recipients.iter().any(|r| r.eq_ignore_ascii_case(viewer));
    }
    // Moderation kinds: authentication is the whole rule, and only in nip42 mode.
    mode != AuthMode::Nip42 || session_pubkey.is_some()
}

/// AUTH enforcement mode — the operator escape hatch (config `AUTH_MODE`),
/// mirroring the repo's other env-driven toggles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuthMode {
    /// Legacy behaviour: writes are gated on the pubkey allowlist alone and no
    /// NIP-42 AUTH round-trip is forced. Recoverable via `AUTH_MODE=allowlist`.
    Allowlist,
    /// PRD-010 G4 (the secure default): NIP-42 AUTH is the universal write gate
    /// and the protected-kind read gate; the allowlist becomes authorisation.
    #[default]
    Nip42,
}

/// Parse the `AUTH_MODE` config value (case-insensitive, whitespace-tolerant).
///
/// Anything other than an explicit `allowlist` resolves to the secure default
/// (`nip42`), so a typo or an empty value fails *closed* (enforced), never open.
pub fn parse_auth_mode(raw: Option<&str>) -> AuthMode {
    match raw.map(|s| s.trim().to_ascii_lowercase()).as_deref() {
        Some("allowlist") => AuthMode::Allowlist,
        _ => AuthMode::Nip42,
    }
}

/// The outcome of verifying a client's kind-22242 AUTH event.
#[derive(Debug, PartialEq, Eq)]
pub enum AuthVerdict {
    /// AUTH succeeded; carries the now-authenticated pubkey (hex).
    Ok(String),
    /// AUTH failed; carries the NIP-01 `OK` message the client should receive.
    Rejected(&'static str),
}

/// Canonicalise a relay URL for tolerant comparison: trim, lowercase, drop the
/// `ws`/`wss`/`http`/`https` scheme, and strip a single trailing slash. This
/// absorbs the trivial spelling differences between the URL a client echoes in
/// its `["relay", …]` tag and the relay's own configured `RELAY_URL`, without
/// weakening the host/path identity that actually matters for NIP-42 scoping.
pub fn canonical_relay_url(u: &str) -> String {
    let lower = u.trim().to_ascii_lowercase();
    let no_scheme = lower
        .strip_prefix("wss://")
        .or_else(|| lower.strip_prefix("ws://"))
        .or_else(|| lower.strip_prefix("https://"))
        .or_else(|| lower.strip_prefix("http://"))
        .unwrap_or(lower.as_str());
    no_scheme.trim_end_matches('/').to_string()
}

/// Whether two relay URLs name the same relay after canonicalisation.
pub fn relay_urls_match(a: &str, b: &str) -> bool {
    canonical_relay_url(a) == canonical_relay_url(b)
}

/// Verify a client's kind-22242 AUTH event against the session's challenge, the
/// relay's own URL, and the clock.
///
/// Checks, in order: kind is 22242; the event id + Schnorr signature verify
/// strictly; the `challenge` tag equals the value THIS session was issued; the
/// `relay` tag names THIS relay (canonicalised); and `created_at` is within
/// `±max_skew` of `now`.
///
/// `own_relay_url = None` (or blank) SKIPS the relay-tag check — the relay's own
/// URL is unconfigured, and the per-session unpredictable challenge is already
/// the primary anti-replay property, so this fails *open* only for the
/// defence-in-depth relay-scoping check and never for the challenge/signature.
/// This lets the gate roll out safely before an operator sets `RELAY_URL`.
///
/// Pure over its inputs (the Schnorr verify is itself a pure function of the
/// event), so the full verdict table is unit-testable without a DO.
pub fn evaluate_auth_event(
    event: &NostrEvent,
    expected_challenge: Option<&str>,
    own_relay_url: Option<&str>,
    now: u64,
    max_skew: u64,
) -> AuthVerdict {
    if event.kind != KIND_AUTH {
        return AuthVerdict::Rejected("invalid: expected kind 22242");
    }

    if nostr_bbs_core::verify_event_strict(event).is_err() {
        return AuthVerdict::Rejected("invalid: signature verification failed");
    }

    // Challenge must equal the exact value issued to this session. A missing
    // session challenge (None) can never match, so it rejects.
    let challenge_tag = filter::tag_value(event, "challenge");
    match (challenge_tag.as_deref(), expected_challenge) {
        (Some(c), Some(expected)) if c == expected => {}
        _ => return AuthVerdict::Rejected("invalid: challenge mismatch"),
    }

    // Relay URL must name THIS relay (canonicalised) — but only when we know our
    // own URL. NIP-42 scopes a client's AUTH to a specific relay so a malicious
    // relay cannot replay it elsewhere; enforcing it here is defence-in-depth on
    // top of the per-session challenge.
    if let Some(own) = own_relay_url.filter(|s| !s.trim().is_empty()) {
        match filter::tag_value(event, "relay") {
            Some(claimed) if relay_urls_match(&claimed, own) => {}
            Some(_) => return AuthVerdict::Rejected("invalid: relay url mismatch"),
            None => return AuthVerdict::Rejected("invalid: missing relay tag"),
        }
    }

    // created_at within the permitted skew window (guards a stale/replayed AUTH).
    if now.abs_diff(event.created_at) > max_skew {
        return AuthVerdict::Rejected("invalid: auth event too old");
    }

    AuthVerdict::Ok(event.pubkey.clone())
}

/// Whether an EVENT (write) is admitted, given the mode and whether the session
/// completed NIP-42 AUTH.
///
/// In `Nip42` mode every write requires an authenticated session (PRD-010 G4);
/// the allowlist is then applied downstream as authorisation on the
/// authenticated identity. In `Allowlist` mode the legacy behaviour stands (the
/// allowlist alone gates). Returns the NIP-01 `OK` reason on denial.
pub fn write_auth_ok(mode: AuthMode, session_authed: bool) -> Result<(), &'static str> {
    match mode {
        AuthMode::Nip42 if !session_authed => Err("auth-required: NIP-42 AUTH required to publish"),
        _ => Ok(()),
    }
}

/// Whether a REQ / COUNT with these filters must be rejected for lack of AUTH.
///
/// In `Nip42` mode, any filter requesting a protected-read kind requires an
/// authenticated session. kind-1059's mandatory `#p` rewrite is applied
/// separately (and gates 1059 in BOTH modes, via
/// [`super::NostrRelayDO::gate_kind_1059_filters`]) so DM privacy never depends
/// on `AUTH_MODE`; this predicate adds the wider protected set for `Nip42` mode.
/// Returns `true` ⇒ the request must be rejected as auth-required.
pub fn protected_read_blocked(
    filters: &[NostrFilter],
    session_authed: bool,
    mode: AuthMode,
) -> bool {
    if mode != AuthMode::Nip42 || session_authed {
        return false;
    }
    filters.iter().any(|f| {
        f.kinds
            .as_ref()
            .is_some_and(|ks| ks.iter().any(|k| is_protected_read_kind(*k)))
    })
}

/// The NIP-01 `OK` reason for an allowlist (authorisation) denial.
///
/// Under NIP-42 semantics a denial AFTER a completed AUTH is `restricted:`
/// (authenticated but not permitted) — distinct from `auth-required:` (must
/// authenticate first). Legacy `Allowlist` mode keeps the historical
/// `blocked:` message so existing clients / probes see no behavioural drift.
pub fn allowlist_denial_reason(mode: AuthMode, session_authed: bool) -> &'static str {
    if mode == AuthMode::Nip42 && session_authed {
        "restricted: pubkey not in allowlist"
    } else {
        "blocked: pubkey not whitelisted"
    }
}

// ---------------------------------------------------------------------------
// Tests (pure logic; the signed-event verdict table also runs as integration
// tests in tests/nip_handlers_tests.rs against real Schnorr signatures).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn filter_kinds(kinds: Option<Vec<u64>>) -> NostrFilter {
        let mut v = serde_json::Map::new();
        if let Some(k) = kinds {
            v.insert("kinds".to_string(), serde_json::json!(k));
        }
        serde_json::from_value(serde_json::Value::Object(v)).expect("filter")
    }

    #[test]
    fn auth_mode_defaults_to_nip42_and_fails_closed() {
        assert_eq!(parse_auth_mode(None), AuthMode::Nip42);
        assert_eq!(parse_auth_mode(Some("")), AuthMode::Nip42);
        assert_eq!(parse_auth_mode(Some("nonsense")), AuthMode::Nip42);
        assert_eq!(parse_auth_mode(Some("nip42")), AuthMode::Nip42);
        assert_eq!(parse_auth_mode(Some("allowlist")), AuthMode::Allowlist);
        assert_eq!(parse_auth_mode(Some("  AllowList ")), AuthMode::Allowlist);
        assert_eq!(AuthMode::default(), AuthMode::Nip42);
    }

    #[test]
    fn canonical_url_absorbs_scheme_case_and_trailing_slash() {
        assert!(relay_urls_match(
            "wss://Relay.Example.com/",
            "relay.example.com"
        ));
        assert!(relay_urls_match(
            "wss://relay.example.com",
            "wss://relay.example.com/"
        ));
        assert!(!relay_urls_match(
            "wss://relay.example.com",
            "wss://evil.example.com"
        ));
    }

    #[test]
    fn write_gate_requires_auth_only_in_nip42_mode() {
        // nip42 mode: unauthenticated write rejected; authenticated allowed.
        assert!(write_auth_ok(AuthMode::Nip42, false).is_err());
        assert_eq!(
            write_auth_ok(AuthMode::Nip42, false).unwrap_err(),
            "auth-required: NIP-42 AUTH required to publish"
        );
        assert!(write_auth_ok(AuthMode::Nip42, true).is_ok());
        // allowlist mode: unauthenticated write passes the AUTH gate (legacy).
        assert!(write_auth_ok(AuthMode::Allowlist, false).is_ok());
        assert!(write_auth_ok(AuthMode::Allowlist, true).is_ok());
    }

    #[test]
    fn protected_read_gate_blocks_unauthed_protected_kinds_in_nip42() {
        let dm = [filter_kinds(Some(vec![4]))];
        let seal = [filter_kinds(Some(vec![13]))];
        let mod_event = [filter_kinds(Some(vec![30910]))];
        let public = [filter_kinds(Some(vec![1, 7]))];

        // Unauthenticated + nip42: protected kinds blocked, public open.
        assert!(protected_read_blocked(&dm, false, AuthMode::Nip42));
        assert!(protected_read_blocked(&seal, false, AuthMode::Nip42));
        assert!(protected_read_blocked(&mod_event, false, AuthMode::Nip42));
        assert!(!protected_read_blocked(&public, false, AuthMode::Nip42));

        // Authenticated: never blocked.
        assert!(!protected_read_blocked(&dm, true, AuthMode::Nip42));

        // Allowlist mode: the wider protected set is not gated here (kind-1059's
        // own gate still applies via gate_kind_1059_filters).
        assert!(!protected_read_blocked(&dm, false, AuthMode::Allowlist));
    }

    #[test]
    fn protected_read_gate_ignores_public_only_moderation_boundaries() {
        // 30909 and 30917 are just outside the moderation carve-out and stay open.
        let just_below = [filter_kinds(Some(vec![30909]))];
        let just_above = [filter_kinds(Some(vec![30917]))];
        assert!(!protected_read_blocked(&just_below, false, AuthMode::Nip42));
        assert!(!protected_read_blocked(&just_above, false, AuthMode::Nip42));
        // A filter with no kinds constraint requests everything but names no
        // protected kind, so it is not blocked (the per-event read gate still
        // withholds protected content downstream).
        let anykind = [filter_kinds(None)];
        assert!(!protected_read_blocked(&anykind, false, AuthMode::Nip42));
    }

    #[test]
    fn allowlist_denial_uses_restricted_prefix_after_auth() {
        assert_eq!(
            allowlist_denial_reason(AuthMode::Nip42, true),
            "restricted: pubkey not in allowlist"
        );
        // Unauthenticated (shouldn't reach here in nip42 mode, but be explicit)
        // and legacy mode keep the historical message.
        assert_eq!(
            allowlist_denial_reason(AuthMode::Nip42, false),
            "blocked: pubkey not whitelisted"
        );
        assert_eq!(
            allowlist_denial_reason(AuthMode::Allowlist, true),
            "blocked: pubkey not whitelisted"
        );
    }
}

#[cfg(test)]
mod protected_read_permitted_tests {
    //! The auth-bypass deepsec-gate found at HIGH: a `REQ ["sub", {}]` names no
    //! kinds, matches every kind, and so passed both filter-level gates —
    //! `query_events` then returned sealed DMs to an anonymous socket. These
    //! pin the per-event gate that closes it.
    use super::*;

    const VIEWER: &str = "aaaa";
    const AUTHOR: &str = "bbbb";
    const STRANGER: &str = "cccc";

    fn to(pk: &str) -> Vec<String> {
        vec![pk.to_string()]
    }

    /// The bypass itself: an anonymous viewer receives no correspondence,
    /// whatever the filter did or did not say.
    #[test]
    fn an_anonymous_viewer_receives_no_correspondence() {
        for kind in [4u64, 13, 14, 1059] {
            for mode in [AuthMode::Nip42, AuthMode::Allowlist] {
                assert!(
                    !protected_read_permitted(kind, AUTHOR, &to(VIEWER), None, mode),
                    "kind {kind} leaked to an anonymous viewer in {mode:?}"
                );
            }
        }
    }

    /// DM privacy does not depend on AUTH_MODE — the relay's own design note,
    /// now true of the per-event gate as well as the filter gate.
    #[test]
    fn a_stranger_receives_no_correspondence_in_either_mode() {
        for kind in [4u64, 13, 14, 1059] {
            for mode in [AuthMode::Nip42, AuthMode::Allowlist] {
                assert!(
                    !protected_read_permitted(kind, AUTHOR, &to(VIEWER), Some(STRANGER), mode),
                    "kind {kind} leaked to a stranger in {mode:?}"
                );
            }
        }
    }

    #[test]
    fn the_recipient_and_the_author_both_receive_their_correspondence() {
        for kind in [4u64, 13, 14, 1059] {
            assert!(protected_read_permitted(
                kind,
                AUTHOR,
                &to(VIEWER),
                Some(VIEWER),
                AuthMode::Nip42
            ));
            assert!(protected_read_permitted(
                kind,
                AUTHOR,
                &to(VIEWER),
                Some(AUTHOR),
                AuthMode::Nip42
            ));
        }
    }

    /// Pubkeys are hex and hex is case-insensitive; a recipient must not be
    /// locked out of their own mail by casing.
    #[test]
    fn recipient_matching_is_case_insensitive() {
        assert!(protected_read_permitted(
            1059,
            AUTHOR,
            &to("AAAA"),
            Some("aaaa"),
            AuthMode::Nip42
        ));
    }

    /// An operator role is not a party to someone else's conversation.
    /// Admin-ness is deliberately not an input to this function.
    #[test]
    fn a_gift_wrap_with_several_recipients_serves_each_of_them() {
        let many = vec![VIEWER.to_string(), STRANGER.to_string()];
        assert!(protected_read_permitted(
            1059,
            AUTHOR,
            &many,
            Some(STRANGER),
            AuthMode::Nip42
        ));
        assert!(!protected_read_permitted(
            1059,
            AUTHOR,
            &many,
            Some("dddd"),
            AuthMode::Nip42
        ));
    }

    /// Moderation events are protected from anonymous readers but are
    /// legitimately readable by the membership — a different rule from
    /// correspondence, and one that must not change under legacy AUTH_MODE.
    #[test]
    fn moderation_kinds_need_only_authentication_and_only_in_nip42() {
        for kind in 30910u64..=30916 {
            assert!(!protected_read_permitted(
                kind,
                AUTHOR,
                &[],
                None,
                AuthMode::Nip42
            ));
            assert!(protected_read_permitted(
                kind,
                AUTHOR,
                &[],
                Some(STRANGER),
                AuthMode::Nip42
            ));
            // Legacy deployments keep their current read behaviour.
            assert!(protected_read_permitted(
                kind,
                AUTHOR,
                &[],
                None,
                AuthMode::Allowlist
            ));
        }
    }

    /// Everything outside the protected set passes through untouched: this gate
    /// must not quietly become a general read filter.
    #[test]
    fn unprotected_kinds_are_untouched() {
        for kind in [0u64, 1, 7, 42, 30023, 31402, 31403] {
            assert!(protected_read_permitted(
                kind,
                AUTHOR,
                &[],
                None,
                AuthMode::Nip42
            ));
        }
    }

    #[test]
    fn the_correspondence_set_is_exactly_the_dm_kinds() {
        for kind in PROTECTED_READ_KINDS {
            assert_eq!(
                is_correspondence_kind(*kind),
                matches!(kind, 4 | 13 | 14 | 1059),
                "kind {kind} is on the wrong side of the correspondence split"
            );
        }
    }
}
