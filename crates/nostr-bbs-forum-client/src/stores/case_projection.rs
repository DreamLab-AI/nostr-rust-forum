//! The relay's own projection of a governance case (`broker_cases`), read over
//! `GET /api/governance/cases`.
//!
//! The client computes most of a case's ADR-2011 boundary itself, from the same
//! pure `nostr-bbs-core` functions the relay runs over the same signed events.
//! One field it **cannot** compute is whether a case is a calibration sample.
//!
//! Selection is `HMAC-SHA256(selection_key, request_id)` under a secret only the
//! relay holds. It is keyed for a specific reason: the request id is the 31402's
//! `d` tag, and on a NIP-33 parameterized-replaceable event the *requesting
//! agent* chooses that freely. Unkeyed, an agent could grind `d` tags offline
//! until it found one that selection never picks, and opt itself out of the
//! oversight FR6.3 exists to impose — ADR-2011's own thesis defeated one level
//! down. Shipping the key to the browser to recompute the flag would publish it
//! to every reader of the WASM bundle and restore the hole exactly. So the flag
//! is read, never derived.
//!
//! The endpoint is `require_authed` — any NIP-98 signer, not admin — so an
//! ordinary logged-in member gets it, which is what FR6.3 needs: calibration
//! samples exist to be shown to the member surface.
//!
//! A projection row answers only for the card its author published. The map is
//! keyed by the `d` tag, which the requesting agent chooses and which collides
//! across authors; the relay stores the first claimant's row (`INSERT OR
//! IGNORE`), so a second agent reusing that `d` would otherwise inherit the
//! first one's tier and calibration flag, and `with_relay_tier` adopts a stored
//! tier downward as well as upward. Each lookup therefore takes the card's
//! author and answers only when the row's `created_by` matches it; a row with no
//! `created_by` (an older relay) answers nothing.
//!
//! An unknown case is **not** a calibration sample (`false`): a legacy case
//! projected before migration 0006, a logged-out viewer, or a projection not yet
//! fetched all fall back to plain effective-tier suppression rather than being
//! shown as something the relay never said they were.

use std::collections::HashMap;

use leptos::prelude::*;

/// What this client reads from a projected case. Additive: the projection
/// carries more, and a field is pulled up here only when a surface needs it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CaseProjection {
    /// `broker_cases.calibration_sample` — relay-authoritative (see module doc).
    pub calibration_sample: bool,
    /// `broker_cases.effective_tier`, where the case was projected after
    /// migration 0006. Carried for cross-checking the client's own computation;
    /// it is not yet what the surfaces gate on.
    pub effective_tier: Option<String>,
    /// `broker_cases.created_by`, lower-cased: the pubkey of the 31402 the row
    /// was projected from. `None` when the relay did not say.
    pub created_by: Option<String>,
}

impl CaseProjection {
    /// Whether this row was projected from a 31402 signed by `author`.
    fn is_by(&self, author: &str) -> bool {
        self.created_by
            .as_deref()
            .is_some_and(|c| c.eq_ignore_ascii_case(author))
    }
}

/// Parse `GET /api/governance/cases` into a map keyed by case id (the 31402's
/// `d` tag). Malformed rows are skipped rather than failing the whole read.
// Unwired: the pure, unit-tested half of a governance surface that is not yet
// rendered. Kept because the tests assert a documented invariant; the `allow`
// is scoped to the item so new dead code in this module is still reported.
#[allow(dead_code)]
pub fn parse_cases(body: &str) -> HashMap<String, CaseProjection> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(body) else {
        return HashMap::new();
    };
    let Some(rows) = v.get("cases").and_then(|c| c.as_array()) else {
        return HashMap::new();
    };
    rows.iter()
        .filter_map(|r| {
            let id = r.get("id")?.as_str()?.to_string();
            Some((
                id,
                CaseProjection {
                    // Absent (a legacy row, or an older relay) is `false`, not
                    // "unknown so show it": the relay is the only authority and
                    // silence from it is not a claim.
                    calibration_sample: r
                        .get("calibration_sample")
                        .and_then(|c| c.as_bool())
                        .unwrap_or(false),
                    effective_tier: r
                        .get("effective_tier")
                        .and_then(|t| t.as_str())
                        .map(str::to_string),
                    created_by: r
                        .get("created_by")
                        .and_then(|c| c.as_str())
                        .map(str::to_ascii_lowercase),
                },
            ))
        })
        .collect()
}

/// Whether the relay's projection marks `case_id`, as published by `author`, a
/// calibration sample.
///
/// A free function over the state rather than a [`CaseProjectionStore`] method,
/// so the governance page can read every card in one pass while already holding
/// a read guard instead of taking a fresh borrow per card. It is the **only**
/// place the rule lives, so there is no second implementation to drift from.
/// `false` for an unknown case: the marker is a claim about the relay's HMAC
/// selection, and the client makes no such claim on its own. `false` too when the
/// row belongs to another author (see the module doc on `d`-tag collisions).
pub fn is_calibration_sample_in(state: &CaseProjectionState, author: &str, case_id: &str) -> bool {
    state
        .cases
        .get(case_id)
        .filter(|c| c.is_by(author))
        .map(|c| c.calibration_sample)
        .unwrap_or(false)
}

/// The relay's stored effective tier for `case_id` as published by `author`, if
/// the projection has it. `None` when the row belongs to another author, so the
/// card keeps the tier it computed itself rather than a stranger's.
pub fn effective_tier_in<'a>(
    state: &'a CaseProjectionState,
    author: &str,
    case_id: &str,
) -> Option<&'a str> {
    state
        .cases
        .get(case_id)
        .filter(|c| c.is_by(author))
        .and_then(|c| c.effective_tier.as_deref())
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct CaseProjectionState {
    pub cases: HashMap<String, CaseProjection>,
    /// A fetch is in flight; a re-render must not start another.
    pub loading: bool,
    /// The read is not available to this viewer (logged out, or refused).
    /// Latched so a surface does not hammer an endpoint it cannot read.
    pub unavailable: bool,
    /// At least one successful read has completed.
    pub loaded: bool,
}

#[derive(Clone, Copy)]
pub struct CaseProjectionStore {
    pub state: RwSignal<CaseProjectionState>,
}

pub fn provide_case_projection_store() {
    provide_context(CaseProjectionStore {
        state: RwSignal::new(CaseProjectionState::default()),
    });
}

pub fn use_case_projection_store() -> CaseProjectionStore {
    expect_context::<CaseProjectionStore>()
}

impl CaseProjectionStore {
    /// Whether a fetch should be started.
    #[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
    pub fn needs_load(&self) -> bool {
        let s = self.state.read();
        !s.loading && !s.unavailable && !s.loaded
    }

    /// Fetch the case projection (NIP-98, any authenticated member).
    #[cfg(target_arch = "wasm32")]
    pub fn load(&self, signer: std::rc::Rc<dyn nostr_bbs_core::signer::Signer>) {
        use wasm_bindgen_futures::spawn_local;

        if !self.needs_load() {
            return;
        }
        let store = *self;
        store.state.update(|s| s.loading = true);
        spawn_local(async move {
            let url = format!(
                "{}/api/governance/cases?limit=100",
                crate::utils::relay_url::auth_api_base()
            );
            let result =
                crate::auth::nip98::fetch_with_nip98_get_signer(&url, signer.as_ref()).await;
            store.state.update(|s| {
                s.loading = false;
                match result {
                    Ok(body) => {
                        s.cases = parse_cases(&body);
                        s.loaded = true;
                    }
                    Err(e) => {
                        let msg = e.to_string();
                        if msg.contains("401") || msg.contains("403") {
                            s.unavailable = true;
                        }
                        web_sys::console::warn_1(
                            &format!("[governance] case projection read failed: {msg}").into(),
                        );
                    }
                }
            });
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_case_projection_envelope() {
        let body = r#"{"cases":[
            {"id":"case-1","calibration_sample":true,"effective_tier":"low","created_by":"AA"},
            {"id":"case-2","calibration_sample":false,"effective_tier":"high"}
        ]}"#;
        let cases = parse_cases(body);
        assert_eq!(cases.len(), 2);
        assert!(cases["case-1"].calibration_sample);
        assert!(!cases["case-2"].calibration_sample);
        assert_eq!(cases["case-2"].effective_tier.as_deref(), Some("high"));
        assert_eq!(cases["case-1"].created_by.as_deref(), Some("aa"));
        assert_eq!(cases["case-2"].created_by, None);
    }

    #[test]
    fn a_legacy_row_without_the_flag_is_not_a_calibration_sample() {
        // A case projected before migration 0006 says nothing about sampling,
        // and silence is not a claim.
        let cases = parse_cases(r#"{"cases":[{"id":"old-1","state":"open"}]}"#);
        assert!(!cases["old-1"].calibration_sample);
        assert_eq!(cases["old-1"].effective_tier, None);
    }

    #[test]
    fn malformed_rows_are_skipped_and_a_bad_body_yields_nothing() {
        let cases = parse_cases(r#"{"cases":[{"no_id":1},{"id":"ok-1"}]}"#);
        assert_eq!(cases.len(), 1);
        assert!(cases.contains_key("ok-1"));
        assert!(parse_cases("").is_empty());
        assert!(parse_cases("not json").is_empty());
        assert!(parse_cases(r#"{"error":"unauthorised"}"#).is_empty());
    }

    #[test]
    fn an_unknown_case_is_never_reported_as_a_calibration_sample() {
        let mut state = CaseProjectionState::default();
        assert!(!is_calibration_sample_in(&state, "aa", "never-seen"));

        state.cases.insert(
            "case-1".into(),
            CaseProjection {
                calibration_sample: true,
                effective_tier: None,
                created_by: Some("aa".into()),
            },
        );
        state.cases.insert(
            "case-2".into(),
            CaseProjection {
                calibration_sample: false,
                effective_tier: None,
                created_by: Some("aa".into()),
            },
        );
        state.loaded = true;

        assert!(is_calibration_sample_in(&state, "aa", "case-1"));
        // Told about, and told it is not one.
        assert!(!is_calibration_sample_in(&state, "aa", "case-2"));
        // Not told about at all — still not one.
        assert!(!is_calibration_sample_in(&state, "aa", "case-3"));
    }

    #[test]
    fn effective_tier_lookup_is_per_case_and_absent_when_unknown() {
        let state = CaseProjectionState {
            cases: parse_cases(
                r#"{"cases":[{"id":"c1","effective_tier":"high","created_by":"aa"},{"id":"c2","created_by":"aa"}]}"#,
            ),
            loaded: true,
            ..Default::default()
        };
        assert_eq!(effective_tier_in(&state, "aa", "c1"), Some("high"));
        assert_eq!(effective_tier_in(&state, "aa", "c2"), None);
        assert_eq!(effective_tier_in(&state, "aa", "missing"), None);
    }

    #[test]
    fn a_colliding_d_tag_never_lends_one_authors_row_to_another() {
        // deepsec finding_d4dc5fdca9f6c089: agent BB reuses the `d` of AA's
        // low-tier case; the relay keeps AA's row. BB's card must not inherit
        // AA's tier (which would drag a high case below the member surface) or
        // AA's calibration flag.
        let state = CaseProjectionState {
            cases: parse_cases(
                r#"{"cases":[{"id":"x","effective_tier":"low","calibration_sample":true,"created_by":"aa"}]}"#,
            ),
            loaded: true,
            ..Default::default()
        };
        assert_eq!(effective_tier_in(&state, "AA", "x"), Some("low"));
        assert!(is_calibration_sample_in(&state, "AA", "x"));
        assert_eq!(effective_tier_in(&state, "bb", "x"), None);
        assert!(!is_calibration_sample_in(&state, "bb", "x"));
    }

    #[test]
    fn a_row_without_created_by_answers_for_nobody() {
        let state = CaseProjectionState {
            cases: parse_cases(
                r#"{"cases":[{"id":"x","effective_tier":"low","calibration_sample":true}]}"#,
            ),
            loaded: true,
            ..Default::default()
        };
        assert_eq!(effective_tier_in(&state, "aa", "x"), None);
        assert!(!is_calibration_sample_in(&state, "aa", "x"));
    }
}
