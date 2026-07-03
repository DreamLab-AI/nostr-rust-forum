//! WI-3 Web-of-Trust (WoT) gating API.
//!
//! The WoT feature lets admins configure a "referente" (reference) pubkey whose
//! NIP-02 follow list (kind-3 event) defines the set of members permitted to
//! register. Admins can add/remove manual overrides, refresh the follow set
//! from a newly supplied kind-3 event, and inspect current status.
//!
//! Because workers-rs has limited outgoing WebSocket support, the admin CLI
//! fetches the referente's kind-3 event from a relay and POSTs it to
//! `/api/wot/refresh` as a JSON payload. The worker verifies the event
//! signature, checks the signer matches `wot_referente_pubkey`, and replaces
//! `wot_entries` with the extracted `p` tags.
//!
//! | Method | Path                            | Auth  | Purpose                              |
//! |--------|---------------------------------|-------|--------------------------------------|
//! | GET    | /api/wot/status                 | admin | Return WoT config + counts           |
//! | POST   | /api/wot/set-referente          | admin | Set/unset referente pubkey + enabled |
//! | POST   | /api/wot/refresh                | admin | Ingest a fresh kind-3 follow list    |
//! | POST   | /api/wot/override/add           | admin | Whitelist a pubkey (source=override) |
//! | POST   | /api/wot/override/remove        | admin | Remove an override entry             |

use nostr_bbs_core::d1_helpers::{js_i64, js_opt_str, js_str};
use nostr_bbs_core::{verify_event_strict, NostrEvent};
use serde::Deserialize;
use serde_json::json;
use wasm_bindgen::JsValue;
use worker::{Env, Response, Result};

use crate::admin::{canonical_url, now_secs, require_admin};
use crate::http::{error_json, json_response};

// ---------------------------------------------------------------------------
// Request bodies
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct SetReferenteBody {
    /// Hex pubkey to mark as the referente. Pass `null` to unset.
    pubkey: Option<String>,
    /// Whether WoT gating is active for registration. Defaults to `true` when
    /// a pubkey is supplied, `false` when it is unset.
    enabled: Option<bool>,
}

#[derive(Deserialize)]
struct RefreshBody {
    /// A signed kind-3 (NIP-02) event from the referente. Its `p` tags become
    /// the new `wot_entries` set (sources 'referente').
    kind3_event: Option<NostrEvent>,
    /// Fallback: an explicit list of hex pubkeys. Used when the admin CLI
    /// cannot fetch a kind-3 event (e.g. relay unreachable).
    pubkeys: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct OverrideBody {
    pubkey: String,
}

// ---------------------------------------------------------------------------
// D1 row types
// ---------------------------------------------------------------------------

/// Row shape for `SELECT * FROM wot_entries`. Fields are read via serde
/// deserialisation from D1 rows, so rustc's dead-code detector flags them.
#[allow(dead_code)]
#[derive(Deserialize)]
struct WotRow {
    pubkey: String,
    added_at: i64,
    source: String,
}

#[derive(Deserialize)]
struct SettingsRow {
    wot_enabled: i64,
    wot_referente_pubkey: Option<String>,
    wot_last_fetched_at: Option<i64>,
    wot_follow_count: Option<i64>,
}

#[derive(Deserialize)]
struct CountRow {
    c: i64,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn js_bool(b: bool) -> JsValue {
    JsValue::from_f64(if b { 1.0 } else { 0.0 })
}

/// Lowercase 64-char hex pubkey check.
fn is_pubkey(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Extract the `p` tag values (index 1) from a kind-3 event.
fn extract_follow_pubkeys(event: &NostrEvent) -> Vec<String> {
    event
        .tags
        .iter()
        .filter(|t| t.len() >= 2 && t[0] == "p")
        .map(|t| t[1].to_lowercase())
        .filter(|p| is_pubkey(p))
        .collect()
}

/// Look up the referente pubkey from `instance_settings`. `Ok(None)` means
/// WoT is unconfigured; never panics on DB failure.
async fn load_settings(env: &Env) -> Option<SettingsRow> {
    let db = env.d1("DB").ok()?;
    let stmt = db.prepare(
        "SELECT wot_enabled, wot_referente_pubkey, wot_last_fetched_at, wot_follow_count \
         FROM instance_settings WHERE id = 1",
    );
    stmt.first::<SettingsRow>(None).await.ok().flatten()
}

// ---------------------------------------------------------------------------
// GET /api/wot/status
// ---------------------------------------------------------------------------

pub async fn handle_status(auth_header: Option<&str>, env: &Env, origin: &str) -> Result<Response> {
    let url = canonical_url(origin, "/api/wot/status");
    if let Err((body, status)) = require_admin(auth_header, &url, "GET", None, env).await {
        return json_response(env, &body, status);
    }

    let settings = load_settings(env).await;
    let (enabled, referente, last, follow_count) = match settings {
        Some(s) => (
            s.wot_enabled == 1,
            s.wot_referente_pubkey,
            s.wot_last_fetched_at,
            s.wot_follow_count,
        ),
        None => (false, None, None, None),
    };

    // Count override entries alongside referente-sourced ones.
    let (total, override_count) = count_entries(env).await;

    json_response(
        env,
        &json!({
            "enabled": enabled,
            "referente_pubkey": referente,
            "last_fetched_at": last,
            "follow_count": follow_count,
            "total_entries": total,
            "manual_overrides": override_count,
        }),
        200,
    )
}

async fn count_entries(env: &Env) -> (i64, i64) {
    let Ok(db) = env.d1("DB") else {
        return (0, 0);
    };
    let total = db
        .prepare("SELECT COUNT(*) AS c FROM wot_entries")
        .first::<CountRow>(None)
        .await
        .ok()
        .flatten()
        .map(|r| r.c)
        .unwrap_or(0);
    let overrides = db
        .prepare("SELECT COUNT(*) AS c FROM wot_entries WHERE source = 'manual_override'")
        .first::<CountRow>(None)
        .await
        .ok()
        .flatten()
        .map(|r| r.c)
        .unwrap_or(0);
    (total, overrides)
}

// ---------------------------------------------------------------------------
// POST /api/wot/set-referente
// ---------------------------------------------------------------------------

pub async fn handle_set_referente(
    body_bytes: &[u8],
    auth_header: Option<&str>,
    env: &Env,
    origin: &str,
) -> Result<Response> {
    let url = canonical_url(origin, "/api/wot/set-referente");
    if let Err((body, status)) =
        require_admin(auth_header, &url, "POST", Some(body_bytes), env).await
    {
        return json_response(env, &body, status);
    }

    let body: SetReferenteBody = match serde_json::from_slice(body_bytes) {
        Ok(b) => b,
        Err(e) => return error_json(env, &format!("Invalid JSON body: {e}"), 400),
    };

    if let Some(ref pk) = body.pubkey {
        if !is_pubkey(pk) {
            return error_json(env, "pubkey must be 64-char hex", 400);
        }
    }

    let db = match env.d1("DB") {
        Ok(d) => d,
        Err(_) => return error_json(env, "Database unavailable", 500),
    };

    let enabled = body.enabled.unwrap_or(body.pubkey.is_some());

    let update = db
        .prepare(
            "UPDATE instance_settings \
             SET wot_referente_pubkey = ?1, wot_enabled = ?2 \
             WHERE id = 1",
        )
        .bind(&[js_opt_str(body.pubkey.as_deref()), js_bool(enabled)])?
        .run()
        .await;

    if let Err(e) = update {
        return error_json(env, &format!("Update failed: {e}"), 500);
    }

    json_response(
        env,
        &json!({
            "ok": true,
            "referente_pubkey": body.pubkey,
            "enabled": enabled,
        }),
        200,
    )
}

// ---------------------------------------------------------------------------
// POST /api/wot/refresh
// ---------------------------------------------------------------------------

pub async fn handle_refresh(
    body_bytes: &[u8],
    auth_header: Option<&str>,
    env: &Env,
    origin: &str,
) -> Result<Response> {
    let url = canonical_url(origin, "/api/wot/refresh");
    if let Err((body, status)) =
        require_admin(auth_header, &url, "POST", Some(body_bytes), env).await
    {
        return json_response(env, &body, status);
    }

    let body: RefreshBody = match serde_json::from_slice(body_bytes) {
        Ok(b) => b,
        Err(e) => return error_json(env, &format!("Invalid JSON body: {e}"), 400),
    };

    let settings = load_settings(env).await;
    let referente = match settings
        .as_ref()
        .and_then(|s| s.wot_referente_pubkey.clone())
    {
        Some(r) => r,
        None => {
            return error_json(
                env,
                "WoT referente not configured. POST /api/wot/set-referente first.",
                409,
            )
        }
    };

    // Resolve the pubkey list: prefer the signed kind-3 event for provenance.
    let follow_list: Vec<String> = if let Some(event) = body.kind3_event.as_ref() {
        if event.kind != 3 {
            return error_json(env, "kind3_event must be kind 3 (follow list)", 400);
        }
        if event.pubkey.to_lowercase() != referente {
            return error_json(
                env,
                "kind3_event signer does not match configured referente",
                400,
            );
        }
        if verify_event_strict(event).is_err() {
            return error_json(env, "kind3_event signature verification failed", 400);
        }
        extract_follow_pubkeys(event)
    } else if let Some(list) = body.pubkeys.as_ref() {
        list.iter()
            .map(|p| p.to_lowercase())
            .filter(|p| is_pubkey(p))
            .collect()
    } else {
        return error_json(env, "Supply either kind3_event or pubkeys[]", 400);
    };

    let db = match env.d1("DB") {
        Ok(d) => d,
        Err(_) => return error_json(env, "Database unavailable", 500),
    };

    // Replace referente-sourced entries. Overrides are preserved.
    let _ = db
        .prepare("DELETE FROM wot_entries WHERE source = 'referente'")
        .run()
        .await;

    let now = now_secs() as i64;
    for pk in &follow_list {
        let _ = db
            .prepare(
                "INSERT INTO wot_entries (pubkey, added_at, source) \
                 VALUES (?1, ?2, 'referente') \
                 ON CONFLICT (pubkey) DO UPDATE SET added_at = excluded.added_at, source = 'referente'",
            )
            .bind(&[js_str(pk), js_i64(now)])?
            .run()
            .await;
    }

    let _ = db
        .prepare(
            "UPDATE instance_settings \
             SET wot_last_fetched_at = ?1, wot_follow_count = ?2 \
             WHERE id = 1",
        )
        .bind(&[js_i64(now), js_i64(follow_list.len() as i64)])?
        .run()
        .await;

    json_response(
        env,
        &json!({
            "ok": true,
            "referente": referente,
            "follow_count": follow_list.len(),
            "fetched_at": now,
        }),
        200,
    )
}

// ---------------------------------------------------------------------------
// POST /api/wot/override/add  |  /api/wot/override/remove
// ---------------------------------------------------------------------------

pub async fn handle_override(
    path: &str,
    body_bytes: &[u8],
    auth_header: Option<&str>,
    env: &Env,
    origin: &str,
) -> Result<Response> {
    let url = canonical_url(origin, path);
    if let Err((body, status)) =
        require_admin(auth_header, &url, "POST", Some(body_bytes), env).await
    {
        return json_response(env, &body, status);
    }

    let body: OverrideBody = match serde_json::from_slice(body_bytes) {
        Ok(b) => b,
        Err(e) => return error_json(env, &format!("Invalid JSON body: {e}"), 400),
    };

    if !is_pubkey(&body.pubkey) {
        return error_json(env, "pubkey must be 64-char hex", 400);
    }

    let db = match env.d1("DB") {
        Ok(d) => d,
        Err(_) => return error_json(env, "Database unavailable", 500),
    };

    let is_add = path == "/api/wot/override/add";
    let now = now_secs() as i64;

    if is_add {
        let run = db
            .prepare(
                "INSERT INTO wot_entries (pubkey, added_at, source) \
                 VALUES (?1, ?2, 'manual_override') \
                 ON CONFLICT (pubkey) DO UPDATE SET source = 'manual_override'",
            )
            .bind(&[js_str(&body.pubkey), js_i64(now)])?
            .run()
            .await;
        if let Err(e) = run {
            return error_json(env, &format!("Insert failed: {e}"), 500);
        }
    } else {
        let run = db
            .prepare("DELETE FROM wot_entries WHERE pubkey = ?1 AND source = 'manual_override'")
            .bind(&[js_str(&body.pubkey)])?
            .run()
            .await;
        if let Err(e) = run {
            return error_json(env, &format!("Delete failed: {e}"), 500);
        }
    }

    json_response(
        env,
        &json!({
            "ok": true,
            "action": if is_add { "added" } else { "removed" },
            "pubkey": body.pubkey,
        }),
        200,
    )
}

// ---------------------------------------------------------------------------
// Registration gate helper (used from webauthn.rs when wot_enabled = 1)
// ---------------------------------------------------------------------------

/// Check if `pubkey` is allowed to register under the current WoT policy.
///
/// Returns:
/// - `Ok(true)`  — WoT disabled OR pubkey is in `wot_entries`.
/// - `Ok(false)` — WoT enabled AND pubkey is not trusted.
/// - `Err(..)`   — transient DB failure; caller should treat as 500.
pub async fn is_allowed_by_wot(pubkey: &str, env: &Env) -> Result<bool> {
    // A transient D1 failure while reading EITHER the policy row or the entries
    // table must surface as `Err` (caller -> 503), never a silent decision. The
    // shared `load_settings` helper collapses a query error into `Ok(None)` via
    // `.ok().flatten()`, which is correct for the admin status/refresh handlers
    // (they render defaults) but WRONG on the registration gate: a settings-read
    // blip on a `wot_enabled = 1` instance would be read as "unconfigured" and
    // short-circuit to `Ok(true)`, silently DISABLING the gate (fail-open
    // bypass). Read the policy row directly here and propagate its error so the
    // gate fails closed to 503, mirroring the entries lookup below.
    let db = env.d1("DB")?;
    let settings = db
        .prepare(
            "SELECT wot_enabled, wot_referente_pubkey, wot_last_fetched_at, wot_follow_count \
             FROM instance_settings WHERE id = 1",
        )
        .first::<SettingsRow>(None)
        .await?;

    // `Ok(None)` from a healthy DB means no policy row -> WoT unconfigured ->
    // open registration (the documented default for a fresh instance).
    let enabled = matches!(settings, Some(ref s) if s.wot_enabled == 1);
    if !enabled {
        return Ok(true);
    }

    // Propagate a transient D1 error as Err (caller maps it to 503) rather than
    // swallowing it into Ok(None) -> deny. A DB blip must not silently deny a
    // legitimately-trusted pubkey during registration; the documented contract
    // above requires the transient-failure signal to reach the caller.
    let row = db
        .prepare("SELECT pubkey, added_at, source FROM wot_entries WHERE pubkey = ?1 LIMIT 1")
        .bind(&[js_str(pubkey)])?
        .first::<WotRow>(None)
        .await?;
    Ok(row.is_some())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use k256::schnorr::SigningKey;
    use nostr_bbs_core::event::{sign_event_deterministic, UnsignedEvent};

    fn ref_sk() -> SigningKey {
        SigningKey::from_bytes(&[0x07u8; 32]).unwrap()
    }
    fn ref_pk() -> String {
        hex::encode(ref_sk().verifying_key().to_bytes())
    }

    fn kind3_with_follows(follows: &[&str]) -> NostrEvent {
        let mut tags: Vec<Vec<String>> = follows
            .iter()
            .map(|p| vec!["p".to_string(), (*p).to_string()])
            .collect();
        tags.insert(0, vec!["client".to_string(), "test".to_string()]);
        let u = UnsignedEvent {
            pubkey: ref_pk(),
            created_at: 1_700_000_000,
            kind: 3,
            tags,
            content: String::new(),
        };
        sign_event_deterministic(u, &ref_sk()).unwrap()
    }

    #[test]
    fn extract_follow_pubkeys_filters_invalid() {
        let good = "aa".repeat(32);
        let bad = "nothex";
        let other_tag = "not-a-p-tag";
        let mut ev = kind3_with_follows(&[&good, bad]);
        ev.tags.push(vec!["x".to_string(), other_tag.to_string()]);
        let extracted = extract_follow_pubkeys(&ev);
        assert_eq!(extracted, vec![good]);
    }

    #[test]
    fn extract_follow_pubkeys_normalizes_case() {
        let upper = "AB".repeat(32);
        let lower = "ab".repeat(32);
        let ev = kind3_with_follows(&[&upper]);
        let extracted = extract_follow_pubkeys(&ev);
        assert_eq!(extracted, vec![lower]);
    }

    #[test]
    fn is_pubkey_accepts_64_hex() {
        assert!(is_pubkey(&"aa".repeat(32)));
        assert!(is_pubkey(&"00".repeat(32)));
        assert!(is_pubkey(&"AB".repeat(32)));
    }

    #[test]
    fn is_pubkey_rejects_wrong_length() {
        assert!(!is_pubkey(""));
        assert!(!is_pubkey("aa"));
        assert!(!is_pubkey(&"aa".repeat(33)));
    }

    #[test]
    fn is_pubkey_rejects_non_hex() {
        let mut s = "aa".repeat(31);
        s.push_str("zz");
        assert!(!is_pubkey(&s));
    }

    #[test]
    fn refresh_body_parses_with_kind3_event() {
        let good = "aa".repeat(32);
        let ev = kind3_with_follows(&[&good]);
        let payload = json!({ "kind3_event": ev });
        let body: RefreshBody = serde_json::from_value(payload).unwrap();
        assert!(body.kind3_event.is_some());
        assert!(body.pubkeys.is_none());
    }

    #[test]
    fn refresh_body_parses_with_pubkey_list_fallback() {
        let good = "aa".repeat(32);
        let payload = json!({ "pubkeys": [good] });
        let body: RefreshBody = serde_json::from_value(payload).unwrap();
        assert_eq!(body.pubkeys.as_ref().unwrap().len(), 1);
        assert!(body.kind3_event.is_none());
    }

    #[test]
    fn override_body_requires_pubkey() {
        let bytes = serde_json::to_vec(&json!({})).unwrap();
        assert!(serde_json::from_slice::<OverrideBody>(&bytes).is_err());
    }
}
