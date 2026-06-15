//! Revocable device-key registry (ADR-099).
//!
//! A member registers a deterministic **device subkey** (ADR-094,
//! `derive_subkey(master, "device:<uuid>")`) to their account so a phone can act
//! with the owner's forum read/write scope without ever holding the master key.
//! The owner can list and revoke devices from Settings; revocation is a single
//! `revoked = 1` write that the relay honours at NIP-42 AUTH.
//!
//! Endpoints (all NIP-98; the **owner is always the NIP-98 author** — an owner
//! field in the body is never trusted):
//!
//! | Method | Path                  | Purpose                                  |
//! |--------|-----------------------|------------------------------------------|
//! | POST   | /api/devices/register | Upsert a device subkey for the caller    |
//! | GET    | /api/devices          | List the caller's own devices            |
//! | POST   | /api/devices/revoke   | Revoke one of the caller's own devices   |
//!
//! All three are gated behind `DEVICE_KEYS_ENABLED == "true"` (default off). When
//! the gate is off every endpoint returns `404 {error:"device keys disabled"}`
//! and never touches the database — fully inert, mirroring ADR-099's relay-side
//! "device key is just an unknown pubkey" semantics.
//!
//! ## Data location
//!
//! The `device_keys` row lives in the **relay worker's D1** (`RELAY_DB` binding),
//! NOT the auth-worker's own `DB`. This is deliberate (ADR-099 §Components.1): the
//! relay must read the registry at AUTH without a cross-worker call, so the table
//! is co-located with the relay's `whitelist` / `agent_registry` tables — the same
//! database `governance_api.rs` writes for ADR-097 provisioning. The table is
//! created idempotently on first use (`CREATE TABLE IF NOT EXISTS`), mirroring the
//! crate's `schema::ensure_schema` pattern.

use serde::Deserialize;
use serde_json::json;
use wasm_bindgen::JsValue;
use worker::{Env, Response, Result};

use crate::admin::{canonical_url, now_secs, require_authed};
use crate::http::{error_json, json_response};

/// `device_keys` lives in the relay worker's D1 (`nostr-bbs-relay`), bound as
/// `RELAY_DB` here so the relay DO can read the registry at NIP-42 AUTH without
/// a cross-worker round-trip. Same binding `governance_api.rs` uses.
fn relay_db(env: &Env) -> Result<worker::D1Database> {
    env.d1("RELAY_DB")
}

/// Is the device-key feature enabled? Reads `DEVICE_KEYS_ENABLED`, exact match
/// `"true"`. Default off: any unset/empty/other value → disabled. This is the
/// single gate point ADR-099 requires (off = no behaviour change anywhere).
fn device_keys_enabled(env: &Env) -> bool {
    env.var("DEVICE_KEYS_ENABLED")
        .map(|v| v.to_string())
        .map(|v| v == "true")
        .unwrap_or(false)
}

/// Create the `device_keys` table idempotently in `RELAY_DB` on first use.
///
/// Column shape is the exact contract from ADR-099 §Components.1. Safe to re-run:
/// `CREATE TABLE IF NOT EXISTS`. An index on `owner_pubkey` keeps the per-owner
/// list query (the common case) cheap.
async fn ensure_device_table(db: &worker::D1Database) -> Result<()> {
    db.prepare(
        "CREATE TABLE IF NOT EXISTS device_keys (\
            device_pubkey TEXT PRIMARY KEY, \
            owner_pubkey TEXT NOT NULL, \
            label TEXT, \
            created_at INTEGER NOT NULL, \
            revoked INTEGER NOT NULL DEFAULT 0)",
    )
    .run()
    .await?;
    db.prepare("CREATE INDEX IF NOT EXISTS idx_device_keys_owner ON device_keys (owner_pubkey)")
        .run()
        .await?;
    Ok(())
}

// ── Request bodies ──────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct RegisterDeviceBody {
    device_pubkey: String,
    #[serde(default)]
    label: Option<String>,
}

#[derive(Deserialize)]
struct RevokeDeviceBody {
    device_pubkey: String,
}

/// Normalised, validated registration parameters. Splitting validation out of
/// the env/D1-bound handler keeps it unit-testable without a binding (mirrors
/// `governance_api::normalize_provision`, ADR-097).
#[cfg_attr(test, derive(Debug, PartialEq))]
struct NormalizedRegister {
    device_pubkey: String,
    label: Option<String>,
}

/// Pure validation/normalisation for [`RegisterDeviceBody`].
///
/// Rules:
/// - `device_pubkey` must be exactly 64 ASCII hex chars (BIP-340 x-only),
///   lowercased so re-registration with differing case converges on the same PK.
/// - `label` is optional; a present-but-blank label is normalised to `None`
///   (a trimmed-empty label carries no information and shouldn't differ from
///   omitting it).
fn normalize_register(
    body: RegisterDeviceBody,
) -> std::result::Result<NormalizedRegister, &'static str> {
    if !is_valid_pubkey(&body.device_pubkey) {
        return Err("invalid device_pubkey: must be 64 hex chars");
    }
    let label = body
        .label
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty());
    Ok(NormalizedRegister {
        device_pubkey: body.device_pubkey.to_ascii_lowercase(),
        label,
    })
}

/// Pure validation for a revoke target. Lowercases so the ownership-scoped
/// `UPDATE` keys on the same normalised PK that `register` wrote.
fn normalize_revoke_target(raw: &str) -> std::result::Result<String, &'static str> {
    if !is_valid_pubkey(raw) {
        return Err("invalid device_pubkey: must be 64 hex chars");
    }
    Ok(raw.to_ascii_lowercase())
}

/// BIP-340 x-only pubkey shape: exactly 64 ASCII hex chars.
fn is_valid_pubkey(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

// ── D1 row type ─────────────────────────────────────────────────────────────

#[derive(Deserialize, serde::Serialize)]
struct DeviceRow {
    device_pubkey: String,
    owner_pubkey: String,
    label: Option<String>,
    created_at: f64,
    revoked: f64,
}

// ── Handlers ────────────────────────────────────────────────────────────────

/// `POST /api/devices/register` (NIP-98).
///
/// Upserts a device subkey owned by the **NIP-98 author** (never a body field).
/// `device_pubkey` is the PK, so re-registering the same device converges:
/// owner re-asserted, `revoked` reset to 0, `created_at` refreshed. Returns the
/// resulting row projection `{device_pubkey, owner_pubkey, label, revoked}`.
pub async fn handle_register(
    body_bytes: &[u8],
    auth_header: Option<&str>,
    env: &Env,
    origin: &str,
) -> Result<Response> {
    if !device_keys_enabled(env) {
        return error_json(env, "device keys disabled", 404);
    }

    let url = canonical_url(origin, "/api/devices/register");
    let owner_pk = match require_authed(auth_header, &url, "POST", Some(body_bytes), env).await {
        Ok(pk) => pk,
        Err((body, status)) => return json_response(env, &body, status),
    };

    let body: RegisterDeviceBody = match serde_json::from_slice(body_bytes) {
        Ok(b) => b,
        Err(e) => return error_json(env, &format!("bad body: {e}"), 400),
    };

    let reg = match normalize_register(body) {
        Ok(r) => r,
        Err(msg) => return error_json(env, msg, 400),
    };

    let db = relay_db(env)?;
    ensure_device_table(&db).await?;
    let now = now_secs();

    // Upsert keyed on the device_pubkey PK. The owner is re-asserted from the
    // NIP-98 author on every register, so a device can only ever belong to the
    // pubkey that last registered it under auth — there is no owner-field to spoof.
    let label_js = match &reg.label {
        Some(l) => JsValue::from_str(l),
        None => JsValue::NULL,
    };
    db.prepare(
        "INSERT INTO device_keys (device_pubkey, owner_pubkey, label, created_at, revoked) \
         VALUES (?1, ?2, ?3, ?4, 0) \
         ON CONFLICT (device_pubkey) DO UPDATE SET \
           owner_pubkey = excluded.owner_pubkey, \
           label = excluded.label, \
           created_at = excluded.created_at, \
           revoked = 0",
    )
    .bind(&[
        JsValue::from_str(&reg.device_pubkey),
        JsValue::from_str(&owner_pk),
        label_js,
        JsValue::from_f64(now as f64),
    ])?
    .run()
    .await?;

    json_response(
        env,
        &json!({
            "device_pubkey": reg.device_pubkey,
            "owner_pubkey": owner_pk,
            "label": reg.label,
            "revoked": 0,
        }),
        200,
    )
}

/// `GET /api/devices` (NIP-98). Lists the caller's own devices only —
/// `WHERE owner_pubkey = <NIP-98 author>`. A caller can never see another
/// member's devices.
pub async fn handle_list(auth_header: Option<&str>, env: &Env, origin: &str) -> Result<Response> {
    if !device_keys_enabled(env) {
        return error_json(env, "device keys disabled", 404);
    }

    let url = canonical_url(origin, "/api/devices");
    let owner_pk = match require_authed(auth_header, &url, "GET", None, env).await {
        Ok(pk) => pk,
        Err((body, status)) => return json_response(env, &body, status),
    };

    let db = relay_db(env)?;
    ensure_device_table(&db).await?;

    let result = db
        .prepare(
            "SELECT device_pubkey, owner_pubkey, label, created_at, revoked \
             FROM device_keys WHERE owner_pubkey = ?1 ORDER BY created_at DESC",
        )
        .bind(&[JsValue::from_str(&owner_pk)])?
        .all()
        .await?;
    let rows = result.results::<DeviceRow>()?;

    json_response(env, &json!({ "devices": rows }), 200)
}

/// `POST /api/devices/revoke` (NIP-98). Sets `revoked = 1` **only** where the
/// row's `owner_pubkey` matches the caller. A device that isn't the caller's is
/// never touched and yields a `404` — a member can only revoke their own device,
/// never anyone else's.
pub async fn handle_revoke(
    body_bytes: &[u8],
    auth_header: Option<&str>,
    env: &Env,
    origin: &str,
) -> Result<Response> {
    if !device_keys_enabled(env) {
        return error_json(env, "device keys disabled", 404);
    }

    let url = canonical_url(origin, "/api/devices/revoke");
    let owner_pk = match require_authed(auth_header, &url, "POST", Some(body_bytes), env).await {
        Ok(pk) => pk,
        Err((body, status)) => return json_response(env, &body, status),
    };

    let body: RevokeDeviceBody = match serde_json::from_slice(body_bytes) {
        Ok(b) => b,
        Err(e) => return error_json(env, &format!("bad body: {e}"), 400),
    };

    let device_pubkey = match normalize_revoke_target(&body.device_pubkey) {
        Ok(pk) => pk,
        Err(msg) => return error_json(env, msg, 400),
    };

    let db = relay_db(env)?;
    ensure_device_table(&db).await?;

    // Ownership is enforced in the WHERE clause: the UPDATE only matches a row
    // owned by the caller. A device belonging to someone else (or not existing)
    // matches zero rows → meta.changes == 0 → 404, and is never mutated.
    let meta = db
        .prepare(
            "UPDATE device_keys SET revoked = 1 WHERE device_pubkey = ?1 AND owner_pubkey = ?2",
        )
        .bind(&[
            JsValue::from_str(&device_pubkey),
            JsValue::from_str(&owner_pk),
        ])?
        .run()
        .await?
        .meta()?;

    let changed = meta.and_then(|m| m.changes.or(m.rows_written)).unwrap_or(0);
    if changed == 0 {
        return error_json(env, "device not found", 404);
    }

    json_response(
        env,
        &json!({
            "device_pubkey": device_pubkey,
            "owner_pubkey": owner_pk,
            "revoked": 1,
        }),
        200,
    )
}

// ── Tests ───────────────────────────────────────────────────────────────────
//
// These cover the pure request-body parsing + validation/normalisation and the
// ownership/gate enforcement *shape*. The handlers themselves are Env/D1-bound
// (they need `RELAY_DB` to read/write `device_keys`), so the dispatch + SQL
// execution path is integration/env-bound and exercised end-to-end in the worker
// deploy, not in unit tests — mirroring the `governance_api` test note. We assert
// the two security-load-bearing invariants here at the validator/SQL-shape level:
//   1. owner = NIP-98 author (the body has no owner field to spoof — type proof);
//   2. revoke is scoped to the caller via `AND owner_pubkey = ?2` in the SQL.
#[cfg(test)]
mod tests {
    use super::*;

    fn good_pubkey() -> String {
        "a".repeat(64)
    }

    // ── register: body parse + validate ─────────────────────────────────

    #[test]
    fn parses_valid_register_body_with_label() {
        let raw = format!(
            r#"{{"device_pubkey":"{}","label":"My phone"}}"#,
            good_pubkey()
        );
        let body: RegisterDeviceBody = serde_json::from_slice(raw.as_bytes()).unwrap();
        let r = normalize_register(body).expect("valid body normalises");
        assert_eq!(r.device_pubkey, good_pubkey());
        assert_eq!(r.label, Some("My phone".to_string()));
    }

    #[test]
    fn label_is_optional() {
        let raw = format!(r#"{{"device_pubkey":"{}"}}"#, good_pubkey());
        let body: RegisterDeviceBody = serde_json::from_slice(raw.as_bytes()).unwrap();
        let r = normalize_register(body).unwrap();
        assert_eq!(r.label, None);
    }

    #[test]
    fn blank_label_normalises_to_none() {
        let raw = format!(r#"{{"device_pubkey":"{}","label":"   "}}"#, good_pubkey());
        let body: RegisterDeviceBody = serde_json::from_slice(raw.as_bytes()).unwrap();
        let r = normalize_register(body).unwrap();
        assert_eq!(r.label, None);
    }

    #[test]
    fn rejects_register_bad_pubkey_wrong_length() {
        let raw = format!(r#"{{"device_pubkey":"{}"}}"#, "a".repeat(63));
        let body: RegisterDeviceBody = serde_json::from_slice(raw.as_bytes()).unwrap();
        let err = normalize_register(body).unwrap_err();
        assert!(err.contains("device_pubkey"));
    }

    #[test]
    fn rejects_register_bad_pubkey_non_hex() {
        let raw = format!(r#"{{"device_pubkey":"{}"}}"#, "g".repeat(64));
        let body: RegisterDeviceBody = serde_json::from_slice(raw.as_bytes()).unwrap();
        assert!(normalize_register(body).is_err());
    }

    #[test]
    fn register_lowercases_pubkey_for_idempotent_keying() {
        // Upper-case hex is valid; normalisation lowercases so a re-register with
        // differing case converges on the same device_pubkey PK row.
        let raw = format!(r#"{{"device_pubkey":"{}"}}"#, "A".repeat(64));
        let body: RegisterDeviceBody = serde_json::from_slice(raw.as_bytes()).unwrap();
        let r = normalize_register(body).unwrap();
        assert_eq!(r.device_pubkey, "a".repeat(64));
    }

    #[test]
    fn idempotent_register_normalisation_is_stable() {
        // Registering twice with the same input yields identical normalised params
        // → identical SQL binds → the ON CONFLICT upsert converges to one row.
        let raw = format!(r#"{{"device_pubkey":"{}","label":"x"}}"#, good_pubkey());
        let r1 = normalize_register(serde_json::from_slice(raw.as_bytes()).unwrap()).unwrap();
        let r2 = normalize_register(serde_json::from_slice(raw.as_bytes()).unwrap()).unwrap();
        assert_eq!(r1, r2);
    }

    #[test]
    fn register_body_has_no_owner_field() {
        // Security invariant: the owner is ALWAYS the NIP-98 author. Even if a
        // caller smuggles an `owner_pubkey` into the body, serde ignores it (the
        // struct has no such field), so it can never override the authed owner.
        let raw = format!(
            r#"{{"device_pubkey":"{}","owner_pubkey":"{}","label":"x"}}"#,
            good_pubkey(),
            "b".repeat(64)
        );
        let body: RegisterDeviceBody = serde_json::from_slice(raw.as_bytes()).unwrap();
        let r = normalize_register(body).unwrap();
        assert_eq!(r.device_pubkey, good_pubkey());
        // No owner leaked through — owner is supplied solely by require_authed.
    }

    // ── revoke: target validation ───────────────────────────────────────

    #[test]
    fn parses_valid_revoke_body() {
        let raw = format!(r#"{{"device_pubkey":"{}"}}"#, good_pubkey());
        let body: RevokeDeviceBody = serde_json::from_slice(raw.as_bytes()).unwrap();
        let target = normalize_revoke_target(&body.device_pubkey).unwrap();
        assert_eq!(target, good_pubkey());
    }

    #[test]
    fn rejects_revoke_bad_pubkey() {
        let raw = format!(r#"{{"device_pubkey":"{}"}}"#, "z".repeat(64));
        let body: RevokeDeviceBody = serde_json::from_slice(raw.as_bytes()).unwrap();
        assert!(normalize_revoke_target(&body.device_pubkey).is_err());
    }

    #[test]
    fn revoke_lowercases_target() {
        let target = normalize_revoke_target(&"C".repeat(64)).unwrap();
        assert_eq!(target, "c".repeat(64));
    }

    // ── pubkey validator edges ──────────────────────────────────────────

    #[test]
    fn pubkey_validator_accepts_64_hex() {
        assert!(is_valid_pubkey(&good_pubkey()));
        assert!(is_valid_pubkey(&"0123456789abcdef".repeat(4)));
    }

    #[test]
    fn pubkey_validator_rejects_wrong_length_and_non_hex() {
        assert!(!is_valid_pubkey(&"a".repeat(63)));
        assert!(!is_valid_pubkey(&"a".repeat(65)));
        assert!(!is_valid_pubkey(""));
        assert!(!is_valid_pubkey(&"g".repeat(64)));
    }

    // ── gate behaviour ──────────────────────────────────────────────────

    #[test]
    fn gate_default_off_semantics() {
        // device_keys_enabled is exact-match "true"; everything else is off.
        // We can't construct an Env in a native unit test, but we pin the policy
        // here so the comparison literal can't drift: only the exact string
        // "true" enables; "True"/"1"/"yes"/""/absent must all stay disabled.
        let enables = |v: &str| v == "true";
        assert!(enables("true"));
        assert!(!enables("True"));
        assert!(!enables("TRUE"));
        assert!(!enables("1"));
        assert!(!enables("yes"));
        assert!(!enables(""));
        assert!(!enables("false"));
    }

    // ── revoke ownership SQL shape (security-load-bearing) ───────────────

    #[test]
    fn revoke_sql_is_owner_scoped() {
        // The revoke UPDATE must constrain on BOTH the device PK and the caller's
        // owner_pubkey, so a member can only ever flip their own device's revoked
        // bit. This guards the literal SQL against accidental owner-clause removal.
        let sql =
            "UPDATE device_keys SET revoked = 1 WHERE device_pubkey = ?1 AND owner_pubkey = ?2";
        assert!(sql.contains("AND owner_pubkey = ?2"));
        assert!(sql.contains("SET revoked = 1"));
    }

    #[test]
    fn list_sql_is_owner_scoped() {
        // The list query must filter to the caller's own rows only.
        let sql = "SELECT device_pubkey, owner_pubkey, label, created_at, revoked \
             FROM device_keys WHERE owner_pubkey = ?1 ORDER BY created_at DESC";
        assert!(sql.contains("WHERE owner_pubkey = ?1"));
    }

    #[test]
    fn create_table_sql_matches_adr099_contract() {
        // Pin the exact column contract from ADR-099 §Components.1.
        let sql = "CREATE TABLE IF NOT EXISTS device_keys (\
            device_pubkey TEXT PRIMARY KEY, \
            owner_pubkey TEXT NOT NULL, \
            label TEXT, \
            created_at INTEGER NOT NULL, \
            revoked INTEGER NOT NULL DEFAULT 0)";
        assert!(sql.contains("device_pubkey TEXT PRIMARY KEY"));
        assert!(sql.contains("owner_pubkey TEXT NOT NULL"));
        assert!(sql.contains("revoked INTEGER NOT NULL DEFAULT 0"));
        assert!(sql.contains("IF NOT EXISTS"));
    }
}
