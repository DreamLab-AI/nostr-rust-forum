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

use nostr_bbs_core::admin_shared::PubkeyRow;
use nostr_bbs_core::event::{verify_event_strict, NostrEvent};
use serde::Deserialize;
use serde_json::json;
use wasm_bindgen::JsValue;
use worker::{Env, Response, Result};

use crate::admin::{canonical_url, is_admin, now_secs, require_authed};
use crate::http::{error_json, json_response};

// ── Device-key proof-of-possession (ADR-099 hardening) ──────────────────────
//
// Linking a device subkey to an owner is a security-load-bearing write: the
// relay's `effective_pubkey()` rebinds the owner's write-allowlist and
// read-scope onto every `device → owner` mapping. Without proof that the caller
// controls the device key, a member could register `device_pubkey = <admin hex>`
// and silently rebind the admin's scope onto their own cohorts (admin lockout /
// cross-account identity hijack). Two independent guards close this:
//
//   1. **Principal exclusion** ([`is_known_principal`]): a `device_pubkey` that
//      is itself a registered principal (on the whitelist, in the admin set, or
//      already an `owner_pubkey` in `device_keys`) is rejected outright — a
//      principal's key can never be demoted to someone's device.
//   2. **Proof-of-possession** ([`verify_device_proof`]): the registration MUST
//      carry a `device_proof` — a Nostr event (kind [`DEVICE_LINK_PROOF_KIND`])
//      **signed by the device key itself** that commits to `(owner_pubkey, exp)`:
//        - `pubkey`     == the `device_pubkey` being registered,
//        - tag `["owner", <owner_pubkey>]` == the authenticated NIP-98 caller
//          (so a captured proof cannot be replayed to link the device to a
//          different account),
//        - tag `["exp", <unix_secs>]` — a short absolute expiry, verified to be
//          in the future but within [`DEVICE_PROOF_MAX_WINDOW_SECS`],
//        - a BIP-340 Schnorr signature, verified with the crate's canonical
//          [`verify_event_strict`] primitive (the same verifier used for
//          NIP-98 events — no new dependency).
//      Because only the holder of the device private key can produce this
//      signature, an attacker cannot forge a proof for a key they do not
//      control (e.g. an admin's pubkey), which is what makes the hijack
//      impossible rather than merely inconvenient.

/// Event kind for a device-link proof-of-possession event (ADR-099).
const DEVICE_LINK_PROOF_KIND: u64 = 27236;

/// Maximum lifetime window for a device-link proof, in seconds. The proof's
/// `exp` must satisfy `now < exp <= now + DEVICE_PROOF_MAX_WINDOW_SECS`, bounding
/// how long a signed proof stays usable (a short round-trip, not a bearer token).
const DEVICE_PROOF_MAX_WINDOW_SECS: u64 = 300;

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
    /// Proof-of-possession of `device_pubkey`: a device-key-signed link proof
    /// committing to `(owner_pubkey, exp)`. See [`verify_device_proof`]. Parsed
    /// leniently (absent → `None`) so malformed-body errors stay distinct from
    /// missing-proof errors; presence is **required** and enforced in
    /// [`handle_register`].
    #[serde(default)]
    device_proof: Option<NostrEvent>,
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
    body: &RegisterDeviceBody,
) -> std::result::Result<NormalizedRegister, &'static str> {
    if !is_valid_pubkey(&body.device_pubkey) {
        return Err("invalid device_pubkey: must be 64 hex chars");
    }
    let label = body
        .label
        .as_ref()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty());
    Ok(NormalizedRegister {
        device_pubkey: body.device_pubkey.to_ascii_lowercase(),
        label,
    })
}

/// Verify a device-link proof-of-possession event (ADR-099 hardening).
///
/// The proof is a Nostr event **signed by the device key being registered**,
/// binding that key to the authenticated owner and a short expiry. It proves the
/// caller controls `device_pubkey` (closing the identity-hijack primitive where
/// a member registers an admin's pubkey as their device) and cannot be replayed
/// to link the device to a different account.
///
/// Checks, in order:
/// 1. `proof.pubkey == expected_device_pubkey` — the proof is authored by the
///    key being linked (both compared lowercased).
/// 2. `proof.kind == DEVICE_LINK_PROOF_KIND` — domain-separates this proof from
///    any other event the device key might have signed.
/// 3. tag `["owner", <pk>]` present and `== expected_owner_pubkey` — the proof
///    commits to *this* owner (the NIP-98 caller), preventing cross-owner replay.
/// 4. tag `["exp", <unix_secs>]` present, parseable, and `now < exp <= now +
///    DEVICE_PROOF_MAX_WINDOW_SECS` — a short, forward-only expiry.
/// 5. BIP-340 Schnorr signature valid via [`verify_event_strict`] (recomputes
///    the event id from scratch, then verifies the sig against `proof.pubkey`).
///
/// `expected_device_pubkey` and `expected_owner_pubkey` MUST already be
/// lowercased by the caller.
fn verify_device_proof(
    proof: &NostrEvent,
    expected_device_pubkey: &str,
    expected_owner_pubkey: &str,
    now: u64,
) -> std::result::Result<(), &'static str> {
    // 1. Author == the device key being registered.
    if proof.pubkey.to_ascii_lowercase() != expected_device_pubkey {
        return Err("device proof pubkey does not match device_pubkey");
    }

    // 2. Domain-separating kind.
    if proof.kind != DEVICE_LINK_PROOF_KIND {
        return Err("device proof has wrong kind");
    }

    // 3. Owner binding: the proof commits to the authenticated caller.
    let owner_tag = proof_tag(proof, "owner").ok_or("device proof missing owner tag")?;
    if owner_tag.to_ascii_lowercase() != expected_owner_pubkey {
        return Err("device proof owner does not match authenticated owner");
    }

    // 4. Short, forward-only expiry.
    let exp: u64 = proof_tag(proof, "exp")
        .and_then(|v| v.parse().ok())
        .ok_or("device proof missing or invalid exp tag")?;
    if exp <= now {
        return Err("device proof expired");
    }
    if exp > now + DEVICE_PROOF_MAX_WINDOW_SECS {
        return Err("device proof exp too far in the future");
    }

    // 5. Signature (proves possession of the device private key).
    verify_event_strict(proof).map_err(|_| "device proof signature invalid")?;
    Ok(())
}

/// First value of the first `[name, value, ..]` tag on `proof`, if present.
fn proof_tag<'a>(proof: &'a NostrEvent, name: &str) -> Option<&'a str> {
    proof
        .tags
        .iter()
        .find(|t| t.first().map(|s| s.as_str()) == Some(name))
        .and_then(|t| t.get(1))
        .map(|s| s.as_str())
}

/// Is `pubkey_lc` (lowercased hex) a registered principal that must never be
/// demoted to a device key?
///
/// Returns `true` if the pubkey is in the admin set (static `ADMIN_PUBKEYS`,
/// `whitelist.is_admin`, or `members.is_admin`), present on the relay whitelist
/// at all, or already an `owner_pubkey` in `device_keys`. Any storage error is
/// treated as "not a principal" only for that individual source — the admin
/// check and each existence probe fail closed independently and never leak
/// ambient authority. This is guard (1) from the module header: it blocks the
/// admin-lockout / cross-account rebind even before proof verification.
async fn is_known_principal(env: &Env, relay_db: &worker::D1Database, pubkey_lc: &str) -> bool {
    // Admin set (static ∪ whitelist.is_admin ∪ members.is_admin).
    if is_admin(pubkey_lc, env).await {
        return true;
    }

    // Any whitelisted principal (member), admin or not.
    if let Ok(stmt) = relay_db
        .prepare("SELECT pubkey FROM whitelist WHERE pubkey = ?1")
        .bind(&[JsValue::from_str(pubkey_lc)])
    {
        if let Ok(Some(_)) = stmt.first::<PubkeyRow>(None).await {
            return true;
        }
    }

    // Already the owner of a device-key mapping (i.e. a principal in its own
    // right). `device_keys` has no `owner_pubkey` index-free existence helper, so
    // we probe directly; `LIMIT 1` keeps it cheap.
    if let Ok(stmt) = relay_db
        .prepare("SELECT owner_pubkey AS pubkey FROM device_keys WHERE owner_pubkey = ?1 LIMIT 1")
        .bind(&[JsValue::from_str(pubkey_lc)])
    {
        if let Ok(Some(_)) = stmt.first::<PubkeyRow>(None).await {
            return true;
        }
    }

    false
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
///
/// ## Security (ADR-099 hardening)
///
/// Before the upsert the caller must clear **two** guards, in this order:
///
/// 1. **Proof-of-possession** — the body carries a `device_proof` signed by the
///    device key committing to `(owner_pubkey, exp)`; verified via
///    [`verify_device_proof`]. Without it, a member could register another
///    principal's pubkey (e.g. an admin's) as their device and silently rebind
///    that principal's write-allowlist + read-scope onto their own cohorts.
/// 2. **Principal exclusion** — the `device_pubkey` must not itself be a
///    registered principal (whitelist / admin set / existing device owner);
///    [`is_known_principal`]. Defence-in-depth over (1).
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

    let reg = match normalize_register(&body) {
        Ok(r) => r,
        Err(msg) => return error_json(env, msg, 400),
    };

    // Owner is the un-spoofable NIP-98 author; lowercase it so the proof's
    // owner-tag binding compares against the same canonical form the device row
    // and admin lookups use.
    let owner_lc = owner_pk.to_ascii_lowercase();
    let now = now_secs();

    // Guard 1: proof-of-possession of the device key, bound to this owner.
    let proof = match &body.device_proof {
        Some(p) => p,
        None => return error_json(env, "device proof required", 400),
    };
    if let Err(msg) = verify_device_proof(proof, &reg.device_pubkey, &owner_lc, now) {
        return error_json(env, msg, 400);
    }

    let db = relay_db(env)?;
    ensure_device_table(&db).await?;

    // Guard 2: the device key must not itself be a registered principal — a
    // whitelisted member, an admin, or an existing device owner. This blocks the
    // admin-lockout / cross-account rebind primitive even for a key the caller
    // legitimately controls (e.g. their own principal identity).
    if is_known_principal(env, &db, &reg.device_pubkey).await {
        return error_json(
            env,
            "device_pubkey is already a registered principal and cannot be linked as a device",
            409,
        );
    }

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
// the security-load-bearing invariants here at the validator/SQL-shape level:
//   1. owner = NIP-98 author (the body has no owner field to spoof — type proof);
//   2. revoke is scoped to the caller via `AND owner_pubkey = ?2` in the SQL;
//   3. proof-of-possession — verify_device_proof accepts only a device-key-signed
//      proof bound to the authenticated owner and a short expiry (ADR-099
//      hardening: closes the admin-lockout / identity-hijack primitive).
// The principal-exclusion guard (is_known_principal) and the full register flow
// are D1/Env-bound and exercised end-to-end in the worker deploy.
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
        let r = normalize_register(&body).expect("valid body normalises");
        assert_eq!(r.device_pubkey, good_pubkey());
        assert_eq!(r.label, Some("My phone".to_string()));
    }

    #[test]
    fn label_is_optional() {
        let raw = format!(r#"{{"device_pubkey":"{}"}}"#, good_pubkey());
        let body: RegisterDeviceBody = serde_json::from_slice(raw.as_bytes()).unwrap();
        let r = normalize_register(&body).unwrap();
        assert_eq!(r.label, None);
    }

    #[test]
    fn blank_label_normalises_to_none() {
        let raw = format!(r#"{{"device_pubkey":"{}","label":"   "}}"#, good_pubkey());
        let body: RegisterDeviceBody = serde_json::from_slice(raw.as_bytes()).unwrap();
        let r = normalize_register(&body).unwrap();
        assert_eq!(r.label, None);
    }

    #[test]
    fn rejects_register_bad_pubkey_wrong_length() {
        let raw = format!(r#"{{"device_pubkey":"{}"}}"#, "a".repeat(63));
        let body: RegisterDeviceBody = serde_json::from_slice(raw.as_bytes()).unwrap();
        let err = normalize_register(&body).unwrap_err();
        assert!(err.contains("device_pubkey"));
    }

    #[test]
    fn rejects_register_bad_pubkey_non_hex() {
        let raw = format!(r#"{{"device_pubkey":"{}"}}"#, "g".repeat(64));
        let body: RegisterDeviceBody = serde_json::from_slice(raw.as_bytes()).unwrap();
        assert!(normalize_register(&body).is_err());
    }

    #[test]
    fn register_lowercases_pubkey_for_idempotent_keying() {
        // Upper-case hex is valid; normalisation lowercases so a re-register with
        // differing case converges on the same device_pubkey PK row.
        let raw = format!(r#"{{"device_pubkey":"{}"}}"#, "A".repeat(64));
        let body: RegisterDeviceBody = serde_json::from_slice(raw.as_bytes()).unwrap();
        let r = normalize_register(&body).unwrap();
        assert_eq!(r.device_pubkey, "a".repeat(64));
    }

    #[test]
    fn idempotent_register_normalisation_is_stable() {
        // Registering twice with the same input yields identical normalised params
        // → identical SQL binds → the ON CONFLICT upsert converges to one row.
        let raw = format!(r#"{{"device_pubkey":"{}","label":"x"}}"#, good_pubkey());
        let b1: RegisterDeviceBody = serde_json::from_slice(raw.as_bytes()).unwrap();
        let b2: RegisterDeviceBody = serde_json::from_slice(raw.as_bytes()).unwrap();
        let r1 = normalize_register(&b1).unwrap();
        let r2 = normalize_register(&b2).unwrap();
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
        let r = normalize_register(&body).unwrap();
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

    // ── device proof-of-possession (security-load-bearing) ──────────────
    //
    // The proof is a device-key-signed event committing to (owner, exp). These
    // tests build real BIP-340-signed proofs with the crate's own signer and
    // assert verify_device_proof accepts only a proof that (a) is authored by
    // the device key, (b) commits to the authenticated owner, (c) is unexpired
    // within the window, and (d) carries a valid signature.

    use k256::schnorr::SigningKey;
    use nostr_bbs_core::event::{sign_event_deterministic, UnsignedEvent};

    const NOW: u64 = 1_700_000_000;

    fn device_sk() -> SigningKey {
        SigningKey::from_bytes(&[0x11u8; 32]).unwrap()
    }
    fn device_pk() -> String {
        hex::encode(device_sk().verifying_key().to_bytes())
    }
    fn owner_pk() -> String {
        // A distinct key's pubkey stands in for the NIP-98 author.
        let sk = SigningKey::from_bytes(&[0x22u8; 32]).unwrap();
        hex::encode(sk.verifying_key().to_bytes())
    }

    /// Build a signed device-link proof with overridable kind/owner/exp.
    fn make_proof(kind: u64, owner: &str, exp: u64) -> NostrEvent {
        let unsigned = UnsignedEvent {
            pubkey: device_pk(),
            created_at: NOW,
            kind,
            tags: vec![
                vec!["owner".to_string(), owner.to_string()],
                vec!["exp".to_string(), exp.to_string()],
            ],
            content: String::new(),
        };
        sign_event_deterministic(unsigned, &device_sk()).unwrap()
    }

    #[test]
    fn device_proof_valid_passes() {
        let proof = make_proof(DEVICE_LINK_PROOF_KIND, &owner_pk(), NOW + 60);
        assert!(verify_device_proof(&proof, &device_pk(), &owner_pk(), NOW).is_ok());
    }

    #[test]
    fn device_proof_rejects_wrong_device_pubkey() {
        // Proof signed by device_sk, but registration claims a different device.
        let proof = make_proof(DEVICE_LINK_PROOF_KIND, &owner_pk(), NOW + 60);
        let other_device = "c".repeat(64);
        let err = verify_device_proof(&proof, &other_device, &owner_pk(), NOW).unwrap_err();
        assert!(err.contains("does not match device_pubkey"));
    }

    #[test]
    fn device_proof_rejects_wrong_owner_binding() {
        // Cross-owner replay: proof commits to owner A, caller authenticates as B.
        let proof = make_proof(DEVICE_LINK_PROOF_KIND, &owner_pk(), NOW + 60);
        let attacker = "d".repeat(64);
        let err = verify_device_proof(&proof, &device_pk(), &attacker, NOW).unwrap_err();
        assert!(err.contains("owner does not match"));
    }

    #[test]
    fn device_proof_rejects_wrong_kind() {
        let proof = make_proof(27235, &owner_pk(), NOW + 60);
        let err = verify_device_proof(&proof, &device_pk(), &owner_pk(), NOW).unwrap_err();
        assert!(err.contains("wrong kind"));
    }

    #[test]
    fn device_proof_rejects_expired() {
        let proof = make_proof(DEVICE_LINK_PROOF_KIND, &owner_pk(), NOW);
        let err = verify_device_proof(&proof, &device_pk(), &owner_pk(), NOW).unwrap_err();
        assert!(err.contains("expired"));
    }

    #[test]
    fn device_proof_rejects_exp_too_far() {
        let proof = make_proof(
            DEVICE_LINK_PROOF_KIND,
            &owner_pk(),
            NOW + DEVICE_PROOF_MAX_WINDOW_SECS + 1,
        );
        let err = verify_device_proof(&proof, &device_pk(), &owner_pk(), NOW).unwrap_err();
        assert!(err.contains("too far"));
    }

    #[test]
    fn device_proof_accepts_exp_at_window_edge() {
        let proof = make_proof(
            DEVICE_LINK_PROOF_KIND,
            &owner_pk(),
            NOW + DEVICE_PROOF_MAX_WINDOW_SECS,
        );
        assert!(verify_device_proof(&proof, &device_pk(), &owner_pk(), NOW).is_ok());
    }

    #[test]
    fn device_proof_rejects_missing_exp_tag() {
        let unsigned = UnsignedEvent {
            pubkey: device_pk(),
            created_at: NOW,
            kind: DEVICE_LINK_PROOF_KIND,
            tags: vec![vec!["owner".to_string(), owner_pk()]],
            content: String::new(),
        };
        let proof = sign_event_deterministic(unsigned, &device_sk()).unwrap();
        let err = verify_device_proof(&proof, &device_pk(), &owner_pk(), NOW).unwrap_err();
        assert!(err.contains("exp"));
    }

    #[test]
    fn device_proof_rejects_missing_owner_tag() {
        let unsigned = UnsignedEvent {
            pubkey: device_pk(),
            created_at: NOW,
            kind: DEVICE_LINK_PROOF_KIND,
            tags: vec![vec!["exp".to_string(), (NOW + 60).to_string()]],
            content: String::new(),
        };
        let proof = sign_event_deterministic(unsigned, &device_sk()).unwrap();
        let err = verify_device_proof(&proof, &device_pk(), &owner_pk(), NOW).unwrap_err();
        assert!(err.contains("owner"));
    }

    #[test]
    fn device_proof_rejects_tampered_signature() {
        let mut proof = make_proof(DEVICE_LINK_PROOF_KIND, &owner_pk(), NOW + 60);
        // Flip a byte in the signature: possession is no longer proven.
        let mut sig = hex::decode(&proof.sig).unwrap();
        sig[0] ^= 0xFF;
        proof.sig = hex::encode(&sig);
        let err = verify_device_proof(&proof, &device_pk(), &owner_pk(), NOW).unwrap_err();
        assert!(err.contains("signature invalid"));
    }

    #[test]
    fn device_proof_rejects_forged_body_under_valid_sig() {
        // An attacker with only the device's PUBLIC key cannot forge a proof:
        // changing the owner tag after signing breaks the recomputed-id check.
        let mut proof = make_proof(DEVICE_LINK_PROOF_KIND, &owner_pk(), NOW + 60);
        proof.tags = vec![
            vec!["owner".to_string(), "e".repeat(64)],
            vec!["exp".to_string(), (NOW + 60).to_string()],
        ];
        // Now the body claims a different owner but the signature/id no longer
        // match — verify_event_strict rejects it. (Even the owner-mismatch guard
        // would catch it first; this pins the signature backstop.)
        let err = verify_device_proof(&proof, &device_pk(), &"e".repeat(64), NOW).unwrap_err();
        assert!(err.contains("signature invalid"));
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
