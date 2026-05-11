//! WI-5 Welcome bot -- admin configuration + first-registration greeter.
//!
//! The welcome bot keeps its `nsec` encrypted at rest (see `crypto.rs`) and
//! emits a signed Nostr kind-1 message whenever a new pubkey registers for
//! the first time. Messages are localised from `CF-IPCountry` (Spanish for
//! `ES`/`MX`/`AR`/`CL`/`CO`, English otherwise). Queued outbox rows live in
//! `welcome_messages`; the relay-worker or an external relay-publish cron
//! forwards them to the configured relay.
//!
//! | Method | Path                           | Auth  | Purpose                            |
//! |--------|--------------------------------|-------|------------------------------------|
//! | GET    | /api/welcome/config            | admin | Current welcome config             |
//! | POST   | /api/welcome/configure         | admin | Set enabled / channel / messages   |
//! | POST   | /api/welcome/set-bot-key       | admin | Upload & encrypt the bot nsec      |
//! | POST   | /api/welcome/test              | admin | Dry-run: return a signed event     |

use nostr_bbs_core::d1_helpers::{js_i64, js_str};
use nostr_bbs_core::keys::signing_key_from_bytes;
use nostr_bbs_core::{sign_event_deterministic, UnsignedEvent};
use serde::Deserialize;
use serde_json::json;
use wasm_bindgen::JsValue;
use worker::{Env, Response, Result};

use crate::admin::{canonical_url, now_secs, require_admin};
use crate::crypto::{decrypt_nsec, encrypt_nsec_hex};
use crate::http::{error_json, json_response};

// ---------------------------------------------------------------------------
// Request bodies
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct ConfigureBody {
    enabled: Option<bool>,
    channel_id: Option<String>,
    message_en: Option<String>,
    message_es: Option<String>,
}

#[derive(Deserialize)]
struct SetBotKeyBody {
    /// 64-hex-char secret key for the welcome bot.
    nsec_hex: String,
    /// Derived x-only pubkey (64 hex). The admin CLI sends it so we avoid
    /// re-deriving on WASM where secp256k1 compilation is fragile.
    pubkey: String,
}

#[derive(Deserialize, Default)]
struct TestBody {
    /// Target pubkey for the test greeting. Defaults to the caller.
    target_pubkey: Option<String>,
    /// `"en"` or `"es"`. Defaults to `"en"`.
    locale: Option<String>,
}

// ---------------------------------------------------------------------------
// D1 row types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct WelcomeConfigRow {
    welcome_enabled: i64,
    welcome_channel_id: Option<String>,
    welcome_message_en: Option<String>,
    welcome_message_es: Option<String>,
    welcome_bot_pubkey: Option<String>,
    welcome_bot_nsec_encrypted: Option<String>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Best-effort lookup of the full welcome config row.
async fn load_config(env: &Env) -> Option<WelcomeConfigRow> {
    let db = env.d1("DB").ok()?;
    db.prepare(
        "SELECT welcome_enabled, welcome_channel_id, welcome_message_en, welcome_message_es, \
                welcome_bot_pubkey, welcome_bot_nsec_encrypted \
         FROM instance_settings WHERE id = 1",
    )
    .first::<WelcomeConfigRow>(None)
    .await
    .ok()
    .flatten()
}

/// Map a CloudFlare `CF-IPCountry` code to `"en"` or `"es"`.
pub fn locale_from_country(country: Option<&str>) -> &'static str {
    match country.map(|s| s.to_ascii_uppercase()) {
        Some(c)
            if matches!(
                c.as_str(),
                "ES" | "MX"
                    | "AR"
                    | "CL"
                    | "CO"
                    | "PE"
                    | "VE"
                    | "EC"
                    | "UY"
                    | "PY"
                    | "BO"
                    | "CR"
                    | "GT"
                    | "HN"
                    | "NI"
                    | "PA"
                    | "DO"
                    | "SV"
                    | "CU"
                    | "PR"
            ) =>
        {
            "es"
        }
        _ => "en",
    }
}

/// Default greeting text when the admin hasn't supplied one yet.
fn default_message(locale: &str) -> &'static str {
    match locale {
        "es" => {
            "¡Bienvenido/a a la comunidad! Echa un vistazo al foro y preséntate cuando quieras."
        }
        _ => {
            "Welcome to the community! Have a look around and introduce yourself when you're ready."
        }
    }
}

/// Build and sign a kind-1 welcome event from the configured bot key.
///
/// `created_at` is passed explicitly so callers in WASM use `now_secs()` while
/// native tests can supply a fixed timestamp.
fn sign_welcome(
    nsec: &[u8; 32],
    bot_pubkey: &str,
    target_pubkey: &str,
    content: &str,
    channel_id: Option<&str>,
    created_at: u64,
) -> std::result::Result<serde_json::Value, String> {
    let sk = signing_key_from_bytes(nsec).map_err(|e| format!("signing key: {e:?}"))?;

    let mut tags: Vec<Vec<String>> = Vec::new();
    tags.push(vec!["p".to_string(), target_pubkey.to_string()]);
    if let Some(ch) = channel_id {
        tags.push(vec![
            "e".to_string(),
            ch.to_string(),
            String::new(),
            "root".to_string(),
        ]);
    }

    let unsigned = UnsignedEvent {
        pubkey: bot_pubkey.to_string(),
        created_at,
        kind: 1,
        tags,
        content: content.to_string(),
    };
    let event = sign_event_deterministic(unsigned, &sk).map_err(|e| format!("sign: {e}"))?;
    serde_json::to_value(event).map_err(|e| format!("serialize: {e}"))
}

// ---------------------------------------------------------------------------
// GET /api/welcome/config
// ---------------------------------------------------------------------------

pub async fn handle_get_config(auth_header: Option<&str>, env: &Env) -> Result<Response> {
    let url = canonical_url(env, "/api/welcome/config");
    if let Err((body, status)) = require_admin(auth_header, &url, "GET", None, env).await {
        return json_response(env, &body, status);
    }

    let cfg = load_config(env).await;
    let out = match cfg {
        Some(c) => json!({
            "enabled": c.welcome_enabled == 1,
            "channel_id": c.welcome_channel_id,
            "message_en": c.welcome_message_en,
            "message_es": c.welcome_message_es,
            "bot_pubkey": c.welcome_bot_pubkey,
            "bot_key_configured": c.welcome_bot_nsec_encrypted.is_some(),
        }),
        None => json!({
            "enabled": false,
            "bot_key_configured": false,
        }),
    };
    json_response(env, &out, 200)
}

// ---------------------------------------------------------------------------
// POST /api/welcome/configure
// ---------------------------------------------------------------------------

pub async fn handle_configure(
    body_bytes: &[u8],
    auth_header: Option<&str>,
    env: &Env,
) -> Result<Response> {
    let url = canonical_url(env, "/api/welcome/configure");
    if let Err((body, status)) =
        require_admin(auth_header, &url, "POST", Some(body_bytes), env).await
    {
        return json_response(env, &body, status);
    }

    let body: ConfigureBody = serde_json::from_slice(body_bytes)
        .map_err(|e| worker::Error::RustError(format!("Invalid JSON: {e}")))?;

    let db = match env.d1("DB") {
        Ok(d) => d,
        Err(_) => return error_json(env, "Database unavailable", 500),
    };

    // Ensure a row exists (schema bootstrap inserts id=1 but guard anyway).
    let _ = db
        .prepare("INSERT OR IGNORE INTO instance_settings (id) VALUES (1)")
        .run()
        .await;

    // Build the UPDATE dynamically so only supplied fields are touched.
    let mut set_parts: Vec<String> = Vec::new();
    let mut binds: Vec<JsValue> = Vec::new();
    if let Some(v) = body.enabled {
        set_parts.push(format!("welcome_enabled = ?{}", binds.len() + 1));
        binds.push(js_i64(if v { 1 } else { 0 }));
    }
    if let Some(ref v) = body.channel_id {
        set_parts.push(format!("welcome_channel_id = ?{}", binds.len() + 1));
        binds.push(js_str(v));
    }
    if let Some(ref v) = body.message_en {
        set_parts.push(format!("welcome_message_en = ?{}", binds.len() + 1));
        binds.push(js_str(v));
    }
    if let Some(ref v) = body.message_es {
        set_parts.push(format!("welcome_message_es = ?{}", binds.len() + 1));
        binds.push(js_str(v));
    }

    if set_parts.is_empty() {
        return error_json(env, "No fields supplied", 400);
    }

    let sql = format!(
        "UPDATE instance_settings SET {} WHERE id = 1",
        set_parts.join(", ")
    );
    let stmt = db.prepare(&sql).bind(&binds)?;
    if let Err(e) = stmt.run().await {
        return error_json(env, &format!("Update failed: {e}"), 500);
    }

    json_response(env, &json!({ "ok": true }), 200)
}

// ---------------------------------------------------------------------------
// POST /api/welcome/set-bot-key
// ---------------------------------------------------------------------------

pub async fn handle_set_bot_key(
    body_bytes: &[u8],
    auth_header: Option<&str>,
    env: &Env,
) -> Result<Response> {
    let url = canonical_url(env, "/api/welcome/set-bot-key");
    if let Err((body, status)) =
        require_admin(auth_header, &url, "POST", Some(body_bytes), env).await
    {
        return json_response(env, &body, status);
    }

    let body: SetBotKeyBody = serde_json::from_slice(body_bytes)
        .map_err(|e| worker::Error::RustError(format!("Invalid JSON: {e}")))?;

    // Sanity-check the pubkey shape: 64 lowercase hex chars.
    let pubkey_lc = body.pubkey.to_lowercase();
    if pubkey_lc.len() != 64 || !pubkey_lc.bytes().all(|b| b.is_ascii_hexdigit()) {
        return error_json(env, "Invalid pubkey", 400);
    }

    let blob = match encrypt_nsec_hex(&body.nsec_hex, env) {
        Ok(b) => b,
        Err(e) => return error_json(env, &format!("Encrypt failed: {e}"), 500),
    };

    let db = match env.d1("DB") {
        Ok(d) => d,
        Err(_) => return error_json(env, "Database unavailable", 500),
    };
    let _ = db
        .prepare("INSERT OR IGNORE INTO instance_settings (id) VALUES (1)")
        .run()
        .await;

    let stmt = db
        .prepare(
            "UPDATE instance_settings SET welcome_bot_pubkey = ?1, \
             welcome_bot_nsec_encrypted = ?2 WHERE id = 1",
        )
        .bind(&[js_str(&pubkey_lc), js_str(&blob)])?;
    if let Err(e) = stmt.run().await {
        return error_json(env, &format!("Update failed: {e}"), 500);
    }

    json_response(
        env,
        &json!({ "ok": true, "bot_pubkey": pubkey_lc, "ciphertext_bytes": blob.len() }),
        200,
    )
}

// ---------------------------------------------------------------------------
// POST /api/welcome/test
// ---------------------------------------------------------------------------

pub async fn handle_test(
    body_bytes: &[u8],
    auth_header: Option<&str>,
    env: &Env,
) -> Result<Response> {
    let url = canonical_url(env, "/api/welcome/test");
    let caller = match require_admin(auth_header, &url, "POST", Some(body_bytes), env).await {
        Ok(pk) => pk,
        Err((body, status)) => return json_response(env, &body, status),
    };

    let body: TestBody = if body_bytes.is_empty() {
        TestBody::default()
    } else {
        serde_json::from_slice(body_bytes).unwrap_or_default()
    };

    let target = body.target_pubkey.unwrap_or(caller);
    let locale = body.locale.as_deref().unwrap_or("en");

    let cfg = match load_config(env).await {
        Some(c) => c,
        None => return error_json(env, "Welcome bot is not configured", 400),
    };

    let nsec_blob = match cfg.welcome_bot_nsec_encrypted.as_deref() {
        Some(b) => b,
        None => return error_json(env, "Welcome bot key is not configured", 400),
    };
    let bot_pubkey = match cfg.welcome_bot_pubkey.as_deref() {
        Some(p) => p,
        None => return error_json(env, "Welcome bot pubkey is missing", 500),
    };

    let nsec = match decrypt_nsec(nsec_blob, env) {
        Ok(k) => k,
        Err(e) => return error_json(env, &format!("Decrypt failed: {e}"), 500),
    };

    let message = match locale {
        "es" => cfg
            .welcome_message_es
            .clone()
            .unwrap_or_else(|| default_message("es").to_string()),
        _ => cfg
            .welcome_message_en
            .clone()
            .unwrap_or_else(|| default_message("en").to_string()),
    };

    let event = match sign_welcome(
        &nsec,
        bot_pubkey,
        &target,
        &message,
        cfg.welcome_channel_id.as_deref(),
        now_secs(),
    ) {
        Ok(ev) => ev,
        Err(e) => return error_json(env, &format!("Sign failed: {e}"), 500),
    };

    // Optionally record in outbox so a cron/relay-worker can publish.
    if let Ok(db) = env.d1("DB") {
        let event_id = event
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let json_str = serde_json::to_string(&event).unwrap_or_default();
        let _ = db
            .prepare(
                "INSERT OR IGNORE INTO welcome_messages \
                 (event_id, target_pubkey, locale, signed_json, sent_at, created_at) \
                 VALUES (?1, ?2, ?3, ?4, NULL, ?5)",
            )
            .bind(&[
                js_str(&event_id),
                js_str(&target),
                js_str(locale),
                js_str(&json_str),
                js_i64(now_secs() as i64),
            ])?
            .run()
            .await;
    }

    json_response(env, &json!({ "ok": true, "event": event }), 200)
}

// ---------------------------------------------------------------------------
// Public helper: called by webauthn::register_verify on first registration.
// ---------------------------------------------------------------------------

/// Queue a welcome greeting for `new_pubkey`. Silently no-ops when the
/// welcome bot is disabled or misconfigured: registration must not fail
/// because of a greeting-level problem.
pub async fn send_on_first_registration(new_pubkey: &str, country_code: Option<&str>, env: &Env) {
    let Some(cfg) = load_config(env).await else {
        return;
    };
    if cfg.welcome_enabled != 1 {
        return;
    }
    let (Some(blob), Some(bot_pubkey)) = (
        cfg.welcome_bot_nsec_encrypted.as_deref(),
        cfg.welcome_bot_pubkey.as_deref(),
    ) else {
        return;
    };

    let locale = locale_from_country(country_code);
    let message = match locale {
        "es" => cfg
            .welcome_message_es
            .clone()
            .unwrap_or_else(|| default_message("es").to_string()),
        _ => cfg
            .welcome_message_en
            .clone()
            .unwrap_or_else(|| default_message("en").to_string()),
    };

    let Ok(nsec) = decrypt_nsec(blob, env) else {
        return;
    };
    let Ok(event) = sign_welcome(
        &nsec,
        bot_pubkey,
        new_pubkey,
        &message,
        cfg.welcome_channel_id.as_deref(),
        now_secs(),
    ) else {
        return;
    };

    // Best-effort insert into outbox table. Errors are silently swallowed.
    if let Ok(db) = env.d1("DB") {
        let event_id = event
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let json_str = serde_json::to_string(&event).unwrap_or_default();
        let Ok(stmt) = db
            .prepare(
                "INSERT OR IGNORE INTO welcome_messages \
                 (event_id, target_pubkey, locale, signed_json, sent_at, created_at) \
                 VALUES (?1, ?2, ?3, ?4, NULL, ?5)",
            )
            .bind(&[
                js_str(&event_id),
                js_str(new_pubkey),
                js_str(locale),
                js_str(&json_str),
                js_i64(now_secs() as i64),
            ])
        else {
            return;
        };
        let _ = stmt.run().await;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locale_from_country_en_default() {
        assert_eq!(locale_from_country(None), "en");
        assert_eq!(locale_from_country(Some("US")), "en");
        assert_eq!(locale_from_country(Some("GB")), "en");
    }

    #[test]
    fn locale_from_country_es_for_latam_and_iberia() {
        for code in ["ES", "MX", "AR", "CL", "CO", "PE", "VE", "EC", "UY"] {
            assert_eq!(locale_from_country(Some(code)), "es", "code = {code}");
        }
    }

    #[test]
    fn locale_from_country_is_case_insensitive() {
        assert_eq!(locale_from_country(Some("es")), "es");
        assert_eq!(locale_from_country(Some("mx")), "es");
        assert_eq!(locale_from_country(Some("gb")), "en");
    }

    #[test]
    fn default_message_es_non_empty() {
        assert!(default_message("es").starts_with("¡Bienvenido"));
    }

    #[test]
    fn default_message_en_non_empty() {
        assert!(default_message("en").starts_with("Welcome"));
    }

    #[test]
    fn configure_body_accepts_partial() {
        let body: ConfigureBody = serde_json::from_str(r#"{"enabled":true}"#).unwrap();
        assert_eq!(body.enabled, Some(true));
        assert!(body.channel_id.is_none());
    }

    #[test]
    fn set_bot_key_body_requires_both_fields() {
        let ok: std::result::Result<SetBotKeyBody, _> =
            serde_json::from_str(r#"{"nsec_hex":"a","pubkey":"b"}"#);
        assert!(ok.is_ok());
        let missing: std::result::Result<SetBotKeyBody, _> =
            serde_json::from_str(r#"{"nsec_hex":"a"}"#);
        assert!(missing.is_err());
    }

    #[test]
    fn sign_welcome_produces_kind1_with_p_tag() {
        // Real signing test with an explicit `created_at` so we avoid the
        // `js_sys::Date::now()` path that panics in native tests.
        let nsec = [42u8; 32];
        let sk = signing_key_from_bytes(&nsec).unwrap();
        let bot_pubkey = hex::encode(sk.verifying_key().to_bytes());
        let target = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let ev = sign_welcome(&nsec, &bot_pubkey, target, "hi!", None, 1_700_000_000).unwrap();
        assert_eq!(ev["kind"], 1);
        let tags = ev["tags"].as_array().unwrap();
        assert!(tags
            .iter()
            .any(|t| t[0] == "p" && t[1].as_str().unwrap() == target));
    }

    #[test]
    fn sign_welcome_includes_channel_tag_when_present() {
        let nsec = [42u8; 32];
        let sk = signing_key_from_bytes(&nsec).unwrap();
        let bot_pubkey = hex::encode(sk.verifying_key().to_bytes());
        let target = "00".repeat(32);
        let channel = "11".repeat(32);
        let ev = sign_welcome(
            &nsec,
            &bot_pubkey,
            &target,
            "hola",
            Some(&channel),
            1_700_000_000,
        )
        .unwrap();
        let tags = ev["tags"].as_array().unwrap();
        let has_e = tags
            .iter()
            .any(|t| t[0] == "e" && t[1].as_str().unwrap() == channel);
        assert!(has_e, "expected e-tag with the channel id");
    }
}
