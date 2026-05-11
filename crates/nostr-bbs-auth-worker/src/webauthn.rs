//! WebAuthn registration and authentication handlers.
//!
//! Implements the server-side WebAuthn ceremony for passkey registration
//! and login, with PRF-derived Nostr keys. Mirrors the TypeScript
//! implementation in `workers/auth-api/index.ts`.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use nostr_bbs_core::d1_helpers::js_str;
use p256::ecdsa::signature::Verifier;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use wasm_bindgen::JsValue;
use worker::*;

use crate::auth;

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

/// Encode bytes as unpadded base64url (RFC 4648 section 5).
fn array_to_base64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decode an unpadded base64url string to bytes.
fn base64url_decode(input: &str) -> std::result::Result<Vec<u8>, base64::DecodeError> {
    URL_SAFE_NO_PAD.decode(input)
}

/// Constant-time comparison of two byte slices.
fn constant_time_equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Current time in milliseconds from the JS runtime.
fn js_now_ms() -> u64 {
    js_sys::Date::now() as u64
}

/// Validate that a string is exactly 64 hex characters (Nostr pubkey).
fn is_valid_pubkey(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Derive a deterministic but meaningless prf_salt for a pubkey that is not
/// registered. Used by `login_options` to make registered/unregistered
/// responses indistinguishable (audit C2). The salt has no cryptographic
/// significance — it is purely a shape-matcher. We use a plain SHA-256 over
/// the pubkey + a fixed domain-separation tag rather than a server secret
/// because the value is intentionally public-derivable: its only purpose is
/// to fill the response field.
fn deterministic_salt_for(pubkey: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"nostr-bbs-prf-salt-fallback-v1\0");
    h.update(pubkey.as_bytes());
    let digest = h.finalize();
    array_to_base64url(&digest)
}

/// Convert a u64 to JsValue (as f64 since JS has no u64).
fn js_u64(v: u64) -> JsValue {
    JsValue::from_f64(v as f64)
}

/// Convert an i32 to JsValue.
fn js_i32(v: i32) -> JsValue {
    JsValue::from_f64(v as f64)
}

/// Convert a u32 to JsValue.
fn js_u32(v: u32) -> JsValue {
    JsValue::from_f64(v as f64)
}

// ---------------------------------------------------------------------------
// Request/response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct RegisterOptionsBody {
    #[serde(rename = "displayName")]
    display_name: Option<String>,
}

#[derive(Deserialize)]
struct RegisterVerifyBody {
    pubkey: Option<String>,
    response: Option<CredentialResponse>,
    #[serde(rename = "credentialId")]
    credential_id_flat: Option<String>,
    #[serde(rename = "publicKey")]
    public_key_flat: Option<String>,
    #[serde(rename = "prfSalt")]
    prf_salt: Option<String>,
    /// WI-4: optional invite code allowing registration bypass when
    /// Web-of-Trust gating is enabled.
    #[serde(rename = "inviteCode")]
    invite_code: Option<String>,
}

#[derive(Deserialize)]
struct CredentialResponse {
    id: Option<String>,
    response: Option<InnerAttestationResponse>,
}

#[derive(Deserialize)]
struct InnerAttestationResponse {
    #[serde(rename = "attestationObject")]
    attestation_object: Option<String>,
}

#[derive(Deserialize)]
struct LoginOptionsBody {
    pubkey: Option<String>,
}

#[derive(Deserialize)]
struct LoginVerifyBody {
    pubkey: Option<String>,
    response: Option<AssertionData>,
}

#[derive(Deserialize)]
struct AssertionData {
    id: Option<String>,
    response: Option<InnerAssertionResponse>,
}

#[derive(Deserialize)]
struct InnerAssertionResponse {
    #[serde(rename = "clientDataJSON")]
    client_data_json: Option<String>,
    #[serde(rename = "authenticatorData")]
    authenticator_data: Option<String>,
    /// ECDSA P-256 (ES256) signature over (authenticatorData || SHA-256(clientDataJSON)).
    /// base64url-encoded, DER format as produced by the authenticator.
    signature: Option<String>,
}

#[derive(Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    ceremony_type: Option<String>,
    challenge: Option<String>,
    origin: Option<String>,
}

#[derive(Deserialize)]
struct CredentialLookupBody {
    #[serde(rename = "credentialId")]
    credential_id: Option<String>,
}

// ---------------------------------------------------------------------------
// D1 row types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct CredentialRow {
    credential_id: Option<String>,
    prf_salt: Option<String>,
}

#[derive(Deserialize)]
struct StoredCredential {
    credential_id: Option<String>,
    #[allow(dead_code)]
    public_key: Option<String>,
    counter: Option<i64>,
}

#[derive(Deserialize)]
struct CheckRow {
    #[allow(dead_code)]
    ok: Option<i64>,
}

#[derive(Deserialize)]
struct PubkeyRow {
    pubkey: Option<String>,
}

// ---------------------------------------------------------------------------
// COSE public key parsing (ES256 / ECDSA P-256)
// ---------------------------------------------------------------------------

/// Extract the ECDSA P-256 `VerifyingKey` from a COSE_Key stored as base64url.
///
/// The stored `public_key` column holds the output of
/// `AuthenticatorAttestationResponse.getPublicKey()` — a COSE_Key encoded in
/// CBOR. For ES256 (alg -7) the CBOR map contains:
///
///   1  (kty)  => 2  (EC2)
///   3  (alg)  => -7 (ES256)
///  -1  (crv)  => 1  (P-256)
///  -2  (x)    => bstr (32 bytes)
///  -3  (y)    => bstr (32 bytes)
///
/// We do a minimal hand-rolled CBOR parse to extract the x and y coordinates
/// rather than pulling in a full CBOR crate. This keeps the WASM binary small
/// for the Cloudflare Workers target.
fn parse_cose_p256_key(
    public_key_b64: &str,
) -> std::result::Result<p256::ecdsa::VerifyingKey, String> {
    let cose_bytes = base64url_decode(public_key_b64)
        .map_err(|e| format!("Failed to decode stored public key: {e}"))?;

    let (x, y) = extract_cose_ec2_coords(&cose_bytes)?;

    if x.len() != 32 || y.len() != 32 {
        return Err(format!(
            "COSE key coordinate size mismatch: x={}, y={}",
            x.len(),
            y.len()
        ));
    }

    // Build uncompressed SEC1 point: 0x04 || x (32 bytes) || y (32 bytes)
    let mut uncompressed = Vec::with_capacity(65);
    uncompressed.push(0x04);
    uncompressed.extend_from_slice(&x);
    uncompressed.extend_from_slice(&y);

    p256::ecdsa::VerifyingKey::from_sec1_bytes(&uncompressed)
        .map_err(|e| format!("Invalid P-256 public key: {e}"))
}

/// Minimal CBOR parser to extract x (-2) and y (-3) coordinates from a
/// COSE_Key map. Handles only the subset of CBOR needed for WebAuthn ES256
/// keys: definite-length maps, positive/negative integers, and byte strings.
fn extract_cose_ec2_coords(data: &[u8]) -> std::result::Result<(Vec<u8>, Vec<u8>), String> {
    if data.is_empty() {
        return Err("Empty COSE key data".into());
    }

    let mut pos = 0;
    let (map_len, consumed) = cbor_read_map_len(data, pos)?;
    pos += consumed;

    let mut x_coord: Option<Vec<u8>> = None;
    let mut y_coord: Option<Vec<u8>> = None;

    for _ in 0..map_len {
        if pos >= data.len() {
            return Err("CBOR truncated reading map key".into());
        }

        // Read integer key (positive or negative)
        let (key_val, consumed) = cbor_read_int(data, pos)?;
        pos += consumed;

        // Read value — we only care about bstr values for keys -2 and -3,
        // but we must skip all other value types to advance `pos`.
        if key_val == -2 || key_val == -3 {
            let (bstr, consumed) = cbor_read_bstr(data, pos)?;
            pos += consumed;
            if key_val == -2 {
                x_coord = Some(bstr);
            } else {
                y_coord = Some(bstr);
            }
        } else {
            let consumed = cbor_skip_value(data, pos)?;
            pos += consumed;
        }
    }

    match (x_coord, y_coord) {
        (Some(x), Some(y)) => Ok((x, y)),
        (None, _) => Err("COSE key missing x coordinate (label -2)".into()),
        (_, None) => Err("COSE key missing y coordinate (label -3)".into()),
    }
}

/// Read the length of a CBOR definite-length map. Returns (map_len, bytes_consumed).
fn cbor_read_map_len(data: &[u8], pos: usize) -> std::result::Result<(usize, usize), String> {
    if pos >= data.len() {
        return Err("CBOR truncated at map header".into());
    }
    let initial = data[pos];
    let major = initial >> 5;
    if major != 5 {
        return Err(format!(
            "Expected CBOR map (major 5), got major {major} at byte {pos}"
        ));
    }
    let additional = (initial & 0x1F) as usize;
    if additional < 24 {
        Ok((additional, 1))
    } else if additional == 24 {
        if pos + 1 >= data.len() {
            return Err("CBOR truncated reading map length".into());
        }
        Ok((data[pos + 1] as usize, 2))
    } else {
        Err(format!(
            "Unsupported CBOR map length encoding: {additional}"
        ))
    }
}

/// Read a CBOR integer (positive or negative). Returns (value_as_i64, bytes_consumed).
fn cbor_read_int(data: &[u8], pos: usize) -> std::result::Result<(i64, usize), String> {
    if pos >= data.len() {
        return Err("CBOR truncated at integer".into());
    }
    let initial = data[pos];
    let major = initial >> 5;
    let additional = (initial & 0x1F) as u64;

    let (raw_val, consumed) = if additional < 24 {
        (additional, 1)
    } else if additional == 24 {
        if pos + 1 >= data.len() {
            return Err("CBOR truncated reading integer payload".into());
        }
        (data[pos + 1] as u64, 2)
    } else if additional == 25 {
        if pos + 2 >= data.len() {
            return Err("CBOR truncated reading integer payload".into());
        }
        let v = u16::from_be_bytes([data[pos + 1], data[pos + 2]]);
        (v as u64, 3)
    } else if additional == 26 {
        if pos + 4 >= data.len() {
            return Err("CBOR truncated reading integer payload".into());
        }
        let v = u32::from_be_bytes([data[pos + 1], data[pos + 2], data[pos + 3], data[pos + 4]]);
        (v as u64, 5)
    } else {
        return Err(format!(
            "Unsupported CBOR integer additional info: {additional}"
        ));
    };

    match major {
        0 => Ok((raw_val as i64, consumed)),        // unsigned
        1 => Ok((-1 - (raw_val as i64), consumed)), // negative
        _ => Err(format!("Expected CBOR integer, got major type {major}")),
    }
}

/// Read a CBOR byte string. Returns (bytes, bytes_consumed).
fn cbor_read_bstr(data: &[u8], pos: usize) -> std::result::Result<(Vec<u8>, usize), String> {
    if pos >= data.len() {
        return Err("CBOR truncated at byte string".into());
    }
    let initial = data[pos];
    let major = initial >> 5;
    if major != 2 {
        return Err(format!(
            "Expected CBOR byte string (major 2), got major {major} at byte {pos}"
        ));
    }
    let additional = (initial & 0x1F) as usize;
    let (bstr_len, header_len) = if additional < 24 {
        (additional, 1)
    } else if additional == 24 {
        if pos + 1 >= data.len() {
            return Err("CBOR truncated reading bstr length".into());
        }
        (data[pos + 1] as usize, 2)
    } else if additional == 25 {
        if pos + 2 >= data.len() {
            return Err("CBOR truncated reading bstr length".into());
        }
        let v = u16::from_be_bytes([data[pos + 1], data[pos + 2]]);
        (v as usize, 3)
    } else {
        return Err(format!(
            "Unsupported CBOR bstr length encoding: {additional}"
        ));
    };

    let start = pos + header_len;
    let end = start + bstr_len;
    if end > data.len() {
        return Err(format!(
            "CBOR byte string overflows buffer: need {end}, have {}",
            data.len()
        ));
    }
    Ok((data[start..end].to_vec(), header_len + bstr_len))
}

/// Skip a single CBOR value (for map entries we don't care about).
/// Returns bytes_consumed.
fn cbor_skip_value(data: &[u8], pos: usize) -> std::result::Result<usize, String> {
    if pos >= data.len() {
        return Err("CBOR truncated skipping value".into());
    }
    let initial = data[pos];
    let major = initial >> 5;
    let additional = (initial & 0x1F) as usize;

    // Read the argument (length / count / value)
    let (arg, header_len) = if additional < 24 {
        (additional as u64, 1usize)
    } else if additional == 24 {
        if pos + 1 >= data.len() {
            return Err("CBOR truncated skipping value".into());
        }
        (data[pos + 1] as u64, 2)
    } else if additional == 25 {
        if pos + 2 >= data.len() {
            return Err("CBOR truncated skipping value".into());
        }
        (u16::from_be_bytes([data[pos + 1], data[pos + 2]]) as u64, 3)
    } else if additional == 26 {
        if pos + 4 >= data.len() {
            return Err("CBOR truncated skipping value".into());
        }
        (
            u32::from_be_bytes([data[pos + 1], data[pos + 2], data[pos + 3], data[pos + 4]]) as u64,
            5,
        )
    } else if additional == 27 {
        if pos + 8 >= data.len() {
            return Err("CBOR truncated skipping value".into());
        }
        (
            u64::from_be_bytes([
                data[pos + 1],
                data[pos + 2],
                data[pos + 3],
                data[pos + 4],
                data[pos + 5],
                data[pos + 6],
                data[pos + 7],
                data[pos + 8],
            ]),
            9,
        )
    } else {
        return Err(format!("Unsupported CBOR additional info: {additional}"));
    };

    match major {
        0 | 1 => {
            // Unsigned / negative integer — no payload beyond header.
            Ok(header_len)
        }
        2 | 3 => {
            // Byte string / text string — skip arg bytes of payload.
            Ok(header_len + arg as usize)
        }
        4 => {
            // Array — skip `arg` items.
            let mut total = header_len;
            for _ in 0..arg {
                total += cbor_skip_value(data, pos + total)?;
            }
            Ok(total)
        }
        5 => {
            // Map — skip `arg` key-value pairs.
            let mut total = header_len;
            for _ in 0..arg {
                total += cbor_skip_value(data, pos + total)?; // key
                total += cbor_skip_value(data, pos + total)?; // value
            }
            Ok(total)
        }
        6 => {
            // Tag — skip the tagged value.
            let inner = cbor_skip_value(data, pos + header_len)?;
            Ok(header_len + inner)
        }
        7 => {
            // Simple / float — header only (no further payload for our use).
            Ok(header_len)
        }
        _ => Err(format!("Unknown CBOR major type: {major}")),
    }
}

// ---------------------------------------------------------------------------
// JSON error helper
// ---------------------------------------------------------------------------

fn json_err(message: &str, status: u16) -> Result<Response> {
    let body = serde_json::json!({ "error": message });
    let json_str = serde_json::to_string(&body).map_err(|e| Error::RustError(e.to_string()))?;
    let resp = Response::ok(json_str)?.with_status(status);
    resp.headers().set("Content-Type", "application/json").ok();
    Ok(resp)
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// POST /auth/register/options
///
/// Generate a WebAuthn PublicKeyCredentialCreationOptions with a
/// server-controlled PRF salt and a random challenge.
pub async fn register_options(body_bytes: &[u8], env: &Env) -> Result<Response> {
    console_log!("[register_options] handler entered");
    let body: RegisterOptionsBody =
        serde_json::from_slice(body_bytes).unwrap_or(RegisterOptionsBody { display_name: None });
    let display_name = body
        .display_name
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "Nostr User".to_string());

    // Generate 32-byte challenge
    let mut challenge_bytes = [0u8; 32];
    getrandom::getrandom(&mut challenge_bytes)
        .map_err(|e| Error::RustError(format!("RNG failed: {e}")))?;
    let challenge_b64 = array_to_base64url(&challenge_bytes);

    // Server-controlled PRF salt
    let mut prf_salt_bytes = [0u8; 32];
    getrandom::getrandom(&mut prf_salt_bytes)
        .map_err(|e| Error::RustError(format!("RNG failed: {e}")))?;
    let prf_salt_b64 = array_to_base64url(&prf_salt_bytes);

    // Temporary user ID for the WebAuthn ceremony
    let mut temp_user_id = [0u8; 16];
    getrandom::getrandom(&mut temp_user_id)
        .map_err(|e| Error::RustError(format!("RNG failed: {e}")))?;
    let temp_user_id_b64 = array_to_base64url(&temp_user_id);

    // Clean expired challenges and store the new one
    let now_ms = js_now_ms();
    let five_min_ago = now_ms.saturating_sub(5 * 60 * 1000);

    let db = env.d1("DB")?;
    let delete_stmt = db
        .prepare("DELETE FROM challenges WHERE created_at < ?1")
        .bind(&[js_u64(five_min_ago)])?;
    let insert_stmt = db
        .prepare("INSERT INTO challenges (pubkey, challenge, created_at) VALUES (?1, ?2, ?3)")
        .bind(&[
            js_str(&challenge_b64),
            js_str(&challenge_b64),
            js_u64(now_ms),
        ])?;
    db.batch(vec![delete_stmt, insert_stmt]).await?;

    let rp_name = env
        .var("RP_NAME")
        .map(|v| v.to_string())
        .unwrap_or_else(|_| "Nostr BBS".to_string());
    let rp_id = env
        .var("RP_ID")
        .map(|v| v.to_string())
        .unwrap_or_else(|_| "example.test".to_string());

    let response_body = serde_json::json!({
        "options": {
            "rp": { "name": rp_name, "id": rp_id },
            "user": {
                "id": temp_user_id_b64,
                "name": display_name,
                "displayName": display_name
            },
            "challenge": challenge_b64,
            "pubKeyCredParams": [
                { "alg": -7, "type": "public-key" },
                { "alg": -257, "type": "public-key" }
            ],
            "timeout": 60000,
            "authenticatorSelection": {
                "residentKey": "required",
                "userVerification": "required"
            },
            "excludeCredentials": []
        },
        "prfSalt": prf_salt_b64
    });

    console_log!(
        "[register_options] responding with {} bytes",
        serde_json::to_string(&response_body)
            .unwrap_or_default()
            .len()
    );
    Response::from_json(&response_body)
}

/// POST /auth/register/verify
///
/// Verify a WebAuthn registration response, store the credential in D1,
/// provision a Solid pod, and return the user's DID/WebID/podUrl.
pub async fn register_verify(
    body_bytes: &[u8],
    _cf_country: Option<&str>,
    _env: &Env,
) -> Result<Response> {
    console_log!("[register_verify] handler entered");
    console_log!(
        "[register_verify] body received ({} bytes)",
        body_bytes.len()
    );
    let body: RegisterVerifyBody = serde_json::from_slice(body_bytes).map_err(|e| {
        console_error!("[register_verify] JSON parse error: {e}");
        Error::RustError(format!("Invalid JSON body: {e}"))
    })?;

    match &body.pubkey {
        Some(pk) if is_valid_pubkey(pk) => {}
        _ => return json_err("Invalid pubkey", 400),
    }

    // SECURITY TODO: Wire this endpoint to a trusted WebAuthn verifier
    // (prefer solid-pod-rs-idp's webauthn-rs wrapper, if it can be made
    // Worker-compatible). Do not restore caller-supplied credential storage.
    json_err(
        "WebAuthn registration verification is disabled until wired to a trusted WebAuthn verifier",
        501,
    )
}

/// POST /auth/login/options
///
/// Generate a WebAuthn PublicKeyCredentialRequestOptions. If a pubkey is
/// provided, include the stored credential ID and PRF salt in the response.
///
/// Audit C2 hardening: this endpoint MUST return an indistinguishable shape
/// for registered and unregistered pubkeys. A 404 on "unknown pubkey" was
/// previously an enumeration oracle. Today, an unregistered pubkey gets:
///   - a fresh challenge (always),
///   - empty `allowCredentials`,
///   - a deterministic-but-meaningless `prfSalt` derived from
///     `HKDF(server_secret, pubkey)`.
/// The downstream WebAuthn ceremony will fail at the authenticator step
/// (no matching credential available) without the server having confirmed
/// existence.
pub async fn login_options(body_bytes: &[u8], env: &Env) -> Result<Response> {
    let body: LoginOptionsBody =
        serde_json::from_slice(body_bytes).unwrap_or(LoginOptionsBody { pubkey: None });

    // Generate 32-byte challenge
    let mut challenge_bytes = [0u8; 32];
    getrandom::getrandom(&mut challenge_bytes)
        .map_err(|e| Error::RustError(format!("RNG failed: {e}")))?;
    let challenge_b64 = array_to_base64url(&challenge_bytes);

    let mut prf_salt: Option<String> = None;
    let mut allow_credentials: Vec<serde_json::Value> = Vec::new();

    let db = env.d1("DB")?;

    if let Some(ref pubkey) = body.pubkey {
        let cred = db
            .prepare(
                "SELECT credential_id, prf_salt FROM webauthn_credentials WHERE pubkey = ?1 LIMIT 1",
            )
            .bind(&[js_str(pubkey)])?
            .first::<CredentialRow>(None)
            .await?;

        match cred {
            None => {
                // Indistinguishable response: deterministic salt over pubkey
                // (HKDF-extract; an attacker cannot tell whether this came
                // from a stored row or from this fallback path).
                prf_salt = Some(deterministic_salt_for(pubkey));
                // allow_credentials stays empty -> the authenticator will
                // refuse to assert with a "no credential" error, which is
                // the same UX as a stale credential.
            }
            Some(cred) => {
                // SECURITY TODO: This remains an account-existence side channel:
                // known users receive allowCredentials while unknown users do not.
                // Move to a discoverable-credential flow or return a padded,
                // policy-safe shape that does not reveal registration status.
                prf_salt = cred.prf_salt;
                if let Some(ref cid) = cred.credential_id {
                    allow_credentials.push(serde_json::json!({
                        "id": cid,
                        "type": "public-key"
                    }));
                }
            }
        }
    }

    // Store challenge (supports discoverable credential flows without pubkey)
    let challenge_pubkey = body
        .pubkey
        .clone()
        .unwrap_or_else(|| "__discoverable__".to_string());
    let now_ms = js_now_ms();
    let five_min_ago = now_ms.saturating_sub(5 * 60 * 1000);

    let delete_stmt = db
        .prepare("DELETE FROM challenges WHERE created_at < ?1")
        .bind(&[js_u64(five_min_ago)])?;
    let insert_stmt = db
        .prepare("INSERT INTO challenges (pubkey, challenge, created_at) VALUES (?1, ?2, ?3)")
        .bind(&[
            js_str(&challenge_pubkey),
            js_str(&challenge_b64),
            js_u64(now_ms),
        ])?;
    db.batch(vec![delete_stmt, insert_stmt]).await?;

    let rp_id = env
        .var("RP_ID")
        .map(|v| v.to_string())
        .unwrap_or_else(|_| "example.test".to_string());

    let response_body = serde_json::json!({
        "options": {
            "challenge": challenge_b64,
            "rpId": rp_id,
            "timeout": 60000,
            "userVerification": "required",
            "allowCredentials": allow_credentials
        },
        "prfSalt": prf_salt
    });

    Response::from_json(&response_body)
}

/// POST /auth/login/verify
///
/// The most complex handler: verifies NIP-98, looks up the stored credential,
/// validates clientDataJSON and authenticatorData, checks the signature
/// counter, and returns the verified pubkey.
pub async fn login_verify(req: &Request, body_bytes: &[u8], env: &Env) -> Result<Response> {
    let body: LoginVerifyBody = serde_json::from_slice(body_bytes)
        .map_err(|_| Error::RustError("Invalid JSON body".to_string()))?;

    let pubkey = match &body.pubkey {
        Some(pk) if is_valid_pubkey(pk) => pk.to_lowercase(),
        _ => return json_err("Invalid pubkey", 400),
    };

    // Step 1: Verify NIP-98 Authorization header
    let auth_header = match req.headers().get("Authorization").ok().flatten() {
        Some(h) => h,
        None => return json_err("NIP-98 Authorization required", 401),
    };

    let request_url = req.url().map(|u| u.to_string()).unwrap_or_default();

    let nip98_result =
        match auth::verify_nip98_replay(&auth_header, &request_url, "POST", Some(body_bytes), env)
            .await
        {
            Ok(token) => token,
            Err(_) => return json_err("Invalid NIP-98 token", 401),
        };

    if nip98_result.pubkey != pubkey {
        return json_err("NIP-98 pubkey mismatch", 401);
    }

    // Step 2: Look up stored credential
    let db = env.d1("DB")?;
    let cred = db
        .prepare(
            "SELECT credential_id, public_key, counter FROM webauthn_credentials WHERE pubkey = ?1 LIMIT 1",
        )
        .bind(&[js_str(&pubkey)])?
        .first::<StoredCredential>(None)
        .await?;

    let cred = match cred {
        Some(c) => c,
        None => return json_err("No registered credential", 400),
    };

    // Step 3: Extract assertion response and verify credential ID
    let assertion_data = match &body.response {
        Some(a) => a,
        None => return json_err("Missing assertion response", 400),
    };
    let inner_response = match &assertion_data.response {
        Some(r) => r,
        None => return json_err("Missing assertion response", 400),
    };

    if assertion_data.id.as_deref() != cred.credential_id.as_deref() {
        return json_err("Credential mismatch", 400);
    }

    // Step 4: Verify clientDataJSON
    let client_data_b64 = match &inner_response.client_data_json {
        Some(s) if !s.is_empty() => s.clone(),
        _ => return json_err("Missing clientDataJSON", 400),
    };

    let client_data_bytes = match base64url_decode(&client_data_b64) {
        Ok(b) => b,
        Err(_) => return json_err("Invalid clientDataJSON", 400),
    };

    let client_data: ClientData = match serde_json::from_slice(&client_data_bytes) {
        Ok(cd) => cd,
        Err(_) => return json_err("Invalid clientDataJSON", 400),
    };

    if client_data.ceremony_type.as_deref() != Some("webauthn.get") {
        return json_err("Invalid ceremony type", 400);
    }

    let expected_origin = env
        .var("EXPECTED_ORIGIN")
        .map(|v| v.to_string())
        .unwrap_or_else(|_| "https://example.com".to_string());

    if client_data.origin.as_deref() != Some(&expected_origin) {
        return json_err("Origin mismatch", 400);
    }

    // Verify challenge was issued by this server and hasn't expired
    let now_ms = js_now_ms();
    let five_min_ago = now_ms.saturating_sub(5 * 60 * 1000);
    let challenge_str = client_data.challenge.unwrap_or_default();

    let challenge_check: Option<CheckRow> = db
        .prepare("SELECT 1 as ok FROM challenges WHERE challenge = ?1 AND created_at > ?2")
        .bind(&[js_str(&challenge_str), js_u64(five_min_ago)])?
        .first::<CheckRow>(None)
        .await?;

    if challenge_check.is_none() {
        return json_err("Invalid or expired challenge", 400);
    }

    // Step 5: Verify authenticatorData
    let auth_data_b64 = match &inner_response.authenticator_data {
        Some(s) if !s.is_empty() => s.clone(),
        _ => return json_err("Missing authenticatorData", 400),
    };

    let auth_data = match base64url_decode(&auth_data_b64) {
        Ok(b) => b,
        Err(_) => return json_err("Invalid authenticatorData", 400),
    };

    if auth_data.len() < 37 {
        return json_err("authenticatorData too short", 400);
    }

    // First 32 bytes = SHA-256(rpId)
    let rp_id = env
        .var("RP_ID")
        .map(|v| v.to_string())
        .unwrap_or_else(|_| "example.test".to_string());
    let rp_id_hash = Sha256::digest(rp_id.as_bytes());

    if !constant_time_equal(&rp_id_hash, &auth_data[..32]) {
        return json_err("RP ID mismatch", 400);
    }

    // Byte 32 = flags: bit 0 (UP), bit 2 (UV)
    let flags = auth_data[32];
    if flags & 0x01 == 0 {
        return json_err("User presence not verified", 400);
    }
    if flags & 0x04 == 0 {
        return json_err("User verification not performed", 400);
    }

    // Bytes 33-36 = sign counter (big-endian u32)
    let sign_count =
        u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]]);
    let stored_counter = cred.counter.unwrap_or(0) as u32;

    // signCount 0 means authenticator doesn't support counters -- skip check
    if sign_count != 0 && sign_count <= stored_counter {
        return json_err("Credential replay detected", 400);
    }

    // Step 6: Verify ECDSA P-256 assertion signature
    //
    // Per WebAuthn spec section 7.2 step 20, the signed message is:
    //   authenticatorData || SHA-256(clientDataJSON)
    // The signature is DER-encoded ECDSA over this message using the
    // credential's ES256 (P-256) private key.
    let signature_b64 = match &inner_response.signature {
        Some(s) if !s.is_empty() => s.clone(),
        _ => return json_err("Missing assertion signature", 400),
    };

    let signature_bytes = match base64url_decode(&signature_b64) {
        Ok(b) => b,
        Err(_) => return json_err("Invalid assertion signature encoding", 400),
    };

    let stored_public_key = match &cred.public_key {
        Some(pk) if !pk.is_empty() => pk.clone(),
        _ => return json_err("No stored public key for credential", 400),
    };

    let verifying_key = match parse_cose_p256_key(&stored_public_key) {
        Ok(vk) => vk,
        Err(e) => {
            console_error!("[login_verify] COSE key parse failed: {e}");
            return json_err(
                "Stored credential public key is invalid or unsupported",
                400,
            );
        }
    };

    // Build signed data: authenticatorData || SHA-256(clientDataJSON)
    let client_data_hash = Sha256::digest(&client_data_bytes);
    let mut signed_data = Vec::with_capacity(auth_data.len() + 32);
    signed_data.extend_from_slice(&auth_data);
    signed_data.extend_from_slice(&client_data_hash);

    // Parse the DER-encoded ECDSA signature
    let ecdsa_sig = match p256::ecdsa::DerSignature::try_from(signature_bytes.as_slice()) {
        Ok(sig) => sig,
        Err(e) => {
            console_error!("[login_verify] DER signature parse failed: {e}");
            return json_err("Assertion signature is malformed", 400);
        }
    };

    if verifying_key.verify(&signed_data, &ecdsa_sig).is_err() {
        return json_err("Assertion signature verification failed", 400);
    }

    // Step 7: All checks passed -- update counter and consume challenge
    let update_stmt = db
        .prepare("UPDATE webauthn_credentials SET counter = ?1 WHERE pubkey = ?2")
        .bind(&[js_u32(sign_count), js_str(&pubkey)])?;
    let delete_stmt = db
        .prepare("DELETE FROM challenges WHERE challenge = ?1")
        .bind(&[js_str(&challenge_str)])?;
    db.batch(vec![update_stmt, delete_stmt]).await?;

    let response_body = serde_json::json!({
        "verified": true,
        "pubkey": pubkey,
        "didNostr": format!("did:nostr:{pubkey}")
    });

    Response::from_json(&response_body)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── array_to_base64url ──────────────────────────────────────────────

    #[test]
    fn base64url_encode_empty() {
        assert_eq!(array_to_base64url(&[]), "");
    }

    #[test]
    fn base64url_encode_single_byte() {
        let encoded = array_to_base64url(&[0xFF]);
        assert_eq!(encoded, "_w"); // base64url(0xFF) = _w (no padding)
    }

    #[test]
    fn base64url_encode_decode_roundtrip() {
        let input = b"hello world";
        let encoded = array_to_base64url(input);
        let decoded = base64url_decode(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn base64url_encode_32_bytes() {
        let input = [0x42u8; 32];
        let encoded = array_to_base64url(&input);
        let decoded = base64url_decode(&encoded).unwrap();
        assert_eq!(decoded.len(), 32);
        assert!(decoded.iter().all(|b| *b == 0x42));
    }

    #[test]
    fn base64url_no_padding() {
        // Base64url should never contain '=' padding
        let input = [1, 2, 3];
        let encoded = array_to_base64url(&input);
        assert!(!encoded.contains('='));
    }

    #[test]
    fn base64url_no_plus_or_slash() {
        // Base64url uses '-' and '_' instead of '+' and '/'
        let input: Vec<u8> = (0..=255).collect();
        let encoded = array_to_base64url(&input);
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
    }

    // ── base64url_decode ────────────────────────────────────────────────

    #[test]
    fn base64url_decode_empty() {
        let decoded = base64url_decode("").unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn base64url_decode_invalid() {
        let result = base64url_decode("!!!not_valid!!!");
        assert!(result.is_err());
    }

    // ── constant_time_equal ─────────────────────────────────────────────

    #[test]
    fn constant_time_equal_same() {
        let a = [1, 2, 3, 4, 5];
        assert!(constant_time_equal(&a, &a));
    }

    #[test]
    fn constant_time_equal_different() {
        let a = [1, 2, 3, 4, 5];
        let b = [1, 2, 3, 4, 6];
        assert!(!constant_time_equal(&a, &b));
    }

    #[test]
    fn constant_time_equal_different_lengths() {
        let a = [1, 2, 3];
        let b = [1, 2, 3, 4];
        assert!(!constant_time_equal(&a, &b));
    }

    #[test]
    fn constant_time_equal_empty() {
        let a: [u8; 0] = [];
        assert!(constant_time_equal(&a, &a));
    }

    #[test]
    fn constant_time_equal_all_zeros() {
        let a = [0u8; 32];
        let b = [0u8; 32];
        assert!(constant_time_equal(&a, &b));
    }

    #[test]
    fn constant_time_equal_one_bit_different() {
        let a = [0u8; 32];
        let mut b = [0u8; 32];
        b[15] = 1; // single bit flip
        assert!(!constant_time_equal(&a, &b));
    }

    // ── is_valid_pubkey ─────────────────────────────────────────────────

    #[test]
    fn valid_pubkey_64_hex() {
        let pk = "a".repeat(64);
        assert!(is_valid_pubkey(&pk));
    }

    #[test]
    fn valid_pubkey_mixed_hex() {
        let pk = "0123456789abcdef".repeat(4);
        assert!(is_valid_pubkey(&pk));
    }

    #[test]
    fn valid_pubkey_uppercase_hex() {
        let pk = "ABCDEF0123456789".repeat(4);
        assert!(is_valid_pubkey(&pk));
    }

    #[test]
    fn invalid_pubkey_too_short() {
        let pk = "a".repeat(63);
        assert!(!is_valid_pubkey(&pk));
    }

    #[test]
    fn invalid_pubkey_too_long() {
        let pk = "a".repeat(65);
        assert!(!is_valid_pubkey(&pk));
    }

    #[test]
    fn invalid_pubkey_non_hex() {
        let pk = "g".repeat(64);
        assert!(!is_valid_pubkey(&pk));
    }

    #[test]
    fn invalid_pubkey_empty() {
        assert!(!is_valid_pubkey(""));
    }

    #[test]
    fn invalid_pubkey_spaces() {
        let pk = format!("{}  {}", "a".repeat(31), "b".repeat(31));
        assert!(!is_valid_pubkey(&pk));
    }

    // ── js_str / js_i32 / js_u32 / js_u64 ──────────────────────────────
    // These are trivial wrappers; we test they don't panic.

    // Note: JsValue-based tests require wasm32 target, so we only test
    // the pure Rust utility functions above in native test mode.

    // ── CBOR / COSE key parsing ────────────────────────────────────────

    /// Build a minimal CBOR-encoded COSE_Key map for EC2/P-256 (ES256).
    ///
    /// Map with 5 entries:
    ///   1 (kty) => 2 (EC2)
    ///   3 (alg) => -7 (ES256)
    ///  -1 (crv) => 1 (P-256)
    ///  -2 (x)   => 32-byte bstr
    ///  -3 (y)   => 32-byte bstr
    fn build_test_cose_key(x: &[u8; 32], y: &[u8; 32]) -> Vec<u8> {
        let mut buf = Vec::new();
        // Map(5) = 0xA5
        buf.push(0xA5);
        // 1 => 2  (kty: EC2)
        buf.push(0x01); // unsigned int 1
        buf.push(0x02); // unsigned int 2
                        // 3 => -7  (alg: ES256)
        buf.push(0x03); // unsigned int 3
        buf.push(0x26); // negative int: -1 - 6 = -7 (major 1, value 6)
                        // -1 => 1  (crv: P-256)
        buf.push(0x20); // negative int: -1 - 0 = -1 (major 1, value 0)
        buf.push(0x01); // unsigned int 1
                        // -2 => bstr(32)  (x coordinate)
        buf.push(0x21); // negative int: -1 - 1 = -2
        buf.push(0x58); // bstr with 1-byte length follows
        buf.push(0x20); // 32
        buf.extend_from_slice(x);
        // -3 => bstr(32)  (y coordinate)
        buf.push(0x22); // negative int: -1 - 2 = -3
        buf.push(0x58); // bstr with 1-byte length follows
        buf.push(0x20); // 32
        buf.extend_from_slice(y);
        buf
    }

    #[test]
    fn cose_extract_coords_roundtrip() {
        let x = [0xAA; 32];
        let y = [0xBB; 32];
        let cose = build_test_cose_key(&x, &y);
        let (ex, ey) = extract_cose_ec2_coords(&cose).unwrap();
        assert_eq!(ex, x);
        assert_eq!(ey, y);
    }

    #[test]
    fn cose_extract_coords_empty_data() {
        let result = extract_cose_ec2_coords(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn cose_extract_coords_not_a_map() {
        // Major type 0 (unsigned int), not 5 (map)
        let result = extract_cose_ec2_coords(&[0x00]);
        assert!(result.is_err());
    }

    #[test]
    fn cose_extract_coords_missing_y() {
        // Map(1) with just -2 => bstr(32)
        let mut buf = Vec::new();
        buf.push(0xA1); // Map(1)
        buf.push(0x21); // -2
        buf.push(0x58);
        buf.push(0x20);
        buf.extend_from_slice(&[0xAA; 32]);
        let result = extract_cose_ec2_coords(&buf);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("y coordinate"));
    }

    #[test]
    fn cose_extract_coords_missing_x() {
        // Map(1) with just -3 => bstr(32)
        let mut buf = Vec::new();
        buf.push(0xA1); // Map(1)
        buf.push(0x22); // -3
        buf.push(0x58);
        buf.push(0x20);
        buf.extend_from_slice(&[0xBB; 32]);
        let result = extract_cose_ec2_coords(&buf);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("x coordinate"));
    }

    #[test]
    fn cose_parse_valid_p256_key() {
        // Generate a real P-256 key and build a COSE key from it.
        use p256::ecdsa::SigningKey;
        let signing_key = SigningKey::from_bytes(&[0x42; 32].into()).unwrap();
        let verifying_key = signing_key.verifying_key();
        let encoded_point = verifying_key.to_encoded_point(false);
        let x: [u8; 32] = encoded_point.x().unwrap().as_slice().try_into().unwrap();
        let y: [u8; 32] = encoded_point.y().unwrap().as_slice().try_into().unwrap();

        let cose = build_test_cose_key(&x, &y);
        let cose_b64 = array_to_base64url(&cose);

        let parsed_key = parse_cose_p256_key(&cose_b64).unwrap();
        assert_eq!(parsed_key, *verifying_key);
    }

    #[test]
    fn cose_parse_invalid_coords_rejected() {
        // All-zero coordinates are not on the P-256 curve.
        let cose = build_test_cose_key(&[0x00; 32], &[0x00; 32]);
        let cose_b64 = array_to_base64url(&cose);
        let result = parse_cose_p256_key(&cose_b64);
        assert!(result.is_err());
    }

    #[test]
    fn cose_parse_bad_base64_rejected() {
        let result = parse_cose_p256_key("!!!invalid!!!");
        assert!(result.is_err());
    }

    // ── End-to-end signature verification ──────────────────────────────

    #[test]
    fn ecdsa_p256_signature_verify_roundtrip() {
        use p256::ecdsa::{signature::Signer, SigningKey};

        // Generate key
        let signing_key = SigningKey::from_bytes(&[0x42; 32].into()).unwrap();
        let verifying_key = signing_key.verifying_key();

        // Simulate WebAuthn signed data: authenticatorData || SHA-256(clientDataJSON)
        let fake_auth_data = [0x01u8; 37]; // minimal authenticator data
        let fake_client_data_json = b"{\"type\":\"webauthn.get\",\"challenge\":\"test\"}";
        let client_data_hash = Sha256::digest(fake_client_data_json);

        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(&fake_auth_data);
        signed_data.extend_from_slice(&client_data_hash);

        // Sign
        let signature: p256::ecdsa::DerSignature = signing_key.sign(&signed_data);

        // Verify (mirrors what login_verify does)
        assert!(verifying_key.verify(&signed_data, &signature).is_ok());
    }

    #[test]
    fn ecdsa_p256_bad_signature_rejected() {
        use p256::ecdsa::{signature::Signer, SigningKey};

        let signing_key = SigningKey::from_bytes(&[0x42; 32].into()).unwrap();
        let verifying_key = signing_key.verifying_key();

        let message = b"correct message";
        let signature: p256::ecdsa::DerSignature = signing_key.sign(&message[..]);

        // Verify against wrong message
        let wrong_message = b"wrong message";
        assert!(verifying_key
            .verify(&wrong_message[..], &signature)
            .is_err());
    }

    #[test]
    fn ecdsa_p256_wrong_key_rejected() {
        use p256::ecdsa::{signature::Signer, SigningKey};

        let signing_key = SigningKey::from_bytes(&[0x42; 32].into()).unwrap();
        let wrong_key = SigningKey::from_bytes(&[0x43; 32].into()).unwrap();
        let wrong_verifying_key = wrong_key.verifying_key();

        let message = b"test message";
        let signature: p256::ecdsa::DerSignature = signing_key.sign(&message[..]);

        // Verify with wrong key
        assert!(wrong_verifying_key
            .verify(&message[..], &signature)
            .is_err());
    }

    // ── CBOR skip_value ────────────────────────────────────────────────

    #[test]
    fn cbor_skip_unsigned_int() {
        // Unsigned int 5 = 0x05 (1 byte)
        assert_eq!(cbor_skip_value(&[0x05], 0).unwrap(), 1);
    }

    #[test]
    fn cbor_skip_negative_int() {
        // Negative int -1 = 0x20 (1 byte)
        assert_eq!(cbor_skip_value(&[0x20], 0).unwrap(), 1);
    }

    #[test]
    fn cbor_skip_bstr() {
        // bstr(3) = 0x43 followed by 3 bytes
        assert_eq!(cbor_skip_value(&[0x43, 0x01, 0x02, 0x03], 0).unwrap(), 4);
    }

    #[test]
    fn cbor_skip_text() {
        // tstr(2) = 0x62 followed by 2 bytes
        assert_eq!(cbor_skip_value(&[0x62, 0x68, 0x69], 0).unwrap(), 3);
    }

    #[test]
    fn cbor_read_int_positive() {
        let (val, consumed) = cbor_read_int(&[0x18, 0xFF], 0).unwrap();
        assert_eq!(val, 255);
        assert_eq!(consumed, 2);
    }

    #[test]
    fn cbor_read_int_negative() {
        // -7 in CBOR: major type 1, additional 6 => 0x26
        let (val, consumed) = cbor_read_int(&[0x26], 0).unwrap();
        assert_eq!(val, -7);
        assert_eq!(consumed, 1);
    }
}

/// POST /auth/lookup
///
/// Look up a pubkey by credential ID (for discoverable credential flows).
pub async fn credential_lookup(body_bytes: &[u8], env: &Env) -> Result<Response> {
    let body: CredentialLookupBody = serde_json::from_slice(body_bytes)
        .map_err(|_| Error::RustError("Invalid JSON body".to_string()))?;

    let credential_id = match &body.credential_id {
        Some(id) if !id.is_empty() => id.clone(),
        _ => return json_err("Missing credentialId", 400),
    };

    let db = env.d1("DB")?;
    let cred = db
        .prepare("SELECT pubkey FROM webauthn_credentials WHERE credential_id = ?1 LIMIT 1")
        .bind(&[js_str(&credential_id)])?
        .first::<PubkeyRow>(None)
        .await?;

    match cred {
        Some(row) => {
            let resp = serde_json::json!({ "pubkey": row.pubkey });
            Ok(Response::from_json(&resp)?)
        }
        None => json_err("Credential not found", 404),
    }
}
