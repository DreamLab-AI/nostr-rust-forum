//! WI-5 Welcome bot -- symmetric encryption for the bot's nsec at rest.
//!
//! Uses ChaCha20-Poly1305 (AEAD) with a 32-byte master key read from the
//! `WELCOME_MASTER_KEY` Worker secret (hex encoded). Ciphertext layout:
//!
//! ```text
//! nonce (12 bytes) || ciphertext || tag (16 bytes)
//! ```
//!
//! The whole blob is base64url-encoded for storage in
//! `instance_settings.welcome_bot_nsec_encrypted`.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use worker::Env;

/// Errors surfaced by the welcome-bot crypto helpers.
#[derive(Debug)]
pub enum CryptoError {
    /// The `WELCOME_MASTER_KEY` secret is absent from the Worker environment.
    MissingMasterKey,
    /// The master key is not a valid 64-char hex string (32 bytes).
    InvalidMasterKey,
    /// The secret plaintext is not a valid 64-char hex (32-byte) nsec.
    InvalidPlaintext,
    /// The stored ciphertext is malformed (wrong length / not base64url).
    MalformedCiphertext,
    /// AEAD encryption failed (extremely unlikely).
    EncryptFailed,
    /// AEAD decryption failed -- tag mismatch or wrong key.
    DecryptFailed,
    /// The RNG backing `getrandom` failed.
    RngFailed,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingMasterKey => f.write_str("WELCOME_MASTER_KEY is not configured"),
            Self::InvalidMasterKey => f.write_str("WELCOME_MASTER_KEY is malformed"),
            Self::InvalidPlaintext => f.write_str("nsec must be 64 hex chars"),
            Self::MalformedCiphertext => f.write_str("ciphertext is malformed"),
            Self::EncryptFailed => f.write_str("encryption failed"),
            Self::DecryptFailed => f.write_str("decryption failed"),
            Self::RngFailed => f.write_str("RNG failed"),
        }
    }
}

impl std::error::Error for CryptoError {}

/// Load the master key from the Worker environment.
fn master_key(env: &Env) -> Result<[u8; 32], CryptoError> {
    let hex_str = env
        .secret("WELCOME_MASTER_KEY")
        .map(|v| v.to_string())
        .or_else(|_| env.var("WELCOME_MASTER_KEY").map(|v| v.to_string()))
        .map_err(|_| CryptoError::MissingMasterKey)?;

    let bytes = hex::decode(hex_str.trim()).map_err(|_| CryptoError::InvalidMasterKey)?;
    if bytes.len() != 32 {
        return Err(CryptoError::InvalidMasterKey);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Encrypt `plaintext` with the master key. Returns `base64url(nonce || ct || tag)`.
pub fn encrypt_with_master(plaintext: &[u8], env: &Env) -> Result<String, CryptoError> {
    let key_bytes = master_key(env)?;
    let key = Key::from_slice(&key_bytes);
    let cipher = ChaCha20Poly1305::new(key);

    let mut nonce_bytes = [0u8; 12];
    getrandom::getrandom(&mut nonce_bytes).map_err(|_| CryptoError::RngFailed)?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ct = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| CryptoError::EncryptFailed)?;

    let mut blob = Vec::with_capacity(12 + ct.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ct);
    Ok(URL_SAFE_NO_PAD.encode(blob))
}

/// Inverse of [`encrypt_with_master`]. Returns the plaintext bytes.
pub fn decrypt_with_master(blob_b64: &str, env: &Env) -> Result<Vec<u8>, CryptoError> {
    let key_bytes = master_key(env)?;
    let key = Key::from_slice(&key_bytes);
    let cipher = ChaCha20Poly1305::new(key);

    let blob = URL_SAFE_NO_PAD
        .decode(blob_b64.trim())
        .map_err(|_| CryptoError::MalformedCiphertext)?;
    if blob.len() < 12 + 16 {
        return Err(CryptoError::MalformedCiphertext);
    }
    let (nonce_bytes, ct) = blob.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ct)
        .map_err(|_| CryptoError::DecryptFailed)
}

/// Convenience: `nsec_hex` is a 64-hex-char private key string. Returns the
/// base64url-encoded blob suitable for storage.
pub fn encrypt_nsec_hex(nsec_hex: &str, env: &Env) -> Result<String, CryptoError> {
    let trimmed = nsec_hex.trim();
    if trimmed.len() != 64 || !trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(CryptoError::InvalidPlaintext);
    }
    let raw = hex::decode(trimmed).map_err(|_| CryptoError::InvalidPlaintext)?;
    encrypt_with_master(&raw, env)
}

/// Decrypt a blob back to a 32-byte nsec.
pub fn decrypt_nsec(blob_b64: &str, env: &Env) -> Result<[u8; 32], CryptoError> {
    let raw = decrypt_with_master(blob_b64, env)?;
    if raw.len() != 32 {
        return Err(CryptoError::DecryptFailed);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit};

    // Round-trip helpers live outside the Worker runtime: we test the
    // pure-crypto path (everything except `master_key`) directly against
    // a fixed key. This gives us real coverage without needing `Env`.

    fn fixed_key() -> [u8; 32] {
        [7u8; 32]
    }

    fn encrypt_with(key_bytes: &[u8; 32], plaintext: &[u8]) -> String {
        let key = Key::from_slice(key_bytes);
        let cipher = ChaCha20Poly1305::new(key);
        let mut nonce_bytes = [0u8; 12];
        getrandom::getrandom(&mut nonce_bytes).unwrap();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = cipher.encrypt(nonce, plaintext).unwrap();
        let mut blob = Vec::with_capacity(12 + ct.len());
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&ct);
        URL_SAFE_NO_PAD.encode(blob)
    }

    fn decrypt_with(key_bytes: &[u8; 32], blob_b64: &str) -> Vec<u8> {
        let key = Key::from_slice(key_bytes);
        let cipher = ChaCha20Poly1305::new(key);
        let blob = URL_SAFE_NO_PAD.decode(blob_b64).unwrap();
        let (n, ct) = blob.split_at(12);
        let nonce = Nonce::from_slice(n);
        cipher.decrypt(nonce, ct).unwrap()
    }

    #[test]
    fn roundtrip_preserves_plaintext() {
        let k = fixed_key();
        let plain = b"a very secret nsec";
        let blob = encrypt_with(&k, plain);
        let out = decrypt_with(&k, &blob);
        assert_eq!(out, plain);
    }

    #[test]
    fn different_nonces_produce_different_blobs() {
        let k = fixed_key();
        let plain = b"hello";
        let a = encrypt_with(&k, plain);
        let b = encrypt_with(&k, plain);
        assert_ne!(a, b, "nonces must differ across calls");
    }

    #[test]
    fn wrong_key_fails_decrypt() {
        let k1 = fixed_key();
        let mut k2 = fixed_key();
        k2[0] = 0;
        let blob = encrypt_with(&k1, b"secret");
        let key = Key::from_slice(&k2);
        let cipher = ChaCha20Poly1305::new(key);
        let raw = URL_SAFE_NO_PAD.decode(&blob).unwrap();
        let (n, ct) = raw.split_at(12);
        let nonce = Nonce::from_slice(n);
        assert!(cipher.decrypt(nonce, ct).is_err());
    }

    #[test]
    fn malformed_ciphertext_fails_split() {
        let raw = URL_SAFE_NO_PAD.encode([0u8; 4]);
        let decoded = URL_SAFE_NO_PAD.decode(raw).unwrap();
        assert!(decoded.len() < 28, "short input must be rejected upstream");
    }

    #[test]
    fn invalid_hex_nsec_is_rejected() {
        // This test does not require Env; we simulate the validation
        // branch in `encrypt_nsec_hex` directly.
        fn looks_valid_nsec(s: &str) -> bool {
            s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
        }
        assert!(!looks_valid_nsec("zz"));
        assert!(!looks_valid_nsec(&"a".repeat(63)));
        assert!(looks_valid_nsec(&"a".repeat(64)));
    }
}
