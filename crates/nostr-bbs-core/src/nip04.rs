//! NIP-04: Encrypted Direct Messages — delegated to upstream `nostr` crate.
//!
//! Phase 5 Stage 2B.2 (ADR-076/078): the hand-rolled NIP-04 (AES-256-CBC)
//! implementation has been absorbed into `nostr::nips::nip04`. This module
//! is now a thin adapter that preserves the kit's `[u8;32]` + hex-string API
//! surface (taken by `wasm_bridge`, `signer`, `gift_wrap`, workers) while
//! delegating all crypto to upstream.
//!
//! Wire format (unchanged): `<ciphertext_base64>?iv=<iv_base64>`.
//!
//! Spec-compliance fix: pre-absorption, the kit's `nip04_shared_secret`
//! computed `SHA-256(ecdh_shared_x)` as the AES-256 key. NIP-04 specifies
//! that the AES key MUST be the raw secp256k1 ECDH x-coordinate WITHOUT
//! hashing (validated by the `nip04-dm.json` reference fixture's
//! `ecdh-shared-secret-derivation` vector: "X-coordinate of secp256k1_ecdh,
//! 32 bytes, NOT hashed"). Absorbing to upstream restores cross-client
//! interop with NDK and other compliant Nostr stacks. The kit is at
//! `3.0.0-rc3` with no persisted kind-4 content from the buggy code path,
//! so no migration is required.
//!
//! Upstream: `nostr::nips::nip04` (rust-nostr 0.44.x).

use nostr::nips::nip04::{
    decrypt as upstream_decrypt, encrypt as upstream_encrypt, Error as UpstreamError,
};
use nostr::util::generate_shared_key;
use nostr::{PublicKey, SecretKey};
use thiserror::Error;

/// Errors that can occur during NIP-04 encryption/decryption.
///
/// Variants are kept structurally compatible with the pre-absorption enum so
/// existing kit callers (signer, gift_wrap, wasm_bridge, workers) continue to
/// compile. `UpstreamCryptoError` is the catch-all for upstream errors that
/// do not map onto a legacy variant.
#[derive(Debug, Error)]
pub enum Nip04Error {
    #[error("invalid secret key")]
    InvalidSecretKey,
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("invalid wire format: missing '?iv=' separator")]
    MissingIvSeparator,
    #[error("invalid base64: {0}")]
    InvalidBase64(String),
    #[error("invalid IV length: expected 16 bytes, got {0}")]
    InvalidIvLength(usize),
    #[error("upstream nostr crypto error: {0}")]
    UpstreamCryptoError(String),
}

/// Compute the NIP-04 shared secret = raw secp256k1 ECDH x-coordinate.
///
/// Per NIP-04, the 32-byte x-coordinate IS the AES-256-CBC key (NOT hashed).
/// Returns the raw shared key. Wraps `nostr::util::generate_shared_key`.
pub fn nip04_shared_secret(
    our_sk_bytes: &[u8; 32],
    their_pk_hex: &str,
) -> Result<[u8; 32], Nip04Error> {
    let secret_key =
        SecretKey::from_slice(our_sk_bytes).map_err(|_| Nip04Error::InvalidSecretKey)?;
    let public_key = parse_pubkey(their_pk_hex)?;

    generate_shared_key(&secret_key, &public_key)
        .map_err(|e| Nip04Error::UpstreamCryptoError(format!("ECDH: {e}")))
}

/// Encrypt plaintext using NIP-04 (AES-256-CBC).
///
/// Returns `"<ciphertext_base64>?iv=<iv_base64>"`.
pub fn nip04_encrypt(
    our_sk: &[u8; 32],
    their_pk_hex: &str,
    plaintext: &str,
) -> Result<String, Nip04Error> {
    let secret_key = SecretKey::from_slice(our_sk).map_err(|_| Nip04Error::InvalidSecretKey)?;
    let public_key = parse_pubkey(their_pk_hex)?;

    upstream_encrypt(&secret_key, &public_key, plaintext).map_err(map_upstream_err)
}

/// Decrypt a NIP-04 ciphertext string `"<ciphertext_base64>?iv=<iv_base64>"`.
///
/// Returns the plaintext string.
pub fn nip04_decrypt(
    our_sk: &[u8; 32],
    their_pk_hex: &str,
    ciphertext_with_iv: &str,
) -> Result<String, Nip04Error> {
    // Pre-validate the wire shape so we surface kit-friendly error variants
    // (`MissingIvSeparator`, `InvalidIvLength`) before delegating to upstream
    // which collapses both into a generic `InvalidContentFormat`.
    let (_, iv_b64) = ciphertext_with_iv
        .split_once("?iv=")
        .ok_or(Nip04Error::MissingIvSeparator)?;
    if iv_b64.is_empty() {
        return Err(Nip04Error::InvalidIvLength(0));
    }
    if let Ok(iv_decoded) = base64_decode(iv_b64) {
        if iv_decoded.len() != 16 {
            return Err(Nip04Error::InvalidIvLength(iv_decoded.len()));
        }
    } else {
        return Err(Nip04Error::InvalidBase64(format!("iv: {iv_b64}")));
    }

    let secret_key = SecretKey::from_slice(our_sk).map_err(|_| Nip04Error::InvalidSecretKey)?;
    let public_key = parse_pubkey(their_pk_hex)?;

    upstream_decrypt(&secret_key, &public_key, ciphertext_with_iv).map_err(map_upstream_err)
}

/// Parse a hex-encoded x-only pubkey into upstream's `PublicKey`.
fn parse_pubkey(their_pk_hex: &str) -> Result<PublicKey, Nip04Error> {
    let pk_bytes = hex::decode(their_pk_hex)
        .map_err(|e| Nip04Error::InvalidPublicKey(format!("hex decode: {e}")))?;
    if pk_bytes.len() != 32 {
        return Err(Nip04Error::InvalidPublicKey(format!(
            "expected 32-byte x-only pubkey, got {} bytes",
            pk_bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&pk_bytes);
    Ok(PublicKey::from_byte_array(arr))
}

/// Helper: base64 STANDARD decode without dragging the engine into every
/// call site.
fn base64_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    BASE64.decode(s)
}

/// Map upstream `nostr::nips::nip04::Error` onto the kit's legacy `Nip04Error`.
fn map_upstream_err(e: UpstreamError) -> Nip04Error {
    match e {
        UpstreamError::Key(k) => Nip04Error::InvalidPublicKey(format!("key: {k}")),
        UpstreamError::InvalidContentFormat => Nip04Error::MissingIvSeparator,
        UpstreamError::Base64Decode => Nip04Error::InvalidBase64("upstream".into()),
        UpstreamError::Utf8Encode => Nip04Error::DecryptionFailed,
        UpstreamError::WrongBlockMode => Nip04Error::DecryptionFailed,
    }
}

// ---------------------------------------------------------------------------
// Tests — preserved post-absorption to validate the delegation path's
// behavioural parity with the legacy raw-bytes API. Reference-vector
// fixture validation lives in `tests/upstream_vectors/nip04-dm.json`.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::generate_keypair;

    fn test_keypair() -> ([u8; 32], String) {
        let kp = generate_keypair().unwrap();
        let sk = *kp.secret.as_bytes();
        let pk = kp.public.to_hex();
        (sk, pk)
    }

    #[test]
    fn shared_secret_is_symmetric() {
        let (sk_a, pk_a) = test_keypair();
        let (sk_b, pk_b) = test_keypair();

        let secret_ab = nip04_shared_secret(&sk_a, &pk_b).unwrap();
        let secret_ba = nip04_shared_secret(&sk_b, &pk_a).unwrap();

        assert_eq!(secret_ab, secret_ba, "ECDH must be symmetric");
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let (sk_a, pk_a) = test_keypair();
        let (sk_b, pk_b) = test_keypair();

        let plaintext = "Hello, NIP-04!";
        let ciphertext = nip04_encrypt(&sk_a, &pk_b, plaintext).unwrap();
        assert!(ciphertext.contains("?iv="), "must contain iv separator");

        let decrypted = nip04_decrypt(&sk_b, &pk_a, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_decrypt_roundtrip_unicode() {
        let (sk_a, pk_a) = test_keypair();
        let (sk_b, pk_b) = test_keypair();

        let plaintext = "Nostr DM 日本語 🔐";
        let ciphertext = nip04_encrypt(&sk_a, &pk_b, plaintext).unwrap();
        let decrypted = nip04_decrypt(&sk_b, &pk_a, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_decrypt_long_message() {
        let (sk_a, pk_a) = test_keypair();
        let (sk_b, pk_b) = test_keypair();

        let plaintext = "x".repeat(4096);
        let ciphertext = nip04_encrypt(&sk_a, &pk_b, &plaintext).unwrap();
        let decrypted = nip04_decrypt(&sk_b, &pk_a, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_key_fails_to_decrypt() {
        let (sk_a, _pk_a) = test_keypair();
        let (_, pk_b) = test_keypair();
        let (sk_wrong, _) = test_keypair();

        let ciphertext = nip04_encrypt(&sk_a, &pk_b, "secret").unwrap();
        let result = nip04_decrypt(&sk_wrong, &pk_b, &ciphertext);
        assert!(result.is_err(), "wrong key must fail");
    }

    #[test]
    fn missing_iv_separator_error() {
        let (sk_a, _) = test_keypair();
        let (_, pk_b) = test_keypair();
        let result = nip04_decrypt(&sk_a, &pk_b, "aGVsbG8=");
        assert!(matches!(result, Err(Nip04Error::MissingIvSeparator)));
    }

    #[test]
    fn invalid_public_key_hex() {
        let sk = [0x01u8; 32];
        let result = nip04_shared_secret(&sk, "not-hex");
        assert!(matches!(result, Err(Nip04Error::InvalidPublicKey(_))));
    }

    #[test]
    fn shared_secret_deterministic() {
        let (sk_a, _) = test_keypair();
        let (_, pk_b) = test_keypair();

        let s1 = nip04_shared_secret(&sk_a, &pk_b).unwrap();
        let s2 = nip04_shared_secret(&sk_a, &pk_b).unwrap();
        assert_eq!(s1, s2, "shared secret must be deterministic");
    }

    #[test]
    fn encrypt_produces_unique_ciphertexts() {
        let (sk_a, _) = test_keypair();
        let (_, pk_b) = test_keypair();

        let ct1 = nip04_encrypt(&sk_a, &pk_b, "hello").unwrap();
        let ct2 = nip04_encrypt(&sk_a, &pk_b, "hello").unwrap();
        assert_ne!(ct1, ct2, "random IV must produce unique ciphertexts");
    }

    #[test]
    fn nip04_iv_present_in_wire_format() {
        let (sk_a, _) = test_keypair();
        let (_, pk_b) = test_keypair();
        let result = nip04_encrypt(&sk_a, &pk_b, "test").unwrap();
        assert!(
            result.contains("?iv="),
            "wire format must contain '?iv=' separator"
        );
        assert_eq!(
            result.matches("?iv=").count(),
            1,
            "exactly one ?iv= separator"
        );
    }

    #[test]
    fn nip04_invalid_iv_format_returns_error() {
        let (sk_a, _) = test_keypair();
        let (_, pk_b) = test_keypair();
        let result = nip04_decrypt(&sk_a, &pk_b, "aGVsbG9Xb3JsZA==");
        assert!(matches!(result, Err(Nip04Error::MissingIvSeparator)));
    }

    #[test]
    fn nip04_invalid_base64_iv_returns_error() {
        let (sk_a, _) = test_keypair();
        let (_, pk_b) = test_keypair();
        let result = nip04_decrypt(&sk_a, &pk_b, "aGVsbG9Xb3JsZA==?iv=!!!notbase64!!!");
        assert!(matches!(result, Err(Nip04Error::InvalidBase64(_))));
    }

    #[test]
    fn nip04_short_iv_returns_error() {
        let (sk_a, _) = test_keypair();
        let (_, pk_b) = test_keypair();
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
        let short_iv = BASE64.encode([0u8; 8]);
        let dummy_ct = BASE64.encode([0u8; 32]);
        let wire = format!("{dummy_ct}?iv={short_iv}");
        let result = nip04_decrypt(&sk_a, &pk_b, &wire);
        assert!(
            matches!(result, Err(Nip04Error::InvalidIvLength(8))),
            "8-byte IV must return InvalidIvLength(8), got: {result:?}"
        );
    }

    #[test]
    fn nip04_empty_plaintext_roundtrip() {
        let (sk_a, pk_a) = test_keypair();
        let (sk_b, pk_b) = test_keypair();
        let ct = nip04_encrypt(&sk_a, &pk_b, "").unwrap();
        let dec = nip04_decrypt(&sk_b, &pk_a, &ct).unwrap();
        assert_eq!(dec, "");
    }

    #[test]
    fn nip04_boundary_15_byte_plaintext() {
        let (sk_a, pk_a) = test_keypair();
        let (sk_b, pk_b) = test_keypair();
        let plaintext = "a".repeat(15);
        let ct = nip04_encrypt(&sk_a, &pk_b, &plaintext).unwrap();
        let dec = nip04_decrypt(&sk_b, &pk_a, &ct).unwrap();
        assert_eq!(dec, plaintext);
    }

    #[test]
    fn nip04_boundary_16_byte_plaintext() {
        let (sk_a, pk_a) = test_keypair();
        let (sk_b, pk_b) = test_keypair();
        let plaintext = "a".repeat(16);
        let ct = nip04_encrypt(&sk_a, &pk_b, &plaintext).unwrap();
        let dec = nip04_decrypt(&sk_b, &pk_a, &ct).unwrap();
        assert_eq!(dec, plaintext);
    }

    /// Kind-4 algorithm-mismatch regression: a NIP-04 wire ciphertext MUST
    /// fail when fed to nip44_decrypt. Both upstream paths reject the wrong
    /// wire format independently, so this test holds post-absorption.
    #[test]
    fn kind4_uses_nip04_not_nip44() {
        use crate::nip44;

        let (sk_a, pk_a) = test_keypair();
        let (sk_b, pk_b) = test_keypair();

        let plaintext = "Kind-4 direct message";
        let nip04_wire = nip04_encrypt(&sk_a, &pk_b, plaintext).unwrap();
        let decrypted = nip04_decrypt(&sk_b, &pk_a, &nip04_wire).unwrap();
        assert_eq!(decrypted, plaintext);

        // nip44_decrypt on a NIP-04 wire ciphertext must fail.
        let mut pk_a_bytes = [0u8; 32];
        if let Ok(decoded) = hex::decode(&pk_a) {
            if decoded.len() == 32 {
                pk_a_bytes.copy_from_slice(&decoded);
            }
        }
        let nip44_result = nip44::decrypt(&sk_b, &pk_a_bytes, &nip04_wire);
        assert!(nip44_result.is_err());
    }
}

// ---------------------------------------------------------------------------
// Property-based tests (native only).
// ---------------------------------------------------------------------------

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod proptests {
    use super::*;
    use crate::keys::generate_keypair;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn nip04_proptest_roundtrip_ascii(
            plaintext in "[a-zA-Z0-9 !@#$%^&*()]{1,200}"
        ) {
            let kp_a = generate_keypair().unwrap();
            let kp_b = generate_keypair().unwrap();
            let sk_a = *kp_a.secret.as_bytes();
            let sk_b = *kp_b.secret.as_bytes();
            let pk_a = kp_a.public.to_hex();
            let pk_b = kp_b.public.to_hex();

            let ct = nip04_encrypt(&sk_a, &pk_b, &plaintext).unwrap();
            let dec = nip04_decrypt(&sk_b, &pk_a, &ct).unwrap();
            prop_assert_eq!(dec, plaintext);
        }

        #[test]
        fn nip04_proptest_wire_always_has_iv_separator(
            plaintext in "[a-z]{1,50}"
        ) {
            let kp_a = generate_keypair().unwrap();
            let kp_b = generate_keypair().unwrap();
            let sk_a = *kp_a.secret.as_bytes();
            let pk_b = kp_b.public.to_hex();

            let ct = nip04_encrypt(&sk_a, &pk_b, &plaintext).unwrap();
            prop_assert!(ct.contains("?iv="));
        }

        #[test]
        fn nip04_proptest_shared_secret_symmetric(
            _unused in 0u8..5u8
        ) {
            let kp_a = generate_keypair().unwrap();
            let kp_b = generate_keypair().unwrap();
            let sk_a = *kp_a.secret.as_bytes();
            let sk_b = *kp_b.secret.as_bytes();
            let pk_a = kp_a.public.to_hex();
            let pk_b = kp_b.public.to_hex();

            let s_ab = nip04_shared_secret(&sk_a, &pk_b).unwrap();
            let s_ba = nip04_shared_secret(&sk_b, &pk_a).unwrap();
            prop_assert_eq!(s_ab, s_ba);
        }

        #[test]
        fn nip04_proptest_wrong_key_cannot_decrypt(
            _unused in 0u8..5u8
        ) {
            let kp_a = generate_keypair().unwrap();
            let kp_b = generate_keypair().unwrap();
            let kp_wrong = generate_keypair().unwrap();

            let sk_a = *kp_a.secret.as_bytes();
            let pk_b = kp_b.public.to_hex();
            let sk_wrong = *kp_wrong.secret.as_bytes();

            let ct = nip04_encrypt(&sk_a, &pk_b, "test").unwrap();
            let result = nip04_decrypt(&sk_wrong, &pk_b, &ct);
            prop_assert!(result.is_err());
        }
    }
}
