//! NIP-44 v2: Encrypted Direct Messages — delegated to upstream `nostr` crate.
//!
//! Phase 5 Stage 2B (ADR-076/078): the hand-rolled NIP-44 v2 implementation
//! has been absorbed into `nostr::nips::nip44`. This module is now a thin
//! adapter that preserves the kit's `[u8;32]`-typed API surface (taken by
//! `wasm_bridge`, benches, and tests) while delegating all crypto to upstream.
//!
//! Upstream: `nostr::nips::nip44` (rust-nostr 0.44.x), audited by paulmillr's
//! reference vector suite via `crates/nostr-bbs-core/tests/upstream_vectors/`.
//!
//! Wire format (unchanged): `version(1) || nonce(32) || ciphertext(variable) || mac(32)`,
//! base64-encoded.

use nostr::nips::nip44::v2::ConversationKey;
use nostr::nips::nip44::{
    decrypt as upstream_decrypt, encrypt as upstream_encrypt, Error as UpstreamError, Version,
};
use nostr::{PublicKey, SecretKey};
use thiserror::Error;

/// Errors specific to NIP-44 v2 operations on the kit's raw-bytes API.
///
/// Variants are kept structurally compatible with the pre-absorption enum so
/// existing kit callers (workers, wasm_bridge) continue to compile. Upstream
/// errors are mapped onto the closest legacy variant; `UpstreamCryptoError`
/// is the catch-all for anything that does not map cleanly.
#[derive(Debug, Error)]
pub enum Nip44Error {
    #[error("invalid secret key")]
    InvalidSecretKey,
    #[error("invalid public key")]
    InvalidPublicKey,
    #[error("plaintext too short (min 1 byte)")]
    PlaintextTooShort,
    #[error("plaintext too long (max 65535 bytes)")]
    PlaintextTooLong,
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("invalid base64")]
    InvalidBase64,
    #[error("invalid payload: {0}")]
    InvalidPayload(&'static str),
    #[error("unsupported version: {0}")]
    UnsupportedVersion(u8),
    #[error("HMAC verification failed")]
    HmacMismatch,
    #[error("upstream nostr crypto error: {0}")]
    UpstreamCryptoError(String),
}

/// Maximum plaintext length per NIP-44 v2 spec (64 KiB - 1).
const MAX_PLAINTEXT_LEN: usize = 65535;

/// Encrypt a plaintext message from sender to recipient per NIP-44 v2.
///
/// Wraps `nostr::nips::nip44::encrypt`. The kit-side API takes raw 32-byte
/// secret/public keys (NIP-01 x-only convention) and returns base64-encoded
/// ciphertext.
pub fn encrypt(
    sender_sk: &[u8; 32],
    recipient_pk: &[u8; 32],
    plaintext: &str,
) -> Result<String, Nip44Error> {
    let pt_bytes = plaintext.as_bytes();
    if pt_bytes.is_empty() {
        return Err(Nip44Error::PlaintextTooShort);
    }
    if pt_bytes.len() > MAX_PLAINTEXT_LEN {
        return Err(Nip44Error::PlaintextTooLong);
    }

    let sk = SecretKey::from_slice(sender_sk).map_err(|_| Nip44Error::InvalidSecretKey)?;
    let pk = PublicKey::from_byte_array(*recipient_pk);

    upstream_encrypt(&sk, &pk, plaintext, Version::V2).map_err(map_upstream_err)
}

/// Decrypt a base64-encoded NIP-44 v2 ciphertext.
///
/// Wraps `nostr::nips::nip44::decrypt`. Returns the plaintext UTF-8 string.
pub fn decrypt(
    recipient_sk: &[u8; 32],
    sender_pk: &[u8; 32],
    payload: &str,
) -> Result<String, Nip44Error> {
    let sk = SecretKey::from_slice(recipient_sk).map_err(|_| Nip44Error::InvalidSecretKey)?;
    let pk = PublicKey::from_byte_array(*sender_pk);

    upstream_decrypt(&sk, &pk, payload).map_err(map_upstream_err)
}

/// Compute the conversation key via ECDH + HKDF-Extract.
///
/// Deterministic: the same `(sk, pk)` pair always yields the same key.
/// Wraps `nostr::nips::nip44::v2::ConversationKey::derive` and extracts the
/// underlying 32-byte HMAC key for kit compatibility.
pub fn conversation_key(sk: &[u8; 32], pk: &[u8; 32]) -> Result<[u8; 32], Nip44Error> {
    let secret_key = SecretKey::from_slice(sk).map_err(|_| Nip44Error::InvalidSecretKey)?;
    let public_key = PublicKey::from_byte_array(*pk);

    let conv = ConversationKey::derive(&secret_key, &public_key).map_err(map_upstream_err)?;
    let bytes = conv.as_bytes();
    if bytes.len() != 32 {
        return Err(Nip44Error::UpstreamCryptoError(format!(
            "ConversationKey::as_bytes returned {} bytes, expected 32",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}

/// Map upstream `nostr::nips::nip44::Error` onto the kit's legacy `Nip44Error`.
fn map_upstream_err(e: UpstreamError) -> Nip44Error {
    match e {
        UpstreamError::Key(_) => Nip44Error::InvalidPublicKey,
        UpstreamError::Base64Decode(_) => Nip44Error::InvalidBase64,
        UpstreamError::Utf8Encode => Nip44Error::InvalidPayload("invalid UTF-8 in plaintext"),
        UpstreamError::UnknownVersion(v) => Nip44Error::UnsupportedVersion(v),
        UpstreamError::VersionNotFound => Nip44Error::InvalidPayload("missing version byte"),
        UpstreamError::NotFound(field) => {
            // Leak field name into the catch-all so debugging stays useful.
            Nip44Error::UpstreamCryptoError(format!("not found in payload: {field}"))
        }
        UpstreamError::V2(v2_err) => {
            use nostr::nips::nip44::v2::ErrorV2;
            match v2_err {
                ErrorV2::MessageEmpty => Nip44Error::PlaintextTooShort,
                ErrorV2::MessageTooLong => Nip44Error::PlaintextTooLong,
                ErrorV2::InvalidHmac => Nip44Error::HmacMismatch,
                ErrorV2::InvalidPadding => Nip44Error::InvalidPayload("invalid padding"),
                ErrorV2::HkdfLength(_) => Nip44Error::DecryptionFailed,
                ErrorV2::TryFromSlice => Nip44Error::InvalidPayload("slice conversion"),
                ErrorV2::FromSlice(_) => Nip44Error::InvalidPayload("from slice"),
                ErrorV2::Utf8Encode(_) => Nip44Error::InvalidPayload("invalid UTF-8 in plaintext"),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests — preserved post-absorption to validate the delegation path's
// behavioural parity with the legacy raw-bytes API. The reference-vector
// fixture validation lives in `tests/upstream_vectors/`.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    use k256::{elliptic_curve::sec1::ToEncodedPoint, SecretKey as K256SecretKey};

    /// Generate a random keypair for testing. Uses k256 for parity with the
    /// pre-absorption test harness so existing test bodies stay verbatim.
    fn random_keypair() -> ([u8; 32], [u8; 32]) {
        let mut sk_bytes = [0u8; 32];
        getrandom::getrandom(&mut sk_bytes).unwrap();
        sk_bytes[0] &= 0x7F;
        if sk_bytes == [0u8; 32] {
            sk_bytes[31] = 1;
        }
        let sk = K256SecretKey::from_bytes((&sk_bytes).into()).unwrap();
        let pk = sk.public_key();
        let pk_point = pk.to_encoded_point(true);
        let pk_bytes: [u8; 32] = pk_point.as_bytes()[1..33].try_into().unwrap();
        let sk_bytes: [u8; 32] = sk.to_bytes().as_slice().try_into().unwrap();
        (sk_bytes, pk_bytes)
    }

    #[test]
    fn test_nip44_roundtrip_basic() {
        let (sender_sk, sender_pk) = random_keypair();
        let (recipient_sk, recipient_pk) = random_keypair();

        let plaintext = "Hello, NIP-44!";
        let encrypted = encrypt(&sender_sk, &recipient_pk, plaintext).unwrap();
        let decrypted = decrypt(&recipient_sk, &sender_pk, &encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_nip44_roundtrip_long_message() {
        let (sender_sk, sender_pk) = random_keypair();
        let (recipient_sk, recipient_pk) = random_keypair();

        let plaintext = "A".repeat(10000);
        let encrypted = encrypt(&sender_sk, &recipient_pk, &plaintext).unwrap();
        let decrypted = decrypt(&recipient_sk, &sender_pk, &encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_nip44_roundtrip_unicode() {
        let (sender_sk, sender_pk) = random_keypair();
        let (recipient_sk, recipient_pk) = random_keypair();

        let plaintext = "🦀 Rust NIP-44 暗号化 テスト";
        let encrypted = encrypt(&sender_sk, &recipient_pk, plaintext).unwrap();
        let decrypted = decrypt(&recipient_sk, &sender_pk, &encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_nip44_empty_plaintext_rejected() {
        let (sender_sk, _) = random_keypair();
        let (_, recipient_pk) = random_keypair();

        let result = encrypt(&sender_sk, &recipient_pk, "");
        assert!(matches!(result, Err(Nip44Error::PlaintextTooShort)));
    }

    #[test]
    fn test_nip44_conversation_key_symmetric() {
        let (sk_a, pk_a) = random_keypair();
        let (sk_b, pk_b) = random_keypair();

        let key_ab = conversation_key(&sk_a, &pk_b).unwrap();
        let key_ba = conversation_key(&sk_b, &pk_a).unwrap();

        assert_eq!(key_ab, key_ba);
    }

    #[test]
    fn test_nip44_conversation_key_deterministic() {
        let (sk_a, _) = random_keypair();
        let (_, pk_b) = random_keypair();

        let key1 = conversation_key(&sk_a, &pk_b).unwrap();
        let key2 = conversation_key(&sk_a, &pk_b).unwrap();

        assert_eq!(key1, key2);
    }

    #[test]
    fn test_nip44_tampered_mac_rejected() {
        let (sender_sk, sender_pk) = random_keypair();
        let (recipient_sk, recipient_pk) = random_keypair();

        let encrypted = encrypt(&sender_sk, &recipient_pk, "secret message").unwrap();
        let mut raw = BASE64.decode(encrypted.as_bytes()).unwrap();

        let last = raw.len() - 1;
        raw[last] ^= 0xFF;

        let tampered = BASE64.encode(&raw);
        let result = decrypt(&recipient_sk, &sender_pk, &tampered);
        assert!(matches!(result, Err(Nip44Error::HmacMismatch)));
    }

    #[test]
    fn test_nip44_tampered_ciphertext_rejected() {
        let (sender_sk, sender_pk) = random_keypair();
        let (recipient_sk, recipient_pk) = random_keypair();

        let encrypted = encrypt(&sender_sk, &recipient_pk, "secret message").unwrap();
        let mut raw = BASE64.decode(encrypted.as_bytes()).unwrap();

        raw[40] ^= 0xFF;

        let tampered = BASE64.encode(&raw);
        let result = decrypt(&recipient_sk, &sender_pk, &tampered);
        assert!(result.is_err());
    }

    #[test]
    fn test_nip44_wrong_key_fails() {
        let (sender_sk, _) = random_keypair();
        let (_, recipient_pk) = random_keypair();
        let (wrong_sk, _) = random_keypair();

        let encrypted = encrypt(&sender_sk, &recipient_pk, "secret").unwrap();
        let (_, wrong_pk) = random_keypair();
        let result = decrypt(&wrong_sk, &wrong_pk, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_nip44_unsupported_version() {
        let (sender_sk, sender_pk) = random_keypair();
        let (recipient_sk, recipient_pk) = random_keypair();

        let encrypted = encrypt(&sender_sk, &recipient_pk, "test").unwrap();
        let mut raw = BASE64.decode(encrypted.as_bytes()).unwrap();
        raw[0] = 0x01;

        let tampered = BASE64.encode(&raw);
        let result = decrypt(&recipient_sk, &sender_pk, &tampered);
        assert!(matches!(result, Err(Nip44Error::UnsupportedVersion(0x01))));
    }

    #[cfg(not(target_arch = "wasm32"))]
    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn proptest_nip44_roundtrip(
                plaintext in "[\\x20-\\x7E]{1,500}"
            ) {
                let (sender_sk, sender_pk) = random_keypair();
                let (recipient_sk, recipient_pk) = random_keypair();

                let encrypted = encrypt(&sender_sk, &recipient_pk, &plaintext).unwrap();
                let decrypted = decrypt(&recipient_sk, &sender_pk, &encrypted).unwrap();

                prop_assert_eq!(decrypted, plaintext);
            }
        }
    }
}
