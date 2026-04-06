//! NIP-44 v2: Encrypted Direct Messages using ChaCha20-Poly1305
//!
//! Wire format: `version(1) || nonce(32) || ciphertext(variable) || mac(32)`
//! Base64-encoded for transport.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use k256::{PublicKey, SecretKey};
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroize;

/// NIP-44 version byte
const VERSION: u8 = 0x02;

/// HKDF salt for conversation key extraction
const HKDF_SALT: &[u8] = b"nip44-v2";

/// Minimum plaintext length (1 byte)
const MIN_PLAINTEXT_LEN: usize = 1;

/// Maximum plaintext length (64 KiB - 1)
const MAX_PLAINTEXT_LEN: usize = 65535;

#[derive(Debug, Error)]
pub enum Nip44Error {
    #[error("invalid secret key")]
    InvalidSecretKey,
    #[error("invalid public key")]
    InvalidPublicKey,
    #[error("ECDH shared secret computation failed")]
    EcdhFailed,
    #[error("HKDF expand failed")]
    HkdfExpandFailed,
    #[error("plaintext too short (min 1 byte)")]
    PlaintextTooShort,
    #[error("plaintext too long (max 65535 bytes)")]
    PlaintextTooLong,
    #[error("encryption failed")]
    EncryptionFailed,
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
}

/// Encrypt a plaintext message from sender to recipient per NIP-44 v2.
///
/// Returns base64-encoded ciphertext string.
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

    let conv_key = conversation_key(sender_sk, recipient_pk)?;

    // Generate random 32-byte nonce
    let mut nonce_bytes = [0u8; 32];
    getrandom::getrandom(&mut nonce_bytes).expect("getrandom failed");

    let encrypted = encrypt_inner(&conv_key, &nonce_bytes, pt_bytes)?;
    Ok(encrypted)
}

/// Decrypt a base64-encoded NIP-44 v2 ciphertext.
///
/// Returns the plaintext string.
pub fn decrypt(
    recipient_sk: &[u8; 32],
    sender_pk: &[u8; 32],
    payload: &str,
) -> Result<String, Nip44Error> {
    let conv_key = conversation_key(recipient_sk, sender_pk)?;
    decrypt_inner(&conv_key, payload)
}

/// Compute the conversation key via ECDH + HKDF-Extract.
///
/// This is deterministic: same (sk, pk) pair always yields the same key.
pub fn conversation_key(sk: &[u8; 32], pk: &[u8; 32]) -> Result<[u8; 32], Nip44Error> {
    let secret_key = SecretKey::from_bytes(sk.into()).map_err(|_| Nip44Error::InvalidSecretKey)?;

    // NIP-44 uses the x-only pubkey (32 bytes). We need to recover the full
    // compressed point (33 bytes with 0x02 prefix) for k256's PublicKey parser.
    let mut compressed = [0u8; 33];
    compressed[0] = 0x02; // assume even y
    compressed[1..].copy_from_slice(pk);

    let public_key =
        PublicKey::from_sec1_bytes(&compressed).map_err(|_| Nip44Error::InvalidPublicKey)?;

    // ECDH: multiply sk * pk to get shared point, take x-coordinate
    let shared_point = {
        let pk_affine = public_key.as_affine();
        let shared = k256::ecdh::diffie_hellman(secret_key.to_nonzero_scalar(), pk_affine);
        let shared_bytes = shared.raw_secret_bytes();
        let mut x = [0u8; 32];
        x.copy_from_slice(shared_bytes.as_slice());
        x
    };

    // HKDF-Extract(salt="nip44-v2", ikm=shared_x)
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), &shared_point);
    let mut conv_key = [0u8; 32];
    // Extract only — use expand with empty info to get the PRK as the key
    hk.expand(&[], &mut conv_key)
        .map_err(|_| Nip44Error::HkdfExpandFailed)?;

    Ok(conv_key)
}

/// Calculate the padded length per NIP-44 spec.
///
/// Matches the reference implementation:
/// - If len <= 32, return 32
/// - For next_power <= 256: chunk = 32
/// - For next_power > 256: chunk = next_power / 8
/// - Round up to next chunk boundary
pub fn calc_padded_len(unpadded_len: usize) -> usize {
    if unpadded_len <= 32 {
        return 32;
    }
    let next_power = unpadded_len.next_power_of_two();
    let chunk = if next_power <= 256 {
        32
    } else {
        next_power / 8
    };
    chunk * unpadded_len.div_ceil(chunk)
}

/// Internal encryption: pads, encrypts, MACs, and base64-encodes.
fn encrypt_inner(
    conv_key: &[u8; 32],
    nonce_bytes: &[u8; 32],
    plaintext: &[u8],
) -> Result<String, Nip44Error> {
    // Derive message keys from conversation key + nonce
    let (chacha_key, chacha_nonce, hmac_key) = derive_message_keys(conv_key, nonce_bytes)?;

    // Pad plaintext
    let padded = pad(plaintext)?;

    // Encrypt with ChaCha20-Poly1305
    let cipher = ChaCha20Poly1305::new((&chacha_key).into());
    let nonce = Nonce::from_slice(&chacha_nonce);
    let ciphertext = cipher
        .encrypt(nonce, padded.as_ref())
        .map_err(|_| Nip44Error::EncryptionFailed)?;

    // HMAC-SHA256(hmac_key, nonce || ciphertext)
    let mac = compute_hmac(&hmac_key, nonce_bytes, &ciphertext);

    // Assemble: version || nonce || ciphertext || mac
    let mut payload = Vec::with_capacity(1 + 32 + ciphertext.len() + 32);
    payload.push(VERSION);
    payload.extend_from_slice(nonce_bytes);
    payload.extend_from_slice(&ciphertext);
    payload.extend_from_slice(&mac);

    Ok(BASE64.encode(&payload))
}

/// Internal decryption: base64-decodes, verifies MAC, decrypts, unpads.
fn decrypt_inner(conv_key: &[u8; 32], payload: &str) -> Result<String, Nip44Error> {
    let raw = BASE64
        .decode(payload.as_bytes())
        .map_err(|_| Nip44Error::InvalidBase64)?;

    // Minimum: version(1) + nonce(32) + ciphertext(at least 32+16 for padded+tag) + mac(32)
    if raw.len() < 1 + 32 + 48 + 32 {
        return Err(Nip44Error::InvalidPayload("payload too short"));
    }

    let version = raw[0];
    if version != VERSION {
        return Err(Nip44Error::UnsupportedVersion(version));
    }

    let nonce_bytes: [u8; 32] = raw[1..33]
        .try_into()
        .map_err(|_| Nip44Error::InvalidPayload("bad nonce"))?;

    let mac_start = raw.len() - 32;
    let ciphertext = &raw[33..mac_start];
    let mac_received: [u8; 32] = raw[mac_start..]
        .try_into()
        .map_err(|_| Nip44Error::InvalidPayload("bad mac"))?;

    // Derive message keys
    let (chacha_key, chacha_nonce, hmac_key) = derive_message_keys(conv_key, &nonce_bytes)?;

    // Verify HMAC first (before decryption)
    let mac_computed = compute_hmac(&hmac_key, &nonce_bytes, ciphertext);
    if !constant_time_eq(&mac_computed, &mac_received) {
        return Err(Nip44Error::HmacMismatch);
    }

    // Decrypt
    let cipher = ChaCha20Poly1305::new((&chacha_key).into());
    let nonce = Nonce::from_slice(&chacha_nonce);
    let padded = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| Nip44Error::DecryptionFailed)?;

    // Unpad
    let plaintext = unpad(&padded)?;

    String::from_utf8(plaintext.to_vec())
        .map_err(|_| Nip44Error::InvalidPayload("invalid UTF-8 in plaintext"))
}

/// Derived message keys: (chacha_key[32], chacha_nonce[12], hmac_key[32]).
type MessageKeys = ([u8; 32], [u8; 12], [u8; 32]);

/// Derive (chacha_key[32], chacha_nonce[12], hmac_key[32]) from conversation key + nonce.
fn derive_message_keys(conv_key: &[u8; 32], nonce: &[u8; 32]) -> Result<MessageKeys, Nip44Error> {
    let hk = Hkdf::<Sha256>::new(Some(conv_key), nonce);
    let mut okm = [0u8; 76];
    hk.expand(b"nip44-v2", &mut okm)
        .map_err(|_| Nip44Error::HkdfExpandFailed)?;

    let mut chacha_key = [0u8; 32];
    let mut chacha_nonce = [0u8; 12];
    let mut hmac_key = [0u8; 32];

    chacha_key.copy_from_slice(&okm[..32]);
    chacha_nonce.copy_from_slice(&okm[32..44]);
    hmac_key.copy_from_slice(&okm[44..76]);

    okm.zeroize();
    Ok((chacha_key, chacha_nonce, hmac_key))
}

/// Pad plaintext: 2-byte big-endian length prefix + content + zero padding.
fn pad(plaintext: &[u8]) -> Result<Vec<u8>, Nip44Error> {
    let unpadded_len = plaintext.len();
    if unpadded_len < MIN_PLAINTEXT_LEN {
        return Err(Nip44Error::PlaintextTooShort);
    }
    if unpadded_len > MAX_PLAINTEXT_LEN {
        return Err(Nip44Error::PlaintextTooLong);
    }

    let padded_len = calc_padded_len(unpadded_len);
    // Total buffer: 2 bytes length prefix + padded_len bytes
    let mut buf = vec![0u8; 2 + padded_len];
    buf[0] = (unpadded_len >> 8) as u8;
    buf[1] = (unpadded_len & 0xFF) as u8;
    buf[2..2 + unpadded_len].copy_from_slice(plaintext);
    // Remaining bytes are already zeroed
    Ok(buf)
}

/// Unpad: read 2-byte big-endian length, extract that many bytes.
fn unpad(padded: &[u8]) -> Result<&[u8], Nip44Error> {
    if padded.len() < 2 + MIN_PLAINTEXT_LEN {
        return Err(Nip44Error::InvalidPayload("padded data too short"));
    }

    let unpadded_len = ((padded[0] as usize) << 8) | (padded[1] as usize);
    if !(MIN_PLAINTEXT_LEN..=MAX_PLAINTEXT_LEN).contains(&unpadded_len) {
        return Err(Nip44Error::InvalidPayload("invalid unpadded length"));
    }

    if 2 + unpadded_len > padded.len() {
        return Err(Nip44Error::InvalidPayload("unpadded length exceeds buffer"));
    }

    // Verify padding is all zeros
    let expected_padded_len = calc_padded_len(unpadded_len);
    if padded.len() != 2 + expected_padded_len {
        return Err(Nip44Error::InvalidPayload("unexpected padded buffer size"));
    }

    for &b in &padded[2 + unpadded_len..] {
        if b != 0 {
            return Err(Nip44Error::InvalidPayload("non-zero padding byte"));
        }
    }

    Ok(&padded[2..2 + unpadded_len])
}

/// HMAC-SHA256(key, nonce || ciphertext)
fn compute_hmac(key: &[u8; 32], nonce: &[u8; 32], ciphertext: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC key length is valid");
    mac.update(nonce);
    mac.update(ciphertext);
    let result = mac.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result.into_bytes());
    out
}

/// Constant-time comparison for MAC verification.
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::{elliptic_curve::sec1::ToEncodedPoint, SecretKey};
    // proptest import moved to proptests submodule (native-only)

    /// Generate a random keypair for testing.
    fn random_keypair() -> ([u8; 32], [u8; 32]) {
        let mut sk_bytes = [0u8; 32];
        getrandom::getrandom(&mut sk_bytes).unwrap();
        // Ensure valid scalar (non-zero, less than curve order)
        sk_bytes[0] &= 0x7F;
        if sk_bytes == [0u8; 32] {
            sk_bytes[31] = 1;
        }
        let sk = SecretKey::from_bytes((&sk_bytes).into()).unwrap();
        let pk = sk.public_key();
        let pk_point = pk.to_encoded_point(true);
        let pk_bytes: [u8; 32] = pk_point.as_bytes()[1..33].try_into().unwrap();
        let sk_bytes: [u8; 32] = sk.to_bytes().as_slice().try_into().unwrap();
        (sk_bytes, pk_bytes)
    }

    #[test]
    fn test_padding_known_values() {
        // NIP-44 spec padding: <=32 → 32, then chunk=32 up to 256, chunk=next_pow2/8 above
        assert_eq!(calc_padded_len(1), 32);
        assert_eq!(calc_padded_len(16), 32);
        assert_eq!(calc_padded_len(32), 32);
        assert_eq!(calc_padded_len(33), 64);
        assert_eq!(calc_padded_len(64), 64);
        assert_eq!(calc_padded_len(65), 96);
        assert_eq!(calc_padded_len(256), 256);
        assert_eq!(calc_padded_len(1024), 1024);
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

        // Flip a byte in the MAC
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

        // Flip a byte in the ciphertext area
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
        // Try decrypting with a wrong key — note: we need a pk that the wrong_sk doesn't match
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
        raw[0] = 0x01; // wrong version

        let tampered = BASE64.encode(&raw);
        let result = decrypt(&recipient_sk, &sender_pk, &tampered);
        assert!(matches!(result, Err(Nip44Error::UnsupportedVersion(0x01))));
    }

    #[test]
    fn test_pad_unpad_roundtrip() {
        for len in [1, 2, 15, 31, 32, 33, 63, 64, 65, 100, 255, 1000, 65535] {
            let data = vec![0x42u8; len];
            let padded = pad(&data).unwrap();
            let unpadded = unpad(&padded).unwrap();
            assert_eq!(unpadded, &data[..], "failed for len={}", len);
        }
    }

    #[test]
    fn test_padding_always_at_least_32() {
        for i in 1..=32 {
            assert_eq!(calc_padded_len(i), 32, "failed for i={}", i);
        }
    }

    #[test]
    fn test_padding_monotonic() {
        let mut prev = calc_padded_len(1);
        for i in 2..=65535 {
            let curr = calc_padded_len(i);
            assert!(
                curr >= prev,
                "padding decreased at i={}: {} < {}",
                i,
                curr,
                prev
            );
            assert!(curr >= i, "padding < input at i={}", i);
            prev = curr;
        }
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

            #[test]
            fn proptest_padding_roundtrip(len in 1usize..=65535) {
                let data = vec![0xAB; len];
                let padded = pad(&data).unwrap();
                let unpadded = unpad(&padded).unwrap();
                prop_assert_eq!(unpadded, &data[..]);
            }
        }
    }
}
