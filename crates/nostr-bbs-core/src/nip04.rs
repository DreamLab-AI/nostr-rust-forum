//! NIP-04: Encrypted Direct Messages (AES-256-CBC).
//!
//! Wire format: `<ciphertext_base64>?iv=<iv_base64>`
//!
//! Key derivation:
//! - ECDH x-coordinate = raw 32-byte shared secret
//! - SHA-256(shared_x) = 32-byte AES-256 key
//! - Random 16-byte IV prepended to wire format

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use k256::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};
use thiserror::Error;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// Errors that can occur during NIP-04 encryption/decryption.
#[derive(Debug, Error)]
pub enum Nip04Error {
    #[error("invalid secret key")]
    InvalidSecretKey,
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),
    #[error("ECDH computation failed")]
    EcdhFailed,
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("invalid wire format: missing '?iv=' separator")]
    MissingIvSeparator,
    #[error("invalid base64: {0}")]
    InvalidBase64(String),
    #[error("invalid IV length: expected 16 bytes, got {0}")]
    InvalidIvLength(usize),
}

/// Compute the NIP-04 shared secret: ECDH x-coordinate → SHA-256.
///
/// The 32-byte output is the AES-256-CBC key.
pub fn nip04_shared_secret(
    our_sk_bytes: &[u8; 32],
    their_pk_hex: &str,
) -> Result<[u8; 32], Nip04Error> {
    let secret_key =
        SecretKey::from_bytes(our_sk_bytes.into()).map_err(|_| Nip04Error::InvalidSecretKey)?;

    let pk_bytes = hex::decode(their_pk_hex)
        .map_err(|e| Nip04Error::InvalidPublicKey(format!("hex decode: {e}")))?;
    if pk_bytes.len() != 32 {
        return Err(Nip04Error::InvalidPublicKey(format!(
            "expected 32-byte x-only pubkey, got {} bytes",
            pk_bytes.len()
        )));
    }

    // Reconstruct compressed point with 0x02 prefix (even y)
    let mut compressed = [0u8; 33];
    compressed[0] = 0x02;
    compressed[1..].copy_from_slice(&pk_bytes);

    let public_key = PublicKey::from_sec1_bytes(&compressed)
        .map_err(|e| Nip04Error::InvalidPublicKey(format!("invalid secp256k1 point: {e}")))?;

    // ECDH: shared point x-coordinate (raw 32 bytes)
    let shared_x = {
        let pk_affine = public_key.as_affine();
        let shared = k256::ecdh::diffie_hellman(secret_key.to_nonzero_scalar(), pk_affine);
        let shared_bytes = shared.raw_secret_bytes();
        let mut x = [0u8; 32];
        x.copy_from_slice(shared_bytes.as_slice());
        x
    };

    // NIP-04: AES key = SHA-256(x-coordinate)
    let aes_key: [u8; 32] = Sha256::digest(shared_x).into();
    Ok(aes_key)
}

/// Encrypt plaintext using NIP-04 (AES-256-CBC).
///
/// Returns `"<ciphertext_base64>?iv=<iv_base64>"`.
pub fn nip04_encrypt(
    our_sk: &[u8; 32],
    their_pk_hex: &str,
    plaintext: &str,
) -> Result<String, Nip04Error> {
    let aes_key = nip04_shared_secret(our_sk, their_pk_hex)?;

    // Generate random 16-byte IV
    let mut iv = [0u8; 16];
    getrandom::getrandom(&mut iv).map_err(|_| Nip04Error::EncryptionFailed)?;

    let encryptor = Aes256CbcEnc::new(&aes_key.into(), &iv.into());
    let pt_bytes = plaintext.as_bytes();

    // encrypt_padded_vec_mut always succeeds for PKCS7 (infallible for valid input)
    let ciphertext = encryptor.encrypt_padded_vec_mut::<Pkcs7>(pt_bytes);

    let ct_b64 = BASE64.encode(&ciphertext);
    let iv_b64 = BASE64.encode(iv);

    Ok(format!("{ct_b64}?iv={iv_b64}"))
}

/// Decrypt a NIP-04 ciphertext string `"<ciphertext_base64>?iv=<iv_base64>"`.
///
/// Returns the plaintext string.
pub fn nip04_decrypt(
    our_sk: &[u8; 32],
    their_pk_hex: &str,
    ciphertext_with_iv: &str,
) -> Result<String, Nip04Error> {
    let aes_key = nip04_shared_secret(our_sk, their_pk_hex)?;

    // Split on "?iv="
    let (ct_b64, iv_b64) = ciphertext_with_iv
        .split_once("?iv=")
        .ok_or(Nip04Error::MissingIvSeparator)?;

    let ciphertext = BASE64
        .decode(ct_b64)
        .map_err(|e| Nip04Error::InvalidBase64(format!("ciphertext: {e}")))?;

    let iv_bytes = BASE64
        .decode(iv_b64)
        .map_err(|e| Nip04Error::InvalidBase64(format!("iv: {e}")))?;

    if iv_bytes.len() != 16 {
        return Err(Nip04Error::InvalidIvLength(iv_bytes.len()));
    }

    let iv: [u8; 16] = iv_bytes.try_into().expect("length already checked");

    let decryptor = Aes256CbcDec::new(&aes_key.into(), &iv.into());
    let plaintext_bytes = decryptor
        .decrypt_padded_vec_mut::<Pkcs7>(&ciphertext)
        .map_err(|_| Nip04Error::DecryptionFailed)?;

    String::from_utf8(plaintext_bytes).map_err(|_| Nip04Error::DecryptionFailed)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

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

        // Wire format must contain "?iv="
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
        // sk_wrong + pk_b → different shared secret → decrypt fails
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
        // Due to random IV, same plaintext must encrypt to different ciphertexts
        let (sk_a, _) = test_keypair();
        let (_, pk_b) = test_keypair();

        let ct1 = nip04_encrypt(&sk_a, &pk_b, "hello").unwrap();
        let ct2 = nip04_encrypt(&sk_a, &pk_b, "hello").unwrap();
        assert_ne!(ct1, ct2, "random IV must produce unique ciphertexts");
    }

    // ── Known test vectors ─────────────────────────────────────────────────────
    //
    // Vectors built from minimal valid secp256k1 scalars (1 and 2).
    // These are the smallest non-zero scalars that produce valid curve points,
    // giving fully deterministic shared-secret and AES-key values.

    fn sk_scalar(n: u8) -> [u8; 32] {
        let mut sk = [0u8; 32];
        sk[31] = n;
        sk
    }

    fn pk_for_scalar(n: u8) -> String {
        use k256::schnorr::SigningKey;
        let sk_bytes = sk_scalar(n);
        let sk = SigningKey::from_bytes(&sk_bytes).unwrap();
        hex::encode(sk.verifying_key().to_bytes())
    }

    #[test]
    fn nip04_known_vector_shared_secret_is_symmetric() {
        let sk_a = sk_scalar(1);
        let sk_b = sk_scalar(2);
        let pk_a = pk_for_scalar(1);
        let pk_b = pk_for_scalar(2);

        let secret_ab = nip04_shared_secret(&sk_a, &pk_b).unwrap();
        let secret_ba = nip04_shared_secret(&sk_b, &pk_a).unwrap();
        assert_eq!(secret_ab, secret_ba, "ECDH shared secret must be symmetric");
        assert_eq!(secret_ab.len(), 32, "shared secret must be 32 bytes");
    }

    #[test]
    fn nip04_known_vector_decrypt_deterministic_ciphertext() {
        // Manually construct a ciphertext with a fixed zero IV so the expected
        // plaintext can be verified deterministically without relying on random IV.
        use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
        type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

        let sk_a = sk_scalar(1);
        let pk_b = pk_for_scalar(2);
        let sk_b = sk_scalar(2);
        let pk_a = pk_for_scalar(1);
        let plaintext = "Hello, NIP-04 vector!";

        let aes_key = nip04_shared_secret(&sk_a, &pk_b).unwrap();
        let iv = [0u8; 16];
        let enc = Aes256CbcEnc::new(&aes_key.into(), &iv.into());
        // encrypt_padded_vec_mut returns Vec<u8> (infallible with alloc feature)
        let ct_bytes: Vec<u8> = enc.encrypt_padded_vec_mut::<Pkcs7>(plaintext.as_bytes());

        let wire = format!("{}?iv={}", BASE64.encode(&ct_bytes), BASE64.encode(iv));

        let decrypted = nip04_decrypt(&sk_b, &pk_a, &wire).unwrap();
        assert_eq!(decrypted, plaintext, "known-vector decryption must match");
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
        assert!(
            matches!(result, Err(Nip04Error::MissingIvSeparator)),
            "missing ?iv= must return MissingIvSeparator"
        );
    }

    #[test]
    fn nip04_invalid_base64_ciphertext_returns_error() {
        let (sk_a, _) = test_keypair();
        let (_, pk_b) = test_keypair();
        let result = nip04_decrypt(&sk_a, &pk_b, "!!!notbase64!!!?iv=AAAAAAAAAAAAAAAAAAAAAA==");
        assert!(
            matches!(result, Err(Nip04Error::InvalidBase64(_))),
            "bad base64 ciphertext must return InvalidBase64"
        );
    }

    #[test]
    fn nip04_invalid_base64_iv_returns_error() {
        let (sk_a, _) = test_keypair();
        let (_, pk_b) = test_keypair();
        let result = nip04_decrypt(&sk_a, &pk_b, "aGVsbG9Xb3JsZA==?iv=!!!notbase64!!!");
        assert!(
            matches!(result, Err(Nip04Error::InvalidBase64(_))),
            "bad base64 IV must return InvalidBase64"
        );
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
        // 15 bytes: one byte under a full AES block — PKCS7 pads to 16
        let (sk_a, pk_a) = test_keypair();
        let (sk_b, pk_b) = test_keypair();
        let plaintext = "a".repeat(15);
        let ct = nip04_encrypt(&sk_a, &pk_b, &plaintext).unwrap();
        let dec = nip04_decrypt(&sk_b, &pk_a, &ct).unwrap();
        assert_eq!(dec, plaintext);
    }

    #[test]
    fn nip04_boundary_16_byte_plaintext() {
        // 16 bytes: exactly one AES block — PKCS7 adds a full padding block
        let (sk_a, pk_a) = test_keypair();
        let (sk_b, pk_b) = test_keypair();
        let plaintext = "a".repeat(16);
        let ct = nip04_encrypt(&sk_a, &pk_b, &plaintext).unwrap();
        let dec = nip04_decrypt(&sk_b, &pk_a, &ct).unwrap();
        assert_eq!(dec, plaintext);
    }

    // ── Kind-4 regression: NIP-04 vs NIP-44 algorithm mismatch ───────────────
    //
    // This test encodes the historical bug: kind-4 content was decrypted with
    // NIP-44 (ChaCha20-Poly1305) instead of NIP-04 (AES-256-CBC).
    // A NIP-04 ciphertext MUST fail nip44_decrypt and MUST succeed nip04_decrypt.

    #[test]
    fn kind4_uses_nip04_not_nip44() {
        use crate::nip44;

        let (sk_a, pk_a) = test_keypair();
        let (sk_b, pk_b) = test_keypair();

        let plaintext = "Kind-4 direct message";

        // Build a genuine NIP-04 (AES-CBC) ciphertext
        let nip04_wire = nip04_encrypt(&sk_a, &pk_b, plaintext).unwrap();

        // Correct path: nip04_decrypt succeeds
        let decrypted = nip04_decrypt(&sk_b, &pk_a, &nip04_wire).unwrap();
        assert_eq!(
            decrypted, plaintext,
            "nip04_decrypt must succeed on NIP-04 wire format"
        );

        // Bug path: nip44_decrypt must NOT succeed on NIP-04 wire format.
        // NIP-44 expects version byte 0x02 and ChaCha20-Poly1305; a NIP-04
        // base64 blob has completely different structure — will fail parsing.
        let sk_b_bytes = sk_b;
        let mut pk_a_bytes = [0u8; 32];
        if let Ok(decoded) = hex::decode(&pk_a) {
            if decoded.len() == 32 {
                pk_a_bytes.copy_from_slice(&decoded);
            }
        }
        let nip44_result = nip44::decrypt(&sk_b_bytes, &pk_a_bytes, &nip04_wire);
        assert!(
            nip44_result.is_err(),
            "nip44_decrypt must FAIL on a NIP-04 ciphertext (algorithm mismatch proves the fix is correct)"
        );
    }
}

// ── Property-based tests (native only) ────────────────────────────────────────

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
            prop_assert!(ct.contains("?iv="), "wire format must contain ?iv= separator");
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
            prop_assert_eq!(s_ab, s_ba, "shared secret must be symmetric");
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
            prop_assert!(result.is_err(), "wrong key must not decrypt");
        }
    }
}
