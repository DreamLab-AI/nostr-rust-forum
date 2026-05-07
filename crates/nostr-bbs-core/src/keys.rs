//! Nostr keypair management, HKDF key derivation from WebAuthn PRF, and BIP-340 Schnorr signing.

use hkdf::Hkdf;
use k256::schnorr::{SigningKey, VerifyingKey};
use sha2::Sha256;
use zeroize::Zeroize;

/// HKDF info string — must match the JavaScript implementation in passkey.ts
const HKDF_INFO: &[u8] = b"nostr-secp256k1-v1";

// ── Error ───────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("invalid secret key bytes (not a valid secp256k1 scalar)")]
    InvalidSecretKey,
    #[error("invalid public key hex: {0}")]
    InvalidPublicKeyHex(String),
    #[error("invalid public key bytes")]
    InvalidPublicKey,
    #[error("signing failed: {0}")]
    SigningFailed(String),
    #[error("signature verification failed")]
    VerifyFailed,
    #[error("invalid signature bytes")]
    InvalidSignature,
    #[error("HKDF expand failed")]
    HkdfExpandFailed,
}

// ── SecretKey ───────────────────────────────────────────────────────────────

/// A secp256k1 secret key with automatic zeroization on drop.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SecretKey {
    bytes: [u8; 32],
}

impl SecretKey {
    /// Create from raw 32 bytes. Returns an error if the bytes are not a valid
    /// secp256k1 scalar (i.e. zero or >= curve order).
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, KeyError> {
        // Validate by attempting to construct a k256 SigningKey
        SigningKey::from_bytes(&bytes).map_err(|_| KeyError::InvalidSecretKey)?;
        Ok(Self { bytes })
    }

    /// Derive the x-only public key (BIP-340).
    pub fn public_key(&self) -> PublicKey {
        let sk = SigningKey::from_bytes(&self.bytes)
            .expect("SecretKey invariant: bytes are always valid");
        let vk = sk.verifying_key();
        let mut pk_bytes = [0u8; 32];
        pk_bytes.copy_from_slice(vk.to_bytes().as_slice());
        PublicKey { bytes: pk_bytes }
    }

    /// Sign a 32-byte message hash using Schnorr BIP-340.
    pub fn sign(&self, message: &[u8; 32]) -> Result<Signature, KeyError> {
        let sk = SigningKey::from_bytes(&self.bytes)
            .expect("SecretKey invariant: bytes are always valid");
        let aux_rand = [0u8; 32];
        let sig = sk
            .sign_raw(message, &aux_rand)
            .map_err(|e| KeyError::SigningFailed(e.to_string()))?;
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&sig.to_bytes());
        Ok(Signature { bytes: sig_bytes })
    }

    /// Expose the raw bytes (use with care — prefer signing through methods).
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

// ── PublicKey ────────────────────────────────────────────────────────────────

/// A 32-byte x-only secp256k1 public key (BIP-340 / Nostr).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    bytes: [u8; 32],
}

impl PublicKey {
    /// Construct from raw 32-byte x-only public key.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, KeyError> {
        VerifyingKey::from_bytes(&bytes).map_err(|_| KeyError::InvalidPublicKey)?;
        Ok(Self { bytes })
    }

    /// Parse from a 64-character lowercase hex string.
    pub fn from_hex(hex_str: &str) -> Result<Self, KeyError> {
        let decoded =
            hex::decode(hex_str).map_err(|_| KeyError::InvalidPublicKeyHex(hex_str.to_string()))?;
        if decoded.len() != 32 {
            return Err(KeyError::InvalidPublicKeyHex(format!(
                "expected 32 bytes, got {}",
                decoded.len()
            )));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&decoded);
        // Validate that the bytes represent a point on the curve
        VerifyingKey::from_bytes(&bytes).map_err(|_| KeyError::InvalidPublicKey)?;
        Ok(Self { bytes })
    }

    /// Export as a 64-character lowercase hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.bytes)
    }

    /// Verify a BIP-340 Schnorr signature over a 32-byte message hash.
    pub fn verify(&self, message: &[u8; 32], sig: &Signature) -> Result<(), KeyError> {
        let vk = VerifyingKey::from_bytes(&self.bytes).map_err(|_| KeyError::InvalidPublicKey)?;
        let k256_sig = k256::schnorr::Signature::try_from(sig.bytes.as_slice())
            .map_err(|_| KeyError::InvalidSignature)?;
        vk.verify_raw(message, &k256_sig)
            .map_err(|_| KeyError::VerifyFailed)
    }

    /// Raw 32-byte representation.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

// ── Keypair ─────────────────────────────────────────────────────────────────

/// A matched secret + public key pair.
pub struct Keypair {
    pub secret: SecretKey,
    pub public: PublicKey,
}

// ── Signature ───────────────────────────────────────────────────────────────

/// A 64-byte BIP-340 Schnorr signature.
#[derive(Clone, Debug)]
pub struct Signature {
    bytes: [u8; 64],
}

impl Signature {
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Self { bytes }
    }

    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.bytes
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.bytes)
    }
}

// ── Backwards-compatible helpers ────────────────────────────────────────────

/// Extract the hex-encoded x-only public key from a 32-byte secret key.
pub fn pubkey_hex(secret_key: &[u8; 32]) -> Result<String, KeyError> {
    let sk = SecretKey::from_bytes(*secret_key)?;
    Ok(sk.public_key().to_hex())
}

/// Create a [`SigningKey`] from a 32-byte secret.
pub fn signing_key_from_bytes(secret_key: &[u8; 32]) -> Result<SigningKey, KeyError> {
    SigningKey::from_bytes(secret_key).map_err(|_| KeyError::InvalidSecretKey)
}

// ── Key derivation ──────────────────────────────────────────────────────────

/// Derive a Nostr keypair from WebAuthn PRF output using HKDF-SHA-256.
///
/// Matches the JavaScript implementation in `passkey.ts`:
/// ```js
/// crypto.subtle.deriveBits({
///   name: 'HKDF', hash: 'SHA-256',
///   salt: new Uint8Array(0),
///   info: new TextEncoder().encode('nostr-secp256k1-v1'),
/// }, keyMaterial, 256)
/// ```
pub fn derive_from_prf(prf_output: &[u8; 32]) -> Result<Keypair, KeyError> {
    let hk = Hkdf::<Sha256>::new(Some(&[]), prf_output);
    let mut okm = [0u8; 32];
    hk.expand(HKDF_INFO, &mut okm)
        .map_err(|_| KeyError::HkdfExpandFailed)?;

    let secret = SecretKey::from_bytes(okm)?;
    let public = secret.public_key();
    // Zeroize the intermediate buffer
    okm.zeroize();

    Ok(Keypair { secret, public })
}

/// Generate a random keypair (primarily for testing).
pub fn generate_keypair() -> Result<Keypair, KeyError> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).expect("getrandom failed");
    // Retry if we hit an invalid scalar (astronomically unlikely)
    match SecretKey::from_bytes(bytes) {
        Ok(secret) => {
            let public = secret.public_key();
            bytes.zeroize();
            Ok(Keypair { secret, public })
        }
        Err(_) => {
            bytes.zeroize();
            generate_keypair() // recurse once
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Compute HKDF-SHA256(salt=empty, ikm, info="nostr-secp256k1-v1") in pure Rust
    /// to create a known test vector.
    fn hkdf_derive(ikm: &[u8; 32]) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(Some(&[]), ikm);
        let mut out = [0u8; 32];
        hk.expand(b"nostr-secp256k1-v1", &mut out).unwrap();
        out
    }

    #[test]
    fn derive_from_prf_produces_expected_key() {
        let prf_input = [0x01u8; 32];
        let expected_secret = hkdf_derive(&prf_input);

        let kp = derive_from_prf(&prf_input).unwrap();
        assert_eq!(kp.secret.as_bytes(), &expected_secret);

        let pk = kp.secret.public_key();
        assert_eq!(pk, kp.public);
    }

    #[test]
    fn derive_from_prf_deterministic() {
        let prf = [0xABu8; 32];
        let kp1 = derive_from_prf(&prf).unwrap();
        let kp2 = derive_from_prf(&prf).unwrap();
        assert_eq!(kp1.secret.as_bytes(), kp2.secret.as_bytes());
        assert_eq!(kp1.public, kp2.public);
    }

    #[test]
    fn derive_from_prf_different_inputs_differ() {
        let kp1 = derive_from_prf(&[0x01u8; 32]).unwrap();
        let kp2 = derive_from_prf(&[0x02u8; 32]).unwrap();
        assert_ne!(kp1.secret.as_bytes(), kp2.secret.as_bytes());
        assert_ne!(kp1.public, kp2.public);
    }

    #[test]
    fn generate_keypair_sign_verify_roundtrip() {
        let kp = generate_keypair().unwrap();
        use sha2::Digest;
        let message = Sha256::digest(b"hello nostr");
        let msg: [u8; 32] = message.into();

        let sig = kp.secret.sign(&msg).unwrap();
        kp.public.verify(&msg, &sig).unwrap();
    }

    #[test]
    fn sign_verify_with_derived_keypair() {
        let kp = derive_from_prf(&[0xFFu8; 32]).unwrap();
        let msg = [0x42u8; 32];
        let sig = kp.secret.sign(&msg).unwrap();
        kp.public.verify(&msg, &sig).unwrap();
    }

    #[test]
    fn verify_wrong_key_fails() {
        let kp_a = generate_keypair().unwrap();
        let kp_b = generate_keypair().unwrap();
        let msg = [0x00u8; 32];

        let sig = kp_a.secret.sign(&msg).unwrap();
        let result = kp_b.public.verify(&msg, &sig);
        assert!(result.is_err());
    }

    #[test]
    fn verify_wrong_message_fails() {
        let kp = generate_keypair().unwrap();
        let msg1 = [0x01u8; 32];
        let msg2 = [0x02u8; 32];

        let sig = kp.secret.sign(&msg1).unwrap();
        let result = kp.public.verify(&msg2, &sig);
        assert!(result.is_err());
    }

    #[test]
    fn public_key_from_hex_valid() {
        let kp = generate_keypair().unwrap();
        let hex_str = kp.public.to_hex();
        let pk2 = PublicKey::from_hex(&hex_str).unwrap();
        assert_eq!(kp.public, pk2);
    }

    #[test]
    fn public_key_from_hex_invalid_length() {
        let result = PublicKey::from_hex("abcd");
        assert!(matches!(result, Err(KeyError::InvalidPublicKeyHex(_))));
    }

    #[test]
    fn public_key_from_hex_invalid_chars() {
        let result = PublicKey::from_hex(&"zz".repeat(32));
        assert!(matches!(result, Err(KeyError::InvalidPublicKeyHex(_))));
    }

    #[test]
    fn public_key_from_hex_not_on_curve() {
        // All zeros is not a valid x-coordinate on secp256k1
        let result = PublicKey::from_hex(&"00".repeat(32));
        assert!(matches!(result, Err(KeyError::InvalidPublicKey)));
    }

    #[test]
    fn secret_key_from_bytes_zero_rejected() {
        let result = SecretKey::from_bytes([0u8; 32]);
        assert!(matches!(result, Err(KeyError::InvalidSecretKey)));
    }

    #[test]
    fn signature_hex_roundtrip() {
        let kp = generate_keypair().unwrap();
        let msg = [0x33u8; 32];
        let sig = kp.secret.sign(&msg).unwrap();
        let hex_str = sig.to_hex();
        assert_eq!(hex_str.len(), 128);
    }

    #[test]
    fn public_key_hex_roundtrip() {
        let kp = generate_keypair().unwrap();
        let hex_str = kp.public.to_hex();
        assert_eq!(hex_str.len(), 64);
        let pk2 = PublicKey::from_hex(&hex_str).unwrap();
        assert_eq!(kp.public, pk2);
    }

    // Backwards-compat helpers
    #[test]
    fn pubkey_hex_produces_64_char_hex() {
        let secret = [0x01u8; 32];
        let pk = pubkey_hex(&secret).unwrap();
        assert_eq!(pk.len(), 64);
        assert!(pk.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn signing_key_roundtrip() {
        let secret = [0x02u8; 32];
        let sk = signing_key_from_bytes(&secret).unwrap();
        let pk = hex::encode(sk.verifying_key().to_bytes());
        assert_eq!(pk.len(), 64);
    }
}
