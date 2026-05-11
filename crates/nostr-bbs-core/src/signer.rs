//! NIP-46 / generic Signer trait for nostr-bbs.
//!
//! Abstracts over different key management backends:
//! - [`PrfSigner`]: wraps a local [`Keypair`] (WebAuthn PRF-derived key)
//! - `Nip07Signer` (forum-client crate): delegates to window.nostr via WASM
//!
//! The trait is `Send + Sync` on native (for tests) and plain on WASM where
//! single-threaded execution is guaranteed.

use async_trait::async_trait;
use thiserror::Error;

use crate::event::{sign_event, NostrEvent, PubkeyMismatch, UnsignedEvent};
use crate::keys::Keypair;
use crate::nip04::{nip04_decrypt as nip04_dec, nip04_encrypt as nip04_enc};
use crate::nip44::{decrypt as nip44_dec, encrypt as nip44_enc};

// ── Error ─────────────────────────────────────────────────────────────────────

/// Errors from the [`Signer`] trait.
#[derive(Debug, Error)]
pub enum SignerError {
    /// The signer could not produce a valid Schnorr signature.
    #[error("signing failed: {0}")]
    SigningFailed(String),

    /// The signed event's pubkey does not match the signer's public key.
    #[error("pubkey mismatch: expected {expected}, got {actual}")]
    PubkeyMismatch {
        /// The signer's own pubkey.
        expected: String,
        /// The pubkey embedded in the UnsignedEvent.
        actual: String,
    },

    /// The underlying key is unavailable or inaccessible (e.g. NIP-07 extension
    /// not installed, or user rejected the signing prompt).
    #[error("key unavailable: {0}")]
    KeyUnavailable(String),

    /// General purpose signing backend error.
    #[error("backend error: {0}")]
    Backend(String),

    /// Encryption failed.
    #[error("encryption failed: {0}")]
    EncryptionFailed(String),

    /// Decryption failed.
    #[error("decryption failed: {0}")]
    DecryptionFailed(String),

    /// Signer is not available (e.g. NIP-07 extension not installed).
    #[error("signer not available")]
    Unavailable,
}

impl From<PubkeyMismatch> for SignerError {
    fn from(e: PubkeyMismatch) -> Self {
        SignerError::PubkeyMismatch {
            expected: e.derived_pubkey,
            actual: e.event_pubkey,
        }
    }
}

// ── Signer trait ──────────────────────────────────────────────────────────────

/// Abstract interface for signing Nostr events.
///
/// Implementations can be synchronous wrappers (PRF-derived key) or async
/// bridges to browser extensions (NIP-07). The `async_trait` macro erases the
/// difference so callers can always `await` the sign call.
#[async_trait(?Send)]
pub trait Signer {
    /// Return the x-only public key (64-char hex) this signer controls.
    fn public_key(&self) -> &str;

    /// Sign an unsigned event, returning a fully signed [`NostrEvent`].
    ///
    /// The `unsigned.pubkey` field MUST match `self.public_key()`. If it does
    /// not, implementations SHOULD return [`SignerError::PubkeyMismatch`].
    async fn sign_event(&self, unsigned: UnsignedEvent) -> Result<NostrEvent, SignerError>;

    /// NIP-44 encrypt plaintext to a recipient (ChaCha20-Poly1305).
    async fn nip44_encrypt(
        &self,
        recipient_pubkey_hex: &str,
        plaintext: &str,
    ) -> Result<String, SignerError>;

    /// NIP-44 decrypt ciphertext from a sender (ChaCha20-Poly1305).
    async fn nip44_decrypt(
        &self,
        sender_pubkey_hex: &str,
        ciphertext: &str,
    ) -> Result<String, SignerError>;

    /// NIP-04 encrypt plaintext to a recipient (AES-256-CBC).
    async fn nip04_encrypt(
        &self,
        recipient_pubkey_hex: &str,
        plaintext: &str,
    ) -> Result<String, SignerError>;

    /// NIP-04 decrypt ciphertext from a sender (AES-256-CBC).
    async fn nip04_decrypt(
        &self,
        sender_pubkey_hex: &str,
        ciphertext: &str,
    ) -> Result<String, SignerError>;
}

// ── PrfSigner ─────────────────────────────────────────────────────────────────

/// A [`Signer`] backed by a locally held [`Keypair`] (e.g. derived from a
/// WebAuthn PRF output via HKDF).
///
/// This is the default signer for passkey-authenticated sessions. The private
/// key lives only in memory and is zeroized on drop via the [`Keypair`]
/// implementation.
pub struct PrfSigner {
    keypair: Keypair,
    pubkey_hex: String,
}

impl PrfSigner {
    /// Create a `PrfSigner` from an existing keypair.
    pub fn new(keypair: Keypair) -> Self {
        let pubkey_hex = keypair.public.to_hex();
        Self {
            keypair,
            pubkey_hex,
        }
    }

    /// Return a reference to the underlying [`Keypair`].
    pub fn keypair(&self) -> &Keypair {
        &self.keypair
    }
}

#[async_trait(?Send)]
impl Signer for PrfSigner {
    fn public_key(&self) -> &str {
        &self.pubkey_hex
    }

    async fn sign_event(&self, unsigned: UnsignedEvent) -> Result<NostrEvent, SignerError> {
        // Build the k256 signing key from raw bytes
        let sk_bytes = self.keypair.secret.as_bytes();
        let signing_key = k256::schnorr::SigningKey::from_bytes(sk_bytes)
            .map_err(|e| SignerError::SigningFailed(e.to_string()))?;

        sign_event(unsigned, &signing_key).map_err(SignerError::from)
    }

    async fn nip44_encrypt(
        &self,
        recipient_pubkey_hex: &str,
        plaintext: &str,
    ) -> Result<String, SignerError> {
        let pk = parse_pk32(recipient_pubkey_hex)?;
        nip44_enc(self.keypair.secret.as_bytes(), &pk, plaintext)
            .map_err(|e| SignerError::EncryptionFailed(e.to_string()))
    }

    async fn nip44_decrypt(
        &self,
        sender_pubkey_hex: &str,
        ciphertext: &str,
    ) -> Result<String, SignerError> {
        let pk = parse_pk32(sender_pubkey_hex)?;
        nip44_dec(self.keypair.secret.as_bytes(), &pk, ciphertext)
            .map_err(|e| SignerError::DecryptionFailed(e.to_string()))
    }

    async fn nip04_encrypt(
        &self,
        recipient_pubkey_hex: &str,
        plaintext: &str,
    ) -> Result<String, SignerError> {
        nip04_enc(
            self.keypair.secret.as_bytes(),
            recipient_pubkey_hex,
            plaintext,
        )
        .map_err(|e| SignerError::EncryptionFailed(e.to_string()))
    }

    async fn nip04_decrypt(
        &self,
        sender_pubkey_hex: &str,
        ciphertext: &str,
    ) -> Result<String, SignerError> {
        nip04_dec(
            self.keypair.secret.as_bytes(),
            sender_pubkey_hex,
            ciphertext,
        )
        .map_err(|e| SignerError::DecryptionFailed(e.to_string()))
    }
}

fn parse_pk32(hex_str: &str) -> Result<[u8; 32], SignerError> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| SignerError::Backend(format!("pubkey hex decode: {e}")))?;
    if bytes.len() != 32 {
        return Err(SignerError::Backend(format!(
            "expected 32-byte pubkey, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    use crate::keys::generate_keypair;

    #[allow(dead_code)]
    fn make_prf_signer() -> (PrfSigner, String) {
        let kp = generate_keypair().unwrap();
        let pk = kp.public.to_hex();
        (PrfSigner::new(kp), pk)
    }

    #[test]
    fn prf_signer_public_key_matches_keypair() {
        let kp = generate_keypair().unwrap();
        let expected_pk = kp.public.to_hex();
        let signer = PrfSigner::new(kp);
        assert_eq!(signer.public_key(), expected_pk);
    }

    #[test]
    fn signer_error_from_pubkey_mismatch() {
        let mismatch = PubkeyMismatch {
            derived_pubkey: "aa".repeat(32),
            event_pubkey: "bb".repeat(32),
        };
        let err = SignerError::from(mismatch);
        assert!(matches!(err, SignerError::PubkeyMismatch { .. }));
    }

    #[test]
    fn nip44_roundtrip_via_signer() {
        let kp_a = generate_keypair().unwrap();
        let kp_b = generate_keypair().unwrap();
        let pk_a = kp_a.public.to_hex();
        let pk_b = kp_b.public.to_hex();
        let signer_a = PrfSigner::new(kp_a);
        let signer_b = PrfSigner::new(kp_b);

        let ct = block_on(signer_a.nip44_encrypt(&pk_b, "nip44 test")).unwrap();
        let pt = block_on(signer_b.nip44_decrypt(&pk_a, &ct)).unwrap();
        assert_eq!(pt, "nip44 test");
    }

    #[test]
    fn nip04_roundtrip_via_signer() {
        let kp_a = generate_keypair().unwrap();
        let kp_b = generate_keypair().unwrap();
        let pk_a = kp_a.public.to_hex();
        let pk_b = kp_b.public.to_hex();
        let signer_a = PrfSigner::new(kp_a);
        let signer_b = PrfSigner::new(kp_b);

        let ct = block_on(signer_a.nip04_encrypt(&pk_b, "nip04 test")).unwrap();
        assert!(ct.contains("?iv="), "NIP-04 must have ?iv= separator");
        let pt = block_on(signer_b.nip04_decrypt(&pk_a, &ct)).unwrap();
        assert_eq!(pt, "nip04 test");
    }

    /// Minimal synchronous executor: polls a future until Ready.
    ///
    /// All [`Signer`] implementations in this crate (and in the
    /// forum-client crate) resolve to `Ready` on the first poll because no
    /// I/O is involved — sign + encrypt operations are pure CPU. To avoid
    /// the previous `Poll::Pending => panic!` (audit H14), we spin-poll a
    /// bounded number of iterations and then return a sentinel via `Err`
    /// surfacing as a [`SignerError::Backend`]. In practice the loop never
    /// runs more than once.
    ///
    /// This helper is `#[cfg(test)]` only, so the bounded spin is
    /// acceptable — it is never reached from production code paths.
    fn block_on<F>(f: F) -> F::Output
    where
        F: std::future::Future,
        F::Output: BlockOnSentinel,
    {
        use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
        fn noop_clone(p: *const ()) -> RawWaker {
            RawWaker::new(p, &VTAB)
        }
        fn noop(_: *const ()) {}
        static VTAB: RawWakerVTable = RawWakerVTable::new(noop_clone, noop, noop, noop);
        let waker = unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTAB)) };
        let mut cx = Context::from_waker(&waker);
        let mut pinned = Box::pin(f);
        const MAX_SPINS: usize = 64;
        for _ in 0..MAX_SPINS {
            match pinned.as_mut().poll(&mut cx) {
                Poll::Ready(v) => return v,
                Poll::Pending => continue,
            }
        }
        // Should never happen for the I/O-free Signer impls in this crate,
        // but if it does we surface the error rather than panic so the test
        // run reports the failure cleanly.
        F::Output::from_pending_timeout()
    }

    /// Allows `block_on` to construct a sentinel for the very rare case
    /// that a future never resolves within the spin budget. Implementations
    /// exist for the concrete `Result<T, SignerError>` types used by
    /// `Signer` and for `String` (used by the encrypt/decrypt return types).
    trait BlockOnSentinel {
        fn from_pending_timeout() -> Self;
    }

    impl<T, E> BlockOnSentinel for Result<T, E>
    where
        E: From<SignerError>,
    {
        fn from_pending_timeout() -> Self {
            Err(
                SignerError::Backend("block_on: future did not resolve within spin budget".into())
                    .into(),
            )
        }
    }
}
