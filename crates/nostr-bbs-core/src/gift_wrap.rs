//! NIP-59 Gift Wrap: Triple-layered encrypted direct messages.
//!
//! Creates three layers of indirection to protect DM metadata:
//!
//! 1. **Rumor** (kind 14) — unsigned event with the actual message content
//! 2. **Seal** (kind 13) — NIP-44 encrypts the rumor, signed by the sender
//! 3. **Gift Wrap** (kind 1059) — NIP-44 encrypts the seal with a throwaway key
//!
//! The outer gift wrap reveals only the recipient (needed for relay routing) and
//! a throwaway pubkey. The sender's identity is hidden inside the encrypted seal.

use crate::event::{sign_event, verify_event_strict, NostrEvent, UnsignedEvent};
use crate::keys::generate_keypair;
use crate::nip04;
use crate::nip44;
use k256::schnorr::SigningKey;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroize;

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum random offset for timestamp obfuscation: 48 hours in seconds.
const TIMESTAMP_JITTER_SECS: u32 = 172_800;

/// Nostr kind for Rumor (unsigned DM content).
const KIND_RUMOR: u64 = 14;

/// Nostr kind for Seal (encrypted rumor, signed by sender).
const KIND_SEAL: u64 = 13;

/// Nostr kind for Gift Wrap (encrypted seal, signed by throwaway key).
pub const KIND_GIFT_WRAP: u64 = 1059;

// ── Error type ───────────────────────────────────────────────────────────────

/// Errors that can occur during gift-wrap creation or unwrapping.
#[derive(Debug, Error)]
pub enum GiftWrapError {
    /// JSON serialization or deserialization failed.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// NIP-44 encryption failed.
    #[error("encryption error: {0}")]
    Encryption(String),

    /// NIP-44 decryption failed.
    #[error("decryption error: {0}")]
    Decryption(String),

    /// The event kind does not match what was expected.
    #[error("invalid event kind: expected {expected}, got {actual}")]
    InvalidKind {
        /// The kind that was expected.
        expected: u64,
        /// The kind that was found.
        actual: u64,
    },

    /// Failed to parse a hex-encoded public key.
    #[error("invalid public key: {0}")]
    InvalidPubkey(String),

    /// Key generation or signing failed.
    #[error("key error: {0}")]
    KeyError(String),

    /// The inner event structure is malformed.
    #[error("parse error: {0}")]
    ParseError(String),

    /// The decrypted seal's id/signature failed verification. NIP-59 requires
    /// the seal (kind 13) to be signed by the sender; an unverified seal lets
    /// an attacker forge the `sender_pubkey`.
    #[error("seal verification failed: {0}")]
    SealVerification(String),

    /// The rumor's author does not match the verified seal signer. NIP-59
    /// binds `rumor.pubkey == seal.pubkey`; a mismatch means the inner author
    /// is attacker-controlled independent of who signed the seal.
    #[error("author mismatch: rumor pubkey {rumor} != seal pubkey {seal}")]
    AuthorMismatch {
        /// The pubkey claimed inside the rumor.
        rumor: String,
        /// The verified pubkey that signed the seal.
        seal: String,
    },
}

// ── Output types ─────────────────────────────────────────────────────────────

/// The result of unwrapping a gift-wrapped event, exposing all three layers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnwrappedGift {
    /// The sender's real public key (from the seal's pubkey field).
    pub sender_pubkey: String,
    /// The inner rumor (kind 14) containing the actual message.
    pub rumor: UnsignedEvent,
    /// The intermediate seal (kind 13).
    pub seal: NostrEvent,
}

// ── Timestamp helpers ────────────────────────────────────────────────────────

/// Get the current Unix timestamp in seconds, platform-aware.
fn now_secs() -> u64 {
    #[cfg(target_arch = "wasm32")]
    {
        (js_sys::Date::now() / 1000.0) as u64
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before UNIX epoch")
            .as_secs()
    }
}

/// Generate a randomized timestamp within +/- TIMESTAMP_JITTER_SECS of now.
///
/// Uses `getrandom` to produce a random offset, then randomly adds or subtracts
/// it from the current time. This prevents timing correlation attacks.
fn randomized_timestamp() -> u64 {
    let now = now_secs();

    // Get 5 random bytes: 4 for offset magnitude, 1 for direction
    let mut rand_bytes = [0u8; 5];
    getrandom::getrandom(&mut rand_bytes).expect("getrandom for timestamp jitter");

    let offset_raw =
        u32::from_le_bytes([rand_bytes[0], rand_bytes[1], rand_bytes[2], rand_bytes[3]]);
    let offset = (offset_raw % TIMESTAMP_JITTER_SECS) as u64;
    let add = rand_bytes[4] & 1 == 0;

    if add {
        now.saturating_add(offset)
    } else {
        now.saturating_sub(offset)
    }
}

// ── Hex helpers ──────────────────────────────────────────────────────────────

/// Decode a 64-char hex string into a 32-byte array.
fn hex_to_32(hex_str: &str) -> Result<[u8; 32], GiftWrapError> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| GiftWrapError::InvalidPubkey(format!("hex decode: {e}")))?;
    if bytes.len() != 32 {
        return Err(GiftWrapError::InvalidPubkey(format!(
            "expected 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

// ── Layer 1: Rumor ───────────────────────────────────────────────────────────

/// Create an unsigned Rumor event (kind 14) containing the DM content.
///
/// The rumor uses the sender's real pubkey and a real timestamp. It is never
/// published directly — it exists only inside an encrypted seal.
///
/// # Arguments
/// * `sender_pubkey` - 64-char hex sender pubkey
/// * `recipient_pubkey` - 64-char hex recipient pubkey (used in `p` tag)
/// * `content` - The plaintext message
pub fn create_rumor(sender_pubkey: &str, recipient_pubkey: &str, content: &str) -> UnsignedEvent {
    UnsignedEvent {
        pubkey: sender_pubkey.to_string(),
        created_at: now_secs(),
        kind: KIND_RUMOR,
        tags: vec![vec!["p".to_string(), recipient_pubkey.to_string()]],
        content: content.to_string(),
    }
}

// ── Layer 2: Seal ────────────────────────────────────────────────────────────

/// Seal a rumor by NIP-44-encrypting it and signing with the sender's key.
///
/// Produces a kind 13 event with:
/// - Randomized timestamp (now +/- 48h)
/// - Empty tags (no metadata leak)
/// - Content: NIP-44 encrypted JSON of the rumor
/// - Signed by the sender's real key
///
/// # Arguments
/// * `rumor` - The unsigned rumor event to seal
/// * `sender_sk` - 32-byte sender secret key
/// * `recipient_pk` - 32-byte recipient x-only public key
pub fn seal_rumor(
    rumor: &UnsignedEvent,
    sender_sk: &[u8; 32],
    recipient_pk: &[u8; 32],
) -> Result<NostrEvent, GiftWrapError> {
    // Serialize the rumor to JSON
    let rumor_json =
        serde_json::to_string(rumor).map_err(|e| GiftWrapError::Serialization(e.to_string()))?;

    // NIP-44 encrypt: sender → recipient
    let encrypted = nip44::encrypt(sender_sk, recipient_pk, &rumor_json)
        .map_err(|e| GiftWrapError::Encryption(e.to_string()))?;

    // Build the signing key to derive the sender pubkey
    let signing_key = SigningKey::from_bytes(sender_sk)
        .map_err(|e| GiftWrapError::KeyError(format!("invalid sender secret key: {e}")))?;
    let sender_pubkey = hex::encode(signing_key.verifying_key().to_bytes());

    // Create the seal event with randomized timestamp and empty tags
    let unsigned_seal = UnsignedEvent {
        pubkey: sender_pubkey,
        created_at: randomized_timestamp(),
        kind: KIND_SEAL,
        tags: vec![],
        content: encrypted,
    };

    sign_event(unsigned_seal, &signing_key)
        .map_err(|e| GiftWrapError::KeyError(format!("seal signing failed: {e}")))
}

// ── Layer 3: Gift Wrap ───────────────────────────────────────────────────────

/// Wrap a seal in a gift wrap using a random throwaway keypair.
///
/// Produces a kind 1059 event with:
/// - Throwaway random pubkey (reveals nothing about the sender)
/// - Randomized timestamp (now +/- 48h)
/// - `["p", recipient_pubkey]` tag (needed for relay routing)
/// - Content: NIP-44 encrypted JSON of the seal
/// - Signed by the throwaway key
///
/// The throwaway secret key is zeroized after signing.
///
/// # Arguments
/// * `seal` - The signed seal event (kind 13)
/// * `recipient_pubkey` - 64-char hex recipient pubkey
pub fn wrap_seal(seal: &NostrEvent, recipient_pubkey: &str) -> Result<NostrEvent, GiftWrapError> {
    // Generate a throwaway keypair
    let throwaway = generate_keypair()
        .map_err(|e| GiftWrapError::KeyError(format!("throwaway keypair generation: {e}")))?;

    let throwaway_sk_bytes = *throwaway.secret.as_bytes();
    let throwaway_pubkey = throwaway.public.to_hex();

    // Serialize the seal to JSON
    let seal_json =
        serde_json::to_string(seal).map_err(|e| GiftWrapError::Serialization(e.to_string()))?;

    // Decode recipient pubkey for NIP-44
    let recipient_pk_bytes = hex_to_32(recipient_pubkey)?;

    // NIP-44 encrypt: throwaway → recipient
    let encrypted = nip44::encrypt(&throwaway_sk_bytes, &recipient_pk_bytes, &seal_json)
        .map_err(|e| GiftWrapError::Encryption(e.to_string()))?;

    // Build the gift wrap event
    let unsigned_wrap = UnsignedEvent {
        pubkey: throwaway_pubkey,
        created_at: randomized_timestamp(),
        kind: KIND_GIFT_WRAP,
        tags: vec![vec!["p".to_string(), recipient_pubkey.to_string()]],
        content: encrypted,
    };

    let throwaway_signing_key = SigningKey::from_bytes(&throwaway_sk_bytes)
        .map_err(|e| GiftWrapError::KeyError(format!("throwaway signing key: {e}")))?;

    let wrapped = sign_event(unsigned_wrap, &throwaway_signing_key)
        .map_err(|e| GiftWrapError::KeyError(format!("gift wrap signing failed: {e}")))?;

    // Zeroize throwaway secret key material
    let mut sk_to_zeroize = throwaway_sk_bytes;
    sk_to_zeroize.zeroize();
    // The Keypair's SecretKey also auto-zeroizes on drop via its Zeroize derive.

    Ok(wrapped)
}

// ── Convenience: full pipeline ───────────────────────────────────────────────

/// Create a fully gift-wrapped DM in one call: rumor -> seal -> wrap.
///
/// This is the primary entry point for sending encrypted DMs via NIP-59.
/// Returns the kind 1059 outer event ready for relay publication.
///
/// # Arguments
/// * `sender_sk` - 32-byte sender secret key
/// * `sender_pubkey` - 64-char hex sender pubkey
/// * `recipient_pubkey` - 64-char hex recipient pubkey
/// * `content` - The plaintext DM content
pub fn gift_wrap(
    sender_sk: &[u8; 32],
    sender_pubkey: &str,
    recipient_pubkey: &str,
    content: &str,
) -> Result<NostrEvent, GiftWrapError> {
    let recipient_pk_bytes = hex_to_32(recipient_pubkey)?;

    let rumor = create_rumor(sender_pubkey, recipient_pubkey, content);
    let seal = seal_rumor(&rumor, sender_sk, &recipient_pk_bytes)?;
    wrap_seal(&seal, recipient_pubkey)
}

// ── Unwrapping ───────────────────────────────────────────────────────────────

/// Unwrap a gift-wrapped event, decrypting both layers to recover the rumor.
///
/// Performs:
/// 1. Validates the outer event is kind 1059
/// 2. NIP-44 decrypts content using `recipient_sk` + gift's throwaway pubkey → Seal
/// 3. Validates the seal is kind 13
/// 4. NIP-44 decrypts seal content using `recipient_sk` + seal's sender pubkey → Rumor
/// 5. Validates the rumor is kind 14
///
/// # Arguments
/// * `gift` - The kind 1059 gift wrap event
/// * `recipient_sk` - 32-byte recipient secret key
pub fn unwrap_gift(
    gift: &NostrEvent,
    recipient_sk: &[u8; 32],
) -> Result<UnwrappedGift, GiftWrapError> {
    // Validate outer kind
    if gift.kind != KIND_GIFT_WRAP {
        return Err(GiftWrapError::InvalidKind {
            expected: KIND_GIFT_WRAP,
            actual: gift.kind,
        });
    }

    // Decrypt layer 1: gift wrap → seal
    // The gift's pubkey is the throwaway key that encrypted the content
    let throwaway_pk_bytes = hex_to_32(&gift.pubkey)?;
    let seal_json = nip44::decrypt(recipient_sk, &throwaway_pk_bytes, &gift.content)
        .map_err(|e| GiftWrapError::Decryption(format!("gift wrap decryption: {e}")))?;

    let seal: NostrEvent = serde_json::from_str(&seal_json)
        .map_err(|e| GiftWrapError::ParseError(format!("seal JSON parse: {e}")))?;

    // Validate seal kind
    if seal.kind != KIND_SEAL {
        return Err(GiftWrapError::InvalidKind {
            expected: KIND_SEAL,
            actual: seal.kind,
        });
    }

    // Verify the seal's id + Schnorr signature before trusting `seal.pubkey`
    // as the sender. NIP-59: the seal is signed by the sender's real key.
    // Without this, an attacker can forge the seal's pubkey to impersonate any
    // author.
    verify_event_strict(&seal).map_err(|e| GiftWrapError::SealVerification(e.to_string()))?;

    // Decrypt layer 2: seal → rumor
    // The seal's pubkey is the sender's real key
    let sender_pk_bytes = hex_to_32(&seal.pubkey)?;
    let rumor_json = nip44::decrypt(recipient_sk, &sender_pk_bytes, &seal.content)
        .map_err(|e| GiftWrapError::Decryption(format!("seal decryption: {e}")))?;

    let rumor: UnsignedEvent = serde_json::from_str(&rumor_json)
        .map_err(|e| GiftWrapError::ParseError(format!("rumor JSON parse: {e}")))?;

    // Validate rumor kind
    if rumor.kind != KIND_RUMOR {
        return Err(GiftWrapError::InvalidKind {
            expected: KIND_RUMOR,
            actual: rumor.kind,
        });
    }

    // Bind the rumor's author to the verified seal signer. NIP-59 requires
    // rumor.pubkey == seal.pubkey; otherwise the inner author is
    // attacker-controlled independent of who actually signed the seal.
    if rumor.pubkey != seal.pubkey {
        return Err(GiftWrapError::AuthorMismatch {
            rumor: rumor.pubkey.clone(),
            seal: seal.pubkey.clone(),
        });
    }

    Ok(UnwrappedGift {
        sender_pubkey: seal.pubkey.clone(),
        rumor,
        seal,
    })
}

// ── Signer-based gift wrap (works for local-key AND NIP-07) ────────────────────

use crate::signer::{Signer, SignerError};

/// Errors from the [`Signer`]-driven gift-wrap path.
///
/// Distinct from [`GiftWrapError`] because these operations are async and may
/// fail in the signing backend (e.g. a NIP-07 extension rejecting a prompt).
#[derive(Debug, Error)]
pub enum SignerGiftWrapError {
    /// The signing/encryption backend failed (local crypto or NIP-07 bridge).
    #[error("signer error: {0}")]
    Signer(#[from] SignerError),

    /// JSON (de)serialization of a layer failed.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// A decrypted layer had an unexpected event kind.
    #[error("invalid event kind: expected {expected}, got {actual}")]
    InvalidKind {
        /// The expected kind.
        expected: u64,
        /// The kind actually found.
        actual: u64,
    },

    /// Throwaway-key generation or signing failed (gift-wrap outer layer).
    #[error("key error: {0}")]
    KeyError(String),

    /// The decrypted seal's id/signature failed verification (see
    /// [`GiftWrapError::SealVerification`]).
    #[error("seal verification failed: {0}")]
    SealVerification(String),

    /// The rumor's author does not match the verified seal signer (see
    /// [`GiftWrapError::AuthorMismatch`]).
    #[error("author mismatch: rumor pubkey {rumor} != seal pubkey {seal}")]
    AuthorMismatch {
        /// The pubkey claimed inside the rumor.
        rumor: String,
        /// The verified pubkey that signed the seal.
        seal: String,
    },
}

/// Seal a rumor using a [`Signer`] for the sender's identity operations.
///
/// The NIP-44 encryption of the rumor and the kind-13 signature both go through
/// the signer, so this works for an in-memory local key (`PrfSigner`) **and** a
/// NIP-07 extension (`Nip07Signer`) — neither requires raw secret-key bytes.
async fn seal_rumor_with_signer(
    rumor: &UnsignedEvent,
    signer: &dyn Signer,
    recipient_pubkey: &str,
) -> Result<NostrEvent, SignerGiftWrapError> {
    let rumor_json = serde_json::to_string(rumor)
        .map_err(|e| SignerGiftWrapError::Serialization(e.to_string()))?;

    // NIP-44 encrypt the rumor to the recipient via the signer (sender → recipient).
    let encrypted = signer.nip44_encrypt(recipient_pubkey, &rumor_json).await?;

    let unsigned_seal = UnsignedEvent {
        pubkey: signer.public_key().to_string(),
        created_at: randomized_timestamp(),
        kind: KIND_SEAL,
        tags: vec![],
        content: encrypted,
    };

    // The seal must be signed by the sender's real key — the signer does this
    // whether the key is local (PrfSigner) or held by the extension (NIP-07).
    Ok(signer.sign_event(unsigned_seal).await?)
}

/// Create a fully gift-wrapped DM using a [`Signer`]: rumor → seal → wrap.
///
/// This is the signer-driven analogue of [`gift_wrap`]. The sender's seal
/// (NIP-44 encrypt + kind-13 signature) is produced through the signer, so the
/// caller does not need raw secret-key bytes. The outer wrap uses a throwaway
/// keypair (pure local crypto, no identity), exactly like [`wrap_seal`].
pub async fn gift_wrap_with_signer(
    signer: &dyn Signer,
    recipient_pubkey: &str,
    content: &str,
) -> Result<NostrEvent, SignerGiftWrapError> {
    let sender_pubkey = signer.public_key();
    let rumor = create_rumor(sender_pubkey, recipient_pubkey, content);
    let seal = seal_rumor_with_signer(&rumor, signer, recipient_pubkey).await?;
    wrap_seal(&seal, recipient_pubkey).map_err(|e| SignerGiftWrapError::KeyError(e.to_string()))
}

/// Unwrap a gift-wrapped (kind 1059) event using a [`Signer`] for decryption.
///
/// Both NIP-44 layers (gift→seal and seal→rumor) are decrypted through the
/// signer, so a local-key session decrypts in-memory and a NIP-07 session
/// decrypts via `window.nostr.nip44.decrypt`. No raw secret-key bytes are
/// required: the in-memory (or extension-held) signing key has full authority.
pub async fn unwrap_gift_with_signer(
    gift: &NostrEvent,
    signer: &dyn Signer,
) -> Result<UnwrappedGift, SignerGiftWrapError> {
    if gift.kind != KIND_GIFT_WRAP {
        return Err(SignerGiftWrapError::InvalidKind {
            expected: KIND_GIFT_WRAP,
            actual: gift.kind,
        });
    }

    // Layer 1: gift wrap → seal. The gift's pubkey is the throwaway key the
    // sender used to encrypt to us; we decrypt with our key against it.
    let seal_json = signer.nip44_decrypt(&gift.pubkey, &gift.content).await?;
    let seal: NostrEvent = serde_json::from_str(&seal_json)
        .map_err(|e| SignerGiftWrapError::Serialization(format!("seal JSON parse: {e}")))?;

    if seal.kind != KIND_SEAL {
        return Err(SignerGiftWrapError::InvalidKind {
            expected: KIND_SEAL,
            actual: seal.kind,
        });
    }

    // Verify the seal's id + Schnorr signature before trusting `seal.pubkey`
    // as the sender (NIP-59: the seal is signed by the sender's real key).
    verify_event_strict(&seal).map_err(|e| SignerGiftWrapError::SealVerification(e.to_string()))?;

    // Layer 2: seal → rumor. The seal's pubkey is the sender's real key.
    let rumor_json = signer.nip44_decrypt(&seal.pubkey, &seal.content).await?;
    let rumor: UnsignedEvent = serde_json::from_str(&rumor_json)
        .map_err(|e| SignerGiftWrapError::Serialization(format!("rumor JSON parse: {e}")))?;

    if rumor.kind != KIND_RUMOR {
        return Err(SignerGiftWrapError::InvalidKind {
            expected: KIND_RUMOR,
            actual: rumor.kind,
        });
    }

    // Bind the rumor's author to the verified seal signer (NIP-59:
    // rumor.pubkey == seal.pubkey).
    if rumor.pubkey != seal.pubkey {
        return Err(SignerGiftWrapError::AuthorMismatch {
            rumor: rumor.pubkey.clone(),
            seal: seal.pubkey.clone(),
        });
    }

    Ok(UnwrappedGift {
        sender_pubkey: seal.pubkey.clone(),
        rumor,
        seal,
    })
}

// ── Kind-4 (NIP-04) direct message handling ───────────────────────────────────

/// Nostr kind for legacy encrypted DM (NIP-04).
pub const KIND_ENCRYPTED_DM: u64 = 4;

/// Decrypt a kind-4 (NIP-04) encrypted direct message.
///
/// Kind-4 events use NIP-04 (AES-256-CBC) — **not** NIP-44. This function
/// corrects the historical mistake of calling `nip44_decrypt` on kind-4 content.
///
/// # Arguments
/// * `event` - The kind-4 event to decrypt
/// * `recipient_sk` - 32-byte recipient secret key
pub fn process_kind4_event(
    event: &NostrEvent,
    recipient_sk: &[u8; 32],
) -> Result<String, GiftWrapError> {
    if event.kind != KIND_ENCRYPTED_DM {
        return Err(GiftWrapError::InvalidKind {
            expected: KIND_ENCRYPTED_DM,
            actual: event.kind,
        });
    }

    // The sender's pubkey is the event pubkey; use NIP-04 (AES-256-CBC), NOT NIP-44
    nip04::nip04_decrypt(recipient_sk, &event.pubkey, &event.content)
        .map_err(|e| GiftWrapError::Decryption(format!("NIP-04 decryption: {e}")))
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::generate_keypair as gen_kp;

    /// Helper: create a sender/recipient keypair pair, returning (sk_bytes, pubkey_hex).
    fn test_keypair() -> ([u8; 32], String) {
        let kp = gen_kp().unwrap();
        let sk = *kp.secret.as_bytes();
        let pk = kp.public.to_hex();
        (sk, pk)
    }

    #[test]
    fn create_rumor_has_correct_structure() {
        let sender_pk = "aa".repeat(32);
        let recipient_pk = "bb".repeat(32);
        let rumor = create_rumor(&sender_pk, &recipient_pk, "hello");

        assert_eq!(rumor.kind, KIND_RUMOR);
        assert_eq!(rumor.pubkey, sender_pk);
        assert_eq!(rumor.content, "hello");
        assert_eq!(rumor.tags.len(), 1);
        assert_eq!(rumor.tags[0], vec!["p", &recipient_pk]);
        assert!(rumor.created_at > 0);
    }

    #[test]
    fn seal_rumor_produces_kind_13() {
        let (sender_sk, sender_pk) = test_keypair();
        let (_, recipient_pk) = test_keypair();
        let recipient_pk_bytes = hex_to_32(&recipient_pk).unwrap();

        let rumor = create_rumor(&sender_pk, &recipient_pk, "sealed message");
        let seal = seal_rumor(&rumor, &sender_sk, &recipient_pk_bytes).unwrap();

        assert_eq!(seal.kind, KIND_SEAL);
        assert_eq!(seal.pubkey, sender_pk);
        assert!(seal.tags.is_empty());
        assert!(!seal.content.is_empty());
        assert!(!seal.id.is_empty());
        assert!(!seal.sig.is_empty());
    }

    #[test]
    fn seal_has_randomized_timestamp() {
        let (sender_sk, sender_pk) = test_keypair();
        let (_, recipient_pk) = test_keypair();
        let recipient_pk_bytes = hex_to_32(&recipient_pk).unwrap();

        let rumor = create_rumor(&sender_pk, &recipient_pk, "timing test");
        let seal1 = seal_rumor(&rumor, &sender_sk, &recipient_pk_bytes).unwrap();
        let seal2 = seal_rumor(&rumor, &sender_sk, &recipient_pk_bytes).unwrap();

        // The two seals should have different randomized timestamps with high probability.
        // There is a negligible chance they could be equal, so we just check they are
        // within the jitter range of now.
        let now = now_secs();
        let jitter = TIMESTAMP_JITTER_SECS as u64;
        assert!(seal1.created_at >= now.saturating_sub(jitter));
        assert!(seal1.created_at <= now.saturating_add(jitter));
        assert!(seal2.created_at >= now.saturating_sub(jitter));
        assert!(seal2.created_at <= now.saturating_add(jitter));
    }

    #[test]
    fn wrap_seal_produces_kind_1059() {
        let (sender_sk, sender_pk) = test_keypair();
        let (_, recipient_pk) = test_keypair();
        let recipient_pk_bytes = hex_to_32(&recipient_pk).unwrap();

        let rumor = create_rumor(&sender_pk, &recipient_pk, "wrapped message");
        let seal = seal_rumor(&rumor, &sender_sk, &recipient_pk_bytes).unwrap();
        let wrapped = wrap_seal(&seal, &recipient_pk).unwrap();

        assert_eq!(wrapped.kind, KIND_GIFT_WRAP);
        // The pubkey should NOT be the sender's — it should be the throwaway key
        assert_ne!(wrapped.pubkey, sender_pk);
        // Should have a p tag pointing to the recipient
        assert_eq!(wrapped.tags.len(), 1);
        assert_eq!(wrapped.tags[0][0], "p");
        assert_eq!(wrapped.tags[0][1], recipient_pk);
        assert!(!wrapped.content.is_empty());
    }

    #[test]
    fn gift_wrap_roundtrip() {
        let (sender_sk, sender_pk) = test_keypair();
        let (recipient_sk, recipient_pk) = test_keypair();

        let content = "Hello from NIP-59 gift wrap!";
        let wrapped = gift_wrap(&sender_sk, &sender_pk, &recipient_pk, content).unwrap();

        assert_eq!(wrapped.kind, KIND_GIFT_WRAP);

        let unwrapped = unwrap_gift(&wrapped, &recipient_sk).unwrap();
        assert_eq!(unwrapped.sender_pubkey, sender_pk);
        assert_eq!(unwrapped.rumor.content, content);
        assert_eq!(unwrapped.rumor.kind, KIND_RUMOR);
        assert_eq!(unwrapped.seal.kind, KIND_SEAL);
    }

    #[test]
    fn gift_wrap_roundtrip_unicode() {
        let (sender_sk, sender_pk) = test_keypair();
        let (recipient_sk, recipient_pk) = test_keypair();

        let content = "Nostr DM with unicode: 日本語テスト 🎁";
        let wrapped = gift_wrap(&sender_sk, &sender_pk, &recipient_pk, content).unwrap();
        let unwrapped = unwrap_gift(&wrapped, &recipient_sk).unwrap();

        assert_eq!(unwrapped.rumor.content, content);
    }

    #[test]
    fn gift_wrap_roundtrip_long_message() {
        let (sender_sk, sender_pk) = test_keypair();
        let (recipient_sk, recipient_pk) = test_keypair();

        let content = "A".repeat(10000);
        let wrapped = gift_wrap(&sender_sk, &sender_pk, &recipient_pk, &content).unwrap();
        let unwrapped = unwrap_gift(&wrapped, &recipient_sk).unwrap();

        assert_eq!(unwrapped.rumor.content, content);
    }

    #[test]
    fn unwrap_with_wrong_key_fails() {
        let (sender_sk, sender_pk) = test_keypair();
        let (_, recipient_pk) = test_keypair();
        let (wrong_sk, _) = test_keypair();

        let wrapped = gift_wrap(&sender_sk, &sender_pk, &recipient_pk, "secret").unwrap();
        let result = unwrap_gift(&wrapped, &wrong_sk);

        assert!(result.is_err());
        assert!(
            matches!(result, Err(GiftWrapError::Decryption(_))),
            "expected Decryption error, got: {:?}",
            result
        );
    }

    #[test]
    fn unwrap_rejects_bad_seal_signature() {
        // A gift wrap whose inner seal (kind 13) has a corrupted signature must
        // be rejected: an unverified seal lets an attacker forge the sender.
        let (sender_sk, sender_pk) = test_keypair();
        let (recipient_sk, recipient_pk) = test_keypair();
        let recipient_pk_bytes = hex_to_32(&recipient_pk).unwrap();

        let rumor = create_rumor(&sender_pk, &recipient_pk, "forged");
        let mut seal = seal_rumor(&rumor, &sender_sk, &recipient_pk_bytes).unwrap();
        // Corrupt the seal's signature so verify_event_strict fails.
        seal.sig = "00".repeat(64);
        let wrapped = wrap_seal(&seal, &recipient_pk).unwrap();

        let result = unwrap_gift(&wrapped, &recipient_sk);
        assert!(
            matches!(result, Err(GiftWrapError::SealVerification(_))),
            "expected SealVerification, got: {:?}",
            result
        );
    }

    #[test]
    fn unwrap_rejects_rumor_pubkey_mismatch() {
        // The seal is validly signed by `sender_sk`, but the rumor inside
        // claims a DIFFERENT author (`victim_pk`). NIP-59 requires
        // rumor.pubkey == seal.pubkey, so this impersonation must be rejected.
        let (sender_sk, sender_pk) = test_keypair();
        let (recipient_sk, recipient_pk) = test_keypair();
        let (_, victim_pk) = test_keypair();
        let recipient_pk_bytes = hex_to_32(&recipient_pk).unwrap();

        let rumor = create_rumor(&victim_pk, &recipient_pk, "impersonation");
        let seal = seal_rumor(&rumor, &sender_sk, &recipient_pk_bytes).unwrap();
        // The seal itself is signed by the real sender, not the victim.
        assert_eq!(seal.pubkey, sender_pk);

        let wrapped = wrap_seal(&seal, &recipient_pk).unwrap();
        let result = unwrap_gift(&wrapped, &recipient_sk);
        assert!(
            matches!(result, Err(GiftWrapError::AuthorMismatch { .. })),
            "expected AuthorMismatch, got: {:?}",
            result
        );
    }

    #[test]
    fn unwrap_rejects_wrong_outer_kind() {
        let fake_event = NostrEvent {
            id: "00".repeat(32),
            pubkey: "aa".repeat(32),
            created_at: 1700000000,
            kind: 1, // wrong kind
            tags: vec![],
            content: String::new(),
            sig: "00".repeat(64),
        };

        let (recipient_sk, _) = test_keypair();
        let result = unwrap_gift(&fake_event, &recipient_sk);

        assert!(matches!(
            result,
            Err(GiftWrapError::InvalidKind {
                expected: KIND_GIFT_WRAP,
                actual: 1
            })
        ));
    }

    #[test]
    fn gift_wrap_sender_pubkey_matches() {
        let (sender_sk, sender_pk) = test_keypair();
        let (recipient_sk, recipient_pk) = test_keypair();

        let wrapped = gift_wrap(&sender_sk, &sender_pk, &recipient_pk, "identity test").unwrap();
        let unwrapped = unwrap_gift(&wrapped, &recipient_sk).unwrap();

        // The sender pubkey recovered from the seal must match the original sender
        assert_eq!(unwrapped.sender_pubkey, sender_pk);
        // The rumor's pubkey must also match the sender
        assert_eq!(unwrapped.rumor.pubkey, sender_pk);
    }

    #[test]
    fn gift_wrap_recipient_tag_present() {
        let (sender_sk, sender_pk) = test_keypair();
        let (_, recipient_pk) = test_keypair();

        let wrapped = gift_wrap(&sender_sk, &sender_pk, &recipient_pk, "tag test").unwrap();

        // The outer gift wrap must have a p tag for relay routing
        let p_tags: Vec<_> = wrapped.tags.iter().filter(|t| t[0] == "p").collect();
        assert_eq!(p_tags.len(), 1);
        assert_eq!(p_tags[0][1], recipient_pk);
    }

    #[test]
    fn seal_has_no_tags() {
        let (sender_sk, sender_pk) = test_keypair();
        let (recipient_sk, recipient_pk) = test_keypair();

        let wrapped = gift_wrap(&sender_sk, &sender_pk, &recipient_pk, "no tags test").unwrap();
        let unwrapped = unwrap_gift(&wrapped, &recipient_sk).unwrap();

        // The seal must have empty tags (no metadata leak)
        assert!(unwrapped.seal.tags.is_empty());
    }

    #[test]
    fn rumor_has_p_tag() {
        let (sender_sk, sender_pk) = test_keypair();
        let (recipient_sk, recipient_pk) = test_keypair();

        let wrapped = gift_wrap(&sender_sk, &sender_pk, &recipient_pk, "p tag test").unwrap();
        let unwrapped = unwrap_gift(&wrapped, &recipient_sk).unwrap();

        let p_tags: Vec<_> = unwrapped
            .rumor
            .tags
            .iter()
            .filter(|t| t[0] == "p")
            .collect();
        assert_eq!(p_tags.len(), 1);
        assert_eq!(p_tags[0][1], recipient_pk);
    }

    #[test]
    fn outer_pubkey_is_throwaway() {
        let (sender_sk, sender_pk) = test_keypair();
        let (_, recipient_pk) = test_keypair();

        let wrapped1 = gift_wrap(&sender_sk, &sender_pk, &recipient_pk, "throwaway 1").unwrap();
        let wrapped2 = gift_wrap(&sender_sk, &sender_pk, &recipient_pk, "throwaway 2").unwrap();

        // Each gift wrap should use a different throwaway key
        assert_ne!(wrapped1.pubkey, wrapped2.pubkey);
        // Neither should be the sender's key
        assert_ne!(wrapped1.pubkey, sender_pk);
        assert_ne!(wrapped2.pubkey, sender_pk);
    }

    #[test]
    fn gift_wrap_event_verifies() {
        let (sender_sk, sender_pk) = test_keypair();
        let (_, recipient_pk) = test_keypair();

        let wrapped = gift_wrap(&sender_sk, &sender_pk, &recipient_pk, "verify test").unwrap();

        // The outer event should be verifiable (signed by throwaway key)
        assert!(crate::event::verify_event(&wrapped));
    }

    #[test]
    fn seal_event_verifies() {
        let (sender_sk, sender_pk) = test_keypair();
        let (recipient_sk, recipient_pk) = test_keypair();

        let wrapped = gift_wrap(&sender_sk, &sender_pk, &recipient_pk, "seal verify test").unwrap();
        let unwrapped = unwrap_gift(&wrapped, &recipient_sk).unwrap();

        // The seal should be verifiable (signed by sender's key)
        assert!(crate::event::verify_event(&unwrapped.seal));
    }

    // ── Signer-driven path ──────────────────────────────────────────────────

    use crate::signer::PrfSigner;

    /// Minimal synchronous executor for the I/O-free `PrfSigner` futures.
    /// `PrfSigner` resolves on the first poll (pure CPU), so a single poll of a
    /// no-op waker suffices for tests on native.
    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
        fn noop(_: *const ()) {}
        fn clone(p: *const ()) -> RawWaker {
            RawWaker::new(p, &VTAB)
        }
        static VTAB: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
        let waker = unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTAB)) };
        let mut cx = Context::from_waker(&waker);
        let mut pinned = Box::pin(fut);
        loop {
            if let Poll::Ready(v) = pinned.as_mut().poll(&mut cx) {
                return v;
            }
        }
    }

    fn prf_signer() -> (PrfSigner, String) {
        let kp = gen_kp().unwrap();
        let pk = kp.public.to_hex();
        (PrfSigner::new(kp), pk)
    }

    #[test]
    fn signer_gift_wrap_roundtrip() {
        let (sender, sender_pk) = prf_signer();
        let (recipient, recipient_pk) = prf_signer();

        let content = "Signer-driven DM 🎁";
        let wrapped = block_on(gift_wrap_with_signer(&sender, &recipient_pk, content)).unwrap();
        assert_eq!(wrapped.kind, KIND_GIFT_WRAP);
        // Outer pubkey is a throwaway, never the sender.
        assert_ne!(wrapped.pubkey, sender_pk);

        let unwrapped = block_on(unwrap_gift_with_signer(&wrapped, &recipient)).unwrap();
        assert_eq!(unwrapped.sender_pubkey, sender_pk);
        assert_eq!(unwrapped.rumor.content, content);
    }

    #[test]
    fn signer_unwrap_is_compatible_with_raw_wrap() {
        // A message wrapped via the raw (legacy) path must unwrap via the signer path.
        let (sender_sk, sender_pk) = test_keypair();
        let recipient = gen_kp().unwrap();
        let recipient_pk = recipient.public.to_hex();
        let recipient_signer = PrfSigner::new(recipient);

        let wrapped = gift_wrap(&sender_sk, &sender_pk, &recipient_pk, "cross-compat").unwrap();
        let unwrapped = block_on(unwrap_gift_with_signer(&wrapped, &recipient_signer)).unwrap();
        assert_eq!(unwrapped.sender_pubkey, sender_pk);
        assert_eq!(unwrapped.rumor.content, "cross-compat");
    }

    #[test]
    fn raw_unwrap_is_compatible_with_signer_wrap() {
        // A message wrapped via the signer path must unwrap via the raw path.
        let (sender, sender_pk) = prf_signer();
        let recipient = gen_kp().unwrap();
        let recipient_sk = *recipient.secret.as_bytes();
        let recipient_pk = recipient.public.to_hex();

        let wrapped = block_on(gift_wrap_with_signer(&sender, &recipient_pk, "reverse")).unwrap();
        let unwrapped = unwrap_gift(&wrapped, &recipient_sk).unwrap();
        assert_eq!(unwrapped.sender_pubkey, sender_pk);
        assert_eq!(unwrapped.rumor.content, "reverse");
    }

    #[test]
    fn signer_unwrap_rejects_wrong_kind() {
        let (recipient, _) = prf_signer();
        let fake = NostrEvent {
            id: "00".repeat(32),
            pubkey: "aa".repeat(32),
            created_at: 1_700_000_000,
            kind: 1,
            tags: vec![],
            content: String::new(),
            sig: "00".repeat(64),
        };
        let result = block_on(unwrap_gift_with_signer(&fake, &recipient));
        assert!(matches!(
            result,
            Err(SignerGiftWrapError::InvalidKind {
                expected: KIND_GIFT_WRAP,
                actual: 1
            })
        ));
    }

    #[test]
    fn signer_unwrap_rejects_bad_seal_signature() {
        // Same protection as the raw path: a corrupted seal signature is
        // rejected by the signer-driven unwrap.
        let (sender_sk, sender_pk) = test_keypair();
        let recipient = gen_kp().unwrap();
        let recipient_pk = recipient.public.to_hex();
        let recipient_pk_bytes = hex_to_32(&recipient_pk).unwrap();
        let recipient_signer = PrfSigner::new(recipient);

        let rumor = create_rumor(&sender_pk, &recipient_pk, "forged");
        let mut seal = seal_rumor(&rumor, &sender_sk, &recipient_pk_bytes).unwrap();
        seal.sig = "00".repeat(64);
        let wrapped = wrap_seal(&seal, &recipient_pk).unwrap();

        let result = block_on(unwrap_gift_with_signer(&wrapped, &recipient_signer));
        assert!(
            matches!(result, Err(SignerGiftWrapError::SealVerification(_))),
            "expected SealVerification, got: {:?}",
            result
        );
    }

    #[test]
    fn signer_unwrap_rejects_rumor_pubkey_mismatch() {
        // Same protection as the raw path: a rumor authored by a different
        // pubkey than the verified seal signer is rejected.
        let (sender_sk, sender_pk) = test_keypair();
        let (_, victim_pk) = test_keypair();
        let recipient = gen_kp().unwrap();
        let recipient_pk = recipient.public.to_hex();
        let recipient_pk_bytes = hex_to_32(&recipient_pk).unwrap();
        let recipient_signer = PrfSigner::new(recipient);

        let rumor = create_rumor(&victim_pk, &recipient_pk, "impersonation");
        let seal = seal_rumor(&rumor, &sender_sk, &recipient_pk_bytes).unwrap();
        assert_eq!(seal.pubkey, sender_pk);
        let wrapped = wrap_seal(&seal, &recipient_pk).unwrap();

        let result = block_on(unwrap_gift_with_signer(&wrapped, &recipient_signer));
        assert!(
            matches!(result, Err(SignerGiftWrapError::AuthorMismatch { .. })),
            "expected AuthorMismatch, got: {:?}",
            result
        );
    }
}
