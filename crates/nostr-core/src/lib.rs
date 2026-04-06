//! Shared Nostr protocol primitives for Nostr BBS forum.
//!
//! This crate provides the cryptographic and protocol building blocks shared
//! between the WASM client bridge and the Rust Cloudflare Workers. It covers:
//!
//! - **NIP-01** event creation, signing, and verification
//! - **NIP-44** encrypted direct messages (ChaCha20-Poly1305)
//! - **NIP-98** HTTP auth token creation and verification
//! - **Key management** including HKDF derivation from WebAuthn PRF output
//! - **Value types** (`EventId`, `Timestamp`, `Tag`, etc.)

pub mod calendar;
pub mod deletion;
pub mod event;
pub mod gift_wrap;
pub mod groups;
pub mod keys;
pub mod nip44;
pub mod nip98;
pub mod types;

#[cfg(target_arch = "wasm32")]
pub mod wasm_bridge;

// ── Re-exports for ergonomic top-level use ─────────────────────────────────

pub use event::{
    compute_event_id, sign_event, sign_event_deterministic, verify_event, verify_event_strict,
    verify_events_batch, EventError, NostrEvent, PubkeyMismatch, UnsignedEvent,
};
pub use gift_wrap::{gift_wrap, unwrap_gift, GiftWrapError, UnwrappedGift};
pub use keys::{derive_from_prf, generate_keypair, Keypair, PublicKey, SecretKey, Signature};
pub use nip44::{decrypt as nip44_decrypt, encrypt as nip44_encrypt};
pub use nip98::{
    create_token as create_nip98_token, verify_token as verify_nip98_token,
    verify_token_at as verify_nip98_token_at, Nip98Token as VerifiedToken,
};
pub use types::{EventId, Tag, Timestamp};

pub use calendar::{
    create_calendar_event, create_rsvp, CalendarError, RsvpStatus,
};
