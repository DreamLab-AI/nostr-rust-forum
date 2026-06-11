//! Shared Nostr protocol primitives for the nostr-bbs forum.
//!
//! This crate provides the cryptographic and protocol building blocks shared
//! between the WASM client bridge and the Rust Cloudflare Workers. It covers:
//!
//! - **NIP-01** event creation, signing, and verification
//! - **NIP-44** encrypted direct messages (ChaCha20-Poly1305)
//! - **NIP-98** HTTP auth token creation and verification
//! - **DID:nostr** document generation (delegates to `solid_pod_rs::did_nostr_types`)
//! - **Key management** including HKDF derivation from WebAuthn PRF output
//! - **Value types** (`EventId`, `Timestamp`, `Tag`, etc.)

pub mod calendar;
pub mod deletion;
pub mod event;
pub mod gift_wrap;
pub mod groups;
pub mod keys;
pub mod moderation_events;
pub mod nip04;
pub mod nip19;
pub mod nip44;
pub mod nip98;
pub mod signer;
pub mod types;

pub mod admin_shared;
pub mod cors;
pub mod d1_helpers;
pub mod did;
pub mod governance;
#[cfg(target_arch = "wasm32")]
pub mod wasm_bridge;

// ── Re-exports for ergonomic top-level use ─────────────────────────────────

pub use event::{
    compute_event_id, sign_event, sign_event_deterministic, sign_event_upstream,
    signing_key_to_upstream, verify_event, verify_event_strict, verify_events_batch, EventError,
    NostrEvent, PubkeyMismatch, UnsignedEvent,
};
pub use gift_wrap::{gift_wrap, unwrap_gift, GiftWrapError, UnwrappedGift};
pub use keys::{
    derive_from_prf, derive_subkey, generate_keypair, Keypair, PublicKey, SecretKey, Signature,
};
pub use nip44::{decrypt as nip44_decrypt, encrypt as nip44_encrypt};
pub use nip98::{
    authorization_header as nip98_authorization_header,
    create_token as create_nip98_token,
    sign_request_header as nip98_sign_request_header,
    // Canonical verification entry point (new — preferred for all new code)
    verify_nip98,
    verify_nip98_with_replay,
    // Legacy aliases (backward-compatible, delegate to verify_token_full internally)
    verify_token as verify_nip98_token,
    verify_token_at as verify_nip98_token_at,
    verify_token_at_with_replay as verify_nip98_token_at_with_replay,
    verify_token_full as verify_nip98_token_full,
    Nip98Error,
    Nip98ReplayStore,
    Nip98Token as VerifiedToken,
    REPLAY_CACHE_TTL_SECS,
    TIMESTAMP_TOLERANCE as NIP98_TIMESTAMP_TOLERANCE,
};
pub use types::{EventId, Tag, Timestamp};

pub use calendar::{
    create_calendar_event, create_calendar_event_signer, create_date_calendar_event, create_rsvp,
    create_rsvp_signer, is_known_venue, read_venue_tag, read_zone_tag, set_venue_tag, set_zone_tag,
    to_free_busy, CalendarError, RsvpStatus, KIND_CALENDAR_DATE_EVENT, KIND_CALENDAR_EVENT,
    KIND_CALENDAR_RSVP, VENUE_DREAMLAB, VENUE_FAIRFIELD, VENUE_TAG, ZONE_TAG,
};

pub use moderation_events::{
    build_ban, build_moderation_action, build_mute, build_report, build_unban, build_unmute,
    build_warning, d_tag_of, mute_expires_at, validate_moderation_event, ModerationEventError,
    ADMIN_ONLY_MOD_KINDS, KIND_BAN, KIND_MODERATION_ACTION, KIND_MUTE, KIND_REPORT,
    KIND_REPORT_NIP56, KIND_UNBAN, KIND_UNMUTE, KIND_WARNING, MOD_KINDS,
};

pub use did::{
    did_nostr_uri, format_multibase_schnorr, is_valid_hex_pubkey, render_did_document_tier1,
    render_did_document_tier3, verify_webid_tag, well_known_path, NostrPubkey,
};
pub use nip04::{nip04_decrypt, nip04_encrypt, nip04_shared_secret, Nip04Error};
pub use nip19::{
    decode_naddr, decode_nevent, decode_note, decode_nprofile, decode_npub, decode_nsec,
    encode_naddr, encode_nevent, encode_note, encode_nprofile, encode_npub, encode_nsec, NAddr,
    NEvent, NProfile, Nip19Error,
};
pub use signer::{PrfSigner, Signer, SignerError};

pub use admin_shared::{
    admin_pubkeys_from_env_str, is_static_admin, IsAdminRow, PubkeyRow, ADMIN_PUBKEYS_VAR,
    MEMBERS_ADMIN_LIST_SQL, MEMBERS_IS_ADMIN_SQL, WHITELIST_ADMIN_LIST_SQL, WHITELIST_IS_ADMIN_SQL,
};
pub use cors::{CorsHeader, POD_CORS_HEADERS, STANDARD_CORS_HEADERS};

pub use governance::{
    extract_d_tag, extract_tag, is_governance_kind, ActionDef, ActionPriority, ActionRequest,
    ActionResponse, ActionStyle, FieldDef, FieldType, LayoutHint, PanelCapability, PanelDefinition,
    PanelSchema, RegisteredAgent, GOVERNANCE_KIND_RANGE, KIND_ACTION_REQUEST, KIND_ACTION_RESPONSE,
    KIND_PANEL_DEFINITION, KIND_PANEL_RETIRED, KIND_PANEL_STATE, KIND_PANEL_UPDATE,
};
