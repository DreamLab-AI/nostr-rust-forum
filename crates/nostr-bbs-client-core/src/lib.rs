//! Shared headless client engine for `nostr-rust-forum` browser clients.
//!
//! Houses the protocol, relay transport, authentication, encrypted-zone crypto,
//! direct messaging, reactive stores, poker engine integration, sidestr wallet,
//! and pure utilities consumed by both `nostr-bbs-forum-client` (the modern web
//! interface) and `nostr-bbs-bbs-client` (the retro TUI terminal interface).

pub mod agent_disclosure;
pub mod auth;
pub mod base;
pub mod dm;
pub mod name_cache;
pub mod poker;
pub mod relay;
pub mod stores;
pub mod toast;
pub mod topics;
pub mod types;
pub mod utils;
pub mod wallet;
pub mod whitelist;
pub mod zone_crypto;

pub use base::base_href;
