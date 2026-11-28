//! Persistent stores backed by localStorage and IndexedDB.
//!
//! Each store is provided via Leptos context and serialized to localStorage
//! on every mutation so state survives page reloads.  IndexedDB is used for
//! larger data sets (messages, profiles, outbox queue).

pub mod admin_alerts;
pub mod badges;
pub mod case_projection;
pub mod channels;
pub mod custom_emoji;
pub mod deletion_sync;
#[allow(dead_code)]
pub mod indexed_db;
pub mod mute;
pub mod notifications;
pub mod panel_registry;
pub mod preferences;
pub mod profile_cache;
pub mod reactions;
pub mod read_position;
pub mod receipts;
pub mod relay_scope;
pub mod signer_admin;
pub mod subs_panel;
pub mod thread_subs;
pub mod thread_subs_sync;
pub mod tombstones;
pub mod zone_access;
pub mod zones;
