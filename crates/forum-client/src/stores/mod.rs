//! Persistent stores backed by localStorage and IndexedDB.
//!
//! Each store is provided via Leptos context and serialized to localStorage
//! on every mutation so state survives page reloads.  IndexedDB is used for
//! larger data sets (messages, profiles, outbox queue).

pub mod badges;
pub mod channels;
#[allow(dead_code)]
pub mod indexed_db;
pub mod mute;
pub mod notifications;
pub mod preferences;
pub mod read_position;
pub mod zone_access;
