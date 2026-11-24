//! `nostr-bbs-bulk-import`: offline bulk import of an external chat archive
//! (Keybase today; Discord, Slack or Matrix through new adapters) into a
//! nostr-bbs forum deployment.
//!
//! It is the kit-native, generalised successor of the Node migrator written
//! for the Keybase pilot (`keybase-port/migrator`, which stays in place for
//! that pilot): everything reusable lives here, and Keybase is one adapter.
//!
//! The operator guide is `docs/bulk-import/README.md`, the archive format
//! `docs/bulk-import/FORMAT.md`, the threat model
//! `docs/bulk-import/SECURITY.md` and the design `docs/bulk-import/DESIGN.md`.
//!
//! # Pipeline
//!
//! ```text
//! source export --adapt--> intermediate archive (JSONL v1)          adapter, format
//!   --plan/titles--> identities.json + structure.json + titles.json  identity, structure, titles, plan
//!   --keys--> keys.json (atomic, refuse-to-change)                  keystore
//!   --media--> optimised, content-addressed images                  media
//!   --build--> local D1 with full ingest parity + ledger            events, d1, pipeline
//!   (operator: mint + grant the zone key, one anchor per thread)
//!   --seal-prep--> nostr-bbs-zone-migrate seal-offline/verify/purge pipeline::seal_prep
//!   --search-input--> docs.jsonl for nostr-bbs-search-build         pipeline::search_input
//!   --upload-plan--> allowlisted dump, R2 list, cutover runbook     pipeline::upload_plan
//! ```
//!
//! # Guarantees
//!
//! - **No network.** The crate links no HTTP or WebSocket client; remote
//!   steps are written as plans for the operator. Sealing runs through
//!   zone-migrate's CLI against a loopback relay only.
//! - **Offline, resumable, idempotent.** Every emitted event carries an
//!   `["import", key]` tag; a ledger (healed from D1) pins each key's event
//!   id, so re-runs add nothing and a growing archive never duplicates.
//! - **Ingest parity.** Rows are written as the relay writes them (`events`,
//!   trigger-filled `event_tags`, `channel_creators`, `profiles`) plus the
//!   control rows an offline build needs (`whitelist`, `channel_zones`,
//!   `pubkey_aliases`, counters, audit rows), with every value bound.
//! - **No forged authorship.** Each person's history is signed by their own
//!   new key, or by a per-person archive key aliased to the live key they
//!   keep (whitelisted only with a signed proof). DMs are copied verbatim or
//!   re-wrapped only when the operator wrote them.
//! - **No hand-rolled cryptography.** Keys, signatures, NIP-44 and gift wraps
//!   come from `nostr-bbs-core` (RustCrypto underneath); sealing from
//!   `nostr-bbs-zone-migrate`.
//!
//! # Example: plan an import without touching a database
//!
//! ```
//! use nostr_bbs_bulk_import::format::{ArchiveWriter, Author, Channel, Message};
//! use nostr_bbs_bulk_import::identity::{self, IdentityFile};
//! use nostr_bbs_bulk_import::plan;
//! use nostr_bbs_bulk_import::structure::Structure;
//!
//! let dir = std::env::temp_dir().join(format!("bi-doc-lib-{}", std::process::id()));
//! let _ = std::fs::remove_dir_all(&dir);
//! let mut w = ArchiveWriter::new("example", "team");
//! w.author(Author { id: "alice".into(), handle: "alice".into(), display_name: None, about: None, bot: false });
//! w.channel(Channel { id: "c1".into(), name: "general".into(), topic: None, created_at: None });
//! w.message(Message {
//!     id: "m1".into(), channel: "c1".into(), author: "alice".into(), created_at: 1_600_000_000,
//!     text: "hello".into(), reply_to: None, edited_at: None, attachments: vec![],
//! });
//! let archive = w.finish(&dir).unwrap();
//!
//! let ids = identity::plan(&archive, &IdentityFile::template(&archive)).unwrap();
//! let structure = Structure::template(&archive, "zone1");
//! structure.validate(&archive).unwrap();
//! let titles = nostr_bbs_bulk_import::titles::Titles {
//!     version: 1,
//!     titles: [("c1".to_string(), "General".to_string())].into(),
//! };
//! titles.validate(&archive, &structure).unwrap();
//! let p = plan::build(&archive, &ids, &structure, &titles);
//! assert_eq!(p.roots.len(), 1, "one topic per source channel");
//! assert_eq!(p.messages.len(), 1);
//! assert_eq!(p.roots[0].created_at, 1_600_000_000 - 1, "a root seals before its replies");
//! assert_eq!(p.roots[0].content, "General", "a topic root is exactly its title");
//! # std::fs::remove_dir_all(&dir).unwrap();
//! ```
//!
//! # Modules
//!
//! - [`format`](mod@format), [`adapter`]: the intermediate archive and its producers.
//! - [`identity`], [`keystore`]: who signs what, and the keys.
//! - [`structure`], [`titles`], [`plan`]: channels to threads and topic
//!   titles; the pure plan.
//! - [`media`], [`target`]: image optimisation and the embedded URLs.
//! - [`events`], `d1`, `pipeline`: signing, the D1 writer and the CLI steps
//!   (`d1` and `pipeline` are native only).
//! - [`dm`]: verbatim copy and operator-sent re-wrap of gift wraps.

#![warn(missing_docs)]

pub mod adapter;
#[cfg(not(target_arch = "wasm32"))]
pub mod d1;
pub mod dm;
pub mod error;
pub mod events;
pub mod format;
pub mod fsutil;
pub mod identity;
pub mod keystore;
pub mod media;
#[cfg(not(target_arch = "wasm32"))]
pub mod pipeline;
pub mod plan;
pub mod structure;
pub mod target;
pub mod titles;

pub use error::ImportError;
