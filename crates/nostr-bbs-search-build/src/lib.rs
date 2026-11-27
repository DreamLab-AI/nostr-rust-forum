//! Builder for a zone's sealed search index (sealed-search design §8 and
//! Phase 2): the library behind `nostr-bbs-search-build`.
//!
//! - [`harvest`]: read a zone's encrypted posts from the relay (NIP-42
//!   authenticated, paged, since a high-water mark), open each with the zone
//!   key of its epoch, and turn them into index rows, leaving out deleted
//!   (kind-5) and superseded (edited) posts.
//! - [`pod`]: the publisher's pod (NIP-98 HTTP, a directory standing in for
//!   one, or a dry run) and a local cache of sealed objects keyed by SHA-256.
//! - [`state`]: the job's state file (high-water mark, last version
//!   published, objects awaiting deletion).
//! - [`pipeline`]: full builds, incremental updates and compactions, from the
//!   newest manifest any trusted publisher holds to a new signed one.
//! - [`memrelay`]: an in-memory relay over NIP-01 events (an export file, or
//!   tests).
//! - [`embed`]: local FP32 bge-small embeddings, loaded on first use.
//! - [`secrets`]: the publisher key, from the environment or a 0600 file.
//!
//! Plaintext exists only in memory, between opening a post and embedding
//! it: it is never written, logged or put in an error message. Neither are
//! zone keys, search keys or embeddings.

#![cfg(not(target_arch = "wasm32"))]

pub mod embed;
pub mod harvest;
pub mod memrelay;
pub mod pipeline;
pub mod pod;
pub mod secrets;
pub mod state;
