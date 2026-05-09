// crates/nostr-bbs-core/tests/upstream_vectors/main.rs
//! Entry point for L1 reference-vector test suite (ADR-082 D6).
//!
//! This file is required by Cargo's test discovery: `tests/<name>/main.rs`
//! is discovered as test target `<name>`. Without it, the `all_fixtures.rs`
//! module is not compiled.

mod all_fixtures;
