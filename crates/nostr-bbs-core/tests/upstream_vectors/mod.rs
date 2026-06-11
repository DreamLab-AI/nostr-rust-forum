// crates/nostr-bbs-core/tests/upstream_vectors/mod.rs
//! L1 reference-vector tests for the forum-side `nostr-core` kit.
//!
//! Per ADR-082 D5, the forum substrate consumes fixtures synced from the
//! VisionClaw monorepo's `docs/specs/fixtures/` directory. The local copies
//! are managed by `scripts/sync-fixtures.sh` (substrate-side) which copies
//! them into `crates/nostr-core/tests/fixtures/`.
//!
//! Until that sync runs, this loader resolves fixtures via an env var
//! `VISIONCLAW_FIXTURE_ROOT` if set, otherwise falls back to
//! `tests/fixtures/`. Tests are `#[ignore]` when the fixture is missing so
//! the CI can run cleanly during the bring-up window.

use std::fs;
use std::path::PathBuf;

pub fn fixture_root() -> PathBuf {
    if let Ok(env_root) = std::env::var("VISIONCLAW_FIXTURE_ROOT") {
        return PathBuf::from(env_root);
    }
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests");
    p.push("fixtures");
    p
}

pub fn try_load_fixture(name: &str) -> Option<serde_json::Value> {
    let mut path = fixture_root();
    path.push(name);
    let bytes = fs::read(&path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

pub fn assert_meta_block(fixture: &serde_json::Value, expected_spec_substring: &str) {
    let meta = fixture.get("_meta").expect("fixture must have _meta block");
    let spec = meta
        .get("spec")
        .and_then(|v| v.as_str())
        .expect("_meta.spec required");
    assert!(
        spec.contains(expected_spec_substring),
        "_meta.spec '{}' did not contain '{}'",
        spec,
        expected_spec_substring
    );
}
