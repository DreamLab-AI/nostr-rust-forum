//! F26 — Upstream `nostr` crate validation canary (per ADR-076 D5).
//!
//! Before the forum can absorb the hand-rolled `nostr-core` modules into the
//! upstream `nostr` crate (rust-nostr.org), we need empirical evidence that
//! `nostr` (without `nostr-sdk`) compiles and runs correctly on the forum's
//! specific WASM/Cloudflare Workers build matrix:
//!
//! - target: `wasm32-unknown-unknown`
//! - toolchain: Rust 1.84.0+ (per Sprint v9 STREAM-C)
//! - features: `nip04`, `nip19`, `nip26`, `nip44`, `nip59`, `nip90`, `nip98`
//!   (all default-features = false; `std` only)
//!
//! This crate is **not** linked into the forum binary. It exists so that
//! `cargo check --target wasm32-unknown-unknown -p nostr-upstream-canary`
//! and `cargo test -p nostr-upstream-canary` (native) tell us:
//!
//! - **PASS** → ADR-076 D5 acceptance criteria met → proceed to per-module
//!   absorption (D6); record outcome as **Shape A** (full absorption).
//! - **FAIL** → some upstream feature does not satisfy the build matrix →
//!   record outcome as **Shape C** (patch-in-place fallback) and document
//!   which feature flag failed for an upstream PR.
//!
//! The test functions reuse the paulmillr/nip44 reference vectors vendored
//! at `docs/specs/fixtures/nip44-v2.json` (VisionClaw monorepo) so a
//! successful PASS doubles as a regression guard for C1 (the conv-key bug
//! the hand-roll shipped).

#![allow(dead_code)]

use nostr::nips::nip44::v2 as upstream_nip44_v2;
use nostr::{Keys, SecretKey};

/// Smoke A — generate a fresh keypair and verify round-trip serialisation.
/// Exercises `nostr::Keys::generate` and `nostr::SecretKey::from_hex`.
pub fn smoke_keypair_roundtrip() -> Result<(), String> {
    let keys = Keys::generate();
    let hex = keys.secret_key().to_secret_hex();
    if hex.len() != 64 {
        return Err(format!(
            "expected 64-char hex secret, got len={}",
            hex.len()
        ));
    }
    let parsed =
        SecretKey::from_hex(&hex).map_err(|e| format!("from_hex round-trip failed: {e}"))?;
    if parsed.to_secret_hex() != hex {
        return Err("secret-key round-trip diverged".to_string());
    }
    Ok(())
}

/// Smoke B — derive a NIP-44 v2 conversation key using a deterministic
/// (sk, pk) pair and assert the expected hex output. The expected hex is
/// taken from the FIRST entry of paulmillr/nip44 vector
/// `v2.valid.get_conversation_key`.
pub fn smoke_nip44_conv_key() -> Result<(), String> {
    // First paulmillr/nip44 conversation-key vector. Source of truth:
    //   <VisionClaw>/docs/specs/fixtures/nip44-v2.json#/vectors/valid/get_conversation_key/0
    // (paulmillr/nip44 @ 671a1f04bcfacaf125b0db68adc45bc9ce0e763b — see UPSTREAM_PINS.md)
    // The original Phase 0 transcription used incorrect sk + pk (the pk happened
    // not to lift to a valid x-only point, so xonly() rejected it as malformed).
    // These are the actual vector #0 values, verified against the fixture file.
    // Phase 3 follow-up: switch to loading from fixture file via include_str! +
    // serde_json so future paulmillr updates auto-sync.
    let sec1 = "315e59ff51cb9209768cf7da80791ddcaae56ac9775eb25b6dee1234bc5d2268";
    let pub2 = "c2f9d9948dc8c7c38321e4b85c8558872eafa0641cd269db76848a6073e69133";
    let expected_conv_key = "3dfef0ce2a4d80a25e7a328accf73448ef67096f65f79588e358d9a0eb9013f1";

    let sk_bytes = hex::decode(sec1).map_err(|e| format!("hex decode sk: {e}"))?;
    let pk_bytes = hex::decode(pub2).map_err(|e| format!("hex decode pk: {e}"))?;

    let sk = SecretKey::from_slice(&sk_bytes).map_err(|e| format!("SecretKey::from_slice: {e}"))?;
    let pk = nostr::PublicKey::from_slice(&pk_bytes)
        .map_err(|e| format!("PublicKey::from_slice: {e}"))?;

    // Derive conversation key via upstream NIP-44 v2 utility.
    let conv = upstream_nip44_v2::ConversationKey::derive(&sk, &pk)
        .map_err(|e| format!("ConversationKey::derive: {e}"))?;
    let actual = hex::encode(conv.as_bytes());
    if actual != expected_conv_key {
        return Err(format!(
            "NIP-44 v2 conv_key mismatch: expected {expected_conv_key}, got {actual}"
        ));
    }
    Ok(())
}

/// Smoke C — NIP-19 npub round-trip via upstream bech32.
pub fn smoke_nip19_npub_roundtrip() -> Result<(), String> {
    use nostr::nips::nip19::ToBech32;
    use nostr::FromBech32;
    let keys = Keys::generate();
    let pk = keys.public_key();
    let npub = pk.to_bech32().map_err(|e| format!("to_bech32: {e}"))?;
    if !npub.starts_with("npub1") {
        return Err(format!("npub does not start with 'npub1': {npub}"));
    }
    let pk2 = nostr::PublicKey::from_bech32(&npub).map_err(|e| format!("from_bech32: {e}"))?;
    if pk2.to_hex() != pk.to_hex() {
        return Err("npub round-trip diverged".to_string());
    }
    Ok(())
}

/// Run every smoke test in sequence. Returns the first failure or Ok.
pub fn run_all_smokes() -> Result<(), String> {
    smoke_keypair_roundtrip()?;
    smoke_nip44_conv_key()?;
    smoke_nip19_npub_roundtrip()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_roundtrip_native() {
        smoke_keypair_roundtrip().expect("keypair round-trip");
    }

    #[test]
    fn nip44_conv_key_native() {
        smoke_nip44_conv_key().expect("NIP-44 v2 conv_key derivation");
    }

    #[test]
    fn nip19_npub_roundtrip_native() {
        smoke_nip19_npub_roundtrip().expect("NIP-19 npub round-trip");
    }

    #[test]
    fn all_smokes_native() {
        run_all_smokes().expect("all upstream smokes");
    }
}
