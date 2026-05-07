//! Property-based tests for NIP-04 (AES-256-CBC encrypted DMs).
//!
//! Sprint v9, STREAM-E1 (cryptographic boundary proptests). Supplements
//! the `nip04_proptest_*` tests inside `nip04.rs` with broader coverage:
//!
//! 1. Roundtrip across full plaintext-length spectrum (1..=1024 bytes,
//!    arbitrary bytes including non-UTF-8 patterns) — *we restrict
//!    plaintext to valid UTF-8 because `nip04_decrypt` returns `String`,
//!    matching the wire contract*.
//! 2. Corrupted ciphertext: flip a random byte at a random index of the
//!    base64 ciphertext portion → must Err, never panic.
//! 3. Wire-format invariants: encrypt always emits `?iv=` separator and a
//!    16-byte (`base64`-decoded) IV.
//! 4. Negative paths: arbitrary strings without `?iv=` → `MissingIvSeparator`,
//!    never panic.
//!
//! Native-only target (proptest pulls native deps).

#![cfg(not(target_arch = "wasm32"))]

use std::panic;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use nostr_core::keys::generate_keypair;
use nostr_core::nip04::{nip04_decrypt, nip04_encrypt, Nip04Error};
use proptest::prelude::*;

// ── Helpers / strategies ──────────────────────────────────────────────────────

/// A single keypair as `(sk_bytes, pk_hex)`.
fn fresh_keypair() -> ([u8; 32], String) {
    let kp = generate_keypair().expect("keypair generation must succeed");
    (*kp.secret.as_bytes(), kp.public.to_hex())
}

/// Plaintext: arbitrary printable + multibyte UTF-8 chars, 1..=1024 chars.
/// Using regex strategy `\PC` (anything that's not a control char).
fn arb_plaintext() -> impl Strategy<Value = String> {
    r"\PC{1,1024}".prop_map(String::from)
}

// ── (E1b-1) Encrypt → decrypt roundtrip across plaintext lengths ─────────────

proptest! {
    #[test]
    fn nip04_roundtrip_arbitrary_plaintext(plaintext in arb_plaintext()) {
        let (sk_a, pk_a) = fresh_keypair();
        let (sk_b, pk_b) = fresh_keypair();

        let ct = nip04_encrypt(&sk_a, &pk_b, &plaintext)
            .expect("encrypt must succeed for any UTF-8 plaintext");
        let dec = nip04_decrypt(&sk_b, &pk_a, &ct)
            .expect("decrypt must succeed for matching keypairs");
        prop_assert_eq!(dec, plaintext);
    }

    #[test]
    fn nip04_roundtrip_short_plaintext(plaintext in r"\PC{1,32}") {
        // Tighter strategy biased to 1..=32 chars exercises padding boundaries.
        let plaintext = plaintext.to_string();
        let (sk_a, pk_a) = fresh_keypair();
        let (sk_b, pk_b) = fresh_keypair();

        let ct = nip04_encrypt(&sk_a, &pk_b, &plaintext).unwrap();
        let dec = nip04_decrypt(&sk_b, &pk_a, &ct).unwrap();
        prop_assert_eq!(dec, plaintext);
    }
}

// ── (E1b-2) Wire-format invariants ───────────────────────────────────────────

proptest! {
    #[test]
    fn nip04_wire_always_has_iv_separator(plaintext in r"[a-zA-Z0-9 ]{1,256}") {
        let (sk_a, _) = fresh_keypair();
        let (_, pk_b) = fresh_keypair();

        let ct = nip04_encrypt(&sk_a, &pk_b, &plaintext).unwrap();
        prop_assert!(ct.contains("?iv="), "wire format must contain ?iv= separator");
        prop_assert_eq!(
            ct.matches("?iv=").count(),
            1,
            "exactly one ?iv= separator"
        );
    }

    #[test]
    fn nip04_wire_iv_is_16_bytes(plaintext in r"[a-z]{1,64}") {
        let (sk_a, _) = fresh_keypair();
        let (_, pk_b) = fresh_keypair();

        let ct = nip04_encrypt(&sk_a, &pk_b, &plaintext).unwrap();
        let (_ct_b64, iv_b64) = ct.split_once("?iv=")
            .expect("encrypt always emits ?iv=");

        let iv_bytes = BASE64
            .decode(iv_b64)
            .expect("emitted IV must be valid base64");
        prop_assert_eq!(iv_bytes.len(), 16, "AES-CBC IV must be 16 bytes");
    }
}

// ── (E1b-3) Corrupted ciphertext returns Err, never panics ───────────────────
//
// Strategy: encrypt valid plaintext → corrupt one byte at a random index of
// the *ciphertext* (base64 portion before `?iv=`) → assert decrypt returns Err.
// Note: simple base64-char corruption sometimes produces valid-but-wrong
// plaintext if PKCS7 padding happens to validate. We enforce the looser
// invariant: result is *either* Err *or* a different plaintext, but never
// equal to the original — and never a panic.

proptest! {
    #[test]
    fn nip04_corrupted_ciphertext_no_panic(
        plaintext in r"\PC{1,200}",
        corrupt_index in 0usize..256,
        corrupt_xor in 1u8..=255,
    ) {
        let (sk_a, pk_a) = fresh_keypair();
        let (sk_b, pk_b) = fresh_keypair();

        let original_ct = nip04_encrypt(&sk_a, &pk_b, &plaintext).unwrap();
        let (ct_b64, iv_b64) = original_ct.split_once("?iv=").unwrap();

        // Decode → corrupt one byte → re-encode
        let mut raw_ct = BASE64.decode(ct_b64).unwrap();
        if raw_ct.is_empty() {
            // Encryption padding always yields >= 16 bytes — but defensive.
            return Ok(());
        }
        let idx = corrupt_index % raw_ct.len();
        raw_ct[idx] ^= corrupt_xor;

        let corrupted = format!("{}?iv={}", BASE64.encode(&raw_ct), iv_b64);

        let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            nip04_decrypt(&sk_b, &pk_a, &corrupted)
        }));
        prop_assert!(
            result.is_ok(),
            "decrypt must never panic on corrupted ciphertext (idx={}, xor={})",
            idx, corrupt_xor
        );

        // Compare to original plaintext: corrupted ciphertext must NOT decrypt
        // back to the original plaintext (would prove malleability).
        match result.unwrap() {
            Err(_) => { /* expected — padding error or UTF-8 error */ }
            Ok(decrypted) => {
                prop_assert_ne!(
                    decrypted, plaintext,
                    "corrupted ciphertext must not produce identical plaintext"
                );
            }
        }
    }

    #[test]
    fn nip04_corrupted_iv_no_panic(
        plaintext in r"[a-zA-Z]{1,128}",
        corrupt_index in 0usize..16,
        corrupt_xor in 1u8..=255,
    ) {
        let (sk_a, pk_a) = fresh_keypair();
        let (sk_b, pk_b) = fresh_keypair();

        let original_ct = nip04_encrypt(&sk_a, &pk_b, &plaintext).unwrap();
        let (ct_b64, iv_b64) = original_ct.split_once("?iv=").unwrap();

        let mut iv_bytes = BASE64.decode(iv_b64).unwrap();
        let idx = corrupt_index % iv_bytes.len();
        iv_bytes[idx] ^= corrupt_xor;

        let corrupted = format!("{}?iv={}", ct_b64, BASE64.encode(&iv_bytes));

        let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            nip04_decrypt(&sk_b, &pk_a, &corrupted)
        }));
        prop_assert!(
            result.is_ok(),
            "decrypt must never panic on corrupted IV"
        );
        // Result is Ok or Err — not asserted further. AES-CBC IV corruption
        // affects only the first block; PKCS7 padding may or may not validate.
    }
}

// ── (E1b-4) Missing ?iv= separator returns MissingIvSeparator ────────────────
//
// Arbitrary base64-shaped strings (no `?iv=`) must always return
// `Nip04Error::MissingIvSeparator` — never panic.

proptest! {
    #[test]
    fn nip04_no_iv_separator_returns_err(s in r"[A-Za-z0-9+/=]{0,500}") {
        // Filter: ensure our generated string contains no "?iv=" sentinel.
        prop_assume!(!s.contains("?iv="));

        let (sk_a, _) = fresh_keypair();
        let (_, pk_b) = fresh_keypair();

        let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            nip04_decrypt(&sk_a, &pk_b, &s)
        }));
        prop_assert!(result.is_ok(), "decrypt must not panic on input lacking ?iv=");
        let inner = result.unwrap();
        prop_assert!(
            matches!(inner, Err(Nip04Error::MissingIvSeparator)),
            "input without ?iv= must return MissingIvSeparator, got {:?}",
            inner
        );
    }

    #[test]
    fn nip04_arbitrary_garbage_no_panic(s in r"\PC{0,500}") {
        // Even completely arbitrary printable text — including possible `?iv=`
        // substrings — must never panic, only Err.
        let (sk_a, _) = fresh_keypair();
        let (_, pk_b) = fresh_keypair();

        let s = s.clone();
        let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            nip04_decrypt(&sk_a, &pk_b, &s)
        }));
        prop_assert!(result.is_ok(), "decrypt must not panic on input {:?}", s);
        // The result is intentionally not asserted — Ok is theoretically
        // reachable on an algebraically lucky input; we only assert no-panic.
        let _ = result.unwrap();
    }
}

// ── (E1b-5) Wrong-key decryption never panics ────────────────────────────────

proptest! {
    #[test]
    fn nip04_wrong_key_returns_err_not_panic(plaintext in r"[a-z]{1,128}") {
        let (sk_a, _pk_a) = fresh_keypair();
        let (_, pk_b) = fresh_keypair();
        let (sk_wrong, _) = fresh_keypair();

        let ct = nip04_encrypt(&sk_a, &pk_b, &plaintext).unwrap();

        let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            // sk_wrong + pk_b → different shared secret → padding/UTF-8 err
            nip04_decrypt(&sk_wrong, &pk_b, &ct)
        }));
        prop_assert!(result.is_ok(), "decrypt must not panic with wrong key");
        // Ok is possible (lucky padding + UTF-8 alignment) — but it must not
        // equal the original plaintext.
        if let Ok(decoded) = result.unwrap() {
            prop_assert_ne!(decoded, plaintext, "wrong key must not recover plaintext");
        }
    }
}
