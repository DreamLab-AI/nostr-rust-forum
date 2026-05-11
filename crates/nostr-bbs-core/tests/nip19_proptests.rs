//! Property-based tests for NIP-19 bech32 entities.
//!
//! Sprint v9, STREAM-E1 (cryptographic boundary proptests). These tests
//! supplement `nip19_tests.rs` with proptest-driven roundtrip and
//! malformed-input fuzzing. They establish:
//!
//! 1. Roundtrip for `npub`/`nsec`: any 32-byte hex blob → encode → decode → same hex.
//! 2. TLV roundtrip for `nprofile`/`nevent`: any pubkey + relay set → encode → decode
//!    → same logical entity (relay set equality).
//! 3. Malformed-input safety: arbitrary printable strings up to 200 chars
//!    must either decode cleanly or return `Err(Nip19Error)` — never panic.
//!
//! Note: NIP-19 codec functions don't validate that 32-byte secrets/pubkeys
//! form valid secp256k1 points — they validate hex length only. This is by
//! design (nip19 is a codec, not a key validator), so arbitrary 32-byte
//! inputs are valid roundtrip subjects.
//!
//! Native-only target (proptest pulls in `rusty-fork` → `wait-timeout`,
//! both unavailable on `wasm32-unknown-unknown`).

#![cfg(not(target_arch = "wasm32"))]

use std::panic;

use nostr_bbs_core::nip19::{
    decode_naddr, decode_nevent, decode_note, decode_nprofile, decode_npub, decode_nsec,
    encode_nevent, encode_note, encode_nprofile, encode_npub, encode_nsec, NEvent, NProfile,
};
use proptest::prelude::*;

// ── Strategies ────────────────────────────────────────────────────────────────

/// Generate a 32-byte hex string (64 lowercase hex chars).
fn arb_hex32() -> impl Strategy<Value = String> {
    prop::collection::vec(any::<u8>(), 32..=32).prop_map(|bytes| hex::encode(bytes))
}

/// Generate a relay URL.
///
/// Phase 5 absorption (ADR-076/078): rust-nostr 0.44's `RelayUrl::parse`
/// validates URL syntax. The legacy hand-roll treated relays as opaque
/// byte strings; the absorbed adapter inherits the stricter URL contract.
/// The generator now produces well-formed `wss://<host>` URLs.
fn arb_relay_url() -> impl Strategy<Value = String> {
    ("[a-z]{1,8}", "[a-z]{2,6}")
        .prop_map(|(host, tld)| format!("wss://{host}.{tld}"))
}

/// Generate a small set of 0..=5 relay URLs.
fn arb_relays() -> impl Strategy<Value = Vec<String>> {
    prop::collection::vec(arb_relay_url(), 0..=5)
}

// ── (E1a-1) Simple-type roundtrip: encode → decode → identity ─────────────────

proptest! {
    #[test]
    fn npub_encode_decode_roundtrip(pk_hex in arb_hex32()) {
        let encoded = encode_npub(&pk_hex).expect("encode_npub must accept any 32-byte hex");
        prop_assert!(encoded.starts_with("npub1"), "must start with npub1, got {}", encoded);
        let decoded = decode_npub(&encoded).expect("decode_npub must succeed on its own output");
        prop_assert_eq!(decoded, pk_hex);
    }

    #[test]
    fn nsec_encode_decode_roundtrip(sk_hex in arb_hex32()) {
        let encoded = encode_nsec(&sk_hex).expect("encode_nsec must accept any 32-byte hex");
        prop_assert!(encoded.starts_with("nsec1"), "must start with nsec1, got {}", encoded);
        let decoded = decode_nsec(&encoded).expect("decode_nsec must succeed on its own output");
        prop_assert_eq!(decoded, sk_hex);
    }

    #[test]
    fn note_encode_decode_roundtrip(id_hex in arb_hex32()) {
        let encoded = encode_note(&id_hex).expect("encode_note must accept any 32-byte hex");
        prop_assert!(encoded.starts_with("note1"));
        let decoded = decode_note(&encoded).expect("decode_note must succeed on its own output");
        prop_assert_eq!(decoded, id_hex);
    }
}

// ── (E1a-2) TLV roundtrip: nprofile / nevent with random relay sets ──────────

proptest! {
    #[test]
    fn nprofile_tlv_roundtrip(
        pk_hex in arb_hex32(),
        relays in arb_relays(),
    ) {
        let profile = NProfile {
            pubkey: pk_hex.clone(),
            relays: relays.clone(),
        };
        let encoded = encode_nprofile(&profile).expect("encode_nprofile must succeed");
        prop_assert!(encoded.starts_with("nprofile1"));

        let decoded = decode_nprofile(&encoded).expect("decode_nprofile must succeed on its own output");
        prop_assert_eq!(decoded.pubkey, pk_hex);
        // Relay set equality (preserve order — push_tlv preserves order).
        prop_assert_eq!(decoded.relays, relays);
    }

    #[test]
    fn nevent_tlv_roundtrip(
        id_hex in arb_hex32(),
        relays in arb_relays(),
        author in proptest::option::of(arb_hex32()),
        // NIP-01 / NIP-19 spec: event kinds are 16-bit unsigned integers
        // (0..=65535). The legacy hand-roll accepted any u32 in its TLV
        // path; the absorbed adapter inherits the spec-correct u16 range.
        kind in proptest::option::of(0u32..=65535u32),
    ) {
        let event = NEvent {
            id: id_hex.clone(),
            relays: relays.clone(),
            author: author.clone(),
            kind,
        };
        let encoded = encode_nevent(&event).expect("encode_nevent must succeed");
        prop_assert!(encoded.starts_with("nevent1"));

        let decoded = decode_nevent(&encoded).expect("decode_nevent must succeed on its own output");
        prop_assert_eq!(decoded.id, id_hex);
        prop_assert_eq!(decoded.relays, relays);
        prop_assert_eq!(decoded.author, author);
        prop_assert_eq!(decoded.kind, kind);
    }
}

// ── (E1a-3) Malformed input never panics ─────────────────────────────────────
//
// All decode functions must return `Err(Nip19Error)` (never panic) on any
// printable-ASCII input up to 200 chars. We use `panic::catch_unwind` to
// catch any latent panic and convert it into a proptest failure with a
// descriptive message.

proptest! {
    #[test]
    fn decode_npub_no_panic_on_arbitrary_strings(s in r"\PC{0,200}") {
        let s = s.clone();
        let result = panic::catch_unwind(panic::AssertUnwindSafe(|| decode_npub(&s)));
        prop_assert!(
            result.is_ok(),
            "decode_npub must not panic on input {:?}",
            s
        );
        // Whatever result.unwrap() is — Ok or Err — both are acceptable.
        let _ = result.unwrap();
    }

    #[test]
    fn decode_nsec_no_panic_on_arbitrary_strings(s in r"\PC{0,200}") {
        let s = s.clone();
        let result = panic::catch_unwind(panic::AssertUnwindSafe(|| decode_nsec(&s)));
        prop_assert!(result.is_ok(), "decode_nsec must not panic on input {:?}", s);
        let _ = result.unwrap();
    }

    #[test]
    fn decode_note_no_panic_on_arbitrary_strings(s in r"\PC{0,200}") {
        let s = s.clone();
        let result = panic::catch_unwind(panic::AssertUnwindSafe(|| decode_note(&s)));
        prop_assert!(result.is_ok(), "decode_note must not panic on input {:?}", s);
        let _ = result.unwrap();
    }

    #[test]
    fn decode_nprofile_no_panic_on_arbitrary_strings(s in r"\PC{0,200}") {
        let s = s.clone();
        let result = panic::catch_unwind(panic::AssertUnwindSafe(|| decode_nprofile(&s)));
        prop_assert!(
            result.is_ok(),
            "decode_nprofile must not panic on input {:?}",
            s
        );
        let _ = result.unwrap();
    }

    #[test]
    fn decode_nevent_no_panic_on_arbitrary_strings(s in r"\PC{0,200}") {
        let s = s.clone();
        let result = panic::catch_unwind(panic::AssertUnwindSafe(|| decode_nevent(&s)));
        prop_assert!(
            result.is_ok(),
            "decode_nevent must not panic on input {:?}",
            s
        );
        let _ = result.unwrap();
    }

    #[test]
    fn decode_naddr_no_panic_on_arbitrary_strings(s in r"\PC{0,200}") {
        let s = s.clone();
        let result = panic::catch_unwind(panic::AssertUnwindSafe(|| decode_naddr(&s)));
        prop_assert!(
            result.is_ok(),
            "decode_naddr must not panic on input {:?}",
            s
        );
        let _ = result.unwrap();
    }
}

// ── (E1a-4) Cross-prefix decode fails fast ───────────────────────────────────
//
// Any encoded entity decoded against a different prefix must return Err
// (`Nip19Error::WrongPrefix`) — never accidentally accept due to TLV
// flexibility.

proptest! {
    #[test]
    fn npub_does_not_decode_as_nsec_or_note(pk_hex in arb_hex32()) {
        let npub = encode_npub(&pk_hex).unwrap();
        prop_assert!(decode_nsec(&npub).is_err(), "npub must not decode as nsec");
        prop_assert!(decode_note(&npub).is_err(), "npub must not decode as note");
        prop_assert!(decode_nprofile(&npub).is_err(), "npub must not decode as nprofile");
    }

    #[test]
    fn nsec_does_not_decode_as_npub_or_note(sk_hex in arb_hex32()) {
        let nsec = encode_nsec(&sk_hex).unwrap();
        prop_assert!(decode_npub(&nsec).is_err(), "nsec must not decode as npub");
        prop_assert!(decode_note(&nsec).is_err(), "nsec must not decode as note");
    }
}
