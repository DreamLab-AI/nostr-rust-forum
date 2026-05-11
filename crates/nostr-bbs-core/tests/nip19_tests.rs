//! Tests for NIP-19: bech32-encoded entities (npub, nsec, note, nprofile, nevent, naddr).
//!
//! These tests exercise the public API that W1 will implement in
//! `crates/nostr-core/src/nip19.rs`.
//!
//! Known vectors are sourced from the nostr-protocol/nips repository and from
//! the widely-deployed nostr-tools JavaScript library.
//!
//! Test categories:
//!   - Known-vector: fixed hex → bech32 → hex (regression coverage)
//!   - Roundtrip: encode → decode → assert equality
//!   - Prefix: verify bech32 human-readable part (hrp) is correct
//!   - Error paths: malformed / wrong hrp / truncated inputs
//!   - TLV structures: nprofile, nevent, naddr (multi-field encoding)

use nostr_bbs_core::nip19::{
    decode_naddr, decode_nevent, decode_note, decode_nprofile, decode_npub, decode_nsec,
    encode_naddr, encode_nevent, encode_note, encode_nprofile, encode_npub, encode_nsec, NAddr,
    NEvent, NProfile, Nip19Error,
};

// ── npub ──────────────────────────────────────────────────────────────────────

/// fiatjaf's well-known public key — the canonical NIP-19 test vector.
/// Source: <https://github.com/nostr-protocol/nips/blob/master/19.md>
const FIATJAF_HEX: &str = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
const FIATJAF_NPUB: &str = "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6";

#[test]
fn npub_known_vector_encode() {
    let encoded = encode_npub(FIATJAF_HEX).expect("encode_npub must succeed on valid hex");
    assert_eq!(
        encoded, FIATJAF_NPUB,
        "fiatjaf npub must match known vector"
    );
}

#[test]
fn npub_known_vector_decode() {
    let decoded = decode_npub(FIATJAF_NPUB).expect("decode_npub must succeed on valid npub");
    assert_eq!(
        decoded, FIATJAF_HEX,
        "fiatjaf npub must decode to known hex"
    );
}

#[test]
fn npub_roundtrip() {
    let hex = "0000000000000000000000000000000000000000000000000000000000000001";
    // Note: scalar 1 produces a valid x-only pubkey — we test the encoding codec,
    // not curve-point validity. If the impl validates the pubkey, use a real pubkey.
    let encoded = encode_npub(hex).expect("encode_npub must succeed");
    assert!(encoded.starts_with("npub1"), "npub must start with 'npub1'");
    let decoded = decode_npub(&encoded).expect("decode_npub must succeed");
    assert_eq!(decoded, hex, "roundtrip must preserve hex pubkey");
}

#[test]
fn npub_prefix_is_correct() {
    let encoded = encode_npub(FIATJAF_HEX).unwrap();
    assert!(encoded.starts_with("npub1"), "npub must begin with 'npub1'");
}

#[test]
fn npub_decode_wrong_hrp_returns_error() {
    // nsec prefix with pubkey data — wrong hrp for decode_npub
    let _nsec_of_pubkey = encode_npub(FIATJAF_HEX).unwrap().replace("npub1", "nsec1");
    // Substitute hrp manually so bech32 checksum still validates for nsec
    // (use a real nsec to ensure it at least gets past bech32 decode)
    let result = decode_npub("nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5");
    assert!(
        matches!(result, Err(Nip19Error::WrongPrefix { .. })),
        "decode_npub must reject non-npub hrp, got: {result:?}"
    );
}

#[test]
fn npub_decode_invalid_bech32_returns_error() {
    let result = decode_npub("npub1!!!invalid!!!");
    assert!(
        matches!(result, Err(Nip19Error::Bech32(_))),
        "decode_npub must return Bech32 error on malformed input"
    );
}

#[test]
fn npub_decode_wrong_data_length_returns_error() {
    // Build a bech32 string that decodes to fewer than 32 bytes
    // by encoding a short byte slice manually
    use bech32::{Bech32, Hrp};
    let short_bytes = [0u8; 16]; // 16 bytes, not 32
    let hrp = Hrp::parse("npub").unwrap();
    let truncated = bech32::encode::<Bech32>(hrp, &short_bytes).unwrap();
    let result = decode_npub(&truncated);
    assert!(
        matches!(result, Err(Nip19Error::InvalidLength { .. })),
        "decode_npub must reject data that is not 32 bytes, got: {result:?}"
    );
}

// ── nsec ──────────────────────────────────────────────────────────────────────

/// Known nsec vector derived from scalar 1 secret key.
/// sk bytes = [0x00..0x01], bech32 using same spec as npub.
#[test]
fn nsec_roundtrip() {
    let sk_hex = "0000000000000000000000000000000000000000000000000000000000000001";
    let encoded = encode_nsec(sk_hex).expect("encode_nsec must succeed");
    assert!(encoded.starts_with("nsec1"), "nsec must start with 'nsec1'");
    let decoded = decode_nsec(&encoded).expect("decode_nsec must succeed");
    assert_eq!(decoded, sk_hex, "nsec roundtrip must preserve hex key");
}

#[test]
fn nsec_prefix_is_correct() {
    let sk_hex = "0101010101010101010101010101010101010101010101010101010101010101";
    let encoded = encode_nsec(sk_hex).unwrap();
    assert!(encoded.starts_with("nsec1"), "nsec must begin with 'nsec1'");
}

#[test]
fn nsec_decode_wrong_hrp_returns_error() {
    // Use a valid npub — decode_nsec should reject npub hrp
    let result = decode_nsec(FIATJAF_NPUB);
    assert!(
        matches!(result, Err(Nip19Error::WrongPrefix { .. })),
        "decode_nsec must reject npub hrp"
    );
}

// ── note ──────────────────────────────────────────────────────────────────────

/// Note ID is a 32-byte SHA-256 event hash.
const NOTE_HEX: &str = "b3e392b11f5d4f28321cedd09303a748acfd0487aea5a7450b3481c60b6e4f87";

#[test]
fn note_roundtrip() {
    let encoded = encode_note(NOTE_HEX).expect("encode_note must succeed");
    assert!(encoded.starts_with("note1"), "note must start with 'note1'");
    let decoded = decode_note(&encoded).expect("decode_note must succeed");
    assert_eq!(
        decoded, NOTE_HEX,
        "note roundtrip must preserve event id hex"
    );
}

#[test]
fn note_decode_wrong_hrp_returns_error() {
    let result = decode_note(FIATJAF_NPUB);
    assert!(
        matches!(result, Err(Nip19Error::WrongPrefix { .. })),
        "decode_note must reject npub hrp"
    );
}

// ── nprofile ─────────────────────────────────────────────────────────────────

#[test]
fn nprofile_roundtrip_with_relay() {
    let p = NProfile {
        pubkey: FIATJAF_HEX.to_string(),
        relays: vec!["wss://relay.damus.io".to_string()],
    };
    let encoded = encode_nprofile(&p).expect("encode_nprofile must succeed");
    assert!(
        encoded.starts_with("nprofile1"),
        "nprofile must start with 'nprofile1'"
    );
    let decoded = decode_nprofile(&encoded).expect("decode_nprofile must succeed");
    assert_eq!(decoded.pubkey, p.pubkey, "pubkey must roundtrip");
    assert_eq!(decoded.relays, p.relays, "relays must roundtrip");
}

#[test]
fn nprofile_roundtrip_multiple_relays() {
    let p = NProfile {
        pubkey: FIATJAF_HEX.to_string(),
        relays: vec![
            "wss://relay.damus.io".to_string(),
            "wss://nos.lol".to_string(),
            "wss://relay.nostr.band".to_string(),
        ],
    };
    let encoded = encode_nprofile(&p).unwrap();
    let decoded = decode_nprofile(&encoded).unwrap();
    assert_eq!(decoded.pubkey, p.pubkey);
    // All relays must be preserved (order may differ — convert to sets)
    let mut enc_relays = decoded.relays.clone();
    let mut orig_relays = p.relays.clone();
    enc_relays.sort();
    orig_relays.sort();
    assert_eq!(enc_relays, orig_relays, "all relays must roundtrip");
}

#[test]
fn nprofile_roundtrip_no_relays() {
    let p = NProfile {
        pubkey: FIATJAF_HEX.to_string(),
        relays: vec![],
    };
    let encoded = encode_nprofile(&p).unwrap();
    let decoded = decode_nprofile(&encoded).unwrap();
    assert_eq!(decoded.pubkey, p.pubkey);
    assert!(
        decoded.relays.is_empty(),
        "no relays must roundtrip as empty"
    );
}

#[test]
fn nprofile_prefix_is_correct() {
    let p = NProfile {
        pubkey: FIATJAF_HEX.to_string(),
        relays: vec![],
    };
    let encoded = encode_nprofile(&p).unwrap();
    assert!(encoded.starts_with("nprofile1"));
}

#[test]
fn nprofile_decode_wrong_hrp_returns_error() {
    let result = decode_nprofile(FIATJAF_NPUB);
    assert!(
        matches!(result, Err(Nip19Error::WrongPrefix { .. })),
        "decode_nprofile must reject npub hrp"
    );
}

#[test]
fn nprofile_decode_truncated_data_returns_error() {
    // Build a very short nprofile that cannot contain a 32-byte pubkey TLV
    use bech32::{Bech32, Hrp};
    let short_bytes = [0u8; 4];
    let hrp = Hrp::parse("nprofile").unwrap();
    let bad = bech32::encode::<Bech32>(hrp, &short_bytes).unwrap();
    let result = decode_nprofile(&bad);
    assert!(
        result.is_err(),
        "decode_nprofile must reject truncated TLV data"
    );
}

// ── nevent ────────────────────────────────────────────────────────────────────

#[test]
fn nevent_roundtrip_with_relay_and_author() {
    let e = NEvent {
        id: NOTE_HEX.to_string(),
        relays: vec!["wss://relay.damus.io".to_string()],
        author: Some(FIATJAF_HEX.to_string()),
        kind: Some(1),
    };
    let encoded = encode_nevent(&e).expect("encode_nevent must succeed");
    assert!(
        encoded.starts_with("nevent1"),
        "nevent must start with 'nevent1'"
    );
    let decoded = decode_nevent(&encoded).expect("decode_nevent must succeed");
    assert_eq!(decoded.id, e.id, "event id must roundtrip");
    assert_eq!(decoded.relays, e.relays, "relays must roundtrip");
    assert_eq!(decoded.author, e.author, "author must roundtrip");
    assert_eq!(decoded.kind, e.kind, "kind must roundtrip");
}

#[test]
fn nevent_roundtrip_minimal() {
    // Minimal nevent: only event id, no relays/author/kind
    let e = NEvent {
        id: NOTE_HEX.to_string(),
        relays: vec![],
        author: None,
        kind: None,
    };
    let encoded = encode_nevent(&e).unwrap();
    let decoded = decode_nevent(&encoded).unwrap();
    assert_eq!(decoded.id, e.id);
    assert!(decoded.relays.is_empty());
    assert!(decoded.author.is_none());
    assert!(decoded.kind.is_none());
}

#[test]
fn nevent_prefix_is_correct() {
    let e = NEvent {
        id: NOTE_HEX.to_string(),
        relays: vec![],
        author: None,
        kind: None,
    };
    let encoded = encode_nevent(&e).unwrap();
    assert!(encoded.starts_with("nevent1"));
}

#[test]
fn nevent_decode_wrong_hrp_returns_error() {
    let result = decode_nevent(FIATJAF_NPUB);
    assert!(
        matches!(result, Err(Nip19Error::WrongPrefix { .. })),
        "decode_nevent must reject npub hrp"
    );
}

// ── naddr ─────────────────────────────────────────────────────────────────────

/// NIP-33 replaceable event address.
#[test]
fn naddr_roundtrip() {
    let a = NAddr {
        identifier: "my-article-slug".to_string(),
        pubkey: FIATJAF_HEX.to_string(),
        kind: 30023, // NIP-23 long-form content
        relays: vec!["wss://relay.damus.io".to_string()],
    };
    let encoded = encode_naddr(&a).expect("encode_naddr must succeed");
    assert!(
        encoded.starts_with("naddr1"),
        "naddr must start with 'naddr1'"
    );
    let decoded = decode_naddr(&encoded).expect("decode_naddr must succeed");
    assert_eq!(
        decoded.identifier, a.identifier,
        "identifier must roundtrip"
    );
    assert_eq!(decoded.pubkey, a.pubkey, "pubkey must roundtrip");
    assert_eq!(decoded.kind, a.kind, "kind must roundtrip");
    assert_eq!(decoded.relays, a.relays, "relays must roundtrip");
}

#[test]
fn naddr_roundtrip_no_relays() {
    let a = NAddr {
        identifier: "slug".to_string(),
        pubkey: FIATJAF_HEX.to_string(),
        kind: 30023,
        relays: vec![],
    };
    let encoded = encode_naddr(&a).unwrap();
    let decoded = decode_naddr(&encoded).unwrap();
    assert_eq!(decoded.identifier, a.identifier);
    assert_eq!(decoded.pubkey, a.pubkey);
    assert_eq!(decoded.kind, a.kind);
    assert!(decoded.relays.is_empty());
}

#[test]
fn naddr_roundtrip_empty_identifier() {
    // Empty d-tag is valid for kind-0 (metadata)
    let a = NAddr {
        identifier: String::new(),
        pubkey: FIATJAF_HEX.to_string(),
        kind: 0,
        relays: vec![],
    };
    let encoded = encode_naddr(&a).unwrap();
    let decoded = decode_naddr(&encoded).unwrap();
    assert_eq!(decoded.identifier, "");
    assert_eq!(decoded.kind, 0);
}

#[test]
fn naddr_prefix_is_correct() {
    let a = NAddr {
        identifier: "test".to_string(),
        pubkey: FIATJAF_HEX.to_string(),
        kind: 30023,
        relays: vec![],
    };
    let encoded = encode_naddr(&a).unwrap();
    assert!(encoded.starts_with("naddr1"));
}

#[test]
fn naddr_decode_wrong_hrp_returns_error() {
    let result = decode_naddr(FIATJAF_NPUB);
    assert!(
        matches!(result, Err(Nip19Error::WrongPrefix { .. })),
        "decode_naddr must reject npub hrp"
    );
}

// ── Cross-type error isolation ─────────────────────────────────────────────────

#[test]
fn decode_npub_rejects_nprofile() {
    let p = NProfile {
        pubkey: FIATJAF_HEX.to_string(),
        relays: vec![],
    };
    let nprofile_str = encode_nprofile(&p).unwrap();
    let result = decode_npub(&nprofile_str);
    assert!(
        result.is_err(),
        "decode_npub must reject an nprofile string"
    );
}

#[test]
fn decode_npub_rejects_nevent() {
    let e = NEvent {
        id: NOTE_HEX.to_string(),
        relays: vec![],
        author: None,
        kind: None,
    };
    let nevent_str = encode_nevent(&e).unwrap();
    let result = decode_npub(&nevent_str);
    assert!(result.is_err(), "decode_npub must reject a nevent string");
}

// ── Bech32 charset compliance ─────────────────────────────────────────────────

#[test]
fn encoded_npub_uses_only_bech32_charset() {
    // bech32 charset: qpzry9x8gf2tvdw0s3jn54khce6mua7l (plus hrp chars)
    // All characters after the separator '1' must be in the bech32 charset.
    let encoded = encode_npub(FIATJAF_HEX).unwrap();
    let bech32_chars = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    let after_sep = encoded
        .split_once('1')
        .map(|(_, rest)| rest)
        .expect("bech32 must have '1' separator");
    for ch in after_sep.chars() {
        assert!(
            bech32_chars.contains(ch),
            "character '{ch}' in npub '{encoded}' is not in bech32 charset"
        );
    }
}
