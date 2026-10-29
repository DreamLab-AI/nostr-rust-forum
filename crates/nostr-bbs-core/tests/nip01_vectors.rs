//! NIP-01 event-id and signature checks over `fixtures/nip01-events.json`.
//!
//! The fixture pins the canonical serialisation of 11 events (7 well-formed, 4 malformed) (it carries no
//! ids or signatures, as the upstream spec gives none). For each one this
//! proves, on the RustCrypto 0.14 Schnorr path:
//!
//! 1. the crate's id equals `sha256(serialised)` and the serialisation is
//!    reproduced byte for byte,
//! 2. a signed event round-trips through `verify_event`, and the signature is
//!    also accepted by the independent upstream `nostr` crate (libsecp256k1),
//! 3. flipping any field, or the signature, is rejected.

use k256::schnorr::SigningKey;
use nostr::JsonUtil;
use nostr_bbs_core::event::{
    compute_event_id, sign_event_deterministic, verify_event, NostrEvent, UnsignedEvent,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn signing_key() -> SigningKey {
    SigningKey::from_bytes((&[0x42u8; 32]).into()).unwrap()
}

fn unsigned(v: &Value, pubkey: &str) -> UnsignedEvent {
    let mut e = v["event"].clone();
    e["pubkey"] = Value::String(pubkey.to_string());
    serde_json::from_value(e).expect("positive vector is a well-formed event")
}

fn all_vectors() -> Vec<Value> {
    let doc: Value =
        serde_json::from_str(include_str!("fixtures/nip01-events.json")).expect("fixture parses");
    doc["vectors"].as_array().unwrap().clone()
}

/// The 7 vectors the spec says are well-formed.
fn vectors() -> Vec<Value> {
    all_vectors()
        .into_iter()
        .filter(|v| v["valid"].as_bool().unwrap())
        .collect()
}

/// The 4 malformed vectors: each must be refused somewhere on the path from
/// JSON to a signed event (parse failure, or pubkey/key mismatch at signing).
#[test]
fn nip01_malformed_vectors_are_refused() {
    let sk = signing_key();
    let mut refused = 0;
    for v in all_vectors()
        .into_iter()
        .filter(|v| !v["valid"].as_bool().unwrap())
    {
        let case = v["case"].as_str().unwrap();
        let ok = match serde_json::from_value::<UnsignedEvent>(v["event"].clone()) {
            Err(_) => false,
            Ok(ev) => sign_event_deterministic(ev, &sk).is_ok(),
        };
        assert!(!ok, "{case}: must be refused");
        refused += 1;
    }
    assert_eq!(refused, 4);
}

#[test]
fn nip01_ids_match_sha256_of_published_serialisation() {
    let vs = vectors();
    assert_eq!(vs.len(), 7);
    for v in &vs {
        let case = v["case"].as_str().unwrap();
        let pubkey = v["event"]["pubkey"].as_str().unwrap();
        let ev = unsigned(v, pubkey);
        let serialised = v["serialised"].as_str().unwrap();
        // The fixture's serialisation is the NIP-01 canonical form, so the
        // crate must reproduce it byte for byte.
        let ours = serde_json::to_string(&(
            0u8,
            &ev.pubkey,
            ev.created_at,
            ev.kind,
            &ev.tags,
            &ev.content,
        ))
        .unwrap();
        assert_eq!(ours, serialised, "{case}: serialisation");
        let expected = Sha256::digest(serialised.as_bytes());
        assert_eq!(
            compute_event_id(&ev).as_slice(),
            expected.as_slice(),
            "{case}: id"
        );
    }
}

#[test]
fn nip01_signed_events_verify_and_tamper_is_rejected() {
    let sk = signing_key();
    let pubkey = hex::encode(sk.verifying_key().to_bytes());
    for v in vectors() {
        let case = v["case"].as_str().unwrap();
        let ev = sign_event_deterministic(unsigned(&v, &pubkey), &sk).unwrap();
        assert_eq!(
            ev.id,
            hex::encode(Sha256::digest(
                serde_json::to_string(&(
                    0u8,
                    &ev.pubkey,
                    ev.created_at,
                    ev.kind,
                    &ev.tags,
                    &ev.content
                ))
                .unwrap()
                .as_bytes()
            )),
            "{case}: signed id"
        );
        assert!(verify_event(&ev), "{case}: own verify");

        // Independent implementation (rust-nostr over libsecp256k1).
        let upstream = nostr::Event::from_json(serde_json::to_string(&ev).unwrap())
            .unwrap_or_else(|e| panic!("{case}: upstream parse: {e}"));
        upstream
            .verify()
            .unwrap_or_else(|e| panic!("{case}: upstream verify: {e}"));

        let tampered: Vec<NostrEvent> = vec![
            NostrEvent {
                content: format!("{}x", ev.content),
                ..ev.clone()
            },
            NostrEvent {
                created_at: ev.created_at + 1,
                ..ev.clone()
            },
            NostrEvent {
                kind: ev.kind + 1,
                ..ev.clone()
            },
            NostrEvent {
                sig: format!("{:0>128}", "0"),
                ..ev.clone()
            },
            NostrEvent {
                sig: {
                    let mut s = ev.sig.clone().into_bytes();
                    s[0] = if s[0] == b'0' { b'1' } else { b'0' };
                    String::from_utf8(s).unwrap()
                },
                ..ev.clone()
            },
        ];
        for (i, t) in tampered.iter().enumerate() {
            assert!(!verify_event(t), "{case}: tamper {i} must be rejected");
        }
    }
}
