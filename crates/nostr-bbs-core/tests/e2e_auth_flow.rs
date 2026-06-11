//! Cross-worker end-to-end integration tests for the auth -> relay -> pod request flow.
//!
//! These tests verify the full Nostr protocol logic that spans multiple workers:
//!
//! 1. **NIP-98 HTTP Auth**: token creation -> verification round-trip, including
//!    URL/method/timestamp/payload-hash validation (auth-worker + pod-worker + search-worker)
//! 2. **Event signing**: create -> sign -> verify pipeline used by the relay-worker
//! 3. **Gift wrap (NIP-59)**: encrypt -> wrap -> unwrap -> decrypt for DM relay routing
//! 4. **NIP-44 encryption**: symmetric encrypt/decrypt used across workers
//! 5. **NIP-19 encoding**: entity encoding round-trips for client <-> relay interop
//! 6. **Moderation events**: build -> sign -> validate pipeline (auth-worker + relay-worker)
//! 7. **Calendar events (NIP-52)**: create -> verify pipeline
//!
//! Workers cannot run in native cargo test (wasm32 runtime required), but these
//! tests exercise the identical protocol logic that workers invoke at request time.

use std::collections::HashSet;

use nostr_bbs_core::{
    // Moderation events
    build_ban,
    build_moderation_action,
    build_mute,
    build_report,
    build_unban,
    build_unmute,
    build_warning,
    // Calendar events (NIP-52)
    create_calendar_event,
    // NIP-98 auth flow
    create_nip98_token,
    create_rsvp,
    d_tag_of,
    decode_naddr,
    decode_nevent,
    decode_note,
    decode_nprofile,
    decode_npub,
    decode_nsec,
    encode_naddr,
    encode_nevent,
    encode_note,
    encode_nprofile,
    // NIP-19 encoding
    encode_npub,
    encode_nsec,
    // Keys
    generate_keypair,

    // Gift wrap (NIP-59)
    gift_wrap,
    mute_expires_at,
    nip04_decrypt,
    // NIP-04 encryption
    nip04_encrypt,
    nip04_shared_secret,

    nip19::{NAddr, NEvent, NProfile},
    nip44_decrypt,

    // NIP-44 encryption
    nip44_encrypt,
    nip98::{authorization_header, create_token_at, verify_token_at},
    nip98_authorization_header,
    // Event signing
    sign_event,
    sign_event_deterministic,
    unwrap_gift,
    validate_moderation_event,
    verify_event,
    verify_event_strict,
    verify_events_batch,
    verify_nip98_token,
    CalendarError,

    EventError,

    GiftWrapError,

    ModerationEventError,
    Nip98Error,
    NostrEvent,
    RsvpStatus,
    UnsignedEvent,
    KIND_BAN,
    KIND_MODERATION_ACTION,

    KIND_MUTE,
    KIND_REPORT,
    KIND_UNBAN,
    KIND_UNMUTE,
    KIND_WARNING,
};

use k256::schnorr::SigningKey;
use sha2::{Digest, Sha256};

// ============================================================================
// Helpers
// ============================================================================

/// Deterministic secret key for admin scenarios.
fn admin_sk_bytes() -> [u8; 32] {
    [0x02u8; 32]
}

fn admin_signing_key() -> SigningKey {
    SigningKey::from_bytes(&admin_sk_bytes()).unwrap()
}

fn admin_pubkey_hex() -> String {
    hex::encode(admin_signing_key().verifying_key().to_bytes())
}

/// Deterministic secret key for a regular user.
fn user_sk_bytes() -> [u8; 32] {
    let mut sk = [0u8; 32];
    sk[0] = 0x01;
    sk[31] = 0x01;
    sk
}

fn user_signing_key() -> SigningKey {
    SigningKey::from_bytes(&user_sk_bytes()).unwrap()
}

fn user_pubkey_hex() -> String {
    hex::encode(user_signing_key().verifying_key().to_bytes())
}

/// Build a fresh random keypair, returning (sk_bytes, pubkey_hex).
fn random_keypair() -> ([u8; 32], String) {
    let kp = generate_keypair().unwrap();
    let sk = *kp.secret.as_bytes();
    let pk = kp.public.to_hex();
    (sk, pk)
}

/// Signing key for NIP-26 scalar helpers.
fn sk_scalar(n: u8) -> [u8; 32] {
    let mut sk = [0u8; 32];
    sk[31] = n;
    sk
}

fn pk_hex_for_scalar(n: u8) -> String {
    let sk = SigningKey::from_bytes(&sk_scalar(n)).unwrap();
    hex::encode(sk.verifying_key().to_bytes())
}

fn admin_set_with(pubkey: &str) -> HashSet<String> {
    let mut s = HashSet::new();
    s.insert(pubkey.to_string());
    s
}

fn sign_deterministic(unsigned: UnsignedEvent, sk: &SigningKey) -> NostrEvent {
    sign_event_deterministic(unsigned, sk).unwrap()
}

// ============================================================================
// 1. NIP-98 HTTP Auth: token creation -> verification round-trip
// ============================================================================

#[test]
fn e2e_nip98_create_verify_roundtrip_no_body() {
    let sk = user_sk_bytes();
    let url = "https://relay.example.com/api/events";
    let method = "GET";

    let token = create_nip98_token(&sk, url, method, None).unwrap();
    let header = nip98_authorization_header(&token);
    let verified = verify_nip98_token(&header, url, method, None).unwrap();

    assert_eq!(verified.pubkey, user_pubkey_hex());
    assert_eq!(verified.url, url);
    assert_eq!(verified.method, method);
    assert!(verified.payload_hash.is_none());
}

#[test]
fn e2e_nip98_create_verify_roundtrip_with_body() {
    let sk = user_sk_bytes();
    let url = "https://pod.example.com/api/upload";
    let method = "POST";
    let body = b"{\"kind\":1,\"content\":\"hello\"}";

    let token = create_nip98_token(&sk, url, method, Some(body)).unwrap();
    let header = nip98_authorization_header(&token);
    let verified = verify_nip98_token(&header, url, method, Some(body)).unwrap();

    assert_eq!(verified.method, method);
    assert!(verified.payload_hash.is_some());

    let expected_hash = hex::encode(Sha256::digest(body));
    assert_eq!(verified.payload_hash.unwrap(), expected_hash);
}

#[test]
fn e2e_nip98_wrong_url_rejected() {
    let sk = user_sk_bytes();
    let token = create_nip98_token(&sk, "https://relay.good.com/api", "GET", None).unwrap();
    let header = nip98_authorization_header(&token);

    let err = verify_nip98_token(&header, "https://relay.evil.com/api", "GET", None).unwrap_err();
    assert!(matches!(err, Nip98Error::UrlMismatch { .. }));
}

#[test]
fn e2e_nip98_wrong_method_rejected() {
    let sk = user_sk_bytes();
    let url = "https://auth.example.com/api/invite";
    let token = create_nip98_token(&sk, url, "GET", None).unwrap();
    let header = nip98_authorization_header(&token);

    let err = verify_nip98_token(&header, url, "DELETE", None).unwrap_err();
    assert!(matches!(err, Nip98Error::MethodMismatch { .. }));
}

#[test]
fn e2e_nip98_expired_timestamp_rejected() {
    let sk = user_sk_bytes();
    let url = "https://search.example.com/api/search";
    let old_ts = 1_600_000_000u64;
    let now_ts = 1_600_000_200u64; // 200 seconds later, beyond 60s tolerance

    let token = create_token_at(&sk, url, "GET", None, old_ts).unwrap();
    let header = authorization_header(&token);

    let err = verify_token_at(&header, url, "GET", None, now_ts).unwrap_err();
    assert!(matches!(err, Nip98Error::TimestampExpired { .. }));
}

#[test]
fn e2e_nip98_within_tolerance_accepted() {
    let sk = user_sk_bytes();
    let url = "https://relay.example.com/api/publish";
    let ts = 1_700_000_000u64;

    let token = create_token_at(&sk, url, "POST", Some(b"event_data"), ts).unwrap();
    let header = authorization_header(&token);

    // 30 seconds later -- within the 60s tolerance window
    let result = verify_token_at(&header, url, "POST", Some(b"event_data"), ts + 30).unwrap();
    assert_eq!(result.created_at, ts);
}

#[test]
fn e2e_nip98_payload_hash_mismatch_rejected() {
    let sk = user_sk_bytes();
    let url = "https://pod.example.com/api/data";
    let original_body = b"original payload";
    let tampered_body = b"tampered payload";

    let token = create_nip98_token(&sk, url, "POST", Some(original_body)).unwrap();
    let header = nip98_authorization_header(&token);

    let err = verify_nip98_token(&header, url, "POST", Some(tampered_body)).unwrap_err();
    assert!(matches!(err, Nip98Error::PayloadMismatch));
}

#[test]
fn e2e_nip98_body_present_but_no_payload_tag_rejected() {
    let sk = user_sk_bytes();
    let url = "https://relay.example.com/api/post";

    // Create token with no body (no payload tag in signed event)
    let token = create_nip98_token(&sk, url, "POST", None).unwrap();
    let header = nip98_authorization_header(&token);

    // Verify with a body -- should be rejected because the signed event has no payload tag
    let err = verify_nip98_token(&header, url, "POST", Some(b"sneaky body")).unwrap_err();
    assert!(matches!(err, Nip98Error::MissingPayloadTag));
}

#[test]
fn e2e_nip98_tampered_signature_rejected() {
    let sk = user_sk_bytes();
    let url = "https://auth.example.com/api/login";
    let token_b64 = create_nip98_token(&sk, url, "GET", None).unwrap();

    // Decode, tamper with sig, re-encode
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    let json_bytes = BASE64.decode(&token_b64).unwrap();
    let mut event: NostrEvent = serde_json::from_slice(&json_bytes).unwrap();
    let mut sig_bytes = hex::decode(&event.sig).unwrap();
    sig_bytes[0] ^= 0xFF;
    event.sig = hex::encode(&sig_bytes);

    let tampered_json = serde_json::to_string(&event).unwrap();
    let tampered_b64 = BASE64.encode(tampered_json.as_bytes());
    let header = nip98_authorization_header(&tampered_b64);

    let err = verify_nip98_token(&header, url, "GET", None).unwrap_err();
    assert!(matches!(err, Nip98Error::InvalidSignature));
}

#[test]
fn e2e_nip98_missing_prefix_rejected() {
    let err = verify_nip98_token("Bearer abc123", "https://x.com", "GET", None).unwrap_err();
    assert!(matches!(err, Nip98Error::MissingPrefix));
}

// ============================================================================
// 2. Event signing -> verification round-trip (relay messages)
// ============================================================================

#[test]
fn e2e_event_sign_verify_roundtrip() {
    let sk = user_signing_key();
    let pubkey = user_pubkey_hex();

    let unsigned = UnsignedEvent {
        pubkey,
        created_at: 1_700_000_000,
        kind: 1,
        tags: vec![],
        content: "Hello from E2E test".to_string(),
    };

    let signed = sign_event(unsigned, &sk).unwrap();
    assert!(verify_event(&signed));
    assert!(verify_event_strict(&signed).is_ok());
}

#[test]
fn e2e_event_tampered_content_fails_verification() {
    let sk = user_signing_key();
    let pubkey = user_pubkey_hex();

    let unsigned = UnsignedEvent {
        pubkey,
        created_at: 1_700_000_000,
        kind: 1,
        tags: vec![],
        content: "original".to_string(),
    };

    let mut signed = sign_event(unsigned, &sk).unwrap();
    signed.content = "tampered by attacker".to_string();
    assert!(!verify_event(&signed));
}

#[test]
fn e2e_event_tampered_id_fails_verification() {
    let sk = user_signing_key();
    let pubkey = user_pubkey_hex();

    let unsigned = UnsignedEvent {
        pubkey,
        created_at: 1_700_000_000,
        kind: 1,
        tags: vec![],
        content: "test".to_string(),
    };

    let mut signed = sign_event(unsigned, &sk).unwrap();
    signed.id = "00".repeat(32);
    let err = verify_event_strict(&signed).unwrap_err();
    assert!(matches!(err, EventError::IdMismatch { .. }));
}

#[test]
fn e2e_event_tampered_signature_fails_verification() {
    let sk = user_signing_key();
    let pubkey = user_pubkey_hex();

    let unsigned = UnsignedEvent {
        pubkey,
        created_at: 1_700_000_000,
        kind: 1,
        tags: vec![],
        content: "integrity test".to_string(),
    };

    let mut signed = sign_event(unsigned, &sk).unwrap();
    let mut sig_bytes = hex::decode(&signed.sig).unwrap();
    sig_bytes[0] ^= 0xFF;
    signed.sig = hex::encode(&sig_bytes);
    let err = verify_event_strict(&signed).unwrap_err();
    assert!(matches!(err, EventError::SignatureInvalid));
}

#[test]
fn e2e_event_wrong_pubkey_rejected_at_signing() {
    let sk = user_signing_key();
    let unsigned = UnsignedEvent {
        pubkey: "aa".repeat(32),
        created_at: 1_700_000_000,
        kind: 1,
        tags: vec![],
        content: "wrong pubkey".to_string(),
    };

    let result = sign_event(unsigned, &sk);
    assert!(result.is_err());
}

#[test]
fn e2e_event_batch_verification() {
    let sk = user_signing_key();
    let pubkey = user_pubkey_hex();

    let good_events: Vec<NostrEvent> = (0..5)
        .map(|i| {
            sign_event_deterministic(
                UnsignedEvent {
                    pubkey: pubkey.clone(),
                    created_at: 1_700_000_000 + i,
                    kind: 1,
                    tags: vec![],
                    content: format!("relay msg {i}"),
                },
                &sk,
            )
            .unwrap()
        })
        .collect();

    let results = verify_events_batch(&good_events);
    assert!(results.iter().all(|r| r.is_ok()));

    // Inject a tampered event
    let mut mixed = good_events;
    mixed[2].content = "tampered".to_string();
    let results = verify_events_batch(&mixed);
    assert!(results[0].is_ok());
    assert!(results[1].is_ok());
    assert!(results[2].is_err());
    assert!(results[3].is_ok());
    assert!(results[4].is_ok());
}

#[test]
fn e2e_event_with_tags_roundtrip() {
    let sk = user_signing_key();
    let pubkey = user_pubkey_hex();

    let unsigned = UnsignedEvent {
        pubkey,
        created_at: 1_700_000_000,
        kind: 1,
        tags: vec![
            vec!["e".to_string(), "aa".repeat(32)],
            vec!["p".to_string(), "bb".repeat(32)],
            vec!["t".to_string(), "nostr".to_string()],
        ],
        content: "event with tags".to_string(),
    };

    let signed = sign_event(unsigned, &sk).unwrap();
    assert!(verify_event(&signed));
    assert_eq!(signed.tags.len(), 3);
    assert_eq!(signed.tags[0][0], "e");
    assert_eq!(signed.tags[1][0], "p");
    assert_eq!(signed.tags[2][0], "t");
}

// ============================================================================
// 3. Gift wrap (NIP-59) encryption -> decryption round-trip
// ============================================================================

#[test]
fn e2e_gift_wrap_roundtrip() {
    let (sender_sk, sender_pk) = random_keypair();
    let (recipient_sk, recipient_pk) = random_keypair();

    let content = "Secret DM from sender to recipient via gift wrap";
    let wrapped = gift_wrap(&sender_sk, &sender_pk, &recipient_pk, content).unwrap();

    assert_eq!(wrapped.kind, 1059); // KIND_GIFT_WRAP
                                    // Outer pubkey is a throwaway -- not the sender
    assert_ne!(wrapped.pubkey, sender_pk);
    // Outer p-tag routes to the recipient
    let p_tag = wrapped.tags.iter().find(|t| t[0] == "p").unwrap();
    assert_eq!(p_tag[1], recipient_pk);

    let unwrapped = unwrap_gift(&wrapped, &recipient_sk).unwrap();
    assert_eq!(unwrapped.sender_pubkey, sender_pk);
    assert_eq!(unwrapped.rumor.content, content);
    assert_eq!(unwrapped.rumor.kind, 14); // KIND_RUMOR
    assert_eq!(unwrapped.seal.kind, 13); // KIND_SEAL
}

#[test]
fn e2e_gift_wrap_wrong_recipient_cannot_decrypt() {
    let (sender_sk, sender_pk) = random_keypair();
    let (_, recipient_pk) = random_keypair();
    let (wrong_sk, _) = random_keypair();

    let wrapped = gift_wrap(&sender_sk, &sender_pk, &recipient_pk, "confidential").unwrap();
    let result = unwrap_gift(&wrapped, &wrong_sk);

    assert!(result.is_err());
    assert!(matches!(result, Err(GiftWrapError::Decryption(_))));
}

#[test]
fn e2e_gift_wrap_unicode_content_preserved() {
    let (sender_sk, sender_pk) = random_keypair();
    let (recipient_sk, recipient_pk) = random_keypair();

    let content = "Nostr DM with unicode: \u{65e5}\u{672c}\u{8a9e}\u{30c6}\u{30b9}\u{30c8}";
    let wrapped = gift_wrap(&sender_sk, &sender_pk, &recipient_pk, content).unwrap();
    let unwrapped = unwrap_gift(&wrapped, &recipient_sk).unwrap();

    assert_eq!(unwrapped.rumor.content, content);
}

#[test]
fn e2e_gift_wrap_each_wrap_uses_different_throwaway_key() {
    let (sender_sk, sender_pk) = random_keypair();
    let (_, recipient_pk) = random_keypair();

    let w1 = gift_wrap(&sender_sk, &sender_pk, &recipient_pk, "msg 1").unwrap();
    let w2 = gift_wrap(&sender_sk, &sender_pk, &recipient_pk, "msg 2").unwrap();

    assert_ne!(w1.pubkey, w2.pubkey);
    assert_ne!(w1.pubkey, sender_pk);
    assert_ne!(w2.pubkey, sender_pk);
}

#[test]
fn e2e_gift_wrap_outer_event_verifies() {
    let (sender_sk, sender_pk) = random_keypair();
    let (_, recipient_pk) = random_keypair();

    let wrapped = gift_wrap(&sender_sk, &sender_pk, &recipient_pk, "sig test").unwrap();
    assert!(verify_event(&wrapped));
}

#[test]
fn e2e_gift_wrap_seal_event_verifies() {
    let (sender_sk, sender_pk) = random_keypair();
    let (recipient_sk, recipient_pk) = random_keypair();

    let wrapped = gift_wrap(&sender_sk, &sender_pk, &recipient_pk, "seal sig test").unwrap();
    let unwrapped = unwrap_gift(&wrapped, &recipient_sk).unwrap();

    assert!(verify_event(&unwrapped.seal));
}

// ============================================================================
// 4. NIP-44 direct encryption round-trip
// ============================================================================

#[test]
fn e2e_nip44_encrypt_decrypt_roundtrip() {
    let (sender_sk, _) = random_keypair();
    let (recipient_sk, recipient_pk) = random_keypair();
    let sender_pk = {
        let sk = SigningKey::from_bytes(&sender_sk).unwrap();
        hex::encode(sk.verifying_key().to_bytes())
    };
    let sender_pk_bytes = hex::decode(&sender_pk).unwrap();
    let recipient_pk_bytes = hex::decode(&recipient_pk).unwrap();

    let plaintext = "NIP-44 encrypted relay message";
    let mut sender_pk_arr = [0u8; 32];
    sender_pk_arr.copy_from_slice(&sender_pk_bytes);
    let mut recipient_pk_arr = [0u8; 32];
    recipient_pk_arr.copy_from_slice(&recipient_pk_bytes);

    let ciphertext = nip44_encrypt(&sender_sk, &recipient_pk_arr, plaintext).unwrap();
    let decrypted = nip44_decrypt(&recipient_sk, &sender_pk_arr, &ciphertext).unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn e2e_nip44_wrong_key_cannot_decrypt() {
    let (sender_sk, _) = random_keypair();
    let (_, recipient_pk) = random_keypair();
    let (wrong_sk, _) = random_keypair();
    let recipient_pk_bytes: [u8; 32] = hex::decode(&recipient_pk).unwrap().try_into().unwrap();

    let ciphertext = nip44_encrypt(&sender_sk, &recipient_pk_bytes, "secret").unwrap();

    let sender_pk = {
        let sk = SigningKey::from_bytes(&sender_sk).unwrap();
        let pk_bytes = sk.verifying_key().to_bytes();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(pk_bytes.as_slice());
        arr
    };

    let result = nip44_decrypt(&wrong_sk, &sender_pk, &ciphertext);
    assert!(result.is_err());
}

// ============================================================================
// 5. NIP-04 legacy encryption round-trip
// ============================================================================

#[test]
fn e2e_nip04_encrypt_decrypt_roundtrip() {
    let (sender_sk, _) = random_keypair();
    let (recipient_sk, recipient_pk) = random_keypair();
    let sender_pk = {
        let sk = SigningKey::from_bytes(&sender_sk).unwrap();
        hex::encode(sk.verifying_key().to_bytes())
    };

    let plaintext = "Legacy NIP-04 DM content";
    let ciphertext = nip04_encrypt(&sender_sk, &recipient_pk, plaintext).unwrap();
    let decrypted = nip04_decrypt(&recipient_sk, &sender_pk, &ciphertext).unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn e2e_nip04_shared_secret_is_symmetric() {
    let (sk_a, pk_a) = random_keypair();
    let (sk_b, pk_b) = random_keypair();

    let shared_ab = nip04_shared_secret(&sk_a, &pk_b).unwrap();
    let shared_ba = nip04_shared_secret(&sk_b, &pk_a).unwrap();

    assert_eq!(shared_ab, shared_ba);
}

// ============================================================================
// 6. NIP-19 encoding round-trips
// ============================================================================

const FIATJAF_HEX: &str = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";

#[test]
fn e2e_nip19_npub_roundtrip() {
    let encoded = encode_npub(FIATJAF_HEX).unwrap();
    assert!(encoded.starts_with("npub1"));
    let decoded = decode_npub(&encoded).unwrap();
    assert_eq!(decoded, FIATJAF_HEX);
}

#[test]
fn e2e_nip19_nsec_roundtrip() {
    let sk_hex = "0000000000000000000000000000000000000000000000000000000000000001";
    let encoded = encode_nsec(sk_hex).unwrap();
    assert!(encoded.starts_with("nsec1"));
    let decoded = decode_nsec(&encoded).unwrap();
    assert_eq!(decoded, sk_hex);
}

#[test]
fn e2e_nip19_note_roundtrip() {
    let event_id = "b3e392b11f5d4f28321cedd09303a748acfd0487aea5a7450b3481c60b6e4f87";
    let encoded = encode_note(event_id).unwrap();
    assert!(encoded.starts_with("note1"));
    let decoded = decode_note(&encoded).unwrap();
    assert_eq!(decoded, event_id);
}

#[test]
fn e2e_nip19_nevent_roundtrip() {
    let e = NEvent {
        id: "b3e392b11f5d4f28321cedd09303a748acfd0487aea5a7450b3481c60b6e4f87".to_string(),
        relays: vec![
            "wss://relay.damus.io".to_string(),
            "wss://nos.lol".to_string(),
        ],
        author: Some(FIATJAF_HEX.to_string()),
        kind: Some(1),
    };
    let encoded = encode_nevent(&e).unwrap();
    assert!(encoded.starts_with("nevent1"));
    let decoded = decode_nevent(&encoded).unwrap();
    assert_eq!(decoded.id, e.id);
    assert_eq!(decoded.author, e.author);
    assert_eq!(decoded.kind, e.kind);
    // Relay order may differ -- compare sorted
    let mut enc_relays = decoded.relays;
    let mut orig_relays = e.relays;
    enc_relays.sort();
    orig_relays.sort();
    assert_eq!(enc_relays, orig_relays);
}

#[test]
fn e2e_nip19_nprofile_roundtrip() {
    let p = NProfile {
        pubkey: FIATJAF_HEX.to_string(),
        relays: vec![
            "wss://relay.damus.io".to_string(),
            "wss://nos.lol".to_string(),
        ],
    };
    let encoded = encode_nprofile(&p).unwrap();
    assert!(encoded.starts_with("nprofile1"));
    let decoded = decode_nprofile(&encoded).unwrap();
    assert_eq!(decoded.pubkey, p.pubkey);
    let mut enc_relays = decoded.relays;
    let mut orig_relays = p.relays;
    enc_relays.sort();
    orig_relays.sort();
    assert_eq!(enc_relays, orig_relays);
}

#[test]
fn e2e_nip19_naddr_roundtrip() {
    let a = NAddr {
        identifier: "my-article".to_string(),
        pubkey: FIATJAF_HEX.to_string(),
        kind: 30023,
        relays: vec!["wss://relay.damus.io".to_string()],
    };
    let encoded = encode_naddr(&a).unwrap();
    assert!(encoded.starts_with("naddr1"));
    let decoded = decode_naddr(&encoded).unwrap();
    assert_eq!(decoded.identifier, a.identifier);
    assert_eq!(decoded.pubkey, a.pubkey);
    assert_eq!(decoded.kind, a.kind);
    assert_eq!(decoded.relays, a.relays);
}

#[test]
fn e2e_nip19_cross_type_decode_rejects_wrong_prefix() {
    let npub = encode_npub(FIATJAF_HEX).unwrap();
    assert!(decode_nsec(&npub).is_err());
    assert!(decode_note(&npub).is_err());
    assert!(decode_nevent(&npub).is_err());
    assert!(decode_nprofile(&npub).is_err());
    assert!(decode_naddr(&npub).is_err());
}

// ============================================================================
// 7. Moderation events: build -> sign -> validate round-trip
// ============================================================================

#[test]
fn e2e_moderation_ban_sign_validate() {
    let admin_pk = admin_pubkey_hex();
    let target_pk = "ff".repeat(32);
    let admin_set = admin_set_with(&admin_pk);

    let unsigned = build_ban(&admin_pk, &target_pk, "spammer", 1_700_000_000);
    assert_eq!(
        d_tag_of(&unsigned),
        Some(format!("{admin_pk}:{target_pk}").as_str())
    );

    let signed = sign_deterministic(unsigned, &admin_signing_key());
    assert_eq!(signed.kind, KIND_BAN);
    assert!(validate_moderation_event(&signed, &admin_set).is_ok());
}

#[test]
fn e2e_moderation_mute_with_expiry_sign_validate() {
    let admin_pk = admin_pubkey_hex();
    let target_pk = "ee".repeat(32);
    let admin_set = admin_set_with(&admin_pk);

    let unsigned = build_mute(
        &admin_pk,
        &target_pk,
        1_700_003_600,
        "cool down",
        1_700_000_000,
    );
    let signed = sign_deterministic(unsigned, &admin_signing_key());

    assert_eq!(signed.kind, KIND_MUTE);
    assert_eq!(mute_expires_at(&signed).unwrap(), Some(1_700_003_600));
    assert!(validate_moderation_event(&signed, &admin_set).is_ok());
}

#[test]
fn e2e_moderation_mute_indefinite_sign_validate() {
    let admin_pk = admin_pubkey_hex();
    let target_pk = "dd".repeat(32);
    let admin_set = admin_set_with(&admin_pk);

    let unsigned = build_mute(&admin_pk, &target_pk, 0, "permanent mute", 1_700_000_000);
    let signed = sign_deterministic(unsigned, &admin_signing_key());

    assert_eq!(mute_expires_at(&signed).unwrap(), None);
    assert!(validate_moderation_event(&signed, &admin_set).is_ok());
}

#[test]
fn e2e_moderation_warning_sign_validate() {
    let admin_pk = admin_pubkey_hex();
    let target_pk = "cc".repeat(32);
    let admin_set = admin_set_with(&admin_pk);

    let unsigned = build_warning(&admin_pk, &target_pk, "off topic", 1_700_000_000);
    let signed = sign_deterministic(unsigned, &admin_signing_key());

    assert_eq!(signed.kind, KIND_WARNING);
    assert!(validate_moderation_event(&signed, &admin_set).is_ok());
}

#[test]
fn e2e_moderation_report_sign_validate() {
    // Reports can be filed by any user (no admin check)
    let reporter_pk = user_pubkey_hex();
    let reported_event_id = "aa".repeat(32);
    let reported_pk = "bb".repeat(32);

    let unsigned = build_report(
        &reporter_pk,
        &reported_event_id,
        &reported_pk,
        "spam",
        1_700_000_000,
    );
    let signed = sign_deterministic(unsigned, &user_signing_key());

    assert_eq!(signed.kind, KIND_REPORT);
    // Validate with empty admin set -- reports bypass admin check
    assert!(validate_moderation_event(&signed, &HashSet::new()).is_ok());
}

#[test]
fn e2e_moderation_action_sign_validate() {
    let admin_pk = admin_pubkey_hex();
    let target_pk = "ff".repeat(32);
    let admin_set = admin_set_with(&admin_pk);

    let unsigned = build_moderation_action(
        &admin_pk,
        "action-uuid-001",
        "ban",
        Some(&target_pk),
        1_700_000_000,
        "banned spammer from relay",
    );
    let signed = sign_deterministic(unsigned, &admin_signing_key());

    assert_eq!(signed.kind, KIND_MODERATION_ACTION);
    assert!(validate_moderation_event(&signed, &admin_set).is_ok());
}

#[test]
fn e2e_moderation_unban_sign_validate() {
    let admin_pk = admin_pubkey_hex();
    let target_pk = "ff".repeat(32);
    let admin_set = admin_set_with(&admin_pk);

    let unsigned = build_unban(&admin_pk, &target_pk, "pardoned", 1_700_000_000);
    let signed = sign_deterministic(unsigned, &admin_signing_key());

    assert_eq!(signed.kind, KIND_UNBAN);
    assert!(validate_moderation_event(&signed, &admin_set).is_ok());
}

#[test]
fn e2e_moderation_unmute_sign_validate() {
    let admin_pk = admin_pubkey_hex();
    let target_pk = "ff".repeat(32);
    let admin_set = admin_set_with(&admin_pk);

    let unsigned = build_unmute(&admin_pk, &target_pk, "cooldown over", 1_700_000_000);
    let signed = sign_deterministic(unsigned, &admin_signing_key());

    assert_eq!(signed.kind, KIND_UNMUTE);
    assert!(validate_moderation_event(&signed, &admin_set).is_ok());
}

#[test]
fn e2e_moderation_non_admin_cannot_ban() {
    let admin_pk = admin_pubkey_hex();
    let target_pk = "ff".repeat(32);

    let unsigned = build_ban(&admin_pk, &target_pk, "spam", 1_700_000_000);
    let signed = sign_deterministic(unsigned, &admin_signing_key());

    // Validate with an empty admin set -- should reject
    let err = validate_moderation_event(&signed, &HashSet::new()).unwrap_err();
    assert!(matches!(err, ModerationEventError::NotAdmin { .. }));
}

#[test]
fn e2e_moderation_unknown_kind_rejected() {
    let admin_pk = admin_pubkey_hex();
    let admin_set = admin_set_with(&admin_pk);

    let unsigned = UnsignedEvent {
        pubkey: admin_pk,
        created_at: 1_700_000_000,
        kind: 1, // not a moderation kind
        tags: vec![vec!["d".to_string(), "x".to_string()]],
        content: String::new(),
    };
    let signed = sign_deterministic(unsigned, &admin_signing_key());

    assert_eq!(
        validate_moderation_event(&signed, &admin_set),
        Err(ModerationEventError::UnknownKind(1)),
    );
}

// ============================================================================
// 8. Calendar events (NIP-52): create -> verify round-trip
// ============================================================================

#[test]
fn e2e_calendar_event_basic() {
    let sk = user_sk_bytes();
    let event =
        create_calendar_event(&sk, "Nostr Meetup", 1_700_000_000, None, None, None, None).unwrap();

    assert_eq!(event.kind, 31923);
    assert!(verify_event(&event));

    let tag_names: Vec<&str> = event.tags.iter().map(|t| t[0].as_str()).collect();
    assert!(tag_names.contains(&"d"));
    assert!(tag_names.contains(&"title"));
    assert!(tag_names.contains(&"start"));
    assert!(tag_names.contains(&"t"));
}

#[test]
fn e2e_calendar_event_with_all_options() {
    let sk = user_sk_bytes();
    let event = create_calendar_event(
        &sk,
        "Workshop",
        1_700_000_000,
        Some(1_700_003_600),
        Some("London"),
        Some("A great workshop"),
        Some(50),
    )
    .unwrap();

    assert_eq!(event.kind, 31923);
    assert_eq!(event.content, "A great workshop");
    assert!(verify_event(&event));

    let end_tag = event.tags.iter().find(|t| t[0] == "end").unwrap();
    assert_eq!(end_tag[1], "1700003600");

    let loc_tag = event.tags.iter().find(|t| t[0] == "location").unwrap();
    assert_eq!(loc_tag[1], "London");

    let max_tag = event.tags.iter().find(|t| t[0] == "max_attendees").unwrap();
    assert_eq!(max_tag[1], "50");
}

#[test]
fn e2e_calendar_event_validation_rejects_empty_title() {
    let sk = user_sk_bytes();
    let result = create_calendar_event(&sk, "", 1_700_000_000, None, None, None, None);
    assert!(matches!(result, Err(CalendarError::EmptyTitle)));
}

#[test]
fn e2e_calendar_event_validation_rejects_end_before_start() {
    let sk = user_sk_bytes();
    let result = create_calendar_event(
        &sk,
        "Title",
        1_700_000_000,
        Some(1_699_999_999),
        None,
        None,
        None,
    );
    assert!(matches!(result, Err(CalendarError::EndBeforeStart { .. })));
}

#[test]
fn e2e_calendar_rsvp_accept() {
    let sk = user_sk_bytes();
    let event_id = "aa".repeat(32);
    let rsvp = create_rsvp(&sk, &event_id, RsvpStatus::Accept).unwrap();

    assert_eq!(rsvp.kind, 31925);
    assert!(verify_event(&rsvp));

    let status_tag = rsvp.tags.iter().find(|t| t[0] == "status").unwrap();
    assert_eq!(status_tag[1], "accepted");
}

#[test]
fn e2e_calendar_rsvp_decline() {
    let sk = user_sk_bytes();
    let event_id = "bb".repeat(32);
    let rsvp = create_rsvp(&sk, &event_id, RsvpStatus::Decline).unwrap();

    assert!(verify_event(&rsvp));
    let status_tag = rsvp.tags.iter().find(|t| t[0] == "status").unwrap();
    assert_eq!(status_tag[1], "declined");
}

#[test]
fn e2e_calendar_rsvp_tentative() {
    let sk = user_sk_bytes();
    let event_id = "cc".repeat(32);
    let rsvp = create_rsvp(&sk, &event_id, RsvpStatus::Tentative).unwrap();

    assert!(verify_event(&rsvp));
    let status_tag = rsvp.tags.iter().find(|t| t[0] == "status").unwrap();
    assert_eq!(status_tag[1], "tentative");
}

#[test]
fn e2e_calendar_rsvp_invalid_event_id_rejected() {
    let sk = user_sk_bytes();
    let result = create_rsvp(&sk, "not-valid-hex", RsvpStatus::Accept);
    assert!(matches!(result, Err(CalendarError::InvalidEventId(_))));
}

// ============================================================================
// 10. Cross-worker E2E: Full auth -> relay -> pod pipeline simulation
// ============================================================================

/// Simulates the full request flow:
/// 1. Client generates a keypair
/// 2. Client creates a NIP-98 token for the relay endpoint
/// 3. Relay verifies the NIP-98 token (auth-worker check)
/// 4. Client creates a Nostr event and signs it
/// 5. Relay verifies the event signature
/// 6. Client creates a NIP-98 token for the pod endpoint
/// 7. Pod verifies the NIP-98 token
/// 8. The same pubkey across all steps is consistent
#[test]
fn e2e_full_auth_relay_pod_flow() {
    // Step 1: Generate a fresh keypair (simulating client bootstrap)
    let kp = generate_keypair().unwrap();
    let sk_bytes = *kp.secret.as_bytes();
    let pubkey_hex = kp.public.to_hex();
    let signing_key = SigningKey::from_bytes(&sk_bytes).unwrap();

    // Step 2: Client authenticates to relay via NIP-98
    let relay_url = "https://relay.forum.example.com/api/events";
    let relay_token = create_nip98_token(&sk_bytes, relay_url, "POST", None).unwrap();
    let relay_header = nip98_authorization_header(&relay_token);

    // Step 3: Relay (auth-worker) verifies the NIP-98 token
    let relay_verified = verify_nip98_token(&relay_header, relay_url, "POST", None).unwrap();
    assert_eq!(relay_verified.pubkey, pubkey_hex);

    // Step 4: Client creates and signs a kind-1 event for relay publication
    let unsigned_event = UnsignedEvent {
        pubkey: pubkey_hex.clone(),
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        kind: 1,
        tags: vec![vec!["t".to_string(), "test".to_string()]],
        content: "Cross-worker E2E test message".to_string(),
    };
    let signed_event = sign_event(unsigned_event, &signing_key).unwrap();

    // Step 5: Relay verifies the event signature
    assert!(verify_event(&signed_event));
    verify_event_strict(&signed_event).unwrap();
    assert_eq!(signed_event.pubkey, pubkey_hex);

    // Step 6: Client authenticates to pod-worker via NIP-98 with a body
    let pod_url = "https://pod.forum.example.com/api/upload";
    let pod_body = b"file-content-bytes-here";
    let pod_token = create_nip98_token(&sk_bytes, pod_url, "POST", Some(pod_body)).unwrap();
    let pod_header = nip98_authorization_header(&pod_token);

    // Step 7: Pod-worker verifies the NIP-98 token
    let pod_verified = verify_nip98_token(&pod_header, pod_url, "POST", Some(pod_body)).unwrap();
    assert_eq!(pod_verified.pubkey, pubkey_hex);
    assert!(pod_verified.payload_hash.is_some());

    // Step 8: Pubkey consistency across all operations
    assert_eq!(relay_verified.pubkey, pod_verified.pubkey);
    assert_eq!(relay_verified.pubkey, signed_event.pubkey);
}

/// Simulates admin moderation flow across workers:
/// 1. Admin creates NIP-98 token for auth-worker
/// 2. Auth-worker verifies admin identity
/// 3. Admin builds a ban event, signs it
/// 4. Relay-worker validates the moderation event
/// 5. Admin builds an unban event to reverse the action
/// 6. Both events are verified for signature integrity
#[test]
fn e2e_admin_moderation_flow() {
    let admin_sk = admin_sk_bytes();
    let admin_pk = admin_pubkey_hex();
    let target_pk = "ff".repeat(32);
    let admin_set = admin_set_with(&admin_pk);
    let admin_signer = admin_signing_key();

    // Step 1-2: Admin authenticates via NIP-98
    let auth_url = "https://auth.forum.example.com/api/admin/ban";
    let auth_token = create_nip98_token(&admin_sk, auth_url, "POST", None).unwrap();
    let auth_header = nip98_authorization_header(&auth_token);
    let auth_verified = verify_nip98_token(&auth_header, auth_url, "POST", None).unwrap();
    assert_eq!(auth_verified.pubkey, admin_pk);

    // Step 3: Admin builds and signs a ban event
    let ban_unsigned = build_ban(&admin_pk, &target_pk, "spam", 1_700_000_000);
    let ban_signed = sign_deterministic(ban_unsigned, &admin_signer);

    // Step 4: Relay-worker validates the moderation event
    assert!(verify_event(&ban_signed));
    assert!(validate_moderation_event(&ban_signed, &admin_set).is_ok());
    assert_eq!(ban_signed.kind, KIND_BAN);

    // Step 5: Admin unbans the user
    let unban_unsigned = build_unban(&admin_pk, &target_pk, "pardoned", 1_700_001_000);
    let unban_signed = sign_deterministic(unban_unsigned, &admin_signer);

    // Step 6: Both events verify
    assert!(verify_event(&unban_signed));
    assert!(validate_moderation_event(&unban_signed, &admin_set).is_ok());
    assert_eq!(unban_signed.kind, KIND_UNBAN);

    // Pubkey consistency: auth token signer == moderation event signer
    assert_eq!(auth_verified.pubkey, ban_signed.pubkey);
    assert_eq!(auth_verified.pubkey, unban_signed.pubkey);
}

/// Simulates the DM relay routing flow:
/// 1. Sender creates a gift-wrapped DM
/// 2. Relay sees the outer p-tag for routing (no sender identity leak)
/// 3. Recipient unwraps and reads the message
/// 4. Sender identity is verified inside the sealed layer
#[test]
fn e2e_dm_relay_routing_flow() {
    let (sender_sk, sender_pk) = random_keypair();
    let (recipient_sk, recipient_pk) = random_keypair();

    // Step 1: Sender creates a gift-wrapped DM
    let message = "Hey, check out the new relay!";
    let wrapped = gift_wrap(&sender_sk, &sender_pk, &recipient_pk, message).unwrap();

    // Step 2: Relay inspects the outer event for routing
    assert_eq!(wrapped.kind, 1059);
    assert!(verify_event(&wrapped));
    // Relay can only see the p-tag for routing -- not the sender
    let routing_pubkey = wrapped
        .tags
        .iter()
        .find(|t| t[0] == "p")
        .map(|t| &t[1])
        .unwrap();
    assert_eq!(routing_pubkey, &recipient_pk);
    // The outer pubkey is a throwaway -- reveals nothing about the sender
    assert_ne!(wrapped.pubkey, sender_pk);

    // Step 3: Recipient unwraps the DM
    let unwrapped = unwrap_gift(&wrapped, &recipient_sk).unwrap();
    assert_eq!(unwrapped.rumor.content, message);

    // Step 4: Recipient verifies sender identity from the sealed layer
    assert_eq!(unwrapped.sender_pubkey, sender_pk);
    assert!(verify_event(&unwrapped.seal));
}

/// Simulates a search-worker authentication flow:
/// 1. Client creates NIP-98 token for search endpoint
/// 2. Search-worker verifies the token
/// 3. Client's pubkey is extracted for quota/rate-limit checks
#[test]
fn e2e_search_worker_auth_flow() {
    let kp = generate_keypair().unwrap();
    let sk_bytes = *kp.secret.as_bytes();
    let pubkey_hex = kp.public.to_hex();

    let search_url = "https://search.forum.example.com/api/search?q=nostr";
    let token = create_nip98_token(&sk_bytes, search_url, "GET", None).unwrap();
    let header = nip98_authorization_header(&token);

    let verified = verify_nip98_token(&header, search_url, "GET", None).unwrap();
    assert_eq!(verified.pubkey, pubkey_hex);
    assert_eq!(verified.url, search_url);
    assert_eq!(verified.method, "GET");
}

/// NIP-98 tokens created at the same timestamp for different endpoints
/// produce different event IDs (no cross-endpoint replay).
#[test]
fn e2e_nip98_different_endpoints_different_event_ids() {
    let sk = user_sk_bytes();
    let ts = 1_700_000_000u64;

    let t1 = create_token_at(&sk, "https://relay.example.com/api", "GET", None, ts).unwrap();
    let t2 = create_token_at(&sk, "https://pod.example.com/api", "GET", None, ts).unwrap();

    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    let e1: NostrEvent = serde_json::from_slice(&BASE64.decode(&t1).unwrap()).unwrap();
    let e2: NostrEvent = serde_json::from_slice(&BASE64.decode(&t2).unwrap()).unwrap();

    // Same pubkey, same timestamp, but different URLs -> different event IDs
    assert_eq!(e1.pubkey, e2.pubkey);
    assert_eq!(e1.created_at, e2.created_at);
    assert_ne!(e1.id, e2.id);
}

/// Verify that NIP-98 tokens created with different methods produce different event IDs.
#[test]
fn e2e_nip98_different_methods_different_event_ids() {
    let sk = user_sk_bytes();
    let url = "https://relay.example.com/api";
    let ts = 1_700_000_000u64;

    let t1 = create_token_at(&sk, url, "GET", None, ts).unwrap();
    let t2 = create_token_at(&sk, url, "POST", None, ts).unwrap();

    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    let e1: NostrEvent = serde_json::from_slice(&BASE64.decode(&t1).unwrap()).unwrap();
    let e2: NostrEvent = serde_json::from_slice(&BASE64.decode(&t2).unwrap()).unwrap();

    assert_ne!(e1.id, e2.id);
}
