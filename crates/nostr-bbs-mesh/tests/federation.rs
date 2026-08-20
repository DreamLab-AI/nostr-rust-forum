//! End-to-end federation tests (PRD-010 conformance surface, ADR-075 §D15).
//!
//! Covers the full crypto stack — build → sign → serialise → wrap → publish →
//! receive → unwrap → validate → verify — plus tamper rejection, NIP-26
//! delegation, LDN/AS2 mapping, transport loopback over an in-memory relay, and
//! parsing the shipped `forum.example.toml` `[mesh]` block.

use serde_json::json;

use nostr_bbs_core::gift_wrap::gift_wrap;
use nostr_bbs_core::keys::{generate_keypair, Keypair};

use nostr_bbs_mesh::config::{MeshConfig, MeshMode};
use nostr_bbs_mesh::delegation::DelegationToken;
use nostr_bbs_mesh::envelope::{Envelope, EnvelopeKind};
use nostr_bbs_mesh::mock::MockRelay;
use nostr_bbs_mesh::transport::{decode_incoming_wrap, MeshError, ReceiveOptions, RelayTransport};

// ── Minimal dependency-free async executor ───────────────────────────────────
// The mock socket never truly suspends (all ops resolve immediately), so a
// poll-until-ready pump is sufficient and keeps the crate free of a tokio /
// futures dev-dependency.
fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    fn noop(_: *const ()) {}
    fn clone(_: *const ()) -> RawWaker {
        RawWaker::new(std::ptr::null(), &VTABLE)
    }
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
    let waker = unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) };
    let mut cx = Context::from_waker(&waker);
    let mut fut = Box::pin(fut);
    loop {
        if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
            return v;
        }
    }
}

fn kp() -> Keypair {
    generate_keypair().unwrap()
}

fn sk(k: &Keypair) -> [u8; 32] {
    *k.secret.as_bytes()
}

// ── 1. Envelope round-trip through the full gift-wrap stack ───────────────────

#[test]
fn envelope_round_trip_build_sign_serialize_parse_verify() {
    let alice = kp();
    let bob = kp();
    let env = Envelope::chat(&alice.public.to_hex(), &bob.public.to_hex(), "hello mesh");

    // build → JCS → gift-wrap (sign) → … → unwrap → parse → validate → verify
    let wrap = gift_wrap(
        &sk(&alice),
        &alice.public.to_hex(),
        &bob.public.to_hex(),
        &env.to_jcs_string(),
    )
    .unwrap();

    let received = decode_incoming_wrap(&wrap, &sk(&bob), &ReceiveOptions::default()).unwrap();
    assert_eq!(received.envelope, env);
    assert_eq!(received.seal_pubkey, alice.public.to_hex());
    assert_eq!(received.event_id, wrap.id);
    assert_eq!(received.envelope.body, json!("hello mesh"));
}

// ── 2a. Tamper rejection — mutated ciphertext fails to unwrap ─────────────────

#[test]
fn tampered_wrap_content_is_rejected() {
    let alice = kp();
    let bob = kp();
    let env = Envelope::chat(&alice.public.to_hex(), &bob.public.to_hex(), "secret");
    let mut wrap = gift_wrap(
        &sk(&alice),
        &alice.public.to_hex(),
        &bob.public.to_hex(),
        &env.to_jcs_string(),
    )
    .unwrap();

    // Flip a character in the encrypted payload.
    let mut chars: Vec<char> = wrap.content.chars().collect();
    let last = chars.len() - 1;
    chars[last] = if chars[last] == 'A' { 'B' } else { 'A' };
    wrap.content = chars.into_iter().collect();

    let err = decode_incoming_wrap(&wrap, &sk(&bob), &ReceiveOptions::default()).unwrap_err();
    assert!(matches!(err, MeshError::GiftWrap(_)), "got {err:?}");
}

// ── 2b. Attribution mismatch — envelope `from` lies about the author ──────────

#[test]
fn forged_from_without_delegation_is_rejected() {
    let alice = kp(); // actually signs
    let carol = kp(); // claimed author
    let bob = kp(); // recipient

    // Envelope claims Carol authored it, but Alice signs the seal and there is
    // no delegation token → attribution mismatch.
    let env = Envelope::chat(
        &carol.public.to_hex(),
        &bob.public.to_hex(),
        "not from carol",
    );
    let wrap = gift_wrap(
        &sk(&alice),
        &alice.public.to_hex(),
        &bob.public.to_hex(),
        &env.to_jcs_string(),
    )
    .unwrap();

    let err = decode_incoming_wrap(&wrap, &sk(&bob), &ReceiveOptions::default()).unwrap_err();
    assert!(matches!(err, MeshError::AttributionMismatch), "got {err:?}");
}

// ── 3. NIP-26 delegation: agent A acts for user U ─────────────────────────────

fn signed_delegation(
    delegator: &Keypair,
    delegatee_hex: &str,
    conditions: &str,
) -> DelegationToken {
    let token = DelegationToken::new(delegator.public.to_hex(), conditions, "00".repeat(64));
    let msg = token.signing_message(delegatee_hex);
    let sig = delegator.secret.sign(&msg).unwrap();
    DelegationToken::new(delegator.public.to_hex(), conditions, sig.to_hex())
}

#[test]
fn valid_delegation_accepts_reattributed_envelope() {
    let user = kp(); // delegator U
    let agent = kp(); // delegatee A (signs the seal)
    let peer = kp(); // recipient B

    let token = signed_delegation(
        &user,
        &agent.public.to_hex(),
        "kind=14&created_at<9999999999",
    );
    let mut env = Envelope::new(
        &user.public.to_hex(),
        &peer.public.to_hex(),
        EnvelopeKind::ToolInvoke,
        json!({ "tool": "urn:agentbox:skill:summarise", "args": { "thread": "abc" } }),
    );
    env.delegation = Some(token);

    // The seal is signed by the AGENT, but `from` is the USER.
    let wrap = gift_wrap(
        &sk(&agent),
        &agent.public.to_hex(),
        &peer.public.to_hex(),
        &env.to_jcs_string(),
    )
    .unwrap();

    let received = decode_incoming_wrap(&wrap, &sk(&peer), &ReceiveOptions::default()).unwrap();
    assert_eq!(
        received.envelope.from,
        format!("did:nostr:{}", user.public.to_hex())
    );
    assert_eq!(received.seal_pubkey, agent.public.to_hex()); // wire signed by agent
}

#[test]
fn delegation_for_wrong_delegatee_is_rejected() {
    let user = kp();
    let agent = kp();
    let impostor = kp(); // delegation was issued for this key, not the agent
    let peer = kp();

    // Token authorises `impostor`, but the seal is signed by `agent`.
    let token = signed_delegation(
        &user,
        &impostor.public.to_hex(),
        "kind=14&created_at<9999999999",
    );
    let mut env = Envelope::new(
        &user.public.to_hex(),
        &peer.public.to_hex(),
        EnvelopeKind::ToolInvoke,
        json!({ "tool": "urn:agentbox:skill:x", "args": {} }),
    );
    env.delegation = Some(token);

    let wrap = gift_wrap(
        &sk(&agent),
        &agent.public.to_hex(),
        &peer.public.to_hex(),
        &env.to_jcs_string(),
    )
    .unwrap();

    let err = decode_incoming_wrap(&wrap, &sk(&peer), &ReceiveOptions::default()).unwrap_err();
    assert!(matches!(err, MeshError::Delegation(_)), "got {err:?}");
}

// ── 4. LDN / AS2 mapping round-trip (ADR-075 §D10) ────────────────────────────

#[test]
fn ldn_as2_mapping_preserves_envelope() {
    let v = kp();
    let u = kp();
    let env = Envelope::new(
        &v.public.to_hex(),
        &u.public.to_hex(),
        EnvelopeKind::KnowledgeLink,
        json!({
            "subject_urn": "urn:visionclaw:bead:abc:0123456789ab",
            "claim": "indexed",
            "context": { "labels": ["KGNode", "Bead"] }
        }),
    );

    // Use a real signed event as the "original" for x:nostrEvent.
    let wrap = gift_wrap(
        &sk(&v),
        &v.public.to_hex(),
        &u.public.to_hex(),
        &env.to_jcs_string(),
    )
    .unwrap();

    let as2 = env.to_ldn_as2(&wrap);
    assert_eq!(as2["type"], "Announce");
    assert_eq!(as2["actor"], format!("did:nostr:{}", v.public.to_hex()));
    assert_eq!(as2["target"], format!("did:nostr:{}", u.public.to_hex()));
    assert_eq!(as2["id"], format!("urn:nostr:event:{}", wrap.id));
    assert_eq!(as2["@context"][0], "https://www.w3.org/ns/activitystreams");

    // The full-fidelity envelope survives under x:envelope.
    let back: Envelope = serde_json::from_value(as2["x:envelope"].clone()).unwrap();
    assert_eq!(back, env);
    // And the signed event survives for verifier re-runs.
    assert_eq!(as2["x:nostrEvent"]["id"], wrap.id);
}

// ── 5. Transport loopback over the in-memory mock relay ───────────────────────

#[test]
fn transport_loopback_send_and_receive() {
    let relay = MockRelay::new();
    let alice = kp();
    let bob = kp();

    let bob_t = RelayTransport::new(relay.connect(), "wss://mock");
    let alice_t = RelayTransport::new(relay.connect(), "wss://mock");

    block_on(async {
        // Bob subscribes to his gift-wrap inbox.
        bob_t
            .subscribe_inbox("inbox", &bob.public.to_hex())
            .await
            .unwrap();

        // Alice sends an IS-Envelope to Bob.
        let env = Envelope::chat(&alice.public.to_hex(), &bob.public.to_hex(), "hi bob");
        let sent_id = alice_t.send_envelope(&sk(&alice), &env).await.unwrap();

        // Bob receives + verifies it.
        let received = bob_t
            .recv_envelope(&sk(&bob), &ReceiveOptions::default())
            .await
            .unwrap()
            .expect("an envelope should arrive");

        assert_eq!(received.event_id, sent_id);
        assert_eq!(received.seal_pubkey, alice.public.to_hex());
        assert_eq!(received.envelope.body, json!("hi bob"));
        assert_eq!(
            received.envelope.from,
            format!("did:nostr:{}", alice.public.to_hex())
        );
    });

    // The relay stored exactly one event (the gift wrap).
    assert_eq!(relay.stored_event_count(), 1);
}

#[test]
fn transport_loopback_delivers_only_to_addressed_recipient() {
    let relay = MockRelay::new();
    let alice = kp();
    let bob = kp();
    let eve = kp(); // subscribes but is not the recipient

    let bob_t = RelayTransport::new(relay.connect(), "wss://mock");
    let eve_t = RelayTransport::new(relay.connect(), "wss://mock");
    let alice_t = RelayTransport::new(relay.connect(), "wss://mock");

    block_on(async {
        eve_t
            .subscribe_inbox("e", &eve.public.to_hex())
            .await
            .unwrap();
        bob_t
            .subscribe_inbox("b", &bob.public.to_hex())
            .await
            .unwrap();

        let env = Envelope::chat(&alice.public.to_hex(), &bob.public.to_hex(), "for bob only");
        alice_t.send_envelope(&sk(&alice), &env).await.unwrap();

        // Eve's inbox filter (#p == eve) does not match the wrap (#p == bob).
        let eve_rx = eve_t
            .recv_envelope(&sk(&eve), &ReceiveOptions::default())
            .await
            .unwrap();
        assert!(eve_rx.is_none(), "Eve must not receive Bob's mail");

        let bob_rx = bob_t
            .recv_envelope(&sk(&bob), &ReceiveOptions::default())
            .await
            .unwrap();
        assert!(bob_rx.is_some(), "Bob must receive his mail");
    });
}

// ── 6. Config: the three topologies + the shipped example ─────────────────────

#[test]
fn all_three_topologies_resolve() {
    let standalone = MeshConfig::from_toml_str(
        r#"[mesh]
mode = "standalone"
"#,
    )
    .unwrap();
    assert_eq!(standalone.resolve().unwrap(), MeshMode::Standalone);

    let federated = MeshConfig::from_toml_str(
        r#"[mesh]
mode = "federated"
peer_relays = ["wss://a.example", "wss://b.example"]
"#,
    )
    .unwrap();
    assert!(matches!(
        federated.resolve().unwrap(),
        MeshMode::Federated { .. }
    ));

    let client = MeshConfig::from_toml_str(
        r#"[mesh]
mode = "client"
client_relay = "wss://hub.example"
"#,
    )
    .unwrap();
    assert_eq!(
        client.resolve().unwrap(),
        MeshMode::Client {
            relay: "wss://hub.example".into()
        }
    );
}

#[test]
fn shipped_forum_example_mesh_block_parses() {
    let doc = include_str!("../../../forum.example.toml");
    let cfg = MeshConfig::from_toml_str(doc).unwrap();
    // The example ships standalone-by-default with the full F12 field set.
    assert_eq!(cfg.resolve().unwrap(), MeshMode::Standalone);
    assert!(cfg.delegation_required);
    assert!(cfg.is_federated_kind(1059));
    assert!(cfg.is_federated_kind(30033));
    assert!(cfg.is_federated_kind(30916));
}
