//! Benchmarks for event parsing (JSON deserialization) and event ID computation.

use criterion::{criterion_group, criterion_main, Criterion};
use k256::schnorr::SigningKey;
use nostr_core::event::{sign_event, NostrEvent, UnsignedEvent};

/// Generate N signed events as JSON strings for deserialization benchmarks.
fn generate_event_jsons(n: usize) -> Vec<String> {
    let sk = SigningKey::from_bytes(&[0x01u8; 32]).unwrap();
    let pubkey = hex::encode(sk.verifying_key().to_bytes());

    (0..n)
        .map(|i| {
            let unsigned = UnsignedEvent {
                pubkey: pubkey.clone(),
                created_at: 1_700_000_000 + i as u64,
                kind: 1,
                tags: vec![
                    vec!["e".to_string(), "a".repeat(64)],
                    vec!["p".to_string(), "b".repeat(64)],
                    vec!["t".to_string(), format!("tag{i}")],
                ],
                content: format!("Benchmark event #{i} with some content to make it realistic"),
            };
            let signed = sign_event(unsigned, &sk).unwrap();
            serde_json::to_string(&signed).unwrap()
        })
        .collect()
}

fn bench_event_deserialize_1k(c: &mut Criterion) {
    let jsons = generate_event_jsons(1_000);
    c.bench_function("event_deserialize_1k", |b| {
        b.iter(|| {
            for json in &jsons {
                let _: NostrEvent = serde_json::from_str(json).unwrap();
            }
        });
    });
}

fn bench_event_id_computation(c: &mut Criterion) {
    let sk = SigningKey::from_bytes(&[0x01u8; 32]).unwrap();
    let pubkey = hex::encode(sk.verifying_key().to_bytes());

    let unsigned = UnsignedEvent {
        pubkey,
        created_at: 1_700_000_000,
        kind: 1,
        tags: vec![
            vec!["e".to_string(), "a".repeat(64)],
            vec!["p".to_string(), "b".repeat(64)],
        ],
        content: "Hello, benchmark!".to_string(),
    };

    c.bench_function("event_id_compute", |b| {
        b.iter(|| nostr_core::event::compute_event_id(&unsigned));
    });
}

fn bench_event_sign(c: &mut Criterion) {
    let sk = SigningKey::from_bytes(&[0x01u8; 32]).unwrap();
    let pubkey = hex::encode(sk.verifying_key().to_bytes());

    c.bench_function("event_sign", |b| {
        b.iter(|| {
            let unsigned = UnsignedEvent {
                pubkey: pubkey.clone(),
                created_at: 1_700_000_000,
                kind: 1,
                tags: vec![],
                content: "bench".to_string(),
            };
            sign_event(unsigned, &sk)
        });
    });
}

fn bench_event_verify(c: &mut Criterion) {
    let sk = SigningKey::from_bytes(&[0x01u8; 32]).unwrap();
    let pubkey = hex::encode(sk.verifying_key().to_bytes());

    let unsigned = UnsignedEvent {
        pubkey,
        created_at: 1_700_000_000,
        kind: 1,
        tags: vec![],
        content: "bench".to_string(),
    };
    let signed = sign_event(unsigned, &sk).unwrap();

    c.bench_function("event_verify", |b| {
        b.iter(|| nostr_core::event::verify_event(&signed));
    });
}

criterion_group!(
    benches,
    bench_event_deserialize_1k,
    bench_event_id_computation,
    bench_event_sign,
    bench_event_verify,
);
criterion_main!(benches);
