//! Benchmarks for NIP-44 v2 encrypt/decrypt at various payload sizes.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use k256::{elliptic_curve::sec1::ToEncodedPoint, SecretKey};
use nostr_core::nip44;

fn random_keypair() -> ([u8; 32], [u8; 32]) {
    let mut sk_bytes = [0u8; 32];
    getrandom::getrandom(&mut sk_bytes).unwrap();
    sk_bytes[0] &= 0x7F;
    if sk_bytes == [0u8; 32] {
        sk_bytes[31] = 1;
    }
    let sk = SecretKey::from_bytes((&sk_bytes).into()).unwrap();
    let pk = sk.public_key();
    let pk_point = pk.to_encoded_point(true);
    let pk_bytes: [u8; 32] = pk_point.as_bytes()[1..33].try_into().unwrap();
    let sk_bytes: [u8; 32] = sk.to_bytes().as_slice().try_into().unwrap();
    (sk_bytes, pk_bytes)
}

fn bench_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("nip44_encrypt");
    let (sender_sk, _sender_pk) = random_keypair();
    let (_recipient_sk, recipient_pk) = random_keypair();

    for size in [1_024, 10_240, 60_000] {
        let plaintext = "A".repeat(size);
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{size}B")),
            &plaintext,
            |b, pt| {
                b.iter(|| nip44::encrypt(&sender_sk, &recipient_pk, pt).unwrap());
            },
        );
    }
    group.finish();
}

fn bench_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("nip44_decrypt");
    let (sender_sk, sender_pk) = random_keypair();
    let (recipient_sk, recipient_pk) = random_keypair();

    for size in [1_024, 10_240, 60_000] {
        let plaintext = "A".repeat(size);
        let ciphertext = nip44::encrypt(&sender_sk, &recipient_pk, &plaintext).unwrap();
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{size}B")),
            &ciphertext,
            |b, ct| {
                b.iter(|| nip44::decrypt(&recipient_sk, &sender_pk, ct).unwrap());
            },
        );
    }
    group.finish();
}

fn bench_conversation_key(c: &mut Criterion) {
    let (sk, _) = random_keypair();
    let (_, pk) = random_keypair();
    c.bench_function("nip44_conversation_key", |b| {
        b.iter(|| nip44::conversation_key(&sk, &pk).unwrap());
    });
}

criterion_group!(
    benches,
    bench_encrypt,
    bench_decrypt,
    bench_conversation_key
);
criterion_main!(benches);
