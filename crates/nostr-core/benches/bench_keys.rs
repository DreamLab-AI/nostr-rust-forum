//! Benchmarks for key generation, HKDF derivation, and Schnorr sign/verify.

use criterion::{criterion_group, criterion_main, Criterion};
use nostr_core::keys;
use sha2::{Digest, Sha256};

fn bench_generate_keypair(c: &mut Criterion) {
    c.bench_function("keys_generate_keypair", |b| {
        b.iter(|| keys::generate_keypair().unwrap());
    });
}

fn bench_derive_from_prf(c: &mut Criterion) {
    let prf_output = [0xABu8; 32];
    c.bench_function("keys_derive_from_prf", |b| {
        b.iter(|| keys::derive_from_prf(&prf_output).unwrap());
    });
}

fn bench_schnorr_sign(c: &mut Criterion) {
    let kp = keys::generate_keypair().unwrap();
    let msg: [u8; 32] = Sha256::digest(b"benchmark message").into();
    c.bench_function("keys_schnorr_sign", |b| {
        b.iter(|| kp.secret.sign(&msg).unwrap());
    });
}

fn bench_schnorr_verify(c: &mut Criterion) {
    let kp = keys::generate_keypair().unwrap();
    let msg: [u8; 32] = Sha256::digest(b"benchmark message").into();
    let sig = kp.secret.sign(&msg).unwrap();
    c.bench_function("keys_schnorr_verify", |b| {
        b.iter(|| kp.public.verify(&msg, &sig).unwrap());
    });
}

fn bench_pubkey_hex(c: &mut Criterion) {
    let kp = keys::generate_keypair().unwrap();
    c.bench_function("keys_pubkey_hex", |b| {
        b.iter(|| keys::pubkey_hex(kp.secret.as_bytes()).unwrap());
    });
}

criterion_group!(
    benches,
    bench_generate_keypair,
    bench_derive_from_prf,
    bench_schnorr_sign,
    bench_schnorr_verify,
    bench_pubkey_hex,
);
criterion_main!(benches);
