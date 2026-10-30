//! Benchmarks for key generation, HKDF derivation, and Schnorr sign/verify.
//!
//! Two tiers per signing-path operation:
//! - `keys_*` — the public API as callers see it. `SecretKey::sign`,
//!   `PublicKey::verify`, and `pubkey_hex` each reconstruct the k256
//!   Signing/VerifyingKey from bytes per call (EC scalar mult, ~219 µs), so
//!   these medians are dominated by that shared reconstruction cost
//!   (dream-cycle 2026-08-16 finding).
//! - `keys_*_hoisted` — the raw operation with the k256 key prebuilt. The
//!   delta between tiers IS the reconstruction overhead; perf claims about
//!   the crypto itself must cite the hoisted tier.

use criterion::{criterion_group, criterion_main, Criterion};
use k256::schnorr::signature::hazmat::PrehashVerifier;
use nostr_bbs_core::keys;
use sha2::{Digest, Sha256};

fn bench_generate_keypair(c: &mut Criterion) {
    c.bench_function("keys_generate_keypair", |b| {
        b.iter(|| keys::generate_keypair().unwrap());
    });
}

fn bench_derive_from_prf(c: &mut Criterion) {
    let prf_output = [0xABu8; 32];
    let salt = [0x0bu8; 32];
    c.bench_function("keys_derive_from_prf", |b| {
        b.iter(|| keys::derive_from_prf(&prf_output, &salt).unwrap());
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

fn bench_schnorr_sign_hoisted(c: &mut Criterion) {
    let kp = keys::generate_keypair().unwrap();
    let sk = keys::signing_key_from_bytes(kp.secret.as_bytes()).unwrap();
    let msg: [u8; 32] = Sha256::digest(b"benchmark message").into();
    c.bench_function("keys_schnorr_sign_hoisted", |b| {
        b.iter(|| sk.sign_raw(&msg, &[0u8; 32]).unwrap());
    });
}

fn bench_schnorr_verify_hoisted(c: &mut Criterion) {
    let kp = keys::generate_keypair().unwrap();
    let sk = keys::signing_key_from_bytes(kp.secret.as_bytes()).unwrap();
    let vk = sk.verifying_key();
    let msg: [u8; 32] = Sha256::digest(b"benchmark message").into();
    let sig = sk.sign_raw(&msg, &[0u8; 32]).unwrap();
    c.bench_function("keys_schnorr_verify_hoisted", |b| {
        b.iter(|| vk.verify_prehash(&msg, &sig).unwrap());
    });
}

fn bench_pubkey_hex_hoisted(c: &mut Criterion) {
    // pubkey_hex = derivation + hex encoding; with derivation hoisted only
    // the encoding remains. If this does NOT collapse versus keys_pubkey_hex,
    // the 2026-08-16 shared-setup hypothesis is falsified.
    let kp = keys::generate_keypair().unwrap();
    let pk_bytes = *kp.public.as_bytes();
    c.bench_function("keys_pubkey_hex_hoisted", |b| {
        b.iter(|| hex::encode(pk_bytes));
    });
}

criterion_group!(
    benches,
    bench_generate_keypair,
    bench_derive_from_prf,
    bench_schnorr_sign,
    bench_schnorr_verify,
    bench_pubkey_hex,
    bench_schnorr_sign_hoisted,
    bench_schnorr_verify_hoisted,
    bench_pubkey_hex_hoisted,
);
criterion_main!(benches);
