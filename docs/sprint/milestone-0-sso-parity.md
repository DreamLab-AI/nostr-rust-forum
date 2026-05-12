# Milestone 0: NIP-98 Token Format Parity Report

Cross-repo SSO sprint pre-condition check between `nostr-bbs-core` (NRF) and
`solid-pod-rs`.

**Date:** 2026-05-12
**Status:** BLOCKING INCOMPATIBILITY FOUND -- Schnorr sign/verify pre-hashing mismatch

---

## Parity Matrix

| # | Field | NRF (`nostr-bbs-core::nip98`) | solid-pod-rs (`auth::nip98`) | Match? | Action |
|---|-------|-------------------------------|-------------------------------|--------|--------|
| 1 | Event kind | `27235` (const `HTTP_AUTH_KIND`) | `27235` (const `HTTP_AUTH_KIND`) | YES | None |
| 2 | Required tag `u` | `["u", "<url>"]` first match | `["u", "<url>"]` first match | YES | None |
| 3 | Required tag `method` | `["method", "<method>"]` first match | `["method", "<method>"]` first match | YES | None |
| 4 | Optional tag `payload` | `["payload", hex(sha256(body))]`; required when non-empty body provided at verify time | Same logic: required when `body.is_some() && !body.is_empty()` | YES | None |
| 5 | Timestamp tolerance | +/-60s default (`TIMESTAMP_TOLERANCE`), configurable via `max_age_secs` param | +/-60s hardcoded (`TIMESTAMP_TOLERANCE`), not configurable at call site | PARTIAL | solid-pod-rs should expose tolerance param for parity |
| 6 | Signature algorithm | BIP-340 Schnorr secp256k1 via `k256::schnorr` -- uses `sign_raw`/`verify_raw` (pre-hashed: 32-byte event ID is the message) | BIP-340 Schnorr secp256k1 via `k256::schnorr` -- uses `Signer::sign`/`Verifier::verify` (double-hashes: applies SHA-256 tagged hash internally to the 32-byte event ID) | **NO** | **CRITICAL -- see below** |
| 7 | Event ID computation | NIP-01 canonical: `sha256([0, pubkey, created_at, kind, tags, content])` via tuple serde | NIP-01 canonical: `sha256(json!([0, pubkey, created_at, kind, tags, content]))` via `json!` macro | YES | Both produce identical JSON arrays |
| 8 | Base64 encoding | `base64::STANDARD` (RFC 4648 standard alphabet, with padding) | `base64::STANDARD` (RFC 4648 standard alphabet, with padding) | YES | None |
| 9 | Token header format | `"Nostr "` prefix (capital N, single space); strips prefix + trims whitespace | `"Nostr "` prefix (capital N, single space); strips prefix + trims whitespace | YES | None |
| 10 | Replay protection | `Nip98ReplayStore` trait -- async `seen_or_record()` with recommended 120s TTL; checked after all crypto passes | None -- no replay store, no event-id dedup | NO | solid-pod-rs must integrate replay store or depend on NRF's trait |
| 11 | URL matching | Exact string equality (`token_url != expected_url`); trailing-slash difference = mismatch | `normalize_url()` strips trailing `/` before comparison | **NO** | Decide on convention; NRF is NIP-98-spec strict, solid-pod-rs is lenient |
| 12 | Method matching | Case-insensitive (`to_uppercase()` both sides) | Case-insensitive (`to_uppercase()` both sides) | YES | None |
| 13 | Size limit | 64 KiB on both encoded and decoded token | 64 KiB on both encoded and decoded token | YES | None |
| 14 | Pubkey validation | 64 hex chars + valid hex decode | 64 hex chars + valid hex decode | YES | None |
| 15 | Verified result type | `Nip98Token { event_id, pubkey, url, method, payload_hash, created_at }` -- includes canonical `event_id` | `Nip98Verified { pubkey, url, method, payload_hash, created_at }` -- no `event_id` field | NO | solid-pod-rs needs `event_id` to key replay cache |
| 16 | Token creation | `create_token()` / `create_token_at()` / `sign_request_header()` | None -- verify-only, no token creation API | NO | solid-pod-rs must depend on NRF for token creation, or add its own |
| 17 | Schnorr feature gate | Always enabled (k256 is a hard dep) | Feature-gated behind `nip98-schnorr`; without it, `verify_schnorr_signature` returns `Err(Unsupported)` | PARTIAL | Production must enable `nip98-schnorr` feature |
| 18 | Error types | Rich enum `Nip98Error` with 13 variants | Generic `PodError::Nip98(String)` | N/A | Different error ergonomics, not a wire-level issue |

---

## Critical Issue: Schnorr Pre-Hashing Mismatch

### The Problem

NRF and solid-pod-rs use different `k256` API layers for BIP-340 Schnorr operations:

**NRF (correct per BIP-340 / NIP-01):**
```rust
// Signing (event.rs line 140)
signing_key.sign_raw(&id_bytes, &aux_rand)

// Verification (event.rs line 237)
verifying_key.verify_raw(&expected_id, &signature)
```

`sign_raw` / `verify_raw` treat the 32-byte input as the **already-hashed message**.
This is correct for Nostr: the event ID is `SHA-256(canonical_json)`, and BIP-340
specifies signing over a 32-byte message hash directly.

**solid-pod-rs (incorrect for Nostr events):**
```rust
// Signing (test helper, nip98.rs line 532)
let signature: k256::schnorr::Signature = sk.sign(&id_bytes);

// Verification (nip98.rs line 199)
vk.verify(&id_bytes, &sig)
```

`Signer::sign` / `Verifier::verify` (from the `signature` crate traits) apply
an additional `SHA-256` tagged hash internally before signing/verifying. This
means solid-pod-rs effectively signs/verifies over `SHA-256(SHA-256(canonical_json))`
instead of `SHA-256(canonical_json)`.

### Consequence

A token created by NRF's `create_token()` will **fail** Schnorr verification in
solid-pod-rs (when `nip98-schnorr` is enabled), and vice versa. The structural
checks (kind, URL, method, timestamp, payload) will all pass, but the signature
check will reject the token.

This also means solid-pod-rs tokens are incompatible with every other NIP-98
implementation in the ecosystem (nostr-tools, rust-nostr, etc.), all of which
use the raw 32-byte event ID as the BIP-340 message.

### Fix

In `solid-pod-rs/crates/solid-pod-rs/src/auth/nip98.rs`, change:

```rust
// Line 173: change import
use k256::schnorr::{Signature, VerifyingKey};
// Remove: use k256::schnorr::{signature::Verifier, Signature, VerifyingKey};

// Line 199: change verify call
vk.verify_raw(&id_bytes, &sig)
    .map_err(|e| PodError::Nip98(format!("schnorr verify: {e}")))?;
```

And in tests, change signing from `sk.sign(&id_bytes)` to
`sk.sign_raw(&id_bytes, &[0u8; 32])`.

---

## Secondary Issues

### URL Normalization Divergence (Row 11)

solid-pod-rs strips trailing slashes via `normalize_url()` before comparison.
NRF performs exact string matching. The NIP-98 spec says the `u` tag "MUST be
the same URL as the one being accessed" -- exact match is the correct reading.

**Recommendation:** Remove `normalize_url` from solid-pod-rs and use exact match.
Or, if trailing-slash leniency is desired ecosystem-wide, add it to NRF as well
behind an opt-in parameter.

### Missing Replay Protection (Row 10)

solid-pod-rs has no replay detection. For SSO, this means a captured NIP-98
token can be replayed within the 60-second window.

**Recommendation:** solid-pod-rs should either:
1. Depend on `nostr-bbs-core` and use its `Nip98ReplayStore` trait, or
2. Implement its own event-id dedup with >= 120s TTL.

### Missing `event_id` in Return Type (Row 15)

`Nip98Verified` has no `event_id` field. Without it, the caller cannot
implement replay caching. The canonical event ID must be returned from
verification.

**Recommendation:** Add `pub event_id: String` to `Nip98Verified`.

### No Token Creation API (Row 16)

solid-pod-rs is verify-only. For SSO flows where solid-pod-rs acts as a
client authenticating to NRF services, it needs the ability to create tokens.

**Recommendation:** Either depend on `nostr-bbs-core::nip98::create_token` or
port the creation logic.

---

## Public API Surface

### NRF (`nostr-bbs-core::nip98`)

| Function | Visibility | Purpose |
|----------|-----------|---------|
| `verify_nip98()` | `pub` | Canonical entry point, system clock, configurable tolerance |
| `verify_token()` | `pub` | Legacy alias, system clock, default tolerance |
| `verify_token_at()` | `pub` | Explicit timestamp, default tolerance |
| `verify_token_full()` | `pub` | Full control: explicit timestamp + custom tolerance |
| `verify_token_at_with_replay()` | `pub async` | Explicit timestamp + replay store |
| `verify_nip98_with_replay()` | `pub async` | Full control + replay store |
| `create_token()` | `pub` | Create token (system clock) |
| `create_token_at()` | `pub` | Create token (explicit timestamp) |
| `sign_request_header()` | `pub` | Create full `Authorization` header |
| `authorization_header()` | `pub` | Prefix token with `Nostr ` |
| `Nip98ReplayStore` | `pub trait` | Replay detection abstraction |
| `Nip98Token` | `pub struct` | Verified token with `event_id` |

### solid-pod-rs (`auth::nip98`)

| Function | Visibility | Purpose |
|----------|-----------|---------|
| `verify()` | `pub async` | System clock, returns pubkey only |
| `verify_at()` | `pub` | Explicit timestamp, returns `Nip98Verified` |
| `compute_event_id()` | `pub` | NIP-01 canonical hash |
| `verify_schnorr_signature()` | `pub` | Feature-gated Schnorr check |
| `authorization_header()` | `pub` | Prefix token with `Nostr ` |
| `Nip98Verifier` | `pub struct` | `SelfSignedVerifier` adapter (re-exported from `lib.rs`) |
| `Nip98Event` | `pub struct` | Deserialized event |
| `Nip98Verified` | `pub struct` | Verification result (no event_id) |

**External consumer access:** `Nip98Verifier` is re-exported at crate root
(`pub use auth::nip98::Nip98Verifier`). The raw `verify` / `verify_at`
functions are accessible via `solid_pod_rs::auth::nip98::verify_at`. The
Schnorr verification is feature-gated behind `nip98-schnorr`.

---

## Action Items for Milestone 1

| Priority | Item | Owner | Effort |
|----------|------|-------|--------|
| P0 | Fix Schnorr sign/verify to use `sign_raw`/`verify_raw` in solid-pod-rs | solid-pod-rs | 1h |
| P0 | Update solid-pod-rs test signing helper to use `sign_raw` | solid-pod-rs | 30m |
| P1 | Add `event_id: String` to `Nip98Verified` | solid-pod-rs | 30m |
| P1 | Add replay store (trait or concrete) to solid-pod-rs | solid-pod-rs | 2h |
| P2 | Remove `normalize_url` or align both repos | both | 1h |
| P2 | Expose configurable timestamp tolerance in solid-pod-rs `verify_at` | solid-pod-rs | 30m |
| P3 | Add `create_token` / `create_token_at` to solid-pod-rs or add NRF as dependency | solid-pod-rs | 2h |
| P3 | Cross-repo integration test: NRF-created token verified by solid-pod-rs | both | 2h |
