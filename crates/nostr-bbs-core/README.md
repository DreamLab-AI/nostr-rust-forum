# nostr-bbs-core

Shared Nostr protocol primitives for the nostr-bbs forum and its consumers:
NIP-01 events and signing, NIP-04/NIP-44 encryption, NIP-19 encodings, NIP-98
HTTP auth, sealed originals, gift wrap, key derivation (including WebAuthn PRF),
moderation and ontology-governance event builders, and the shared value types.

## Licence

`MIT OR Apache-2.0`, at your option, from `1.0.0-beta.16` onward. Versions up to
`1.0.0-beta.15` were published as `AGPL-3.0-only` and keep that licence. The
rest of the `nostr-rust-forum` workspace (workers, clients, server) remains
AGPL-3.0-only; only this crate is permissive.

### The `did` feature

The `did` module (DID:nostr document rendering) is behind an off-by-default
`did` feature because it depends on `solid-pod-rs`, which is AGPL-3.0-only.
With default features the crate pulls no copyleft dependency. **A build with
`did` enabled is AGPL-3.0 as a combined work**, so enable it only where that is
acceptable (the forum's own workers do).

```toml
nostr-bbs-core = "1.0.0-beta.16"                         # permissive
nostr-bbs-core = { version = "1.0.0-beta.16", features = ["did"] }  # AGPL build
```

## Cryptography

No hand-rolled primitives: `k256` (Schnorr/secp256k1), `chacha20poly1305`,
`sha2`/`hmac`/`hkdf`, via the `nostr` crate where it has the construction.
