# ADR-094 — Deterministic purpose-scoped subkey derivation

- **Status:** Accepted
- **Date:** 2026-06-11
- **Owners:** `nostr-bbs-core` (crate `keys.rs`, wasm bridge). Cross-stack contract
  shared with agentbox (mirror/agent key derivation, JS implementation).
- **Related:** Existing `derive_from_prf` (HKDF-from-PRF — a *different*
  construction, see §4); agentbox mirror key derivation (the JS path this ADR
  must match byte-for-byte).

---

## 1. Context

Multiple independent consumers need to derive the **same** purpose-scoped key from
a single root secret key:

- **Forum device keys** (`nostr-bbs-core`, native + wasm) — per-purpose keys
  derived from a user/device root.
- **agentbox agent / mirror keys** (JavaScript) — the mirror already derives a
  child key from the root for the Telegram mirror identity using the tag
  `"agentbox-mirror-v1"`.

agentbox's existing JS derivation is:

```js
// child_sk = HMAC-SHA256(key = root_sk_32_bytes, msg = utf8(tag))
const child_sk = crypto.createHmac('sha256', rootSk32Bytes).update(tag, 'utf8').digest();
```

For the two stacks to converge on one identity per purpose, the Rust derivation
must produce the **identical 32 bytes** for the same `(root, tag)`. There was no
shared Rust primitive for this; consumers either re-implemented HMAC ad hoc or
risked diverging from the JS contract.

## 2. Decision

Add a single canonical primitive to `nostr-bbs-core`:

```rust
pub fn derive_subkey(root: &SecretKey, tag: &str) -> Result<SecretKey, KeyError>
```

### Scheme

1. `H = HMAC-SHA-256(key = root.secret_bytes_32, msg = utf8(tag))` → 32 bytes.
2. Map `H` to a secp256k1 secret scalar using the **same validation path** as
   `SecretKey::from_bytes` (the k256 `SigningKey::from_bytes` constructor, which
   **validates** — rejecting zero and any value `>=` the curve order `n`; it does
   not silently reduce mod `n`, so the 32 HMAC bytes are the secret verbatim).
3. On the astronomically-unlikely rejection (`H == 0` or `H >= n`), return
   `KeyError::InvalidSecretKey`. We do **not** silently re-hash or increment,
   because doing so would break JS parity; the probability is `< 2^-127` and a
   surfaced error is the correct, deterministic behaviour.

### Cross-language contract

The Rust output equals the JS output, byte-for-byte, for any `(root, tag)`:

| Side | Construction |
|------|--------------|
| JS   | `createHmac('sha256', rootSk).update(tag,'utf8').digest()` |
| Rust | `Hmac::<Sha256>::new_from_slice(root.as_bytes()).update(tag.as_bytes()).finalize()` |

Both feed the raw 32-byte HMAC output into the same secp256k1 scalar validation.
The wasm bridge (`derive_subkey_js`) lets the browser client derive identically.

### Rotation

Rotation is **by tag**. Append/bump a version suffix: `"agentbox-mirror-v1"` →
`"agentbox-mirror-v2"`. The root is unchanged; the new tag yields an unrelated
child via HMAC domain separation. Old and new subkeys are independent of each
other (but both recoverable from the root — see §5).

## 3. Known-answer vector

Locked into the test suite to pin the cross-language contract:

| Input | Value |
|-------|-------|
| `root` | `0x01` repeated 32 times |
| `tag`  | `agentbox-mirror-v1` |
| `child_sk` (hex) | `2d07f2ce93d0361687fdd81d2690082b5d6c35b93e3ece2d44bcf115ef8f695d` |

JS cross-check:

```sh
node -e 'const c=require("crypto");
  const root=Buffer.alloc(32,0x01);
  console.log(c.createHmac("sha256",root).update("agentbox-mirror-v1","utf8").digest("hex"));'
# => 2d07f2ce93d0361687fdd81d2690082b5d6c35b93e3ece2d44bcf115ef8f695d
```

## 4. Why not reuse `derive_from_prf` (HKDF)?

`derive_from_prf` uses **HKDF-Expand-SHA-256** with `salt = empty`,
`info = "nostr-secp256k1-v1"`. That is a different construction (HKDF, not raw
HMAC over a tag) chosen to match the WebAuthn-PRF JS path. It is *not*
interchangeable: HKDF-Expand prepends counter bytes and the info string, so its
output for a given key differs from a bare `HMAC(key, tag)`.

`derive_subkey` deliberately uses the **bare keyed-HMAC-over-tag** construction
because that is what agentbox's JS mirror already shipped. Keeping both is
intentional: PRF→identity stays HKDF; root→purpose-scoped-child is HMAC. They
serve different contracts and must not be merged.

## 5. Security note

A subkey derived by `derive_subkey` is **fully recoverable from the root** by
anyone holding the root and the tag. It provides **domain separation**, not
**compromise isolation**:

- ✅ Use it to give each purpose a distinct, stable, reproducible key (forum
  device key, mirror identity, agent identity) without storing N secrets.
- ❌ Do **not** use it where independence from the root is required — e.g.
  delegating authority you must later be able to revoke without rotating the
  root, or any context where the holder of the subkey must provably *not* be
  able to act as the root. Compromise of the root compromises every subkey.

For revocable delegation, use NIP-26 delegation tokens, not `derive_subkey`.

## 6. Consequences

- One canonical primitive; consumers stop re-implementing HMAC.
- Forum and agentbox keys converge on a single tested contract with a pinned
  known-answer vector guarding against silent divergence.
- The wasm bridge exposes the same derivation to the browser client.
- Bumping a tag suffix is the supported rotation path.
