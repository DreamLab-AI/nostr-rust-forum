# nostr-BBS-rs -- Decentralized Forum on Nostr

A full-stack, open-source forum built on the Nostr protocol. Passkey-first authentication, Solid pod storage, config-driven zone access, and Cloudflare Workers backend -- all in Rust.

## Architecture

Seven crates in a Cargo workspace:

| Crate | Type | Purpose |
|-------|------|---------|
| `nostr-core` | Library | Shared Nostr protocol: NIP-01/07/09/29/33/40/42/45/50/52/98, key management, event validation, WASM bridge |
| `auth-worker` | CF Worker | WebAuthn register/login (passkey), NIP-98 verification, pod provisioning, rate limiting (D1 + KV + R2) |
| `pod-worker` | CF Worker | Solid pod storage: LDP containers, WAC ACL, JSON Patch, conditional requests, quotas, WebID, micropayments (R2 + KV) |
| `preview-worker` | CF Worker | Link preview with SSRF protection, OG/meta parsing, oEmbed, rate limiting |
| `relay-worker` | CF Worker | NIP-01 WebSocket relay via Durable Objects, hibernation-safe sessions, subscription persistence (D1 + DO) |
| `search-worker` | CF Worker | RuVector search, RVF binary format, in-memory cosine k-NN, rate limiting (R2 + KV) |
| `forum-client` | Leptos App | Browser client (Leptos 0.7 CSR + Trunk), passkey auth, 18 pages, 58+ components, admin panel |

## Features

- **Passkey-first auth** -- WebAuthn PRF extension derives Nostr keys deterministically; private keys never stored
- **3-zone access model** -- Configurable public/members/private zones with cohort-based access control
- **First-user-is-admin** -- No hardcoded admin keys; first registrant gets admin privileges
- **Solid pods** -- Per-user W3C-compliant storage with WAC ACL, LDP containers, and JSON Patch
- **Offline-first** -- Service worker + IndexedDB caching with 30-day eviction
- **WebGPU effects** -- 3-tier rendering: WebGPU compute > Canvas2D > CSS fallback
- **Micropayments** -- HTTP 402 + Web Ledgers for per-resource satoshi costs
- **NIP coverage** -- 1, 7, 9, 11, 16, 29, 33, 40, 42, 45, 50, 52, 98

## NIP Coverage

| NIP | Description | Crate |
|-----|-------------|-------|
| 01 | Basic protocol, event signing | nostr-core, relay-worker |
| 07 | Browser extension (NIP-07) | forum-client |
| 09 | Event deletion | nostr-core, relay-worker |
| 11 | Relay information document | relay-worker |
| 16 | Ephemeral events | relay-worker |
| 29 | Group access (relay-enforced) | nostr-core, relay-worker |
| 33 | Parameterized replaceable events | nostr-core, relay-worker |
| 40 | Channel creation/metadata | nostr-core, relay-worker |
| 42 | Channel messages | relay-worker |
| 45 | Event counts | relay-worker |
| 50 | Search | search-worker |
| 52 | Calendar events | nostr-core |
| 98 | HTTP Auth | nostr-core, all workers |

## Quick Start

```bash
# Prerequisites
rustup target add wasm32-unknown-unknown
cargo install trunk
npm i -g wrangler

# Build all crates
cargo build --workspace

# Run tests
cargo test --workspace

# Serve the forum client locally
cd crates/forum-client && trunk serve
```

See [SETUP.md](SETUP.md) for full deployment instructions.

## Crate Dependency Graph

```
forum-client ---- nostr-core
auth-worker  ---- nostr-core
relay-worker ---- nostr-core
pod-worker   ---- nostr-core
search-worker --- nostr-core
preview-worker    (standalone)
```

## Zone Model

The forum uses a 3-zone access model configurable via `BbsConfig`:

| Default Zone | Default ID | Purpose |
|-------------|-----------|---------|
| Public | `home` | Open to all authenticated users |
| Members | `members` | Restricted to approved members |
| Private | `private` | Invite-only / admin-granted |

Zone names, IDs, and cohort mappings are all runtime-configurable. See `crates/forum-client/src/stores/zone_access.rs` for the `BbsConfig` struct.

## Related

- **[nostr-bbs-core](https://github.com/DreamLab-AI/nostr-bbs-core)** -- Standalone Rust crate extracting the `nostr-core` NIP library from this project. 140 tests, compiles to native + wasm32, all crypto delegates to NCC-audited RustCrypto crates. Use it independently if you only need Nostr protocol primitives (NIP-01/07/09/29/33/40/42/44/45/50/52/98).

## License

MIT
