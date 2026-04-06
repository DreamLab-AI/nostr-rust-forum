# Setup Guide

This guide walks through deploying nostr-BBS-rs on Cloudflare Workers with a static Leptos WASM frontend.

## Prerequisites

1. **Rust** (stable) with `wasm32-unknown-unknown` target:
   ```bash
   rustup target add wasm32-unknown-unknown
   ```

2. **Trunk** (for building the Leptos WASM client):
   ```bash
   cargo install trunk
   ```

3. **wrangler** (Cloudflare Workers CLI):
   ```bash
   npm i -g wrangler
   wrangler login
   ```

4. **worker-build** (for Rust Workers):
   ```bash
   cargo install worker-build
   ```

## 1. Cloudflare Account Setup

Create the following resources in your Cloudflare account:

### D1 Databases

```bash
wrangler d1 create nostr-bbs-auth
wrangler d1 create nostr-bbs-relay
```

Initialize the auth database schema:

```sql
-- Run via: wrangler d1 execute nostr-bbs-auth --command "..."
CREATE TABLE IF NOT EXISTS webauthn_credentials (
    pubkey TEXT NOT NULL,
    credential_id TEXT NOT NULL,
    public_key TEXT NOT NULL,
    counter INTEGER DEFAULT 0,
    prf_salt TEXT,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (pubkey)
);

CREATE TABLE IF NOT EXISTS challenges (
    pubkey TEXT NOT NULL,
    challenge TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_challenges_created ON challenges(created_at);
```

Initialize the relay database schema:

```sql
-- Run via: wrangler d1 execute nostr-bbs-relay --command "..."
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    pubkey TEXT NOT NULL,
    kind INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    content TEXT NOT NULL,
    tags TEXT NOT NULL,
    sig TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_pubkey ON events(pubkey);
CREATE INDEX IF NOT EXISTS idx_events_kind ON events(kind);
CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_at);

CREATE TABLE IF NOT EXISTS whitelist (
    pubkey TEXT PRIMARY KEY,
    cohorts TEXT NOT NULL DEFAULT '["members"]',
    added_at INTEGER NOT NULL,
    added_by TEXT NOT NULL DEFAULT 'auto-registration',
    is_admin INTEGER NOT NULL DEFAULT 0
);
```

### KV Namespaces

```bash
wrangler kv namespace create SESSIONS
wrangler kv namespace create POD_META
wrangler kv namespace create RATE_LIMIT
wrangler kv namespace create SEARCH_CONFIG
```

### R2 Buckets

```bash
wrangler r2 bucket create nostr-bbs-pods
wrangler r2 bucket create nostr-bbs-vectors
```

## 2. Configure wrangler.toml Files

Update each worker's `wrangler.toml` with the resource IDs from step 1:

- `crates/auth-worker/wrangler.toml` -- D1 ID, KV IDs (SESSIONS, POD_META), R2 bucket, RP_ID, RP_NAME, EXPECTED_ORIGIN
- `crates/pod-worker/wrangler.toml` -- KV ID (POD_META), EXPECTED_ORIGIN
- `crates/preview-worker/wrangler.toml` -- KV ID (RATE_LIMIT), ALLOWED_ORIGIN
- `crates/relay-worker/wrangler.toml` -- D1 ID, RELAY_NAME, ALLOWED_ORIGIN(S)
- `crates/search-worker/wrangler.toml` -- R2 bucket, KV ID (SEARCH_CONFIG), ALLOWED_ORIGIN(S)

Set your domain in all `RP_ID`, `EXPECTED_ORIGIN`, `ALLOWED_ORIGIN`, and `ALLOWED_ORIGINS` vars.

## 3. Deploy Workers

```bash
cd crates/auth-worker && wrangler deploy
cd crates/pod-worker && wrangler deploy
cd crates/preview-worker && wrangler deploy
cd crates/relay-worker && wrangler deploy
cd crates/search-worker && wrangler deploy
```

## 4. Configure DNS

Add CNAME or Workers Routes for your subdomains:

| Subdomain | Worker |
|-----------|--------|
| `api.your-domain.com` | auth-worker + relay-worker |
| `pods.your-domain.com` | pod-worker |
| `search.your-domain.com` | search-worker |
| `preview.your-domain.com` | preview-worker |

## 5. Update Forum Client URLs

Edit the following files to point to your deployed worker URLs:

- `crates/forum-client/src/relay.rs` -- `DEFAULT_RELAY_URL`
- `crates/forum-client/src/utils/relay_url.rs` -- relay HTTP/WS URLs
- `crates/forum-client/src/utils/pod_client.rs` -- pod API URL
- `crates/forum-client/src/utils/search_client.rs` -- search API URL
- `crates/forum-client/src/components/global_search.rs` -- search API URL
- `crates/forum-client/src/components/link_preview.rs` -- preview API URL

Alternatively, set environment variables at compile time:
- `RELAY_URL` -- WebSocket relay URL
- `RELAY_HTTP_URL` -- HTTP relay URL
- `POD_API_URL` -- Pod worker URL
- `SEARCH_API_URL` -- Search worker URL
- `PREVIEW_API_URL` -- Preview worker URL

## 6. Build and Deploy Forum Client

```bash
cd crates/forum-client

# Local development
trunk serve

# Production build (for deployment at /community/ path)
FORUM_BASE=/community trunk build --release --public-url /community/

# Or root deployment
trunk build --release
```

The built files are in `crates/forum-client/dist/`. Deploy to any static hosting (GitHub Pages, Cloudflare Pages, Netlify, etc.).

## 7. First-User-Is-Admin Flow

1. Open the deployed forum in a browser
2. Click "Sign Up" and complete the passkey registration
3. The first user to register automatically becomes admin with all-zone access
4. Navigate to `/admin` to manage users, zones, and settings
5. Use the admin panel to:
   - Approve/promote other users
   - Assign zone access (public/members/private)
   - Create channels and categories
   - Configure community settings

## 8. Zone Configuration

The 3-zone model is configurable:

| Zone | Default ID | Default Cohorts |
|------|-----------|----------------|
| Public | `home` | home, lobby, approved, cross-access |
| Members | `members` | members, business, trainers, trainees, cross-access |
| Private | `private` | private, private-only, cross-access |

To customize zones, provide a `BbsConfig` in your Leptos app before calling `provide_zone_access()`:

```rust
use crate::stores::zone_access::BbsConfig;

let config = BbsConfig {
    zone_public_name: "Lobby".into(),
    zone_members_name: "Team".into(),
    zone_private_name: "VIP".into(),
    ..Default::default()
};
provide_context(config);
provide_zone_access();
```

## Troubleshooting

- **Passkey registration fails**: Verify `RP_ID` matches your domain exactly (no `https://` prefix)
- **CORS errors**: Ensure `EXPECTED_ORIGIN` / `ALLOWED_ORIGINS` include your frontend URL
- **Relay not connecting**: Check `DEFAULT_RELAY_URL` points to your deployed relay-worker
- **Zone access empty**: The relay's `/api/check-whitelist` endpoint must return `access` object with zone flags
- **First user not admin**: Check relay D1 `whitelist` table -- the `is_admin` column should be 1

## Running Tests

```bash
# All workspace tests (native)
cargo test --workspace

# nostr-core only
cargo test -p nostr-core

# WASM target check (no native tests)
cargo check --target wasm32-unknown-unknown -p forum-client
```
