# Setup Guide

This guide walks through deploying nostr-rust-forum on Cloudflare Workers with a static Leptos WASM frontend.

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

Apply the governance migration (Agent Control Surface Protocol):

```bash
wrangler d1 execute nostr-bbs-relay --file crates/nostr-bbs-relay-worker/migrations/0002_governance.sql
```

This creates four tables: `agent_registry`, `broker_cases`, `broker_decisions`,
`broker_roles`. The migration is idempotent (uses `IF NOT EXISTS`). The same
tables are also created inline by the auth-worker on startup.

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

- `crates/nostr-bbs-auth-worker/wrangler.toml` -- D1 ID, KV IDs (SESSIONS, POD_META), R2 bucket, RP_ID, RP_NAME, EXPECTED_ORIGIN
- `crates/nostr-bbs-pod-worker/wrangler.toml` -- KV ID (POD_META), EXPECTED_ORIGIN
- `crates/nostr-bbs-preview-worker/wrangler.toml` -- KV ID (RATE_LIMIT), ALLOWED_ORIGIN
- `crates/nostr-bbs-relay-worker/wrangler.toml` -- D1 ID, RELAY_NAME, ALLOWED_ORIGIN(S)
- `crates/nostr-bbs-search-worker/wrangler.toml` -- R2 bucket, KV ID (SEARCH_CONFIG), ALLOWED_ORIGIN(S)

Set your domain in all `RP_ID`, `EXPECTED_ORIGIN`, `ALLOWED_ORIGIN`, and `ALLOWED_ORIGINS` vars.

## 3. Deploy Workers

```bash
cd crates/nostr-bbs-auth-worker && wrangler deploy
cd crates/nostr-bbs-pod-worker && wrangler deploy
cd crates/nostr-bbs-preview-worker && wrangler deploy
cd crates/nostr-bbs-relay-worker && wrangler deploy
cd crates/nostr-bbs-search-worker && wrangler deploy
```

## 4. Configure DNS

Add CNAME or Workers Routes for your subdomains:

| Subdomain | Worker |
|-----------|--------|
| `api.your-domain.com` | nostr-bbs-auth-worker + nostr-bbs-relay-worker |
| `pods.your-domain.com` | nostr-bbs-pod-worker |
| `search.your-domain.com` | nostr-bbs-search-worker |
| `preview.your-domain.com` | nostr-bbs-preview-worker |

## 5. Update Forum Client URLs

Edit the following files to point to your deployed worker URLs:

- `crates/nostr-bbs-forum-client/src/relay.rs` -- `DEFAULT_RELAY_URL`
- `crates/nostr-bbs-forum-client/src/utils/relay_url.rs` -- relay HTTP/WS URLs
- `crates/nostr-bbs-forum-client/src/utils/pod_client.rs` -- pod API URL
- `crates/nostr-bbs-forum-client/src/utils/search_client.rs` -- search API URL
- `crates/nostr-bbs-forum-client/src/components/global_search.rs` -- search API URL
- `crates/nostr-bbs-forum-client/src/components/link_preview.rs` -- preview API URL

Alternatively, set environment variables at compile time:
- `RELAY_URL` -- WebSocket relay URL
- `RELAY_HTTP_URL` -- HTTP relay URL
- `POD_API_URL` -- Pod worker URL
- `SEARCH_API_URL` -- Search worker URL
- `PREVIEW_API_URL` -- Preview worker URL

## 6. Build and Deploy Forum Client

```bash
cd crates/nostr-bbs-forum-client

# Local development
trunk serve

# Production build (for deployment at /community/ path)
FORUM_BASE=/community trunk build --release --public-url /community/

# Or root deployment
trunk build --release
```

The built files are in `crates/nostr-bbs-forum-client/dist/`. Deploy to any static hosting (GitHub Pages, Cloudflare Pages, Netlify, etc.).

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

## 8. Agent Control Surface (Governance)

The forum provides an Agent Control Surface Protocol for human-in-the-loop
governance. Agents publish interactive control panels via nostr events (kinds
31400-31405); humans respond with signed decisions.

### Registering an Agent

Agents must be registered by an admin before they can publish governance events:

```bash
# Register an agent pubkey via the governance REST API
curl -X POST https://api.your-domain.com/api/governance/agents/register \
  -H "Authorization: Nostr <base64-nip98-token>" \
  -H "Content-Type: application/json" \
  -d '{"pubkey": "<agent_64hex_pubkey>", "name": "My Agent", "description": "Enrichment queue agent", "rate_limit_per_min": 60}'
```

### Granting Broker Roles

Broker roles control which humans can act on governance cases:

```bash
# Grant the broker role to a human pubkey
curl -X POST https://api.your-domain.com/api/governance/roles/grant \
  -H "Authorization: Nostr <base64-nip98-token>" \
  -H "Content-Type: application/json" \
  -d '{"pubkey": "<human_64hex_pubkey>", "role": "broker"}'
```

Available roles: `contributor`, `auditor`, `broker`, `admin`.

### Governance Dashboard

Once agents are registered and publishing events, the governance dashboard is
available at `/governance` in the forum client. It shows:

- **Active Panels** -- agent-published PanelDefinitions with schema, fields, and actions
- **Pending Actions** -- action requests awaiting human review with approve/reject buttons
- **Registered Agents** -- count of active agents publishing to the relay

### Governance D1 Migration

The governance tables are created by `0002_governance.sql` in
`crates/nostr-bbs-relay-worker/migrations/`. Apply with:

```bash
wrangler d1 execute nostr-bbs-relay --file crates/nostr-bbs-relay-worker/migrations/0002_governance.sql
```

The auth-worker also creates these tables inline via `schema.rs` on first request.

## 9. Zone Configuration

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
- **Agent events rejected by relay**: The agent pubkey must be registered in `agent_registry` with `active = 1`. Use `GET /api/governance/agents` to verify registration status
- **Governance page empty**: The relay subscription for kinds 31400-31405 requires the WebSocket connection to be established. Check browser console for relay connection status
- **Action response signing fails**: The user must be authenticated via passkey or NIP-07 before signing action responses. Check `auth.is_authenticated()` state
- **Governance migration not applied**: Run `wrangler d1 execute nostr-bbs-relay --file crates/nostr-bbs-relay-worker/migrations/0002_governance.sql` to create governance tables

## Running Tests

```bash
# All workspace tests (native)
cargo test --workspace

# nostr-bbs-core only
cargo test -p nostr-bbs-core

# WASM target check (no native tests)
cargo check --target wasm32-unknown-unknown -p nostr-bbs-forum-client

# Anti-drift lint (rejects stale identifiers and branding leaks)
scripts/anti-drift-lint.sh

# Sync cross-substrate test fixtures from VisionClaw
scripts/sync-fixtures.sh

# CI gate: verify fixtures are up to date
scripts/sync-fixtures.sh --verify
```
