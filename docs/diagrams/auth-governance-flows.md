# Auth-Worker Flows: Sequence Diagrams

Generated from source code — not from documentation. All file:line references point at
the Rust source under `crates/nostr-bbs-auth-worker/`.
Re-verified against `origin/main` `3c48e2656d7cabefa894a59b827f5f0d3a8b32b7` (v1.0.0-beta.21-rc.2, 2026-11-22): every citation below was
re-derived from its symbol at that revision.

---

## 1. NIP-98 Request Verification Path

Every `/api/*` route (and the `POST /api/native-pod/provision` out-of-band handler)
passes through this path before any business logic executes.

Sources:
- `lib.rs:145-156`, `lib.rs:159-219` — outer `fetch` + `handle_request`
- `lib.rs:226-351` — `route()` (+ `route_sprint_api()` at `lib.rs:357`)
- `admin.rs:26-34` — `verify()` (thin wrapper)
- `auth.rs:15-31` — `verify_nip98_replay()` (thin wrapper selecting `REPLAY_DB = "DB"`)
- `crates/nostr-bbs-rate-limit/src/replay.rs:148-174` — `verify_nip98()` (actual D1 path)
- `crates/nostr-bbs-core/src/nip98.rs:417-513` — `verify_token_full()` (all structural checks)
- `crates/nostr-bbs-core/src/nip98.rs:564-594` — `verify_nip98_with_replay()` (replay layer)

```mermaid
sequenceDiagram
    participant C as Client
    participant W as auth-worker (lib.rs:159)
    participant RL as nostr-bbs-rate-limit (replay.rs:148)
    participant CORE as nostr-bbs-core/nip98.rs:417
    participant D1R as D1: nostr-bbs-auth (nip98_replay table)

    C->>W: HTTP request + Authorization: Nostr <base64>
    W->>W: ensure_schema() + ensure_replay_schema() [lib.rs:164-165]
    W->>W: IP rate-limit check (SESSIONS KV, 20 req/60s) [lib.rs:175-182]
    W->>W: read body_bytes for POST/PUT/PATCH [lib.rs:196-199]

    alt path starts with /api/
        W->>W: route_sprint_api() first — self-verifying sprint modules [lib.rs:289-301]
        Note over W: Sprint modules (moderation, wot, invites, etc.)<br/>call require_admin / require_authed directly
        W->>RL: verify_nip98(auth_header, url, method, body, env, "DB") [auth.rs:22]
        RL->>RL: get JS wall-clock now [replay.rs:156]
        RL->>RL: construct D1ReplayStore {db, ttl=120s} [replay.rs:160-164]
        RL->>CORE: verify_nip98_token_at_with_replay(..., store) [replay.rs:165-173]
        CORE->>CORE: verify_token_full() — 10 structural checks [nip98.rs:417]
        Note over CORE: 1. Strip "Nostr " prefix [nip98.rs:425]<br/>2. Size gate 64 KiB [nip98.rs:431]<br/>3. Base64-decode + JSON parse [nip98.rs:436]<br/>4. kind == 27235 [nip98.rs:443]<br/>5. pubkey = 64 hex chars [nip98.rs:448]<br/>6. |now - created_at| ≤ 60s [nip98.rs:453]<br/>7. Recompute ID + Schnorr sig verify [nip98.rs:462]<br/>8. u-tag == expected_url [nip98.rs:467]<br/>9. method-tag == expected_method (case-insensitive) [nip98.rs:476]<br/>10. payload-tag SHA-256 == SHA-256(body) if body present [nip98.rs:486]
        CORE->>D1R: INSERT OR IGNORE INTO nip98_replay (event_id, expires_at) [replay.rs:12-13, 25-44]
        D1R-->>CORE: changes (else rows_written) = 1 (first-seen) or 0 (replay) [replay.rs:47-55]
        alt rows_written == 0
            CORE-->>W: Err(Nip98Error::Replayed)
            W-->>C: 401 {"error":"Invalid NIP-98 token"}
        end
        CORE-->>RL: Ok(Nip98Token {event_id, pubkey, url, method, ...})
        RL-->>W: Ok(Nip98Token)
        W->>W: extract pubkey from token [lib.rs:333-337]
        W-->>C: route to handler with authed pubkey
    end
```

### Author extraction and authorisation

`Nip98Token.pubkey` is the **recomputed-and-verified** signer pubkey — never trusted
from the client body. Two gate levels consume it:

- `require_authed()` (`admin.rs:125-147`): any valid NIP-98 token; returns `pubkey`.
- `require_admin()` (`admin.rs:92-120`): additionally calls `is_admin(pubkey, env)` (`admin.rs:53-86`),
  which checks two sources in order: `ADMIN_PUBKEYS` env var → `RELAY_DB whitelist.is_admin`.
  The auth-side `members` table is **no longer consulted** (`admin.rs:4-5`, `admin.rs:71-83`): legacy member
  rows never re-grant authority after demotion. The relay's own `is_admin` resolves the same two sources
  (`crates/nostr-bbs-relay-worker/src/auth.rs:181`, `auth.rs:208`).

---

## 2. Governance Flows

### 2a. Whitelist Add / Remove

These operate on `RELAY_DB` (the relay's `nostr-bbs-relay` D1, bound as `RELAY_DB` in
the auth-worker). The binding is now declared in `wrangler.toml` with a placeholder
`database_id` that deployments must override with the relay worker's actual D1 id
(Finding 1, resolved — anomaly register R6).

Sources: `admins.rs:128-264`, `admin.rs:53-120`

```mermaid
sequenceDiagram
    participant A as Admin Client
    participant W as auth-worker
    participant D1A as D1: nostr-bbs-auth (DB — members table)
    participant D1R as D1: nostr-bbs-relay (RELAY_DB — whitelist table)
    participant KV as KV: admin_pubkeys_cache (60-s TTL)

    A->>W: POST /api/admins/add  Authorization: Nostr ...
    W->>W: require_admin() [admins.rs:135]
    Note over W: NIP-98 verify → is_admin() check [admin.rs:53]<br/>is_admin() reads ADMIN_PUBKEYS env → RELAY_DB whitelist.is_admin (no members lookup)

    W->>D1R: INSERT INTO whitelist (pubkey, is_admin=1, cohorts='["home"]', added_at)<br/>ON CONFLICT DO UPDATE SET is_admin=1 [admins.rs:160-171]
    D1R-->>W: ok

    W->>D1A: INSERT INTO members (pubkey, is_admin=1, created_at)<br/>ON CONFLICT DO UPDATE SET is_admin=1 [admins.rs:179-192]
    D1A-->>W: ok (best-effort, errors ignored, row is not read by is_admin)

    W->>KV: DELETE admin_pubkeys_cache (bust_cache) [admins.rs:194]
    W-->>A: 200 {"ok":true, "pubkey":"...", "action":"admin_added"}

    A->>W: POST /api/admins/remove  Authorization: Nostr ...
    W->>W: require_admin() — prevents self-removal [admins.rs:214, 229-231]
    W->>D1R: UPDATE whitelist SET is_admin=0 WHERE pubkey=? [admins.rs:239-243]
    D1R-->>W: ok
    W->>D1A: UPDATE members SET is_admin=0 WHERE pubkey=? [admins.rs:249-255]
    D1A-->>W: ok
    W->>KV: DELETE admin_pubkeys_cache [admins.rs:257]
    W-->>A: 200 {"ok":true, "pubkey":"...", "action":"admin_removed"}
```

### 2b. Agent Provisioning — POST /api/governance/agents/provision (ADR-097)

Atomic D1 batch writing both `whitelist` and `agent_registry` in one implicit D1
transaction. Both tables live in `nostr-bbs-relay` (accessed via `RELAY_DB`).

Sources: `governance_api.rs:405-501`

```mermaid
sequenceDiagram
    participant A as Admin Client
    participant W as auth-worker
    participant V as normalize_provision() [governance_api.rs:120]
    participant D1R as D1: nostr-bbs-relay (RELAY_DB)<br/>tables: whitelist, agent_registry

    A->>W: POST /api/governance/agents/provision<br/>Body: {pubkey, name, description, cohorts, rate_limit_per_min?}
    W->>W: require_admin() [governance_api.rs:441]
    Note over W: NIP-98 verify → admin gate

    W->>W: serde_json::from_slice body [governance_api.rs:446]
    W->>V: normalize_provision(body) [governance_api.rs:451]
    Note over V: Rules [governance_api.rs:86-94, 120-134]:<br/>• pubkey exactly 64 hex chars, lowercased<br/>• name non-empty after trim<br/>• cohorts non-empty Vec

    V-->>W: Ok(NormalizedProvision) or Err(msg) → 400

    W->>W: serde_json::to_string(cohorts) [governance_api.rs:456]

    W->>D1R: PREPARE whitelist grant (WHITELIST_GRANT_COHORTS_SQL)<br/>INSERT INTO whitelist (pubkey, cohorts, added_at, added_by)<br/>ON CONFLICT (pubkey) DO UPDATE merges the new cohorts into the existing set (never removes one) and sets added_by [governance_api.rs:466, whitelist_sql.rs:73-86]

    W->>D1R: PREPARE agent_registry upsert<br/>INSERT OR REPLACE INTO agent_registry<br/>(pubkey, name, description, registered_by, registered_at, rate_limit_per_min, active=1) [governance_api.rs:474-487]

    W->>D1R: db.batch([whitelist_stmt, registry_stmt]) [governance_api.rs:490]
    Note over D1R: D1 batch = implicit transaction<br/>All-or-nothing, no partial state

    D1R-->>W: Ok or Err
    W-->>A: 200 {"pubkey":"...", "cohorts":[...], "registered":true}
```

### 2c. Agent Register / Revoke

```mermaid
sequenceDiagram
    participant A as Admin Client
    participant W as auth-worker
    participant D1R as D1: nostr-bbs-relay (RELAY_DB — agent_registry)

    A->>W: POST /api/governance/agents/register<br/>Body: {pubkey, name, description?, rate_limit_per_min?}
    W->>W: require_admin() [governance_api.rs:362]
    W->>W: validate pubkey (64 hex), name non-empty, pubkey lowercased [governance_api.rs:372-375, 108-111]
    W->>D1R: INSERT OR REPLACE INTO agent_registry<br/>(pubkey, name, description, registered_by, registered_at, rate_limit_per_min, active=1) [governance_api.rs:380-394]
    D1R-->>W: ok
    W-->>A: 201 {"ok":true, "pubkey":"...", "name":"..."}

    A->>W: POST /api/governance/agents/revoke  Body: {pubkey}
    W->>W: require_admin() [governance_api.rs:510-514]
    W->>D1R: UPDATE agent_registry SET active=0 WHERE lower(pubkey)=? [governance_api.rs:531-535]
    D1R-->>W: meta.changes
    W-->>A: 200 {"ok":true, "pubkey":"...", "active":false} or 404 no such agent when changes == 0 [governance_api.rs:543-551]
```

### 2d. Broker Roles — Grant / Revoke / List

```mermaid
sequenceDiagram
    participant A as Admin/Auth Client
    participant W as auth-worker
    participant D1R as D1: nostr-bbs-relay (RELAY_DB — broker_roles)

    A->>W: POST /api/governance/roles/grant  Body: {pubkey, role}
    W->>W: require_admin() [governance_api.rs:670]
    W->>W: validate pubkey 64 hex, then lowercase it [governance_api.rs:680, 690]
    W->>D1R: INSERT OR REPLACE INTO broker_roles (pubkey, role, granted_by, granted_at) [governance_api.rs:692-703]
    D1R-->>W: ok
    W-->>A: 201 {"ok":true, "pubkey":"...", "role":"..."}

    A->>W: POST /api/governance/roles/revoke  Body: {pubkey, role}
    W->>W: require_admin() [governance_api.rs:739-743]
    W->>D1R: DELETE FROM broker_roles WHERE lower(pubkey)=? AND role=? [governance_api.rs:756-760]
    D1R-->>W: meta.changes
    W-->>A: 200 {"ok":true, ..., "revoked":true} or 404 no such role assignment when changes == 0 [governance_api.rs:762-776]

    A->>W: GET /api/governance/roles
    W->>W: require_authed() [governance_api.rs:718]
    W->>D1R: SELECT * FROM broker_roles ORDER BY pubkey, role [governance_api.rs:724]
    D1R-->>W: rows
    W-->>A: 200 {"roles":[...]}
```

### 2e. Broker Cases — List / Get (read-only from auth-worker)

Broker cases are **written by the relay worker's Durable Object** (kind-31402
ActionRequests projected by `project_action_request`, `nip_handlers.rs:3901-3982`, whose upsert
is `CASE_UPSERT_SQL`, `nip_handlers.rs:1033-1053`; kind-31403 decisions projected by
`project_action_response`, `nip_handlers.rs:4110-4306`, through the receipts batch,
`receipts.rs:672-716`; kind-31400 PanelDefinitions are stored as events but NOT projected to
`broker_cases`, only consulted for panel tags, `nip_handlers.rs:3833`; the relay cron also
updates case state, `cron.rs:844`) and **read by the auth-worker** via the same `RELAY_DB`
binding.

```mermaid
sequenceDiagram
    participant RC as Relay Client (WebSocket)
    participant RDO as nostr-bbs-relay DO (nip_handlers.rs:1089)
    participant D1R as D1: nostr-bbs-relay (broker_cases, broker_decisions)
    participant AC as Auth Client (HTTP)
    participant W as auth-worker

    RC->>RDO: EVENT kind=31402 (ActionRequest) — agent pubkey
    RDO->>RDO: is_registered_agent(pubkey) → SELECT active FROM agent_registry [nip_handlers.rs:1354-1357, 3787-3806], unless a kanban approval request from a whitelisted author
    D1R-->>RDO: active=1
    RDO->>D1R: INSERT INTO broker_cases (...) ON CONFLICT (id) DO UPDATE for the same author while undecided and newer [nip_handlers.rs:1033-1053, 3940]

    RC->>RDO: EVENT kind=31403 (ActionResponse) — admin pubkey
    RDO->>RDO: response_admission(is_admin, is_reviewer, delegated) → admin, or reviewer delegated for that case [nip_handlers.rs:298-319, 1374-1388]
    RDO->>D1R: INSERT INTO broker_decisions (...) guarded by case state and receipt [receipts.rs:185-191]
    RDO->>D1R: UPDATE broker_cases SET state=new_state in the same D1 batch as the receipt [receipts.rs:192-193, 713-716]

    AC->>W: GET /api/governance/cases[?state=open]
    W->>W: require_authed() [governance_api.rs:561]
    W->>D1R: SELECT * FROM broker_cases [WHERE state=?] ORDER BY updated_at DESC LIMIT 100 [governance_api.rs:571-580]
    D1R-->>W: rows
    W-->>AC: 200 {"cases":[...]}

    AC->>W: GET /api/governance/cases/:id
    W->>W: require_authed() [governance_api.rs:594]
    W->>D1R: SELECT * FROM broker_cases WHERE id=? [governance_api.rs:599-603]
    D1R-->>W: row or None
    W-->>AC: 200 {"case":{...}} or 404
```

---

## 3. Device-Key Registry Lifecycle (ADR-099)

All three handlers are gated by `DEVICE_KEYS_ENABLED == "true"` (exact string,
default off). The `device_keys` table lives in `RELAY_DB` (nostr-bbs-relay D1)
so the relay DO can read it without a cross-worker call. The relay does that on EVENT write-gating and REQ/COUNT read-scope resolution (`nip_handlers.rs:1161-1162`, `2276`), not in `handle_auth` (`nip_handlers.rs:2124`).

Sources: `devices.rs:1-550`

```mermaid
sequenceDiagram
    participant U as Member Client
    participant W as auth-worker
    participant G as device_keys_enabled() [devices.rs:100]
    participant T as ensure_device_table() [devices.rs:121]
    participant D1R as D1: nostr-bbs-relay (RELAY_DB — device_keys)
    participant RDOA as nostr-bbs-relay DO [nip_handlers.rs:1089]

    Note over W,D1R: All three endpoints check gate first

    U->>W: POST /api/devices/register  Body: {device_pubkey, label?}
    W->>G: DEVICE_KEYS_ENABLED == "true"? [devices.rs:371]
    G-->>W: false → 404 {"error":"device keys disabled"} (default)

    Note over W,D1R: When DEVICE_KEYS_ENABLED=true:
    W->>W: require_authed() → owner_pk = NIP-98 author [devices.rs:376]
    Note over W: owner is NEVER taken from request body [devices.rs:9]
    W->>W: normalize_register(body) [devices.rs:386]
    Note over W: • device_pubkey: 64 hex, lowercased<br/>• label: trim, None if blank [devices.rs:176-191]
    W->>W: verify_device_proof(device_proof, device_pubkey, owner) — signed by the device key, owner and exp bound, else 400 [devices.rs:398-404, 215-251]
    W->>T: CREATE TABLE IF NOT EXISTS device_keys (...) [devices.rs:121, 407]
    T->>D1R: DDL (idempotent)
    W->>D1R: is_known_principal(device_pubkey) — admin, whitelisted or existing device owner → 409 [devices.rs:413-419, 273-302]
    W->>D1R: INSERT INTO device_keys (device_pubkey, owner_pubkey, label, created_at, revoked=0)<br/>ON CONFLICT (device_pubkey) DO UPDATE SET label=excluded.label<br/>only WHERE same owner AND revoked=0 [devices.rs:331, 427-436]
    D1R-->>W: meta.changes (409 if not 1, owner and revocation are immutable) [devices.rs:438-444]
    W-->>U: 200 {device_pubkey, owner_pubkey, label, revoked:0}

    U->>W: GET /api/devices
    W->>G: gate check [devices.rs:462]
    W->>W: require_authed() → owner_pk [devices.rs:467]
    W->>T: ensure_device_table
    W->>D1R: SELECT ... FROM device_keys WHERE owner_pubkey=? ORDER BY created_at DESC [devices.rs:475-482]
    D1R-->>W: rows
    W-->>U: 200 {"devices":[...]}

    U->>W: POST /api/devices/revoke  Body: {device_pubkey}
    W->>G: gate check [devices.rs:498]
    W->>W: require_authed() → owner_pk [devices.rs:503]
    W->>W: normalize_revoke_target(device_pubkey) [devices.rs:513]
    W->>T: ensure_device_table
    W->>D1R: UPDATE device_keys SET revoked=1<br/>WHERE device_pubkey=? AND owner_pubkey=? [devices.rs:524-534]
    Note over D1R: ownership enforced in WHERE clause [devices.rs:521-523]<br/>meta.changes == 0 → 404 (device not yours / not found)
    D1R-->>W: meta.changes
    W-->>U: 200 {device_pubkey, owner_pubkey, revoked:1} or 404

    Note over RDOA,D1R: Relay DO reads device_keys on EVENT/REQ handling
    RDOA->>RDOA: effective_pubkey(incoming_pubkey) [nip_handlers.rs:3779, called at 1162 and 2276]
    alt DEVICE_KEYS_ENABLED=true
        RDOA->>D1R: SELECT owner_pubkey FROM device_keys<br/>WHERE device_pubkey=? AND revoked=0 LIMIT 1 [nip_handlers.rs:3752-3770, memoised 2338]
        D1R-->>RDOA: owner_pubkey or None
        RDOA->>RDOA: treat owner_pubkey as the effective principal for whitelist/zone checks
    end
```

---

## 4. Findings

Each finding has: severity (HIGH/MEDIUM/LOW/INFO), file:line, description, and
classification.

---

**Finding 1 — RESOLVED (anomaly register R6)**
`crates/nostr-bbs-auth-worker/wrangler.toml`

~~`governance_api.rs` and `devices.rs` both call `env.d1("RELAY_DB")` at runtime but
no `RELAY_DB` binding appeared in `wrangler.toml`.~~ The kit template now declares a
`[[d1_databases]]` stanza for `RELAY_DB` (`database_name = "nostr-bbs-relay"`) with an
explicit placeholder `database_id` of all-zeros (`wrangler.toml:14-20`) and a comment instructing deployments
to point it at the relay worker's actual D1. Downstream deploys override it; a deploy
that forgets still fails per-request with 500s on `/api/governance/*` and
`/api/devices/*`, but the template drift is fixed.

---

**Finding 2 — RESOLVED (anomaly register R8)**
`crates/nostr-bbs-auth-worker/src/http.rs:19-43`

~~Two `cors_headers()` implementations existed; the `http.rs` version fallback-filled
`"https://example.com"`.~~ Consolidated: `http.rs::cors_headers()` is now the single
canonical builder and is fail-closed — when `EXPECTED_ORIGIN` is unset or empty it
emits **no** `Access-Control-Allow-Origin` header. `lib.rs` imports it
(`use crate::http::cors_headers`, `lib.rs:38`); there is no duplicate definition.

---

**Finding 3 — RESOLVED (anomaly register R4)**
~~`crates/nostr-bbs-auth-worker/src/delegation.rs`~~ (file removed)

~~`POST /api/delegation/verify` 501 stub with no consumer.~~ The NIP-26 delegation
implementation, its test suite, and the auth-worker 501 stub were deleted (~860
lines) as superseded by ADR-099 device keys. No `delegation` route or module remains
in the auth-worker.

---

**Finding 4 — RESOLVED (mitigated by disjoint key prefixes)**
`crates/nostr-bbs-auth-worker/wrangler.toml:26-28`, `wrangler.toml:42-44` — `SESSIONS` and `KV` bindings

The `KV` namespace binding (`id = 901345296c2848788066686aa67d5909`) still resolves to the
same physical KV namespace as `SESSIONS` (same id), and `admins.rs:54` / `admins.rs:101`
use `env.kv("KV")` for the `admin_pubkeys_cache` key. ~~A key collision (e.g. if an IP
address coincidentally matches `admin_pubkeys_cache`) would corrupt the admin cache or
inflate rate-limit counters.~~ The keyspaces are now disjoint by construction: the rate
limiter only writes `rl:{ip}:{bucket}` keys (`crates/nostr-bbs-rate-limit/src/lib.rs:45`),
the `wrangler.toml:22-25` note records the sharing, and `admins.rs:343-349` unit-tests that
`ADMIN_CACHE_KEY` never starts with `rl:`. The cache is also no longer an authority:
`get_admin_pubkeys` re-queries D1 on every call and the KV write is compatibility-only
(`admins.rs:47-97`).

---

**Finding 5 — RESOLVED (COM-17 / F5)**
`crates/nostr-bbs-auth-worker/src/governance_api.rs:27-33`

The module doc comment states "broker_decisions" lives in `RELAY_DB`. ~~`broker_decisions`
(the append-only audit trail of individual decisions) has **no read endpoint** in the
auth-worker; there is no `GET /api/governance/decisions` or equivalent.~~ The read
endpoint now exists: `handle_list_decisions` (`governance_api.rs:619-661`, doc comment
`governance_api.rs:611-618`) behind a `require_authed` gate, routed at `lib.rs:556`,
paged by `?limit=` / `?offset=` with an optional `?case_id=` filter. The relay writes
`broker_decisions` through the receipts batch (`relay_do/receipts.rs:185-191`).

---

**Finding 6 — RESOLVED (shared validator)**
`crates/nostr-bbs-auth-worker/src/governance_api.rs:86-94`

`handle_register_agent` performed pubkey/name validation inline using copied if-blocks,
while `handle_provision_agent` called the extracted `normalize_provision()`, so a change
to validation rules would need applying in two places. Both paths now share
`validate_agent_fields` (`governance_api.rs:86-94`): `handle_register_agent` calls it via
`canonical_agent_pubkey` (`governance_api.rs:108-111`, call at `governance_api.rs:372`)
and `normalize_provision` (`governance_api.rs:120-134`, call at `governance_api.rs:451`)
calls it directly. The unit tests sit in `mod tests` at `governance_api.rs:788`.

---

**Finding 7 — LOW | ok (cross-worker D1 sharing — explicit note)**
`crates/nostr-bbs-relay-worker/src/relay_do/nip_handlers.rs:3752-3770` (`device_owner`)
reads `device_keys` from `self.env.d1("DB")` (the relay's own D1, `nostr-bbs-relay`,
`nip_handlers.rs:3753`), memoised per DO by `cached_device_owner` (`nip_handlers.rs:2338`).
`crates/nostr-bbs-auth-worker/src/devices.rs:87-89` (`relay_db`) writes `device_keys` via `env.d1("RELAY_DB")`
(which is the same physical D1 when the binding is correctly declared, see Finding 1).
This cross-worker D1 sharing is **intentional** and documented in `devices.rs:23-31` and
`governance_api.rs:27-30`. The relay reads; the auth-worker writes. There is no
cross-worker D1 transaction; both ends are designed to tolerate eventual consistency
within a single D1 write (which is synchronous from D1's perspective).

---

**Finding 8 — LOW | isolated (partially resolved)**
`crates/nostr-bbs-auth-worker/src/lib.rs:637` — `POST /api/native-pod/provision`

This endpoint (`handle_native_pod_provision`, `lib.rs:695-`) requires `NATIVE_POD_URL`
and `NATIVE_POD_ADMIN_KEY` env vars (`lib.rs:769-788`). `NATIVE_POD_URL` is now
declared in `wrangler.toml` `[vars]` at `wrangler.toml:66` (placeholder value); `NATIVE_POD_ADMIN_KEY` is
documented there as a `wrangler secret put` secret, never inline. The endpoint returns
`503 {"error":"native pod not configured"}` when either is missing — a proper
fail-closed response. The forum client's `pod_browser.rs` reads `NATIVE_POD_URL` as a
build-time `option_env!` constant (`pod_browser.rs:128`), not as a runtime auth-worker call; the admin UI is
the intended consumer of this route (unverified at 3c48e26: no client caller of
`/api/native-pod/provision` was searched for).

---

**Finding 9 — INFO | ok**
`crates/nostr-bbs-auth-worker/src/lib.rs:164` — `ensure_schema()` called on every request

`schema.rs:ensure_schema()` (`schema.rs:19`) is called at the top of `handle_request`
(`lib.rs:159-164`) with no once-per-isolate guard, issuing `CREATE TABLE IF NOT EXISTS` /
`CREATE INDEX IF NOT EXISTS` for ~23 table/index DDL statements (counted by grep over
`schema.rs:19-242`) against `DB`. The relay's `ensure_schema()`
(`crates/nostr-bbs-relay-worker/src/lib.rs:1059`, run once per isolate at `lib.rs:224-228`)
independently manages the governance tables; the auth-side note at `schema.rs:237-241` still names the old `ensure_tables_exist()`, a stale comment. There
is no coordination between the two, which is correct: they target different D1
databases and neither can safely create the other's tables.

---

**Finding 10 — RESOLVED (commit 42b1ded, ADR-102)**
`crates/nostr-bbs-relay-worker/src/trust.rs:326` — `decide_demotion()` (formerly `check_demotion()`)

~~`check_demotion()` is implemented but never called.~~ The 5-minute cron
(`crates/nostr-bbs-relay-worker/wrangler.toml:123` `crons`, `scheduled()` at `lib.rs:1623`) now runs the paged
`trust_sweep::sweep_inactive_demotions` (`trust_sweep.rs:538`) after keep-warm (`lib.rs:1633`),
applying the pure policy `trust::decide_demotion` (`trust.rs:326`) to whitelist rows past the
~6-month inactivity gate. The old `check_demotion(pubkey, env)` helper was deleted so
no request path can commit a demotion (`trust.rs:414-420`). `last_active_at` is stamped by
`trust::update_last_active` (`trust.rs:459`), flushed on the relay's read path through the
`ActivityLedger` (`relay_do/read_cache.rs:27-33`), so active lurkers are not demoted.

---

## D1 Table / Binding Cross-Reference

| Table | Physical D1 | Writer(s) | Reader(s) |
|-------|-------------|-----------|-----------|
| `whitelist` | nostr-bbs-relay (RELAY_DB in auth, DB in relay) | auth-worker `/api/admins/add`, `/api/governance/agents/provision`, invite redemption (`invites.rs:238`) | relay DO trust checks, auth `is_admin()` (`admin.rs:72-83`), relay `is_admin` (`auth.rs:181`) |
| `agent_registry` | nostr-bbs-relay | auth-worker `/api/governance/agents/register`, `/provision` | relay DO `is_registered_agent()` |
| `broker_cases` | nostr-bbs-relay | relay DO (kind 31402 upsert `nip_handlers.rs:1033`, kind 31403 state `receipts.rs:192`), relay cron (`cron.rs:844`) | auth-worker `/api/governance/cases/*` |
| `broker_decisions` | nostr-bbs-relay | relay DO (kind 31403 events, `receipts.rs:185`) | auth-worker `GET /api/governance/decisions` (`governance_api.rs:619`, Finding 5) |
| `broker_roles` | nostr-bbs-relay | auth-worker `/api/governance/roles/grant` | auth-worker `/api/governance/roles` list |
| `device_keys` | nostr-bbs-relay | auth-worker `/api/devices/register`, `/revoke` | relay DO `device_owner()` on EVENT / REQ via `effective_pubkey` (`nip_handlers.rs:3752`, `1162`, `2276`), not at NIP-42 AUTH |
| `nip98_replay` | nostr-bbs-auth (DB in auth, REPLAY_DB in relay) | both workers atomically via `INSERT OR IGNORE` | both workers (same table = cross-worker replay detected) |
| `members` | nostr-bbs-auth | auth-worker invite redemption (`invites.rs:672`, `878`), `/api/admins/add` (`admins.rs:179`) | auth-worker invite flow (`invites.rs:134`). **Not read by `is_admin()`** (`admin.rs:4-5`) |
| `moderation_actions` | nostr-bbs-auth | auth-worker `/api/mod/ban` etc. | auth-worker `/api/mod/actions` list |
| `mod_reports` | nostr-bbs-auth | auth-worker `/api/mod/report` | auth-worker `/api/mod/reports` list |
| `wot_entries` | nostr-bbs-auth | auth-worker `/api/wot/*` | auth-worker wot module |
| `instance_settings` | nostr-bbs-auth | auth-worker welcome/wot configure (`welcome.rs:226`, `wot.rs:220`) | auth-worker welcome/wot status |
| `username_reservations` | nostr-bbs-auth | auth-worker `/api/username/claim` | auth-worker `/api/username/check`, `/resolve` |
| `nip1984_reports` | nostr-bbs-auth | relay-worker (kind-1984 event projection — **written by relay, not auth**) | auth-worker `GET /api/moderation/reports` |
| `challenges` | nostr-bbs-auth | auth-worker WebAuthn register flow | auth-worker WebAuthn auth flow |
| `webauthn_credentials` | nostr-bbs-auth | auth-worker WebAuthn register/verify | auth-worker login flows |
