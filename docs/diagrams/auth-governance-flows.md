# Auth-Worker Flows: Sequence Diagrams

Generated from source code — not from documentation. All file:line references point at
the Rust source under `crates/nostr-bbs-auth-worker/`.

---

## 1. NIP-98 Request Verification Path

Every `/api/*` route (and the `POST /api/native-pod/provision` out-of-band handler)
passes through this path before any business logic executes.

Sources:
- `lib.rs:160-231` — outer `fetch` + `handle_request`
- `lib.rs:233-363` — `route()`
- `admin.rs:28-36` — `verify()` (thin wrapper)
- `auth.rs:15-31` — `verify_nip98_replay()` (thin wrapper selecting `REPLAY_DB = "DB"`)
- `crates/nostr-bbs-rate-limit/src/replay.rs:77-103` — `verify_nip98()` (actual D1 path)
- `crates/nostr-bbs-core/src/nip98.rs:400-496` — `verify_token_full()` (all structural checks)
- `crates/nostr-bbs-core/src/nip98.rs:547-577` — `verify_nip98_with_replay()` (replay layer)

```mermaid
sequenceDiagram
    participant C as Client
    participant W as auth-worker (lib.rs:160)
    participant RL as nostr-bbs-rate-limit (replay.rs:77)
    participant CORE as nostr-bbs-core/nip98.rs:400
    participant D1R as D1: nostr-bbs-auth (nip98_replay table)

    C->>W: HTTP request + Authorization: Nostr <base64>
    W->>W: ensure_schema() + ensure_replay_schema() [lib.rs:180-181]
    W->>W: IP rate-limit check (SESSIONS KV, 20 req/60s) [lib.rs:191-198]
    W->>W: read body_bytes for POST/PUT/PATCH [lib.rs:212-215]

    alt path starts with /api/
        W->>W: route_sprint_api() first — self-verifying sprint modules [lib.rs:301-313]
        Note over W: Sprint modules (moderation, wot, invites, etc.)<br/>call require_admin / require_authed directly
        W->>RL: verify_nip98(auth_header, url, method, body, env, "DB") [auth.rs:22]
        RL->>RL: get JS wall-clock now [replay.rs:85]
        RL->>RL: construct D1ReplayStore {db, ttl=120s} [replay.rs:91-93]
        RL->>CORE: verify_nip98_with_replay(..., store) [replay.rs:94-101]
        CORE->>CORE: verify_token_full() — 10 structural checks [nip98.rs:400]
        Note over CORE: 1. Strip "Nostr " prefix [nip98.rs:409]<br/>2. Size gate 64 KiB [nip98.rs:415]<br/>3. Base64-decode + JSON parse [nip98.rs:420]<br/>4. kind == 27235 [nip98.rs:427]<br/>5. pubkey = 64 hex chars [nip98.rs:431]<br/>6. |now - created_at| ≤ 60s [nip98.rs:437]<br/>7. Recompute ID + Schnorr sig verify [nip98.rs:446]<br/>8. u-tag == expected_url [nip98.rs:451]<br/>9. method-tag == expected_method (case-insensitive) [nip98.rs:460]<br/>10. payload-tag SHA-256 == SHA-256(body) if body present [nip98.rs:470]
        CORE->>D1R: INSERT OR IGNORE INTO nip98_replay (event_id, expires_at) [replay.rs:27]
        D1R-->>CORE: rows_written = 1 (first-seen) or 0 (replay)
        alt rows_written == 0
            CORE-->>W: Err(Nip98Error::Replayed)
            W-->>C: 401 {"error":"Invalid NIP-98 token"}
        end
        CORE-->>RL: Ok(Nip98Token {event_id, pubkey, url, method, ...})
        RL-->>W: Ok(Nip98Token)
        W->>W: extract pubkey from token [lib.rs:345]
        W-->>C: route to handler with authed pubkey
    end
```

### Author extraction and authorisation

`Nip98Token.pubkey` is the **recomputed-and-verified** signer pubkey — never trusted
from the client body. Two gate levels consume it:

- `require_authed()` (`admin.rs:136-158`): any valid NIP-98 token; returns `pubkey`.
- `require_admin()` (`admin.rs:99-131`): additionally calls `is_admin(pubkey, env)`,
  which checks three sources in order: `ADMIN_PUBKEYS` env var → `RELAY_DB whitelist.is_admin` → `DB members.is_admin`.

---

## 2. Governance Flows

### 2a. Whitelist Add / Remove

These operate on `RELAY_DB` (the relay's `nostr-bbs-relay` D1, bound as `RELAY_DB` in
the auth-worker — **but this binding is absent from `wrangler.toml`**; see Finding 1).

Sources: `admins.rs:160-297`, `admin.rs:57-97`

```mermaid
sequenceDiagram
    participant A as Admin Client
    participant W as auth-worker
    participant D1A as D1: nostr-bbs-auth (DB — members table)
    participant D1R as D1: nostr-bbs-relay (RELAY_DB — whitelist table)
    participant KV as KV: admin_pubkeys_cache (60-s TTL)

    A->>W: POST /api/admins/add  Authorization: Nostr ...
    W->>W: require_admin() [admins.rs:169]
    Note over W: NIP-98 verify → is_admin() check [admin.rs:57]<br/>is_admin() reads ADMIN_PUBKEYS env → RELAY_DB whitelist → DB members

    W->>D1R: INSERT INTO whitelist (pubkey, is_admin=1, cohorts='["home"]', added_at)<br/>ON CONFLICT DO UPDATE SET is_admin=1 [admins.rs:193-204]
    D1R-->>W: ok

    W->>D1A: INSERT INTO members (pubkey, is_admin=1, created_at)<br/>ON CONFLICT DO UPDATE SET is_admin=1 [admins.rs:211-225]
    D1A-->>W: ok (best-effort, errors ignored)

    W->>KV: DELETE admin_pubkeys_cache (bust_cache) [admins.rs:227]
    W-->>A: 200 {"ok":true, "pubkey":"...", "action":"admin_added"}

    A->>W: POST /api/admins/remove  Authorization: Nostr ...
    W->>W: require_admin() — prevents self-removal [admins.rs:262]
    W->>D1R: UPDATE whitelist SET is_admin=0 WHERE pubkey=? [admins.rs:274-279]
    D1R-->>W: ok
    W->>D1A: UPDATE members SET is_admin=0 WHERE pubkey=? [admins.rs:282-291]
    D1A-->>W: ok
    W->>KV: DELETE admin_pubkeys_cache [admins.rs:293]
    W-->>A: 200 {"ok":true, "pubkey":"...", "action":"admin_removed"}
```

### 2b. Agent Provisioning — POST /api/governance/agents/provision (ADR-097)

Atomic D1 batch writing both `whitelist` and `agent_registry` in one implicit D1
transaction. Both tables live in `nostr-bbs-relay` (accessed via `RELAY_DB`).

Sources: `governance_api.rs:259-332`

```mermaid
sequenceDiagram
    participant A as Admin Client
    participant W as auth-worker
    participant V as normalize_provision() [governance_api.rs:84]
    participant D1R as D1: nostr-bbs-relay (RELAY_DB)<br/>tables: whitelist, agent_registry

    A->>W: POST /api/governance/agents/provision<br/>Body: {pubkey, name, description, cohorts, rate_limit_per_min?}
    W->>W: require_admin() [governance_api.rs:266]
    Note over W: NIP-98 verify → admin gate

    W->>W: serde_json::from_slice body [governance_api.rs:271]
    W->>V: normalize_provision(body) [governance_api.rs:276]
    Note over V: Rules [governance_api.rs:84-103]:<br/>• pubkey exactly 64 hex chars, lowercased<br/>• name non-empty after trim<br/>• cohorts non-empty Vec

    V-->>W: Ok(NormalizedProvision) or Err(msg) → 400

    W->>W: serde_json::to_string(cohorts) [governance_api.rs:281]

    W->>D1R: PREPARE whitelist upsert<br/>INSERT INTO whitelist (pubkey, cohorts, added_at, added_by)<br/>ON CONFLICT (pubkey) DO UPDATE SET cohorts=excluded.cohorts, added_by=excluded.added_by [governance_api.rs:291-302]

    W->>D1R: PREPARE agent_registry upsert<br/>INSERT OR REPLACE INTO agent_registry<br/>(pubkey, name, description, registered_by, registered_at, rate_limit_per_min, active=1) [governance_api.rs:305-318]

    W->>D1R: db.batch([whitelist_stmt, registry_stmt]) [governance_api.rs:321]
    Note over D1R: D1 batch = implicit transaction<br/>All-or-nothing; no partial state

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
    W->>W: require_admin() [governance_api.rs:189]
    W->>W: validate pubkey (64 hex), name non-empty [governance_api.rs:199-203]
    W->>D1R: INSERT OR REPLACE INTO agent_registry<br/>(pubkey, name, description, registered_by, registered_at, rate_limit_per_min, active=1) [governance_api.rs:209-223]
    D1R-->>W: ok
    W-->>A: 201 {"ok":true, "pubkey":"...", "name":"..."}

    A->>W: POST /api/governance/agents/revoke  Body: {pubkey}
    W->>W: require_admin() [governance_api.rs:341]
    W->>D1R: UPDATE agent_registry SET active=0 WHERE pubkey=? [governance_api.rs:353]
    D1R-->>W: ok
    W-->>A: 200 {"ok":true, "pubkey":"...", "active":false}
```

### 2d. Broker Roles — Grant / Revoke / List

```mermaid
sequenceDiagram
    participant A as Admin/Auth Client
    participant W as auth-worker
    participant D1R as D1: nostr-bbs-relay (RELAY_DB — broker_roles)

    A->>W: POST /api/governance/roles/grant  Body: {pubkey, role}
    W->>W: require_admin() [governance_api.rs:428]
    W->>W: validate pubkey 64 hex [governance_api.rs:438]
    W->>D1R: INSERT OR REPLACE INTO broker_roles (pubkey, role, granted_by, granted_at) [governance_api.rs:445-457]
    D1R-->>W: ok
    W-->>A: 201 {"ok":true, "pubkey":"...", "role":"..."}

    A->>W: POST /api/governance/roles/revoke  Body: {pubkey, role}
    W->>W: require_admin() [governance_api.rs:492]
    W->>D1R: DELETE FROM broker_roles WHERE pubkey=? AND role=? [governance_api.rs:504-509]
    D1R-->>W: ok
    W-->>A: 200 {"ok":true, ..., "revoked":true}

    A->>W: GET /api/governance/roles
    W->>W: require_authed() [governance_api.rs:470]
    W->>D1R: SELECT * FROM broker_roles ORDER BY pubkey, role [governance_api.rs:477]
    D1R-->>W: rows
    W-->>A: 200 {"roles":[...]}
```

### 2e. Broker Cases — List / Get (read-only from auth-worker)

Broker cases are **written by the relay worker's Durable Object** (kinds 31400/31402
projected at `nip_handlers.rs:1144`) and **read by the auth-worker** via the same
`RELAY_DB` binding.

```mermaid
sequenceDiagram
    participant RC as Relay Client (WebSocket)
    participant RDO as nostr-bbs-relay DO (nip_handlers.rs:1127)
    participant D1R as D1: nostr-bbs-relay (broker_cases, broker_decisions)
    participant AC as Auth Client (HTTP)
    participant W as auth-worker

    RC->>RDO: EVENT kind=31400 (ActionRequest) — agent pubkey
    RDO->>RDO: is_registered_agent(pubkey) → SELECT active FROM agent_registry [nip_handlers.rs:1117]
    D1R-->>RDO: active=1
    RDO->>D1R: INSERT OR REPLACE INTO broker_cases (...) [nip_handlers.rs:1144]

    RC->>RDO: EVENT kind=31403 (ActionResponse) — admin pubkey
    RDO->>RDO: governance_response_blocked check (is_admin required)
    RDO->>D1R: INSERT OR IGNORE INTO broker_decisions (...) [nip_handlers.rs:1187]
    RDO->>D1R: UPDATE broker_cases SET state=resolved/rejected [nip_handlers.rs:1207]

    AC->>W: GET /api/governance/cases[?state=open]
    W->>W: require_authed() [governance_api.rs:372]
    W->>D1R: SELECT * FROM broker_cases [WHERE state=?] ORDER BY updated_at DESC LIMIT 100 [governance_api.rs:383-394]
    D1R-->>W: rows
    W-->>AC: 200 {"cases":[...]}

    AC->>W: GET /api/governance/cases/:id
    W->>W: require_authed() [governance_api.rs:404]
    W->>D1R: SELECT * FROM broker_cases WHERE id=? [governance_api.rs:409]
    D1R-->>W: row or None
    W-->>AC: 200 {"case":{...}} or 404
```

---

## 3. Device-Key Registry Lifecycle (ADR-099)

All three handlers are gated by `DEVICE_KEYS_ENABLED == "true"` (exact string,
default off). The `device_keys` table lives in `RELAY_DB` (nostr-bbs-relay D1)
so the relay DO can read it at NIP-42 AUTH without a cross-worker call.

Sources: `devices.rs:1-320`

```mermaid
sequenceDiagram
    participant U as Member Client
    participant W as auth-worker
    participant G as device_keys_enabled() [devices.rs:51]
    participant T as ensure_device_table() [devices.rs:63]
    participant D1R as D1: nostr-bbs-relay (RELAY_DB — device_keys)
    participant RDOA as nostr-bbs-relay DO [nip_handlers.rs:1064]

    Note over W,D1R: All three endpoints check gate first

    U->>W: POST /api/devices/register  Body: {device_pubkey, label?}
    W->>G: DEVICE_KEYS_ENABLED == "true"? [devices.rs:166]
    G-->>W: false → 404 {"error":"device keys disabled"} (default)

    Note over W,D1R: When DEVICE_KEYS_ENABLED=true:
    W->>W: require_authed() → owner_pk = NIP-98 author [devices.rs:171]
    Note over W: owner is NEVER taken from request body [devices.rs:9]
    W->>W: normalize_register(body) [devices.rs:181]
    Note over W: • device_pubkey: 64 hex, lowercased<br/>• label: trim, None if blank [devices.rs:111-125]
    W->>T: CREATE TABLE IF NOT EXISTS device_keys (...) [devices.rs:63]
    T->>D1R: DDL (idempotent)
    W->>D1R: INSERT INTO device_keys (device_pubkey, owner_pubkey, label, created_at, revoked=0)<br/>ON CONFLICT (device_pubkey) DO UPDATE SET owner_pubkey=exc, label=exc, created_at=exc, revoked=0 [devices.rs:197-213]
    D1R-->>W: ok
    W-->>U: 200 {device_pubkey, owner_pubkey, label, revoked:0}

    U->>W: GET /api/devices
    W->>G: gate check [devices.rs:231]
    W->>W: require_authed() → owner_pk [devices.rs:236]
    W->>T: ensure_device_table
    W->>D1R: SELECT ... FROM device_keys WHERE owner_pubkey=? ORDER BY created_at DESC [devices.rs:245-252]
    D1R-->>W: rows
    W-->>U: 200 {"devices":[...]}

    U->>W: POST /api/devices/revoke  Body: {device_pubkey}
    W->>G: gate check [devices.rs:268]
    W->>W: require_authed() → owner_pk [devices.rs:272]
    W->>W: normalize_revoke_target(device_pubkey) [devices.rs:282]
    W->>T: ensure_device_table
    W->>D1R: UPDATE device_keys SET revoked=1<br/>WHERE device_pubkey=? AND owner_pubkey=? [devices.rs:295]
    Note over D1R: ownership enforced in WHERE clause [devices.rs:292]<br/>meta.changes == 0 → 404 (device not yours / not found)
    D1R-->>W: meta.changes
    W-->>U: 200 {device_pubkey, owner_pubkey, revoked:1} or 404

    Note over RDOA,D1R: Relay DO reads device_keys at NIP-42 AUTH
    RDOA->>RDOA: effective_pubkey(incoming_pubkey) [nip_handlers.rs:1098]
    alt DEVICE_KEYS_ENABLED=true
        RDOA->>D1R: SELECT owner_pubkey FROM device_keys<br/>WHERE device_pubkey=? AND revoked=0 LIMIT 1 [nip_handlers.rs:1080]
        D1R-->>RDOA: owner_pubkey or None
        RDOA->>RDOA: treat owner_pubkey as the effective principal for whitelist/zone checks
    end
```

---

## 4. Findings

Each finding has: severity (HIGH/MEDIUM/LOW/INFO), file:line, description, and
classification.

---

**Finding 1 — HIGH | isolated**
`crates/nostr-bbs-auth-worker/wrangler.toml` (entire file, no `RELAY_DB` stanza)

`governance_api.rs` and `devices.rs` both call `env.d1("RELAY_DB")` at runtime, and
`admin.rs:69` also reads `RELAY_DB` for `whitelist.is_admin`. None of these bindings
appear in `wrangler.toml`. At deploy time every call to `env.d1("RELAY_DB")` will
return `Err`, which propagates as a `worker::Error` and eventually returns a 500. The
entire governance surface (`/api/governance/*`), device-key surface (`/api/devices/*`),
and admin-flag checks are silently broken in the deployed worker until the binding is
added. The relay worker correctly declares `RELAY_DB` pointing at `nostr-bbs-auth`
(for replay protection), but the auth worker's separate `RELAY_DB` — which must point
at `nostr-bbs-relay` (`97c77d23-...`) — has no `[[d1_databases]]` entry.

---

**Finding 2 — HIGH | duplicate**
`crates/nostr-bbs-auth-worker/src/lib.rs:45-69` vs `crates/nostr-bbs-auth-worker/src/http.rs:8-27`

Two `cors_headers()` implementations exist in the same crate. The `lib.rs` version
is fail-closed: when `EXPECTED_ORIGIN` is unset it emits **no** `Access-Control-Allow-Origin`
header (the safe behaviour documented at `lib.rs:38-44`). The `http.rs` version
fallback-fills `"https://example.com"` (`http.rs:12`). Every sprint module (moderation,
wot, invites, welcome, admins, governance, devices) imports from `http.rs` via
`crate::http::json_response`, meaning their CORS responses silently grant `example.com`
on misconfigured deploys — contradicting the hardening note in `lib.rs`. The `lib.rs`
version is only used by the legacy `/api/profile` branch and CORS-preflight path.

---

**Finding 3 — MEDIUM | isolated**
`crates/nostr-bbs-auth-worker/src/delegation.rs:26-38`, routed at `lib.rs:582-585`

`POST /api/delegation/verify` is registered in the router and responds `501 Not Implemented`.
No client in the repo calls this endpoint (confirmed by grep across all crates). The
route carries no auth requirement: `_auth_header` is ignored. This is stub scaffolding
from a deferred work item (NIP-26 delegation, commented "W6") that has no consumer,
exercises no logic, and cannot be tested end-to-end.

---

**Finding 4 — MEDIUM | legacy**
`crates/nostr-bbs-auth-worker/wrangler.toml:29-30` — `KV` binding

The `KV` namespace binding (`id = 901345296c2848788066686aa67d5909`) resolves to the
same physical KV namespace as `SESSIONS` (`id = 901345296c2848788066686aa67d5909`).
The comment says "Legacy alias used by admins.rs cache". `admins.rs:54` uses `env.kv("KV")`
to read/write the `admin_pubkeys_cache` key. Since `KV` and `SESSIONS` are the same
namespace, the rate-limit counter bucket and the admin-pubkey cache share a namespace
and a keyspace. A key collision (e.g. if an IP address coincidentally matches
`admin_pubkeys_cache`) would corrupt the admin cache or inflate rate-limit counters.

---

**Finding 5 — MEDIUM | doc-drift**
`crates/nostr-bbs-auth-worker/src/governance_api.rs:25-31`

The module doc comment states "broker_decisions" lives in `RELAY_DB`. The handler
`handle_list_cases` and `handle_get_case` read `broker_cases` from `RELAY_DB` via
the governance API, but `broker_decisions` (the append-only audit trail of individual
decisions) has **no read endpoint** in the auth-worker. The relay DO writes to
`broker_decisions` (`nip_handlers.rs:1187`) and the auth-worker references it in
comments, but there is no `GET /api/governance/decisions` or equivalent. Callers who
want the decision trail must query D1 directly.

---

**Finding 6 — LOW | duplicate**
`crates/nostr-bbs-auth-worker/src/governance_api.rs:199-203` vs `governance_api.rs:87-92`

`handle_register_agent` (`governance_api.rs:199-203`) performs pubkey/name validation
inline using copied if-blocks. `handle_provision_agent` (`governance_api.rs:276`) calls
the extracted `normalize_provision()` which is unit-tested (`governance_api.rs:544-642`).
The `register` path's inline validation is functionally equivalent but untested in the
same way: a future change to validation rules would need to be applied in two places.

---

**Finding 7 — LOW | ok (cross-worker D1 sharing — explicit note)**
`crates/nostr-bbs-relay-worker/src/relay_do/nip_handlers.rs:1072` reads `device_keys`
from `self.env.d1("DB")` (the relay's own D1, `nostr-bbs-relay`).
`crates/nostr-bbs-auth-worker/src/devices.rs:44` writes `device_keys` via `env.d1("RELAY_DB")`
(which is the same physical D1 when the binding is correctly declared, see Finding 1).
This cross-worker D1 sharing is **intentional** and documented in `devices.rs:26-31` and
`governance_api.rs:25-31`. The relay reads; the auth-worker writes. There is no
cross-worker D1 transaction; both ends are designed to tolerate eventual consistency
within a single D1 write (which is synchronous from D1's perspective).

---

**Finding 8 — LOW | isolated**
`crates/nostr-bbs-auth-worker/src/lib.rs:588-592` — `POST /api/native-pod/provision`

This endpoint (`handle_native_pod_provision`, `lib.rs:639-758`) requires `NATIVE_POD_URL`
and `NATIVE_POD_ADMIN_KEY` env vars (`lib.rs:712-732`). Neither is declared in
`wrangler.toml`. The endpoint returns `503 {"error":"native pod not configured"}` when
either is missing — a proper fail-closed response — but the endpoint is effectively
always disabled on the current deploy configuration. The forum client's
`pod_browser.rs:19` reads `NATIVE_POD_URL` as a build-time `option_env!` constant,
not as a runtime auth-worker call, so there is no client-side HTTP consumer for this
auth-worker route.

---

**Finding 9 — INFO | ok**
`crates/nostr-bbs-auth-worker/src/lib.rs:180-181` — `ensure_schema()` called on every cold start

`schema.rs:ensure_schema()` runs every cold start, issuing `CREATE TABLE IF NOT EXISTS`
for ~14 table/index DDL statements against `DB`. The relay's `ensure_tables_exist()`
independently manages the governance tables (`lib.rs:630-707` in the relay crate). There
is no coordination between the two, which is correct: they target different D1
databases and neither can safely create the other's tables.

---

**Finding 10 — INFO | isolated**
`crates/nostr-bbs-relay-worker/src/trust.rs:287` — `check_demotion()` is `#[allow(dead_code)]`

`check_demotion()` is implemented but never called. `check_promotion()` is called from
`nip_handlers.rs` after qualifying events, but the symmetric demotion pass has no
scheduled invocation (the cron at `crates/nostr-bbs-relay-worker/wrangler.toml` runs
`scheduled()` every 5 minutes but does not invoke `check_demotion`). Demotion logic
exists only in tests; no user can be automatically demoted in the current deployment.
This is not in scope for the auth-worker audit but is directly adjacent to the
governance trust model.

---

## D1 Table / Binding Cross-Reference

| Table | Physical D1 | Writer(s) | Reader(s) |
|-------|-------------|-----------|-----------|
| `whitelist` | nostr-bbs-relay (RELAY_DB in auth, DB in relay) | auth-worker `/api/admins/add`, `/api/governance/agents/provision` | relay DO trust checks, auth `is_admin()` |
| `agent_registry` | nostr-bbs-relay | auth-worker `/api/governance/agents/register`, `/provision` | relay DO `is_registered_agent()` |
| `broker_cases` | nostr-bbs-relay | relay DO (kinds 31400, 31402 events) | auth-worker `/api/governance/cases/*` |
| `broker_decisions` | nostr-bbs-relay | relay DO (kind 31403 events) | **no HTTP read endpoint** (Finding 5) |
| `broker_roles` | nostr-bbs-relay | auth-worker `/api/governance/roles/grant` | auth-worker `/api/governance/roles` list |
| `device_keys` | nostr-bbs-relay | auth-worker `/api/devices/register`, `/revoke` | relay DO `device_owner()` at NIP-42 AUTH |
| `nip98_replay` | nostr-bbs-auth (DB in auth, REPLAY_DB in relay) | both workers atomically via `INSERT OR IGNORE` | both workers (same table = cross-worker replay detected) |
| `members` | nostr-bbs-auth | auth-worker invite redemption, `/api/admins/add` | auth-worker `is_admin()` |
| `moderation_actions` | nostr-bbs-auth | auth-worker `/api/mod/ban` etc. | auth-worker `/api/mod/actions` list |
| `mod_reports` | nostr-bbs-auth | auth-worker `/api/mod/report` | auth-worker `/api/mod/reports` list |
| `wot_entries` | nostr-bbs-auth | auth-worker `/api/wot/*` | auth-worker wot module |
| `instance_settings` | nostr-bbs-auth | auth-worker welcome/wot configure | auth-worker welcome/wot status |
| `username_reservations` | nostr-bbs-auth | auth-worker `/api/username/claim` | auth-worker `/api/username/check`, `/resolve` |
| `nip1984_reports` | nostr-bbs-auth | relay-worker (kind-1984 event projection — **written by relay, not auth**) | auth-worker `GET /api/moderation/reports` |
| `challenges` | nostr-bbs-auth | auth-worker WebAuthn register flow | auth-worker WebAuthn auth flow |
| `webauthn_credentials` | nostr-bbs-auth | auth-worker WebAuthn register/verify | auth-worker login flows |
