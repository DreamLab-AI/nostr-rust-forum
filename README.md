# nostr-rust-forum — Decentralized Forum Kit on Nostr

A full-stack, open-source forum kit built on the Nostr protocol. Passkey-first
authentication, Solid pod storage, config-driven zone access with cohort
gating, tiered NIP-52 calendars, semantic search, and Cloudflare Workers
backend — all in Rust. Operators consume this kit by creating a
`forum-config/` package that overlays branding, zones, and deployment config.

**Maintainer**: [John O'Hare](https://github.com/jjohare) · **Upstream IP**: [Melvin Carvalho](https://github.com/melvincarvalho) ([JSS](https://github.com/JavaScriptSolidServer/JavaScriptSolidServer), [DID:Nostr](https://github.com/nicholasgasior/did-nostr)) · [MAINTAINERS.md](MAINTAINERS.md)

**Current release:** `v1.0.0-beta.2` (see [CHANGELOG.md](CHANGELOG.md)) — `main`
additionally carries the June 2026 zones/calendar/search sprint described
below (`3503eeb..6f9c2d0`).

## Screenshots

Captured from a live deployment, signed in as a `friends`-cohort member.

![Zone tiles as seen by a friends-cohort member](docs/screenshots/forum-zones-friends-view.webp)
*Config-driven zone tiles with hero banners. The viewer holds the `friends`
cohort: the public zone and the Friends zone render as enterable tiles;
Family and DreamLab (business) render as greyed locked tiles — definitions
served, content withheld by the relay.*

![Friends zone section chat](docs/screenshots/forum-section-friends-chat.webp)
*Inside a cohort-gated section. Kind-42 messages are served only after NIP-42
AUTH establishes the session's cohorts. Identity chips use the shared
display-name resolution (display_name > name > NIP-05 > short pubkey) —
seeded test users without kind-0 metadata render as the short-pubkey
fallback shown here, and fill in reactively when metadata arrives.*

![Events page with free/busy projection](docs/screenshots/forum-events-freebusy-friends.webp)
*Tiered NIP-52 calendar for a friends-cohort viewer: their own circle's
events appear in full detail (title, time, RSVP), while family/business
events at a shared venue are projected down to anonymous free/busy blocks —
start/end and venue only, title and participants stripped by the relay.*

## Capability Overview (June 2026)

The `3503eeb..6f9c2d0` sprint replaced the last hardcoded access model with a
fully config-driven one and hardened the live read path end to end:

- **Config-driven zones** — `Zone { id, display_name, required_cohorts,
  write_cohorts, banner_image_url, visibility, encrypted }` in
  `nostr-bbs-config`. The relay enforces from a `ZONE_CONFIG` env var
  (deny-by-default); the client renders banner-headed tiles from
  `window.__ENV__.ZONE_CONFIG`. Arbitrary private sections plus a public
  landing are now data, not code.
- **Per-tier read/write gating** — read access from `required_cohorts`,
  write access from `write_cohorts ?? required_cohorts`; admins bypass;
  unauthenticated readers are limited to `public` zones; kind-40 channel
  definitions are filtered for `hidden` zones so non-members cannot
  enumerate them. A NIP-98 admin route (`POST /api/admin/channel-zone`) is
  the sole channel→zone mapping write path (UPSERT + audit trail).
- **Tiered NIP-52 calendar** — events carry `["zone", <slug>]` and optional
  `["venue", <name>]` tags; the relay projects each event per viewer cohort
  into full / free-busy / omit. The projector is the *complete* access
  decision for calendar kinds (no upstream zone gate). RSVPs are served only
  when the viewer's tier for the target event is Full, and the target's
  zone/venue resolve exclusively from the stored referenced event —
  author-mirrored zone tags cannot spoof access. Kind 31922 (date-based)
  joins 31923; `to_free_busy()` strips title/location/content/participants.
- **Semantic search** — the search worker embeds via Cloudflare Workers AI
  `@cf/baai/bge-small-en-v1.5` (384-dim, worker 0.8.1 native `Ai` binding),
  L2-normalized for cosine k-NN. The hash embedder remains only as an
  explicit fallback when the binding is absent, and `/status` truthfully
  reports which model is active.
- **Display-name resolution everywhere** — a single tracked/reactive
  resolution path (`user_display`: display_name > name > NIP-05 > short
  pubkey) now backs all 26 former raw-pubkey render sites: nav identity chip
  (shows the claimed username), event cards, admin tables, chat, mentions
  (`@hex` and `nostr:npub1` both resolve), search, bookmarks, typing
  indicators. Names fill in as kind-0 metadata arrives.
- **Live read-path fixes** — REQs opened before the NIP-42 handshake are
  replayed after AUTH (sections no longer show "0 messages" for the session
  lifetime); D1 tag filters use `instr()` instead of `LIKE` (D1 rejected the
  escaped LIKE pattern as "too complex" and silently broke **all** `#e`/`#p`
  subscriptions); RSVP clicks no longer panic the WASM runtime (contexts
  resolved at component construction, not inside `spawn_local`).

## Zones & Cohorts

Zones are the kit's access primitive. A zone is a named group of channels
gated by cohort membership; cohorts are string slugs stored on the relay
whitelist (`whitelist.cohorts`) and granted via the NIP-98 admin API. The
zone list is operator data, defined once in the deployment's `forum.toml`
and fanned out to both enforcement points:

```mermaid
flowchart LR
    subgraph operator["forum-config (operator overlay)"]
        TOML["forum.toml<br/>[[zones]] blocks"]
    end
    TOML -->|serialized JSON| ZC["ZONE_CONFIG"]
    ZC -->|env var| RELAY["relay-worker<br/>deny-by-default gate"]
    ZC -->|window.__ENV__| CLIENT["forum-client<br/>banner tiles"]
    RELAY -->|"REQ filter: read gate,<br/>kind-40 visibility filter"| WS["WebSocket sessions"]
    RELAY -->|"EVENT gate:<br/>write_cohorts"| WS
    CLIENT -->|"locked-tile treatment,<br/>hidden zones omitted"| UI["Zone tiles UI"]
```

The client renders what the config describes; **the relay is the real access
boundary**. Visibility controls what non-members can see of a zone's
existence:

| `visibility` | Listed to non-members | Content readable | Kind-40 definition served |
|--------------|----------------------|------------------|---------------------------|
| `public` | Yes | Yes (no auth required) | Yes |
| `locked` (default) | Yes — greyed banner tile | No | Yes (so the tile renders) |
| `hidden` | No | No | No |

Read/write access per viewer:

| Viewer | Read zone content | Write to zone |
|--------|-------------------|---------------|
| Admin | Always | Always |
| Member of a `required_cohorts` entry | Yes | If member of `write_cohorts ?? required_cohorts` |
| Authenticated, no matching cohort | `public` zones only | `public` zones only if cohort matches `write_cohorts` |
| Unauthenticated | `public` zones only | No |

A `public` zone with `write_cohorts = ["friends"]` gives the common pattern
of an openly readable landing zone that only an inner circle can post to.
The `encrypted` flag marks a zone's content as client-side NIP-44 encrypted;
the relay records the flag only.

## Tiered NIP-52 Calendar

Calendar events (kinds 31922/31923) bind to a zone via a `["zone", <slug>]`
tag and optionally to a shared venue via `["venue", <name>]`. The relay's
projector (`relay_do/calendar_projection.rs`) decides, for every
(viewer, event) pair, one of three outcomes — and it is the complete access
decision for calendar kinds, deny-by-default for unknown zones:

```mermaid
flowchart TD
    REQ["Calendar REQ from viewer"] --> OWN{"viewer is owner<br/>or admin?"}
    OWN -- yes --> FULL["Full — event served unchanged"]
    OWN -- no --> COHORT{"viewer cohort"}
    COHORT -- family --> FULL
    COHORT -- friends --> FZ{"event zone"}
    FZ -- "friends / public" --> FULL
    FZ -- "family / business" --> VENUE{"at a recognised<br/>shared venue?"}
    VENUE -- yes --> FB["FreeBusy — to_free_busy():<br/>start/end/venue/busy only"]
    VENUE -- no --> OMIT["Omit — viewer unaware<br/>the event exists"]
    FZ -- unknown --> OMIT
    COHORT -- business --> BZ{"event zone"}
    BZ -- "business / public" --> FULL
    BZ -- "family / friends / unknown" --> OMIT
    COHORT -- "none / anon" --> PZ{"event zone"}
    PZ -- public --> FULL
    PZ -- other --> OMIT
```

The projection matrix (operator-approved, encoded in 25 unit tests):

| Viewer ↓ / Event zone → | family | business | friends | public | unknown |
|-------------------------|--------|----------|---------|--------|---------|
| admin / owner | full | full | full | full | full |
| family | full | full | full | full | full |
| friends | free/busy\* | free/busy\* | full | full | omit |
| business | omit | full | omit | full | omit |
| no cohort / anon | omit | omit | omit | full | omit |

\* Friends see family/business events as free/busy **only at a recognised
shared venue**; off-site events are omitted — friends see venue blocking,
never private off-site time.

`to_free_busy()` keeps start/end, venue, and a busy flag; it strips title,
location, content, and participants, and clears the signature (the result is
a derived view, not the signed original). **RSVPs (kind 31925) are served
only when the viewer's tier for the target event is Full** — participant
lists must not leak through a free/busy block — and the target's zone and
venue resolve exclusively from the stored referenced event, so a spoofed
zone tag mirrored onto the RSVP cannot widen access. An unresolvable target
serves only admin/owner.

## Architecture

Twelve crates in a Cargo workspace:

| Crate | Type | Purpose |
|-------|------|---------|
| `nostr-bbs-core` | Library | Shared Nostr protocol: NIP-01/07/09/29/33/40/42/44/45/50/52/98, key management, event validation, NIP-52 zone/venue tags + `to_free_busy()`, governance domain model (kinds 31400-31405), WASM bridge |
| `nostr-bbs-config` | Library | Operator configuration schema: zone definitions (visibility, cohorts, banners, encryption flag), deployment topology |
| `nostr-bbs-mesh` | Library | Private relay mesh federation, NIP-42 AUTH gate, peer discovery |
| `nostr-bbs-setup-skill` | Library | Provider-abstracted AI configurator for operator onboarding |
| `nostr-bbs-auth-worker` | CF Worker | WebAuthn register/login (passkey), NIP-98 verification, pod provisioning (CF + native-tier admin provisioning), governance REST API (agent registry, broker cases, roles), rate limiting (D1 + KV + R2) |
| `nostr-bbs-pod-worker` | CF Worker | Solid pod storage: LDP containers, WAC ACL, JSON Patch, conditional requests, quotas, WebID, micropayments (R2 + KV) |
| `nostr-bbs-preview-worker` | CF Worker | Link preview with SSRF protection, OG/meta parsing, oEmbed, rate limiting |
| `nostr-bbs-relay-worker` | CF Worker | NIP-01 WebSocket relay via Durable Objects, hibernation-safe sessions, config-driven zone gating (`zone_config.rs`), tiered calendar projection (`calendar_projection.rs`), agent registry gate, governance event routing (kinds 31400-31405), subscription persistence (D1 + DO) |
| `nostr-bbs-search-worker` | CF Worker | Semantic vector search via Workers AI BGE-small embeddings, RVF binary format, in-memory cosine k-NN, rate limiting (R2 + KV) |
| `nostr-bbs-rate-limit` | Library | Shared application-layer rate limiting via Cloudflare KV, consumed by all workers |
| `nostr-bbs-forum-client` | Leptos App | Browser client (Leptos 0.7 CSR + Trunk), passkey auth, 22 pages, 60+ components, config-driven zone tiles, reactive display-name resolution, admin panel (incl. NativePods tab), pod browser with VS Code-style GitPanel + AppManifestPanel, governance dashboard with PanelRegistry |
| `nostr-bbs-upstream-canary` | Test | Validates upstream `nostr` crate compatibility on WASM/CF Workers build matrix |

## Crate Dependency Graph

```
nostr-bbs-forum-client ----+
nostr-bbs-auth-worker  ----+
nostr-bbs-relay-worker ----+--> nostr-bbs-core
nostr-bbs-pod-worker   ----+
nostr-bbs-search-worker ---+
nostr-bbs-config ------------> nostr-bbs-core
nostr-bbs-mesh --------------> nostr-bbs-core + nostr-bbs-config
nostr-bbs-rate-limit --------> nostr-bbs-core (shared KV rate limiter)
nostr-bbs-preview-worker       (standalone)
nostr-bbs-upstream-canary      (standalone, publish = false)
```

## Features

- **Config-driven zones** -- Arbitrary cohort-gated sections defined in operator config; banner tiles, locked/hidden visibility tiers, per-zone write cohorts, deny-by-default relay enforcement
- **Tiered NIP-52 calendar** -- Per-cohort full / free-busy / omit projection with venue awareness and anti-spoof RSVP gating
- **Agent Control Surface Protocol** -- Agents publish interactive control panels (kinds 31400-31405) to the relay; the forum renders them as decision surfaces with approve/reject/configure actions, creating a universal human-in-the-loop governance plane
- **Passkey-first auth** -- WebAuthn PRF extension derives Nostr keys deterministically; private keys never stored
- **Recovery & device-onboarding sheet** -- Signup issues a 100% client-side printable one-page sheet (nsec/npub/relay QRs + restore steps + optional relay sweep), Save-as-PDF; 0xchat mobile on-ramp; insist-with-override gate (ADR-095)
- **Deterministic subkey derivation** -- `derive_subkey(root, tag)` = HMAC-SHA-256(root, tag) → validated secp256k1 key; one tested primitive (native + wasm) for rotatable, recoverable purpose-scoped keys, with JS-parity to agentbox (ADR-094)
- **First-user-is-admin** -- No hardcoded admin keys; first registrant gets admin privileges
- **Consolidated agent provisioning** -- `POST /api/governance/agents/provision` (NIP-98 admin) provisions whitelist + agent registry atomically in one D1 batch, replacing the four-call seed dance (ADR-097)
- **Solid pods** -- Per-user W3C-compliant storage with WAC ACL, LDP containers, and JSON Patch
- **Per-container pod delegation** -- Container `<dir>/.acl` resolution fix plus an opt-in `PUT {"@delegation":{agent,modes}}` grant that never confers Control and never locks the owner out (ADR-096)
- **Semantic search** -- Workers AI BGE-small embeddings with cosine k-NN over an RVF store
- **Display-name resolution** -- One reactive resolution path for every identity render site; `@hex` and `nostr:npub1` mentions resolve
- **Offline-first** -- Service worker + IndexedDB caching with 30-day eviction
- **WebGPU effects** -- 3-tier rendering: WebGPU compute > Canvas2D > CSS fallback
- **Micropayments** -- HTTP 402 + Web Ledgers for per-resource satoshi costs
- **Relay mesh** -- Private NIP-42 relay mesh for cross-system federation via `did:nostr`
- **Operator overlay** -- Operators inject branding, zones, and config via `forum-config/` without forking

## Operator Notes

### `ZONE_CONFIG`

The relay reads a `ZONE_CONFIG` env var (set in the deployment's
`wrangler.toml` `[vars]`) containing a JSON array — the serde serialization
of `nostr_bbs_config::schema::Zone`:

```json
[
  {
    "id": "public",
    "display_name": "MiniMooNoir",
    "required_cohorts": [],
    "write_cohorts": ["friends", "agent"],
    "banner_image_url": "/images/heroes/minimoonoir-hero.webp",
    "visibility": "public",
    "encrypted": false
  },
  {
    "id": "friends",
    "display_name": "Friends",
    "required_cohorts": ["friends"],
    "banner_image_url": "/images/heroes/minimoonoir-hero.webp",
    "visibility": "locked",
    "encrypted": false
  }
]
```

All fields except `id` and `display_name` are serde-defaulted:
`required_cohorts` defaults to `[]`, `write_cohorts` to absent (falls back
to `required_cohorts`), `visibility` to `"locked"`, `encrypted` to `false`.
The deploy pipeline injects the same JSON into the client as
`window.__ENV__.ZONE_CONFIG`, so the tiles and the gate always describe the
same model. When the config is absent the client falls back to the legacy
three-zone layout and the relay denies non-public reads — nothing regresses
open.

Channel→zone bindings are written exclusively through the NIP-98
admin route `POST /api/admin/channel-zone`.

### Consuming-repo dual pin (`KIT_REF` + Cargo `rev`)

A deployment repo pins this kit in **two places that must move together**:

1. `KIT_REF` in the deploy workflow — the kit git SHA the WASM forum client
   and workers are built from.
2. `rev = "<sha>"` on every `nostr-bbs-*` git dependency in
   `forum-config/Cargo.toml` — the kit crates the operator overlay compiles
   against.

A mismatch builds the client at one rev and the config overlay at another;
schema additions (e.g. new `Zone` fields) will silently deserialize to
defaults or fail the overlay build. Bump both in the same commit.

### CI gate policy

The kit CI requires two hard gates; the rest run as advisory
(`continue-on-error`, visible but non-blocking):

| Check | Status | Rationale |
|-------|--------|-----------|
| `cargo fmt --check` | **Hard gate** | Mechanical, zero-cost to keep green |
| `wasm32-unknown-unknown` check | **Hard gate** | The deploy-relevant target — what worker-build/trunk actually compile |
| clippy (`-D warnings`) | Advisory | Too strict for the evolving kit |
| workspace test suite | Advisory | Per-feature tests are run by each contributing change |
| rustdoc | Advisory | |
| cargo-deny | Advisory | Fails on the action's musl toolchain bootstrap (infra, not policy) |

## Phase 1 (May 2026)

The JSS Phase 1 cross-repo sprint (closed 2026-05-16) landed federated
identity, pod-resident key provisioning, and pod data export across
the ecosystem. From this kit's perspective:

- **Federated NIP-05 resolution** -- `nostr-bbs-auth-worker` resolves
  `/.well-known/nostr.json?name=<local>` against the local D1
  whitelist first and falls back to the user's pod over HTTP when
  `[nip05].resolver_mode = "federated"` (the new default; legacy
  operators can pin `"d1-only"`). The federated path is documented in
  [ADR-086 §9](docs/adr/ADR-086-nip05-pod-federation.md).
- **Schema-typed `[nip05]` config** -- `nostr-bbs-config` now exposes
  a first-class `Nip05Config` block (resolver mode, pod base URL,
  fallback timeouts, CORS policy). Operators wire it via
  `forum-config/`; runtime values flow into `wrangler.toml` as
  `NIP05_RESOLVER_MODE` and `POD_BASE_URL`.
- **solid-pod-rs JSS v0.0.197 alignment** -- workspace dependency is pinned
  to `solid-pod-rs` `0.4.0-alpha.17` (published on crates.io; earlier rc builds
  used git revisions `8668792` / `4ac7670`). The
  forum consumes the WASM-safe `core` surface and mirrors the new server
  browser contract in the Worker tier: JSS-compatible CORS, Solid auth
  challenge headers, exposed notification discovery, and an authenticated
  `POST /.pods` creation alias mapped to `/pods/{nostr-pubkey}/`.

Two follow-up ADRs are open:
[ADR-087](docs/adr/ADR-087-cf-workers-portable-cores.md) (draft) tracks
the CF-Workers portability gap in solid-pod-rs that currently blocks
shipping the pod-resident signup UX, data export UX, and NIP-05 badge
inside the CF Workers runtime.
[ADR-088](docs/adr/ADR-088-wac-turtle-serializer-quirk.md) (draft)
tracks a small bare-path IRI quirk in the upstream WAC Turtle
serializer.

### Phase 1 extension: git-pods (2026-05-16)

Upstream `solid-pod-rs` v0.4.0-alpha.12 (JSS #471) ships **git-auto-init**
at pod provisioning: pods become clone-able `git` repositories on
deployments that can spawn a `git init` subprocess (server-Tokio
runtimes, e.g. agentbox). The NRF kit surfaces the per-user clone
command on the Settings page so users on those deployments can see and
copy it. **The Cloudflare Workers tier cannot auto-init git** — no
process-spawning capability, no Tokio runtime, no `wasm32` target for
`tokio::process`. CF-Workers-provisioned pods remain LDP+R2 prefixes
with no git history; the clone URL is rendered with a caveat advising
that resolution depends on the operator's deployment.
[ADR-089](docs/adr/ADR-089-git-pods-cf-workers-limitation.md) (draft)
documents the option matrix and the shipping default (defer on CF
Workers; `gix`-on-R2 and external git-init sidecar tracked as future
options).

### JSS v0.0.197 HTTP parity surface (2026-05-17)

The pod-worker now follows the same browser-facing envelope as the native
`solid-pod-rs-server` for high-value Solid flows:

- `POD_CORS_HEADERS` exposes Solid, WAC, payment, and notification headers used
  by pod browser, upload, and agent clients.
- `401` Solid pod responses include `WWW-Authenticate: DPoP realm="Solid",
  Bearer realm="Solid"`.
- LDP responses include `Updates-Via` pointing at the Worker notification
  subscription sidecar for the requested resource.
- `POST /.pods` accepts `{"name":"<64-hex-nostr-pubkey>"}` with a matching
  NIP-98 signature and returns the JSS-shaped `{ name, webId, podUri }` body.
  The Worker intentionally keeps pod names tied to Nostr pubkeys because WAC
  ownership is `did:nostr:<pubkey>`.

## Agent Control Surface Protocol

The forum acts as a universal human-in-the-loop (HITL) control plane for any
agent system. Agents publish structured nostr events into the forum relay; the
forum renders them as interactive decision surfaces. Humans respond through the
same relay with cryptographically signed events.

```mermaid
sequenceDiagram
    participant Agent
    participant Relay as relay-worker (DO)
    participant Client as forum-client (WASM)
    participant Human

    Agent->>Relay: kind 31400 PanelDefinition
    Relay-->>Client: subscription (kinds 31400-31405)
    Agent->>Relay: kind 31402 ActionRequest
    Relay-->>Client: push to PanelRegistry
    Client-->>Human: render decision UI
    Human->>Client: approve / reject / configure
    Client->>Relay: kind 31403 ActionResponse (NIP-98 signed)
    Relay-->>Agent: subscription on kind 31403
```

**Event kinds (parameterized replaceable, `d`-tag addressable):**

| Kind  | Name            | Publisher | Purpose                                      |
|-------|-----------------|-----------|----------------------------------------------|
| 31400 | PanelDefinition | Agent     | Declare a control panel (schema, fields, actions, layout) |
| 31401 | PanelState      | Agent     | Publish current panel data snapshot           |
| 31402 | ActionRequest   | Agent     | Request a human decision (approve/reject/configure) |
| 31403 | ActionResponse  | Human     | Respond to an action request (signed by human's key) |
| 31404 | PanelUpdate     | Agent     | Incremental state diff                        |
| 31405 | PanelRetired    | Agent     | Retire a control panel                        |

**Trust model:**
- Agent pubkeys must be registered in the `agent_registry` D1 table (admin-gated)
- Governance events from unregistered agents are rejected at relay ingress
- Human responses require standard NIP-98 auth; broker-role users can act on any case
- Decisions are cryptographically signed nostr events -- immutable audit trail

**D1 governance schema** (4 tables, deployed via `0002_governance.sql` migration):
- `agent_registry` -- registered agent pubkeys with per-agent rate limits
- `broker_cases` -- case aggregate (category, subject, state, priority, assignment)
- `broker_decisions` -- append-only decision audit trail with provenance chain
- `broker_roles` -- role assignments (contributor, auditor, broker, admin)

**REST API** (8 endpoints on auth-worker, all NIP-98 gated):

| Method | Path                            | Gate  | Purpose                  |
|--------|---------------------------------|-------|--------------------------|
| GET    | /api/governance/agents          | any   | List registered agents   |
| POST   | /api/governance/agents/provision| admin | Atomic whitelist + registry provisioning (ADR-097) |
| POST   | /api/governance/agents/register | admin | Register an agent pubkey |
| POST   | /api/governance/agents/revoke   | admin | Deactivate an agent      |
| GET    | /api/governance/cases           | any   | List broker cases        |
| GET    | /api/governance/cases/:id       | any   | Get a single broker case |
| POST   | /api/governance/roles/grant     | admin | Grant a broker role      |
| GET    | /api/governance/roles           | any   | List role assignments    |

See [docs/architecture.md](docs/architecture.md) for data flow diagrams and
[docs/sprint/enterprise-lift-value-assessment.md](docs/sprint/enterprise-lift-value-assessment.md)
for the full ADR and protocol specification.

## NIP Coverage

The relay advertises its supported NIPs in the NIP-11 information document
(`crates/nostr-bbs-relay-worker/src/nip11.rs`): `1, 9, 11, 16, 29, 33, 40,
42, 45, 50, 56, 59, 65, 90, 98`.

| NIP | Description | Crate |
|-----|-------------|-------|
| 01 | Basic protocol, event signing | nostr-bbs-core, nostr-bbs-relay-worker |
| 07 | Browser extension signer | nostr-bbs-forum-client |
| 09 | Event deletion | nostr-bbs-core, nostr-bbs-relay-worker |
| 11 | Relay information document | nostr-bbs-relay-worker |
| 16 | Event treatment (replaceable/ephemeral) | nostr-bbs-relay-worker |
| 17 | NIP-59 gift-wrap transport only (NIP-17 inbox routing not implemented) | nostr-bbs-core, nostr-bbs-relay-worker |
| 29 | Relay-based groups | nostr-bbs-core, nostr-bbs-relay-worker |
| 33 | Parameterized replaceable events | nostr-bbs-core, nostr-bbs-relay-worker |
| 40 | Expiration timestamp | nostr-bbs-core, nostr-bbs-relay-worker |
| 42 | Authentication of clients to relays | nostr-bbs-relay-worker, nostr-bbs-mesh, nostr-bbs-forum-client (post-AUTH subscription replay) |
| 44 | Encrypted payloads v2 | nostr-bbs-core |
| 45 | Event counts | nostr-bbs-relay-worker |
| 50 | Search capability (semantic, Workers AI embeddings) | nostr-bbs-search-worker |
| 52 | Calendar events (kinds 31922/31923, tiered per-cohort projection) | nostr-bbs-core, nostr-bbs-relay-worker |
| 56 | Reporting (kind-1984, relay-enforced moderation) | nostr-bbs-relay-worker |
| 59 | Gift wrap | nostr-bbs-core, nostr-bbs-relay-worker |
| 65 | Relay list metadata | nostr-bbs-relay-worker |
| 90 | Data vending machines | nostr-bbs-relay-worker |
| 98 | HTTP Auth | nostr-bbs-core, all workers |
| app:31400-31405 | Agent Control Surface Protocol | nostr-bbs-core, nostr-bbs-relay-worker, nostr-bbs-auth-worker, nostr-bbs-forum-client |

The relay's NIP-11 document also carries a `dreamlab.agent_control_surface`
namespaced extension block advertising the governance kinds (31400-31405,
sourced from `nostr_bbs_core::governance` constants), `agent_auth = "nip98"`,
and `agent_identity = "did:nostr"`, so a NIP-11-reading agent can discover the
mesh's agent control surface and its registry gate.

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
cd crates/nostr-bbs-forum-client && trunk serve
```

See [SETUP.md](SETUP.md) for full deployment instructions.

## Federation Transports

nostr-rust-forum participates in two of the three DreamLab federation transport strata. As a Cloudflare Workers application, it cannot join a Tailscale tailnet directly.

### Stratum 2 — Nostr Relays (All Components)

The `nostr-bbs-mesh` crate connects to peer relays over standard NIP-01 WebSocket. Relay addresses can be private infrastructure relays (reachable over Tailscale between agentboxes) or public Nostr relays for censorship-resistant message passing.

```toml
# forum.toml / dreamlab.toml
[mesh]
mode = "federated"
peer_relays = [
    "ws://agentbox.tailnet-name.ts.net:7777",   # Agentbox relay (private, via Tailscale between agentboxes)
    "wss://relay.damus.io",                       # Public relay (censorship resistance)
]
```

The forum's CF Workers relay (Durable Objects) bridges between the browser WebSocket sessions and the wider relay mesh. Governance events (kinds 31400-31405) propagate from agentbox and VisionClaw through the mesh to the forum's governance dashboard.

All relay traffic is authenticated via NIP-98/NIP-42 `did:nostr` Schnorr signatures — authentication is independent of transport.

### Stratum 3 — Cloudflare Tunnels (Edge ↔ Local)

CF Workers reach local solid-pod-rs and agentbox instances through Cloudflare tunnels. The pod-worker uses tunnel-routed HTTPS for federated NIP-05 resolution, pod resource access, and the `.pods` creation endpoint.

```
CF Workers → CF Tunnel → solid-pod-rs (local)    # Pod reads/writes
CF Workers → CF Tunnel → agentbox (local)         # Relay mesh bridge
```

### Cross-Network Architecture

```
┌─────────────────────┐     ┌─────────────────────┐
│  CF Workers (forum)  │     │  Agentbox (local)    │
│  - relay-worker     │     │  - nostr-rs-relay    │
│  - pod-worker       │     │  - solid-pod-rs      │
│  - auth-worker      │     │  - management-api    │
└────────┬────────────┘     └────────┬─────────────┘
         │ CF Tunnel (HTTPS)          │ Tailscale (WireGuard)
         │                            │
         ▼                            ▼
   ┌───────────┐              ┌───────────────┐
   │ solid-pod │              │ Other agentbox │
   │   (local) │              │   instances    │
   └───────────┘              └───────────────┘
         ▲                            ▲
         │         Nostr Relays        │
         └────────── (NIP-01) ─────────┘
```

## Pod Storage Tiers

Pods resolve across two tiers, routed by WebID (ADR-093). NIP-98 provides
cross-tier authentication without shared state.

| Tier | Backend | Git | Provisioning |
|------|---------|-----|--------------|
| CF Workers | `nostr-bbs-pod-worker` — LDP containers on R2 | None (no `tokio::process`, no `wasm32` git target) | `POST /.pods` (NIP-98) |
| Native | `solid-pod-rs-server` on agentbox, fronted by a Cloudflare Tunnel | Smart HTTP git transport at `/_git/<pubkey>/` | `POST /api/native-pod/provision` (admin NIP-98) → native `/_admin/provision/<pubkey>` |

The native tier is gated by the `[native_pod]` config section
(`enabled`, `base_url`, `allowlist_cohorts`, `git_enabled`,
`admin_provision_url`) and is disabled by default. The pod browser
(`pages/pod_browser.rs`) probes the native server on mount; when reachable it
renders two extra panes below the CF Workers pod:

- **GitPanel** (`components/git_panel.rs`) — a VS Code-style Source Control
  surface: staged/unstaged/untracked sections, per-file stage/unstage/discard/
  diff, inline diff viewer, commit box, and lazy commit history.
- **AppManifestPanel** — reads/writes `apps/manifest.json` via NIP-98
  (JSS #464, apps as first-class pod repositories).

See [docs/adr/ADR-093-native-pod-mesh.md](docs/adr/ADR-093-native-pod-mesh.md)
for the two-tier decision and [docs/architecture.md](docs/architecture.md) for
the WebID-based tier routing.

## Part of VisionFlow

nostr-rust-forum is the **forum kit and governance UI** of the [VisionFlow](https://github.com/DreamLab-AI/VisionFlow) coordination platform — a federated architecture for human–AI intelligence built on `did:nostr` identity, OWL 2 EL reasoning, and Nostr message passing.

| Substrate | Repository | Role |
|:----------|:-----------|:-----|
| **VisionFlow** | [DreamLab-AI/VisionFlow](https://github.com/DreamLab-AI/VisionFlow) | Ecosystem guide and coordination architecture |
| **VisionClaw** | [DreamLab-AI/VisionClaw](https://github.com/DreamLab-AI/VisionClaw) | Knowledge engineering — OWL 2 EL, 92 CUDA kernels, XR |
| **Agentbox** | [DreamLab-AI/agentbox](https://github.com/DreamLab-AI/agentbox) | Harness engineering — Nix, 90+ skills, sovereign pods |
| **solid-pod-rs** | [DreamLab-AI/solid-pod-rs](https://github.com/DreamLab-AI/solid-pod-rs) | Cryptographic foundation — JSS Rust port, DID:Nostr |
| **nostr-rust-forum** | **[DreamLab-AI/nostr-rust-forum](https://github.com/DreamLab-AI/nostr-rust-forum)** | **Forum kit — passkey auth, governance events** |
| **dreamlab-ai-website** | [DreamLab-AI/dreamlab-ai-website](https://github.com/DreamLab-AI/dreamlab-ai-website) | Branded deployment — React, WASM, Cloudflare Workers |

## Documentation

- [SETUP.md](SETUP.md) -- Full deployment guide (Cloudflare resources, DNS, client build)
- [CHANGELOG.md](CHANGELOG.md) -- Release history
- [CONTRIBUTING.md](CONTRIBUTING.md) -- How to contribute
- [SECURITY.md](SECURITY.md) -- Responsible disclosure policy
- [docs/architecture.md](docs/architecture.md) -- Architecture overview, request lifecycle, data flow, governance event routing
- [docs/sprint/enterprise-lift-value-assessment.md](docs/sprint/enterprise-lift-value-assessment.md) -- Agent Control Surface Protocol ADR, value assessment, sprint plan
- [docs/sprint/milestone-0-sso-parity.md](docs/sprint/milestone-0-sso-parity.md) -- NIP-98 cross-repo SSO parity report

## License

Licensed under [AGPL-3.0-only](LICENSE), inherited from upstream JSS
([JavaScriptSolidServer](https://github.com/JavaScriptSolidServer/JavaScriptSolidServer)).
