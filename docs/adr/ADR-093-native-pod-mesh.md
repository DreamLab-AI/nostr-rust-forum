# ADR-093 — Native pod mesh: hybrid CF Workers + agentbox two-tier architecture

- **Status:** Accepted
- **Date:** 2026-05-17
- **Owners:** Cross-stack — `nostr-bbs-pod-worker` (CF tier), `nostr-bbs-forum-client`
  (pod browser), `nostr-bbs-auth-worker` (admin provisioning). Authored by
  `nrf-native-pod-mesh` following the git-pods mesh sprint.
- **Related:** ADR-089 (git-pods unavailability on CF Workers — the constraint this
  ADR resolves); ADR-087 (CF-Workers-portable cores — same wasm32/Tokio gap);
  ADR-032 (embed solid-pod-rs library); JSS #464 (apps as first-class pod
  repositories, `/.well-known/apps`); JSS #471 (solid-pod-rs git-auto-init).

---

## 1. Context

ADR-089 established that Cloudflare Workers cannot spawn subprocesses and therefore
cannot host the `git` feature of `solid-pod-rs`. The Workers tier (`nostr-bbs-pod-worker`)
stores pods as R2 prefixes with no native filesystem, no `tokio::process`, and no
git history.

Simultaneously, the agentbox container runs a full Linux environment with a server
Tokio runtime. It can compile `solid-pod-rs-server --features git` and expose:

- Smart HTTP git transport at `/_git/<pubkey>/` (clone, push, pull).
- `/.well-known/apps` aggregation endpoint (JSS #464) — pods as first-class app
  repositories.
- `/_admin/provision/<pubkey>` REST endpoint for operator-driven pod creation.

Users who need git version control for their pods — particularly developers
using pods as app repositories — have no path to that capability on the CF tier
alone. The ecosystem already has an agentbox container; adding a Cloudflare Tunnel
in front of it provides encrypted, zero-config TLS without opening a public port.

A user-visible capability gap therefore exists: CF-tier pods are LDP+R2 with no
version history; agentbox-tier pods are LDP+filesystem+git. The pod browser must
surface both without requiring the user to understand the underlying deployment
topology.

---

## 2. Decision

Adopt a **hybrid two-tier architecture**:

| Tier | Deployment | Storage | Git | Auth |
|------|-----------|---------|-----|------|
| CF Workers | Cloudflare edge | R2 + KV | No (501) | NIP-98 (Schnorr) |
| Native (agentbox) | Docker container | Host filesystem | Yes | NIP-98 (Schnorr) |

### 2.1 Cloudflare Tunnel transport

The agentbox `solid-pod-rs-server` instance is exposed via a Cloudflare Tunnel
at `pods-native.dreamlab-ai.com`. The tunnel provides:

- Encrypted transport (TLS terminated at Cloudflare edge) with no open inbound
  ports on the agentbox host.
- A stable public hostname independent of the container's IP address.
- Zero infrastructure change to the CF Workers deployment.

### 2.2 NIP-98 cross-tier auth (trust bridge)

Both tiers verify requests using NIP-98 Schnorr signatures over the user's
secp256k1 pubkey. Because the signature is self-contained — it covers the URL,
HTTP method, and optional body hash — each tier verifies independently from the
same pubkey. No token exchange, no shared session store, no cross-tier RPC is
required.

```
Browser signs:  Event { kind: 27235, tags: [["u", url], ["method", "GET"]], pubkey, sig }
CF tier:        nostr_bbs_core::nip98::verify(event, url, method, body_hash)
Native tier:    solid-pod-rs-server verifies same event structure independently
```

The same passkey-derived privkey (ADR-089 auth flow, PRF extension) signs
requests to both tiers. From the user's perspective, authentication is seamless.

### 2.3 Admin provisioning path

Native pods are provisioned on demand rather than automatically at registration.
The provisioning flow is:

```
Admin UI  →  POST /api/native-pod/provision  →  auth-worker
                                                  │ X-Pod-Admin-Key (PSK)
                                                  ↓
                                         POST /_admin/provision/{pubkey}
                                              (native server)
                                                  │
                                         mkdir pod dir + .acl + git init
```

1. Admin clicks "Provision native pod" in the admin panel.
2. Forum-client calls `auth-worker POST /api/native-pod/provision` with a
   NIP-98-signed request carrying the target pubkey.
3. `auth-worker` forwards to the native server's `/_admin/provision/{pubkey}`
   endpoint with a pre-shared key (`X-Pod-Admin-Key` header). The PSK is stored
   in `ADMIN_KV`; it never appears in client-visible responses.
4. Native server creates the pod directory, writes a WAC `.acl` granting the
   pubkey owner access, and runs `git init -b main`.
5. `auth-worker` returns the allocated native pod URL to the client.

The PSK is the only secret crossing tiers. It is distinct from any user
credential and is rotatable without affecting user sessions.

### 2.4 Cohort-based access control

The native tier is not universally available. The `[native_pod]` config section
in `dreamlab.toml` lists which cohorts are entitled to native pods:

```toml
[native_pod]
enabled = true
base_url = "https://pods-native.dreamlab-ai.com"
allowlist_cohorts = ["developer", "early-access"]
git_enabled = true
admin_provision_url = "https://pods-native.dreamlab-ai.com/_admin/provision"
```

The pod browser reads the user's cohort from the forum auth state and conditionally
renders the native pod card. Users in non-allowlisted cohorts see only the CF pod
card.

### 2.5 Pod browser two-probe pattern

The pod browser (`pages/pod_browser.rs`) mounts two independent `Effect::new`
probes:

1. **CF probe** — always runs; calls `{CF_POD_URL}/{pubkey}/` and renders the
   standard pod card.
2. **Native probe** — runs only when `NATIVE_POD_URL` (build-time env) is set
   and the user's cohort is in `allowlist_cohorts`; calls
   `{NATIVE_POD_URL}/{pubkey}/` and renders a second pod card with a git badge
   and the `/_git/<pubkey>/` clone URL.

Each probe is independent: a 404 or network error on one does not suppress the
other. The native probe degrades gracefully to "Git API not available" (the
shipping default documented in ADR-089 section 4).

### 2.6 `AppManifestPanel` and `/.well-known/apps`

The native server exposes `/.well-known/apps` per JSS #464, aggregating
`manifest.json` from all pods that have one. The `AppManifestPanel` component
in the forum client renders this index when the native probe succeeds, surfacing
pods as app repositories alongside the git panel.

---

## 3. Consequences

### Positive

- Git version control is available for developer-cohort users without any change
  to the CF Workers codebase.
- Cloudflare Tunnel provides encrypted transport with no open inbound ports and
  no TLS certificate management burden on the operator.
- NIP-98 cross-tier auth requires no shared infrastructure — both tiers verify
  independently, so tier independence is preserved.
- The CF Workers tier remains unchanged; existing users are unaffected.
- Pod browser auto-discovery means users see the correct card set without manual
  configuration.

### Negative

- Users are split across two tiers. A user provisioned on the CF tier cannot
  retroactively gain git history without migrating pod data.
- Native pods require admin action to provision — there is no self-service path.
- The agentbox container must remain running and reachable via the Tunnel at all
  times; it is a new operational dependency.
- Two pod URLs per ecosystem increases the config surface operators must manage
  (`[pod].base_url` for CF, `[native_pod].base_url` for native).

### Neutral

- The pod browser probes both tiers independently on mount; the probe latency
  is additive but hidden by concurrent `Effect::new` scheduling.
- WebID documents at `https://pods.dreamlab-ai.com/{pubkey}/profile/card#me`
  (CF tier) and `https://pods-native.dreamlab-ai.com/{pubkey}/profile/card#me`
  (native tier) are structurally identical; the `pod_base_url` field in the
  WebID determines which tier a given user is on.
- The PSK rotation procedure is documented in `SETUP.md` but requires a worker
  re-deploy to pick up the new `ADMIN_KV` value.

---

## 4. Options Considered

### Option A — Isomorphic-git in WASM (rejected)

Run a pure-WASM git implementation inside the CF Worker, backed by R2 as the
"filesystem". This is the option (b) path from ADR-089.

- **Pro:** closes the deployment-tier gap; no second server required.
- **Con:** R2 has no filesystem semantics; a shim translating gix's
  `std::fs`-shaped I/O into R2 `put`/`get` calls is a substantial research
  effort with unknown maturity. CF Workers' 30 s CPU budget is hostile to
  packfile operations. No champion identified for 2026.

### Option B — CF Worker acting as a reverse proxy to native (rejected)

Add a proxy path in `nostr-bbs-pod-worker` that forwards `/_git/*` and
`/.well-known/apps` requests to the native server.

- **Pro:** single hostname for all pod operations; client needs no native URL.
- **Con:** adds latency on the hot path (double hop through CF edge); couples
  the CF Worker's availability to the native server's availability; a Worker
  failure mode now propagates upstream errors to all pod clients. Violates
  the CF tier's design goal of independence.

### Option C — Pure native deployment (rejected)

Remove the CF Workers tier entirely and run `solid-pod-rs-server` as the only
pod backend.

- **Pro:** one pod URL, full git, no tier divergence.
- **Con:** loses CF edge caching, global PoP distribution, Durable Objects for
  relay sessions, D1 for event persistence, and the entire CF Workers ecosystem
  that NRF is built on. Not a viable migration path for existing CF deployments.

### Option D — Hybrid two-tier (selected — this ADR)

See section 2.

---

## 5. Implementation Details

### Build-time constant

`NATIVE_POD_URL` is a build-time env var consumed by `forum-client`'s Trunk
build. When unset (default for CF-only deployments), the native probe does not
run and the native pod card is never rendered. Operators enabling the native
tier set this var in their Trunk build config or CI environment.

### CORS allowlist

The native server's CORS configuration must include the forum-client origin
(`https://dreamlab-ai.com`) and any local dev origins. This is set in the
`solid-pod-rs-server` startup config, not in the CF Worker.

### PSK admin key lifecycle

- Generated at agentbox deploy time; stored as a `ADMIN_KV` binding value in
  the CF Workers deployment.
- Rotated by: (1) generating a new random key, (2) updating `ADMIN_KV` via
  `wrangler kv put`, (3) restarting the native server with the new value in its
  environment, (4) re-deploying auth-worker to pick up the new `ADMIN_KV` value.
- The PSK is never logged or returned to clients.

### Config schema (`nostr-bbs-config`)

`NativePod` struct in `crates/nostr-bbs-config/src/schema.rs`:

```rust
pub struct NativePod {
    pub enabled: bool,
    pub base_url: String,
    pub allowlist_cohorts: Vec<String>,
    pub git_enabled: bool,
    pub admin_provision_url: String,
}
```

The struct is `Option<NativePod>` in `BbsConfig`; absent config means the
native tier is disabled for that operator deployment.

---

## 6. Migration / Impact

- **`nostr-bbs-pod-worker`**: no change. Returns 501 on `/_git/*` requests as
  before (ADR-089 section 5).
- **`nostr-bbs-auth-worker`**: gains `handle_native_pod_provision` handler
  at `POST /api/native-pod/provision`. NIP-98 gated; admin-only.
- **`nostr-bbs-forum-client`**: `pod_browser.rs` gains `NATIVE_POD_URL` const,
  second `Effect::new` probe, and native pod card with git badge and clone URL.
  `admin.rs` gains `NativePodsTab` listing provisioned native pods with a
  "Provision" action.
- **`nostr-bbs-config`**: `NativePod` struct; optional field on `BbsConfig`.
- **`forum-config/dreamlab.toml`**: `[native_pod]` section added for the
  DreamLab operator overlay.
- **Agentbox**: `solid-pod-rs-server --features git` running on port 3001,
  Cloudflare Tunnel configured for `pods-native.dreamlab-ai.com`.

---

## 7. References

- ADR-089 — git-pods unavailability on CF Workers (the constraint this ADR
  resolves; option D corresponds to sidecar option (c) of ADR-089, now
  implemented).
- ADR-087 — CF Workers portable cores (same wasm32/Tokio gap).
- ADR-032 — embed solid-pod-rs library (dependency-direction precedent).
- JSS #464 — `/.well-known/apps`, pods as first-class app repositories.
- JSS #471 — `solid-pod-rs` git-auto-init at pod provisioning.
- `solid-pod-rs` v0.4.0-alpha.14 (`4ac7670`) — git HTTP transport.
- Cloudflare Tunnel documentation — zero-config TLS for private origins.
