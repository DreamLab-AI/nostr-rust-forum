# Pod ACL and Identity Layer — Cartography Audit

Generated from source code. All file:line references are to the live codebase,
re-verified against `origin/main` `3c48e2656d7cabefa894a59b827f5f0d3a8b32b7` (v1.0.0-beta.21-rc.2, 2026-11-22).

---

## 1. Pod Resource GET/PUT with WAC Authorisation

The `find_effective_acl` resolver in `crates/nostr-bbs-pod-worker/src/acl.rs:314`
drives every request. It is called from two places in `lib.rs`:

- Line 1016 — standard resource flow (GET, PUT, POST, PATCH, DELETE)
- Line 1653 — ACL resource flow (`handle_acl_request`), for the *parent* resource

> **Resolution-order change (commit 682a948):** the R2 sidecar walk is now
> AUTHORITATIVE and runs first; the KV `acl:{owner_pubkey}` key is a legacy
> pod-level document consulted ONLY when no R2 sidecar resolves at any level.
> The previous KV-first fast path let a stale owner-granular KV entry shadow
> every R2 sidecar — including ADR-096 delegation grants (former Finding 1,
> now resolved). The pure ordering lives in `resolve_effective_acl`
> (`acl.rs:421`, `#[cfg(test)]` only at `acl.rs:420`; the live `find_effective_acl`
> inlines the same R2-then-KV order at `acl.rs:320-375`) for unit testing.

### 1a. GET /pods/{pubkey}/{resource} — Full ACL Walk

```mermaid
sequenceDiagram
    participant C as Client
    participant W as pod-worker (lib.rs)
    participant KV as CF KV (POD_META)
    participant R2 as CF R2 (PODS)
    participant WAC as solid_pod_rs::wac::evaluate_access

    C->>W: GET /pods/{pubkey}/{resource}
    Note over W: parse_pod_route() validates pubkey hex<br/>and resource path (P2 traversal guard)<br/>lib.rs:94-115

    W->>W: NIP-98 verify (auth::verify_nip98_replay)<br/>agent_uri = "did:nostr:{requester_pk}"<br/>lib.rs:809-831,843-847

    W->>W: required_mode = coerce_required_mode_for_acl(resource_path, "GET")<br/>→ Read (non-acl path)<br/>acl.rs:111-116

    Note over W: find_effective_acl(bucket, kv, owner_pubkey, resource_path)<br/>acl.rs:314 — R2 sidecars AUTHORITATIVE, KV miss-fallback only (commit 682a948)<br/>An oversized or unreadable sidecar is a terminal deny, not a miss (acl.rs:40-54, 350-353)

    Note over W: Build probe sequence via acl_probe_sequence(resource_path)<br/>acl.rs:208

    Note over W: Probe 1 (non-inherited): {resource}.acl<br/>e.g. /private/agent/SOUL.md.acl<br/>acl.rs:228

    W->>R2: GET pods/{pubkey}/{resource}.acl
    alt R2 hit and <=64 KiB
        R2-->>W: bytes → AclDocument (inherited=false)
    else absent (an oversized or unreadable sidecar denies here instead)
        Note over W: Probe 2 (inherited): {dir}/.acl for immediate container<br/>e.g. /private/agent/.acl (ADR-096 fix)<br/>acl.rs:239

        W->>R2: GET pods/{pubkey}{dir}/.acl
        alt R2 hit
            R2-->>W: bytes → AclDocument (inherited=true)
        else miss
            Note over W: Probe 3 (inherited): legacy flat {dir-without-slash}.acl<br/>e.g. /private/agent.acl<br/>acl.rs:245-249

            W->>R2: GET pods/{pubkey}/private/agent.acl
            alt R2 hit
                R2-->>W: bytes → AclDocument (inherited=true)
            else miss
                Note over W: Continue walk: parent dir = /private/<br/>Probe: /private/.acl then /private.acl then /.acl<br/>acl.rs:252

                W->>R2: GET pods/{pubkey}/private/.acl
                W->>R2: GET pods/{pubkey}/private.acl
                W->>R2: GET pods/{pubkey}/.acl
                R2-->>W: first hit wins, doc.inherited = true

                alt no R2 sidecar at ANY level
                    Note over W: KV MISS-FALLBACK only — legacy pod-level ACL<br/>acl.rs:356-375
                    W->>KV: GET acl:{owner_pubkey}
                    alt KV hit and parseable (<=64 KiB)
                        KV-->>W: AclDocument (pod-level, non-inherited)
                    end
                end
            end
        end
    end

    alt No ACL found at any level
        W-->>C: 401/403 (deny-all, None → !has_access)<br/>lib.rs:1025-1036
    else AclDocument resolved
        W->>WAC: evaluate_access(acl_doc, agent_uri, resource_path, Read)
        Note over WAC: If inherited=true: only acl:default rules apply<br/>(WAC §4.2, enforced upstream)
        WAC-->>W: bool

        alt Access denied
            W-->>C: 401 (unauthenticated) or 403 (authenticated)<br/>lib.rs:1025-1036
        else Access granted
            W->>R2: GET pods/{pubkey}{resource}
            R2-->>W: object bytes
            W->>W: add_ldp_headers / add_wac_allow / add_cache_control
            W-->>C: 200 OK + WAC-Allow header
        end
    end
```

### 1b. PUT /pods/{pubkey}/{resource} — Write Path

```mermaid
sequenceDiagram
    participant C as Client
    participant W as pod-worker (lib.rs)
    participant R2 as CF R2 (PODS)
    participant D1 as CF D1 (REPLAY_DB)

    C->>W: PUT /pods/{pubkey}/{resource} + body
    W->>W: NIP-98 verify (replay-protected via D1)<br/>lib.rs:809-831
    W->>W: required_mode = Write (coerce_required_mode_for_acl)<br/>acl.rs:111-116
    Note over W: find_effective_acl() → same probe sequence as GET
    W->>W: evaluate_access(acl_doc, agent_uri, resource_path, Write)
    alt Denied
        W-->>C: 401/403
    else Granted
        W->>W: content_length check (<=50 MiB) lib.rs:1277-1293
        W->>W: Conditional check: If-Match vs existing ETag lib.rs:1295-1309
        W->>D1: quota::check_and_reserve_d1(owner_pubkey, data_len)<br/>lib.rs:1312
        alt Quota exceeded
            D1-->>W: Err
            W-->>C: 413
        else Quota OK
            alt resource_path == "/profile/card"
                W->>W: validate_webid_html(data) — UTF-8 + JSON-LD script block check<br/>lib.rs:1317-1321
            end
            W->>R2: PUT pods/{pubkey}{resource}
            W->>W: notifications::notify_change (non-blocking) lib.rs:1333
            W-->>C: 201 Created + WAC-Allow
        end
    end
```

---

## 2. Delegation Grant: PUT `{"@delegation":{...}}` to Container Sidecar

This is the "structured grant" shortcut documented in ADR-096.
The ACL-write handler in `lib.rs:1753-1818` detects the `@delegation` envelope
before the generic JSON-LD path and calls `build_delegation_acl` in `acl.rs:461`.

```mermaid
sequenceDiagram
    participant C as Client (acl:Control holder)
    participant W as handle_acl_request (lib.rs:1622)
    participant ACL as acl::build_delegation_acl (acl.rs:461)
    participant R2 as CF R2

    C->>W: PUT /pods/{pubkey}/{container}/.acl<br/>body: {"@delegation":{"agent":"did:nostr:...","modes":["acl:Read","acl:Write"]}}
    Note over W: is_acl_path() → true → handle_acl_request() lib.rs:992

    W->>W: parent_path = protected resource from acl::effective_acl_target(acl_path, Read)<br/>e.g. "/private/agent/" lib.rs:1648-1650

    W->>W: find_effective_acl(bucket, kv, owner_pubkey, parent_path)<br/>→ parent_acl (same probe sequence as §1a)

    W->>W: evaluate_access(parent_acl, agent_uri, parent_path, Control)
    alt No acl:Control
        W-->>C: 401/403 "acl:Control required to modify ACL" lib.rs:1730
    else Has Control
        W->>W: JSON parse body → detect "@delegation" key lib.rs:1769
        W->>W: validate agent starts with "did:nostr:" lib.rs:1770-1783
        W->>W: parse modes array, "acl:Control" silently ignored lib.rs:1785-1804

        W->>ACL: build_delegation_acl(owner_did, agent_did, container, modes)
        Note over ACL: 1. ALWAYS emit #owner auth:<br/>   agent=owner_did, accessTo+default=container<br/>   modes=[Read,Write,Control] acl.rs:505-517
        Note over ACL: 2. Strip acl:Control from delegate modes acl.rs:519-525
        Note over ACL: 3. If delegate_modes non-empty, emit #delegate auth:<br/>   agent=agent_did, accessTo+default=container<br/>   modes=requested_minus_Control acl.rs:527-542
        Note over ACL: Result: AclDocument {inherited:false, @graph:[#owner,#delegate]}
        ACL-->>W: AclDocument

        W->>W: serde_json::to_vec(doc) — canonical wire JSON-LD
        W->>W: acl::parse_acl_with_cap (64 KiB cap) then acl::preserves_owner_control, else 422<br/>lib.rs:1823-1835
        W->>R2: PUT pods/{owner}/{container}/.acl (content-type: application/ld+json)
        W-->>C: 201 {"status":"ok"}
    end
```

**Owner lock-out invariant**: `build_delegation_acl` always re-emits the owner's
`[Read, Write, Control]` grant regardless of what the caller requested. The delegate
never receives `acl:Control` even if `"acl:Control"` is included in the modes array
— it is silently dropped at `acl.rs:521-525` (and ignored at `lib.rs:1794`).

---

## 3. Identity Derivation: `derive_subkey` HMAC-SHA-256

Defined in `crates/nostr-bbs-core/src/keys.rs:252`.
Scheme (ADR-094): `child_sk = HMAC-SHA-256(key=root_sk_32bytes, msg=utf8(tag))`.

```mermaid
flowchart TD
    ROOT["SecretKey (32 bytes)\n(secp256k1 scalar)"]

    ROOT -->|"HMAC-SHA256(root, tag)"| HMAC["hmac::Hmac<Sha256>\nkeys.rs:254-257"]
    HMAC -->|"32-byte output"| VALIDATE["SecretKey::from_bytes(child)\nreject if zero or ≥ curve order\nkeys.rs:263"]
    VALIDATE --> CHILDSK["child SecretKey"]

    CHILDSK -->|"child.public_key()"| CHILDPK["child PublicKey (x-only BIP-340)"]

    subgraph "Known production tags (keys.rs + wasm_bridge.rs + devices.rs)"
        T1["'agentbox-mirror-v1'\nNostr session mirror child key\nagentbox CLAUDE.md (unverified at 3c48e26), keys.rs:235,452,461"]
        T2["'agentbox-agent-v1'\nAgentbox agent identity\nkeys.rs:462 (test/domain-separation only)"]
        T3["'device:{uuid}'\nRevocable device subkey (ADR-099)\nformat!('device:{}', Uuid::new_v4())\nforum-client/src/utils/devices.rs:133,182\nauth-worker/src/devices.rs:4 (doc)"]
    end

    CHILDSK -.->|used as| T1
    CHILDSK -.->|used as| T2
    CHILDSK -.->|used as| T3

    subgraph "JS parity (ADR-094)"
        JSP["crypto.createHmac('sha256', root)\n  .update(tag, 'utf8').digest()\nKnown-answer vector: root=[0x01×32],\ntag='agentbox-mirror-v1'\n→ 2d07f2ce…695d\nkeys.rs:470-484"]
    end

    HMAC -.->|byte-for-byte identical| JSP

    subgraph "WASM bridge export (wasm32 only)"
        WB["derive_subkey_js(root_hex, tag)\nwasm_bridge.rs:88\nReturns {publicKey, secretKeyHex, nsec}"]
    end

    CHILDSK -.->|wrapped by| WB
```

### 3a. PRF Key Derivation (separate construction — HKDF-Expand)

```mermaid
sequenceDiagram
    participant B as forum-client (passkey.rs)
    participant WA as WebAuthn PRF extension
    participant W as CF Workers auth-worker
    participant WASM as nostr-bbs-core WASM (forum-client)

    B->>WA: navigator.credentials.create() (register) or get() (login) with PRF eval<br/>passkey.rs:348,402
    WA-->>B: prf_output (32 bytes)

    B->>WASM: derive_from_prf(prf_output, prfSalt bytes) [passkey.rs:153,274 calls nostr_bbs_core::derive_from_prf directly, JS export derive_keypair_from_prf is wasm_bridge.rs:61]
    Note over WASM: HKDF-SHA256(salt=derivation_salt, ikm=prf_output, info="podkey/nostr-secret/v1" + counter byte)<br/>first valid scalar for counter 0..=255 wins, keys.rs:197-218
    WASM-->>B: {secretKey: Uint8Array(32), publicKey: hex64}

    Note over B: This keypair IS the Nostr identity<br/>(different construction from derive_subkey — see ADR-094)
    B->>W: POST /auth/register/verify {pubkey, response}
    W-->>B: {verified:true, pubkey, didNostr}
```

`derive_from_prf` (HKDF-Expand, keys.rs:197) and `derive_subkey` (HMAC, keys.rs:252)
are intentionally different constructions. The PRF path produces the **root** identity
keypair from the authenticator secret. `derive_subkey` produces **child** keys from
that root.

---

## 4. Pod Provisioning — Eager `provision_pod`

There are two entry points that trigger provisioning. Neither is triggered
automatically during WebAuthn `register_verify` — provisioning is an explicit
separate call.

```mermaid
sequenceDiagram
    participant C as Client
    participant PW as pod-worker (lib.rs)
    participant AW as auth-worker (pod.rs)
    participant R2 as CF R2 (PODS)
    participant KV as CF KV (POD_META)

    rect rgb(230, 240, 255)
        Note over C,KV: Path A: POST /.pods (JSS-compatible, lib.rs:635)
        C->>PW: POST /.pods {"name":"{64-hex-pubkey}"}<br/>+ Authorization: Nostr <nip98>
        PW->>PW: NIP-98 verify, requester_pubkey must equal name lib.rs:652-664
        PW->>R2: pod_exists(bucket, name) lib.rs:668
        alt Already provisioned
            PW-->>C: 409 "Pod already provisioned"
        else Not yet provisioned
            PW->>PW: provision_pod(bucket, kv, name, pod_base, None) lib.rs:673
        end
    end

    rect rgb(240, 255, 230)
        Note over C,KV: Path B: POST /pods/{pubkey}/.provision (lib.rs:852)
        C->>PW: POST /pods/{pubkey}/.provision<br/>+ Authorization: Nostr <nip98><br/>+ body (optional): {"display_name":"..."}
        PW->>PW: NIP-98 verify, require owner OR admin lib.rs:809-831,862-868
        PW->>R2: pod_exists(bucket, owner_pubkey) lib.rs:871
        alt Already provisioned
            PW-->>C: 409
        else Not yet provisioned
            PW->>PW: provision_pod(bucket, kv, owner_pubkey, pod_base, display_name) lib.rs:886
        end
    end

    rect rgb(255, 245, 220)
        Note over C,AW: Path C (REMOVED): auth-worker pod.rs no longer provisions anything
        Note over AW: auth-worker::pod::provision_pod was deleted in commit 5910bd0<br/>pod.rs now holds only handle_profile (GET /api/profile, reads R2 profile/card)<br/>pod.rs:9, routed from auth-worker lib.rs:337<br/>No auth-worker provisioner remains
    end

    Note over PW,R2: pod-worker provision_pod() creates full tree:
    PW->>R2: PUT pods/{pubkey}/ (root container marker) provision.rs:127-142
    PW->>R2: PUT pods/{pubkey}/profile/ (x7 sub-containers) provision.rs:144-160
    PW->>R2: PUT pods/{pubkey}/profile/card (WebID HTML) provision.rs:163-175
    PW->>R2: PUT pods/{pubkey}/.acl (root ACL: owner RWC + default) provision.rs:177-198
    PW->>R2: PUT pods/{pubkey}/public/.acl (foaf:Agent R + owner RWC) provision.rs:200-227
    PW->>R2: PUT pods/{pubkey}/media/public/.acl (same as public) provision.rs:229-242
    PW->>R2: PUT pods/{pubkey}/private/.acl (owner-only RWC) provision.rs:244-265
    PW->>R2: PUT pods/{pubkey}/inbox/.acl (authenticated Append + owner RWC) provision.rs:267-294
    PW->>R2: PUT pods/{pubkey}/profile/.acl (foaf:Agent R + owner RWC) provision.rs:296-323
    PW->>R2: PUT pods/{pubkey}/settings/.acl (owner-only) provision.rs:325-346
    PW->>R2: PUT pods/{pubkey}/settings/publicTypeIndex.jsonld provision.rs:358-368
    PW->>R2: PUT pods/{pubkey}/settings/privateTypeIndex.jsonld provision.rs:369-379
    PW->>R2: PUT pods/{pubkey}/settings/publicTypeIndex.jsonld.acl (owner RWC + foaf:Agent R) provision.rs:380-392
    PW->>KV: update_usage(kv, owner_pubkey, 0) provision.rs:396
    PW-->>C: 201 {"status":"provisioned","podUrl":"...","webId":"...","didNostr":"..."} (Path B, lib.rs:897-909)<br/>Path A returns 201 {"name","webId","podUri"} lib.rs:675-685
```

---

## Findings

### Finding 1 — RESOLVED (commit 682a948) | KV Fast-Path Masked R2 Sidecars

**File**: `crates/nostr-bbs-pod-worker/src/acl.rs:314-376`
**Classification**: Fixed design gap

~~The KV fast-path read `acl:{owner_pubkey}` FIRST and returned unconditionally
on a hit, shadowing every R2 sidecar — so delegation grants written into R2
(via `build_delegation_acl`) were unreachable for pods carrying that KV key.~~
Fixed at the single resolver every access decision funnels through:
`find_effective_acl` now runs the most-specific-first R2 probe sequence first
and authoritatively; the legacy pod-level KV key is consulted only when no R2
sidecar resolves at any level, so it can never mask a more-specific R2
delegation sidecar. The ordering is extracted into the pure
`resolve_effective_acl` helper (`acl.rs:421`, `#[cfg(test)]` only, with its regression tests
calling it at `acl.rs:1416-1514`; the live resolver inlines the same order at `acl.rs:320-375`).
The auth-worker `pod::provision_pod` — the only writer of the masking KV key — has since
been deleted (see Finding 4).

---

### Finding 2 — RESOLVED (commit 6ef842b) | Duplicated `is_acl_path` / `path_is_acl` Predicate

**File**: formerly `crates/nostr-bbs-pod-worker/src/acl.rs:53-55` and
`crates/nostr-bbs-pod-worker/src/lib.rs:119-121`; now `lib.rs:118-120` only
**Classification**: Duplication / maintenance risk

~~`acl.rs` defines a private `fn path_is_acl(path: &str) -> bool { path.ends_with(".acl") }`
and `lib.rs` defines an identical private `fn is_acl_path(path: &str) -> bool { path.ends_with(".acl") }`.
They are the same predicate with different names. `lib.rs` could simply call the
public surface from `acl.rs` (which already exports `coerce_required_mode_for_acl`
that internally uses `path_is_acl`), or `acl.rs` could export `path_is_acl` and
`lib.rs` can import it. A future maintainer who changes the predicate in one place
(e.g. to also match `.acl.gz` for compressed ACLs) will silently miss the other.~~

Resolved: `path_is_acl` no longer exists in `acl.rs`. `coerce_required_mode_for_acl` (`acl.rs:111-116`)
now delegates sidecar detection to the shared `effective_acl_target` re-exported from
`solid_pod_rs::wac` (`acl.rs:36-38`, called at `acl.rs:115`), and the pod-worker's `.acl`
handler uses the same function (`lib.rs:1648-1650`). The only local predicate left is
`is_acl_path` (`lib.rs:118-120`), used for routing at `lib.rs:296` and `lib.rs:992`.

---

### Finding 3 — PARTLY RESOLVED (HEAD 3c48e26) | `parse_acl_with_cap` and `parse_acl_text_with_cap` are Private but Mentioned in Module Doc as Kit-Specific

**File**: `crates/nostr-bbs-pod-worker/src/acl.rs:12-13`, functions at `acl.rs:137` and `acl.rs:168`
**Classification**: Export/visibility inconsistency

~~The module-level doc comment (`acl.rs:12-13`) calls out both `parse_acl_with_cap`
and `parse_acl_text_with_cap` as named kit-specific extensions alongside
`find_effective_acl` and `coerce_required_mode_for_acl`, all of which are
described as the public kit surface. However `parse_acl_with_cap` (line 137) and
`parse_acl_text_with_cap` (line 168) are declared `fn` (private). This is a doc/
visibility mismatch. If callers outside the module ever need to apply the size cap
independently (e.g. a future partial-ACL merge path), they cannot without
duplicating the cap logic. Either make them `pub(crate)` to match the doc intent,
or remove them from the module doc description.~~

Amended: `parse_acl_with_cap` is now `pub` (`acl.rs:137`) and is used by the pod-worker's ACL PUT
handler (`lib.rs:1823`), so the visibility mismatch is gone for it. `parse_acl_text_with_cap` is now
`#[cfg(test)]` (`acl.rs:167-168`) yet the module doc still lists it as a kit extension
(`acl.rs:12-13`): only that doc nit remains.

---

### Finding 4 — RESOLVED (commit 5910bd0) | Auth-Worker `pod::provision_pod` Is Dead Code as a Provisioner

**File**: formerly `crates/nostr-bbs-auth-worker/src/pod.rs:29-113` (function deleted)
**Classification**: Dead code / architectural drift

~~`pod::provision_pod` in the auth-worker is never called for actual provisioning.
It is defined at `pod.rs:29` and the only call to `pod::` in `lib.rs` is at
line 318 (`pod::handle_profile`). Provisioning is performed by the pod-worker's
own `provision::provision_pod` (`pod-worker/src/provision.rs:106`), reachable via
`POST /.pods` or `POST /pods/{pubkey}/.provision`.~~

~~The two implementations have diverging behaviour:
- `auth-worker::pod::provision_pod` writes only 3 objects (KV ACL, R2 profile
  card, KV meta) with a single flat ACL document in KV.
- `pod-worker::provision::provision_pod` writes 13+ R2 objects (per-container
  ACLs, TypeIndex documents, WebID HTML, sub-containers) and no KV ACL entry.~~

~~If `auth-worker::pod::provision_pod` were ever wired into a signup flow, it would
produce an under-provisioned pod with a legacy KV ACL. Since commit 682a948 the
resolver treats that KV key as a miss-fallback only (it can no longer suppress R2
sidecars — former Finding 1), but the function remains an under-provisioning dead
path flagged for deletion.~~

Resolved: `crates/nostr-bbs-auth-worker/src/pod.rs` now contains only `handle_profile` (`pod.rs:9`),
routed from `crates/nostr-bbs-auth-worker/src/lib.rs:337`. There is no `provision_pod` in the
auth-worker. The sole provisioner is the pod-worker's `provision::provision_pod`
(`provision.rs:111`), reached via `POST /.pods` (`lib.rs:635`, call at `lib.rs:673`) and
`POST /pods/{pubkey}/.provision` (`lib.rs:852`, call at `lib.rs:886`).

---

### Finding 5 — LOW | WASM Bridge Exports Without Production JS Consumers

**File**: `crates/nostr-bbs-core/src/wasm_bridge.rs`
**Classification**: Dead export surface

The following `#[wasm_bindgen]` exports in `wasm_bridge.rs` have no production JS
consumers in the repo. They appear only in the benchmark harness
(`benchmarks/js-vs-wasm/bench.mjs`) or not at all:

| Export | File:Line | Benchmark only | No consumers found |
|--------|-----------|---------------|--------------------|
| `create_nip98_token` | `wasm_bridge.rs:120` | Yes (bench.mjs:38, noted to panic in WASM due to `SystemTime`) | — |
| `verify_nip98_token` | `wasm_bridge.rs:141` | — | No JS caller found |
| `verify_nip98_token_at` | `wasm_bridge.rs:159` | — | No JS caller found |
| `schnorr_verify` | `wasm_bridge.rs:249` | — | No JS caller found |

`derive_keypair_from_prf`, `schnorr_sign`, `compute_event_id`, and `nip44_encrypt`/
`nip44_decrypt` are used in the benchmark. `derive_subkey_js` and
`generate_keypair` are consumed by `forum-client` via the Rust WASM target (not
via the exported JS symbols directly, since `forum-client` is itself a Rust WASM
crate). The four symbols above have no identified JS callers; `create_nip98_token`
is additionally documented in the benchmark to panic in WASM due to
`std::time::SystemTime::now()` being unavailable. These should either gain
consumers or be removed from the public WASM surface to reduce the compiled
bundle size.

---

### Finding 6 — RESOLVED (commit c0fd600) | `key_provisioning.rs` and `nip05_endpoint.rs` Are Permanently-Parked Stubs

**File**: formerly `crates/nostr-bbs-pod-worker/src/key_provisioning.rs` and
`crates/nostr-bbs-pod-worker/src/nip05_endpoint.rs` (both deleted)
**Classification**: Dead module / maintenance debt

~~Both modules compile to a single `const _: () = ();` line. They are gated behind
`#[cfg(feature = "solid-pod-rs-phase1")]` which is never enabled in the workspace.
The comments document why: `key_provisioning` requires `solid-pod-rs-idp` (a sibling
crate not depended on), and `nip05_endpoint` requires actix-web (incompatible with
the CF Workers runtime). Neither blocker is in the near-term roadmap per the
consumer-surface-map. The modules exist only as source-level breadcrumbs but add
noise to `lib.rs:40-42` (`mod export; mod key_provisioning; mod nip05_endpoint;`).
They should be removed or moved to a `//! TODO: Phase 1` ADR comment until
activation is realistic.~~

Resolved: both files are gone from `crates/nostr-bbs-pod-worker/src/`, and the comment at
`lib.rs:37-40` records that the `provision-keys` and `nip05-endpoint` shims were removed.
The one remaining staging shim is `mod export;` (`lib.rs:41`), gated by `solid-pod-rs-phase1`
(`Cargo.toml:22`, `export.rs:17`).

---

### Finding 7 — INFO | `acl_probe_sequence` Legacy Flat `{dir}.acl` Form Remains Reachable — Noted, Not a Bug

**File**: `crates/nostr-bbs-pod-worker/src/acl.rs:237-253`
**Classification**: Informational

The resolver retains the legacy flat-sidecar probe (`/private/agent.acl` for a
resource under `/private/agent/`) interleaved between the container sidecar probe
(`/private/agent/.acl`) and the grandparent container probe. This is intentional
for backward-compatibility during migration (documented at `acl.rs:172-204`). Newly
provisioned pods write container sidecars (`{dir}/.acl`) per `provision.rs`. Older
pods may have only flat sidecars. Both remain reachable with correct precedence
(own > container > legacy flat > ancestor). No action required.
