# ADR-097 — Consolidated agent identity provisioning

- **Status:** Accepted
- **Date:** 2026-06-11
- **Owners:** `nostr-bbs-auth-worker` (governance API — the admin surface);
  `nostr-bbs-relay-worker` (owns the `whitelist` cohort table and the
  `agent_registry` table, both in the `nostr-bbs-relay` D1). Membership /
  registry data-model work.
- **Related:** ADR-094 (subkey derivation — agents are commonly *derived* keys,
  not freshly generated ones); ADR-096 (pod delegation — a provisioned agent
  often acts under a delegated pod mandate); the relay worker's
  `/api/whitelist/add` contract; the governance `/api/governance/agents/register`
  route this composes with.

---

## 1. Context

A deployment that brings a bot identity online currently hand-rolls a
multi-call seed script. The verified sequence is four separate ad-hoc steps:

1. **Generate / derive the agent key** (often an ADR-094 subkey of an operator
   key, sometimes a fresh BIP-340 keypair).
2. **`POST /api/whitelist/add` `{ pubkey, cohorts }`** — relay worker — adds the
   pubkey to the membership/cohort allowlist so the agent can read/post in the
   cohorts it belongs to.
3. **`POST /api/governance/agents/register` `{ pubkey, name, … }`** — auth
   worker — inserts the `agent_registry` row that gates the agent-only event
   kinds (the relay DO checks `agent_registry.active` before accepting agent
   governance kinds 31400–31405).
4. **Client publishes the agent's own kind-0 profile + NIP-65 relay list**,
   signed by the agent key.

Steps 2 and 3 are both *admin-side* writes — they require NIP-98 admin auth and
mutate server-owned tables. Splitting them across two calls means:

- **Non-atomic provisioning.** A deployment that does step 2 but fails before
  step 3 leaves an allowlisted pubkey with no registry row (can read/post but is
  not a recognised agent), or the reverse. Operators then write bespoke
  retry/rollback glue per deployment.
- **Duplicated knowledge.** Every seed script re-encodes the cohort vocabulary,
  the pubkey-validation rule, and the registry column set. They drift.
- **No single audited operation.** There is no one record that says "this admin
  provisioned this agent with these cohorts at this time".

Step 1 (key material) and step 4 (the agent's own signed events) are
**necessarily client-side** and stay there — see §4.

## 2. Decision

Introduce **one admin-authenticated operation** that performs both admin-side
writes atomically and idempotently:

```
POST /api/governance/agents/provision        (NIP-98 admin)
{
  "pubkey": "<64-hex>",          // BIP-340 x-only, lower-cased on the server
  "name": "scribe-bot",
  "description": "optional",
  "cohorts": ["ai-agents", "members"],   // required, non-empty
  "rate_limit_per_min": 60       // optional, defaults to 60
}
→ 200 { "pubkey": "<64-hex>", "cohorts": [...], "registered": true }
```

Server-side it:

1. **Allowlist upsert** — writes the pubkey + cohorts into the `whitelist` table
   using the *exact* SQL contract of the relay worker's `/api/whitelist/add`
   (`INSERT … ON CONFLICT (pubkey) DO UPDATE SET cohorts = excluded.cohorts,
   added_by = excluded.added_by`). The contract is reused, not re-invented: the
   two paths converge on identical row shapes.
2. **Registry upsert** — `INSERT OR REPLACE INTO agent_registry (…)`, reusing the
   identical column set written by `handle_register_agent` (pubkey, name,
   description, registered_by, registered_at, rate_limit_per_min, active=1).

The lives the new handler in `governance_api.rs`; it lives beside, and shares the
`require_admin` gate with, the existing `/register` route. **The `/register`
route is unchanged** — `provision` is purely additive.

## 3. Same-worker, therefore atomic

The `whitelist` table and the `agent_registry` table **both live in the
`nostr-bbs-relay` D1** (the relay worker's `DB`). The auth worker reaches that
database through its `RELAY_DB` binding — the same binding `admin.rs` already
uses to read `whitelist.is_admin`, and the same binding `handle_register_agent`
already uses to write `agent_registry`.

Because both writes target **one physical D1**, they are issued as a single
`db.batch(vec![whitelist_stmt, registry_stmt])`. D1 `batch()` runs its
statements in one implicit transaction, so provisioning is **all-or-nothing** —
there is no partial-failure window where one table is written and the other is
not.

> No cross-worker transaction is invented. The atomicity here is a property of
> the two tables co-residing in `nostr-bbs-relay`, not of any distributed-commit
> machinery. If a future migration moved `whitelist` and `agent_registry` into
> *different* physical databases, this handler would have to degrade to two
> sequential writes with an explicit partial-failure response body
> (`{ whitelisted: true, registered: false, error }`) and the atomicity claim in
> this ADR would be void. That degradation is documented here so the constraint
> is not silently lost. It does **not** apply today.

## 4. What stays client-side

The endpoint **does not need, and never receives, the agent private key.**

- **Key material (step 1)** is the caller's responsibility. Agents are commonly
  **ADR-094-derived subkeys** of an operator key; the caller derives (or
  generates) the keypair and passes only the 64-hex *public* key.
- **The agent's own kind-0 profile and NIP-65 relay list (step 4)** must be
  *signed by the agent key* and published by the caller. Server-side
  provisioning cannot forge these — that is the point of self-sovereign Nostr
  identity. The caller publishes them after a successful `provision` call.

This keeps the trust boundary clean: the admin operation governs *membership and
registry* (server-owned state); the agent's *identity events* remain
client-signed (key-owned state).

## 5. Composition

- **ADR-094 (subkey derivation):** the `pubkey` field accepts a derived subkey's
  public key exactly as it accepts a freshly generated one — provisioning is
  agnostic to key provenance.
- **ADR-096 (pod delegation):** a provisioned agent that later acts under a
  delegated pod mandate is unaffected; provisioning establishes membership +
  registry, delegation is a separate, orthogonal grant.

## 6. Idempotency

Both writes are primary-key-keyed upserts on `pubkey`, and the server
lower-cases the pubkey before keying. Provisioning the same agent twice
converges to the same end state: cohorts replaced with the latest set, registry
row replaced and re-activated (`active = 1`). A re-provision is a safe way to
*update* an agent's cohorts or rate limit.

## 7. Consequences

- Deployments replace a 4-call seed script's two admin-side calls with **one**
  atomic, idempotent call. Key derivation and the agent's signed events remain
  the caller's two remaining responsibilities.
- The cohort vocabulary, pubkey validation, and registry column set are encoded
  **once**, in the handler, not per deployment script.
- `/register` and `/api/whitelist/add` keep working unchanged for callers that
  still want the granular paths.
- Validation/normalisation is a pure function (`normalize_provision`),
  unit-tested without a D1 binding; the atomic batch write is env-bound and
  exercised in the worker deploy.

## 8. Rejected alternatives

- **Cross-worker 2-phase commit.** Rejected — unnecessary (the tables co-reside)
  and out of scope; CF Workers + D1 offer no distributed-transaction primitive.
- **Teaching the relay worker to also write `agent_registry`.** Rejected — the
  governance/admin surface is the auth worker; the relay worker should not grow
  an admin governance endpoint. The auth worker already holds the `RELAY_DB`
  binding and the `require_admin` gate, so it is the correct home.
- **Accepting the agent privkey to publish kind-0/NIP-65 server-side.**
  Rejected — breaks the self-sovereign identity boundary; the server must never
  hold or sign with an agent's key.
