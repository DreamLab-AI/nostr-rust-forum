# Deploy runbook: Phases 0 to 4 (dormant), and the cutover that is NOT part of it

> Status: readiness runbook. Nothing here has been executed. Deploying and
> migrating are production, outward-facing actions and need explicit operator
> go. This document is the plan to approve, not a record of work done.

## What this deploy is, and is not

It ships the Phases 1 to 4 code to production **dormant**. Every new behaviour
sits behind a flag that is off, so a correctly sequenced deploy changes nothing
a member can see. It is a code-in-place step, not an activation.

The feature flags and their production state for this deploy:

| Flag | Where | This deploy |
|---|---|---|
| `RECIPIENT_KEYS_ENABLED` | relay + auth worker vars | absent / `"false"` — OFF |
| `ZONE_GROUPS_ENABLED` | relay var | absent — OFF |
| `GRANT_SWEEP_ENABLED` | client `window.__ENV__` | absent — OFF |
| `public_inbox` opt-in | per member, client | OFF by default |

With the flags off, `ensure_schema` does not create `recipient_keys`,
`recipient_keys.proof` or `zone_epoch_keys` (gated at `lib.rs:860-899`), and the
D1 migrations `0011`/`0012`/`0013` are not applied (migrations run only by an
explicit `wrangler d1 migrations apply`, never on a worker deploy). So the new
schema stays absent until activation. Keep it that way for this deploy.

## The one hard precondition: RELAY_URL

The NIP-42 relay-tag check now **fails closed**. The shipped `wrangler.toml` has
`RELAY_URL = ""`, and a relay deployed with it blank **refuses every
authenticated write** and logs an error on each AUTH. This is deliberate
(ADR-2029 security review): the relay never derives its identity from the
request. So `RELAY_URL` must be set in production **before** the relay deploys,
or the board stops accepting posts and DMs.

This also closes a genuine pre-existing production exposure: the live relay today
runs with the relay-tag check skipped, so it is worth setting `RELAY_URL` even
ahead of this deploy.

```
# Set the relay's own wss:// URL as a production var (exact, canonical).
cd crates/nostr-bbs-relay-worker
wrangler secret put RELAY_URL          # or a [vars] entry in the prod config
#   value: wss://<the host clients actually connect to>
# If the relay answers at more than one hostname, also:
wrangler secret put RELAY_URL_ALIASES  # comma-separated wss:// URLs
```

Note: production D1/R2 are named `dreamlab-*`, while the repo config says
`nostr-bbs-*`; production deploys from an out-of-repo config (see
`disaster-recovery.md` §0). Set `RELAY_URL` in whichever config production
actually deploys from.

## Order

1. **Branch merged and CI green.** `feat/upgrade-phase-0-1` merged to `main`;
   GitHub CI green (it runs on PR and `main`, not on the branch alone).
2. **Backup first.** Run `scripts/dr-export.sh <dir outside the repo>`; record the
   D1 Time Travel bookmark and the per-table counts. A restore rehearsal into a
   scratch D1 was exercised on 2026-10-20 (`disaster-recovery.md`).
3. **Set `RELAY_URL`** (and aliases) in the production relay config. Confirm the
   flags above are off/absent in that config.
4. **Deploy the relay worker.** Immediately verify a member can authenticate and
   post: AUTH must succeed (proves `RELAY_URL` matches), reads and writes behave
   as before. If AUTH fails with `invalid: relay url unconfigured`, `RELAY_URL`
   is wrong or unset — fix it, no rollback of code needed.
5. **Deploy the auth worker.** `RECIPIENT_KEYS_ENABLED="false"` keeps the
   recipient-key routes returning 404. No migration applied.
6. **Deploy the pod worker** (unchanged by this work; deploy only if its code
   moved).
7. **Deploy the clients** (forum-client, bbs-client) to GitHub Pages. Do not
   inject `RECIPIENT_KEYS_ENABLED`, `ZONE_GROUPS_ENABLED` or `GRANT_SWEEP_ENABLED`
   into `window.__ENV__`; absent means off.
8. **Verify dormancy.** A member sends a DM and a channel post, reads existing
   zone content, opens the kanban. All unchanged. The DM relay-list, requests
   inbox, tickets and inbox keys do nothing yet.

## Rollback

Code rollback is `wrangler rollback` (or redeploy the previous version) per
worker. D1 is untouched because no migration was applied and `ensure_schema`
created nothing, so there is no schema to revert. The clients redeploy the
previous Pages build. D1 Time Travel from step 2 is the data safety net, not
expected to be needed for a dormant deploy.

## The cutover and first zone migration are NOT this deploy

ADR-2028's cutover clock (30 days, operator-chosen) starts when this deploy
lands. The cutover and the first zone migration are separate, gated, and **not
executable yet**:

- **Owner tooling is unbuilt.** The NIP-171 key plane ships dormant, but the
  owner flow that generates a zone's recovery master, registers the group
  identity and issues the first `kind:1014` tickets has no caller yet (p4c's
  `register_group_identity` / `HeldGroupIdentities` await it). This is Phase 4
  step 4 and was deliberately deferred; it must be built before any zone moves.
- **The epoch-binding hard blocker** (ADR-2028): `ZONE_GROUPS_ENABLED` must not
  be turned on anywhere until the epoch binding is owner-only. That is part of
  the same owner tooling.
- **Activation sequence, when the tooling exists**, per the Phase 2 design's
  landing section: turn on `RECIPIENT_KEYS_ENABLED`, register inbox keys,
  re-issue grants to them, confirm the ledger, then (optionally) the sweep; then
  per-zone, smallest first, with the owner holding the master, migrate to
  NIP-171 after a fresh backup and a dry run. The NIP-17 overlay opt-in
  (`public_inbox`) is a separate per-member activation.

So the immediate deliverable the operator can approve is the **dormant deploy
above**. Cutover is a later, separately approved step that first needs the owner
tooling built.
