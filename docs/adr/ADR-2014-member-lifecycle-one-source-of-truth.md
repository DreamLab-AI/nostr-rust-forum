---
id: ADR-2014
title: One member lifecycle, one authoritative store, one admin surface
date: 2026-09-24
decision_status: proposed
implementation_status: none
activation_status: inactive
supersedes: []
superseded_by: []
verified_commit: 56e8c4f
owner: jjohare
review_trigger: phase 1 (the relay `members` projection) merging; any new writer to `whitelist`, auth `members` or `username_reservations`; any new admin tab or sub-view that lists people
repo: nostr-rust-forum
domain: IDENTITY-keys-and-trust.md
---

# ADR-2014 — One member lifecycle, one authoritative store, one admin surface

## Context

Membership is stored in two D1 databases that never reconcile: the auth worker's
`username_reservations` and `members` (`nostr-bbs-auth`) and the relay's `whitelist`
(`nostr-bbs-relay`), which the auth worker also writes through its `RELAY_DB` binding. The
admin panel derives "Pending" by subtracting one from the other in the browser. On
2026-09-24 the operator reported that 8 pending users bounced back after every approval.
The cause was that the client read only the first page (20 rows) of the relay whitelist
(fixed in `56e8c4f`, see Verification). That this was possible at all is the defect this
record addresses: three notions of "pending", four approve paths, five cohort derivations,
and four writers that replace a member's cohorts rather than merge them.

## Decision

### D1. Today's duplication (the map this decision replaces)

Paths are relative to `crates/`; lines verified at `56e8c4f`.

**Stores.**

| State | Where | DDL |
|---|---|---|
| Sign-up / handle / real name / dismissed | auth `username_reservations` (`status` `active`/`dismissed`) | `nostr-bbs-auth-worker/src/schema.rs:208`, `:232` |
| "Member" with admin flag and invite provenance | auth `members` | `nostr-bbs-auth-worker/src/schema.rs:116` |
| Access, cohorts, admin flag, trust, suspension, silence, notes | relay `whitelist` | **none in code**: base table only in `SETUP.md:82`; columns added at `nostr-bbs-relay-worker/src/lib.rs:638-648`; `expires_at` is read (`whitelist.rs:87,190,194,208,212`, `relay_do/storage.rs:353`) but defined nowhere |
| Invites | auth `invitations`, `invitation_redemptions` | `schema.rs:123`, `:136`, `zone_id` ALTER `:158` |
| WoT admission | auth `wot_entries` | `schema.rs:103` |
| Ban / mute | auth `moderation_actions` **and** relay mirror | `schema.rs:70`; `nostr-bbs-relay-worker/src/lib.rs:731` |
| Agents | relay `agent_registry`, `broker_roles` | `lib.rs:758`, `:825` |
| Key succession | relay `pubkey_aliases` | `lib.rs:838` |
| Devices | relay `device_keys` (created by the auth worker) | `nostr-bbs-auth-worker/src/devices.rs:123` |
| Admin audit | relay `admin_log` | `lib.rs:690` |
| NIP-05 handle | KV `POD_META nip05:{username}` | written `username.rs:279`, deleted `:382` |

**Writers to `whitelist`** (cohort semantics in bold where they destroy data):

| Path | Trigger | Semantics |
|---|---|---|
| `nostr-bbs-auth-worker/src/username.rs:307` | username claim (auto-whitelist) | `DO NOTHING` |
| `nostr-bbs-auth-worker/src/invites.rs:245`, `:271` | zone-bound invite redeem | insert then **merge** (the only merge) |
| `nostr-bbs-auth-worker/src/admins.rs:187` | `/api/admins/add` | `DO UPDATE is_admin=1` |
| `nostr-bbs-auth-worker/src/governance_api.rs:465` | `/api/governance/agents/provision` | **replace cohorts** |
| `nostr-bbs-relay-worker/src/whitelist.rs:315` | `/api/whitelist/add` | **replace cohorts**, keep `added_at` |
| `nostr-bbs-relay-worker/src/whitelist.rs:523` | `/api/whitelist/update-cohorts` | **replace** (and creates rows) |
| `nostr-bbs-relay-worker/src/whitelist.rs:395` | `/api/whitelist/set-admin` | update only |
| `nostr-bbs-relay-worker/src/user_admin.rs:197`, `:300`, `:363`, `:458` | delete, suspend, silence, notes | delete / update |
| `nostr-bbs-relay-worker/src/user_admin.rs:610` | `/api/admin/alias` with inherit | **replace cohorts** |
| `nostr-bbs-relay-worker/src/trust.rs:238`, `trust_sweep.rs:417` | activity, cron | trust level |
| `nostr-bbs-relay-worker/src/whitelist.rs:467` | `/api/admin/reset-db` | delete all |

Auth `members` is written only by invite redemption (`invites.rs:671`, `:877`) and
`/api/admins/*` (`admins.rs:207`, `:276`, `:335`). A username claim never writes it, so a
claim-joined user fails the invite tenure check (`invites.rs:141`). A plain invite writes
`members` but not `whitelist`. The UI demotes an admin through the relay's `set-admin`, which
leaves `members.is_admin = 1`. Admin status is resolved three ways: the auth worker's
`admin.rs:57`, the relay's `auth.rs:175-204` (which reads a `members` table the relay DB does
not have), and `nostr-bbs-core/src/admin_shared.rs:72-82`.

**Admin UI surfaces** (`nostr-bbs-forum-client/src`):

| Surface | Reads | Writes | Its idea of "pending" |
|---|---|---|---|
| Members → Active (`pages/admin.rs:521`, `admin/user_table.rs`) | `/api/whitelist/list` (all pages since `56e8c4f`), `/api/admin/registrations` again for names (`admin/mod.rs:222`) | add, update-cohorts, set-admin, delete (3 calls, `admin/mod.rs:462-545`), suspend, silence, notes, alias | none; trust is hardcoded "TL0" and silence always shows off, because the list omits both |
| Members → Pending (`admin/registrations.rs:44`) | registrations and the whitelist | `/api/whitelist/add` with `default_approval_cohort()` (`:26`); dismiss | reservations minus whitelist (`admin/membership.rs:105`) |
| Members → Access (`admin/section_requests.rs:38`) | kind 9021 events | `/api/whitelist/add` (**replaces cohorts**, `:314`), kind 9000/9005 with no `h` tag (rejected at `relay_do/nip_handlers.rs:980`) | every 9021 seen; nothing produces 9021 (`nostr-bbs-core/src/groups.rs:208` has no caller) |
| Members → Invites (`admin/invites.rs:85`) | `/api/invites/mine` | create; revoke sends the **code** (`:182`), and the server looks it up by **id** (`nostr-bbs-auth-worker/src/invites.rs:733`) | n/a |
| Overview stat and Members badge (`admin/overview.rs:92`, `pages/admin.rs:375`) | the Pending derivation | none | as Pending |
| Bell alerts (`stores/admin_alerts.rs:59`) | the whitelist | none | "awaiting zone access": whitelisted with no zone-gating cohort, a set that **no tab lists** |
| Agents (`admin/agents_roster.rs:196`) | `/api/governance/agents` | register (writes no whitelist row, so the agent cannot post) and revoke (leaves the whitelist row) | n/a |

The five cohort derivations are `pages/admin.rs:937`, `admin/user_table.rs:27`,
`admin/registrations.rs:26`, `stores/admin_alerts.rs:48` and `admin/invites.rs:70`. The relay's
`check-whitelist` also hardcodes the legacy `home/members/private` names
(`nostr-bbs-relay-worker/src/whitelist.rs:102-126`).

### D2. One lifecycle

A member is one row keyed by lowercase hex pubkey. It has exactly one `state`:

```
             claim / invite / WoT / admin-add / agent-provision
                               |
                               v
   +----------- requested ----------+
   | decline                        | approve (admin; or auto: invite, WoT, auto_approve zone)
   v                                v
declined                          active <--------------+
   | re-request (admin reopen)      | suspend / silence  | reinstate
   +--> requested                   v                    |
                                 suspended -------------+
                                    | remove
   active --remove--> removed <-----+
```

- `requested`: has a handle and optional real name, **no relay access**. This is Pending.
- `active`: relay access and one or more cohorts. Admin is a flag on an active member, not a
  state.
- `declined`: kept for audit and to hold the handle; can be reopened by an admin only.
- `suspended`: `suspended_until` (NULL means indefinite) plus a `silenced` flag, enforced on the
  device owner as well as the signing key.
- `removed`: a tombstone. The handle is released, the row is kept for audit and to block
  silent re-admission; events are purged only when the admin asks.
- **Cohorts** are a set on the member. Every grant is a **merge**; the only removal is an
  explicit revoke of a named cohort. No endpoint may replace the set wholesale.
- **Trust** (TL0–TL3) stays computed by the relay (`trust.rs`, ADR-2006) and becomes a column
  the admin list returns.
- **Agents** are members with `kind = 'agent'`. Provisioning creates an `active` member with the
  agent cohort merged in, and revoking suspends that member, in one transaction with
  `agent_registry`.
- **Zone access** is "has a cohort that a zone requires". "Awaiting zone access" is a filter
  over `active` members, not a separate pending state.

### D3. One authoritative store

The relay DB owns membership: a new `members` table in `nostr-bbs-relay` that supersedes
`whitelist`, with a checked-in migration (the first real DDL for this data). It holds
`pubkey`, `state`, `kind`, `cohorts`, `is_admin`, the trust columns, `suspended_until`,
`silenced`, `notes`, `handle`, `requested_at`, `decided_at`, `decided_by` and
`joined_via`. The relay is the admission point, so it keeps the data it enforces on its own
disk. `real_name` stays in the auth DB (the relay never sees real names) and joins by pubkey
at read time.

Auth `members` is retired: `is_admin` and `first_seen_at`/`joined_via_invite_id` move to the
relay row. `username_reservations` keeps only the handle registry (NIP-05) and real name, and
its `status` column is replaced by the member `state`. Every writer in D1 goes through one
relay module (`membership.rs`) exposing `request`, `approve`, `decline`, `grant_cohorts`,
`revoke_cohorts`, `set_admin`, `suspend`, `reinstate` and `remove`. The auth worker calls
it over a service binding or, as an interim step, over `RELAY_DB` using the same SQL constants
from `nostr-bbs-core`. Every transition writes `admin_log` in the same D1 batch. Admin
resolution becomes one query in `nostr-bbs-core/src/admin_shared.rs`.

### D4. One admin surface

The Members tab is one paginated, server-filtered table: `GET /api/admin/members?state=&cohort=&q=&cursor=`
returns state, cohorts, handle, real name (joined), trust, suspension and silence. The Pending,
Access and "awaiting zone access" views become filters (`state=requested`,
`state=active&cohort=none`). Invites stay a separate panel because they are not people. Row
and bulk actions call `POST /api/admin/members/transition` with
`{pubkeys: [...], action, cohorts?, reason?}`. The endpoint applies all transitions in one
batch and returns a per-pubkey outcome, so a bulk approve either commits or reports each
failure. The client keeps one cohort derivation (from `ZONE_CONFIG`) and no set arithmetic:
it renders what the server returns. The Section Access view is deleted until a producer of
kind 9021 exists.

### D5. Migration that disturbs no existing member

1. Create `members` alongside `whitelist`. Copy every `whitelist` row as `state='active'`,
   carrying cohorts, admin, trust, suspension, silence and notes verbatim; a past `expires_at`
   becomes `suspended_until` with the same value. OR the admin flag with auth
   `members.is_admin`. Copy `joined_via_invite_id` and `first_seen_at` where present.
2. Insert every `username_reservations` row not already present as `state='requested'`
   (`status='active'`) or `state='declined'` (`status='dismissed'`).
3. Normalise pubkeys to lowercase. Where two rows collide under case-folding, merge their
   cohorts, keep the earliest `added_at`, and record the merge in `admin_log`.
4. Dual-write for one release: the membership module writes `members` and mirrors `whitelist`.
   Admission reads `members`, falling back to `whitelist` on a miss, and logs every miss.
5. A reconciliation job (cron) compares the two stores and reports differences. Cut-over
   happens when it has reported zero differences for seven days. Then drop the fallback, stop
   mirroring and keep `whitelist` read-only for one further release before removal.

No member loses access, cohorts or admin status at any step. Nothing is deleted before the
cut-over, and step 1 is a pure copy.

### D6. Phased implementation and acceptance

| Phase | Scope | Acceptance tests |
|---|---|---|
| 0 (done, `56e8c4f`) | Client reads every whitelist page; one Pending derivation | `admin::membership::tests` (5 tests), including 28 members with 8 beyond page 1 |
| 1 | Checked-in DDL for `whitelist` including `expires_at`; merge-not-replace on the four replacing writers; lowercase pubkeys on write; invite revoke by code; list returns trust, suspension and silence | For each writer, a pure SQL-builder test that a grant never removes an existing cohort. Revoke-by-code test. Admin-list JSON includes the trust fields |
| 2 | Relay `members` table, migration D5 steps 1–3, `membership.rs` module and transition endpoint with audit | Migration fixture: N whitelist + M reservations (including case collisions and past `expires_at`) gives exactly N active and M' requested, with identical cohorts and admin flags. Every transition writes one `admin_log` row. Invalid transitions (e.g. `removed → active`) are refused |
| 3 | Dual-write, admission fallback, reconciliation cron | The reconciliation reports zero differences on the fixture. Admission is identical for every fixture pubkey under both stores. Suspension is enforced on a device key whose owner is suspended |
| 4 | Single Members table with filters and bulk transitions; delete Pending/Access sub-views and client set arithmetic | Bulk approve of 50 requested members leaves 0 in `state=requested` after refetch. A `wasm32` check. An e2e journey: sign up → appears under Requested → approve → can post |
| 5 | Retire auth `members`, `whitelist` fallback and `username_reservations.status`; one admin resolver | `grep` finds no reader of the retired tables. The admin resolver has one implementation, in `nostr-bbs-core` |

## Consequences

- The Pending bounce class of bug becomes impossible: the client no longer infers membership
  from two lists, and the server answers "who is pending" directly.
- Bulk actions become atomic and audited.
- Cohort grants stop destroying data.
- Agents and humans share one lifecycle, so an agent that is provisioned can post, and one that
  is revoked cannot.

Costs:

- A relay-DB migration and a dual-write period.
- The auth worker gains a hard dependency on the relay's membership module, via a service
  binding or shared SQL constants.
- `username_reservations.status` and auth `members` must be kept readable until phase 5.

Follow-on work:

- The living doc `IDENTITY-keys-and-trust.md` needs a Membership section when phase 2 lands.
- The stale kind-0 auto-whitelist prose at `nostr-bbs-relay-worker/src/relay_do/storage.rs:1-4`
  and `nostr-bbs-config/src/schema.rs:209-213` should be corrected in phase 1.

Forbidden after acceptance:

- Any new table or column that records whether a pubkey may use the relay, outside `members`.
- Any endpoint that replaces a member's cohort set.
- Any client-side derivation of membership state.

## Verification

Proposed; phases 1–5 are not built. The duplication map in D1 was taken by `grep -n` and
`sed -n` over the tree at `56e8c4f`. Nothing in this record was checked against a deployed D1.
In particular, whether production `whitelist` has an `expires_at` column is unverified: the
code reads it, but no DDL in the repository creates it.

Phase 0 evidence: `cargo test -p nostr-bbs-forum-client membership` fails at the parent
commit `a623ba8`'s single-page read ("8 members still pending after approval"; pager returned
20 of 250 rows) and passes at `56e8c4f` (5/5; full crate 460/460).
