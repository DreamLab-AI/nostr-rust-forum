---
id: ADR-2022
title: Declare gift-wrap recipients in config so the relay admits them without a whitelist row
date: 2026-10-15
decision_status: accepted
implementation_status: complete
activation_status: staged
supersedes: []
superseded_by: []
verified_commit: ec8621a
owner: jjohare
review_trigger: the gift-wrap admission rule changes, or a client library for form ingress is added to the kit
repo: nostr-rust-forum
domain: IDENTITY-keys-and-trust.md
lineage: extends the recipient-keyed gift-wrap admission rule (legacy ADR-104).
---

# ADR-2022 — Declare gift-wrap recipients in config so the relay admits them without a whitelist row

## Context

A static site can take contact enquiries, signups and chat messages with no database: the browser
gift-wraps (NIP-59) each message to a recipient pubkey and publishes the wrap to the relay. The relay
admits a kind-1059 wrap only if its recipient is whitelisted in D1, and `POST /api/admin/reset-db`
empties that table. After a reset every such form fails with "gift-wrap recipient not whitelisted"
until someone re-runs a manual step. Operators also keep the recipient pubkeys in several hand-synced
places, and a second recipient (for example a monitoring key that reads a copy) has no declared home.

## Decision

1. `forum.toml` gains an optional `[[ingress]]` table array: `label`, `pubkey`, `role`
   (`primary` | `copy` | `agent`), optional `description`, optional `authorised_by`. An empty or absent
   list is valid and changes nothing.
2. The deploy pipeline renders the list with `nostr_bbs_config::ingress::ingress_relay_var` into the
   relay worker's `INGRESS_RECIPIENTS` binding. The worker reads it with `parse_ingress_relay_var`, which
   **fails closed**: a missing or malformed binding yields no recipients and bad entries are dropped.
3. In the kind-1059 branch of the admission gate only, a recipient in that list is admitted without a
   D1 lookup; every other recipient must still be whitelisted. Events an ingress key *authors* are checked
   against the whitelist exactly as before.
4. `GET /api/check-whitelist` adds `ingressRecipient` (boolean). It does not change `isWhitelisted`
   or the access flags.
5. `GET /api/agents/disclosure` merges entries that have an `authorised_by`, at read time, with no writes.
   A registry row for the same pubkey wins.

## Consequences

- A declared recipient survives `reset-db`, and the recipient list is reviewed in `forum.toml` rather
  than rebuilt by hand.
- Declaring grants no cohort, no admin right and no zone key. An ingress key must not be given the
  `agent` cohort: that cohort receives the key of any zone with `agent_keys = true`.
- Each additional recipient is another copy of every message and another key able to read it. The
  recipient remains an open inbox bounded only by the relay's per-IP rate limit.
- Not covered: the admin Agents roster (auth worker), and a browser or embed library for building the
  wraps, which operators still supply.

## Verification

`cargo test -p nostr-bbs-config -p nostr-bbs-relay-worker` covers validation, the render/parse round
trip, the fail-closed counter-examples (malformed, empty, stranger, junk principal), the disclosure
merge (registry wins, unattributed entries omitted), and a structural test that the gate consults the
list only inside the gift-wrap branch. Surviving a live `reset-db` is argued from those tests, not run.
