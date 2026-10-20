# Phase 2 design: separate inbox keys for zone grants and the session mirror

Status: design, awaiting two operator decisions before implementation. Implements ADR-2027
decision 2. Produced by an Opus specialist in the upgrade mesh and checked by the lead against
the code; file anchors are to `crates/nostr-bbs-relay-worker/src/relay_do/nip_handlers.rs`
unless stated.

## Goal

A zone-key grant (rumor kind 21453) or a session-mirror transcript (kind 14) must never be
addressed to a key that a member's other NIP-17 client can decrypt. Today both go to the member's
identity pubkey, so the moment a member advertises our relay in a public kind 10050, their
nostr.chat tab receives and opens them. This phase changes only where wraps are sent. It does not
protect against a stolen identity signer, which can still recover the inbox key.

## Decisions

1. **Inbox key: random, backed up as kind 30078 encrypted to the member's own identity**, `d` =
   `nostr-bbs/zone-inbox/v1`. Works identically for local-key and NIP-07 members, since a NIP-07
   signer offers NIP-44 encrypt and decrypt to self but no repeatable secret (its signatures and
   NIP-44 output are randomised, so subkey derivation is impossible there). The dormant device-key
   table is not reused: a device-key row lets the key act as its owner for whitelist, trust and
   zone writes (`effective_pubkey`, `:2627`), which an inbox key must never do.
2. **Registration: authenticated REST call to the auth-worker writing a private D1 row.** A public
   event would link identity and inbox key for every observer; a private row means the `p` tag on
   a wrap no longer identifies the recipient, an improvement on today. Table
   `recipient_keys(key PK, owner_pubkey, zone, role IN ('inbox','epoch'), created_at, revoked)`.
   `effective_pubkey` never reads it. Feature switch `RECIPIENT_KEYS_ENABLED`, default off. Grant
   issuers (`auto_grant`, `zone-migrate`, agentbox `zone-keys.js`) get a lookup endpoint limited to
   admins and zone owners.
3. **Relay rules.**
   - Admission (`:1149-1153`): `p` in `INGRESS_RECIPIENTS` accepts; `p` with an unrevoked inbox row
     accepts only if the owner is whitelisted; otherwise `p` itself must be whitelisted. An
     unregistered key is refused with its own reason, `blocked: gift-wrap recipient not registered`.
   - Reads: a session may read wraps for its own pubkey plus its registered inbox keys, set A,
     looked up per pubkey on demand and cached like `cached_device_owner`. It cannot be loaded at
     AUTH because `save_auth` (`:2085`) persists only the pubkey and the cache is empty after
     hibernation. REQ and COUNT (`:2128-2150`) cut the requested `#p` down to A, or set it to A when
     absent. `gift_wrap_readable_by` (`:169`, called at `:1893` and `:2449`) and `broadcast.rs:63-129`
     check against A.
   - Deletion lane for cleanup: `deletion_targets_others` (`:1296-1305`) treats a 1059 addressed to
     A as the member's own event, and the non-privileged SQL in `process_deletion` (`:2493`) gains a
     recipient branch. Without this, members below trust level 3 cannot remove their old grants.
   - Push (`push_fanout.rs:24,48`) looks up the raw `p`; inbox keys have no subscription, so grants
     trigger no notification, which is correct.
   - Missing row: sender gets `OK false`, and the grant ledger records a member only on `OK true`
     (`auto_grant.rs:153-165`), so the member is retried, not wrongly marked granted. Reader gets
     nothing and nothing reports it.
   - Rejected: a second connection authenticating as the inbox key. Every tab would need two
     sockets and the inbox key becomes a logged-in identity.
4. **Mirror: a dedicated mirror key, never the zone-inbox key.** Random key in agentbox secrets;
   pubkey added to `INGRESS_RECIPIENTS`, so no D1 row and it survives a reset;
   `AGENTBOX_MIRROR_RECIPIENT_PUBKEY` points at it (`/opt/agentbox/config/hooks/nostr-live-mirror.cjs:77-85`).
   In Amethyst the operator imports the mirror nsec instead of the operator nsec; AUTH does not
   check the whitelist (`:2059-2092`) so it reads its own wraps with no relay change. Never publish
   a 10050 for it. Importing the zone-inbox key into Amethyst would expose grants there.
5. **Existing grants: re-issue, then each member deletes the old copies.** Only the recipient can
   tell which of the wraps are grants: each is signed by a throwaway key with encrypted content,
   and the ledger stores member pubkeys, not wrap ids. The member's client unwraps every 21453
   addressed to its identity and sends a kind 5 per wrap through the new deletion lane. The grant
   ledger key (`grant_ledger.rs:18-24`) becomes `grants_sent:v2:<zone>:<epoch>` recording the
   recipient key, otherwise re-issue skips every member as already granted.
6. **Phase 4 carries over.** NIP-171 kind 1014 tickets go to the same inbox key under the same
   rules and lookup; ADR-2028's epoch pubkeys become `role='epoch'` rows maintained by an admin,
   able to receive wraps but never to log in. One conflict for later: a member reading zones in
   Anagram expects tickets at their identity key.
7. **Primitives: no new construction in this phase.** Phase 2 keeps core's `gift_wrap_kind` and
   `unwrap_gift_kind` with the inbox secret; only the recipient changes. Adopting the `nostr`
   crate's `EventBuilder::gift_wrap` and `UnwrappedGift::from_gift_wrap` is a separate follow-up,
   and the lead confirmed in `nostr-0.44.3/src/nips/nip59.rs:85-125` that upstream decrypts the
   wrap before verifying anything and never checks the wrap's own signature. ADR-2025 requires the
   outer verification first. So the follow-up is "upstream builder for construction, ADR-2025
   wrapper for unwrap", not a wholesale replacement.

## Migration order

1. Table, endpoints, relay rules, behind `RECIPIENT_KEYS_ENABLED` off.
2. Mirror key and ingress entry (independent of the rest; agentbox repository).
3. Client creates, backs up, registers and subscribes to the inbox key; DMs stay on identity.
4. Issuers look up inbox keys, switch to the v2 ledger, re-issue.
5. Members' clients delete old grant wraps.
6. `public_inbox` opt-in (Phase 3) requires a registered inbox key and finished cleanup.

## Tests

Relay admission: registered key accepted; revoked refused; owner not a member refused;
unregistered refused with its own reason; outsider's wrap to a non-member still refused.
Relay reads: REQ and COUNT with `#p` = inbox key return to the owner only; another member's
session sees nothing; set A survives hibernation (lookup on demand). Deletion: member below TL3
deletes a 1059 addressed to their inbox key; cannot delete one addressed to another member.
Client: backup record round-trips through NIP-44 self-encryption for local and NIP-07 signers;
registration failure leaves no inbox key in use; v2 ledger does not skip re-issue. Mirror: a wrap
to the mirror pubkey is admitted via ingress with no D1 row.

## Operator decisions before implementation

- **D1. Cleanup of old grants.** Members' clients delete old grant wraps (recommended: the only
  party that can identify them, and it leaves no readable copy on the relay), versus leaving them
  until each member's 10050 points elsewhere (simpler, but every historical grant stays readable
  by any NIP-17 client of that member for as long as it remains on the relay).
- **D2. Mirror reading.** Switch Amethyst to the mirror key (recommended: zero relay change,
  grants never enter the phone) versus keeping the operator nsec in Amethyst and accepting that the
  phone can decrypt grants (status quo risk, no action).

## Landing: how the dual paths come down

Every dual path in Phases 2 to 4 exists so that a member who is mid-migration is never cut off:
inbox key beside identity key, v2 ledger beside v1, 1014 tickets beside 21453 grants, derived
epochs beside legacy ones, kind-42 `zk` transport beside NIP-171 rumors. None of it is protocol
debt. It is transition scaffolding, and it comes down on a cutover date the operator sets.

Before cutover, any member who logs in crosses automatically: the client registers an inbox key
and receives a ticket in the background. After cutover the relay admits only the new shapes.
A member who did not log in before cutover keeps their identity or takes a new one; an admin
re-whitelists it and the zone owner issues a ticket to its inbox key. The imported-epoch record
(ADR-2028 decision 3) lets the owner grant full history, so the only cost of missing the
automatic path is one admin action. A new identity is clean for everything except authorship:
posts signed by the old key stay attributed to it, and there is no honest way to re-author them.

The removal release then deletes: 21453 build and parse everywhere (client, migrator, agentbox
module), the v1 ledger fallback, the identity-key grant subscription, random epoch generation,
and the ADR-2017 sealed-original reader once sealed originals are recorded as imported epochs.
`RECIPIENT_KEYS_ENABLED` and `GRANT_SWEEP_ENABLED` stop being flags. What remains by decision:
the `zk` tag on kind 42 (our transport) and one imported-epoch record per zone (the price of not
re-signing ciphertext). The cutover date is an operator decision and is recorded in ADR-2028 when
Phase 4 begins.
