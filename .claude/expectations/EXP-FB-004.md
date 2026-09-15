---
id: EXP-FB-004
parent_spec: forum-member-feedback-2026-09 item 4
linked_adrs: []
priority: critical
regression_critical: true
evidence_category: executable
status: accepted
authored_by: pair
---

## Expectation: a DM conversation's history is fetchable, and the sender keeps their own copy

Member feedback, verbatim: *"DM history isn't viewable - more generally broken"*.

Four independent defects made this true; all four are fixed.

**1. Gift-wrap filters must not constrain `authors`.** A NIP-59 kind-1059 wrap is
signed by a throwaway key minted per message, so any `authors` constraint matches
zero rows at the relay. `conversation_filters` / `inbox_filters` /
`incoming_filters` build gift-wrap filters keyed on `#p` alone; the conversation
is selected locally after unwrapping, because a wrap exposes no relay-visible
hint of which conversation it belongs to.

**2. Kinds 4 and 1059 are queried by separate filters.** The relay's DM privacy
gate rewrites `#p` to the authenticated pubkey on any filter mentioning kind
1059. Bundling kind 4 into that filter let the rewrite clobber the legacy query
and destroy outbound kind-4 history as collateral damage.

**3. Sending publishes the NIP-17 wrap PAIR.** `gift_wrap_pair_with_signer`
seals one rumor twice — once to the recipient, once to the sender — and wraps
each. Both copies reconstruct an identical rumor; the two wraps carry distinct
ids and distinct throwaway authors so they stay unlinkable on the wire. Without
the self-copy a sent message is write-only for its author and does not survive a
reload.

**4. Kind-4 DMs decrypt with NIP-04.** Kind 4 is AES-256-CBC, not NIP-44; the
client called `nip44_decrypt`, so every legacy DM failed and was dropped with a
console warning. Both the call site and the NIP-07 bridge (which hard-wired
`nip04_decrypt` to `window.nostr.nip44`) now use NIP-04, falling back to NIP-44
only when the extension exposes no `nip04` namespace.

Additionally, the rendered message list is scoped to `current_conversation`: the
inbound subscription is necessarily inbox-wide (see 1), so an unscoped view
rendered a third party's DM inside whatever conversation happened to be open.

### In scope
- `dm/mod.rs` filter builders + host-target tests asserting filter SHAPE
- `nostr_bbs_core::gift_wrap_pair_with_signer` + its five tests
- NIP-04 decryption at the call site and in the NIP-07 bridge
- Conversation scoping of the `messages()` memo

### Out of scope (intentionally)
- Durable local DM persistence (no IndexedDB store for DMs). Re-derivation from
  the relay now works, so this is an optimisation, not a correctness fix.
- Relay-side `ORDER BY created_at` on 1059 sorting by the randomised wrap
  timestamp — only bites once a conversation exceeds the 500-row default limit.
- A `CLOSED` frame handler in the relay client (failures still surface only via
  the 3s missing-EOSE retry).

### Counter-examples (must NOT happen)
- Any kind-1059 filter carrying `authors`
- Kinds 4 and 1059 sharing one filter
- A history (non-realtime) filter carrying `since`
- A sent message that its own author cannot decrypt
