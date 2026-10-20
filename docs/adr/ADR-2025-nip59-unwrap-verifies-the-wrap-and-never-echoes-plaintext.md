---
id: ADR-2025
title: NIP-59 unwrap verifies the outer wrap first and never echoes decrypted bytes in an error
date: 2026-10-19
decision_status: accepted
implementation_status: complete
activation_status: staged
supersedes: []
superseded_by: []
verified_commit: fb9ef30 (working tree on top of it; re-record on commit)
owner: DreamLab-AI/nostr-rust-forum maintainers
review_trigger: Any proposal to refuse a rumor that carries a `sig` or a seal with tags, or to add a script-src to the client CSP
repo: nostr-rust-forum
---

# ADR-2025 — NIP-59 unwrap verifies the outer wrap first and never echoes decrypted bytes in an error

## Context

A review of lnbits/anagram (Svelte Nostr messenger, 2026-10) against this workspace found the
primitives equal (both delegate NIP-44 v2 to an audited upstream; both backdate seal and wrap
timestamps, past only) but three conventions missing here. The three gift-wrap readers
(`nostr-bbs-core::gift_wrap`, `nostr-bbs-forum-client::zone_crypto::unwrap_any`,
`nostr-bbs-zone-migrate::grants::open_gift_wrap`) decrypted a kind-1059 without checking the
wrap's own id and signature. Parse failures on decrypted layers passed serde's message through,
and serde quotes the offending value (`invalid type: string "..."`), so a malformed rumor could
copy decrypted bytes into a console line. The forum client, served from GitHub Pages, shipped no
Content Security Policy at all. The forum and its DMs are live; nothing stored may stop opening.

## Decision

1. **Every reader verifies the outer wrap before decrypting.** `verify_event_strict` runs on the
   kind-1059 first in all three readers. Core reports it as the new variants
   `GiftWrapError::WrapVerification` and `SignerGiftWrapError::WrapVerification`. This is a shape
   check, not a sender check: the wrap key is a throwaway. The seal verification and the
   `rumor.pubkey == seal.pubkey` binding remain the checks that protect the recipient.
2. **Every error on an unwrap path is a fixed string.** Decrypt and parse failures name the layer
   (`gift wrap layer`, `seal JSON malformed`, `rumor JSON malformed`) and nothing else. The
   `SignerGiftWrapError::Signer` variant keeps the backend's text, which names an extension
   capability or refusal, never message content; the forum client matches on that variant, then
   on its text, to detect an extension without NIP-44, and shows one fixed sentence per failure
   category. The extension's own rejection value can reach the DM error banner through that
   variant. It is text the extension wrote about itself, not decrypted bytes, and is accepted.
3. **A rumor carrying a `sig` is tolerated, not refused.** NIP-59 says the rumor MUST be unsigned,
   but the relay admits wraps from clients this workspace does not control and a signed rumor
   costs its sender deniability without letting anyone forge a message. Refusing it would risk
   stored DMs. The same reasoning keeps seals with tags accepted. Both stay tolerated until a
   measured need says otherwise (see `review_trigger`).
4. **The forum client carries a meta CSP of `object-src 'none'; base-uri 'none'; form-action
   'self'` and `referrer: no-referrer`.** No `script-src`: Trunk injects an inline loader whose
   hash changes per build and the deploy step rewrites the `window.__ENV__` block, so a hash list
   could not be kept honest. `frame-ancestors` is header-only and GitHub Pages sends no headers.
   `no-referrer` keeps the forum URL, which names the channel or DM thread being read, out of the
   request logs of every linked site and embedded image host. The one embed that needs a Referer,
   the YouTube iframe in `components/media_embed.rs`, opts back in with
   `referrerpolicy="strict-origin-when-cross-origin"`.

Not adopted from the review, with reasons recorded: a NIP-44 conversation-key cache (unmeasured
cost, would add secret-derived state to the published crate); a zone-key recovery master
(ADR-2026, proposed, because the first design re-derived secrets removed members still hold).

## Consequences

- The wire format is unchanged: rumor, seal, wrap, the kind-21453 grant payload
  `{zone, epoch, secret, pubkey, created_at}` and the `zk` tag are byte-identical. Every wrap the
  deployed relay stores already passed `verify_event_strict` on ingest, so none fails the new check.
- `nostr-bbs-core` 1.0.0-beta.18 adds a variant to two public enums that are not
  `#[non_exhaustive]`; an outside exhaustive `match` breaks. The one exhaustive match in this
  workspace, the DM send-failure text, was updated in the same change.
- Console lines and the DM error banner no longer carry anything derived from plaintext.
- A browser-level key-exposure test (anagram records every request, WebSocket frame and console
  line and asserts the nsec and a plaintext canary appear in none) is deferred: the repo has no
  browser harness. The unit-level analogue (Display and Debug of every unwrap error checked
  against a canary) is in place in core and the client.

## Verification

At the working tree over `631c09f`: `cargo test -p nostr-bbs-core --lib gift_wrap` 38 passed,
including `unwrap_rejects_tampered_outer_wrap`, `signer_unwrap_rejects_tampered_outer_wrap`,
`unwrap_errors_never_echo_decrypted_content`, and the compatibility set
`legacy_seal_without_rumor_id_still_opens`, `rumor_signed_by_a_foreign_client_still_opens`,
`non_dm_rumor_kinds_still_open_through_both_paths`, `seal_with_tags_from_a_foreign_client_still_opens`.
`cargo test -p nostr-bbs-forum-client` 715 passed including
`grant_unwrap_refuses_a_tampered_wrap_before_decrypting` and
`grant_unwrap_errors_never_echo_decrypted_bytes`; `cargo test -p nostr-bbs-zone-migrate` including
`tampered_wrap_is_refused_before_any_decryption`. `cargo clippy --workspace --all-targets
--all-features -D warnings` clean; `cargo check --target wasm32-unknown-unknown -p
nostr-bbs-forum-client` clean; `cargo doc --no-deps -p nostr-bbs-core` no warnings. Full-suite
results for the other unwrap callers (mesh, poker-citizen, bbs-client) and the deepsec gate are
reported in the change that lands this record.
