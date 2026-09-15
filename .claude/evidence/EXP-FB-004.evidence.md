# Evidence — EXP-FB-004 (DM history)

## Defect 1 — `authors` on a gift-wrap filter

`crates/nostr-bbs-forum-client/src/dm/mod.rs:300-311` at `11b674c`:

```rust
let sent_filter = Filter {
    kinds: Some(vec![4, 1059]),
    authors: Some(vec![my_pk.clone()]),
    p_tags: Some(vec![partner_pk.clone()]),
    ..Default::default()
};
let recv_filter = Filter {
    kinds: Some(vec![4, 1059]),
    authors: Some(vec![partner_pk]),
    p_tags: Some(vec![my_pk.clone()]),
    ..Default::default()
};
```

A kind-1059 wrap's `pubkey` is a throwaway key
(`crates/nostr-bbs-core/src/gift_wrap.rs:243-283`, pinned by that file's own
`outer_pubkey_is_throwaway` test). The relay translates `authors` to
`pubkey IN (...)` (`crates/nostr-bbs-relay-worker/src/relay_do/filter.rs:79-94`).
No stored 1059 row can match. `load_conversation_messages` — the ONLY history
source for `/dm/:pubkey` — therefore returned zero gift wraps, always.

## Defect 2 — the relay's `#p` rewrite clobbers the bundled kind-4 query

`crates/nostr-bbs-relay-worker/src/relay_do/nip_handlers.rs:1637-1659`
(`gate_kind_1059_filters`) inserts `#p = <authed pubkey>` on every filter whose
`kinds` contains 1059. Because the client bundled kinds 4 and 1059 into one
filter, `{kinds:[4,1059], authors:[me]}` became
`{kinds:[4,1059], authors:[me], "#p":[me]}` — "events I authored and addressed
to myself" — destroying outbound kind-4 history too.

## Defect 3 — no self-addressed wrap

`gift_wrap_with_signer` (`gift_wrap.rs:475-484`) emits ONE wrap, encrypted to the
recipient and authored by a throwaway key. Live broadcast additionally goes only
to the recipient's session
(`crates/nostr-bbs-relay-worker/src/relay_do/broadcast.rs:49-99`). So the sender
could neither decrypt nor locate their own sent messages; the optimistic bubble
(`dm/mod.rs:374-403`) was the only copy and died with the page.

## Defect 4 — kind-4 decrypted with the wrong algorithm

`dm/mod.rs:874` called `signer.nip44_decrypt(...)` on kind-4 (NIP-04,
AES-256-CBC) content. Core already carried the correct helper at
`gift_wrap.rs:561-575`, whose doc comment states it "corrects the historical
mistake of calling `nip44_decrypt` on kind-4 content". Compounding it,
`crates/nostr-bbs-forum-client/src/auth/nip07.rs:219-225` implemented the
`nip04_decrypt` trait method by calling `nip07_nip44_decrypt`, so even a
corrected call site would still have used NIP-44 under a NIP-07 session.

## Tests added

### Core — the NIP-17 wrap pair

```
$ cargo test -p nostr-bbs-core wrap_pair
test gift_wrap::tests::wrap_pair_addresses_each_copy_to_exactly_one_party ... ok
test gift_wrap::tests::wrap_pair_copies_are_unlinkable_on_the_wire ... ok
test gift_wrap::tests::wrap_pair_self_copy_is_not_readable_by_the_recipient ... ok
test gift_wrap::tests::wrap_pair_copies_agree_on_the_rumor ... ok
test gift_wrap::tests::wrap_pair_lets_the_sender_read_their_own_sent_message ... ok

test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 393 filtered out
```

`wrap_pair_lets_the_sender_read_their_own_sent_message` is the direct regression
test for defect 3: it asserts the sender's own signer unwraps the self-copy.

### Client — filter SHAPE (the bug no crypto test could catch)

```
$ cargo test -p nostr-bbs-forum-client
test dm::tests::no_gift_wrap_filter_constrains_authors ... ok
test dm::tests::gift_wrap_and_legacy_kinds_never_share_a_filter ... ok
test dm::tests::gift_wrap_filter_is_addressed_to_me ... ok
test dm::tests::conversation_gift_wrap_filter_is_not_narrowed_to_the_partner ... ok
test dm::tests::conversation_legacy_filters_cover_both_directions ... ok
test dm::tests::inbox_legacy_filters_cover_sent_and_received ... ok
test dm::tests::only_the_realtime_wrap_filter_is_windowed ... ok
test dm::tests::gift_wrap_lookback_covers_the_nip59_randomisation_window ... ok

test result: ok. 442 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

`no_gift_wrap_filter_constrains_authors` fails against the pre-fix code and is
the regression test for defect 1; `gift_wrap_and_legacy_kinds_never_share_a_filter`
for defect 2.

### Compile

```
$ cargo check -p nostr-bbs-forum-client --target wasm32-unknown-unknown
(clean — no errors)
```

## Honest limits

- **No live relay round-trip was performed.** These tests assert filter shape and
  crypto round-trips, not that a real relay returns rows. The reasoning that
  connects them is documented above with relay-side `file:line` citations, but
  end-to-end confirmation needs a deployed relay and two accounts.
- Defect 4's NIP-07 half is **untestable on the host target** — it calls
  `window.nostr` — so it carries no automated test. It is a one-line
  namespace correction with a documented fallback.
- DMs are still not persisted locally (no IndexedDB store), so every navigation
  re-derives from the relay. That is now merely slow rather than lossy.
