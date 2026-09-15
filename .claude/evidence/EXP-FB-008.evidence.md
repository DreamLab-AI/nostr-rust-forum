# Evidence — EXP-FB-008 (reply / unread ingress)

## What the investigation DISPROVED first

The obvious hypothesis — "replies carry no p-tag, so `#p` ingress is impossible"
— is **false**. `pages/thread.rs:585-607` publishes NIP-10 *marked* e-tags and
p-tags the topic author unconditionally:

```rust
let mut tags = vec![
    vec!["e", cid,     "", "root"],    // channel
    vec!["e", root.id, "", "reply"],   // topic root
    vec!["p", root.pubkey],            // <- topic-root author, unconditional
];
if parent_id != root.id {
    tags.push(vec!["e", parent_id, "", QUOTE_MARKER]);
    if parent_pk != root.pubkey && !parent_pk.is_empty() {
        tags.push(vec!["p", parent_pk]);
    }
}
```

The routing information was present. It was being discarded on the receiving
side.

## Defect 1 — a channel-wide read position suppresses per-topic replies

`stores/notifications.rs:751` computes unread as
`created_at > read_ts && created_at > baseline`. `read_ts` is keyed per
**channel** (`stores/read_position.rs:16`,
`localStorage["nostrbbs:read_positions"]`), but a channel holds many topics, and
three render-time effects stamp it to the channel's newest message:

| Site | Trigger |
|---|---|
| `pages/section.rs:262-289` | opening a section's **topic-title list** |
| `pages/thread.rs:331-356` | opening any ONE topic in the section |
| `pages/channel.rs:467-686` | the chat view, on every message arrival |

So glancing at a section index — which renders titles and nothing else — marks
every reply in every topic of that section read. A reply to your post in a topic
you never opened is `created_at <= read_ts` before you can see it.

Note the section-page effect is **not** gratuitous: it exists so the forum
index's "N new" chip can clear (comment at `section.rs:248-256`). Deleting it
would regress that. The fix therefore went on the notification side rather than
the read-position side.

## Defect 2 — the suppression was written into persistent storage first

`stores/notifications.rs:412-445` at `11b674c`:

```rust
if store.seen_messages.with_untracked(|s| s.contains(&event.id)) { continue; }
store.seen_messages.update(|s| { ...; s.insert(event.id.clone()) });  // :418-428
seen_changed = true;                                                  // :429
if !post_is_notifiable(...) { continue; }                             // :437-445
```

`seen_messages` is persisted as `notified_ids` under
`localStorage["nostrbbs:notif_sync:<pubkey>"]` (`:47`, `:713-715`). Writing an id
there is a permanent statement that the event has had its chance — and it
happened **before** the notifiability test. Any event observed during a transient
bad state (auth unresolved, the provisional `now` baseline at `:286-288`, read
positions freshly clobbered) was burned in and could never notify again. The
`MAX_SEEN_IDS` eviction drops an *arbitrary* `HashSet` element rather than the
oldest, so it does not reliably heal this either.

## The fix

`PostVerdict` distinguishes rejections that can never reverse (`OwnPost`,
`BeforeBaseline`) from one that can (`AlreadyRead`), and only the former are
burned into the persisted set. `classify_post` additionally takes
`directed_at_me`: a p-tagged post skips the read-position gate, because
"someone addressed this to me by name" and "this channel is marked read" are
different claims. The baseline and own-post gates are unchanged.

## Tests

```
$ cargo test -p nostr-bbs-forum-client
test stores::notifications::tests::a_read_position_rejection_is_not_permanent ... ok
test stores::notifications::tests::own_posts_and_pre_baseline_posts_are_permanent ... ok
test stores::notifications::tests::a_notified_post_is_permanent ... ok
test stores::notifications::tests::authorship_beats_a_reversible_rejection ... ok
test stores::notifications::tests::baseline_beats_read_position ... ok
test stores::notifications::tests::classify_post_agrees_with_the_legacy_predicate ... ok
test stores::notifications::tests::a_reply_addressed_to_me_survives_a_channel_wide_read_position ... ok
test stores::notifications::tests::being_addressed_does_not_defeat_the_immutable_gates ... ok

test result: ok. 450 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

`a_read_position_rejection_is_not_permanent` is the regression test for defect 2;
`a_reply_addressed_to_me_survives_a_channel_wide_read_position` for defect 1.
`classify_post_agrees_with_the_legacy_predicate` exhaustively pins the refactor
against the pre-existing suppression model over a 4×4×3×3 grid, so the
durability split cannot have changed *which* posts notify (only which are
permanently filed).

## Honest limits

- **The largest remaining gap is not fixed.** There is still no inbound `#p`
  subscription; notifications remain a derived view over the channel firehose.
  A reply in a channel that is not in your channel list, or older than the
  relay's default 500-row window, is still never seen. See EXP-FB-008
  "Out of scope" for the full list of what remains.
- No live multi-user round-trip was performed. The tests assert the pure
  suppression logic, not that a real second account's reply arrives.
