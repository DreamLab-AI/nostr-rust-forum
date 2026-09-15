# Evidence — EXP-FB-007 (@-mentions in posts)

## What was already built

The member reported *"Can't @ other members in posts"*. Most of the feature
exists and works:

- `components/mention_autocomplete.rs:451` — `MentionAutocomplete`, wired into
  `components/message_input.rs:864` and `pages/dm_list.rs:350`.
- `pages/thread.rs:971` (reply composer), `:1227` / `:1350` (edit composers) and
  `pages/section.rs:465` (new topic) all use `MessageInput`, so the autocomplete
  is present in the post composers.
- `resolve_content_mentions` emits `["p", pubkey]` for *typed* `@handle`s as well
  as picked ones, called from `thread.rs:619`, `thread.rs:735`, `section.rs:591`,
  `channel.rs:736`, `category.rs:665`.
- `components/mention_text.rs` parses NIP-27 `nostr:npub1…` (`:203`, `:227-239`),
  raw-hex `@<64hex>` and `@username`, rendering each as a highlighted badge, with
  bech32 decoding at `:341`.
- `mention_autocomplete.rs:158-176` carries a known-users seed so a mention
  resolves even with a cold ProfileCache and no search backend.

So the composer half of the complaint did not reproduce.

## The actual gap — the reading side

`pages/thread.rs:1027` at `11b674c`:

```rust
{(!text.is_empty()).then(|| view! { <MentionText content=text /> })}
```

`MentionText`'s own doc (`mention_text.rs:44-50`) states that `@username`
mentions resolve via the event's `["p", pubkey]` tags *when supplied*, via the
NameCache otherwise, and fall back to **plain text** when neither resolves.
`PostBody` supplied no tags. So a mention of anyone not already in this session's
NameCache rendered as grey text with no link — which from a reader's seat is
exactly "@ doesn't work".

Fixed by carrying the event's tags on `ReplyView` (`thread.rs:77`), populating
them at both construction sites (`:484`, `:505`) and threading them through
`PostBody` into `MentionText`.

## Second defect, found via the notification investigation

`pages/thread.rs:711-745` rebuilds an edited reply's tag list from scratch:
`root`/`reply`/`edit` e-tag markers plus mention p-tags — but **not** the
`["p", root.pubkey]` tag that the original publish adds unconditionally at
`:592`. An edited reply therefore lost the routing p-tag and became invisible to
the person it was a reply to. Now re-added explicitly.

## Verification

```
$ cargo check -p nostr-bbs-forum-client --target wasm32-unknown-unknown
(clean)
$ cargo test -p nostr-bbs-forum-client
test result: ok. 450 passed; 0 failed
```

`mention_text.rs`'s existing parse tests (including `parse_npub_mention` at
`:459`) continue to pass; no new test was added for the tag-threading because the
change is a prop pass-through whose behaviour is already covered by those tests
plus `MentionText`'s tag-resolution path.

## Honest limits

- **This item is `partial`, not fully shipped.** The composer inserts `@handle`
  text, not a NIP-27 `nostr:npub1…` reference. Inside this forum that resolves
  (the p-tag carries the identity), but it is not interoperable with external
  Nostr clients, which look for the `nostr:` URI. Changing the inserted form
  touches four publish paths and every already-published post, which is beyond a
  feedback pass.
- The tag-threading fix is **not visually verified** — it compiles and the
  resolution path it feeds is tested, but no rendered page was inspected.
