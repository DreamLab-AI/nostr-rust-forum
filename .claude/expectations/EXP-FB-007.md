---
id: EXP-FB-007
parent_spec: forum-member-feedback-2026-09 item 7
linked_adrs: []
priority: low
regression_critical: false
evidence_category: executable
status: partial
authored_by: pair
---

## Expectation: @-mentions work in posts, and render as links

Member feedback, verbatim: *"Can't @ other members in posts"*.

**Most of this was already built, and the report was about the rendered result
rather than the composer.** `MentionAutocomplete` is wired into the shared
`MessageInput`, which is what `pages/thread.rs` (reply + edit) and
`pages/section.rs` (new topic) already use; publish paths in `thread.rs`,
`section.rs`, `channel.rs` and `category.rs` all call `resolve_content_mentions`
to emit `["p", pubkey]` tags for typed `@handle`s as well as picked ones; and
`MentionText` already parses NIP-27 `nostr:npub1…`, raw-hex `@<64hex>` and
`@username`, rendering each as a highlighted badge.

The real gap was on the READING side: `PostBody` in `thread.rs` rendered
`<MentionText content=text />` **without passing the post's tags**. `MentionText`
resolves a typed `@handle` to a pubkey by pairing it with the event's `["p",
pubkey]` tags, falling back to the session NameCache and then to plain text —
so a mention of anyone not already cached this session degraded to grey text.
From a reader's seat that is indistinguishable from "@ doesn't work".
`ReplyView` now carries the event's tags through to `PostBody`.

Also fixed, from the notification investigation: editing a reply rebuilt its tag
list from scratch and **dropped the topic author's `["p", root.pubkey]` tag**,
so an edited reply became invisible to the person it replied to.

### In scope
- Threading the post's tags through `ReplyView` → `PostBody` → `MentionText`
- Preserving the topic-author p-tag across an edit

### Out of scope (intentionally) — and why this is `partial`
- The composer inserts `@handle` text, not a NIP-27 `nostr:npub1…` reference.
  Within this forum that resolves correctly (the p-tag carries the identity and
  `MentionText` renders the badge), but it is not interoperable with external
  Nostr clients, which look for the `nostr:` URI. Changing the inserted form is
  a wire-format change affecting four publish paths and every already-published
  post, so it is not a feedback-pass edit.
- `pages/board.rs`'s kanban card description textareas have no mention support.
  They are card metadata, not posts.

### Counter-examples (must NOT happen)
- A post rendering a mention as plain text when its own p-tags could resolve it
- An edit silently dropping a routing p-tag
