---
id: EXP-FB-008
parent_spec: forum-member-feedback-2026-09 item 8
linked_adrs: []
priority: critical
regression_critical: true
evidence_category: executable
status: accepted
authored_by: pair
---

## Expectation: a reply addressed to me reaches me, and cannot be silenced forever

Member feedback, verbatim: *"Replies and unread notification is not working. -
ingress particularly"*.

The investigation disproved the obvious hypothesis: replies **do** carry the
parent author's `["p", pubkey]` tag, and they use NIP-10 marked e-tags. Ingress
failed for two other reasons.

**1. A channel-wide read position suppressed per-topic replies.** Unread is
computed as `created_at > read_ts`, but `read_ts` is per *channel* while a
channel holds many topics — and it is stamped to the channel's newest message by
render-time effects. Opening a section's topic-title *list* marked every reply
in every topic of that section as read, having shown the reader nothing but
titles. A reply to your post in a topic you never opened was already
`created_at <= read_ts` before you could see it.

Fixed by making "addressed to me" bypass the read-position gate: a p-tag means
someone addressed this to you by name, which a channel-wide read marker does not
speak to. The baseline and own-post gates still apply, so this widens ingress
without opening a backfill floodgate and cannot notify you about yourself.

**2. The suppression was made permanent.** The producer inserted the event id
into the *persisted* `seen_messages` set **before** testing notifiability. Since
that set is serialised as `notified_ids`, any event evaluated during a transient
bad state — auth unresolved, a provisional `now` baseline, read positions freshly
clobbered — was burned in and could never notify again, on that reload or any
future one. That is what turned a recoverable glitch into permanent silence.

Fixed by classifying the verdict's *durability*: an id is recorded only when the
answer cannot change (we notified, or it is the user's own post, or it predates
the sync floor — both immutable). A read-position rejection is left
re-checkable, because read positions are written by render-time effects and can
be wrong.

Also fixed: an edited reply no longer drops the topic author's p-tag (see
EXP-FB-007).

### In scope
- `PostVerdict` + `classify_post` and the producer's ordering
- The directed-at-me ingress bypass
- Preserving the routing p-tag across an edit

### Out of scope (intentionally)
- **No dedicated inbound `#p` subscription was added.** Notifications remain a
  derived view over the channel firehose, so a reply in a channel not in your
  channel list — or older than the relay's default 500-row window — is still
  never seen. A `Filter { kinds: [42, 1111, …], p_tags: [me], since }` opened at
  app start is the right architecture and is the largest remaining gap.
- NIP-22 `kind:1111` replies are published by the chat Reply affordance but
  never subscribed, and `channels.rs` drops non-42 events and cannot read the
  uppercase `"E"` root tag. Those replies still vanish.
- Read positions remain per-channel rather than per-topic.
- Notification links still target `/chat/{cid}` rather than the forum thread,
  and that destination stamps the channel read on arrival.
- Mobile has no notification bell or bottom-nav entry.

### Counter-examples (must NOT happen)
- A post recorded as "already notified" on a ground that could later reverse
- A reply addressed to me suppressed by a channel-wide read position
- The bypass notifying me about my own post, or defeating the first-sync floor
