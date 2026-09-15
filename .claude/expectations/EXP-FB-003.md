---
id: EXP-FB-003
parent_spec: forum-member-feedback-2026-09 item 3
linked_adrs: []
priority: low
regression_critical: false
evidence_category: executable
status: accepted
authored_by: pair
---

## Expectation: a member can add their own reaction emoji

Member feedback, verbatim: *"Configurable / add your own emojis"*.

The reaction picker's emoji set was a compile-time `&[&str]` const of eight.
`stores/custom_emoji.rs` adds a per-user list persisted to localStorage at
`nostrbbs:custom-emojis`, following the same idiom as `stores/preferences.rs`
(`get_local_storage()`, serde round-trip, cross-tab write listener). The picker
renders the built-ins, then the user's own, then a compact add box; each custom
entry carries a permanently-rendered remove control.

Validation bounds shape and length only — no emoji whitelist, so flags, ZWJ
sequences and skin-tone modifiers all survive a round-trip. The list is capped
at 32 entries and each entry at 16 chars so localStorage cannot grow unbounded.
Custom emoji flow through the existing `toggle_reaction` path unchanged; they
are ordinary NIP-25 kind-7 content strings.

### In scope
- `normalise_custom_emoji` / `insert_capped` as pure, host-tested free functions
- `CustomEmojiStore` with `emojis`/`signal`/`add`/`remove`
- Picker UI: custom row, add box, per-entry remove
- Root provider wired in `app.rs` for cross-tab sync

### Out of scope (intentionally)
- Pod-backed sync of the list. Local storage only, as the brief allowed.
- A settings-page manager — the picker's own remove control covers it.
- An emoji keyboard inside the popover; the OS picker is the right tool.
- Most-recently-used reordering. Re-adding an existing entry leaves the order
  alone, deliberately, so the grid does not reshuffle under a finger.

### Counter-examples (must NOT happen)
- A multi-codepoint emoji (family ZWJ, flag, skin tone) being mangled or rejected
- An unbounded localStorage entry
- A remove control that is unreachable on touch
