# Evidence — EXP-FB-003 / EXP-FB-005 (custom emoji + Slack-style affordance)

## The defect

`components/reaction_bar.rs` at `11b674c`:

```rust
/// Common reaction emojis offered in the picker.
const REACTION_EMOJIS: &[&str] = &[ ... 8 entries ... ];   // :19-28
```

A compile-time const — no way for a member to add their own. And the affordance:

```rust
<button
    class="... text-sm"
    on:click=move |_| show_picker.update(|v| *v = !*v)
    aria-label="Add reaction"
>
    "+"                                                    // :~195
</button>
```

A literal `"+"`, which is what the member called "non standard, and non
intuitive".

## What shipped

New `stores/custom_emoji.rs`, persisted at `nostrbbs:custom-emojis`, following
`stores/preferences.rs`'s idiom (`get_local_storage()`, serde, cross-tab write
listener). Public API:

```rust
pub const MAX_CUSTOM_EMOJI: usize = 32;
pub const MAX_EMOJI_CHARS: usize = 16;
pub fn normalise_custom_emoji(raw: &str) -> Option<String>;
pub fn insert_capped(list: Vec<String>, item: String, cap: usize) -> Vec<String>;
pub struct CustomEmojiStore;  // emojis() / signal() / add() / remove()
pub fn provide_custom_emoji_store();
pub fn use_custom_emoji_store() -> CustomEmojiStore;
```

Entries are re-validated on load (localStorage is user-writable). Validation
bounds length and shape only — no emoji whitelist — so flags, ZWJ sequences and
skin-tone modifiers round-trip intact.

`use_custom_emoji_store()` **self-provisions** rather than `expect_context()`.
The file's own comments warn that an `expect_context` panic inside a message card
kills the whole WASM runtime; the fallback reads the persisted list, so only
cross-tab sync depends on the root call. `provide_custom_emoji_store()` is now
wired at the app root (`app.rs:325`), so cross-tab sync is active.

The `"+"` is replaced by an inline SVG smiley-with-plus (face circle, two filled
eye dots with `stroke="none"` so the 1.6 stroke does not blob them at 16px, a
smile arc, and a plus at the upper right clear of the face), with `title`,
`aria-label`, `aria-haspopup`/`aria-expanded`, and `role="dialog"` on the popover.

**Rest state, reasoned:** Slack fades the affordance in on hover. Copying that
literally makes it unreachable on touch, and this Tailwind config has no
`hover-hover:` variant to guard the fade with. So it is permanently visible at
`opacity-70`, brightening on `hover:`/`focus-visible:`. Opacity-only, so no
reflow in a dense message row. Same reasoning for the per-emoji remove control:
a permanently rendered 14px `×` with `stop_propagation()` so removing does not
also publish the reaction underneath.

## Tests

12 new pure host-target tests in `stores/custom_emoji.rs`:

```
normalise_trims_surrounding_whitespace
normalise_rejects_empty_and_whitespace_only
normalise_rejects_interior_whitespace_and_control_chars
normalise_rejects_over_long_input
normalise_accepts_multi_codepoint_sequences     (ZWJ family, flag, skin tone, VS16 heart)
insert_capped_appends_in_order
insert_capped_dedupes_without_reordering
insert_capped_evicts_oldest_first
insert_capped_trims_an_oversized_list_down_to_cap
insert_capped_with_zero_cap_is_a_noop
sanitise_list_drops_junk_dedupes_and_caps
sanitise_list_keeps_a_short_valid_list_intact
```

```
$ cargo test -p nostr-bbs-forum-client
test result: ok. 450 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
$ cargo check -p nostr-bbs-forum-client --target wasm32-unknown-unknown
(clean)
```

## Honest limits

- **Not visually verified.** The icon is described above and the markup compiles,
  but no rendered page or device was inspected.
- No pod-backed sync of the list (localStorage only, as the brief allowed), no
  settings-page manager, no emoji keyboard inside the popover.
- Dedupe leaves order alone rather than promoting to front — deliberate, so the
  grid does not reshuffle under a finger. Most-recently-used ordering would be a
  one-line change plus a test flip.
