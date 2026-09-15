# Evidence — EXP-FB-002 (mobile thread density + overlap)

## Overlap root cause

`crates/nostr-bbs-forum-client/src/pages/channel.rs:816` and
`src/pages/dm_chat.rs:166`:

```rust
<div class="flex flex-col h-[calc(100vh-64px)]" ...>
```

Viewport minus the 64px sticky header. `.mobile-bottom-nav`
(`style.css:394-400`) is `position: fixed`, ~55px plus
`env(safe-area-inset-bottom)`, and is not accounted for. The existing
`main { padding-bottom: calc(4rem + env(...)) }` (`style.css:407-410`) cannot
compensate because the column's height is absolute rather than content-driven:
ancestor padding makes the page taller without moving the column's bottom edge
off the nav.

Second instance, same defect: `src/components/notification_center.rs:114` —
`fixed top-16 h-[calc(100dvh-4rem)] z-50`, bottom edge at the viewport floor,
same stacking context as the nav.

The **thread page itself** has no sticky or fixed composer —
`#thread-reply-composer` is an ordinary block at the end of the flow — so the
thread-page half of the complaint was vertical rhythm only, not z-overlap. A
sweep of `position: absolute|fixed|sticky`, negative margins and
`transform: translate` across the thread reading surfaces found only the
popover anchors (`message_bubble.rs:165`, `message_input.rs:919`), which are
correct.

## Changes

`style.css` only: +271 / −2. No `.rs`, `index.html`, `design-tokens.css` or
`tailwind.config.js` touched.

§19 rewritten to publish `--forum-mobile-nav-h: 3.5rem` on `:root` inside
`@media (max-width: 639px)`, with `:root:not(:has(.mobile-bottom-nav))` zeroing
it so a signed-out reader (the nav is `<Show when=is_authed>`) does not get a
dead 56px strip. Degrades to the reserved band in browsers without `:has()`.

§31 appended, per-block:

| Block | Fix | Delta |
|---|---|---|
| 31a | `h-[calc(100vh-64px)]` and `h-[calc(100dvh-4rem)]` re-derived from `100dvh` minus header, nav token and safe-area inset | the overlap; also kills the iOS `100vh` large-viewport bug |
| 31b | `#thread-reply-composer { scroll-margin-bottom }` (the Reply tap calls `scroll_into_view()`, `thread.rs:673-679`) | composer never lands behind the nav |
| 31c | thread gutter `p-4` → `0.75rem`, qualified `:has(article.rounded-xl.p-5)` because `section.rs:357` shares the root signature | −25% |
| 31d | topic-root card `p-5 mt-4` → `0.875rem` / `0.75rem` | −30% / −25% |
| 31e | reply card `p-4` → `0.75rem 0.8125rem` | −25% |
| 31f | reply stack `space-y-3` → 8px, qualified past Tailwind's own (0,3,0) selector | −33% |
| 31g | `mt-6` wrapper → 1rem; `h3 mb-3` → 0.5rem | −33% |
| 31h | composer `mt-6` → 1rem | −33% |
| 31i | avatar/meta `gap-3` → 0.625rem, scoped to the two thread cards | −17% |
| 31j | nested indent 30px → 20px, keeping the 2px rule as the nesting signal | −33% |
| 31k | send button (32px) given a transparent 44px `::after` hit expander; visual size unchanged | 32 → 44px |

No colour declarations added, so `LIGHT_THEME_CSS` and the
`[data-density="compact"]` overrides in `stores/preferences.rs` are untouched
and compose cleanly — they target `.glass-card` / `.space-y-6` / `.space-y-4` /
`.py-3`, none of which §31 touches.

## Verification

```
$ cd crates/nostr-bbs-forum-client
$ ./.tailwindcss -c tailwind.config.js -i tailwind.css -o /tmp/tw-check.css --minify
Done in 1946ms.     # exit 0, 69387-byte output
```

That compiles `tailwind.css` only, so the edited file was additionally parsed
through the same PostCSS pipeline:

```
$ ./.tailwindcss -c tailwind.config.js -i style.css -o /tmp/style-parse-check.css
Done.               # exit 0
```

Emitted utility selectors were diffed against the hand-written ones to confirm
the escapes match byte-for-byte: `.bg-gray-800\/70`, `.bg-gray-800\/40`,
`.border-gray-700\/50`, `.h-\[calc\(100vh-64px\)\]`, `.h-\[calc\(100dvh-4rem\)\]`
all present in Tailwind's output exactly as written in §31.

Breakpoint is `max-width: 639px` rather than 640 to match §19 and sit under
Tailwind's `sm:`; 640 would double-apply in the 1px overlap with every `sm:`
utility on these surfaces.

## Honest limits

- **Not visually verified on a device or in a browser.** The CSS compiles, the
  selectors provably match Tailwind's emitted output, and the overlap arithmetic
  is sound — but "reads better on mobile" is the member's call, and the
  percentages above are computed from the declarations, not measured from a
  rendered page.
- §31a is a CSS override of a markup problem; see EXP-FB-002 "Out of scope".
