---
id: EXP-FB-002
parent_spec: forum-member-feedback-2026-09 item 2
linked_adrs: []
priority: high
regression_critical: false
evidence_category: manual
status: accepted
authored_by: pair
---

## Expectation: a thread is followable on a narrow viewport, and nothing overlaps

Member feedback, verbatim: *"Slightly more streamlined / compact / thoughtful
design system particularly good mobile. Lots of space and overlap making it hard
to follow a thread"*.

Two distinct complaints, addressed separately.

**Overlap.** The chat and DM columns size themselves `h-[calc(100vh-64px)]` —
viewport minus the sticky header only, reserving nothing for the *fixed*
`.mobile-bottom-nav`. The compose bar pinned at the bottom of that flex column,
and the tail of the message list, sat underneath the nav. Ancestor
`padding-bottom` could not rescue it because the column's height is absolute,
not content-driven — which is also why the defect survived review: the
compensation *looked* present. A published `--forum-mobile-nav-h` token now
re-derives those heights from `100dvh` minus header, nav and safe-area inset.
The same defect in the notification drawer (`h-[calc(100dvh-4rem)]`, same
`z-50` as the nav) is fixed with the same token.

**Density.** A measured pass on the thread reading surfaces below 639px: card
padding, reply-stack gaps, avatar/meta gutters and composer margins tightened by
roughly 25-33%, for a net thread stack around 28-32% shorter. Nested-reply
indentation drops from 30px to 20px while keeping the 2px left rule as the
nesting signal, so nesting still reads without eating horizontal space.

Compaction does not shrink tap targets: the send button (32px, already below the
44px guideline) gains a transparent 44px hit expander.

### In scope
- `style.css` only — no markup, no logic, no colour declarations (so the
  runtime light theme and compact-density overrides compose cleanly)
- `max-width: 639px` to match the existing §19 breakpoint and sit under
  Tailwind's `sm:`

### Out of scope (intentionally)
- The honest repair for the overlap is in the markup: `channel.rs:816`,
  `channel.rs:810` and `dm_chat.rs:166` should stop hardcoding viewport
  arithmetic. Until then the CSS override is load-bearing and those class
  strings must not change without updating the selector.
- `--forum-mobile-nav-h` is hand-derived from the nav's box; a `ResizeObserver`
  writing the measured height would make it self-correcting, but that is a Rust
  change.
- Hover-revealed composer/message buttons (emoji, attach, per-message actions)
  remain below 44px and are `opacity-0` on touch — invisible but tappable. A
  genuine mobile bug, but fixing it means choosing a touch presentation, which
  is a component decision, not a CSS one. Flagged, not papered over.

### Counter-examples (must NOT happen)
- The compose bar or last message sitting under the fixed bottom nav
- A signed-out reader (who has no bottom nav) getting a dead reserved strip
- Any interactive target shrinking below 44px in the name of compactness
