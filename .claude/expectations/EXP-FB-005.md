---
id: EXP-FB-005
parent_spec: forum-member-feedback-2026-09 item 5
linked_adrs: []
priority: low
regression_critical: false
evidence_category: manual
status: accepted
authored_by: pair
---

## Expectation: the add-reaction affordance is a conventional icon, not a "+"

Member feedback, verbatim: *"Plus sign for emojis non standard, and non
intuitive. Look at other examples such as slack"*.

The affordance was a button whose label was the literal string `"+"`. It is now
an inline SVG of Slack's mark — a smiley face with a small plus at its upper
right, clear of the face — carrying both the existing `aria-label="Add reaction"`
and a native `title` tooltip, plus `aria-haspopup`/`aria-expanded`; the popover
gets `role="dialog"`.

**Rest state.** Slack fades the affordance in on hover. Copying that literally
would make it unreachable on touch, where there is no hover, and this Tailwind
config has no `hover-hover:` variant to guard it with. The button is therefore
permanently visible at `opacity-70`, brightening on `hover:` and
`focus-visible:` — low-emphasis at rest, clear on interaction, and always
tappable. Opacity-only, so there is no reflow or layout shift in a dense
message row.

### In scope
- The icon, its labels and ARIA, and the rest/hover/focus states

### Out of scope (intentionally)
- Long-press-to-reveal on touch. The always-visible treatment is simpler and
  discoverable; a hidden affordance is what the member complained about.

### Counter-examples (must NOT happen)
- An affordance that is invisible or unreachable on a touch device
- Hover/focus states that reflow the message row
