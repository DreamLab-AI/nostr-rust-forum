//! Click-to-copy for abridged public keys.
//!
//! The rule: wherever the forum shows a shortened key — a hex pubkey or an
//! npub, as `abcd12...ef56`, `abcd1234…`, or the 8-char fallback name of a
//! member with no profile — clicking it copies the FULL key. Hex copies as
//! hex, npub as npub.
//!
//! - [`CopyKey`] is the one affordance: a `<button type="button">` styled as
//!   the inline text it replaces, with a ~1.2 s "Copied" / "Copy failed"
//!   confirmation announced through `aria-live`.
//! - [`KeyName`] renders a member's resolved name, falling back to a
//!   [`CopyKey`] while (or because) no profile name exists.
//! - [`KeyedText`] + [`KeyedTextView`] carry a sentence that mentions a key
//!   (an admin action banner, a notification body) from the store that builds
//!   it to the view that renders it, so the key inside stays copyable.
//!
//! Every write goes through [`crate::utils::clipboard`].

use leptos::prelude::*;
use serde::{Deserialize, Serialize};

use crate::components::user_display::try_display_name_tracked;
use crate::utils::{set_timeout_once, shorten_pubkey};

/// How long the "Copied" / "Copy failed" confirmation stays up.
pub const FEEDBACK_MS: i32 = 1_200;

/// Text shown while a successful copy is being confirmed.
pub const COPIED_LABEL: &str = "Copied";
/// Text shown while a failed copy is being reported.
pub const FAILED_LABEL: &str = "Copy failed";

// -- State machine ------------------------------------------------------------

/// What a [`CopyKey`] is currently showing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CopyState {
    /// The abridged key.
    #[default]
    Idle,
    /// The confirmation after a successful copy.
    Copied,
    /// The notice after a failed copy.
    Failed,
}

/// The [`CopyKey`] state machine: `Idle → Copied → Idle` and
/// `Idle → Failed → Idle`, with each confirmation expiring after
/// [`FEEDBACK_MS`].
///
/// Every settled copy bumps a generation counter and only the timer of the
/// LATEST copy may return the button to idle, so a double click does not cut
/// the second confirmation short when the first one's timer fires.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CopyFeedback {
    state: CopyState,
    generation: u32,
}

impl CopyFeedback {
    /// Record a copy outcome and return the generation its expiry timer must
    /// present to [`CopyFeedback::expire`].
    pub fn settle(&mut self, copied: bool) -> u32 {
        self.generation = self.generation.wrapping_add(1);
        self.state = if copied {
            CopyState::Copied
        } else {
            CopyState::Failed
        };
        self.generation
    }

    /// Return to idle — but only if no later copy has settled since the one
    /// that issued `generation`.
    pub fn expire(&mut self, generation: u32) {
        if self.generation == generation {
            self.state = CopyState::Idle;
        }
    }

    /// The visible text: `idle` (the abridged key) or the confirmation.
    pub fn label<'a>(&self, idle: &'a str) -> &'a str {
        match self.state {
            CopyState::Idle => idle,
            CopyState::Copied => COPIED_LABEL,
            CopyState::Failed => FAILED_LABEL,
        }
    }
}

// -- The affordance -----------------------------------------------------------

/// Base classes: inline text with no button chrome. Colour, size and font
/// family are inherited from the surrounding text (Tailwind's preflight
/// already resets `font-family` and the background on buttons), so the key
/// looks exactly as it did before it became clickable.
const BASE_CLASS: &str = "copy-key inline p-0 m-0 border-0 bg-transparent text-inherit \
     cursor-copy rounded-sm hover:underline decoration-dotted underline-offset-2 \
     focus:outline-none focus-visible:ring-1 focus-visible:ring-amber-400/70";

/// The glyph an icon-only [`CopyKey`] shows at rest.
const ICON_GLYPH: &str = "\u{29c9}";

/// An abridged public key that copies the full key when clicked.
///
/// Renders a `<button type="button">` that looks like the inline text it
/// replaces, so Enter and Space work and it sits in the tab order. The click
/// does not propagate: a copy inside a clickable row or card never also
/// triggers the row. Never nest it inside an `<a>` — pass `icon = true` and
/// render it as the link's sibling instead.
#[component]
pub fn CopyKey(
    /// The full key to copy (64-char hex or an npub, copied verbatim).
    #[prop(into)]
    full: String,
    /// The abridged text to show. Defaults to [`shorten_pubkey`] of `full`.
    #[prop(optional, into)]
    display: Option<String>,
    /// Extra classes for the button, e.g. `font-mono` where the key was
    /// monospace before.
    #[prop(optional, into)]
    class: Option<String>,
    /// Show a compact copy glyph instead of the abridged text — for the
    /// sibling of a link whose own text already shows the key.
    #[prop(optional)]
    icon: bool,
    /// Keep focus where it is on mouse-down (an option inside a composer's
    /// autocomplete must not blur the textarea and close the dropdown).
    #[prop(optional)]
    keep_focus: bool,
) -> impl IntoView {
    let display = display.unwrap_or_else(|| shorten_pubkey(&full));
    let feedback = RwSignal::new(CopyFeedback::default());

    let title = format!("Click to copy {full}");
    let aria_label = format!("Copy public key {display}");
    let idle_text = if icon {
        ICON_GLYPH.to_string()
    } else {
        display
    };
    let class = format!("{BASE_CLASS} {}", class.unwrap_or_default());

    let on_mousedown = move |ev: leptos::ev::MouseEvent| {
        ev.stop_propagation();
        if keep_focus {
            ev.prevent_default();
        }
    };
    let on_click = move |ev: leptos::ev::MouseEvent| {
        ev.stop_propagation();
        crate::utils::clipboard::copy_text_then(&full, move |ok| {
            // The button may have unmounted while the clipboard promise was
            // pending; `try_*` makes a write to a disposed signal a no-op.
            let Some(generation) = feedback.try_update(|f| f.settle(ok)) else {
                return;
            };
            set_timeout_once(
                move || {
                    feedback.try_update(|f| f.expire(generation));
                },
                FEEDBACK_MS,
            );
        });
    };

    view! {
        <button
            type="button"
            class=class
            title=title
            aria-label=aria_label
            on:mousedown=on_mousedown
            on:click=on_click
        >
            <span aria-live="polite">
                {move || feedback.with(|f| f.label(&idle_text).to_string())}
            </span>
        </button>
    }
}

/// A member's display name, or — while no profile name resolves — their
/// abridged key as a [`CopyKey`].
///
/// The name is held in a `Memo` so the profile cache's frequent unrelated
/// updates do not rebuild the button (and cut a "Copied" confirmation short).
#[component]
pub fn KeyName(
    /// Hex pubkey of the member.
    #[prop(into)]
    pubkey: String,
    /// Extra classes for the fallback key button.
    #[prop(optional, into)]
    key_class: Option<String>,
) -> impl IntoView {
    let pk = pubkey.clone();
    let name = Memo::new(move |_| try_display_name_tracked(&pk));
    let key_class = key_class.unwrap_or_default();
    move || match name.get() {
        Some(n) => n.into_any(),
        None => view! { <CopyKey full=pubkey.clone() class=key_class.clone() /> }.into_any(),
    }
}

// -- Text that mentions a key -------------------------------------------------

/// A key as a sentence shows it: the full key plus the abridged text.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRef {
    /// The full key (hex or npub) that a click copies.
    pub full: String,
    /// The abridged text shown in place of it.
    pub display: String,
}

/// One run of a [`KeyedText`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TextPart {
    /// Plain text.
    Text(String),
    /// An abridged key, rendered as a [`CopyKey`].
    Key(KeyRef),
}

/// A sentence that may mention keys, kept as runs so the view can render each
/// key as a [`CopyKey`] while the rest reads exactly as the flat string the
/// surface showed before.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeyedText {
    parts: Vec<TextPart>,
}

impl KeyedText {
    /// An empty sentence.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append plain text.
    pub fn text(mut self, s: impl Into<String>) -> Self {
        let s = s.into();
        if s.is_empty() {
            return self;
        }
        if let Some(TextPart::Text(prev)) = self.parts.last_mut() {
            prev.push_str(&s);
        } else {
            self.parts.push(TextPart::Text(s));
        }
        self
    }

    /// Append a key: `full` is copied, `display` is shown.
    pub fn key(mut self, full: impl Into<String>, display: impl Into<String>) -> Self {
        self.parts.push(TextPart::Key(KeyRef {
            full: full.into(),
            display: display.into(),
        }));
        self
    }

    /// Split `text` around every occurrence of `key.display`, turning each
    /// into a copyable key. Text that does not contain it stays plain.
    pub fn with_key(text: &str, key: &KeyRef) -> Self {
        if key.display.is_empty() {
            return Self::new().text(text);
        }
        let mut out = Self::new();
        let mut rest = text;
        while let Some(at) = rest.find(&key.display) {
            out = out
                .text(&rest[..at])
                .key(key.full.clone(), key.display.clone());
            rest = &rest[at + key.display.len()..];
        }
        out.text(rest)
    }
}

impl From<String> for KeyedText {
    fn from(s: String) -> Self {
        Self::new().text(s)
    }
}

impl From<&str> for KeyedText {
    fn from(s: &str) -> Self {
        Self::new().text(s)
    }
}

/// Render a [`KeyedText`]: plain runs as text, keys as [`CopyKey`]s.
#[component]
pub fn KeyedTextView(
    /// The sentence to render.
    text: KeyedText,
    /// Extra classes for every key button in it.
    #[prop(optional, into)]
    key_class: Option<String>,
) -> impl IntoView {
    let key_class = key_class.unwrap_or_default();
    text.parts
        .into_iter()
        .map(|part| match part {
            TextPart::Text(t) => t.into_any(),
            TextPart::Key(k) => {
                view! { <CopyKey full=k.full display=k.display class=key_class.clone() /> }
                    .into_any()
            }
        })
        .collect_view()
}

#[cfg(test)]
mod tests {
    use super::*;

    impl CopyFeedback {
        fn state(&self) -> CopyState {
            self.state
        }
    }

    impl KeyedText {
        fn parts(&self) -> &[TextPart] {
            &self.parts
        }

        /// The sentence as flat text, keys in their abridged form — what the
        /// surface showed before keys became copyable.
        fn plain(&self) -> String {
            self.parts
                .iter()
                .map(|p| match p {
                    TextPart::Text(t) => t.as_str(),
                    TextPart::Key(k) => k.display.as_str(),
                })
                .collect()
        }
    }

    const HEX: &str = "11ed64225dd5e2c5e18f61ad43d5ad9272d08739d3a20dd25886197b0738663c";

    #[test]
    fn idle_copied_idle() {
        let mut f = CopyFeedback::default();
        assert_eq!(f.state(), CopyState::Idle);
        assert_eq!(f.label("11ed64...663c"), "11ed64...663c");
        let g = f.settle(true);
        assert_eq!(f.state(), CopyState::Copied);
        assert_eq!(f.label("11ed64...663c"), COPIED_LABEL);
        f.expire(g);
        assert_eq!(f.state(), CopyState::Idle);
        assert_eq!(f.label("11ed64...663c"), "11ed64...663c");
    }

    #[test]
    fn idle_failed_idle() {
        let mut f = CopyFeedback::default();
        let g = f.settle(false);
        assert_eq!(f.state(), CopyState::Failed);
        assert_eq!(f.label("k"), FAILED_LABEL);
        f.expire(g);
        assert_eq!(f.state(), CopyState::Idle);
    }

    #[test]
    fn a_stale_timer_does_not_cut_a_later_confirmation_short() {
        let mut f = CopyFeedback::default();
        let first = f.settle(false);
        let second = f.settle(true);
        f.expire(first);
        assert_eq!(f.state(), CopyState::Copied);
        f.expire(second);
        assert_eq!(f.state(), CopyState::Idle);
    }

    #[test]
    fn generation_wraps_without_panicking() {
        let mut f = CopyFeedback {
            state: CopyState::Idle,
            generation: u32::MAX,
        };
        let g = f.settle(true);
        assert_eq!(g, 0);
        f.expire(g);
        assert_eq!(f.state(), CopyState::Idle);
    }

    #[test]
    fn keyed_text_builds_and_flattens() {
        let t = KeyedText::new()
            .text("Added ")
            .key(HEX, "11ed6422...663c")
            .text(" to ")
            .text("whitelist");
        assert_eq!(t.plain(), "Added 11ed6422...663c to whitelist");
        assert_eq!(t.parts().len(), 3);
        assert!(matches!(&t.parts()[1], TextPart::Key(k) if k.full == HEX));
    }

    #[test]
    fn keyed_text_from_plain_string_has_no_keys() {
        let t: KeyedText = "Channel 'general' created".into();
        assert_eq!(
            t.parts(),
            &[TextPart::Text("Channel 'general' created".into())]
        );
        assert_eq!(KeyedText::from(String::new()).parts(), &[]);
    }

    #[test]
    fn with_key_splits_on_every_occurrence() {
        let k = KeyRef {
            full: HEX.into(),
            display: "11ed6422\u{2026}663c".into(),
        };
        let t = KeyedText::with_key("11ed6422\u{2026}663c has joined — 11ed6422\u{2026}663c", &k);
        assert_eq!(
            t.plain(),
            "11ed6422\u{2026}663c has joined — 11ed6422\u{2026}663c"
        );
        let keys = t
            .parts()
            .iter()
            .filter(|p| matches!(p, TextPart::Key(_)))
            .count();
        assert_eq!(keys, 2);
        // Absent display: the text stays a single plain run.
        let none = KeyedText::with_key("Beema has joined", &k);
        assert_eq!(none.parts(), &[TextPart::Text("Beema has joined".into())]);
    }

    #[test]
    fn with_key_is_safe_on_non_ascii_text() {
        let k = KeyRef {
            full: HEX.into(),
            display: "😀…😀".into(),
        };
        let t = KeyedText::with_key("é😀…😀ü", &k);
        assert_eq!(t.plain(), "é😀…😀ü");
        assert_eq!(t.parts().len(), 3);
        let empty = KeyRef {
            full: HEX.into(),
            display: String::new(),
        };
        assert_eq!(KeyedText::with_key("abc", &empty).plain(), "abc");
    }
}
