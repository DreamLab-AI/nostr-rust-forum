//! Shared UI-agnostic data types used across stores and client views.

use serde::{Deserialize, Serialize};

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
    /// An abridged key, rendered as a copyable affordance.
    Key(KeyRef),
}

/// A sentence that may mention keys, kept as runs so views can render each
/// key as copyable while the rest reads as flat text.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeyedText {
    pub parts: Vec<TextPart>,
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

    /// The sentence as flat text, keys in their abridged form.
    pub fn plain(&self) -> String {
        self.parts
            .iter()
            .map(|p| match p {
                TextPart::Text(t) => t.as_str(),
                TextPart::Key(k) => k.display.as_str(),
            })
            .collect()
    }

    /// Borrow the underlying text/key parts.
    pub fn parts(&self) -> &[TextPart] {
        &self.parts
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

/// A single emoji reaction on a message, aggregated across all reactors.
#[derive(Clone, Debug, PartialEq)]
pub struct Reaction {
    pub emoji: String,
    pub count: u32,
    pub reacted_by_me: bool,
}
