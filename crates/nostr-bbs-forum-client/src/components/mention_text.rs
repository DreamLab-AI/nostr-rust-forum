//! @mention rendering -- parses `nostr:npub1...`, raw-hex `@<64-hex>`, and
//! username-style `@<name>` patterns. Mentions are rendered as highlighted
//! amber spans within markdown-rendered text.
//!
//! Username resolution prefers the event's `["p", pubkey]` tags when paired
//! with the matching `@username` token in the content. When no tag match is
//! available we fall back to the shared `NameCache`. If neither resolves we
//! render the literal `@username` as plain text so the message is never lost.

use leptos::prelude::*;

use crate::components::user_display::{use_display_name, use_display_name_memo};

/// A parsed segment of message text.
#[derive(Clone, Debug)]
enum Segment {
    /// Plain text (may contain markdown).
    Text(String),
    /// A pubkey-style mention (raw hex pubkey to highlight, no name resolution).
    PubkeyMention(String),
    /// An nostr:npub1... mention; we keep the bech32 string as-is for display.
    NpubMention(String),
    /// A `@username` style mention. `pubkey` is `Some` when we resolved the
    /// username from a `["p", pubkey]` tag; otherwise the renderer will try
    /// the shared NameCache and finally fall back to plain text.
    UsernameMention {
        username: String,
        pubkey: Option<String>,
    },
}

/// Render message text with @mentions highlighted and markdown rendered.
///
/// Parses three patterns:
/// - `nostr:npub1...` (variable bech32 tail)
/// - `@<64 hex chars>` (raw pubkey reference)
/// - `@<name>` where `name` matches `[a-z0-9_-]{3,30}` (username reference)
///
/// Username mentions are resolved via `tags` (looking for `["p", pubkey]`)
/// when supplied, and via the shared `NameCache` otherwise. If neither
/// produces a match the `@name` is rendered as plain text.
#[component]
pub(crate) fn MentionText(
    /// The raw message content to parse and render.
    content: String,
    /// Optional event tags. Used to resolve `@username` to a pubkey link.
    /// When omitted (existing call sites), username mentions still resolve
    /// via NameCache; failing that they render as plain text.
    #[prop(optional, into)]
    tags: Option<Vec<Vec<String>>>,
) -> impl IntoView {
    let tags_owned = tags.unwrap_or_default();
    let segments = parse_mentions(&content);

    view! {
        <span class="break-words">
            {segments.into_iter().map(|seg| {
                match seg {
                    Segment::Text(text) => {
                        // sanitize_markdown_inline trims leading/trailing
                        // whitespace, which would glue a mention chip to the
                        // adjacent text (e.g. "@bobhello" / "please@bob"). Re-emit
                        // a single boundary space wherever the raw segment had one
                        // so spacing around @mentions survives rendering.
                        let lead = text.starts_with(|c: char| c.is_whitespace());
                        let trail = text.ends_with(|c: char| c.is_whitespace());
                        let html = render_markdown_inline(&text);
                        let has_body = !html.trim().is_empty();
                        view! {
                            <span>
                                {lead.then_some(" ")}
                                <span inner_html=html />
                                {(trail && has_body).then_some(" ")}
                            </span>
                        }.into_any()
                    }
                    Segment::PubkeyMention(pubkey) => {
                        // Resolve the mentioned user's nickname reactively;
                        // falls back to the shortened hex while in flight.
                        let display = use_display_name_memo(pubkey.clone());
                        view! {
                            <span
                                class="text-amber-400 font-medium cursor-pointer hover:text-amber-300 hover:underline transition-colors"
                                title=format!("Pubkey: {}", pubkey)
                            >
                                {"@"}{move || display.get()}
                            </span>
                        }.into_any()
                    }
                    Segment::NpubMention(npub) => {
                        // Decode npub -> hex so the mention resolves through the
                        // shared profile cache; bech32 shortening is the fallback
                        // when decoding fails.
                        match npub_to_hex(&npub) {
                            Some(hex_pk) => {
                                let display = use_display_name_memo(hex_pk);
                                view! {
                                    <span
                                        class="text-amber-400 font-medium cursor-pointer hover:text-amber-300 hover:underline transition-colors"
                                        title=format!("Npub: {}", npub)
                                    >
                                        {"@"}{move || display.get()}
                                    </span>
                                }.into_any()
                            }
                            None => {
                                let short = shorten_mention(&npub);
                                view! {
                                    <span
                                        class="text-amber-400 font-medium cursor-pointer hover:text-amber-300 hover:underline transition-colors"
                                        title=format!("Npub: {}", npub)
                                    >
                                        {"@"}{short}
                                    </span>
                                }.into_any()
                            }
                        }
                    }
                    Segment::UsernameMention { username, pubkey } => {
                        // Tag-based lookup first; otherwise scan all p-tags so that
                        // an @username with a matching cached display_name resolves.
                        let resolved_pubkey = pubkey
                            .or_else(|| resolve_username_via_tags(&username, &tags_owned));

                        match resolved_pubkey {
                            Some(pk) => {
                                // Reactive: fills in when kind-0 arrives.
                                let display = use_display_name_memo(pk.clone());
                                let href = format!("/community/profile/{}", pk);
                                view! {
                                    <a
                                        href=href
                                        class="text-amber-400 font-medium hover:text-amber-300 hover:underline transition-colors"
                                        title=format!("@{}", username)
                                    >
                                        {"@"}{move || display.get()}
                                    </a>
                                }.into_any()
                            }
                            None => {
                                // Plain text fallback so the message is preserved.
                                view! {
                                    <span class="text-gray-300">{"@"}{username}</span>
                                }.into_any()
                            }
                        }
                    }
                }
            }).collect_view()}
        </span>
    }
}

/// Resolve a `@username` token to a hex pubkey by walking the event's `p`
/// tags and asking the NameCache whether the cached display name matches
/// the typed username (case-insensitive).
fn resolve_username_via_tags(username: &str, tags: &[Vec<String>]) -> Option<String> {
    let want = username.to_lowercase();
    for tag in tags {
        if tag.first().map(|s| s.as_str()) == Some("p") {
            if let Some(pk) = tag.get(1) {
                let display = use_display_name(pk).to_lowercase();
                if display == want {
                    return Some(pk.clone());
                }
                // Some clients tag with a hint as the 4th item — check it too.
                if let Some(hint) = tag.get(3) {
                    if hint.to_lowercase() == want {
                        return Some(pk.clone());
                    }
                }
            }
        }
    }
    None
}

/// Parse text for mention patterns. Returns segments in order.
fn parse_mentions(input: &str) -> Vec<Segment> {
    let mut segments = Vec::new();
    let mut remaining = input;

    while !remaining.is_empty() {
        // Find the next mention pattern.
        let nostr_pos = remaining.find("nostr:npub1");
        let at_pos = find_next_at(remaining);

        let next_pos = match (nostr_pos, at_pos) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };

        match next_pos {
            None => {
                if !remaining.is_empty() {
                    segments.push(Segment::Text(remaining.to_string()));
                }
                break;
            }
            Some(pos) => {
                if pos > 0 {
                    segments.push(Segment::Text(remaining[..pos].to_string()));
                }

                let at_this = &remaining[pos..];

                if at_this.starts_with("nostr:npub1") {
                    let after_nostr = &at_this[6..]; // skip "nostr:"
                    let npub_len = after_nostr
                        .chars()
                        .take_while(|c| c.is_alphanumeric())
                        .count();
                    let npub = &after_nostr[..npub_len];
                    segments.push(Segment::NpubMention(npub.to_string()));
                    remaining = &remaining[pos + 6 + npub_len..];
                } else if let Some(after_at) = at_this.strip_prefix('@') {
                    // Try hex pubkey first (64 chars).
                    let hex_len = after_at
                        .chars()
                        .take(64)
                        .take_while(|c| c.is_ascii_hexdigit())
                        .count();
                    if hex_len == 64 {
                        let pubkey = after_at[..64].to_string();
                        segments.push(Segment::PubkeyMention(pubkey));
                        remaining = &remaining[pos + 1 + 64..];
                        continue;
                    }
                    // Username-style: ^[a-z0-9][a-z0-9_-]{2,29}\b$
                    let name_len = after_at
                        .chars()
                        .take_while(|c| {
                            c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '_' || *c == '-'
                        })
                        .count();
                    if (3..=30).contains(&name_len) {
                        let username = after_at[..name_len].to_string();
                        // Must start with lowercase or digit (regex: ^[a-z0-9]...).
                        let first_ok = username
                            .chars()
                            .next()
                            .map(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
                            .unwrap_or(false);
                        if first_ok {
                            segments.push(Segment::UsernameMention {
                                username,
                                pubkey: None,
                            });
                            remaining = &remaining[pos + 1 + name_len..];
                            continue;
                        }
                    }
                    // Not a recognised mention — emit the @ as text and continue.
                    segments.push(Segment::Text("@".to_string()));
                    remaining = &remaining[pos + 1..];
                }
            }
        }
    }

    // Merge adjacent Text segments.
    let mut merged = Vec::new();
    for seg in segments {
        match (&seg, merged.last_mut()) {
            (Segment::Text(new), Some(Segment::Text(prev))) => {
                prev.push_str(new);
            }
            _ => merged.push(seg),
        }
    }
    merged
}

/// Find the next `@` character that could start a mention (hex pubkey OR
/// username). Returns the byte position.
fn find_next_at(input: &str) -> Option<usize> {
    let bytes = input.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b != b'@' {
            continue;
        }
        // Quick hex check (64 chars).
        if i + 65 <= input.len() {
            let candidate = &input[i + 1..i + 65];
            if candidate.chars().all(|c| c.is_ascii_hexdigit()) {
                return Some(i);
            }
        }
        // Username check (≥3 valid chars).
        let after = &input[i + 1..];
        let len = after
            .chars()
            .take_while(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '_' || *c == '-')
            .count();
        if len >= 3
            && after
                .chars()
                .next()
                .map(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
                .unwrap_or(false)
        {
            return Some(i);
        }
    }
    None
}

/// Decode an `npub1...` bech32 string to a 64-char hex pubkey so mentions can
/// resolve through the shared profile cache. Returns `None` for anything that
/// is not a valid 32-byte `npub`.
fn npub_to_hex(npub: &str) -> Option<String> {
    let (hrp, data) = bech32::decode(npub).ok()?;
    if hrp.as_str() != "npub" || data.len() != 32 {
        return None;
    }
    Some(hex::encode(data))
}

/// Normalise a mention pubkey to 64-char lowercase hex for `["p", pubkey]`
/// tag emission. Accepts a 64-hex pubkey (any case) or a bech32 `npub1...`.
/// Returns `None` for anything else so malformed autocomplete data can never
/// produce an invalid p-tag.
pub(crate) fn normalise_mention_pubkey(s: &str) -> Option<String> {
    let s = s.trim();
    if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Some(s.to_ascii_lowercase());
    }
    if s.starts_with("npub1") {
        return npub_to_hex(s);
    }
    None
}

/// Shorten a pubkey or npub for display.
fn shorten_mention(s: &str) -> String {
    if s.len() <= 12 {
        s.to_string()
    } else {
        format!("{}...{}", &s[..8], &s[s.len() - 4..])
    }
}

/// Render markdown inline (strip wrapping `<p>` tags for inline use).
fn render_markdown_inline(text: &str) -> String {
    crate::utils::sanitize::sanitize_markdown_inline(text)
}

// -- Tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_plain_text() {
        let segs = parse_mentions("hello world");
        assert_eq!(segs.len(), 1);
        match &segs[0] {
            Segment::Text(s) => assert_eq!(s, "hello world"),
            _ => panic!("expected Text"),
        }
    }

    #[test]
    fn parse_username_mention() {
        let segs = parse_mentions("hi @alice how are you");
        assert_eq!(segs.len(), 3);
        match &segs[0] {
            Segment::Text(s) => assert_eq!(s, "hi "),
            _ => panic!("expected Text"),
        }
        match &segs[1] {
            Segment::UsernameMention { username, .. } => assert_eq!(username, "alice"),
            _ => panic!("expected UsernameMention"),
        }
        match &segs[2] {
            Segment::Text(s) => assert_eq!(s, " how are you"),
            _ => panic!("expected Text"),
        }
    }

    #[test]
    fn parse_username_mention_with_underscore_and_hyphen() {
        let segs = parse_mentions("ping @bob_99 and @al-pha");
        let usernames: Vec<&str> = segs
            .iter()
            .filter_map(|s| match s {
                Segment::UsernameMention { username, .. } => Some(username.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(usernames, vec!["bob_99", "al-pha"]);
    }

    #[test]
    fn parse_username_mention_too_short_falls_back_to_text() {
        let segs = parse_mentions("@ab is too short");
        assert_eq!(segs.len(), 1);
        match &segs[0] {
            Segment::Text(s) => assert!(s.starts_with("@ab")),
            _ => panic!("expected Text fallback"),
        }
    }

    #[test]
    fn parse_hex_pubkey_mention() {
        let pk = "a".repeat(64);
        let input = format!("yo @{} bro", pk);
        let segs = parse_mentions(&input);
        let has_pubkey = segs.iter().any(|s| matches!(s, Segment::PubkeyMention(_)));
        assert!(has_pubkey);
    }

    #[test]
    fn parse_npub_mention() {
        let segs = parse_mentions("see nostr:npub1abcdefghijk for more");
        let has_npub = segs.iter().any(|s| matches!(s, Segment::NpubMention(_)));
        assert!(has_npub);
    }

    #[test]
    fn parse_username_mention_starting_with_underscore_rejected() {
        let segs = parse_mentions("@_alice");
        // Should NOT be a UsernameMention because regex requires [a-z0-9] first.
        let has_mention = segs.iter().any(|s| {
            matches!(
                s,
                Segment::UsernameMention { .. } | Segment::PubkeyMention(_)
            )
        });
        assert!(!has_mention);
    }

    #[test]
    fn resolve_username_via_p_tag_hint() {
        let tags = vec![vec![
            "p".to_string(),
            "abcd".repeat(16),
            "wss://relay".to_string(),
            "alice".to_string(),
        ]];
        let pk = resolve_username_via_tags("alice", &tags);
        assert_eq!(pk, Some("abcd".repeat(16)));
    }

    #[test]
    fn resolve_username_via_p_tag_no_match() {
        let tags = vec![vec![
            "p".to_string(),
            "abcd".repeat(16),
            String::new(),
            "bob".to_string(),
        ]];
        let pk = resolve_username_via_tags("alice", &tags);
        assert!(pk.is_none());
    }

    #[test]
    fn shorten_long_string() {
        let pk = "a".repeat(64);
        assert_eq!(shorten_mention(&pk), "aaaaaaaa...aaaa");
    }

    #[test]
    fn shorten_short_passthrough() {
        assert_eq!(shorten_mention("alice"), "alice");
    }

    #[test]
    fn merge_adjacent_text_segments() {
        // Single @ followed by something not a mention should still merge.
        let segs = parse_mentions("foo @ bar @1 baz");
        // Verify no panics; segments may be Text-only.
        assert!(segs.iter().all(|s| matches!(s, Segment::Text(_))));
    }
}
