//! @mention rendering -- parses nostr:npub1... and @pubkey patterns and
//! renders them as highlighted amber spans within markdown-rendered text.

use leptos::prelude::*;

/// A parsed segment of message text.
#[derive(Clone, Debug)]
enum Segment {
    /// Plain text (may contain markdown).
    Text(String),
    /// A mention: the hex pubkey to highlight.
    Mention(String),
}

/// Render message text with @mentions highlighted and markdown rendered.
///
/// Parses `nostr:npub1...` and `@<64-hex-char>` patterns. Mentions are
/// rendered as amber-colored spans. Non-mention text is rendered as
/// markdown via comrak.
#[component]
pub(crate) fn MentionText(
    /// The raw message content to parse and render.
    content: String,
) -> impl IntoView {
    let segments = parse_mentions(&content);

    view! {
        <span class="break-words">
            {segments.into_iter().map(|seg| {
                match seg {
                    Segment::Text(text) => {
                        // Render markdown for text segments
                        let html = render_markdown_inline(&text);
                        view! {
                            <span inner_html=html />
                        }.into_any()
                    }
                    Segment::Mention(pubkey) => {
                        let short = shorten_mention(&pubkey);
                        view! {
                            <span
                                class="text-amber-400 font-medium cursor-pointer hover:text-amber-300 hover:underline transition-colors"
                                title=format!("Pubkey: {}", pubkey)
                            >
                                {"@"}{short}
                            </span>
                        }.into_any()
                    }
                }
            }).collect_view()}
        </span>
    }
}

/// Parse text for mention patterns. Returns segments in order.
///
/// Recognized patterns:
/// - `nostr:npub1<bech32>` (variable length)
/// - `@<64 hex chars>` (raw pubkey reference)
fn parse_mentions(input: &str) -> Vec<Segment> {
    let mut segments = Vec::new();
    let mut remaining = input;

    while !remaining.is_empty() {
        // Find the next mention pattern
        let nostr_pos = remaining.find("nostr:npub1");
        let at_pos = find_at_pubkey(remaining);

        let next_pos = match (nostr_pos, at_pos) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };

        match next_pos {
            None => {
                // No more mentions, push remaining text
                if !remaining.is_empty() {
                    segments.push(Segment::Text(remaining.to_string()));
                }
                break;
            }
            Some(pos) => {
                // Push text before the mention
                if pos > 0 {
                    segments.push(Segment::Text(remaining[..pos].to_string()));
                }

                let at_this = &remaining[pos..];

                if at_this.starts_with("nostr:npub1") {
                    // Extract the bech32 npub (alphanumeric chars after "nostr:")
                    let after_nostr = &at_this[6..]; // skip "nostr:"
                    let npub_len = after_nostr
                        .chars()
                        .take_while(|c| c.is_alphanumeric())
                        .count();
                    let npub = &after_nostr[..npub_len];
                    // Use the npub as-is for display (we don't decode bech32 here)
                    segments.push(Segment::Mention(npub.to_string()));
                    remaining = &remaining[pos + 6 + npub_len..];
                } else if let Some(hex_part) = at_this.strip_prefix('@') {
                    // @<64 hex chars>
                    let hex_len = hex_part
                        .chars()
                        .take(64)
                        .take_while(|c| c.is_ascii_hexdigit())
                        .count();
                    if hex_len == 64 {
                        let pubkey = hex_part[..64].to_string();
                        segments.push(Segment::Mention(pubkey));
                        remaining = &remaining[pos + 1 + 64..];
                    } else {
                        // Not a valid mention, consume the @ and continue
                        segments.push(Segment::Text("@".to_string()));
                        remaining = &remaining[pos + 1..];
                    }
                }
            }
        }
    }

    // Merge adjacent Text segments
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

/// Find position of an `@` followed by exactly 64 hex chars.
fn find_at_pubkey(input: &str) -> Option<usize> {
    let bytes = input.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'@' && i + 65 <= input.len() {
            let candidate = &input[i + 1..i + 65];
            if candidate.chars().all(|c| c.is_ascii_hexdigit()) {
                return Some(i);
            }
        }
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
///
/// Delegates to [`crate::utils::sanitize::sanitize_markdown_inline`] which
/// strips all raw HTML and applies tag filtering to prevent XSS.
fn render_markdown_inline(text: &str) -> String {
    crate::utils::sanitize::sanitize_markdown_inline(text)
}
