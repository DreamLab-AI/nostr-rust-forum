//! HTML sanitization for user-generated markdown content.
//!
//! All user-supplied markdown MUST pass through [`sanitize_markdown`] before
//! being injected via `inner_html` to prevent stored XSS. The function uses
//! comrak with `unsafe_ = false` (strips raw HTML) and `tagfilter = true`
//! (blocks dangerous tags like `<script>`, `<style>`, `<iframe>`, etc.).

use comrak::{markdown_to_html, Options};

/// Convert markdown to safe HTML with all raw HTML stripped.
///
/// This is the **only** approved way to render user-generated markdown in the
/// forum client. Using `comrak::markdown_to_html` directly is forbidden because
/// the default options allow raw HTML passthrough, enabling XSS.
///
/// # Safety guarantees
///
/// - `options.render.unsafe_` is `false` — raw HTML tags in the input are
///   stripped from the output.
/// - `options.extension.tagfilter` is `true` — an additional allowlist-based
///   filter blocks dangerous tags (`<script>`, `<style>`, `<textarea>`,
///   `<title>`, `<plaintext>`, `<xmp>`, `<iframe>`, `<noembed>`, `<noframes>`,
///   `<noscript>`).
/// - Autolinks, tables, and strikethrough are enabled for usability.
pub fn sanitize_markdown(input: &str) -> String {
    let mut options = Options::default();
    options.render.unsafe_ = false; // Strip raw HTML
    options.extension.tagfilter = true; // Additional tag filtering
    options.extension.autolink = true;
    options.extension.table = true;
    options.extension.strikethrough = true;
    markdown_to_html(input, &options)
}

/// Convert markdown to safe HTML, then strip the outer `<p>...</p>` wrapper
/// for inline rendering contexts (e.g., within a `<span>`).
///
/// Uses the same sanitization rules as [`sanitize_markdown`].
pub fn sanitize_markdown_inline(input: &str) -> String {
    let html = sanitize_markdown(input);
    let trimmed = html.trim();
    if trimmed.starts_with("<p>") && trimmed.ends_with("</p>") {
        trimmed[3..trimmed.len() - 4].to_string()
    } else {
        trimmed.to_string()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── XSS prevention ──────────────────────────────────────────────────

    #[test]
    fn strips_script_tags() {
        let output = sanitize_markdown("<script>alert(1)</script>");
        assert!(!output.contains("<script>"));
        assert!(!output.contains("</script>"));
        assert!(!output.contains("alert"));
    }

    #[test]
    fn strips_img_onerror() {
        let output = sanitize_markdown("<img onerror=alert(1)>");
        assert!(!output.contains("onerror"));
        assert!(!output.contains("alert"));
    }

    #[test]
    fn strips_iframe_tag() {
        let output = sanitize_markdown("<iframe src=\"https://evil.com\"></iframe>");
        // comrak tagfilter replaces dangerous tags with HTML-encoded versions
        assert!(!output.contains("<iframe"));
    }

    #[test]
    fn strips_style_tag() {
        let output = sanitize_markdown("<style>body{display:none}</style>");
        assert!(!output.contains("<style>"));
    }

    #[test]
    fn strips_textarea_tag() {
        let output = sanitize_markdown("<textarea>injected</textarea>");
        assert!(!output.contains("<textarea>"));
    }

    #[test]
    fn strips_raw_html_div() {
        let output = sanitize_markdown("<div onclick=\"alert(1)\">click me</div>");
        assert!(!output.contains("<div"));
        assert!(!output.contains("onclick"));
    }

    #[test]
    fn strips_svg_onload() {
        let output = sanitize_markdown("<svg onload=alert(1)>");
        assert!(!output.contains("onload"));
        assert!(!output.contains("alert"));
    }

    #[test]
    fn strips_event_handler_in_anchor() {
        let output = sanitize_markdown("<a href=\"#\" onmouseover=\"alert(1)\">hover</a>");
        assert!(!output.contains("onmouseover"));
    }

    // ── valid markdown rendering ────────────────────────────────────────

    #[test]
    fn renders_bold() {
        let output = sanitize_markdown("**bold** text");
        assert!(output.contains("<strong>bold</strong>"));
    }

    #[test]
    fn renders_italic() {
        let output = sanitize_markdown("*italic* text");
        assert!(output.contains("<em>italic</em>"));
    }

    #[test]
    fn renders_link() {
        let output = sanitize_markdown("[link](https://example.com)");
        assert!(output.contains("<a href=\"https://example.com\">link</a>"));
    }

    #[test]
    fn renders_code_inline() {
        let output = sanitize_markdown("`code`");
        assert!(output.contains("<code>code</code>"));
    }

    #[test]
    fn renders_code_block() {
        let output = sanitize_markdown("```\nfn main() {}\n```");
        assert!(output.contains("<code>"));
        assert!(output.contains("fn main()"));
    }

    #[test]
    fn renders_heading() {
        let output = sanitize_markdown("# Hello");
        assert!(output.contains("<h1>"));
        assert!(output.contains("Hello"));
    }

    #[test]
    fn renders_list() {
        let output = sanitize_markdown("- item 1\n- item 2");
        assert!(output.contains("<li>"));
        assert!(output.contains("item 1"));
        assert!(output.contains("item 2"));
    }

    #[test]
    fn renders_strikethrough() {
        let output = sanitize_markdown("~~deleted~~");
        assert!(output.contains("<del>deleted</del>"));
    }

    #[test]
    fn renders_autolink() {
        let output = sanitize_markdown("Visit https://example.com for more");
        assert!(output.contains("<a href=\"https://example.com\">"));
    }

    #[test]
    fn renders_table() {
        let input = "| A | B |\n|---|---|\n| 1 | 2 |";
        let output = sanitize_markdown(input);
        assert!(output.contains("<table>"));
        assert!(output.contains("<td>"));
    }

    // ── edge cases ──────────────────────────────────────────────────────

    #[test]
    fn empty_input() {
        let output = sanitize_markdown("");
        assert_eq!(output.trim(), "");
    }

    #[test]
    fn whitespace_only() {
        let output = sanitize_markdown("   \n\n   ");
        assert_eq!(output.trim(), "");
    }

    #[test]
    fn plain_text_wrapped_in_p() {
        let output = sanitize_markdown("hello world");
        assert!(output.contains("<p>hello world</p>"));
    }

    #[test]
    fn unicode_content() {
        let output = sanitize_markdown("Hello **world** (Ger: Welt) -- Nostr is great");
        assert!(output.contains("<strong>world</strong>"));
    }

    // ── sanitize_markdown_inline ────────────────────────────────────────

    #[test]
    fn inline_strips_outer_p() {
        let output = sanitize_markdown_inline("hello");
        assert!(!output.starts_with("<p>"));
        assert!(!output.ends_with("</p>"));
        assert_eq!(output, "hello");
    }

    #[test]
    fn inline_preserves_formatting() {
        let output = sanitize_markdown_inline("**bold** text");
        assert!(output.contains("<strong>bold</strong>"));
        assert!(!output.starts_with("<p>"));
    }

    #[test]
    fn inline_empty_input() {
        let output = sanitize_markdown_inline("");
        assert_eq!(output.trim(), "");
    }

    #[test]
    fn inline_with_link() {
        let output = sanitize_markdown_inline("[click](https://example.com)");
        assert!(output.contains("<a href"));
        assert!(!output.starts_with("<p>"));
    }

    #[test]
    fn inline_multiline_keeps_all_content() {
        // If input produces multiple paragraphs, the outer p stripping
        // should not apply (it only strips if it starts and ends with <p>...</p>)
        let output = sanitize_markdown_inline("para1\n\npara2");
        assert!(output.contains("para1"));
        assert!(output.contains("para2"));
    }
}
