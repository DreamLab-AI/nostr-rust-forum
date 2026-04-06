//! OpenGraph metadata parsing and HTML helpers.
//!
//! Extracts OG title, description, image, and site name from HTML,
//! with fallbacks to standard HTML `<title>` and `<meta name="description">`.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use worker::*;

// ── Compiled regex cache (compiled once per isolate, not per request) ────────

pub(crate) struct OgRegexes {
    pub og_title_1: Regex,
    pub og_title_2: Regex,
    pub html_title: Regex,
    pub og_desc_1: Regex,
    pub og_desc_2: Regex,
    pub meta_desc: Regex,
    pub og_image_1: Regex,
    pub og_image_2: Regex,
    pub og_site_name: Regex,
    pub decimal_entity: Regex,
    pub hex_entity: Regex,
}

pub(crate) fn og_regexes() -> &'static OgRegexes {
    static INSTANCE: OnceLock<OgRegexes> = OnceLock::new();
    INSTANCE.get_or_init(|| OgRegexes {
        og_title_1: Regex::new(
            r#"(?i)<meta\s+property=["']og:title["']\s+content=["']([^"']+)["']"#,
        )
        .unwrap(),
        og_title_2: Regex::new(
            r#"(?i)<meta\s+content=["']([^"']+)["']\s+property=["']og:title["']"#,
        )
        .unwrap(),
        html_title: Regex::new(r"(?i)<title>([^<]+)</title>").unwrap(),
        og_desc_1: Regex::new(
            r#"(?i)<meta\s+property=["']og:description["']\s+content=["']([^"']+)["']"#,
        )
        .unwrap(),
        og_desc_2: Regex::new(
            r#"(?i)<meta\s+content=["']([^"']+)["']\s+property=["']og:description["']"#,
        )
        .unwrap(),
        meta_desc: Regex::new(
            r#"(?i)<meta\s+name=["']description["']\s+content=["']([^"']+)["']"#,
        )
        .unwrap(),
        og_image_1: Regex::new(
            r#"(?i)<meta\s+property=["']og:image["']\s+content=["']([^"']+)["']"#,
        )
        .unwrap(),
        og_image_2: Regex::new(
            r#"(?i)<meta\s+content=["']([^"']+)["']\s+property=["']og:image["']"#,
        )
        .unwrap(),
        og_site_name: Regex::new(
            r#"(?i)<meta\s+property=["']og:site_name["']\s+content=["']([^"']+)["']"#,
        )
        .unwrap(),
        decimal_entity: Regex::new(r"&#(\d+);").unwrap(),
        hex_entity: Regex::new(r"&#x([0-9a-fA-F]+);").unwrap(),
    })
}

// ── Cache payload types ─────────────────────────────────────────────────────

/// Intermediate for round-tripping cached OG data (without `cached` field baked in).
#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct OgCachePayload {
    pub r#type: String,
    pub url: String,
    pub domain: String,
    pub favicon: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    #[serde(rename = "siteName", skip_serializing_if = "Option::is_none")]
    pub site_name: Option<String>,
}

// ── HTML helpers ─────────────────────────────────────────────────────────────

pub(crate) fn decode_html_entities(text: &str) -> String {
    let mut decoded = text.to_string();

    // Named entities -- simple str replacements (no regex needed)
    let named: &[(&str, &str)] = &[
        ("&amp;", "&"),
        ("&lt;", "<"),
        ("&gt;", ">"),
        ("&quot;", "\""),
        ("&#39;", "'"),
        ("&apos;", "'"),
        ("&nbsp;", " "),
    ];
    for (entity, replacement) in named {
        decoded = decoded.replace(entity, replacement);
    }

    let re = og_regexes();

    // Numeric decimal entities: &#123;
    decoded = re
        .decimal_entity
        .replace_all(&decoded, |caps: &regex::Captures| {
            let num: u32 = caps[1].parse().unwrap_or(0);
            if num > 0 && num < 0x10FFFF {
                char::from_u32(num)
                    .map(|c| c.to_string())
                    .unwrap_or_default()
            } else {
                String::new()
            }
        })
        .to_string();

    // Hex entities: &#x7B;
    decoded = re
        .hex_entity
        .replace_all(&decoded, |caps: &regex::Captures| {
            let num = u32::from_str_radix(&caps[1], 16).unwrap_or(0);
            if num > 0 && num < 0x10FFFF {
                char::from_u32(num)
                    .map(|c| c.to_string())
                    .unwrap_or_default()
            } else {
                String::new()
            }
        })
        .to_string();

    decoded
}

pub(crate) fn resolve_url(relative_url: &str, base_url: &str) -> String {
    match Url::parse(base_url).and_then(|base: Url| base.join(relative_url)) {
        Ok(u) => u.to_string(),
        Err(_) => relative_url.to_string(),
    }
}

// ── OG parser ────────────────────────────────────────────────────────────────

struct OgPreview {
    url: String,
    domain: String,
    favicon: String,
    title: Option<String>,
    description: Option<String>,
    image: Option<String>,
    site_name: Option<String>,
}

fn extract_meta(html: &str, pattern: &Regex) -> Option<String> {
    pattern
        .captures(html)
        .map(|caps| decode_html_entities(&caps[1]))
}

fn parse_open_graph_tags(html: &str, target_url: &str) -> OgPreview {
    let domain = Url::parse(target_url)
        .ok()
        .and_then(|u: Url| u.host_str().map(|h: &str| h.to_string()))
        .unwrap_or_default()
        .trim_start_matches("www.")
        .to_string();

    let favicon = format!("https://www.google.com/s2/favicons?domain={}&sz=32", domain);

    let re = og_regexes();

    let title = extract_meta(html, &re.og_title_1)
        .or_else(|| extract_meta(html, &re.og_title_2))
        .or_else(|| extract_meta(html, &re.html_title));

    let description = extract_meta(html, &re.og_desc_1)
        .or_else(|| extract_meta(html, &re.og_desc_2))
        .or_else(|| extract_meta(html, &re.meta_desc));

    let image_url =
        extract_meta(html, &re.og_image_1).or_else(|| extract_meta(html, &re.og_image_2));
    let image = image_url.map(|u| resolve_url(&u, target_url));

    let site_name = extract_meta(html, &re.og_site_name);

    OgPreview {
        url: target_url.to_string(),
        domain,
        favicon,
        title,
        description,
        image,
        site_name,
    }
}

// ── Fetch helper ─────────────────────────────────────────────────────────────

pub(crate) async fn fetch_open_graph_data(target_url: &str) -> Result<OgCachePayload> {
    let headers = Headers::new();
    let _ = headers.set("Accept", "text/html,application/xhtml+xml");
    let _ = headers.set("User-Agent", "LinkPreviewAPI/1.0 (Link Preview Bot)");

    let mut init = RequestInit::new();
    init.with_method(Method::Get);
    init.with_headers(headers);

    let request = Request::new_with_init(target_url, &init)?;
    let mut response = Fetch::Request(request).send().await?;

    if response.status_code() != 200 {
        return Err(Error::RustError(format!(
            "Failed to fetch: {}",
            response.status_code()
        )));
    }

    let html = response.text().await?;
    let preview = parse_open_graph_tags(&html, target_url);

    Ok(OgCachePayload {
        r#type: "opengraph".to_string(),
        url: preview.url,
        domain: preview.domain,
        favicon: preview.favicon,
        title: preview.title,
        description: preview.description,
        image: preview.image,
        site_name: preview.site_name,
    })
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // HTML entity decoding tests
    #[test]
    fn decodes_named_entities() {
        assert_eq!(decode_html_entities("&amp;"), "&");
        assert_eq!(decode_html_entities("&lt;b&gt;"), "<b>");
        assert_eq!(decode_html_entities("&quot;hello&quot;"), "\"hello\"");
        assert_eq!(decode_html_entities("don&#39;t"), "don't");
    }

    #[test]
    fn decodes_decimal_entities() {
        assert_eq!(decode_html_entities("&#65;"), "A");
        assert_eq!(decode_html_entities("&#123;"), "{");
    }

    #[test]
    fn decodes_hex_entities() {
        assert_eq!(decode_html_entities("&#x41;"), "A");
        assert_eq!(decode_html_entities("&#x7B;"), "{");
    }

    // OG parser tests
    #[test]
    fn parses_og_title_property_first() {
        let html = r#"<meta property="og:title" content="Test Title">"#;
        let preview = parse_open_graph_tags(html, "https://example.com/page");
        assert_eq!(preview.title.as_deref(), Some("Test Title"));
    }

    #[test]
    fn parses_og_title_content_first() {
        let html = r#"<meta content="Test Title" property="og:title">"#;
        let preview = parse_open_graph_tags(html, "https://example.com/page");
        assert_eq!(preview.title.as_deref(), Some("Test Title"));
    }

    #[test]
    fn falls_back_to_html_title() {
        let html = r#"<title>Fallback Title</title>"#;
        let preview = parse_open_graph_tags(html, "https://example.com/page");
        assert_eq!(preview.title.as_deref(), Some("Fallback Title"));
    }

    #[test]
    fn parses_description() {
        let html = r#"<meta property="og:description" content="A description">"#;
        let preview = parse_open_graph_tags(html, "https://example.com/page");
        assert_eq!(preview.description.as_deref(), Some("A description"));
    }

    #[test]
    fn falls_back_to_meta_description() {
        let html = r#"<meta name="description" content="Meta desc">"#;
        let preview = parse_open_graph_tags(html, "https://example.com/page");
        assert_eq!(preview.description.as_deref(), Some("Meta desc"));
    }

    #[test]
    fn parses_image_and_resolves_relative() {
        let html = r#"<meta property="og:image" content="/images/hero.jpg">"#;
        let preview = parse_open_graph_tags(html, "https://example.com/page");
        assert_eq!(
            preview.image.as_deref(),
            Some("https://example.com/images/hero.jpg")
        );
    }

    #[test]
    fn parses_site_name() {
        let html = r#"<meta property="og:site_name" content="Example Site">"#;
        let preview = parse_open_graph_tags(html, "https://example.com/page");
        assert_eq!(preview.site_name.as_deref(), Some("Example Site"));
    }

    #[test]
    fn sets_domain_and_favicon() {
        let html = "";
        let preview = parse_open_graph_tags(html, "https://www.example.com/page");
        assert_eq!(preview.domain, "example.com");
        assert_eq!(
            preview.favicon,
            "https://www.google.com/s2/favicons?domain=example.com&sz=32"
        );
    }

    // URL resolution tests
    #[test]
    fn resolves_absolute_url() {
        assert_eq!(
            resolve_url("https://cdn.example.com/img.png", "https://example.com/"),
            "https://cdn.example.com/img.png"
        );
    }

    #[test]
    fn resolves_relative_url() {
        assert_eq!(
            resolve_url("/img.png", "https://example.com/page"),
            "https://example.com/img.png"
        );
    }
}
