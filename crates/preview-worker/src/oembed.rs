//! Twitter/X oEmbed detection and fetching.
//!
//! Detects Twitter/X URLs and fetches rich embed HTML via the
//! publish.twitter.com oEmbed API.

use serde::{Deserialize, Serialize};
use worker::*;

use super::percent_encode;

const TWITTER_OEMBED_URL: &str = "https://publish.twitter.com/oembed";

// ── Types ────────────────────────────────────────────────────────────────────

/// Intermediate struct for deserializing Twitter oEmbed API response.
#[derive(Deserialize)]
struct TwitterOembedData {
    html: String,
    author_name: String,
    author_url: String,
    #[serde(default)]
    provider_name: Option<String>,
}

/// Intermediate for round-tripping cached Twitter data.
#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct TwitterCachePayload {
    pub r#type: String,
    pub url: String,
    pub html: String,
    pub author_name: String,
    pub author_url: String,
    pub provider_name: String,
}

// ── Twitter detection ────────────────────────────────────────────────────────

pub(crate) fn is_twitter_url(raw_url: &str) -> bool {
    let parsed = match Url::parse(raw_url) {
        Ok(u) => u,
        Err(_) => return false,
    };

    let hostname: String = match parsed.host_str() {
        Some(h) => h.to_lowercase(),
        None => return false,
    };

    matches!(
        hostname.as_str(),
        "twitter.com"
            | "x.com"
            | "www.twitter.com"
            | "www.x.com"
            | "mobile.twitter.com"
            | "mobile.x.com"
    )
}

// ── Fetch helper ─────────────────────────────────────────────────────────────

pub(crate) async fn fetch_twitter_embed(target_url: &str) -> Result<TwitterCachePayload> {
    let oembed_url = format!(
        "{}?url={}&omit_script=true&dnt=true&theme=dark",
        TWITTER_OEMBED_URL,
        percent_encode(target_url)
    );

    let headers = Headers::new();
    let _ = headers.set("Accept", "application/json");
    let _ = headers.set("User-Agent", "LinkPreviewAPI/1.0");

    let mut init = RequestInit::new();
    init.with_method(Method::Get);
    init.with_headers(headers);

    let request = Request::new_with_init(&oembed_url, &init)?;
    let mut response = Fetch::Request(request).send().await?;

    if response.status_code() != 200 {
        return Err(Error::RustError(format!(
            "Twitter oEmbed failed: {}",
            response.status_code()
        )));
    }

    let data: TwitterOembedData = response.json().await?;
    Ok(TwitterCachePayload {
        r#type: "twitter".to_string(),
        url: target_url.to_string(),
        html: data.html,
        author_name: data.author_name,
        author_url: data.author_url,
        provider_name: data.provider_name.unwrap_or_else(|| "X".to_string()),
    })
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_twitter_urls() {
        assert!(is_twitter_url("https://twitter.com/user/status/123"));
        assert!(is_twitter_url("https://x.com/user/status/123"));
        assert!(is_twitter_url("https://www.twitter.com/user"));
        assert!(is_twitter_url("https://www.x.com/user"));
        assert!(is_twitter_url("https://mobile.twitter.com/user"));
        assert!(is_twitter_url("https://mobile.x.com/user"));
    }

    #[test]
    fn rejects_non_twitter() {
        assert!(!is_twitter_url("https://example.com/"));
        assert!(!is_twitter_url("https://nottwitter.com/"));
    }
}
