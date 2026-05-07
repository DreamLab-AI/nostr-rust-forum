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
    use crate::ssrf::{read_text_capped, ssrf_fetch_with_redirects, SsrfFetchError};

    let oembed_url = format!(
        "{}?url={}&omit_script=true&dnt=true&theme=dark",
        TWITTER_OEMBED_URL,
        percent_encode(target_url)
    );

    let headers = Headers::new();
    let _ = headers.set("Accept", "application/json");
    let _ = headers.set("User-Agent", "LinkPreviewAPI/1.0");

    // Manual-redirect fetch with SSRF re-validation on every hop. The oEmbed
    // host is a public Twitter endpoint, but a misconfigured upstream or
    // hijacked DNS could redirect into private space; treat it the same as
    // arbitrary OG fetches.
    let response = ssrf_fetch_with_redirects(&oembed_url, &headers)
        .await
        .map_err(|e: SsrfFetchError| Error::RustError(e.to_string()))?;

    let status = response.status_code();
    if status != 200 {
        return Err(Error::RustError(format!("Twitter oEmbed failed: {status}")));
    }

    // Read with body cap, then parse — workers-rs's `Response::json()` would
    // bypass our limit.
    let body = read_text_capped(response)
        .await
        .map_err(|e: SsrfFetchError| Error::RustError(e.to_string()))?;
    let data: TwitterOembedData =
        serde_json::from_str(&body).map_err(|e| Error::RustError(e.to_string()))?;
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
