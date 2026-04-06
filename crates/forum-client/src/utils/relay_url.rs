//! Centralized relay and auth API URL resolution.
//!
//! Checks `window.__ENV__` first (runtime override), then compile-time env vars,
//! then production fallback. All forum-client modules should use these functions
//! instead of duplicating URL resolution logic.

/// Base URL for the relay HTTP API (whitelist, setup-status, etc.).
///
/// Converts a WebSocket relay URL to HTTPS for HTTP API calls.
pub fn relay_api_base() -> String {
    // Runtime override via window.__ENV__.RELAY_API_URL (direct HTTP URL)
    if let Some(url) = window_env("RELAY_API_URL") {
        return url;
    }
    // Runtime override via window.__ENV__.VITE_RELAY_URL (WebSocket URL, converted)
    if let Some(url) = window_env("VITE_RELAY_URL") {
        return ws_to_http(&url);
    }
    // Compile-time fallback
    let relay = option_env!("VITE_RELAY_URL")
        .unwrap_or("wss://your-relay.your-subdomain.workers.dev");
    ws_to_http(relay)
}

/// Base URL for the auth HTTP API (WebAuthn registration/login).
pub fn auth_api_base() -> String {
    // Runtime override via window.__ENV__.AUTH_API_URL
    if let Some(url) = window_env("AUTH_API_URL") {
        return url;
    }
    // Runtime override via window.__ENV__.VITE_AUTH_API_URL
    if let Some(url) = window_env("VITE_AUTH_API_URL") {
        return url;
    }
    // Legacy: window.__AUTH_API_URL__
    if let Some(window) = web_sys::window() {
        if let Ok(val) = js_sys::Reflect::get(&window, &"__AUTH_API_URL__".into()) {
            if let Some(s) = val.as_string() {
                if !s.is_empty() {
                    return s;
                }
            }
        }
    }
    // Compile-time fallback
    option_env!("VITE_AUTH_API_URL")
        .unwrap_or("https://api.example.com")
        .to_string()
}

/// Read a key from the `window.__ENV__` object (runtime config injected by index.html).
fn window_env(key: &str) -> Option<String> {
    let window = web_sys::window()?;
    let env = js_sys::Reflect::get(&window, &"__ENV__".into()).ok()?;
    if env.is_undefined() || env.is_null() {
        return None;
    }
    let val = js_sys::Reflect::get(&env, &key.into()).ok()?;
    let s = val.as_string()?;
    if s.is_empty() { None } else { Some(s) }
}

/// Convert a WebSocket URL to an HTTP(S) URL for API calls.
fn ws_to_http(url: &str) -> String {
    url.replace("wss://", "https://")
        .replace("ws://", "http://")
        .trim_end_matches('/')
        .to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── ws_to_http ──────────────────────────────────────────────────────

    #[test]
    fn ws_to_http_wss() {
        assert_eq!(
            ws_to_http("wss://relay.example.com"),
            "https://relay.example.com"
        );
    }

    #[test]
    fn ws_to_http_ws() {
        assert_eq!(
            ws_to_http("ws://relay.example.com"),
            "http://relay.example.com"
        );
    }

    #[test]
    fn ws_to_http_strips_trailing_slash() {
        assert_eq!(
            ws_to_http("wss://relay.example.com/"),
            "https://relay.example.com"
        );
    }

    #[test]
    fn ws_to_http_preserves_path() {
        assert_eq!(
            ws_to_http("wss://relay.example.com/v1/relay"),
            "https://relay.example.com/v1/relay"
        );
    }

    #[test]
    fn ws_to_http_preserves_port() {
        assert_eq!(
            ws_to_http("ws://localhost:8080"),
            "http://localhost:8080"
        );
    }

    #[test]
    fn ws_to_http_no_scheme_change() {
        // If URL is already HTTP, it should pass through
        assert_eq!(
            ws_to_http("https://relay.example.com"),
            "https://relay.example.com"
        );
    }

    #[test]
    fn ws_to_http_production_url() {
        assert_eq!(
            ws_to_http("wss://your-relay.your-subdomain.workers.dev"),
            "https://your-relay.your-subdomain.workers.dev"
        );
    }

    #[test]
    fn ws_to_http_strips_multiple_trailing_slashes() {
        // Only the last trailing slash is stripped per trim_end_matches
        assert_eq!(
            ws_to_http("wss://relay.example.com///"),
            "https://relay.example.com"
        );
    }
}
