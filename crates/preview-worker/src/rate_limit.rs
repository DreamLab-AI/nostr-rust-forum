//! Application-layer rate limiting via Cloudflare KV.
//!
//! Uses a sliding-window approach with minute-bucketed KV keys.
//! Key format: `rl:{ip}:{minute_bucket}` with TTL = window seconds.

use worker::*;

/// Check whether the request from `ip` exceeds `limit` requests per `window_secs`.
///
/// Returns `true` if the request is allowed, `false` if rate-limited.
/// On KV errors, the request is allowed (fail-open).
pub async fn check_rate_limit(
    env: &Env,
    ip: &str,
    limit: u32,
    window_secs: u64,
) -> bool {
    let kv = match env.kv("RATE_LIMIT") {
        Ok(kv) => kv,
        Err(_) => return true, // fail-open
    };

    let bucket = js_sys::Date::now() as u64 / (window_secs * 1000);
    let key = format!("rl:{}:{}", ip, bucket);

    let current: u32 = match kv.get(&key).text().await {
        Ok(Some(val)) => val.parse().unwrap_or(0),
        _ => 0,
    };

    if current >= limit {
        return false;
    }

    // Increment counter with TTL
    let new_val = (current + 1).to_string();
    if let Ok(builder) = kv.put(&key, &new_val) {
        let _ = builder.expiration_ttl(window_secs).execute().await;
    }

    true
}

/// Extract the client IP from CF-Connecting-IP header, falling back to "unknown".
pub fn client_ip(req: &Request) -> String {
    req.headers()
        .get("CF-Connecting-IP")
        .ok()
        .flatten()
        .unwrap_or_else(|| "unknown".to_string())
}
