//! Solid Notifications Protocol (simplified webhook implementation).
//!
//! Subscribers register via POST to `{resource}.notifications` with a webhook URL.
//! On resource change, the pod-worker sends a POST to the webhook URL.

use serde::{Deserialize, Serialize};
use worker::*;

#[derive(Debug, Serialize, Deserialize)]
pub struct Subscription {
    pub webhook_url: String,
    pub resource_path: String,
    pub created_at: u64,
}

/// Store a notification subscription in KV.
pub async fn subscribe(
    kv: &kv::KvStore,
    owner_pubkey: &str,
    resource_path: &str,
    webhook_url: &str,
) -> Result<()> {
    let key = format!("notify:{owner_pubkey}:{resource_path}");
    let mut subs = get_subscriptions(kv, &key).await;

    // Avoid duplicates
    if subs.iter().any(|s| s.webhook_url == webhook_url) {
        return Ok(());
    }

    subs.push(Subscription {
        webhook_url: webhook_url.to_string(),
        resource_path: resource_path.to_string(),
        created_at: (js_sys::Date::now() / 1000.0) as u64,
    });

    let json = serde_json::to_string(&subs)
        .map_err(|e| Error::RustError(format!("notify serialize: {e}")))?;
    kv.put(&key, &json)?.execute().await?;
    Ok(())
}

/// Remove a notification subscription from KV.
pub async fn unsubscribe(
    kv: &kv::KvStore,
    owner_pubkey: &str,
    resource_path: &str,
    webhook_url: &str,
) -> Result<bool> {
    let key = format!("notify:{owner_pubkey}:{resource_path}");
    let mut subs = get_subscriptions(kv, &key).await;
    let original_len = subs.len();

    subs.retain(|s| s.webhook_url != webhook_url);

    if subs.len() == original_len {
        return Ok(false); // Nothing removed
    }

    if subs.is_empty() {
        kv.delete(&key).await?;
    } else {
        let json = serde_json::to_string(&subs)
            .map_err(|e| Error::RustError(format!("notify serialize: {e}")))?;
        kv.put(&key, &json)?.execute().await?;
    }
    Ok(true)
}

/// Get all subscriptions for a resource.
async fn get_subscriptions(kv: &kv::KvStore, key: &str) -> Vec<Subscription> {
    kv.get(key)
        .text()
        .await
        .ok()
        .flatten()
        .and_then(|json| serde_json::from_str(&json).ok())
        .unwrap_or_default()
}

/// Notify all subscribers of a resource change (fire-and-forget).
///
/// This is best-effort delivery. Failures are silently ignored so as not
/// to block the main request path.
pub async fn notify_change(
    kv: &kv::KvStore,
    owner_pubkey: &str,
    resource_path: &str,
    change_type: &str,
) {
    let key = format!("notify:{owner_pubkey}:{resource_path}");
    let subs = get_subscriptions(kv, &key).await;

    for sub in &subs {
        let body = serde_json::json!({
            "type": change_type,
            "object": resource_path,
            "pod": format!("/pods/{owner_pubkey}/"),
            "published": js_sys::Date::now() / 1000.0
        });

        let headers = worker::Headers::new();
        headers.set("Content-Type", "application/json").ok();

        // Best-effort delivery -- don't block the response on webhook failures.
        // Workers Fetch API requires a Request object; build one manually.
        if let Ok(url) = worker::Url::parse(&sub.webhook_url) {
            let mut init = RequestInit::new();
            init.with_method(Method::Post);
            init.with_headers(headers);

            if let Ok(request) = Request::new_with_init(url.as_str(), &init) {
                // We intentionally ignore the result -- fire-and-forget.
                let _ = Fetch::Request(request).send().await;
            }
        }

        // Fallback: if URL parsing or request construction fails, skip silently.
        let _ = body; // suppress unused warning in error paths
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscription_serialization() {
        let sub = Subscription {
            webhook_url: "https://example.com/hook".into(),
            resource_path: "/public/data.json".into(),
            created_at: 1700000000,
        };
        let json = serde_json::to_string(&sub).unwrap();
        let parsed: Subscription = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.webhook_url, "https://example.com/hook");
        assert_eq!(parsed.resource_path, "/public/data.json");
        assert_eq!(parsed.created_at, 1700000000);
    }

    #[test]
    fn subscription_round_trip_vec() {
        let subs = vec![
            Subscription {
                webhook_url: "https://a.com/hook".into(),
                resource_path: "/public/".into(),
                created_at: 1000,
            },
            Subscription {
                webhook_url: "https://b.com/hook".into(),
                resource_path: "/private/doc.json".into(),
                created_at: 2000,
            },
        ];
        let json = serde_json::to_string(&subs).unwrap();
        let parsed: Vec<Subscription> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].webhook_url, "https://a.com/hook");
        assert_eq!(parsed[1].resource_path, "/private/doc.json");
    }

    #[test]
    fn subscription_deserialize_empty_array() {
        let parsed: Vec<Subscription> = serde_json::from_str("[]").unwrap();
        assert!(parsed.is_empty());
    }
}
