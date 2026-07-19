//! Pod provisioning and profile retrieval.
//!
//! Creates per-user Solid pods in R2 with WAC ACL metadata in KV,
//! and serves profile cards from R2.

use worker::*;

/// Handle GET /api/profile: return the authenticated user's profile card from R2.
pub async fn handle_profile(pubkey: &str, env: &Env, cors: Headers) -> Result<Response> {
    let bucket = env.bucket("PODS")?;
    let r2_key = format!("pods/{pubkey}/profile/card");

    let object = match bucket.get(&r2_key).execute().await? {
        Some(obj) => obj,
        None => {
            let body = serde_json::json!({ "error": "Profile not found" });
            let json_str =
                serde_json::to_string(&body).map_err(|e| Error::RustError(e.to_string()))?;
            let resp = Response::ok(json_str)?.with_status(404).with_headers(cors);
            resp.headers().set("Content-Type", "application/json").ok();
            return Ok(resp);
        }
    };

    let body = object
        .body()
        .ok_or_else(|| Error::RustError("R2 object has no body".to_string()))?;
    let bytes = body.bytes().await?;
    let resp = Response::from_bytes(bytes)?.with_headers(cors);
    resp.headers()
        .set("Content-Type", "application/ld+json")
        .ok();
    Ok(resp)
}

#[cfg(test)]
mod tests {
    #[test]
    fn pod_base_urls_are_trimmed_before_appending_pubkey() {
        let pod_base_url = "https://pods.example.com/".trim_end_matches('/');
        let pubkey = "a".repeat(64);
        assert_eq!(
            format!("{pod_base_url}/pods/{pubkey}/profile/card#me"),
            format!("https://pods.example.com/pods/{pubkey}/profile/card#me")
        );
        assert_eq!(
            format!("{pod_base_url}/pods/{pubkey}/"),
            format!("https://pods.example.com/pods/{pubkey}/")
        );
    }
}
