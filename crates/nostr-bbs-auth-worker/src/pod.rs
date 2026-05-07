//! Pod provisioning and profile retrieval.
//!
//! Creates per-user Solid pods in R2 with WAC ACL metadata in KV,
//! and serves profile cards from R2.

use serde_json::json;
use worker::*;

/// Pod base URL template. The pubkey is appended as a path segment.
const POD_BASE_URL: &str = "https://pods.example.com";

/// Provision a new Solid pod for the given pubkey.
///
/// Creates:
/// - ACL document in KV (`acl:{pubkey}`) with owner + public read rules
/// - Profile card in R2 (`pods/{pubkey}/profile/card`) as JSON-LD
/// - Pod metadata in KV (`meta:{pubkey}`)
///
/// Returns the WebID and pod URL on success.
pub async fn provision_pod(pubkey: &str, env: &Env) -> Result<PodInfo> {
    let did = format!("did:nostr:{pubkey}");

    let default_acl = json!({
        "@context": {
            "acl": "http://www.w3.org/ns/auth/acl#",
            "foaf": "http://xmlns.com/foaf/0.1/"
        },
        "@graph": [
            {
                "@id": "#owner",
                "@type": "acl:Authorization",
                "acl:agent": { "@id": did },
                "acl:accessTo": { "@id": "./" },
                "acl:default": { "@id": "./" },
                "acl:mode": [
                    { "@id": "acl:Read" },
                    { "@id": "acl:Write" },
                    { "@id": "acl:Control" }
                ]
            },
            {
                "@id": "#public",
                "@type": "acl:Authorization",
                "acl:agentClass": { "@id": "foaf:Agent" },
                "acl:accessTo": { "@id": "./profile/" },
                "acl:mode": [{ "@id": "acl:Read" }]
            },
            {
                "@id": "#media-public",
                "@type": "acl:Authorization",
                "acl:agentClass": { "@id": "foaf:Agent" },
                "acl:accessTo": { "@id": "./media/public/" },
                "acl:mode": [{ "@id": "acl:Read" }]
            }
        ]
    });

    let profile_card = json!({
        "@context": {
            "foaf": "http://xmlns.com/foaf/0.1/"
        },
        "@id": did,
        "@type": "foaf:Person"
    });

    let acl_json =
        serde_json::to_string(&default_acl).map_err(|e| Error::RustError(e.to_string()))?;
    let profile_json =
        serde_json::to_string(&profile_card).map_err(|e| Error::RustError(e.to_string()))?;
    let now_ms = (js_sys::Date::now()) as u64;
    let meta_json = serde_json::to_string(&json!({
        "created": now_ms,
        "storageUsed": 0
    }))
    .map_err(|e| Error::RustError(e.to_string()))?;

    // Write ACL to KV
    let kv = env.kv("POD_META")?;
    kv.put(&format!("acl:{pubkey}"), acl_json)?
        .execute()
        .await?;

    // Write profile card to R2
    let bucket = env.bucket("PODS")?;
    let r2_key = format!("pods/{pubkey}/profile/card");
    bucket
        .put(&r2_key, profile_json)
        .http_metadata(HttpMetadata {
            content_type: Some("application/ld+json".to_string()),
            ..Default::default()
        })
        .execute()
        .await?;

    // Write metadata to KV
    kv.put(&format!("meta:{pubkey}"), meta_json)?
        .execute()
        .await?;

    Ok(PodInfo {
        web_id: format!("{POD_BASE_URL}/{pubkey}/profile/card#me"),
        pod_url: format!("{POD_BASE_URL}/{pubkey}/"),
    })
}

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

/// Pod provisioning result.
pub struct PodInfo {
    pub web_id: String,
    pub pod_url: String,
}
