//! Pod provisioning — creates default directory structure, ACLs, and TypeIndex
//! documents for new Solid pods.
//!
//! TypeIndex bootstrap (rows 14/164/166 — JSS #301 + #297) mirrors the logic
//! published in solid-pod-rs v0.4.0-alpha.2 `provision.rs`. Both public and
//! private type indexes are created; the public one gets a sibling ACL granting
//! `foaf:Agent` read so Solid clients can discover a freshly bootstrapped pod's
//! public profile without fighting the default-private `/settings/.acl`.

use worker::*;

/// Default container structure for a new pod.
const DEFAULT_CONTAINERS: &[&str] = &[
    "profile/",
    "public/",
    "private/",
    "inbox/",
    "settings/",
    "media/",
    "media/public/",
];

/// Storage path of the public type-index document.
///
/// Mirrors `solid_pod_rs::provision::PUBLIC_TYPE_INDEX_PATH`.
pub const PUBLIC_TYPE_INDEX_PATH: &str = "settings/publicTypeIndex.jsonld";

/// Storage path of the private type-index document.
///
/// Mirrors `solid_pod_rs::provision::PRIVATE_TYPE_INDEX_PATH`.
pub const PRIVATE_TYPE_INDEX_PATH: &str = "settings/privateTypeIndex.jsonld";

/// Storage path of the sibling ACL for the public type-index document.
///
/// Mirrors `solid_pod_rs::provision::PUBLIC_TYPE_INDEX_ACL_PATH`.
pub const PUBLIC_TYPE_INDEX_ACL_PATH: &str = "settings/publicTypeIndex.jsonld.acl";

/// Render the JSON-LD body for a Solid TypeIndex document.
///
/// `visibility_marker` is either `"solid:ListedDocument"` (public) or
/// `"solid:UnlistedDocument"` (private). Mirrors
/// `solid_pod_rs::provision::render_type_index_body`.
fn render_type_index_body(pod_base_url: &str, visibility_marker: &str) -> Vec<u8> {
    let body = serde_json::json!({
        "@context": { "solid": "http://www.w3.org/ns/solid/terms#" },
        "@id": pod_base_url,
        "@type": ["solid:TypeIndex", visibility_marker],
        "http://www.w3.org/ns/solid/terms#TypeRegistration": []
    });
    serde_json::to_vec_pretty(&body).unwrap_or_default()
}

/// Build the ACL JSON-LD body for `publicTypeIndex.jsonld`.
///
/// Grants:
/// - Pod owner (`did:nostr:{pubkey}`) → `acl:Read`, `acl:Write`, `acl:Control`
/// - Public (`foaf:Agent`) → `acl:Read`
///
/// Placed at `settings/publicTypeIndex.jsonld.acl` so it overrides the
/// default-private `/settings/.acl` for this one resource.
fn render_public_type_index_acl(owner_did: &str) -> Vec<u8> {
    let acl = serde_json::json!({
        "@context": {
            "acl": "http://www.w3.org/ns/auth/acl#",
            "foaf": "http://xmlns.com/foaf/0.1/"
        },
        "@graph": [
            {
                "@id": "#owner",
                "@type": "acl:Authorization",
                "acl:agent": { "@id": owner_did },
                "acl:accessTo": { "@id": format!("/{PUBLIC_TYPE_INDEX_PATH}") },
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
                "acl:accessTo": { "@id": format!("/{PUBLIC_TYPE_INDEX_PATH}") },
                "acl:mode": { "@id": "acl:Read" }
            }
        ]
    });
    serde_json::to_vec_pretty(&acl).unwrap_or_default()
}

/// Provision a new pod with default containers, ACLs, and WebID profile.
///
/// **Divergence from upstream `solid_pod_rs::provision::provision_pod`
/// (alpha.12):** this CF-Workers port intentionally does NOT perform
/// `git init -b main` against the pod root. The alpha.12 `git` feature
/// pulls in `tokio::process` for the `git init` subprocess fallback,
/// which has no `wasm32-unknown-unknown` target. CF Workers also lacks
/// process-spawning and a Tokio runtime, so the upstream code path is
/// structurally unreachable here. See **ADR-089** (`docs/adr/ADR-089-git-pods-cf-workers-limitation.md`)
/// for the option matrix and shipping decision. Pods provisioned by
/// this worker are LDP+R2 prefixes with no git history; the parallel
/// agentbox deployment of the same kit does git-init on its server
/// Tokio runtime, so users on that tier get a clone-able pod. The
/// forum-client surfaces a clone URL with an "available on git-init-
/// enabled deployments" caveat to bridge the two tiers.
///
/// **Native pod-git identity + trail (ADR-124 §5.4):** on the native build the
/// clone-able pod root additionally carries the canonical `agent.did.json`
/// (ADR-125 §2 Multikey), `git config nostr.privkey`, and the
/// `gitmark.json`/`blocktrails.json` web-contract trail. That writer lives in
/// [`crate::pod_git_anchor`] (gated `#[cfg(not(target_arch = "wasm32"))]`, so it
/// is structurally absent here on CF). It anchors `states[]` onto **real
/// forum-pod commit SHAs** — never the CF 501 stub. I1–I4 hold: the `agent_did`
/// is the unchanged `did:nostr:<hex>` string and nothing in the trail is read by
/// the NIP-98 auth path (ADR-124 §7).
pub async fn provision_pod(
    bucket: &Bucket,
    kv: &kv::KvStore,
    owner_pubkey: &str,
    pod_base: &str,
    display_name: Option<&str>,
) -> Result<()> {
    let base = format!("pods/{owner_pubkey}");

    // Canonical owner DID, minted through the shared helper so the URI scheme
    // stays consistent with the rest of the ecosystem. Falls back to the literal
    // form only if `owner_pubkey` is not valid hex (callers validate upstream).
    let owner_did = crate::did::NostrPubkey::from_hex(owner_pubkey)
        .map(|pk| nostr_bbs_core::did_nostr_uri(&pk))
        .unwrap_or_else(|_| format!("did:nostr:{owner_pubkey}"));

    // Create root container marker
    let root_meta = serde_json::json!({
        "@context": {"ldp": "http://www.w3.org/ns/ldp#"},
        "@type": "ldp:BasicContainer"
    });
    bucket
        .put(
            format!("{base}/"),
            serde_json::to_vec(&root_meta).unwrap_or_default(),
        )
        .http_metadata(HttpMetadata {
            content_type: Some("application/ld+json".into()),
            ..Default::default()
        })
        .execute()
        .await?;

    // Create sub-containers
    for container in DEFAULT_CONTAINERS {
        let container_meta = serde_json::json!({
            "@context": {"ldp": "http://www.w3.org/ns/ldp#"},
            "@type": "ldp:BasicContainer"
        });
        bucket
            .put(
                format!("{base}/{container}"),
                serde_json::to_vec(&container_meta).unwrap_or_default(),
            )
            .http_metadata(HttpMetadata {
                content_type: Some("application/ld+json".into()),
                ..Default::default()
            })
            .execute()
            .await?;
    }

    // Create WebID profile
    let webid_html = crate::webid::generate_webid_html(owner_pubkey, display_name, pod_base);
    bucket
        .put(
            format!("{base}/profile/card"),
            webid_html.as_bytes().to_vec(),
        )
        .http_metadata(HttpMetadata {
            content_type: Some("text/html".into()),
            ..Default::default()
        })
        .execute()
        .await?;

    // Root ACL: owner has full control
    let root_acl = serde_json::json!({
        "@context": {"acl": "http://www.w3.org/ns/auth/acl#"},
        "@graph": [{
            "@id": "#owner",
            "acl:agent": {"@id": owner_did.clone()},
            "acl:accessTo": {"@id": "./"},
            "acl:default": {"@id": "./"},
            "acl:mode": [{"@id": "acl:Read"}, {"@id": "acl:Write"}, {"@id": "acl:Control"}]
        }]
    });
    bucket
        .put(
            format!("{base}/.acl"),
            serde_json::to_vec(&root_acl).unwrap_or_default(),
        )
        .http_metadata(HttpMetadata {
            content_type: Some("application/ld+json".into()),
            ..Default::default()
        })
        .execute()
        .await?;

    // Public container: world-readable, owner full control
    let public_acl = serde_json::json!({
        "@context": {"acl": "http://www.w3.org/ns/auth/acl#"},
        "@graph": [{
            "@id": "#public",
            "acl:agentClass": {"@id": "foaf:Agent"},
            "acl:accessTo": {"@id": "./"},
            "acl:default": {"@id": "./"},
            "acl:mode": {"@id": "acl:Read"}
        }, {
            "@id": "#owner",
            "acl:agent": {"@id": owner_did.clone()},
            "acl:accessTo": {"@id": "./"},
            "acl:default": {"@id": "./"},
            "acl:mode": [{"@id": "acl:Read"}, {"@id": "acl:Write"}, {"@id": "acl:Control"}]
        }]
    });
    bucket
        .put(
            format!("{base}/public/.acl"),
            serde_json::to_vec(&public_acl).unwrap_or_default(),
        )
        .http_metadata(HttpMetadata {
            content_type: Some("application/ld+json".into()),
            ..Default::default()
        })
        .execute()
        .await?;

    // Public media container: world-readable uploads, owner full control.
    // The forum-client writes images to `/media/public/`; provisioning it
    // explicitly keeps the user-facing media flow aligned with the browser UI.
    bucket
        .put(
            format!("{base}/media/public/.acl"),
            serde_json::to_vec(&public_acl).unwrap_or_default(),
        )
        .http_metadata(HttpMetadata {
            content_type: Some("application/ld+json".into()),
            ..Default::default()
        })
        .execute()
        .await?;

    // Private container: owner-only
    let private_acl = serde_json::json!({
        "@context": {"acl": "http://www.w3.org/ns/auth/acl#"},
        "@graph": [{
            "@id": "#owner",
            "acl:agent": {"@id": owner_did.clone()},
            "acl:accessTo": {"@id": "./"},
            "acl:default": {"@id": "./"},
            "acl:mode": [{"@id": "acl:Read"}, {"@id": "acl:Write"}, {"@id": "acl:Control"}]
        }]
    });
    bucket
        .put(
            format!("{base}/private/.acl"),
            serde_json::to_vec(&private_acl).unwrap_or_default(),
        )
        .http_metadata(HttpMetadata {
            content_type: Some("application/ld+json".into()),
            ..Default::default()
        })
        .execute()
        .await?;

    // Inbox: append for authenticated, read+write+control for owner
    let inbox_acl = serde_json::json!({
        "@context": {"acl": "http://www.w3.org/ns/auth/acl#"},
        "@graph": [{
            "@id": "#authenticated-append",
            "acl:agentClass": {"@id": "acl:AuthenticatedAgent"},
            "acl:accessTo": {"@id": "./"},
            "acl:default": {"@id": "./"},
            "acl:mode": {"@id": "acl:Append"}
        }, {
            "@id": "#owner",
            "acl:agent": {"@id": owner_did.clone()},
            "acl:accessTo": {"@id": "./"},
            "acl:default": {"@id": "./"},
            "acl:mode": [{"@id": "acl:Read"}, {"@id": "acl:Write"}, {"@id": "acl:Control"}]
        }]
    });
    bucket
        .put(
            format!("{base}/inbox/.acl"),
            serde_json::to_vec(&inbox_acl).unwrap_or_default(),
        )
        .http_metadata(HttpMetadata {
            content_type: Some("application/ld+json".into()),
            ..Default::default()
        })
        .execute()
        .await?;

    // Profile container ACL: public-readable (for WebID), owner full control
    let profile_acl = serde_json::json!({
        "@context": {"acl": "http://www.w3.org/ns/auth/acl#"},
        "@graph": [{
            "@id": "#public",
            "acl:agentClass": {"@id": "foaf:Agent"},
            "acl:accessTo": {"@id": "./"},
            "acl:default": {"@id": "./"},
            "acl:mode": {"@id": "acl:Read"}
        }, {
            "@id": "#owner",
            "acl:agent": {"@id": owner_did.clone()},
            "acl:accessTo": {"@id": "./"},
            "acl:default": {"@id": "./"},
            "acl:mode": [{"@id": "acl:Read"}, {"@id": "acl:Write"}, {"@id": "acl:Control"}]
        }]
    });
    bucket
        .put(
            format!("{base}/profile/.acl"),
            serde_json::to_vec(&profile_acl).unwrap_or_default(),
        )
        .http_metadata(HttpMetadata {
            content_type: Some("application/ld+json".into()),
            ..Default::default()
        })
        .execute()
        .await?;

    // Settings container ACL: owner-only
    let settings_acl = serde_json::json!({
        "@context": {"acl": "http://www.w3.org/ns/auth/acl#"},
        "@graph": [{
            "@id": "#owner",
            "acl:agent": {"@id": owner_did.clone()},
            "acl:accessTo": {"@id": "./"},
            "acl:default": {"@id": "./"},
            "acl:mode": [{"@id": "acl:Read"}, {"@id": "acl:Write"}, {"@id": "acl:Control"}]
        }]
    });
    bucket
        .put(
            format!("{base}/settings/.acl"),
            serde_json::to_vec(&settings_acl).unwrap_or_default(),
        )
        .http_metadata(HttpMetadata {
            content_type: Some("application/ld+json".into()),
            ..Default::default()
        })
        .execute()
        .await?;

    // -----------------------------------------------------------------------
    // TypeIndex bootstrap (rows 14/164/166 — JSS #301 + #297).
    //
    // The public TypeIndex gets a sibling ACL granting foaf:Agent read so
    // Solid clients can discover the pod's public profile. The private
    // TypeIndex inherits the default-private /settings/.acl.
    //
    // Mirrors solid-pod-rs v0.4.0-alpha.2 provision::provision_pod logic.
    // -----------------------------------------------------------------------
    let pod_url = format!("{pod_base}/pods/{owner_pubkey}/");

    let public_ti_url = format!("{pod_url}{PUBLIC_TYPE_INDEX_PATH}");
    let public_ti_body = render_type_index_body(&public_ti_url, "solid:ListedDocument");
    bucket
        .put(format!("{base}/{PUBLIC_TYPE_INDEX_PATH}"), public_ti_body)
        .http_metadata(HttpMetadata {
            content_type: Some("application/ld+json".into()),
            ..Default::default()
        })
        .execute()
        .await?;

    let private_ti_url = format!("{pod_url}{PRIVATE_TYPE_INDEX_PATH}");
    let private_ti_body = render_type_index_body(&private_ti_url, "solid:UnlistedDocument");
    bucket
        .put(format!("{base}/{PRIVATE_TYPE_INDEX_PATH}"), private_ti_body)
        .http_metadata(HttpMetadata {
            content_type: Some("application/ld+json".into()),
            ..Default::default()
        })
        .execute()
        .await?;

    let public_ti_acl_body = render_public_type_index_acl(&owner_did);
    bucket
        .put(
            format!("{base}/{PUBLIC_TYPE_INDEX_ACL_PATH}"),
            public_ti_acl_body,
        )
        .http_metadata(HttpMetadata {
            content_type: Some("application/ld+json".into()),
            ..Default::default()
        })
        .execute()
        .await?;

    // Initialize quota (KV-based; D1 migration pending)
    #[allow(deprecated)]
    crate::quota::update_usage(kv, owner_pubkey, 0).await?;

    Ok(())
}

/// Check if a pod exists (has a root container).
pub async fn pod_exists(bucket: &Bucket, owner_pubkey: &str) -> bool {
    let key = format!("pods/{owner_pubkey}/");
    bucket
        .get(&key)
        .execute()
        .await
        .map(|o| o.is_some())
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_containers_are_valid() {
        for c in DEFAULT_CONTAINERS {
            assert!(c.ends_with('/'), "Container must end with /: {c}");
            assert!(!c.contains(".."), "No traversal: {c}");
        }
    }

    #[test]
    fn default_containers_include_required() {
        let names: Vec<&str> = DEFAULT_CONTAINERS.to_vec();
        assert!(names.contains(&"profile/"));
        assert!(names.contains(&"public/"));
        assert!(names.contains(&"private/"));
        assert!(names.contains(&"inbox/"));
        assert!(names.contains(&"settings/"));
        assert!(names.contains(&"media/"));
        assert!(names.contains(&"media/public/"));
    }

    #[test]
    fn type_index_paths_are_under_settings() {
        assert!(PUBLIC_TYPE_INDEX_PATH.starts_with("settings/"));
        assert!(PRIVATE_TYPE_INDEX_PATH.starts_with("settings/"));
        assert!(PUBLIC_TYPE_INDEX_ACL_PATH.starts_with("settings/"));
        assert!(PUBLIC_TYPE_INDEX_ACL_PATH.ends_with(".acl"));
    }

    #[test]
    fn render_type_index_body_is_valid_json() {
        let body = render_type_index_body(
            "https://pods.example/settings/publicTypeIndex.jsonld",
            "solid:ListedDocument",
        );
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let types = v["@type"].as_array().unwrap();
        let type_strs: Vec<&str> = types.iter().filter_map(|t| t.as_str()).collect();
        assert!(type_strs.contains(&"solid:TypeIndex"));
        assert!(type_strs.contains(&"solid:ListedDocument"));
    }

    #[test]
    fn render_public_type_index_acl_is_valid_json() {
        let body = render_public_type_index_acl("did:nostr:aabb");
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(v["@graph"].is_array());
        let graph = v["@graph"].as_array().unwrap();
        assert_eq!(graph.len(), 2);
        // One entry for owner, one for foaf:Agent
        let ids: Vec<&str> = graph.iter().filter_map(|e| e["@id"].as_str()).collect();
        assert!(ids.contains(&"#owner"));
        assert!(ids.contains(&"#public"));
    }

    /// Regression: solid-pod-rs's wac evaluator only matches leading-slash
    /// pod-relative `acl:accessTo` IRIs. If the accessTo is emitted without the
    /// leading slash the public-read carve-out never matches AND the owner is
    /// locked out of `publicTypeIndex.jsonld`. Every authorization's accessTo
    /// must therefore start with "/".
    #[test]
    fn render_public_type_index_acl_access_to_has_leading_slash() {
        let body = render_public_type_index_acl("did:nostr:aabb");
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let graph = v["@graph"].as_array().unwrap();
        for entry in graph {
            let access_to = entry["acl:accessTo"]["@id"]
                .as_str()
                .expect("acl:accessTo @id must be a string");
            assert!(
                access_to.starts_with('/'),
                "acl:accessTo must be a leading-slash pod-relative path: {access_to}"
            );
            assert_eq!(access_to, format!("/{PUBLIC_TYPE_INDEX_PATH}"));
        }
    }
}
