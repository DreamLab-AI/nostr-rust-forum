//! Pod provisioning -- creates default directory structure and ACLs for new pods.

use worker::*;

/// Default container structure for a new pod.
const DEFAULT_CONTAINERS: &[&str] = &[
    "profile/",
    "public/",
    "private/",
    "inbox/",
    "settings/",
];

/// Provision a new pod with default containers, ACLs, and WebID profile.
pub async fn provision_pod(
    bucket: &Bucket,
    kv: &kv::KvStore,
    owner_pubkey: &str,
    pod_base: &str,
    display_name: Option<&str>,
) -> Result<()> {
    let base = format!("pods/{owner_pubkey}");

    // Create root container marker
    let root_meta = serde_json::json!({
        "@context": {"ldp": "http://www.w3.org/ns/ldp#"},
        "@type": "ldp:BasicContainer"
    });
    bucket
        .put(
            &format!("{base}/"),
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
                &format!("{base}/{container}"),
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
    let webid_html =
        crate::webid::generate_webid_html(owner_pubkey, display_name, pod_base);
    bucket
        .put(
            &format!("{base}/profile/card"),
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
            "acl:agent": {"@id": format!("did:nostr:{owner_pubkey}")},
            "acl:accessTo": {"@id": "./"},
            "acl:default": {"@id": "./"},
            "acl:mode": [{"@id": "acl:Read"}, {"@id": "acl:Write"}, {"@id": "acl:Control"}]
        }]
    });
    bucket
        .put(
            &format!("{base}/.acl"),
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
            "acl:agent": {"@id": format!("did:nostr:{owner_pubkey}")},
            "acl:accessTo": {"@id": "./"},
            "acl:default": {"@id": "./"},
            "acl:mode": [{"@id": "acl:Read"}, {"@id": "acl:Write"}, {"@id": "acl:Control"}]
        }]
    });
    bucket
        .put(
            &format!("{base}/public/.acl"),
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
            "acl:agent": {"@id": format!("did:nostr:{owner_pubkey}")},
            "acl:accessTo": {"@id": "./"},
            "acl:default": {"@id": "./"},
            "acl:mode": [{"@id": "acl:Read"}, {"@id": "acl:Write"}, {"@id": "acl:Control"}]
        }]
    });
    bucket
        .put(
            &format!("{base}/private/.acl"),
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
            "acl:agent": {"@id": format!("did:nostr:{owner_pubkey}")},
            "acl:accessTo": {"@id": "./"},
            "acl:default": {"@id": "./"},
            "acl:mode": [{"@id": "acl:Read"}, {"@id": "acl:Write"}, {"@id": "acl:Control"}]
        }]
    });
    bucket
        .put(
            &format!("{base}/inbox/.acl"),
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
            "acl:agent": {"@id": format!("did:nostr:{owner_pubkey}")},
            "acl:accessTo": {"@id": "./"},
            "acl:default": {"@id": "./"},
            "acl:mode": [{"@id": "acl:Read"}, {"@id": "acl:Write"}, {"@id": "acl:Control"}]
        }]
    });
    bucket
        .put(
            &format!("{base}/profile/.acl"),
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
            "acl:agent": {"@id": format!("did:nostr:{owner_pubkey}")},
            "acl:accessTo": {"@id": "./"},
            "acl:default": {"@id": "./"},
            "acl:mode": [{"@id": "acl:Read"}, {"@id": "acl:Write"}, {"@id": "acl:Control"}]
        }]
    });
    bucket
        .put(
            &format!("{base}/settings/.acl"),
            serde_json::to_vec(&settings_acl).unwrap_or_default(),
        )
        .http_metadata(HttpMetadata {
            content_type: Some("application/ld+json".into()),
            ..Default::default()
        })
        .execute()
        .await?;

    // Initialize quota
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
    }
}
