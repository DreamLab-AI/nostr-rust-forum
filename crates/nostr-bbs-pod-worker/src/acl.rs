//! WAC (Web Access Control) — absorbed adapter over `solid_pod_rs::wac`.
//!
//! Phase 5 absorption (ADR-076/078): the JSON-LD WAC parsing + evaluation
//! moves to the upstream pure-logic surface. Kit-specific extensions stay
//! local:
//!
//! - [`coerce_required_mode_for_acl`] — Sprint v9 STREAM-B B3 escalation guard
//!   for `*.acl` writes. Upstream WAC has no equivalent because the spec
//!   leaves the choice of HTTP-method → mode mapping to the operator.
//! - [`MAX_ACL_DOC_BYTES`] — kit caps ACL JSON-LD at 64 KiB (upstream's
//!   `MAX_ACL_BYTES` is 1 MiB; kit deliberately stricter per audit C3).
//! - [`parse_acl_with_cap`] / [`parse_acl_text_with_cap`] — apply the
//!   stricter cap before delegating to `serde_json::from_slice`.
//! - [`find_effective_acl`] — CF Workers R2 + KV walk-up resolver. Tied to
//!   the worker-rs API; can't live in upstream which is runtime-agnostic.
//!
//! @see <https://solid.github.io/web-access-control-spec/>

// Pure-logic re-exports from solid-pod-rs 0.4.0-alpha.4 `wac` module. These
// were the kit's hand-rolled implementations; the upstream surface is API-
// shape compatible and battle-tested in the JSS port.
pub use solid_pod_rs::wac::{
    method_to_mode, mode_name, wac_allow_header, AccessMode, AclAuthorization, AclDocument,
    IdOrIds, IdRef,
};

/// All access modes, used for iterating when building WAC-Allow headers.
pub const ALL_MODES: &[AccessMode] = &[
    AccessMode::Read,
    AccessMode::Write,
    AccessMode::Append,
    AccessMode::Control,
];

/// Evaluate whether access should be granted based on an ACL document.
///
/// Thin wrapper passing `request_origin = None` to upstream WAC 1.x
/// evaluation. The kit's pod-worker does not yet emit `acl:origin`-gated
/// rules; if/when that ships, callers should switch to
/// [`solid_pod_rs::wac::evaluate_access`] directly.
#[inline]
pub fn evaluate_access(
    acl_doc: Option<&AclDocument>,
    agent_uri: Option<&str>,
    resource_path: &str,
    required_mode: AccessMode,
) -> bool {
    solid_pod_rs::wac::evaluate_access(acl_doc, agent_uri, resource_path, required_mode, None)
}

// ---------------------------------------------------------------------------
// Kit-specific: WAC Control coercion for `*.acl` paths (Sprint v9 STREAM-B B3)
// ---------------------------------------------------------------------------

/// Determine if a path targets an `.acl` sidecar (matches `lib.rs::is_acl_path`).
fn path_is_acl(path: &str) -> bool {
    path.ends_with(".acl")
}

/// Coerce the required `AccessMode` for a request when the target resource is
/// an `.acl` sidecar.
///
/// Per the WAC spec, only holders of `acl:Control` on the parent resource may
/// **write** an ACL document, and reading an ACL requires either `acl:Read`
/// on the parent OR `acl:Control`. The standard HTTP-method mapping (PUT →
/// Write) is therefore unsafe for `.acl` paths because a principal with mere
/// `acl:Write` would otherwise be able to escalate to `acl:Control` by
/// overwriting the sidecar. Coerce write-class methods to `Control` so the
/// caller never grants `.acl` writes purely on `acl:Write`.
///
/// GET/HEAD remain `Read` because callers compose this with an additional
/// `Control` check at the handler level.
pub fn coerce_required_mode_for_acl(path: &str, method: &str) -> AccessMode {
    let base = method_to_mode(method);
    if !path_is_acl(path) {
        return base;
    }
    match base {
        AccessMode::Read => AccessMode::Read,
        // Any write/append against an .acl resource MUST require Control.
        AccessMode::Write | AccessMode::Append | AccessMode::Control => AccessMode::Control,
    }
}

// ---------------------------------------------------------------------------
// Kit-specific: stricter 64 KiB ACL document cap + R2/KV resolver
// ---------------------------------------------------------------------------

/// Hard cap on the size (in bytes) of an ACL JSON-LD document we will parse.
///
/// 64 KiB is far larger than any realistic policy graph and prevents an
/// attacker from forcing the WAC evaluator to allocate or recurse into a
/// pathologically large `@graph`. Sidecars beyond this size are treated as
/// "no ACL found" so resolution falls back to the parent container.
///
/// The upstream `solid_pod_rs::wac::MAX_ACL_BYTES` is 1 MiB; the kit chooses
/// a tighter ceiling per audit C3 because the forum's pod surface area is
/// far smaller than a generic Solid pod.
pub const MAX_ACL_DOC_BYTES: usize = 64 * 1024;

/// Parse an ACL document from raw bytes, enforcing [`MAX_ACL_DOC_BYTES`].
///
/// Returns `Some(doc)` on success and `None` for any size or parse failure.
fn parse_acl_with_cap(bytes: &[u8]) -> Option<AclDocument> {
    if bytes.len() > MAX_ACL_DOC_BYTES {
        return None;
    }
    serde_json::from_slice::<AclDocument>(bytes).ok()
}

/// Same as [`parse_acl_with_cap`] but operates on a `&str`.
fn parse_acl_text_with_cap(text: &str) -> Option<AclDocument> {
    if text.len() > MAX_ACL_DOC_BYTES {
        return None;
    }
    serde_json::from_str::<AclDocument>(text).ok()
}

/// Find the effective ACL for a resource by walking up the container tree.
///
/// Resolution order:
/// 1. KV fast-path: `acl:{owner_pubkey}` (the pod-level ACL)
/// 2. R2 sidecar walk: `{resource_path}.acl` -> `{parent}/.acl` -> ... -> `/.acl`
///
/// All ACL documents are parsed via [`parse_acl_with_cap`] so any single
/// graph larger than [`MAX_ACL_DOC_BYTES`] is rejected (treated as missing).
///
/// Returns `None` if no ACL document is found at any level (deny-all).
pub async fn find_effective_acl(
    bucket: &worker::Bucket,
    kv: &worker::kv::KvStore,
    owner_pubkey: &str,
    resource_path: &str,
) -> Option<AclDocument> {
    // Fast path: pod-level ACL in KV
    let kv_key = format!("acl:{owner_pubkey}");
    if let Ok(Some(text)) = kv.get(&kv_key).text().await {
        if let Some(doc) = parse_acl_text_with_cap(&text) {
            return Some(doc);
        }
    }

    // Walk up the container tree looking for `.acl` sidecar files in R2
    let mut path = resource_path.to_string();
    loop {
        let acl_key = format!("pods/{owner_pubkey}{path}.acl");
        if let Ok(Some(obj)) = bucket.get(&acl_key).execute().await {
            if let Some(body) = obj.body() {
                if let Ok(bytes) = body.bytes().await {
                    if let Some(doc) = parse_acl_with_cap(&bytes) {
                        return Some(doc);
                    }
                }
            }
        }

        // Move up one directory level
        if path == "/" || path.is_empty() {
            break;
        }
        // Strip trailing slash before finding parent
        let trimmed = path.trim_end_matches('/');
        path = match trimmed.rfind('/') {
            Some(0) => "/".to_string(),
            Some(pos) => trimmed[..pos].to_string(),
            None => "/".to_string(),
        };
    }

    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
//
// These exercise the absorbed surface. Semantic parity with the legacy
// hand-roll is required for the absorption to be safe; any divergence must
// be documented and either ratified or reverted.

#[cfg(test)]
mod tests {
    use super::*;

    fn make_doc(graph: Vec<AclAuthorization>) -> AclDocument {
        AclDocument {
            context: None,
            graph: Some(graph),
        }
    }

    fn auth_read_public(path: &str) -> AclAuthorization {
        AclAuthorization {
            id: None,
            r#type: None,
            agent: None,
            agent_class: Some(IdOrIds::Single(IdRef {
                id: "foaf:Agent".to_string(),
            })),
            agent_group: None,
            origin: None,
            access_to: Some(IdOrIds::Single(IdRef {
                id: path.to_string(),
            })),
            default: None,
            mode: Some(IdOrIds::Single(IdRef {
                id: "acl:Read".to_string(),
            })),
            condition: None,
        }
    }

    fn auth_write_agent(path: &str, agent: &str) -> AclAuthorization {
        AclAuthorization {
            id: None,
            r#type: None,
            agent: Some(IdOrIds::Single(IdRef {
                id: agent.to_string(),
            })),
            agent_class: None,
            agent_group: None,
            origin: None,
            access_to: Some(IdOrIds::Single(IdRef {
                id: path.to_string(),
            })),
            default: None,
            mode: Some(IdOrIds::Single(IdRef {
                id: "acl:Write".to_string(),
            })),
            condition: None,
        }
    }

    #[test]
    fn no_acl_denies_all() {
        assert!(!evaluate_access(None, None, "/foo", AccessMode::Read));
    }

    #[test]
    fn empty_graph_denies_all() {
        let doc = AclDocument {
            context: None,
            graph: None,
        };
        assert!(!evaluate_access(Some(&doc), None, "/foo", AccessMode::Read));
    }

    #[test]
    fn public_read_grants_anonymous() {
        let doc = make_doc(vec![auth_read_public("/")]);
        assert!(evaluate_access(Some(&doc), None, "/", AccessMode::Read));
    }

    #[test]
    fn public_read_denies_write() {
        let doc = make_doc(vec![auth_read_public("/")]);
        assert!(!evaluate_access(Some(&doc), None, "/", AccessMode::Write));
    }

    #[test]
    fn agent_write_grants_matching_agent() {
        let agent = "did:nostr:abc123";
        let doc = make_doc(vec![auth_write_agent("/data", agent)]);
        assert!(evaluate_access(
            Some(&doc),
            Some(agent),
            "/data",
            AccessMode::Write
        ));
    }

    #[test]
    fn agent_write_denies_different_agent() {
        let doc = make_doc(vec![auth_write_agent("/data", "did:nostr:abc123")]);
        assert!(!evaluate_access(
            Some(&doc),
            Some("did:nostr:other"),
            "/data",
            AccessMode::Write
        ));
    }

    #[test]
    fn acl_write_grants_append() {
        let agent = "did:nostr:abc123";
        let doc = make_doc(vec![auth_write_agent("/data", agent)]);
        assert!(evaluate_access(
            Some(&doc),
            Some(agent),
            "/data",
            AccessMode::Append
        ));
    }

    #[test]
    fn access_to_matches_children() {
        let doc = make_doc(vec![auth_read_public("/media")]);
        assert!(evaluate_access(
            Some(&doc),
            None,
            "/media/photo.jpg",
            AccessMode::Read
        ));
    }

    #[test]
    fn default_applies_to_children() {
        let auth = AclAuthorization {
            id: None,
            r#type: None,
            agent: None,
            agent_class: Some(IdOrIds::Single(IdRef {
                id: "foaf:Agent".to_string(),
            })),
            agent_group: None,
            origin: None,
            access_to: None,
            default: Some(IdOrIds::Single(IdRef {
                id: "/public".to_string(),
            })),
            mode: Some(IdOrIds::Single(IdRef {
                id: "acl:Read".to_string(),
            })),
            condition: None,
        };
        let doc = make_doc(vec![auth]);
        assert!(evaluate_access(
            Some(&doc),
            None,
            "/public/file.txt",
            AccessMode::Read
        ));
    }

    #[test]
    fn authenticated_agent_requires_auth() {
        let auth = AclAuthorization {
            id: None,
            r#type: None,
            agent: None,
            agent_class: Some(IdOrIds::Single(IdRef {
                id: "acl:AuthenticatedAgent".to_string(),
            })),
            agent_group: None,
            origin: None,
            access_to: Some(IdOrIds::Single(IdRef {
                id: "/members".to_string(),
            })),
            default: None,
            mode: Some(IdOrIds::Single(IdRef {
                id: "acl:Read".to_string(),
            })),
            condition: None,
        };
        let doc = make_doc(vec![auth]);

        // Anonymous denied
        assert!(!evaluate_access(
            Some(&doc),
            None,
            "/members",
            AccessMode::Read
        ));
        // Authenticated granted
        assert!(evaluate_access(
            Some(&doc),
            Some("did:nostr:abc"),
            "/members",
            AccessMode::Read
        ));
    }

    #[test]
    fn method_to_mode_mapping() {
        assert_eq!(method_to_mode("GET"), AccessMode::Read);
        assert_eq!(method_to_mode("HEAD"), AccessMode::Read);
        assert_eq!(method_to_mode("PUT"), AccessMode::Write);
        assert_eq!(method_to_mode("DELETE"), AccessMode::Write);
        assert_eq!(method_to_mode("POST"), AccessMode::Append);
        assert_eq!(method_to_mode("PATCH"), AccessMode::Write);
    }

    #[test]
    fn full_uri_mode_recognized() {
        let auth = AclAuthorization {
            id: None,
            r#type: None,
            agent: None,
            agent_class: Some(IdOrIds::Single(IdRef {
                id: "http://xmlns.com/foaf/0.1/Agent".to_string(),
            })),
            agent_group: None,
            origin: None,
            access_to: Some(IdOrIds::Single(IdRef {
                id: "/".to_string(),
            })),
            default: None,
            mode: Some(IdOrIds::Single(IdRef {
                id: "http://www.w3.org/ns/auth/acl#Read".to_string(),
            })),
            condition: None,
        };
        let doc = make_doc(vec![auth]);
        assert!(evaluate_access(Some(&doc), None, "/", AccessMode::Read));
    }

    #[test]
    fn multiple_modes_on_single_auth() {
        let auth = AclAuthorization {
            id: None,
            r#type: None,
            agent: Some(IdOrIds::Single(IdRef {
                id: "did:nostr:owner".to_string(),
            })),
            agent_class: None,
            agent_group: None,
            origin: None,
            access_to: Some(IdOrIds::Single(IdRef {
                id: "/".to_string(),
            })),
            default: None,
            mode: Some(IdOrIds::Multiple(vec![
                IdRef {
                    id: "acl:Read".to_string(),
                },
                IdRef {
                    id: "acl:Write".to_string(),
                },
                IdRef {
                    id: "acl:Control".to_string(),
                },
            ])),
            condition: None,
        };
        let doc = make_doc(vec![auth]);
        let agent = Some("did:nostr:owner");
        assert!(evaluate_access(Some(&doc), agent, "/", AccessMode::Read));
        assert!(evaluate_access(Some(&doc), agent, "/", AccessMode::Write));
        assert!(evaluate_access(Some(&doc), agent, "/", AccessMode::Append));
        assert!(evaluate_access(Some(&doc), agent, "/", AccessMode::Control));
    }

    #[test]
    fn deserialize_acl_document() {
        let json = concat!(
            r##"{"@context":{"acl":"http://www.w3.org/ns/auth/acl#"},"##,
            r##""@graph":[{"@id":"#public","##,
            r##""acl:agentClass":{"@id":"foaf:Agent"},"##,
            r##""acl:accessTo":{"@id":"/"},"##,
            r##""acl:mode":{"@id":"acl:Read"}}]}"##,
        );
        let doc: AclDocument = serde_json::from_str(json).unwrap();
        assert!(evaluate_access(Some(&doc), None, "/", AccessMode::Read));
    }

    #[test]
    fn mode_name_returns_lowercase() {
        assert_eq!(mode_name(AccessMode::Read), "read");
        assert_eq!(mode_name(AccessMode::Write), "write");
        assert_eq!(mode_name(AccessMode::Append), "append");
        assert_eq!(mode_name(AccessMode::Control), "control");
    }

    #[test]
    fn wac_allow_public_read_only() {
        let doc = make_doc(vec![auth_read_public("/")]);
        let header = wac_allow_header(Some(&doc), None, "/");
        assert_eq!(header, "user=\"read\", public=\"read\"");
    }

    #[test]
    fn wac_allow_owner_full_public_read() {
        let public_read = auth_read_public("/");
        let owner_full = AclAuthorization {
            id: None,
            r#type: None,
            agent: Some(IdOrIds::Single(IdRef {
                id: "did:nostr:owner".to_string(),
            })),
            agent_class: None,
            agent_group: None,
            origin: None,
            access_to: Some(IdOrIds::Single(IdRef {
                id: "/".to_string(),
            })),
            default: None,
            mode: Some(IdOrIds::Multiple(vec![
                IdRef {
                    id: "acl:Read".to_string(),
                },
                IdRef {
                    id: "acl:Write".to_string(),
                },
                IdRef {
                    id: "acl:Control".to_string(),
                },
            ])),
            condition: None,
        };
        let doc = make_doc(vec![public_read, owner_full]);
        let header = wac_allow_header(Some(&doc), Some("did:nostr:owner"), "/");
        assert_eq!(
            header,
            "user=\"read write append control\", public=\"read\""
        );
    }

    #[test]
    fn wac_allow_no_acl_denies_everything() {
        let header = wac_allow_header(None, Some("did:nostr:owner"), "/");
        assert_eq!(header, "user=\"\", public=\"\"");
    }

    #[test]
    fn all_modes_contains_four_entries() {
        assert_eq!(ALL_MODES.len(), 4);
    }

    // ── ACL Control coercion (audit C3) ─────────────────────────────────

    #[test]
    fn coerce_acl_path_put_requires_control() {
        assert_eq!(
            coerce_required_mode_for_acl("/profile/card.acl", "PUT"),
            AccessMode::Control
        );
    }

    #[test]
    fn coerce_acl_path_patch_requires_control() {
        assert_eq!(
            coerce_required_mode_for_acl("/.acl", "PATCH"),
            AccessMode::Control
        );
    }

    #[test]
    fn coerce_acl_path_post_requires_control() {
        // POST normally maps to Append; on .acl it must be Control too.
        assert_eq!(
            coerce_required_mode_for_acl("/data.acl", "POST"),
            AccessMode::Control
        );
    }

    #[test]
    fn coerce_acl_path_delete_requires_control() {
        assert_eq!(
            coerce_required_mode_for_acl("/data.acl", "DELETE"),
            AccessMode::Control
        );
    }

    #[test]
    fn coerce_acl_path_get_remains_read() {
        // Reading still requires Read (handler composes with Control fallback).
        assert_eq!(
            coerce_required_mode_for_acl("/profile/card.acl", "GET"),
            AccessMode::Read
        );
    }

    #[test]
    fn coerce_non_acl_path_unchanged() {
        assert_eq!(
            coerce_required_mode_for_acl("/profile/card", "PUT"),
            AccessMode::Write
        );
        assert_eq!(
            coerce_required_mode_for_acl("/profile/card", "POST"),
            AccessMode::Append
        );
    }

    // ── ACL doc size cap ───────────────────────────────────────────────

    #[test]
    fn parse_acl_within_cap_succeeds() {
        let json = concat!(
            r##"{"@graph":[{"@id":"#root","##,
            r##""acl:agentClass":{"@id":"foaf:Agent"},"##,
            r##""acl:accessTo":{"@id":"/"},"##,
            r##""acl:mode":{"@id":"acl:Read"}}]}"##,
        );
        let doc = parse_acl_with_cap(json.as_bytes());
        assert!(doc.is_some());
    }

    #[test]
    fn parse_acl_oversized_rejected() {
        // Build a > 64 KiB "ACL document"-shaped blob.
        let pad: String = "a".repeat(MAX_ACL_DOC_BYTES + 10);
        let bytes = pad.into_bytes();
        let doc = parse_acl_with_cap(&bytes);
        assert!(
            doc.is_none(),
            "documents larger than MAX_ACL_DOC_BYTES must be rejected"
        );
    }
}
