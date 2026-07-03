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

// Pure-logic re-exports from the solid-pod-rs `wac` module. These were the
// kit's hand-rolled implementations; the upstream surface is API-shape
// compatible and battle-tested in the JSS port.
//
// `effective_acl_target` is the SHARED sidecar-elevation policy — the single
// source of truth co-owned with solid-pod-rs' native server (it internally
// consults `protected_resource_for_acl`). The forum re-exports it here so
// every WAC decision (the pod-worker's `.acl` handler AND
// `coerce_required_mode_for_acl` below) funnels through one module and cannot
// drift from upstream.
pub use solid_pod_rs::wac::{
    effective_acl_target, method_to_mode, wac_allow_header, AccessMode, AclDocument,
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

/// Coerce the required `AccessMode` for a request whose target may be an
/// `.acl` / `.meta` sidecar, delegating to the SHARED sidecar-elevation
/// policy [`effective_acl_target`] (`solid_pod_rs::wac::effective_acl_target`).
///
/// A sidecar governs another resource's authorization graph, so WAC §4.3.5
/// requires `acl:Control` on the protected resource for ANY access — read AND
/// write. `effective_acl_target` is the single source of truth for that
/// decision (co-owned with solid-pod-rs' native server), so the forum no
/// longer re-derives it: a sidecar path collapses to `Control`, and a normal
/// path passes through the standard HTTP-method mapping unchanged.
///
/// This closes BOTH the write escalation (a mere `acl:Write` holder seizing
/// `acl:Control` by overwriting a sidecar) and the read-side disclosure (P2-1
/// — an `acl:Read` holder reading the sidecar's authorization graph). Reads
/// and writes now elevate identically, matching the pod-worker's `.acl`
/// handler, which composes the same `effective_acl_target` decision.
pub fn coerce_required_mode_for_acl(path: &str, method: &str) -> AccessMode {
    let base = method_to_mode(method);
    // Delegate sidecar detection + elevation to the shared policy: for an
    // `.acl`/`.meta` path the returned mode is `Control`; otherwise `base`.
    effective_acl_target(path, base).1
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

/// Compute the ordered list of R2 sidecar keys to probe for a resource,
/// most-specific first, paired with the WAC `inherited` flag that the
/// resulting [`AclDocument`] must carry.
///
/// The previous resolver had a container-resolution gap (ADR-096): it only
/// ever probed `{path}.acl` and then derived parents from the path with the
/// trailing slash stripped, so for `/private/agent/SOUL.md` it walked
/// `…/SOUL.md.acl → /private/agent.acl → /private.acl → /.acl` and NEVER
/// probed the per-container sidecar `/private/agent/.acl`. A normal Solid
/// container ACL at `<dir>/.acl` was therefore unreachable, forcing
/// deployments to write a flat `<dir>.acl` instead.
///
/// This builder restores correct WAC semantics by probing, at every level of
/// the upward walk, BOTH forms:
///
/// 1. the resource's own flat sidecar `{path}.acl` (resolution-specific to
///    that exact resource; `inherited = false`), and
/// 2. the container sidecar `{dir}/.acl` for each enclosing directory
///    (`inherited = true`, because for an ancestor container only
///    `acl:default` rules may apply — WAC §4.2, enforced by the upstream
///    evaluator's `AclDocument::inherited` gate).
///
/// For the resource's OWN sidecar `inherited` is `false` so its
/// `acl:accessTo` rules apply directly. The flat per-resource sidecar of an
/// ANCESTOR (e.g. `/private/agent.acl` resolved for `/private/agent/SOUL.md`)
/// is treated as inherited, matching the pre-existing walk-up contract.
///
/// Precedence is strictly most-specific-wins: the first key that resolves to
/// a parseable document is returned, so a resource-specific `{path}.acl`
/// beats the container `{dir}/.acl`, which beats `{parent}/.acl`, …, which
/// beats `/.acl`. The legacy flat-sidecar form for each ancestor remains in
/// the sequence (interleaved by specificity) so existing flat deployments
/// keep resolving — both forms stay reachable.
///
/// `(key_path, inherited)` tuples are returned; callers prefix with
/// `pods/{owner_pubkey}` and parse with the size cap.
fn acl_probe_sequence(resource_path: &str) -> Vec<(String, bool)> {
    let mut probes: Vec<(String, bool)> = Vec::new();

    // Normalise: callers pass absolute pod-relative paths beginning with `/`.
    let resource = if resource_path.is_empty() {
        "/"
    } else {
        resource_path
    };

    // (1) The resource's OWN sidecar (`inherited = false`).
    //
    // For a non-container resource `/a/b/c` this is the flat `/a/b/c.acl`,
    // whose `acl:accessTo` applies directly to `/a/b/c`.
    //
    // For a container target `/a/b/` this own-sidecar IS the container
    // sidecar `/a/b/.acl`; it is non-inherited relative to the container
    // itself so `acl:accessTo: /a/b/` and its direct-child rules apply.
    //
    // Both cases are `{resource}.acl`, so a single push covers them.
    probes.push((format!("{resource}.acl"), false));

    // (2) Walk up the enclosing containers. For each ancestor directory we
    // probe the container sidecar `<dir>/.acl` (inherited) AND keep the
    // legacy flat `<dir>.acl` form (also inherited) for backward compat.
    //
    // Most-specific first: immediate parent container before grandparent.
    let mut dir = parent_dir(resource);
    loop {
        // Container sidecar `<dir>/.acl`. `dir` always ends in `/` here
        // (it is a container path, including the root "/").
        probes.push((format!("{dir}.acl"), true));

        if dir == "/" {
            break;
        }

        // Legacy flat sidecar for this ancestor: `<dir without trailing />.acl`
        // e.g. dir = "/private/agent/" -> "/private/agent.acl".
        let flat = dir.trim_end_matches('/');
        if !flat.is_empty() {
            probes.push((format!("{flat}.acl"), true));
        }

        dir = parent_dir(flat);
    }

    probes
}

/// Return the enclosing container path for a pod-relative resource path,
/// always normalised to end with a trailing `/` (so `/a/b/c` -> `/a/b/`,
/// `/a/b/` -> `/a/`, `/a` -> `/`, `/` -> `/`).
fn parent_dir(path: &str) -> String {
    if path == "/" || path.is_empty() {
        return "/".to_string();
    }
    // Strip a single trailing slash (container input) before finding the
    // last separator so `/a/b/` resolves to its parent `/a/`.
    let trimmed = path.trim_end_matches('/');
    match trimmed.rfind('/') {
        Some(0) | None => "/".to_string(),
        Some(pos) => format!("{}/", &trimmed[..pos]),
    }
}

/// Find the effective ACL for a resource by walking up the container tree.
///
/// Resolution order (most-specific first; first parseable hit wins):
/// 1. R2 sidecar walk built by [`acl_probe_sequence`], which probes BOTH the
///    resource's own flat sidecar `{path}.acl` AND every enclosing container
///    sidecar `{dir}/.acl` (the container case the legacy resolver skipped —
///    ADR-096), interleaved with the legacy flat `{dir}.acl` ancestor form.
/// 2. KV miss-fallback ONLY: the pod-level `acl:{owner_pubkey}` key, consulted
///    exclusively when the R2 walk found nothing at any level.
///
/// ## Why R2 is authoritative and KV is a fallback (delegation masking fix)
///
/// The KV `acl:{owner_pubkey}` key is a legacy whole-pod ACL keyed only by
/// owner. It is NOT a cache of the resolved R2 result: nothing writes through
/// to it on an `.acl` PUT, and the live provisioner
/// ([`crate::provision::provision_pod`]) only ever writes R2 sidecars. Probing
/// it FIRST (the previous behaviour) let a stale, owner-granular KV entry
/// UNCONDITIONALLY short-circuit and shadow every more-specific R2 sidecar —
/// including a per-container delegation grant written by
/// [`build_delegation_acl`] to `<container>/.acl` (ADR-096). A pod whose owner
/// happened to have a KV entry (e.g. legacy auth-worker provisioning) could
/// therefore never have a delegation take effect.
///
/// R2 sidecars are the single source of truth. We resolve them first, by
/// strict most-specific-wins precedence, so a delegation grant becomes
/// effective on the very next resource access. KV is consulted only as a
/// miss-fallback for pods that have no R2 sidecar at all, preserving any
/// pre-existing KV-only deployments without ever masking R2.
///
/// An ACL resolved from an ANCESTOR carries `inherited = true`, so the
/// upstream evaluator honours only its `acl:default` rules (WAC §4.2). The
/// resource's own sidecar carries `inherited = false`. The KV fallback ACL is
/// a pod-level (root) document and is treated as non-inherited (its rules name
/// the pod root via `acl:accessTo`/`acl:default`).
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
    // (1) R2 sidecar walk — AUTHORITATIVE. Own sidecar, then each enclosing
    // container sidecar, most-specific first. The first parseable hit wins, so
    // a per-container delegation grant at `<container>/.acl` is honoured before
    // any broader (pod-level) ACL can apply.
    for (probe_path, inherited) in acl_probe_sequence(resource_path) {
        let acl_key = format!("pods/{owner_pubkey}{probe_path}");
        if let Ok(Some(obj)) = bucket.get(&acl_key).execute().await {
            if let Some(body) = obj.body() {
                if let Ok(bytes) = body.bytes().await {
                    if let Some(doc) = resolve_r2_sidecar(&bytes, inherited) {
                        return Some(doc);
                    }
                }
            }
        }
    }

    // (2) KV miss-fallback ONLY: a legacy pod-level ACL. Reached solely when
    // the R2 walk resolved nothing, so it can never shadow a more-specific R2
    // sidecar (and therefore can never mask a delegation grant).
    let kv_key = format!("acl:{owner_pubkey}");
    if let Ok(Some(text)) = kv.get(&kv_key).text().await {
        if let Some(doc) = resolve_kv_fallback(&text) {
            return Some(doc);
        }
    }

    None
}

/// Parse an R2 sidecar's bytes into an [`AclDocument`], stamping the
/// `inherited` flag the [`acl_probe_sequence`] entry carried. Returns `None`
/// if the bytes are missing, oversized, or unparseable (so the walk falls
/// through to the next, broader probe).
///
/// Split out from [`find_effective_acl`] so the runtime-agnostic resolution
/// ordering (R2-authoritative, KV-fallback) is unit-testable without the
/// worker R2/KV runtime types — see [`resolve_effective_acl`].
fn resolve_r2_sidecar(bytes: &[u8], inherited: bool) -> Option<AclDocument> {
    let mut doc = parse_acl_with_cap(bytes)?;
    // Mark inherited resolution so the evaluator applies only `acl:default`
    // rules for ancestor containers.
    doc.inherited = inherited;
    Some(doc)
}

/// Parse the legacy KV pod-level ACL text into an [`AclDocument`]. The KV ACL
/// names the pod root directly, so it is non-inherited (the default).
fn resolve_kv_fallback(text: &str) -> Option<AclDocument> {
    parse_acl_text_with_cap(text)
}

/// Pure, runtime-agnostic core of [`find_effective_acl`]: given an ordered
/// most-specific-first list of R2 sidecar candidates `(bytes, inherited)` and
/// an optional legacy KV pod-level ACL `text`, return the effective ACL using
/// the EXACT precedence the live resolver uses — R2 is authoritative, KV is a
/// miss-fallback consulted only when no R2 sidecar resolves.
///
/// This is the load-bearing ordering that fixes the pod-delegation masking
/// bug (a stale KV `acl:{owner}` entry must never shadow a more-specific R2
/// delegation sidecar). [`find_effective_acl`] is a thin async I/O loop that
/// feeds R2/KV reads into exactly this decision.
fn resolve_effective_acl<'a>(
    r2_candidates: impl IntoIterator<Item = (&'a [u8], bool)>,
    kv_text: Option<&str>,
) -> Option<AclDocument> {
    for (bytes, inherited) in r2_candidates {
        if let Some(doc) = resolve_r2_sidecar(bytes, inherited) {
            return Some(doc);
        }
    }
    kv_text.and_then(resolve_kv_fallback)
}

// ---------------------------------------------------------------------------
// Kit-specific: delegation ACL builder (ADR-096)
// ---------------------------------------------------------------------------

/// Build the canonical merged ACL JSON-LD document granting `agent_did`
/// the requested `modes` on `container_path`, while PRESERVING the owner's
/// full `acl:Control` over the same container.
///
/// This is the pure core of the per-container delegation operation
/// (ADR-096): an `acl:Control` holder can grant another `did:nostr` agent
/// Read/Write on one of their containers without hand-authoring JSON-LD.
/// The worker's authed `PUT /<container>/.acl` route serialises a structured
/// grant `{container, agent_did, modes}` through this function and stores the
/// result at the container sidecar `pods/<owner>/<container>/.acl`.
///
/// Invariants:
/// - The emitted `@graph` ALWAYS contains an owner authorisation granting
///   `acl:Read acl:Write acl:Control` on `container_path` via BOTH
///   `acl:accessTo` (the container itself) and `acl:default` (its
///   descendants). This is what stops an owner from locking themselves out:
///   no delegation can overwrite or omit the owner's Control.
/// - The delegate authorisation grants exactly the requested `modes` (deduped,
///   `acl:Control` stripped — a delegation never confers Control; that would
///   let the delegate re-delegate or seize the container) on `container_path`
///   via `acl:accessTo` + `acl:default`.
/// - `owner_did` and `agent_did` are written verbatim as `did:nostr:<hex>`
///   `@id` values; callers validate the DID shape upstream.
///
/// Returns the [`AclDocument`] AST; callers serialise via `serde_json` to the
/// canonical wire shape and round-trip cleanly through this crate's parser.
pub fn build_delegation_acl(
    owner_did: &str,
    agent_did: &str,
    container_path: &str,
    modes: &[AccessMode],
) -> AclDocument {
    use solid_pod_rs::wac::{AclAuthorization, IdOrIds, IdRef};

    // Normalise the container path to a leading-slash form. We keep the
    // trailing slash if present so `acl:accessTo` names the container itself.
    let path = if container_path.is_empty() {
        "/".to_string()
    } else {
        container_path.to_string()
    };

    let id_ref = |s: &str| IdRef { id: s.to_string() };
    let single = |s: &str| Some(IdOrIds::Single(id_ref(s)));

    // Helper: build `acl:mode` value from a mode slice, deduped, in canonical
    // order (Read, Write, Append, Control). Returns `None` for an empty set.
    fn modes_value(modes: &[AccessMode]) -> Option<IdOrIds> {
        use solid_pod_rs::wac::{IdOrIds, IdRef};
        let order = [
            (AccessMode::Read, "acl:Read"),
            (AccessMode::Write, "acl:Write"),
            (AccessMode::Append, "acl:Append"),
            (AccessMode::Control, "acl:Control"),
        ];
        let mut refs: Vec<IdRef> = Vec::new();
        for (m, iri) in order {
            if modes.contains(&m) {
                refs.push(IdRef {
                    id: iri.to_string(),
                });
            }
        }
        match refs.len() {
            0 => None,
            1 => Some(IdOrIds::Single(refs.into_iter().next().unwrap())),
            _ => Some(IdOrIds::Multiple(refs)),
        }
    }

    // Owner authorisation: ALWAYS full control on the container + descendants.
    let owner_auth = AclAuthorization {
        id: Some("#owner".to_string()),
        r#type: Some("acl:Authorization".to_string()),
        agent: single(owner_did),
        agent_class: None,
        agent_group: None,
        origin: None,
        access_to: single(&path),
        default: single(&path),
        mode: modes_value(&[AccessMode::Read, AccessMode::Write, AccessMode::Control]),
        condition: None,
    };

    // Delegate authorisation: requested modes MINUS Control (never delegate
    // Control — that would let the grantee re-delegate or seize the container).
    let delegate_modes: Vec<AccessMode> = modes
        .iter()
        .copied()
        .filter(|m| *m != AccessMode::Control)
        .collect();

    let mut graph = vec![owner_auth];

    if let Some(mode_val) = modes_value(&delegate_modes) {
        graph.push(AclAuthorization {
            id: Some("#delegate".to_string()),
            r#type: Some("acl:Authorization".to_string()),
            agent: single(agent_did),
            agent_class: None,
            agent_group: None,
            origin: None,
            access_to: single(&path),
            default: single(&path),
            mode: Some(mode_val),
            condition: None,
        });
    }

    AclDocument {
        context: Some(serde_json::json!({
            "acl": "http://www.w3.org/ns/auth/acl#"
        })),
        graph: Some(graph),
        inherited: false,
    }
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
    use solid_pod_rs::wac::{mode_name, AclAuthorization, IdOrIds, IdRef};

    fn make_doc(graph: Vec<AclAuthorization>) -> AclDocument {
        AclDocument {
            context: None,
            graph: Some(graph),
            ..Default::default()
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
            ..Default::default()
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
    fn coerce_acl_path_get_requires_control() {
        // P2-1: reading an `.acl` sidecar now elevates to Control under the
        // shared policy — a mere `acl:Read` holder must not read the
        // authorization graph. (Was `Read` under the drifted local copy that
        // relied on a separate handler-level Control check.)
        assert_eq!(
            coerce_required_mode_for_acl("/profile/card.acl", "GET"),
            AccessMode::Control
        );
        assert_eq!(
            coerce_required_mode_for_acl("/profile/card.acl", "HEAD"),
            AccessMode::Control
        );
    }

    #[test]
    fn coerce_meta_sidecar_also_elevates() {
        // The shared policy governs `.meta` sidecars identically to `.acl`.
        assert_eq!(
            coerce_required_mode_for_acl("/data.meta", "GET"),
            AccessMode::Control
        );
        assert_eq!(
            coerce_required_mode_for_acl("/data.meta", "PUT"),
            AccessMode::Control
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

    // ── P2-1: `.acl` read requires Control, never mere Read (info-disclosure) ──
    //
    // `handle_acl_request`'s GET/HEAD branch needs the worker R2/KV runtime
    // and is not unit-testable natively. Its load-bearing decision is the
    // SHARED sidecar-elevation policy: a GET on an `.acl`/`.meta` path runs the
    // WAC check as `acl:Control` on the PROTECTED resource — never `acl:Read`
    // on the sidecar. This test drives that exact decision through
    // `effective_acl_target` + `evaluate_access`, the two functions the
    // handler composes, on a PUBLIC-READABLE container.

    #[test]
    fn read_only_agent_denied_get_acl_on_public_container() {
        // A public-readable container: foaf:Agent may Read `/public/`.
        let container_acl = make_doc(vec![auth_read_public("/public/")]);
        let read_agent = Some("did:nostr:reader");

        // The requested sidecar path and the shared elevation decision.
        let (protected, required) = effective_acl_target("/public/.acl", AccessMode::Read);
        assert_eq!(protected, "/public/");
        assert_eq!(
            required,
            AccessMode::Control,
            "reading an .acl must elevate to acl:Control on the protected resource"
        );

        // P2-1 FIX: the read-only agent is DENIED the sidecar — a public-read
        // ACL confers no Control.
        assert!(
            !evaluate_access(Some(&container_acl), read_agent, &protected, required),
            "a non-Control agent must be DENIED GET /public/.acl even though /public/ is public-readable"
        );
        // Anonymous is likewise denied.
        assert!(!evaluate_access(Some(&container_acl), None, &protected, required));

        // Regression guard: prove the container really IS public-readable, so
        // the deny above is the P2-1 fix and not an artefact of an empty ACL.
        // Under the OLD `Read || Control` shortcut both of these Read grants
        // would have leaked the sidecar to the reader and to anonymous.
        assert!(
            evaluate_access(Some(&container_acl), read_agent, "/public/", AccessMode::Read),
            "container must be public-readable, else the P2-1 scenario is vacuous"
        );
        assert!(evaluate_access(Some(&container_acl), None, "/public/", AccessMode::Read));
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

    // ── ACL container resolution gap (ADR-096) ─────────────────────────
    //
    // `find_effective_acl` itself needs R2 + KV (worker runtime types) and
    // is therefore not unit-testable on the native target. These tests
    // exercise the PURE probe-sequence builder that is the load-bearing
    // change — `find_effective_acl` is a thin loop over its output that
    // returns the first parseable hit, so probe order == resolution order.

    /// Convenience: collect just the probe key paths in order.
    fn probe_keys(resource: &str) -> Vec<String> {
        acl_probe_sequence(resource)
            .into_iter()
            .map(|(k, _)| k)
            .collect()
    }

    #[test]
    fn container_sidecar_is_probed_for_direct_child() {
        // BUG REPRO (now fixed): `/private/agent/SOUL.md` must probe the
        // per-container sidecar `/private/agent/.acl`, which the legacy
        // resolver NEVER reached.
        let keys = probe_keys("/private/agent/SOUL.md");
        assert!(
            keys.contains(&"/private/agent/.acl".to_string()),
            "container sidecar /private/agent/.acl must be probed; got {keys:?}"
        );
        // Root container sidecar is the final fallback.
        assert!(keys.contains(&"/.acl".to_string()));
    }

    #[test]
    fn container_sidecar_is_probed_for_deeper_descendant() {
        // The previously-broken case: a deeper resource `/dir/sub/file`
        // must still reach BOTH `/dir/sub/.acl` and `/dir/.acl`.
        let keys = probe_keys("/dir/sub/file");
        assert!(
            keys.contains(&"/dir/sub/.acl".to_string()),
            "immediate container /dir/sub/.acl must be probed; got {keys:?}"
        );
        assert!(
            keys.contains(&"/dir/.acl".to_string()),
            "ancestor container /dir/.acl must be probed; got {keys:?}"
        );
        assert!(keys.contains(&"/.acl".to_string()));
    }

    #[test]
    fn own_flat_sidecar_still_reachable() {
        // The flat-sidecar form must remain reachable (do not break the
        // deployment workaround during migration).
        let keys = probe_keys("/dir/file");
        // Own flat sidecar, most specific.
        assert_eq!(keys.first().map(String::as_str), Some("/dir/file.acl"));
        // Ancestor legacy flat form preserved.
        assert!(
            keys.contains(&"/dir.acl".to_string()),
            "legacy flat ancestor /dir.acl must remain reachable; got {keys:?}"
        );
    }

    #[test]
    fn most_specific_precedence_ordering() {
        // (b) Precedence: `/dir/file.acl` (own) precedes `/dir/.acl`
        // (container) precedes `/.acl` (root). First parseable hit wins,
        // so position in this vec == resolution precedence.
        let keys = probe_keys("/dir/file");
        let pos = |needle: &str| keys.iter().position(|k| k == needle);
        let own = pos("/dir/file.acl").expect("own sidecar present");
        let container = pos("/dir/.acl").expect("container sidecar present");
        let root = pos("/.acl").expect("root sidecar present");
        assert!(
            own < container,
            "own /dir/file.acl must precede container /dir/.acl ({own} !< {container}); {keys:?}"
        );
        assert!(
            container < root,
            "container /dir/.acl must precede root /.acl ({container} !< {root}); {keys:?}"
        );
    }

    #[test]
    fn own_sidecar_is_not_inherited_ancestors_are() {
        // The resource's own sidecar applies `acl:accessTo` directly
        // (inherited = false); every ancestor sidecar applies only
        // `acl:default` (inherited = true) per WAC §4.2.
        let seq = acl_probe_sequence("/private/agent/SOUL.md");
        let (own_key, own_inherited) = &seq[0];
        assert_eq!(own_key, "/private/agent/SOUL.md.acl");
        assert!(!own_inherited, "own sidecar must NOT be inherited");
        for (key, inherited) in &seq[1..] {
            assert!(
                *inherited,
                "ancestor sidecar {key} must be marked inherited"
            );
        }
    }

    #[test]
    fn root_resource_probes_root_sidecar() {
        let keys = probe_keys("/");
        // Own sidecar of the root container IS `/.acl`.
        assert_eq!(keys.first().map(String::as_str), Some("/.acl"));
    }

    #[test]
    fn container_target_probes_its_own_and_parent_sidecars() {
        // A container target `/private/agent/` probes its own `/private/agent/.acl`
        // (non-inherited) then ancestors.
        let seq = acl_probe_sequence("/private/agent/");
        assert_eq!(seq[0], ("/private/agent/.acl".to_string(), false));
        let keys: Vec<String> = seq.into_iter().map(|(k, _)| k).collect();
        assert!(keys.contains(&"/private/.acl".to_string()));
        assert!(keys.contains(&"/.acl".to_string()));
    }

    // ── Delegation builder (ADR-096) ───────────────────────────────────

    const OWNER: &str =
        "did:nostr:0000000000000000000000000000000000000000000000000000000000000001";
    const DELEGATE: &str =
        "did:nostr:0000000000000000000000000000000000000000000000000000000000000002";

    #[test]
    fn build_delegation_grants_owner_control_and_agent_read() {
        // (c) builder emits owner-Control + agent-Read and round-trips
        // through the AclDocument parser.
        let doc = build_delegation_acl(OWNER, DELEGATE, "/private/agent/", &[AccessMode::Read]);

        // Owner retains full Control on the container + descendants.
        assert!(evaluate_access(
            Some(&doc),
            Some(OWNER),
            "/private/agent/",
            AccessMode::Control
        ));
        assert!(evaluate_access(
            Some(&doc),
            Some(OWNER),
            "/private/agent/",
            AccessMode::Write
        ));
        // Delegate has Read on the container...
        assert!(evaluate_access(
            Some(&doc),
            Some(DELEGATE),
            "/private/agent/",
            AccessMode::Read
        ));
        // ...and on descendants (acl:default), but NOT Write or Control.
        assert!(evaluate_access(
            Some(&doc),
            Some(DELEGATE),
            "/private/agent/SOUL.md",
            AccessMode::Read
        ));
        assert!(!evaluate_access(
            Some(&doc),
            Some(DELEGATE),
            "/private/agent/",
            AccessMode::Write
        ));
        assert!(!evaluate_access(
            Some(&doc),
            Some(DELEGATE),
            "/private/agent/",
            AccessMode::Control
        ));

        // Round-trip: serialise to canonical wire JSON-LD and reparse.
        let wire = serde_json::to_string(&doc).expect("serialises");
        let reparsed = parse_acl_text_with_cap(&wire).expect("round-trips through parser");
        assert!(evaluate_access(
            Some(&reparsed),
            Some(OWNER),
            "/private/agent/",
            AccessMode::Control
        ));
        assert!(evaluate_access(
            Some(&reparsed),
            Some(DELEGATE),
            "/private/agent/",
            AccessMode::Read
        ));
    }

    #[test]
    fn build_delegation_grants_write_includes_append() {
        let doc = build_delegation_acl(OWNER, DELEGATE, "/shared/", &[AccessMode::Write]);
        assert!(evaluate_access(
            Some(&doc),
            Some(DELEGATE),
            "/shared/",
            AccessMode::Write
        ));
        // Upstream maps Write -> {Write, Append}, so Append follows.
        assert!(evaluate_access(
            Some(&doc),
            Some(DELEGATE),
            "/shared/",
            AccessMode::Append
        ));
        assert!(!evaluate_access(
            Some(&doc),
            Some(DELEGATE),
            "/shared/",
            AccessMode::Control
        ));
    }

    #[test]
    fn build_delegation_never_grants_control_to_delegate() {
        // (d) Even if a caller asks for Control, the delegate must NOT get
        // it — only the owner holds Control. This is the lock-out guard.
        let doc = build_delegation_acl(
            OWNER,
            DELEGATE,
            "/private/",
            &[AccessMode::Read, AccessMode::Write, AccessMode::Control],
        );
        // Delegate gets Read + Write but Control is stripped.
        assert!(evaluate_access(
            Some(&doc),
            Some(DELEGATE),
            "/private/",
            AccessMode::Read
        ));
        assert!(evaluate_access(
            Some(&doc),
            Some(DELEGATE),
            "/private/",
            AccessMode::Write
        ));
        assert!(
            !evaluate_access(Some(&doc), Some(DELEGATE), "/private/", AccessMode::Control),
            "a delegation must never confer acl:Control on the grantee"
        );
        // Owner Control is intact.
        assert!(evaluate_access(
            Some(&doc),
            Some(OWNER),
            "/private/",
            AccessMode::Control
        ));
    }

    #[test]
    fn build_delegation_owner_control_survives_empty_modes() {
        // A no-op delegation (empty modes) still emits the owner's Control
        // grant — the owner can never be locked out by an empty grant.
        let doc = build_delegation_acl(OWNER, DELEGATE, "/x/", &[]);
        assert!(evaluate_access(
            Some(&doc),
            Some(OWNER),
            "/x/",
            AccessMode::Control
        ));
        // No delegate authorisation emitted, so the delegate has nothing.
        assert!(!evaluate_access(
            Some(&doc),
            Some(DELEGATE),
            "/x/",
            AccessMode::Read
        ));
        // Exactly one authorisation (owner only) in the graph.
        assert_eq!(doc.graph.as_ref().map(Vec::len), Some(1));
    }

    // ── Pod-delegation masking (audit O3 / pod-cartography F-1) ─────────
    //
    // `find_effective_acl` needs the worker R2/KV runtime types and is not
    // unit-testable natively. Its load-bearing logic is the resolution
    // ORDERING — R2 sidecars are authoritative, the legacy KV `acl:{owner}`
    // pod-level entry is a miss-fallback only. `resolve_effective_acl` is the
    // pure core that `find_effective_acl` feeds R2/KV reads into; these tests
    // drive it with the SAME `acl_probe_sequence` order the live resolver
    // uses, modelling a provisioned pod (KV owner ACL set) plus a delegation
    // grant written to the container `.acl`.

    /// The exact legacy pod-level ACL the (now-dead) auth-worker
    /// `pod::provision_pod` writes to KV `acl:{owner}`: owner-only Control on
    /// the pod root, public read on profile/media. Crucially it contains NO
    /// delegate authorisation — so if it shadows R2, the delegate is denied.
    fn legacy_kv_owner_acl() -> String {
        format!(
            concat!(
                r##"{{"@context":{{"acl":"http://www.w3.org/ns/auth/acl#","##,
                r##""foaf":"http://xmlns.com/foaf/0.1/"}},"##,
                r##""@graph":[{{"@id":"#owner","@type":"acl:Authorization","##,
                r##""acl:agent":{{"@id":"{owner}"}},"##,
                r##""acl:accessTo":{{"@id":"/"}},"acl:default":{{"@id":"/"}},"##,
                r##""acl:mode":[{{"@id":"acl:Read"}},{{"@id":"acl:Write"}},"##,
                r##"{{"@id":"acl:Control"}}]}}]}}"##,
            ),
            owner = OWNER,
        )
    }

    /// Build the R2 candidate list for `resource_path` exactly as the live
    /// resolver does — `acl_probe_sequence` order — pulling each sidecar's
    /// bytes from a `(probe_key -> json)` store. `probe_key` is the
    /// pod-relative `.acl` path (the second tuple field of the sequence is the
    /// `inherited` flag).
    fn r2_candidates_for<'a>(
        resource_path: &str,
        store: &'a std::collections::HashMap<String, Vec<u8>>,
    ) -> Vec<(&'a [u8], bool)> {
        acl_probe_sequence(resource_path)
            .into_iter()
            .filter_map(|(key, inherited)| {
                store.get(&key).map(|bytes| (bytes.as_slice(), inherited))
            })
            .collect()
    }

    #[test]
    fn delegation_grant_is_not_masked_by_legacy_kv_owner_acl() {
        // Scenario: a pod was provisioned via the path that sets the KV
        // `acl:{owner}` entry (legacy auth-worker provisioning). The owner
        // then delegates Write on `/private/agent/` to DELEGATE by PUTting
        // the structured grant — the worker serialises it via
        // `build_delegation_acl` and stores it at the CONTAINER sidecar
        // `pods/{owner}/private/agent/.acl`.
        let kv_owner_acl = legacy_kv_owner_acl();

        let delegation =
            build_delegation_acl(OWNER, DELEGATE, "/private/agent/", &[AccessMode::Write]);
        let delegation_bytes = serde_json::to_vec(&delegation).expect("delegation serialises");

        let mut r2: std::collections::HashMap<String, Vec<u8>> = std::collections::HashMap::new();
        // The PUT route stores the grant at the container sidecar; in
        // pod-relative probe-key terms that is `/private/agent/.acl`.
        r2.insert("/private/agent/.acl".to_string(), delegation_bytes);

        // Resolve the effective ACL for a resource INSIDE the delegated
        // container, through the real probe order + resolution precedence.
        let resource = "/private/agent/SOUL.md";
        let candidates = r2_candidates_for(resource, &r2);
        let effective = resolve_effective_acl(candidates, Some(&kv_owner_acl))
            .expect("an ACL must resolve (R2 sidecar present)");

        // THE FIX: the R2 delegation sidecar wins; the KV owner-only ACL did
        // NOT short-circuit and mask it. The delegate now has Write...
        assert!(
            evaluate_access(
                Some(&effective),
                Some(DELEGATE),
                resource,
                AccessMode::Write
            ),
            "delegate must resolve Write — KV owner ACL must not mask the R2 delegation grant"
        );
        // ...and Append (Write implies Append upstream)...
        assert!(evaluate_access(
            Some(&effective),
            Some(DELEGATE),
            resource,
            AccessMode::Append
        ));
        // ...but never Control (delegation never confers Control).
        assert!(!evaluate_access(
            Some(&effective),
            Some(DELEGATE),
            resource,
            AccessMode::Control
        ));
        // The owner's Control survives in the delegation doc.
        assert!(evaluate_access(
            Some(&effective),
            Some(OWNER),
            resource,
            AccessMode::Control
        ));
    }

    #[test]
    fn masking_repro_kv_first_would_have_denied_delegate() {
        // Guard against regressing to the old "KV first" ordering. Under the
        // buggy order the legacy KV owner-only ACL (no delegate authorisation)
        // would have been returned and the delegate denied Write. Assert that
        // the KV doc, on its own, indeed lacks the grant — so the ONLY reason
        // the previous test passes is the R2-first precedence.
        let kv_owner_acl = legacy_kv_owner_acl();
        let kv_doc = resolve_kv_fallback(&kv_owner_acl).expect("KV ACL parses");
        assert!(
            !evaluate_access(
                Some(&kv_doc),
                Some(DELEGATE),
                "/private/agent/SOUL.md",
                AccessMode::Write
            ),
            "legacy KV owner ACL grants the delegate nothing — proving it WOULD mask the grant if probed first"
        );
        // And it keeps owner Control, confirming it is a real owner ACL.
        assert!(evaluate_access(
            Some(&kv_doc),
            Some(OWNER),
            "/private/agent/SOUL.md",
            AccessMode::Control
        ));
    }

    #[test]
    fn kv_fallback_still_serves_when_no_r2_sidecar() {
        // Single-source-of-truth must not break pre-existing KV-only pods:
        // with NO R2 sidecar at any level, the KV owner ACL is the fallback.
        let kv_owner_acl = legacy_kv_owner_acl();
        let empty_r2: std::collections::HashMap<String, Vec<u8>> = std::collections::HashMap::new();
        let candidates = r2_candidates_for("/private/agent/SOUL.md", &empty_r2);
        assert!(candidates.is_empty(), "no R2 sidecars in this scenario");

        let effective = resolve_effective_acl(candidates, Some(&kv_owner_acl))
            .expect("KV fallback resolves when R2 is empty");
        // Owner retains Control via the fallback.
        assert!(evaluate_access(
            Some(&effective),
            Some(OWNER),
            "/private/agent/SOUL.md",
            AccessMode::Control
        ));
    }

    #[test]
    fn no_r2_no_kv_denies_all() {
        let empty_r2: std::collections::HashMap<String, Vec<u8>> = std::collections::HashMap::new();
        let candidates = r2_candidates_for("/foo", &empty_r2);
        assert!(resolve_effective_acl(candidates, None).is_none());
    }
}
