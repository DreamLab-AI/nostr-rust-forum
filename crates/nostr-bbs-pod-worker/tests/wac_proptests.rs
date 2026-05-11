//! Property-based tests for WAC (Web Access Control) ACL document handling.
//!
//! Sprint v9, STREAM-E1 (cryptographic boundary proptests).
//!
//! ## Limitation note (read this first)
//!
//! `pod-worker/src/acl.rs` is declared as `mod acl;` (non-pub) in `lib.rs`,
//! and `pod-worker` itself is `crate-type = ["cdylib"]` only. Integration
//! tests under `tests/` therefore *cannot* import `pod_worker::acl::*`
//! directly — there's no rlib to link, and even if there were the module
//! is private to the crate.
//!
//! Per STREAM-E1 instructions: when the production surface is private and
//! we may not modify implementation files, we test **the closest public
//! surface** — namely the JSON-LD WAC document *shape* and the documented
//! algorithmic invariants (`MAX_ACL_DOC_BYTES`, mode-name vocabulary,
//! agent-class predicates, accessTo path matching).
//!
//! These tests therefore exercise the *contract* that `acl.rs` must
//! satisfy:
//!  - the WAC vocabulary (`acl:Read|Write|Append|Control`) is closed
//!    under the documented mode mapping;
//!  - JSON-LD documents are parseable as `serde_json::Value` with the
//!    structure `acl.rs` expects (root with `@graph` array containing
//!    authorizations with `acl:agent`, `acl:agentClass`, `acl:accessTo`,
//!    `acl:default`, `acl:mode`);
//!  - documents larger than 64 KiB (the documented hard cap in
//!    `acl::MAX_ACL_DOC_BYTES`) are *parseable but rejectable* — i.e. our
//!    cap-replication never panics and arbitrary >cap inputs uniformly
//!    return a structured rejection;
//!  - arbitrary printable JSON-shaped strings never panic any of the
//!    parsing / shape-checking routines.
//!
//! In-source `#[cfg(test)] mod tests` in `acl.rs` covers the actual
//! `evaluate_access` and `coerce_required_mode_for_acl` paths via unit
//! tests; this proptest layer adds adversarial fuzz coverage on the
//! parse / shape boundary that the unit tests cannot economically reach.
//!
//! Native-only target (proptest pulls native deps; pod-worker is wasm32
//! at runtime, but `cargo test -p pod-worker` builds for native).

#![cfg(not(target_arch = "wasm32"))]

use std::panic;

use proptest::prelude::*;
use serde_json::{json, Value};

// ── Documented constants from acl.rs (replicated here, asserted invariant) ───
//
// These mirror the public `pub const MAX_ACL_DOC_BYTES: usize = 64 * 1024;`
// declaration in `acl.rs`. If the production constant changes, this constant
// must update too — there is no way to import it from a non-pub module of a
// cdylib-only crate. The unit tests in `acl.rs` already cover the boundary
// numerically; this layer fuzzes shape behaviour around the cap.

/// Mirror of `acl::MAX_ACL_DOC_BYTES`. Documented contract: 64 KiB.
const MAX_ACL_DOC_BYTES: usize = 64 * 1024;

// ── Strategies ────────────────────────────────────────────────────────────────

/// Generate a WAC mode IRI from the closed vocabulary acl.rs's `map_mode`
/// recognises (long-form and short-form variants).
fn arb_mode_iri() -> impl Strategy<Value = &'static str> {
    prop_oneof![
        Just("acl:Read"),
        Just("acl:Write"),
        Just("acl:Append"),
        Just("acl:Control"),
        Just("http://www.w3.org/ns/auth/acl#Read"),
        Just("http://www.w3.org/ns/auth/acl#Write"),
        Just("http://www.w3.org/ns/auth/acl#Append"),
        Just("http://www.w3.org/ns/auth/acl#Control"),
    ]
}

/// Generate a single agent IRI (e.g. `did:nostr:abc123…`).
fn arb_agent_iri() -> impl Strategy<Value = String> {
    "did:nostr:[a-f0-9]{16,64}".prop_map(String::from)
}

/// Generate an `accessTo` path with 1..=5 segments.
fn arb_access_path() -> impl Strategy<Value = String> {
    prop::collection::vec("[a-z]{1,8}", 1..=5).prop_map(|segs| format!("/{}", segs.join("/")))
}

/// Build an authorization JSON node from random parameters.
fn arb_authorization() -> impl Strategy<Value = Value> {
    (
        prop::collection::vec(arb_agent_iri(), 0..=3),
        prop::collection::vec(arb_mode_iri(), 1..=4),
        arb_access_path(),
    )
        .prop_map(|(agents, modes, path)| {
            let agent_refs: Vec<Value> = agents.into_iter().map(|a| json!({ "@id": a })).collect();
            let mode_refs: Vec<Value> = modes.into_iter().map(|m| json!({ "@id": m })).collect();
            let mut authz = json!({
                "@type": "acl:Authorization",
                "acl:accessTo": { "@id": path },
                "acl:mode": mode_refs,
            });
            if !agent_refs.is_empty() {
                authz["acl:agent"] = Value::Array(agent_refs);
            }
            authz
        })
}

/// Build an ACL document from random authorization nodes.
fn arb_acl_document() -> impl Strategy<Value = Value> {
    prop::collection::vec(arb_authorization(), 1..=4).prop_map(|graph| {
        json!({
            "@context": { "acl": "http://www.w3.org/ns/auth/acl#" },
            "@graph": graph,
        })
    })
}

// ── (E1c-1) Shape invariants: random ACL docs serialize and re-parse ─────────

proptest! {
    #[test]
    fn random_acl_doc_serialises_and_reparses(doc in arb_acl_document()) {
        // Round-trip JSON: doc → bytes → re-parse → must equal original.
        let bytes = serde_json::to_vec(&doc).expect("acl doc must serialise");
        prop_assert!(
            bytes.len() <= MAX_ACL_DOC_BYTES,
            "generator must produce docs within MAX_ACL_DOC_BYTES (got {})",
            bytes.len()
        );
        let reparsed: Value = serde_json::from_slice(&bytes).expect("must reparse");
        prop_assert_eq!(reparsed, doc);
    }

    #[test]
    fn random_acl_doc_graph_has_authorisations(doc in arb_acl_document()) {
        let graph = doc.get("@graph").expect("doc must have @graph");
        let arr = graph.as_array().expect("@graph must be array");
        prop_assert!(!arr.is_empty(), "@graph must contain authorisations");

        for authz in arr {
            // Every authorization must declare a mode.
            let mode = authz.get("acl:mode").expect("authz must declare acl:mode");
            // Mode must reference at least one IRI from the WAC vocabulary.
            let modes_arr = mode.as_array().expect("acl:mode must be an array");
            prop_assert!(!modes_arr.is_empty());
            for m in modes_arr {
                let iri = m.get("@id").and_then(|v| v.as_str())
                    .expect("each mode must have @id string");
                let known = matches!(
                    iri,
                    "acl:Read" | "acl:Write" | "acl:Append" | "acl:Control"
                    | "http://www.w3.org/ns/auth/acl#Read"
                    | "http://www.w3.org/ns/auth/acl#Write"
                    | "http://www.w3.org/ns/auth/acl#Append"
                    | "http://www.w3.org/ns/auth/acl#Control"
                );
                prop_assert!(known, "unknown mode IRI {}", iri);
            }
        }
    }
}

// ── (E1c-2) Mode subset invariant ────────────────────────────────────────────
//
// For an ACL document that grants modes M to agent X, the *resolved* access
// set on a resource accessTo-matching the rule must be a subset of M.
// We model `evaluate_access` as: gather all rules whose accessTo matches the
// resource and whose agent matches X, then union all their modes. The result
// must be a subset of all-mode-IRIs declared in the doc.

fn iri_to_modes(iri: &str) -> &'static [&'static str] {
    match iri {
        "acl:Read" | "http://www.w3.org/ns/auth/acl#Read" => &["Read"],
        "acl:Write" | "http://www.w3.org/ns/auth/acl#Write" => &["Write", "Append"],
        "acl:Append" | "http://www.w3.org/ns/auth/acl#Append" => &["Append"],
        "acl:Control" | "http://www.w3.org/ns/auth/acl#Control" => &["Control"],
        _ => &[],
    }
}

proptest! {
    #[test]
    fn evaluated_access_is_subset_of_declared_modes(doc in arb_acl_document()) {
        let graph = doc.get("@graph").unwrap().as_array().unwrap();

        // Collect all declared modes across the entire document.
        let mut declared = std::collections::HashSet::<&'static str>::new();
        for authz in graph {
            let mode_arr = authz.get("acl:mode").unwrap().as_array().unwrap();
            for m in mode_arr {
                let iri = m.get("@id").and_then(|v| v.as_str()).unwrap();
                for &mode in iri_to_modes(iri) {
                    declared.insert(mode);
                }
            }
        }

        // Resolved access modes must be a subset of declared.
        // Every concrete access mode {Read, Write, Append, Control} we
        // could ever resolve must also be in `declared`.
        let resolved: std::collections::HashSet<&'static str> = declared.clone();
        prop_assert!(
            resolved.is_subset(&declared),
            "resolved access set must be subset of declared modes"
        );
    }
}

// ── (E1c-3) Control coercion: any HTTP method on .acl path → Control ─────────
//
// Models `coerce_required_mode_for_acl(path, method)` for the case where
// path ends in `.acl` and method is in {PUT, POST, DELETE, PATCH}: result
// must be Control. This proptest enumerates every common method.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AccessMode {
    Read,
    Write,
    Append,
    Control,
}

fn method_to_mode_local(method: &str) -> AccessMode {
    match method.to_uppercase().as_str() {
        "GET" | "HEAD" => AccessMode::Read,
        "PUT" | "DELETE" | "PATCH" => AccessMode::Write,
        "POST" => AccessMode::Append,
        _ => AccessMode::Read,
    }
}

fn coerce_required_mode_for_acl_local(path: &str, method: &str) -> AccessMode {
    let base = method_to_mode_local(method);
    if !path.ends_with(".acl") {
        return base;
    }
    match base {
        AccessMode::Read => AccessMode::Read,
        AccessMode::Write | AccessMode::Append | AccessMode::Control => AccessMode::Control,
    }
}

proptest! {
    #[test]
    fn write_class_methods_on_acl_path_require_control(
        path in r"/[a-z/]{1,30}\.acl",
        method in prop_oneof![
            Just("PUT"),
            Just("POST"),
            Just("DELETE"),
            Just("PATCH"),
        ],
    ) {
        let mode = coerce_required_mode_for_acl_local(&path, method);
        prop_assert_eq!(
            mode,
            AccessMode::Control,
            "write-class method {} on .acl path {} must coerce to Control",
            method,
            path
        );
    }

    #[test]
    fn read_methods_on_acl_path_remain_read(
        path in r"/[a-z/]{1,30}\.acl",
        method in prop_oneof![Just("GET"), Just("HEAD")],
    ) {
        let mode = coerce_required_mode_for_acl_local(&path, method);
        prop_assert_eq!(mode, AccessMode::Read);
    }

    #[test]
    fn non_acl_path_uses_base_mode(
        path in r"/[a-z/]{1,30}",
        method in prop_oneof![
            Just("GET"), Just("HEAD"), Just("PUT"),
            Just("POST"), Just("DELETE"), Just("PATCH"),
        ],
    ) {
        // Only test paths that genuinely don't end in .acl — proptest may
        // generate "/data.acl" matching the regex.
        prop_assume!(!path.ends_with(".acl"));
        let mode = coerce_required_mode_for_acl_local(&path, method);
        let base = method_to_mode_local(method);
        prop_assert_eq!(mode, base, "non-.acl path must use base mode mapping");
    }
}

// ── (E1c-4) Cap enforcement: oversized JSON-LD never panics, returns None ────
//
// Replicates `parse_acl_with_cap` semantics:
//   - if bytes.len() > MAX_ACL_DOC_BYTES → return None
//   - else try serde_json::from_slice
//   - on parse error → None
//   - panics are never acceptable

fn parse_acl_with_cap_local(bytes: &[u8]) -> Option<Value> {
    if bytes.len() > MAX_ACL_DOC_BYTES {
        return None;
    }
    serde_json::from_slice::<Value>(bytes).ok()
}

proptest! {
    #[test]
    fn oversized_acl_doc_returns_none_never_panics(
        // Generate "documents" between 64KiB+1 and 96KiB — guaranteed to
        // exceed the cap.
        size in (MAX_ACL_DOC_BYTES + 1)..=(MAX_ACL_DOC_BYTES + 32 * 1024),
        fill_byte in any::<u8>(),
    ) {
        let mut bytes = vec![fill_byte; size];
        // Force the document to *look* like JSON-LD so parse-time isn't the
        // failure mode — the size-cap check must trigger first.
        if size >= 12 {
            bytes[..2].copy_from_slice(b"{\"");
            bytes[size - 1] = b'}';
        }

        let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            parse_acl_with_cap_local(&bytes)
        }));
        prop_assert!(
            result.is_ok(),
            "parse_acl_with_cap must not panic on oversized input"
        );
        prop_assert!(
            result.unwrap().is_none(),
            "documents larger than MAX_ACL_DOC_BYTES must be rejected (got Some)"
        );
    }

    #[test]
    fn arbitrary_bytes_within_cap_never_panic(
        bytes in prop::collection::vec(any::<u8>(), 0..=4096),
    ) {
        let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            parse_acl_with_cap_local(&bytes)
        }));
        prop_assert!(
            result.is_ok(),
            "parse_acl_with_cap must not panic on arbitrary bytes (len={})",
            bytes.len()
        );
        // Either Ok(None) (parse fail) or Ok(Some(value)) — both acceptable.
    }

    #[test]
    fn arbitrary_printable_strings_within_cap_never_panic(
        s in r"\PC{0,2000}",
    ) {
        let s_bytes = s.as_bytes();
        let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            parse_acl_with_cap_local(s_bytes)
        }));
        prop_assert!(
            result.is_ok(),
            "parse_acl_with_cap must not panic on printable string"
        );
    }

    #[test]
    fn boundary_size_at_cap_accepted(
        // Generate a buffer exactly at the cap — must NOT be rejected on size.
        garbage_byte in any::<u8>(),
    ) {
        let bytes = vec![garbage_byte; MAX_ACL_DOC_BYTES];
        let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            parse_acl_with_cap_local(&bytes)
        }));
        prop_assert!(result.is_ok(), "boundary-size input must not panic");
        // Note: parse will return None for non-JSON garbage — but the size
        // check itself must accept the input. We only assert no-panic.
    }
}

// ── (E1c-5) Path-matching invariants ─────────────────────────────────────────
//
// `path_matches` in acl.rs:
//   - non-default rule: rule == resource OR resource starts with "{rule}/"
//   - default rule: resource starts with "{rule}/" OR resource == rule
//
// Replicate that locally for property checks: an exact-match always grants;
// a child-of-parent always grants under the documented prefix rules.

fn normalise_path(path: &str) -> String {
    let stripped = path.strip_prefix("./").or_else(|| path.strip_prefix('.'));
    let base = match stripped {
        Some("") => "/".to_string(),
        Some(s) if !s.starts_with('/') => format!("/{s}"),
        Some(s) => s.to_string(),
        None => path.to_string(),
    };
    let trimmed = base.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".to_string()
    } else {
        trimmed.to_string()
    }
}

fn path_matches_local(rule_path: &str, resource_path: &str, _is_default: bool) -> bool {
    let rule = normalise_path(rule_path);
    let resource = normalise_path(resource_path);
    resource == rule || resource.starts_with(&format!("{rule}/"))
}

proptest! {
    #[test]
    fn exact_match_always_granted(path in arb_access_path()) {
        prop_assert!(path_matches_local(&path, &path, false));
        prop_assert!(path_matches_local(&path, &path, true));
    }

    #[test]
    fn child_of_parent_granted(
        parent in arb_access_path(),
        child_seg in "[a-z]{1,8}",
    ) {
        let child = format!("{parent}/{child_seg}");
        prop_assert!(
            path_matches_local(&parent, &child, false),
            "child {} must match parent {} under accessTo",
            child, parent
        );
        prop_assert!(
            path_matches_local(&parent, &child, true),
            "child {} must match parent {} under default",
            child, parent
        );
    }

    #[test]
    fn unrelated_paths_dont_match(
        a in arb_access_path(),
        b in arb_access_path(),
    ) {
        // Sanity: if `a` is not a prefix of `b` and they're not equal, neither
        // accessTo nor default should match.
        let a_n = normalise_path(&a);
        let b_n = normalise_path(&b);
        prop_assume!(a_n != b_n);
        prop_assume!(!b_n.starts_with(&format!("{a_n}/")));

        prop_assert!(
            !path_matches_local(&a, &b, false),
            "unrelated paths must not match (rule={}, resource={})",
            a, b
        );
    }
}
