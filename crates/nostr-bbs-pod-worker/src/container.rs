//! LDP Container operations on R2.
//!
//! Containers are identified by a trailing `/` in the path.
//! Container metadata is derived from R2 prefix listing (no separate
//! document stored).  Membership is built from `Bucket::list()`.

use worker::*;

/// Check if a path represents a container (ends with `/` or is root).
pub fn is_container(path: &str) -> bool {
    path == "/" || path.ends_with('/')
}

/// List container members via R2 prefix listing.
/// Returns a JSON-LD document with `ldp:contains` triples.
pub async fn list_container(
    bucket: &Bucket,
    owner_pubkey: &str,
    container_path: &str,
) -> Result<serde_json::Value> {
    let prefix = format!("pods/{owner_pubkey}{container_path}");
    let listed = bucket.list().prefix(&prefix).execute().await?;

    let mut seen = std::collections::HashSet::new();
    let mut members: Vec<serde_json::Value> = Vec::new();

    for obj in listed.objects() {
        let key = obj.key();
        // Strip the prefix to get relative path
        let relative = match key.strip_prefix(&prefix) {
            Some(r) => r,
            None => continue,
        };
        if relative.is_empty() {
            continue; // Skip the container marker itself
        }

        // Only include direct children.  Nested paths collapse into a
        // sub-container entry (first segment + `/`).
        let name = if let Some(slash_pos) = relative.find('/') {
            &relative[..=slash_pos]
        } else {
            relative
        };

        let id = format!("{container_path}{name}");
        if !seen.insert(id.clone()) {
            continue; // Already emitted this child
        }

        members.push(serde_json::json!({
            "@id": id,
            "dcterms:modified": obj.uploaded().to_string(),
        }));
    }

    Ok(serde_json::json!({
        "@context": {
            "ldp": "http://www.w3.org/ns/ldp#",
            "dcterms": "http://purl.org/dc/terms/"
        },
        "@id": container_path,
        "@type": ["ldp:Container", "ldp:BasicContainer"],
        "ldp:contains": members
    }))
}

/// Longest `Slug` (in bytes) honoured as a child name. Longer hints are
/// ignored and a generated name is used instead.
pub const MAX_SLUG_BYTES: usize = 160;

/// Return `slug` when it is acceptable as a child name, `None` otherwise.
///
/// A container POST is authorised by `acl:Append` on the container, so the
/// child name must never let that grant reach anything Append does not
/// cover. A slug is accepted only when ALL of these hold:
///
/// - it is 1..=[`MAX_SLUG_BYTES`] bytes of `[A-Za-z0-9._-]` (an allowlist, so
///   `/`, `\`, `%`-encodings, spaces and every control byte are excluded
///   without a separate decode step);
/// - it does not start with `.` (no dot-files, no `.acl`, no `.`/`..`);
/// - it does not name an ACL or meta sidecar. The sidecar test is the shared
///   WAC policy [`solid_pod_rs::wac::protected_resource_for_acl`] (`.acl`,
///   `.meta`), applied to the ASCII-lower-cased name because the upstream
///   check is case-sensitive; `.meta.json` is refused in addition, as the
///   JSON-serialised meta form some Solid servers use.
///
/// Solid treats `Slug` as a hint, so a refused slug is treated as absent and
/// the caller falls back to a generated name (reported via `Location`).
pub fn accepted_slug(slug: Option<&str>) -> Option<&str> {
    let s = slug?;
    let b = s.as_bytes();
    let well_formed = !b.is_empty()
        && b.len() <= MAX_SLUG_BYTES
        && b[0] != b'.'
        && b.iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'));
    if !well_formed {
        return None;
    }
    let lower = s.to_ascii_lowercase();
    if solid_pod_rs::wac::protected_resource_for_acl(&lower).is_some()
        || lower.ends_with(".meta.json")
    {
        return None;
    }
    Some(s)
}

/// Resolve the target path for a POST to a container.
///
/// If the `Slug` passes [`accepted_slug`] it is used as the child name;
/// otherwise a random name from [`generated_child_path`] is used.
pub fn resolve_slug(container_path: &str, slug: Option<&str>) -> String {
    match accepted_slug(slug) {
        Some(name) => format!("{container_path}{name}"),
        None => generated_child_path(container_path),
    }
}

/// A fresh child path under `container_path` with a random (UUID v4) name.
pub fn generated_child_path(container_path: &str) -> String {
    format!("{container_path}{}", generate_id())
}

/// Generate an unpredictable, collision-resistant child name.
///
/// UUID v4 draws from the platform CSPRNG (`crypto.getRandomValues` on
/// wasm32 via `getrandom`'s `js` backend, the OS RNG natively). The previous
/// implementation derived every byte from the millisecond clock, so two POSTs
/// in the same millisecond produced the same name and names were guessable.
fn generate_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_container_detects_trailing_slash() {
        assert!(is_container("/"));
        assert!(is_container("/media/"));
        assert!(!is_container("/file.txt"));
        assert!(!is_container("/media/photo.jpg"));
    }

    #[test]
    fn resolve_slug_uses_provided_slug() {
        assert_eq!(resolve_slug("/photos/", Some("cat.jpg")), "/photos/cat.jpg");
    }

    #[test]
    fn resolve_slug_rejects_slash_in_slug() {
        // Slug with `/` is rejected, so a generated id is used instead
        let result = resolve_slug("/photos/", Some("a/b"));
        assert!(result.starts_with("/photos/"));
        assert!(!result.contains("a/b"));
    }

    #[test]
    fn resolve_slug_rejects_dotdot() {
        let result = resolve_slug("/photos/", Some(".."));
        assert!(result.starts_with("/photos/"));
        assert!(!result.contains(".."));
    }

    /// Slugs naming an ACL/meta sidecar, a dot-file, or carrying control or
    /// percent-encoded bytes must never become the child name: a container
    /// POST only needs `acl:Append`, and a sidecar would rewrite the
    /// container's authorisation graph.
    #[test]
    fn resolve_slug_rejects_sidecar_and_hidden_names() {
        for bad in [
            ".acl",
            "x.acl",
            "X.ACL",
            "item.Acl",
            ".meta",
            "x.meta",
            "x.META",
            "x.meta.json",
            ".hidden",
            ".",
            "a\nb",
            "a\u{0}b",
            "a\u{7f}b",
            "%2Eacl",
            "%2e%2e",
            "a%2Fb",
            "a\\b",
            "a b",
        ] {
            let result = resolve_slug("/inbox/", Some(bad));
            assert!(result.starts_with("/inbox/"), "{bad:?} -> {result}");
            assert_ne!(result, format!("/inbox/{bad}"), "slug {bad:?} was accepted");
            assert!(
                accepted_slug(Some(bad)).is_none(),
                "slug {bad:?} was accepted"
            );
        }
    }

    #[test]
    fn resolve_slug_keeps_ordinary_names() {
        for good in [
            "note.jsonld",
            "cat.jpg",
            "2026-11-26_msg",
            "README",
            "a.acl.txt",
        ] {
            assert_eq!(accepted_slug(Some(good)), Some(good));
            assert_eq!(
                resolve_slug("/inbox/", Some(good)),
                format!("/inbox/{good}")
            );
        }
    }

    #[test]
    fn resolve_slug_rejects_overlong() {
        let long = "a".repeat(MAX_SLUG_BYTES + 1);
        assert!(accepted_slug(Some(&long)).is_none());
        let max = "a".repeat(MAX_SLUG_BYTES);
        assert_eq!(accepted_slug(Some(&max)), Some(max.as_str()));
    }

    #[test]
    fn generated_names_are_distinct_and_plain() {
        let a = generate_id();
        let b = generate_id();
        assert_ne!(a, b, "two names generated back-to-back collided");
        assert!(accepted_slug(Some(&a)).is_some());
    }

    #[test]
    fn resolve_slug_rejects_empty() {
        let result = resolve_slug("/photos/", Some(""));
        assert!(result.starts_with("/photos/"));
        assert_ne!(result, "/photos/");
    }
}
