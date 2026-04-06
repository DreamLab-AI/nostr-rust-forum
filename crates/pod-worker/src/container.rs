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

/// Resolve the target path for a POST to a container.
///
/// If a valid `Slug` is provided it is used as the child name; otherwise a
/// timestamp-based pseudo-random name is generated.  Slug values containing
/// `/` or `..` are rejected (treated as absent).
pub fn resolve_slug(container_path: &str, slug: Option<&str>) -> String {
    let name = slug
        .filter(|s| !s.is_empty() && !s.contains('/') && !s.contains(".."))
        .map(|s| s.to_string())
        .unwrap_or_else(generate_id);

    format!("{container_path}{name}")
}

/// Generate a pseudo-unique identifier.
///
/// In the Workers WASM environment this uses `Date.now()` via `js_sys`.
/// In native test builds it falls back to `std::time` so unit tests can
/// run without a JS runtime.
fn generate_id() -> String {
    let t: u64 = {
        #[cfg(target_arch = "wasm32")]
        {
            js_sys::Date::now() as u64
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0)
        }
    };

    let bytes: Vec<u8> = (0u8..16)
        .map(|i| {
            // Mix timestamp bits with the index for basic uniqueness
            let shift = (i as u64 * 7) % 64;
            ((t.wrapping_shr(shift as u32)) ^ (i as u64 * 0x9e3779b9)) as u8
        })
        .collect();

    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        (bytes[6] & 0x0f) | 0x40, bytes[7],
        (bytes[8] & 0x3f) | 0x80, bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    )
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

    #[test]
    fn resolve_slug_rejects_empty() {
        let result = resolve_slug("/photos/", Some(""));
        assert!(result.starts_with("/photos/"));
        assert_ne!(result, "/photos/");
    }
}
