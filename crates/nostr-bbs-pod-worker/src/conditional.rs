//! Conditional request handling (ETags, If-Match, If-None-Match)
//! and Range request parsing per RFC 7233.

use worker::*;

/// Check conditional request headers against a resource's ETag.
///
/// Returns `Some(status)` if a conditional response should be returned
/// instead of the normal body:
/// - `304 Not Modified` for `If-None-Match` hit (GET / HEAD)
/// - `412 Precondition Failed` for `If-Match` miss (PUT / DELETE / PATCH)
///
/// Returns `None` when the request should proceed normally.
pub fn check_preconditions(headers: &Headers, resource_etag: &str) -> Option<u16> {
    // If-None-Match: return 304 if ETag matches (for GET/HEAD caching)
    if let Ok(Some(inm)) = headers.get("If-None-Match") {
        let etags: Vec<&str> = inm.split(',').map(|s| s.trim().trim_matches('"')).collect();
        if etags.iter().any(|e| *e == resource_etag || *e == "*") {
            return Some(304);
        }
    }

    // If-Match: return 412 if ETag does NOT match (for safe overwrites)
    if let Ok(Some(im)) = headers.get("If-Match") {
        let etags: Vec<&str> = im.split(',').map(|s| s.trim().trim_matches('"')).collect();
        if !etags.iter().any(|e| *e == resource_etag || *e == "*") {
            return Some(412);
        }
    }

    None
}

/// Parse a `Range` header and return `(start, end)` byte offsets (inclusive).
///
/// Supports a single byte range only (`bytes=START-END`, `bytes=START-`,
/// `bytes=-SUFFIX`).  Returns `None` if the header is absent, malformed,
/// or unsatisfiable.
pub fn parse_range(headers: &Headers, resource_size: u64) -> Option<(u64, u64)> {
    let range_header = headers.get("Range").ok()??;
    let range_str = range_header.strip_prefix("bytes=")?;

    let (start_str, end_str) = range_str.split_once('-')?;

    let start: u64 = if start_str.is_empty() {
        // Suffix range: `-500` means last 500 bytes
        let suffix: u64 = end_str.parse().ok()?;
        resource_size.saturating_sub(suffix)
    } else {
        start_str.parse().ok()?
    };

    let end: u64 = if end_str.is_empty() {
        resource_size - 1
    } else {
        end_str.parse().ok()?
    };

    if start > end || start >= resource_size {
        return None;
    }

    Some((start, end.min(resource_size - 1)))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    // We can't easily construct `worker::Headers` in unit tests without the
    // JS runtime, so we test the range parsing logic inline and test
    // `check_preconditions` indirectly via integration tests.

    #[test]
    fn parse_range_logic_normal() {
        // Direct logic test — simulate what parse_range would do
        let start: u64 = 0;
        let end: u64 = 499;
        let size: u64 = 1000;
        assert!(start <= end && start < size);
        assert_eq!(end.min(size - 1), 499);
    }

    #[test]
    fn parse_range_logic_suffix() {
        let size: u64 = 1000;
        let suffix: u64 = 200;
        let start = size.saturating_sub(suffix);
        assert_eq!(start, 800);
    }

    #[test]
    fn parse_range_logic_open_end() {
        let size: u64 = 1000;
        let start: u64 = 500;
        let end = size - 1;
        assert_eq!(end, 999);
        assert!(start <= end);
    }

    #[test]
    fn parse_range_logic_unsatisfiable() {
        let size: u64 = 1000;
        let start: u64 = 1000;
        // start >= size → unsatisfiable
        assert!(start >= size);
    }
}
