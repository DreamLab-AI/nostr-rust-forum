//! Shared CORS header definitions consumed by all worker crates.
//!
//! Workers are separate `cdylib` WASM targets and cannot share response builder
//! code directly (each has its own `worker::Headers` type from the same crate,
//! but the instances are isolated). This module provides the **canonical** CORS
//! header name/value pairs so every worker applies the same policy.
//!
//! ## Usage
//!
//! Workers call [`cors_header_pairs`] to get the standard pairs, then apply
//! them to their own `worker::Headers` instance.
//!
//! Workers that need extended headers (e.g. the pod-worker exposes `ETag`,
//! `WAC-Allow`, etc.) should call [`cors_header_pairs`] first and then append
//! their additional headers.

/// A single CORS header name/value pair.
pub type CorsHeader = (&'static str, &'static str);

/// Standard CORS header pairs shared across all workers.
///
/// - `Access-Control-Allow-Methods`: GET, POST, OPTIONS (the minimum set all
///   workers support; pod-worker extends with PUT/DELETE/PATCH/HEAD).
/// - `Access-Control-Allow-Headers`: Content-Type, Authorization (sufficient
///   for NIP-98; pod-worker extends with Slug, If-Match, etc.).
/// - `Access-Control-Max-Age`: 86400 (24 hours; reduces preflight frequency).
///
/// The `Access-Control-Allow-Origin` header is NOT included here because its
/// value is worker-specific (read from `EXPECTED_ORIGIN` or `ALLOWED_ORIGINS`).
/// Each worker must set it separately.
pub const STANDARD_CORS_HEADERS: &[CorsHeader] = &[
    ("Access-Control-Allow-Methods", "GET, POST, OPTIONS"),
    (
        "Access-Control-Allow-Headers",
        "Content-Type, Authorization",
    ),
    ("Access-Control-Max-Age", "86400"),
];

/// Extended CORS header pairs for the pod-worker (LDP / Solid / payments).
///
/// The pod-worker allows additional HTTP methods and exposes additional
/// response headers required by the Solid protocol and WAC.
pub const POD_CORS_HEADERS: &[CorsHeader] = &[
    (
        "Access-Control-Allow-Methods",
        "GET, PUT, POST, DELETE, PATCH, HEAD, OPTIONS",
    ),
    (
        "Access-Control-Allow-Headers",
        "Content-Type, Authorization, Slug, If-Match, If-None-Match, Range",
    ),
    ("Access-Control-Max-Age", "86400"),
    (
        "Access-Control-Expose-Headers",
        "ETag, Accept-Ranges, Content-Range, Link, Location, WAC-Allow",
    ),
];

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_cors_has_expected_headers() {
        let names: Vec<&str> = STANDARD_CORS_HEADERS.iter().map(|(n, _)| *n).collect();
        assert!(names.contains(&"Access-Control-Allow-Methods"));
        assert!(names.contains(&"Access-Control-Allow-Headers"));
        assert!(names.contains(&"Access-Control-Max-Age"));
    }

    #[test]
    fn pod_cors_has_extended_methods() {
        let methods = POD_CORS_HEADERS
            .iter()
            .find(|(n, _)| *n == "Access-Control-Allow-Methods")
            .map(|(_, v)| *v)
            .unwrap();
        assert!(methods.contains("PUT"));
        assert!(methods.contains("DELETE"));
        assert!(methods.contains("PATCH"));
    }

    #[test]
    fn standard_cors_does_not_include_origin() {
        // Origin is worker-specific; must not be in the shared constant.
        assert!(!STANDARD_CORS_HEADERS
            .iter()
            .any(|(n, _)| *n == "Access-Control-Allow-Origin"));
    }
}
