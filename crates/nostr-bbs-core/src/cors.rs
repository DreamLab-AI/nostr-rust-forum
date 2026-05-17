//! Shared CORS header definitions consumed by all worker crates.
//!
//! Workers are separate `cdylib` WASM targets and cannot share response builder
//! code directly (each has its own `worker::Headers` type from the same crate,
//! but the instances are isolated). This module provides the **canonical** CORS
//! header name/value pairs so every worker applies the same policy.
//!
//! ## Usage
//!
//! Workers iterate over [`STANDARD_CORS_HEADERS`] to get the standard pairs,
//! then apply them to their own `worker::Headers` instance.
//!
//! Workers that need extended headers (e.g. the pod-worker exposes `ETag`,
//! `WAC-Allow`, etc.) should use [`POD_CORS_HEADERS`] instead, which includes
//! the additional methods and expose headers.

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
/// response headers required by the Solid protocol and WAC. This intentionally
/// mirrors the JSS-compatible global envelope used by solid-pod-rs-server so
/// browser clients see one predictable surface across native and Worker pods.
pub const POD_CORS_HEADERS: &[CorsHeader] = &[
    (
        "Access-Control-Allow-Methods",
        "GET, HEAD, POST, PUT, DELETE, PATCH, OPTIONS",
    ),
    (
        "Access-Control-Allow-Headers",
        "Accept, Authorization, Content-Type, DPoP, If-Match, If-None-Match, Link, Range, Slug, Origin",
    ),
    ("Access-Control-Allow-Credentials", "true"),
    ("Access-Control-Max-Age", "86400"),
    (
        "Access-Control-Expose-Headers",
        "Accept-Patch, Accept-Post, Accept-Ranges, Allow, Content-Length, Content-Range, Content-Type, ETag, Link, Location, Updates-Via, WAC-Allow, X-Cost, X-Balance, X-Pay-Currency",
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
        assert!(methods.contains("HEAD"));
    }

    #[test]
    fn pod_cors_matches_solid_jss_browser_surface() {
        let allow_headers = POD_CORS_HEADERS
            .iter()
            .find(|(n, _)| *n == "Access-Control-Allow-Headers")
            .map(|(_, v)| *v)
            .unwrap();
        assert!(allow_headers.contains("DPoP"));
        assert!(allow_headers.contains("Origin"));
        assert!(allow_headers.contains("Link"));

        let expose_headers = POD_CORS_HEADERS
            .iter()
            .find(|(n, _)| *n == "Access-Control-Expose-Headers")
            .map(|(_, v)| *v)
            .unwrap();
        assert!(expose_headers.contains("Updates-Via"));
        assert!(expose_headers.contains("Accept-Patch"));
        assert!(expose_headers.contains("X-Pay-Currency"));

        assert!(POD_CORS_HEADERS
            .iter()
            .any(|(n, v)| *n == "Access-Control-Allow-Credentials" && *v == "true"));
    }

    #[test]
    fn standard_cors_does_not_include_origin() {
        // Origin is worker-specific; must not be in the shared constant.
        assert!(!STANDARD_CORS_HEADERS
            .iter()
            .any(|(n, _)| *n == "Access-Control-Allow-Origin"));
    }
}
