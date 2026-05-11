//! NIP-26 delegation endpoint — **not yet implemented**.
//!
//! NIP-26 allows a delegator to sign a token that grants another pubkey
//! (the delegatee) the right to publish events on their behalf under specific
//! conditions. Full relay-side delegation validation (tag checking on EVENT
//! ingress) is not yet implemented; this endpoint returns **501 Not Implemented**
//! so callers know the feature is unavailable rather than silently succeeding.
//!
//! Endpoint:
//!   POST /api/delegation/verify  ->  501 Not Implemented

use worker::{Env, Response, Result};

use crate::http::json_response;

// ---------------------------------------------------------------------------
// POST /api/delegation/verify — 501 Not Implemented
// ---------------------------------------------------------------------------

/// Return 501 Not Implemented for the NIP-26 delegation verification endpoint.
///
/// Previous versions returned 200 OK from a verification stub, which led
/// callers to believe delegation had succeeded. Until NIP-26 is fully
/// supported (relay-side delegation tag validation on EVENT ingress), this
/// endpoint explicitly signals that the feature is unavailable.
pub async fn handle_verify(
    _body_bytes: &[u8],
    _auth_header: Option<&str>,
    env: &Env,
) -> Result<Response> {
    json_response(
        env,
        &serde_json::json!({
            "error": "NIP-26 delegation is not yet supported"
        }),
        501,
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #[test]
    fn stub_module_compiles() {
        // Intentionally minimal: the handler is a 501 stub.
        // Integration tests verify the HTTP status via the worker harness.
    }
}
