//! Response-size cap shared by the transports.
//!
//! Kept free of any runtime type so the cap logic is tested natively; the
//! Workers transport ([`crate::fetch`]) feeds it the `Content-Length` header and
//! each streamed chunk.
// Only the `worker` transport calls these outside tests.
#![cfg_attr(not(feature = "worker"), allow(dead_code))]

use crate::TransportError;

/// `false` when a parseable `Content-Length` already exceeds `cap`, so the
/// body is refused before any of it is read. A missing or unparseable header
/// passes; [`append_capped`] still bounds the bytes actually read.
pub(crate) fn content_length_ok(header: Option<&str>, cap: usize) -> bool {
    match header.and_then(|v| v.trim().parse::<u64>().ok()) {
        Some(len) => len <= cap as u64,
        None => true,
    }
}

/// Append `chunk` to `buf` unless that would take it past `cap`, in which case
/// nothing is appended and [`TransportError::Other`] is returned.
pub(crate) fn append_capped(
    buf: &mut Vec<u8>,
    chunk: &[u8],
    cap: usize,
) -> Result<(), TransportError> {
    if chunk.len() > cap.saturating_sub(buf.len()) {
        return Err(TransportError::Other);
    }
    buf.extend_from_slice(chunk);
    Ok(())
}
