//! The relay seam: a small async [`Relay`] trait, the REQ [`Filter`], and
//! relay-independent helpers for paging and id lookups.
//!
//! The binary's WebSocket + HTTP client is one implementation; the tests use
//! an in-memory fake. Everything the engine knows about the relay's limits is
//! pinned here, with the relay source it came from.

use std::collections::{HashMap, HashSet};

use nostr_bbs_core::NostrEvent;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Largest `limit` the relay honours per filter. Mirrors `MAX_QUERY_LIMIT` in
/// `nostr-bbs-relay-worker/src/relay_do/storage.rs`; larger values are
/// clamped, so paging must treat a page of exactly this size as "maybe more".
pub const MAX_REQ_LIMIT: u32 = 1000;

/// Ids per `ids` REQ. The relay binds each id as one D1 parameter
/// (`relay_do/filter.rs` `build_filter_conditions`) and D1 caps a statement at
/// 100 bound parameters, so id lookups are batched well below that.
pub const MAX_IDS_PER_REQ: usize = 50;

/// Most ids `POST /api/admin/events/delete` accepts per call.
pub const MAX_DELETE_IDS: usize = 200;

/// A NIP-01 REQ filter, restricted to the fields the migrator uses.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Filter {
    /// Event ids.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ids: Option<Vec<String>>,
    /// Event kinds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kinds: Option<Vec<u64>>,
    /// `#e` tag values.
    #[serde(rename = "#e", skip_serializing_if = "Option::is_none")]
    pub e_tags: Option<Vec<String>>,
    /// `#p` tag values.
    #[serde(rename = "#p", skip_serializing_if = "Option::is_none")]
    pub p_tags: Option<Vec<String>>,
    /// Inclusive upper bound on `created_at` (the relay uses `created_at <= until`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub until: Option<u64>,
    /// Maximum events to return.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// The relay's answer to an `EVENT`: NIP-01 `["OK", <id>, <accepted>, <message>]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishOutcome {
    /// Whether the relay stored (or already had) the event.
    pub accepted: bool,
    /// The relay's message, such as `blocked: sealed originals are admin-only`.
    pub message: String,
}

/// Response of `POST /api/admin/events/delete`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct DeleteOutcome {
    /// Rows deleted.
    pub deleted: u64,
    /// Ids that were not stored on the relay.
    #[serde(rename = "notFound", default)]
    pub not_found: Vec<String>,
    /// Ids that exist but are not kind 42, and so were left alone.
    #[serde(default)]
    pub skipped: Vec<String>,
}

/// A transport or protocol failure talking to the relay. Such errors abort
/// the current step and leave the state file as last saved; they never mark
/// an entry `failed`.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RelayError {
    /// Connecting, sending or receiving failed.
    #[error("relay transport error: {0}")]
    Transport(String),
    /// The relay did not answer in time.
    #[error("relay timed out waiting for {0}")]
    Timeout(String),
    /// The relay closed a subscription (NIP-01 `CLOSED`) with this reason.
    #[error("relay closed the subscription: {0}")]
    Closed(String),
    /// An HTTP endpoint answered with a non-success status.
    #[error("relay HTTP {status}: {body}")]
    Http {
        /// HTTP status code.
        status: u16,
        /// Response body (the relay's JSON error).
        body: String,
    },
    /// The relay's answer was not in the expected shape.
    #[error("unexpected relay response: {0}")]
    Protocol(String),
}

/// Everything the migrator needs from a relay deployment.
///
/// Implementations talk to one relay as one authenticated identity (the
/// migrator). Calls are sequential; implementations need not be `Send`.
// Futures from this trait are awaited on a single-threaded runtime (and in
// tests on a no-op waker), so the auto-trait bounds that `async fn` in a
// public trait cannot express are not needed.
#[allow(async_fn_in_trait)]
pub trait Relay {
    /// Run one REQ with a single filter and return every event up to EOSE.
    async fn query(&mut self, filter: &Filter) -> Result<Vec<NostrEvent>, RelayError>;

    /// Publish an event and return the relay's `OK`.
    async fn publish(&mut self, event: &NostrEvent) -> Result<PublishOutcome, RelayError>;

    /// `GET /api/check-whitelist?pubkey=` → `isAdmin`.
    async fn is_admin(&mut self, pubkey: &str) -> Result<bool, RelayError>;

    /// `POST /api/admin/events/delete` with `{"ids": [..], "reason": ".."}`,
    /// NIP-98 authenticated as the migrator. At most [`MAX_DELETE_IDS`] ids.
    async fn delete_events(
        &mut self,
        ids: &[String],
        reason: &str,
    ) -> Result<DeleteOutcome, RelayError>;
}

/// Result of [`fetch_all`].
#[derive(Debug, Default)]
pub struct Fetched {
    /// Every distinct event matched, in the order the relay returned them.
    pub events: Vec<NostrEvent>,
    /// `created_at` seconds holding more events than one page, where the
    /// relay's `until`-only paging cannot guarantee completeness.
    pub ambiguous_seconds: Vec<u64>,
}

/// Page through every event matching `base` using `until` cursors and the
/// relay's maximum page size.
///
/// The relay returns newest first and `until` is inclusive, so each next
/// page starts at the oldest `created_at` seen and overlap is deduplicated by
/// id. A full page that adds nothing new means more than
/// [`MAX_REQ_LIMIT`] events share one second; paging then steps past that
/// second and records it in [`Fetched::ambiguous_seconds`].
pub async fn fetch_all<R: Relay>(relay: &mut R, base: &Filter) -> Result<Fetched, RelayError> {
    let mut out = Fetched::default();
    let mut seen = HashSet::new();
    let mut until = base.until;
    loop {
        let mut filter = base.clone();
        filter.limit = Some(MAX_REQ_LIMIT);
        filter.until = until;
        let page = relay.query(&filter).await?;
        let full = page.len() >= MAX_REQ_LIMIT as usize;
        let mut added = 0usize;
        let mut oldest = u64::MAX;
        for ev in page {
            oldest = oldest.min(ev.created_at);
            if seen.insert(ev.id.clone()) {
                out.events.push(ev);
                added += 1;
            }
        }
        if !full {
            return Ok(out);
        }
        if added == 0 {
            out.ambiguous_seconds.push(oldest);
            if oldest == 0 {
                return Ok(out);
            }
            until = Some(oldest - 1);
        } else {
            until = Some(oldest);
        }
    }
}

/// Fetch events by id, [`MAX_IDS_PER_REQ`] at a time. Ids the relay does not
/// return are simply absent from the map.
pub async fn fetch_by_ids<R: Relay>(
    relay: &mut R,
    ids: &[String],
) -> Result<HashMap<String, NostrEvent>, RelayError> {
    let mut out = HashMap::new();
    for chunk in ids.chunks(MAX_IDS_PER_REQ) {
        let filter = Filter {
            ids: Some(chunk.to_vec()),
            limit: Some(chunk.len() as u32),
            ..Filter::default()
        };
        for ev in relay.query(&filter).await? {
            if chunk.contains(&ev.id) {
                out.insert(ev.id.clone(), ev);
            }
        }
    }
    Ok(out)
}

/// The HTTP origin serving a relay's API: `wss://host/…` → `https://host`,
/// `ws://host:port/…` → `http://host:port`.
///
/// ```
/// use nostr_bbs_zone_migrate::relay::http_origin;
/// assert_eq!(http_origin("wss://relay.example.org").unwrap(), "https://relay.example.org");
/// assert_eq!(http_origin("ws://127.0.0.1:8787/x").unwrap(), "http://127.0.0.1:8787");
/// assert!(http_origin("https://relay.example.org").is_err());
/// ```
pub fn http_origin(relay_url: &str) -> Result<String, String> {
    let (scheme, rest) = if let Some(rest) = relay_url.strip_prefix("wss://") {
        ("https", rest)
    } else if let Some(rest) = relay_url.strip_prefix("ws://") {
        ("http", rest)
    } else {
        return Err(format!(
            "relay URL must start with wss:// or ws:// (got {relay_url})"
        ));
    };
    let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if host.is_empty() {
        return Err(format!("relay URL has no host: {relay_url}"));
    }
    Ok(format!("{scheme}://{host}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_serialises_to_nip01_shape() {
        let f = Filter {
            kinds: Some(vec![42]),
            e_tags: Some(vec!["c".into()]),
            until: Some(5),
            limit: Some(MAX_REQ_LIMIT),
            ..Filter::default()
        };
        assert_eq!(
            serde_json::to_string(&f).unwrap(),
            r##"{"kinds":[42],"#e":["c"],"until":5,"limit":1000}"##
        );
    }

    #[test]
    fn delete_outcome_reads_the_relay_shape() {
        let d: DeleteOutcome =
            serde_json::from_str(r#"{"deleted":2,"notFound":["a"],"skipped":["b"]}"#).unwrap();
        assert_eq!(d.deleted, 2);
        assert_eq!(d.not_found, vec!["a"]);
        assert_eq!(d.skipped, vec!["b"]);
        let d: DeleteOutcome = serde_json::from_str(r#"{"deleted":0}"#).unwrap();
        assert!(d.not_found.is_empty() && d.skipped.is_empty());
    }
}
