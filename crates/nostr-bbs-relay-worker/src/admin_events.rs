//! Silent admin deletion of stored channel messages (ADR-2017).
//!
//! | Method | Path                       | Purpose                                         |
//! |--------|----------------------------|-------------------------------------------------|
//! | POST   | /api/admin/events/delete   | Delete kind-42 rows by id, with no kind-5 event |
//!
//! ## Why this is silent
//!
//! The sealed-original migration re-publishes each plaintext kind-42 in an
//! encrypted zone as an envelope that carries the *complete original signed
//! event*. Readers open the envelope and show the inner event under its
//! **original id**. The plaintext row must then be removed from the relay.
//!
//! A NIP-09 kind-5 cannot do that. The relay stores the kind-5 itself
//! (`relay_do/nip_handlers.rs` `process_deletion`), every forum client
//! receives it through its unbounded `kinds:[5,40,41]` subscription
//! (`crates/nostr-bbs-forum-client/src/stores/channels.rs`), and
//! `fold_deletions` in the same file tombstones every id it names. That id is
//! also the id of the restored inner event, so a kind-5 purge would hide the
//! very history the envelope preserves, on every client, for good.
//!
//! This endpoint therefore deletes the D1 rows directly: it emits **no kind-5
//! and no broadcast**, and it writes one `events.delete` row to the admin
//! audit log so the purge is still accountable.
//!
//! ## Side tables
//!
//! `event_tags` is maintained by the `trg_event_tags_ad` `AFTER DELETE ON
//! events` trigger (migration `0004_event_tags.sql`), which no later migration
//! or `ensure_schema` statement drops, so no explicit delete is needed here,
//! exactly as for the relay's other event-deleting paths. Kind 42 has no other
//! projection.

use nostr_bbs_core::d1_helpers::js_str;
use serde::Deserialize;
use serde_json::json;
use worker::{Env, Request, Response, Result};

use crate::audit;
use crate::auth;
use crate::cors::json_response;

/// Most ids accepted in one request. The migrator sends chunks of at most this.
pub(crate) const MAX_DELETE_IDS: usize = 200;

/// Longest `reason` accepted, in characters. It is stored in `admin_log`.
pub(crate) const MAX_REASON_CHARS: usize = 1000;

/// The only kind this endpoint deletes (NIP-28 channel message).
const KIND_CHANNEL_MESSAGE: u64 = 42;

/// Audit-log action name for this endpoint.
const AUDIT_ACTION: &str = "events.delete";

// ---------------------------------------------------------------------------
// Request body
// ---------------------------------------------------------------------------

/// Wire shape of the request body. Unknown fields are refused: this is a
/// destructive call and a misspelt field should fail loudly.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeleteEventsBody {
    ids: Vec<String>,
    reason: String,
}

/// A validated delete request.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct DeleteEventsRequest {
    /// Event ids, lowercased, duplicates removed, in request order.
    pub ids: Vec<String>,
    /// Operator-supplied reason, trimmed.
    pub reason: String,
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Parse and validate a `POST /api/admin/events/delete` body.
///
/// Accepts `{"ids":[<64-hex>, ...], "reason":"<text>"}` with 1 to
/// [`MAX_DELETE_IDS`] ids and a non-blank reason of at most
/// [`MAX_REASON_CHARS`] characters. Ids are lowercased (the relay stores ids
/// in lowercase hex) and de-duplicated, so a repeated id is reported once.
/// The limit applies to the ids as sent. `Err` carries a message for a 400
/// response.
pub(crate) fn parse_delete_body(bytes: &[u8]) -> std::result::Result<DeleteEventsRequest, String> {
    let body: DeleteEventsBody =
        serde_json::from_slice(bytes).map_err(|e| format!("Invalid body: {e}"))?;

    if body.ids.is_empty() {
        return Err("ids must contain at least one event id".into());
    }
    if body.ids.len() > MAX_DELETE_IDS {
        return Err(format!(
            "ids must contain at most {MAX_DELETE_IDS} event ids, got {}",
            body.ids.len()
        ));
    }

    let mut ids: Vec<String> = Vec::with_capacity(body.ids.len());
    for (i, id) in body.ids.iter().enumerate() {
        if !is_hex64(id) {
            return Err(format!("ids[{i}] is not a 64-character hex event id"));
        }
        let id = id.to_ascii_lowercase();
        if !ids.contains(&id) {
            ids.push(id);
        }
    }

    let reason = body.reason.trim();
    if reason.is_empty() {
        return Err("reason must not be empty".into());
    }
    if reason.chars().count() > MAX_REASON_CHARS {
        return Err(format!(
            "reason must be at most {MAX_REASON_CHARS} characters"
        ));
    }

    Ok(DeleteEventsRequest {
        ids,
        reason: reason.to_string(),
    })
}

// ---------------------------------------------------------------------------
// Per-id decision
// ---------------------------------------------------------------------------

/// What to do with one requested id, given the stored row's kind.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Disposition {
    /// No row with this id: report in `notFound`.
    NotFound,
    /// A row exists but is not kind 42: leave it, report in `skipped`.
    Skipped,
    /// A kind-42 row: delete it.
    Delete,
}

/// Decide the fate of one id from the kind of its stored row (`None` = absent).
pub(crate) fn disposition(stored_kind: Option<u64>) -> Disposition {
    match stored_kind {
        None => Disposition::NotFound,
        Some(KIND_CHANNEL_MESSAGE) => Disposition::Delete,
        Some(_) => Disposition::Skipped,
    }
}

/// Outcome of a delete run, serialised as the response body.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct DeleteOutcome {
    /// Ids whose kind-42 row was removed.
    pub deleted: Vec<String>,
    /// Ids with no stored row.
    pub not_found: Vec<String>,
    /// Ids whose row exists but is not kind 42.
    pub skipped: Vec<String>,
}

impl DeleteOutcome {
    /// The response body `{"deleted": n, "notFound": [...], "skipped": [...]}`.
    pub(crate) fn response_json(&self) -> serde_json::Value {
        json!({
            "deleted": self.deleted.len(),
            "notFound": self.not_found,
            "skipped": self.skipped,
        })
    }

    /// The `admin_log.new_value` details: the count and every id by outcome.
    pub(crate) fn audit_details(&self) -> serde_json::Value {
        json!({
            "count": self.deleted.len(),
            "ids": self.deleted,
            "notFound": self.not_found,
            "skipped": self.skipped,
        })
    }
}

// ---------------------------------------------------------------------------
// POST /api/admin/events/delete
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct KindRow {
    kind: f64,
}

/// `POST /api/admin/events/delete` — NIP-98 admin only; see the module docs.
///
/// Body `{"ids":[<64-hex>, ...], "reason":"<text>"}` (1 to [`MAX_DELETE_IDS`]
/// ids). For each id the stored row's kind is read first: absent ids go to
/// `notFound`, rows of another kind go to `skipped` and are left untouched,
/// and kind-42 rows are deleted with `DELETE FROM events WHERE id = ?1 AND
/// kind = 42`. A row that vanishes between the read and the delete is
/// reported as `notFound`.
///
/// Responses: `200 {"deleted": n, "notFound": [...], "skipped": [...]}`;
/// `400 {"error"}` for a malformed body; `401`/`403` from NIP-98. If D1 fails
/// part-way the rows already deleted stay deleted, the audit row is still
/// written, and the reply is `500` with the partial counts plus `error`;
/// retrying is safe because deleted ids then report as `notFound`.
pub async fn handle_delete_events(mut req: Request, env: &Env) -> Result<Response> {
    let request_url = req.url()?.to_string();
    let auth_header = req.headers().get("Authorization").ok().flatten();
    let body_bytes = req.bytes().await.unwrap_or_default();
    // Empty body is "no body" for NIP-98 payload-hash semantics; it then
    // fails body validation below with a 400.
    let body_for_auth: Option<&[u8]> = if body_bytes.is_empty() {
        None
    } else {
        Some(&body_bytes)
    };

    let admin_pubkey = match auth::require_nip98_admin(
        auth_header.as_deref(),
        &request_url,
        "POST",
        body_for_auth,
        env,
    )
    .await
    {
        Ok(pk) => pk,
        Err((body, status)) => return json_response(env, &body, status),
    };

    let request = match parse_delete_body(&body_bytes) {
        Ok(r) => r,
        Err(msg) => return json_response(env, &json!({ "error": msg }), 400),
    };

    let db = env.d1("DB")?;
    let mut outcome = DeleteOutcome::default();
    let mut failure: Option<String> = None;

    for id in &request.ids {
        let stored_kind = match db
            .prepare("SELECT kind FROM events WHERE id = ?1")
            .bind(&[js_str(id)])
        {
            Ok(stmt) => match stmt.first::<KindRow>(None).await {
                Ok(row) => row.map(|r| r.kind as u64),
                Err(e) => {
                    failure = Some(format!("lookup of {id} failed: {e}"));
                    break;
                }
            },
            Err(e) => {
                failure = Some(format!("lookup of {id} failed: {e}"));
                break;
            }
        };

        match disposition(stored_kind) {
            Disposition::NotFound => outcome.not_found.push(id.clone()),
            Disposition::Skipped => outcome.skipped.push(id.clone()),
            Disposition::Delete => {
                let run = match db
                    .prepare("DELETE FROM events WHERE id = ?1 AND kind = 42")
                    .bind(&[js_str(id)])
                {
                    Ok(stmt) => stmt.run().await,
                    Err(e) => Err(e),
                };
                match run {
                    Ok(res) => {
                        let changes = res.meta().ok().flatten().and_then(|m| m.changes);
                        // D1 always reports `changes` for a DELETE; if it is
                        // ever absent, the row was present a moment ago and
                        // the statement succeeded, so count it as deleted.
                        if changes == Some(0) {
                            outcome.not_found.push(id.clone());
                        } else {
                            outcome.deleted.push(id.clone());
                        }
                    }
                    Err(e) => {
                        failure = Some(format!("delete of {id} failed: {e}"));
                        break;
                    }
                }
            }
        }
    }

    let details = outcome.audit_details().to_string();
    let _ = audit::log_admin_action(
        env,
        &admin_pubkey,
        AUDIT_ACTION,
        None,
        None,
        None,
        Some(&details),
        Some(&request.reason),
    )
    .await;

    match failure {
        None => json_response(env, &outcome.response_json(), 200),
        Some(msg) => {
            let mut body = outcome.response_json();
            body["error"] = json!(msg);
            json_response(env, &body, 500)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(c: char) -> String {
        c.to_string().repeat(64)
    }

    fn body(v: serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(&v).unwrap()
    }

    #[test]
    fn accepts_a_valid_body() {
        let req = parse_delete_body(&body(json!({
            "ids": [id('a'), id('b')],
            "reason": "  sealed as originals (ADR-2017)  ",
        })))
        .unwrap();
        assert_eq!(req.ids, vec![id('a'), id('b')]);
        assert_eq!(req.reason, "sealed as originals (ADR-2017)");
    }

    #[test]
    fn lowercases_and_dedupes_ids_in_order() {
        let req = parse_delete_body(&body(json!({
            "ids": [id('B'), id('a'), id('b')],
            "reason": "r",
        })))
        .unwrap();
        assert_eq!(req.ids, vec![id('b'), id('a')]);
    }

    #[test]
    fn accepts_exactly_the_limit() {
        let ids: Vec<String> = (0..MAX_DELETE_IDS).map(|i| format!("{i:064x}")).collect();
        let req = parse_delete_body(&body(json!({ "ids": ids, "reason": "r" }))).unwrap();
        assert_eq!(req.ids.len(), MAX_DELETE_IDS);
    }

    #[test]
    fn refuses_more_than_the_limit() {
        let ids: Vec<String> = (0..=MAX_DELETE_IDS).map(|i| format!("{i:064x}")).collect();
        let err = parse_delete_body(&body(json!({ "ids": ids, "reason": "r" }))).unwrap_err();
        assert!(err.contains("at most 200"), "{err}");
    }

    #[test]
    fn limit_counts_ids_as_sent_not_after_dedupe() {
        let ids = vec![id('a'); MAX_DELETE_IDS + 1];
        assert!(parse_delete_body(&body(json!({ "ids": ids, "reason": "r" }))).is_err());
    }

    #[test]
    fn refuses_empty_ids() {
        let err = parse_delete_body(&body(json!({ "ids": [], "reason": "r" }))).unwrap_err();
        assert!(err.contains("at least one"), "{err}");
    }

    #[test]
    fn refuses_bad_hex() {
        for bad in [
            "a".repeat(63),
            "a".repeat(65),
            format!("g{}", "a".repeat(63)),
            String::new(),
            format!("{} ", "a".repeat(63)),
        ] {
            let err = parse_delete_body(&body(json!({ "ids": [id('a'), bad], "reason": "r" })))
                .unwrap_err();
            assert!(err.contains("ids[1]"), "{err}");
        }
    }

    #[test]
    fn refuses_non_string_ids() {
        assert!(parse_delete_body(&body(json!({ "ids": [42], "reason": "r" }))).is_err());
        assert!(parse_delete_body(&body(json!({ "ids": id('a'), "reason": "r" }))).is_err());
    }

    #[test]
    fn refuses_missing_or_blank_reason() {
        assert!(parse_delete_body(&body(json!({ "ids": [id('a')] }))).is_err());
        assert!(parse_delete_body(&body(json!({ "ids": [id('a')], "reason": null }))).is_err());
        let err =
            parse_delete_body(&body(json!({ "ids": [id('a')], "reason": "   " }))).unwrap_err();
        assert!(err.contains("reason"), "{err}");
    }

    #[test]
    fn refuses_overlong_reason() {
        let ok = "x".repeat(MAX_REASON_CHARS);
        assert!(parse_delete_body(&body(json!({ "ids": [id('a')], "reason": ok }))).is_ok());
        let long = "x".repeat(MAX_REASON_CHARS + 1);
        assert!(parse_delete_body(&body(json!({ "ids": [id('a')], "reason": long }))).is_err());
    }

    #[test]
    fn refuses_missing_ids_unknown_fields_and_garbage() {
        assert!(parse_delete_body(&body(json!({ "reason": "r" }))).is_err());
        assert!(parse_delete_body(&body(json!({
            "ids": [id('a')], "reason": "r", "kind": 1
        })))
        .is_err());
        assert!(parse_delete_body(b"").is_err());
        assert!(parse_delete_body(b"not json").is_err());
        assert!(parse_delete_body(b"[]").is_err());
    }

    #[test]
    fn only_kind_42_is_deleted() {
        assert_eq!(disposition(None), Disposition::NotFound);
        assert_eq!(disposition(Some(42)), Disposition::Delete);
        for kind in [0, 1, 5, 7, 40, 41, 1059, 30023] {
            assert_eq!(disposition(Some(kind)), Disposition::Skipped, "kind {kind}");
        }
    }

    #[test]
    fn response_and_audit_shapes() {
        let outcome = DeleteOutcome {
            deleted: vec![id('a'), id('b')],
            not_found: vec![id('c')],
            skipped: vec![id('d')],
        };
        assert_eq!(
            outcome.response_json(),
            json!({ "deleted": 2, "notFound": [id('c')], "skipped": [id('d')] })
        );
        assert_eq!(
            outcome.audit_details(),
            json!({
                "count": 2,
                "ids": [id('a'), id('b')],
                "notFound": [id('c')],
                "skipped": [id('d')],
            })
        );
        assert_eq!(
            DeleteOutcome::default().response_json(),
            json!({ "deleted": 0, "notFound": [], "skipped": [] })
        );
    }

    #[test]
    fn audit_details_for_a_full_chunk_fit_comfortably() {
        let outcome = DeleteOutcome {
            deleted: (0..MAX_DELETE_IDS).map(|i| format!("{i:064x}")).collect(),
            ..Default::default()
        };
        // 200 ids x (64 hex + quotes + comma) plus framing: well under D1's
        // 1 MB row limit.
        assert!(outcome.audit_details().to_string().len() < 16 * 1024);
    }
}
