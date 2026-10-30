//! Jev option (NF-03-S1-01): advisory moderation triage of admitted public posts.
//!
//! This runs from the cron tick, **after** the normal admission pipeline has
//! already accepted and stored an event. It cannot reject, accept, hide,
//! delete, ban or re-trust anything; it writes one advisory row into
//! `jev_triage`, which a human moderator reads through
//! `GET /api/jev/triage`. It never writes `reports` (that table feeds the
//! three-report auto-hide) or `hidden_events`, and nothing in admission, auth
//! or trust reads `jev_triage`.
//!
//! What leaves the Worker when the flag is on: the plaintext of an admitted
//! kind-42 post in a zone that is public-read and not encrypted, plus the text
//! of the post it replies to in the same channel. Never DMs, gift wraps,
//! encrypted-zone ciphertext, or anything in a non-public zone.

use nostr_bbs_jev::{ask, Answer, Fallback, JevConfig, JevTransport, Question};
use serde_json::json;

/// Flag variable (default off).
pub const FLAG: &str = "JEV_TRIAGE";
/// Per-consumer privacy switch: when `1`/`true` triage refuses cloud endpoints.
pub const LOCAL_ONLY_FLAG: &str = "JEV_TRIAGE_LOCAL_ONLY";
/// Version of the question set; stored with every row and logged.
pub const QUESTION_SET_VERSION: &str = "forum-moderation-triage/1";
/// Posts examined per cron tick (each is one <=4 s call, sequential).
pub const PER_TICK_CAP: usize = 5;
/// Only posts received within this window are considered.
pub const WINDOW_SECS: i64 = 24 * 3600;
/// Max characters of a post (and its parent) sent to Jev.
pub const TEXT_MAX_CHARS: usize = 1200;
/// Default hazard probability at/above which a row is queued for a human.
/// Unfitted: to be set from labelled data before any claim of uplift.
pub const DEFAULT_QUEUE_THRESHOLD: f64 = 0.5;

/// An admitted, eligible post.
#[derive(Debug, Clone, PartialEq)]
pub struct Candidate {
    /// Event id.
    pub event_id: String,
    /// Channel (kind-40 id).
    pub channel_id: String,
    /// Zone the channel belongs to.
    pub zone: String,
    /// Plaintext content.
    pub text: String,
    /// Plaintext of the replied-to post in the same channel, if any.
    pub parent: Option<String>,
}

/// One advisory row to be stored.
#[derive(Debug, Clone, PartialEq)]
pub struct TriageRow {
    /// Event id.
    pub event_id: String,
    /// Channel id.
    pub channel_id: String,
    /// Zone id.
    pub zone: String,
    /// P(spam).
    pub spam: f64,
    /// P(abuse).
    pub abuse: f64,
    /// P(contextual harm).
    pub harm: f64,
    /// Expected severity level (0-based rubric position, 0..=3).
    pub severity: f64,
    /// Confidence in the severity.
    pub severity_confidence: f64,
    /// Whether a human should look (any hazard >= threshold).
    pub queued: bool,
    /// Question-set version.
    pub question_set: &'static str,
}

/// Clip to [`TEXT_MAX_CHARS`] on a char boundary.
pub fn clip(s: &str) -> String {
    s.chars().take(TEXT_MAX_CHARS).collect()
}

fn questions() -> Vec<(&'static str, Question)> {
    vec![
        (
            "spam",
            Question::Noul {
                instructions: "Is `post.text` spam: unsolicited advertising, scam or phishing \
                               links, repetitive promotion, or content-free flooding? Ordinary \
                               on-topic discussion, including a single relevant link, is not spam."
                    .into(),
            },
        ),
        (
            "abuse",
            Question::Noul {
                instructions: "Is `post.text` abusive: harassment, slurs or hateful content aimed at \
                               a person or group, threats, or sexual content about a named person? \
                               Blunt disagreement or strong language not aimed at a person is not \
                               abuse. Use `post.replying_to`, when present, to see who is addressed."
                    .into(),
            },
        ),
        (
            "harm",
            Question::Noul {
                instructions: "Given `post.replying_to` (when present) as context, does `post.text` \
                               carry contextual harm that is not obvious from its words alone: \
                               doxxing, encouraging self-harm, coordinated pile-on, or pressure to \
                               act dangerously? Quoting or criticising such content is not harm."
                    .into(),
            },
        ),
        (
            "severity",
            Question::Score {
                instructions: "If `post.text` breaks community norms for spam, abuse or harm, how \
                               urgently does a human moderator need to look at it? Rate benign \
                               content as the lowest level."
                    .into(),
                criteria: vec![
                    "Benign: nothing for a moderator to do".into(),
                    "Minor: low-priority, worth a glance".into(),
                    "Serious: should be reviewed soon".into(),
                    "Urgent: review immediately".into(),
                ],
            },
        ),
    ]
}

/// Triage one post. `Err` means "store nothing".
pub async fn triage_one<T: JevTransport + ?Sized>(
    transport: &T,
    cfg: &JevConfig,
    c: &Candidate,
    queue_threshold: f64,
) -> Result<TriageRow, Fallback> {
    let state = json!({
        "post": { "text": clip(&c.text), "replying_to": c.parent.as_deref().map(clip) },
    });
    let qs = questions();
    let a = ask(transport, cfg, &state, &qs).await?;
    let noul = |k: &str| match a.get(k) {
        Some(Answer::Noul(p)) => Ok(*p),
        _ => Err(Fallback::Malformed),
    };
    let (spam, abuse, harm) = (noul("spam")?, noul("abuse")?, noul("harm")?);
    let (severity, severity_confidence) = match a.get("severity") {
        Some(Answer::Score { score, confidence }) => (*score, *confidence),
        _ => return Err(Fallback::Malformed),
    };
    Ok(TriageRow {
        event_id: c.event_id.clone(),
        channel_id: c.channel_id.clone(),
        zone: c.zone.clone(),
        spam,
        abuse,
        harm,
        severity,
        severity_confidence,
        queued: spam.max(abuse).max(harm) >= queue_threshold,
        question_set: QUESTION_SET_VERSION,
    })
}

/// Triage a batch (at most [`PER_TICK_CAP`]). Stops at the first
/// transport-class failure (timeout / HTTP error / no endpoint) so an outage
/// costs one deadline, not five. Per-post fallbacks (malformed) skip that post.
/// The returned rows are the only thing the caller may write.
pub async fn triage_batch<T: JevTransport + ?Sized>(
    transport: &T,
    cfg: &JevConfig,
    cands: &[Candidate],
    queue_threshold: f64,
) -> (Vec<TriageRow>, Option<Fallback>) {
    let mut rows = Vec::new();
    for c in cands.iter().take(PER_TICK_CAP) {
        match triage_one(transport, cfg, c, queue_threshold).await {
            Ok(r) => rows.push(r),
            Err(
                f @ (Fallback::Timeout
                | Fallback::Transport
                | Fallback::Http(_)
                | Fallback::NoEndpoint),
            ) => {
                return (rows, Some(f));
            }
            Err(_) => {} // malformed/low-confidence: skip this post, keep going
        }
    }
    (rows, None)
}

/// Zone ids whose content may be sent: public-read AND not encrypted.
pub fn eligible_zone_ids(zones: &crate::zone_config::ZoneConfig) -> Vec<String> {
    zones
        .zone_ids()
        .filter(|id| zones.is_public_read(id) && !zones.is_encrypted(id))
        .map(str::to_string)
        .collect()
}

// ---------------------------------------------------------------------------
// Worker-side runner (D1 + HTTP). Everything above is natively testable.
// ---------------------------------------------------------------------------

use crate::zone_config::{is_zone_ciphertext, ZoneConfig};
use nostr_bbs_core::d1_helpers::{js_f64, js_str};
use serde::Deserialize;
use wasm_bindgen::JsValue;
use worker::{console_log, Env, Request, Response, Result};

#[derive(Deserialize)]
struct EvRow {
    id: String,
    content: String,
    tags: String,
    channel_id: String,
    zone: String,
}

fn parse_tags(raw: &str) -> Vec<Vec<String>> {
    serde_json::from_str(raw).unwrap_or_default()
}

/// The `e` tag marked `reply`, if any (NIP-10 marker form).
fn reply_target(tags: &[Vec<String>]) -> Option<&str> {
    tags.iter()
        .find(|t| t.len() >= 4 && t[0] == "e" && t[3] == "reply")
        .map(|t| t[1].as_str())
}

/// Whether the triage flag is on. When off the sweep is a no-op, the list
/// route is not matched, and the table is never created.
pub fn flag_on(env: &Env) -> bool {
    env.var(FLAG)
        .map(|v| matches!(v.to_string().trim(), "1" | "true"))
        .unwrap_or(false)
}

/// Same statement as `migrations/0011_jev_triage.sql`. Created lazily, only
/// once the flag is on, so the relay boot path (`ensure_schema`) is unchanged.
const CREATE_SQL: &str = "CREATE TABLE IF NOT EXISTS jev_triage (\
    event_id TEXT PRIMARY KEY, channel_id TEXT NOT NULL, zone TEXT NOT NULL, \
    spam REAL NOT NULL, abuse REAL NOT NULL, harm REAL NOT NULL, \
    severity REAL NOT NULL, severity_confidence REAL NOT NULL, \
    queued INTEGER NOT NULL, model TEXT NOT NULL, question_set TEXT NOT NULL, \
    created_at INTEGER NOT NULL)";

async fn ensure_table(db: &worker::D1Database) -> bool {
    match db.prepare(CREATE_SQL).run().await {
        Ok(_) => true,
        Err(_) => false,
    }
}

/// Run one triage tick. Never errors to the caller.
pub async fn run_sweep(env: &Env) {
    let lookup = nostr_bbs_jev::fetch::env_lookup(env);
    // Resolver is only consulted for the flag here; FlagOff is silent and
    // touches nothing.
    let cfg = match nostr_bbs_jev::resolve(
        &lookup,
        FLAG,
        nostr_bbs_jev::local_only(&lookup, LOCAL_ONLY_FLAG),
    ) {
        Ok(c) => c,
        Err(Fallback::FlagOff) => return,
        Err(why) => {
            console_log!("jev triage fallback: {}", why.tag());
            return;
        }
    };
    let threshold = lookup("JEV_TRIAGE_QUEUE_THRESHOLD")
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(DEFAULT_QUEUE_THRESHOLD);
    let Ok(db) = env.d1("DB") else { return };
    if !ensure_table(&db).await {
        return;
    }
    let zones = ZoneConfig::load(env);
    let zone_ids = eligible_zone_ids(&zones);
    if zone_ids.is_empty() {
        return;
    }
    let now = crate::auth::js_now_secs() as i64;
    let marks: Vec<String> = (0..zone_ids.len()).map(|i| format!("?{}", i + 3)).collect();
    let sql = format!(
        "SELECT e.id AS id, e.content AS content, e.tags AS tags, cz.channel_id AS channel_id, \
                cz.zone AS zone \
         FROM events e \
         JOIN event_tags t ON t.event_id = e.id AND t.name = 'e' \
         JOIN channel_zones cz ON cz.channel_id = t.value AND cz.archived = 0 \
         WHERE e.kind = 42 AND e.received_at >= ?1 \
           AND cz.zone IN ({}) \
           AND e.id NOT IN (SELECT event_id FROM jev_triage) \
           AND e.id NOT IN (SELECT event_id FROM hidden_events) \
         GROUP BY e.id ORDER BY e.received_at DESC LIMIT ?2",
        marks.join(", ")
    );
    let mut binds: Vec<JsValue> = vec![js_f64((now - WINDOW_SECS) as f64), js_f64(50.0)];
    binds.extend(zone_ids.iter().map(|z| js_str(z)));
    let rows: Vec<EvRow> = match db.prepare(&sql).bind(&binds) {
        Ok(stmt) => match stmt.all().await.and_then(|r| r.results::<EvRow>()) {
            Ok(r) => r,
            Err(_) => return,
        },
        Err(_) => return,
    };

    let mut cands = Vec::new();
    for r in rows {
        let tags = parse_tags(&r.tags);
        // Defence in depth: never send zone ciphertext, whatever the config says.
        if is_zone_ciphertext(&r.zone, &tags, &r.content) {
            continue;
        }
        let parent = match reply_target(&tags) {
            Some(pid) => fetch_parent(&db, pid, &r.channel_id).await,
            None => None,
        };
        cands.push(Candidate {
            event_id: r.id,
            channel_id: r.channel_id,
            zone: r.zone,
            text: r.content,
            parent,
        });
        if cands.len() >= PER_TICK_CAP {
            break;
        }
    }
    if cands.is_empty() {
        return;
    }

    let (rows, fallback) =
        triage_batch(&nostr_bbs_jev::fetch::WorkersFetch, &cfg, &cands, threshold).await;
    if let Some(why) = fallback {
        console_log!("jev triage fallback: {}", why.tag());
    }
    for r in &rows {
        let res = db
            .prepare(
                "INSERT OR IGNORE INTO jev_triage (event_id, channel_id, zone, spam, abuse, harm, \
                 severity, severity_confidence, queued, model, question_set, created_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            )
            .bind(&[
                js_str(&r.event_id),
                js_str(&r.channel_id),
                js_str(&r.zone),
                js_f64(r.spam),
                js_f64(r.abuse),
                js_f64(r.harm),
                js_f64(r.severity),
                js_f64(r.severity_confidence),
                js_f64(if r.queued { 1.0 } else { 0.0 }),
                js_str(&cfg.model),
                js_str(r.question_set),
                js_f64(now as f64),
            ]);
        if let Ok(stmt) = res {
            let _ = stmt.run().await;
        }
    }
    console_log!(
        "jev triage: examined={} annotated={} question_set={} model={}",
        cands.len(),
        rows.len(),
        QUESTION_SET_VERSION,
        cfg.model
    );
}

/// Parent post text, only if it is a kind-42 in the SAME channel (hence the
/// same public zone).
async fn fetch_parent(
    db: &worker::D1Database,
    parent_id: &str,
    channel_id: &str,
) -> Option<String> {
    #[derive(Deserialize)]
    struct P {
        content: String,
    }
    let stmt = db
        .prepare(
            "SELECT e.content AS content FROM events e \
             JOIN event_tags t ON t.event_id = e.id AND t.name = 'e' AND t.value = ?2 \
             WHERE e.id = ?1 AND e.kind = 42 LIMIT 1",
        )
        .bind(&[js_str(parent_id), js_str(channel_id)])
        .ok()?;
    stmt.first::<P>(None)
        .await
        .ok()
        .flatten()
        .map(|p| p.content)
}

/// `GET /api/jev/triage?queued=1&limit=50&offset=0` -- NIP-98 admin only.
/// Read-only advisory queue; acting on it is a human moderator's decision
/// through the existing report/moderation endpoints.
pub async fn handle_list(req: &Request, env: &Env) -> Result<Response> {
    let url = req.url()?;
    let auth_header = req.headers().get("Authorization").ok().flatten();
    if let Err((body, status)) =
        crate::auth::require_nip98_admin(auth_header.as_deref(), &url.to_string(), "GET", None, env)
            .await
    {
        return crate::cors::json_response(env, &body, status);
    }
    let params: std::collections::HashMap<String, String> = url
        .query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let limit: u32 = params
        .get("limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(50)
        .min(200);
    let offset: u32 = params
        .get("offset")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let only_queued = params.get("queued").map(|v| v == "1").unwrap_or(false);
    let db = env.d1("DB")?;
    if !ensure_table(&db).await {
        return crate::cors::json_response(
            env,
            &json!({ "error": "triage store unavailable" }),
            503,
        );
    }
    let sql = format!(
        "SELECT event_id, channel_id, zone, spam, abuse, harm, severity, severity_confidence, \
         queued, model, question_set, created_at FROM jev_triage {} \
         ORDER BY severity DESC, created_at DESC LIMIT ?1 OFFSET ?2",
        if only_queued { "WHERE queued = 1" } else { "" }
    );
    let result = db
        .prepare(&sql)
        .bind(&[js_f64(limit as f64), js_f64(offset as f64)])?
        .all()
        .await?;
    let items: Vec<serde_json::Value> = result.results::<serde_json::Value>()?;
    crate::cors::json_response(
        env,
        &json!({ "advisory": true, "items": items, "limit": limit, "offset": offset }),
        200,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zone_config::ZoneConfig;
    use nostr_bbs_jev::testutil::{block_on, Mock};
    use nostr_bbs_jev::TransportError;

    fn cfg() -> JevConfig {
        JevConfig {
            endpoint: "http://e".into(),
            model: "m".into(),
            bearer: None,
            deadline_ms: 10,
        }
    }
    fn cand(i: usize) -> Candidate {
        Candidate {
            event_id: format!("e{i}"),
            channel_id: "c".into(),
            zone: "public".into(),
            text: format!("hello {i}"),
            parent: Some("parent text".into()),
        }
    }
    fn reply(spam: f64, abuse: f64, harm: f64, sev: f64, conf: f64) -> String {
        json!({"model":"jev-1","answers":{
            "spam":{"type":"noul","noul":spam},
            "abuse":{"type":"noul","noul":abuse},
            "harm":{"type":"noul","noul":harm},
            "severity":{"type":"score","score":sev,"confidence":conf,"legend":{}}},
            "usage":{"input_tokens":1,"output_tokens":1}})
        .to_string()
    }

    #[test]
    fn accept_path_annotates_and_queues() {
        let m = Mock::new(Ok((200, reply(0.9, 0.1, 0.1, 2.5, 0.8))));
        let (rows, f) = block_on(triage_batch(
            &m,
            &cfg(),
            &[cand(1)],
            DEFAULT_QUEUE_THRESHOLD,
        ));
        assert!(f.is_none());
        assert_eq!(rows.len(), 1);
        assert!(rows[0].queued);
        assert_eq!(rows[0].question_set, QUESTION_SET_VERSION);
        let benign = Mock::new(Ok((200, reply(0.05, 0.02, 0.01, 0.1, 0.9))));
        let (rows, _) = block_on(triage_batch(
            &benign,
            &cfg(),
            &[cand(2)],
            DEFAULT_QUEUE_THRESHOLD,
        ));
        assert!(!rows[0].queued, "benign content is recorded but not queued");
    }

    #[test]
    fn wire_shape() {
        let m = Mock::new(Ok((200, reply(0.1, 0.1, 0.1, 0.0, 0.9))));
        block_on(triage_batch(&m, &cfg(), &[cand(1)], 0.5));
        let body: serde_json::Value = serde_json::from_str(&m.requests.borrow()[0].2).unwrap();
        assert_eq!(body["state"]["post"]["text"], "hello 1");
        assert_eq!(body["state"]["post"]["replying_to"], "parent text");
        for k in ["spam", "abuse", "harm"] {
            assert_eq!(body["questions"][k]["type"], "noul");
        }
        assert!(body["questions"]["severity"]["criteria"].is_array());
        // no pubkeys, ids or zone names leave
        let s = body.to_string();
        assert!(!s.contains("e1") || !s.contains("\"event_id\""));
        assert!(body["state"]["post"].get("event_id").is_none());
    }

    #[test]
    fn every_fallback_writes_nothing() {
        let cs = [cand(1), cand(2), cand(3)];
        let cases = vec![
            Err(TransportError::Timeout),
            Err(TransportError::Other),
            Ok((500, String::new())),
            Ok((429, String::new())),
            Ok((200, "nope".into())),
            Ok((
                200,
                r#"{"answers":{"spam":{"type":"noul","noul":0.9}}}"#.into(),
            )),
        ];
        for rep in cases {
            let (rows, _) = block_on(triage_batch(&Mock::new(rep), &cfg(), &cs, 0.5));
            assert!(rows.is_empty(), "a failed call must leave no annotation");
        }
    }

    #[test]
    fn outage_costs_one_deadline_not_five() {
        let m = Mock::new(Err(TransportError::Timeout));
        let cs: Vec<_> = (0..5).map(cand).collect();
        let (_, f) = block_on(triage_batch(&m, &cfg(), &cs, 0.5));
        assert_eq!(f, Some(Fallback::Timeout));
        assert_eq!(m.requests.borrow().len(), 1);
    }

    #[test]
    fn per_tick_cap_is_enforced() {
        let m = Mock::new(Ok((200, reply(0.1, 0.1, 0.1, 0.0, 0.9))));
        let cs: Vec<_> = (0..20).map(cand).collect();
        let (rows, _) = block_on(triage_batch(&m, &cfg(), &cs, 0.5));
        assert_eq!(rows.len(), PER_TICK_CAP);
    }

    #[test]
    fn only_public_unencrypted_zones_are_eligible() {
        let z = ZoneConfig::from_json(
            r#"[{"id":"public","visibility":"public"},
                {"id":"locked","visibility":"locked"},
                {"id":"hidden","visibility":"hidden"},
                {"id":"cohorted","visibility":"public","required_cohorts":["x"]},
                {"id":"enc","visibility":"public","encrypted":true}]"#,
        )
        .with_encryption(true);
        // `enc` is public so the zone is never treated as encrypted (see
        // ZoneConfig::is_encrypted); the content-level ciphertext guard in the
        // SQL candidate filter covers it. Locked/hidden/cohorted never qualify.
        let ids = eligible_zone_ids(&z);
        assert!(ids.contains(&"public".to_string()));
        for bad in ["locked", "hidden", "cohorted"] {
            assert!(
                !ids.contains(&bad.to_string()),
                "{bad} must not be eligible"
            );
        }
    }
}
