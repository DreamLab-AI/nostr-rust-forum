//! User-card activity stats and the public successor map.
//!
//! | Method | Path                        | Auth                  |
//! |--------|-----------------------------|-----------------------|
//! | GET    | /api/profile-stats?pubkey=  | optional NIP-98 (GET) |
//! | GET    | /api/profiles/successors    | none                  |
//!
//! ## Viewer-scoped counts
//!
//! Stats are computed only over events the *viewer* could read through REQ.
//! A kind-42 in a channel bound to a zone (`channel_zones`) counts only when
//! the viewer may read that zone — the same predicate as the REQ read gate in
//! `relay_do::nip_handlers` (admin bypass, public-read zones, cohort match).
//! Without a valid NIP-98 header the viewer is anonymous and sees public
//! zones only. A card therefore never reveals activity in a zone the person
//! clicking it could not already browse.
//!
//! ## Linked identities
//!
//! `pubkey_aliases` links a replaced `old_pubkey` to its `new_pubkey`. Stats
//! for either key are computed over the whole identity (the successor plus
//! every key it replaced), and the response names the successor so clients can
//! redirect a stale key (DM targets, mention pickers) to the live one. The
//! successor map is public: an alias is a deliberate "these keys are the same
//! person" statement made by an admin, and it carries no reason or actor.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use serde_json::json;
use wasm_bindgen::JsValue;
use worker::{D1Database, Env, Request, Response, Result};

use crate::auth;
use crate::cors::json_response as cors_json_response;
use crate::trust;
use crate::zone_config::ZoneConfig;

/// Kinds counted as authored posts: NIP-01 notes, NIP-28 channel messages and
/// NIP-22 comments.
const POST_KINDS: [u32; 3] = [1, 42, 1111];

/// Upper bound on rows scanned per identity. The response flags `truncated`
/// when the cap is hit so the card can say "at least".
const MAX_ROWS: u32 = 5000;

/// Channels listed under "most active in".
const TOP_CHANNELS: usize = 5;

// ---------------------------------------------------------------------------
// Pure aggregation (unit-tested; no Env)
// ---------------------------------------------------------------------------

/// One authored event, as read from D1.
#[derive(Debug, Clone, Deserialize)]
pub struct PostRow {
    pub kind: f64,
    pub created_at: f64,
    /// Raw JSON tag array as stored in `events.tags`.
    pub tags: String,
}

/// Activity in one channel.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ChannelActivity {
    pub id: String,
    pub count: u32,
    pub last_at: u64,
}

/// Aggregated, viewer-visible activity.
#[derive(Debug, Clone, PartialEq, Default, Serialize)]
pub struct Activity {
    pub post_count: u32,
    pub first_post_at: Option<u64>,
    pub last_post_at: Option<u64>,
    pub top_channels: Vec<ChannelActivity>,
}

/// Channel id of a kind-42 message: its first `e` tag, matching
/// `filter::tag_value(event, "e")` on the REQ read path.
pub fn channel_of(kind: u32, tags_json: &str) -> Option<String> {
    if kind != 42 {
        return None;
    }
    let tags: Vec<Vec<String>> = serde_json::from_str(tags_json).ok()?;
    tags.into_iter()
        .find(|t| t.len() >= 2 && t[0] == "e")
        .map(|mut t| t.swap_remove(1))
}

/// Aggregate `rows` into viewer-visible activity.
///
/// `channel_zone` maps a channel id to its bound zone; unbound channels are
/// public (the REQ gate's "undeclared channel is unscoped" rule).
/// `can_read_zone` answers whether the viewer may read a zone.
pub fn aggregate<F>(
    rows: &[PostRow],
    channel_zone: &HashMap<String, String>,
    can_read_zone: F,
    top_n: usize,
) -> Activity
where
    F: Fn(&str) -> bool,
{
    let mut out = Activity::default();
    let mut per_channel: HashMap<String, ChannelActivity> = HashMap::new();

    for row in rows {
        let kind = row.kind as u32;
        let at = row.created_at as u64;
        let channel = channel_of(kind, &row.tags);
        if let Some(cid) = channel.as_deref() {
            if let Some(zone) = channel_zone.get(cid) {
                if !can_read_zone(zone) {
                    continue;
                }
            }
        }
        out.post_count += 1;
        out.first_post_at = Some(out.first_post_at.map_or(at, |f| f.min(at)));
        out.last_post_at = Some(out.last_post_at.map_or(at, |l| l.max(at)));
        if let Some(cid) = channel {
            let entry = per_channel.entry(cid.clone()).or_insert(ChannelActivity {
                id: cid,
                count: 0,
                last_at: 0,
            });
            entry.count += 1;
            entry.last_at = entry.last_at.max(at);
        }
    }

    let mut channels: Vec<ChannelActivity> = per_channel.into_values().collect();
    channels.sort_by(|a, b| {
        b.count
            .cmp(&a.count)
            .then(b.last_at.cmp(&a.last_at))
            .then(a.id.cmp(&b.id))
    });
    channels.truncate(top_n);
    out.top_channels = channels;
    out
}

/// Viewer read predicate over zones, mirroring `trust::has_zone_access`.
pub fn viewer_can_read(zones: &ZoneConfig, zone: &str, cohorts: &[String], is_admin: bool) -> bool {
    is_admin || zones.is_public_read(zone) || zones.cohorts_can_read(zone, cohorts)
}

/// Channel display name from a kind-40 `content` JSON (`{"name": ...}`).
pub fn channel_name(content: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(content)
        .ok()?
        .get("name")?
        .as_str()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

// ---------------------------------------------------------------------------
// D1 helpers
// ---------------------------------------------------------------------------

fn is_valid_pubkey(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn placeholders(from: usize, n: usize) -> String {
    (from..from + n)
        .map(|i| format!("?{i}"))
        .collect::<Vec<_>>()
        .join(", ")
}

#[derive(Deserialize)]
struct NewRow {
    new_pubkey: String,
}

#[derive(Deserialize)]
struct OldRow {
    old_pubkey: String,
}

/// The key that replaced `pubkey`, if any.
async fn successor_of(db: &D1Database, pubkey: &str) -> Option<String> {
    db.prepare("SELECT new_pubkey FROM pubkey_aliases WHERE old_pubkey = ?1 LIMIT 1")
        .bind(&[JsValue::from_str(pubkey)])
        .ok()?
        .first::<NewRow>(None)
        .await
        .ok()
        .flatten()
        .map(|r| r.new_pubkey)
}

/// Keys that `root` replaced.
async fn predecessors_of(db: &D1Database, root: &str) -> Vec<String> {
    let Ok(stmt) = db
        .prepare("SELECT old_pubkey FROM pubkey_aliases WHERE new_pubkey = ?1")
        .bind(&[JsValue::from_str(root)])
    else {
        return Vec::new();
    };
    match stmt.all().await {
        Ok(r) => r
            .results::<OldRow>()
            .unwrap_or_default()
            .into_iter()
            .map(|r| r.old_pubkey)
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Resolve the NIP-98 viewer, if a valid header was sent. Any failure is
/// treated as anonymous rather than an error: the card still renders, just
/// scoped to public zones.
async fn resolve_viewer(req: &Request, env: &Env) -> Option<String> {
    let header = req.headers().get("Authorization").ok().flatten()?;
    let url = req.url().ok()?.to_string();
    auth::verify_nip98_replay(&header, &url, "GET", None, env)
        .await
        .ok()
        .map(|t| t.pubkey)
}

// ---------------------------------------------------------------------------
// GET /api/profile-stats
// ---------------------------------------------------------------------------

pub async fn handle_profile_stats(req: &Request, env: &Env) -> Result<Response> {
    let url = req.url()?;
    let pubkey = url
        .query_pairs()
        .find(|(k, _)| k == "pubkey")
        .map(|(_, v)| v.to_lowercase())
        .unwrap_or_default();
    if !is_valid_pubkey(&pubkey) {
        return cors_json_response(env, &json!({ "error": "Invalid pubkey format" }), 400);
    }

    let db = match env.d1("DB") {
        Ok(db) => db,
        Err(_) => return cors_json_response(env, &json!({ "error": "Database unavailable" }), 500),
    };

    // Identity set: the live key plus every key it replaced.
    let superseded_by = successor_of(&db, &pubkey).await;
    let root = superseded_by.clone().unwrap_or_else(|| pubkey.clone());
    let mut identities = vec![root.clone()];
    for old in predecessors_of(&db, &root).await {
        if !identities.contains(&old) {
            identities.push(old);
        }
    }

    // Authored posts across the identity, newest first, capped.
    let kinds = POST_KINDS
        .iter()
        .map(|k| k.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "SELECT kind, created_at, tags FROM events \
         WHERE pubkey IN ({}) AND kind IN ({kinds}) \
         ORDER BY created_at DESC LIMIT ?{}",
        placeholders(1, identities.len()),
        identities.len() + 1
    );
    let mut binds: Vec<JsValue> = identities.iter().map(|p| JsValue::from_str(p)).collect();
    binds.push(JsValue::from_f64(MAX_ROWS as f64));
    let rows: Vec<PostRow> = match db.prepare(&sql).bind(&binds) {
        Ok(stmt) => match stmt.all().await {
            Ok(r) => r.results().unwrap_or_default(),
            Err(_) => return cors_json_response(env, &json!({ "error": "Query failed" }), 500),
        },
        Err(_) => return cors_json_response(env, &json!({ "error": "Bind failed" }), 500),
    };
    let truncated = rows.len() as u32 >= MAX_ROWS;

    // Zone bindings for every channel touched.
    let channel_ids: Vec<String> = rows
        .iter()
        .filter_map(|r| channel_of(r.kind as u32, &r.tags))
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    let channel_zone = load_channel_zones(&db, &channel_ids).await;

    // Viewer scope.
    let viewer = resolve_viewer(req, env).await;
    let (cohorts, is_admin) = match viewer.as_deref() {
        Some(pk) => trust::get_viewer_cohorts(pk, env).await,
        None => (Vec::new(), false),
    };
    let zones = ZoneConfig::load(env);
    let activity = aggregate(
        &rows,
        &channel_zone,
        |zone| viewer_can_read(&zones, zone, &cohorts, is_admin),
        TOP_CHANNELS,
    );

    // Names for the listed channels.
    let top_ids: Vec<String> = activity.top_channels.iter().map(|c| c.id.clone()).collect();
    let names = load_channel_names(&db, &top_ids).await;
    let top: Vec<serde_json::Value> = activity
        .top_channels
        .iter()
        .map(|c| {
            json!({
                "id": c.id,
                "name": names.get(&c.id),
                "zone": channel_zone.get(&c.id),
                "count": c.count,
                "last_at": c.last_at,
            })
        })
        .collect();

    cors_json_response(
        env,
        &json!({
            "pubkey": pubkey,
            "superseded_by": superseded_by,
            "identities": identities,
            "post_count": activity.post_count,
            "first_post_at": activity.first_post_at,
            "last_post_at": activity.last_post_at,
            "top_channels": top,
            "truncated": truncated,
            "scope": if viewer.is_some() { "viewer" } else { "public" },
        }),
        200,
    )
}

async fn load_channel_zones(db: &D1Database, ids: &[String]) -> HashMap<String, String> {
    #[derive(Deserialize)]
    struct Row {
        channel_id: String,
        zone: String,
    }
    let mut out = HashMap::new();
    for chunk in ids.chunks(90) {
        let sql = format!(
            "SELECT channel_id, zone FROM channel_zones WHERE channel_id IN ({})",
            placeholders(1, chunk.len())
        );
        let binds: Vec<JsValue> = chunk.iter().map(|s| JsValue::from_str(s)).collect();
        if let Ok(stmt) = db.prepare(&sql).bind(&binds) {
            if let Ok(r) = stmt.all().await {
                for row in r.results::<Row>().unwrap_or_default() {
                    out.insert(row.channel_id, row.zone);
                }
            }
        }
    }
    out
}

async fn load_channel_names(db: &D1Database, ids: &[String]) -> HashMap<String, String> {
    #[derive(Deserialize)]
    struct Row {
        id: String,
        content: String,
    }
    let mut out = HashMap::new();
    if ids.is_empty() {
        return out;
    }
    let sql = format!(
        "SELECT id, content FROM events WHERE kind = 40 AND id IN ({})",
        placeholders(1, ids.len())
    );
    let binds: Vec<JsValue> = ids.iter().map(|s| JsValue::from_str(s)).collect();
    if let Ok(stmt) = db.prepare(&sql).bind(&binds) {
        if let Ok(r) = stmt.all().await {
            for row in r.results::<Row>().unwrap_or_default() {
                if let Some(name) = channel_name(&row.content) {
                    out.insert(row.id, name);
                }
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// GET /api/profiles/successors
// ---------------------------------------------------------------------------

/// Public `{ "successors": { old_pubkey: new_pubkey } }` map.
pub async fn handle_successors(env: &Env) -> Result<Response> {
    #[derive(Deserialize)]
    struct Row {
        old_pubkey: String,
        new_pubkey: String,
    }
    let db = match env.d1("DB") {
        Ok(db) => db,
        Err(_) => return cors_json_response(env, &json!({ "error": "Database unavailable" }), 500),
    };
    let rows: Vec<Row> = match db
        .prepare("SELECT old_pubkey, new_pubkey FROM pubkey_aliases")
        .all()
        .await
    {
        Ok(r) => r.results().unwrap_or_default(),
        Err(_) => return cors_json_response(env, &json!({ "error": "Query failed" }), 500),
    };
    let map: serde_json::Map<String, serde_json::Value> = rows
        .into_iter()
        .map(|r| (r.old_pubkey, serde_json::Value::String(r.new_pubkey)))
        .collect();
    cors_json_response(env, &json!({ "successors": map }), 200)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(channel: &str, at: u64) -> PostRow {
        PostRow {
            kind: 42.0,
            created_at: at as f64,
            tags: format!(r#"[["e","{channel}","","root"],["p","ab"]]"#),
        }
    }

    fn note(at: u64) -> PostRow {
        PostRow {
            kind: 1.0,
            created_at: at as f64,
            tags: "[]".into(),
        }
    }

    const ZONES: &str = r#"[
        {"id":"public","required_cohorts":[],"visibility":"public"},
        {"id":"family","required_cohorts":["family"],"visibility":"hidden"},
        {"id":"business","required_cohorts":["business"],"visibility":"locked"}
    ]"#;

    fn bound() -> HashMap<String, String> {
        HashMap::from([
            ("fam".to_string(), "family".to_string()),
            ("biz".to_string(), "business".to_string()),
            ("pub".to_string(), "public".to_string()),
        ])
    }

    #[test]
    fn channel_of_takes_first_e_tag_of_kind_42_only() {
        assert_eq!(
            channel_of(42, r#"[["p","x"],["e","c1"],["e","c2"]]"#),
            Some("c1".into())
        );
        assert_eq!(channel_of(1, r#"[["e","c1"]]"#), None);
        assert_eq!(channel_of(42, "not json"), None);
        assert_eq!(channel_of(42, r#"[["e"]]"#), None);
    }

    #[test]
    fn anonymous_viewer_sees_public_and_unbound_only() {
        let zones = ZoneConfig::from_json(ZONES);
        let rows = vec![
            msg("pub", 10),
            msg("fam", 20),
            msg("biz", 30),
            msg("free", 40),
            note(5),
        ];
        let a = aggregate(
            &rows,
            &bound(),
            |z| viewer_can_read(&zones, z, &[], false),
            5,
        );
        assert_eq!(a.post_count, 3);
        assert_eq!(a.first_post_at, Some(5));
        assert_eq!(a.last_post_at, Some(40));
        let ids: Vec<&str> = a.top_channels.iter().map(|c| c.id.as_str()).collect();
        assert!(!ids.contains(&"fam") && !ids.contains(&"biz"));
    }

    #[test]
    fn member_sees_own_cohort_zone_but_not_others() {
        let zones = ZoneConfig::from_json(ZONES);
        let cohorts = vec!["family".to_string()];
        let rows = vec![msg("fam", 20), msg("biz", 30)];
        let a = aggregate(
            &rows,
            &bound(),
            |z| viewer_can_read(&zones, z, &cohorts, false),
            5,
        );
        assert_eq!(a.post_count, 1);
        assert_eq!(a.top_channels[0].id, "fam");
    }

    #[test]
    fn admin_sees_everything() {
        let zones = ZoneConfig::from_json(ZONES);
        let rows = vec![msg("fam", 20), msg("biz", 30)];
        let a = aggregate(
            &rows,
            &bound(),
            |z| viewer_can_read(&zones, z, &[], true),
            5,
        );
        assert_eq!(a.post_count, 2);
    }

    #[test]
    fn unknown_zone_binding_denies_non_admin() {
        let zones = ZoneConfig::from_json(ZONES);
        let map = HashMap::from([("x".to_string(), "nonexistent".to_string())]);
        let a = aggregate(
            &[msg("x", 1)],
            &map,
            |z| viewer_can_read(&zones, z, &[], false),
            5,
        );
        assert_eq!(a.post_count, 0);
        assert_eq!(a.first_post_at, None);
    }

    #[test]
    fn top_channels_rank_by_count_then_recency_and_truncate() {
        let zones = ZoneConfig::from_json(ZONES);
        let rows = vec![
            msg("a", 1),
            msg("a", 2),
            msg("b", 9),
            msg("b", 3),
            msg("c", 50),
            msg("d", 4),
        ];
        let a = aggregate(
            &rows,
            &HashMap::new(),
            |z| viewer_can_read(&zones, z, &[], false),
            3,
        );
        let ids: Vec<&str> = a.top_channels.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids, vec!["b", "a", "c"]);
        assert_eq!(a.top_channels[0].count, 2);
        assert_eq!(a.top_channels[0].last_at, 9);
    }

    #[test]
    fn channel_name_parses_kind40_content() {
        assert_eq!(
            channel_name(r#"{"name":" Games ","about":"x"}"#),
            Some("Games".into())
        );
        assert_eq!(channel_name(r#"{"name":""}"#), None);
        assert_eq!(channel_name("{}"), None);
        assert_eq!(channel_name("nope"), None);
    }
}
