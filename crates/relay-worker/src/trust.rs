//! Trust level computation and promotion logic.
//!
//! 4-level trust system:
//! - TL0 (Newcomer): Default on whitelist entry. Can read public, post in lobby.
//! - TL1 (Member): 3+ days active, 10+ posts read, 1+ post created. Full posting.
//! - TL2 (Regular): 14+ days, 50+ reads, 10+ posts, 0 mod actions. Create channels, pin own.
//! - TL3 (Trusted): Admin-granted only. Moderate, move topics, close threads.
//!
//! Hysteresis: TL2 demotion at 90% of threshold + 6-month inactivity.
//! TL3 never auto-demoted.

use serde::Deserialize;
use wasm_bindgen::JsValue;
use worker::Env;

use crate::auth;

// ---------------------------------------------------------------------------
// Trust level enum
// ---------------------------------------------------------------------------

/// Trust levels for community members.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum TrustLevel {
    /// TL0: Newcomer. Default on whitelist entry.
    Newcomer = 0,
    /// TL1: Member. Full posting in accessible zones.
    Member = 1,
    /// TL2: Regular. Create channels, pin own posts.
    Regular = 2,
    /// TL3: Trusted. Admin-granted only. Moderate, move topics.
    Trusted = 3,
}

impl TrustLevel {
    pub fn from_i32(v: i32) -> Self {
        match v {
            0 => Self::Newcomer,
            1 => Self::Member,
            2 => Self::Regular,
            3 => Self::Trusted,
            _ if v < 0 => Self::Newcomer,
            _ => Self::Trusted,
        }
    }

    pub fn as_i32(self) -> i32 {
        self as u8 as i32
    }
}

// ---------------------------------------------------------------------------
// Configurable thresholds
// ---------------------------------------------------------------------------

/// Thresholds for automatic trust level promotion.
///
/// Defaults match PRD v7.0 values. Can be overridden via the `settings` table.
#[allow(dead_code)]
pub struct TrustThresholds {
    pub tl1_days_active: i32,
    pub tl1_posts_read: i32,
    pub tl1_posts_created: i32,
    pub tl2_days_active: i32,
    pub tl2_posts_read: i32,
    pub tl2_posts_created: i32,
    /// Demotion threshold as a percentage (0-100) of the promotion threshold.
    pub demotion_hysteresis_pct: i32,
    /// Inactivity period in seconds before demotion is considered (6 months default).
    pub inactivity_demotion_secs: i64,
}

impl Default for TrustThresholds {
    fn default() -> Self {
        Self {
            tl1_days_active: 3,
            tl1_posts_read: 10,
            tl1_posts_created: 1,
            tl2_days_active: 14,
            tl2_posts_read: 50,
            tl2_posts_created: 10,
            demotion_hysteresis_pct: 90,
            inactivity_demotion_secs: 6 * 30 * 24 * 60 * 60, // ~6 months
        }
    }
}

/// D1 row type for reading a setting value.
#[derive(Deserialize)]
struct SettingRow {
    value: String,
}

impl TrustThresholds {
    /// Load thresholds from the D1 `settings` table, falling back to defaults
    /// for any missing keys.
    pub async fn load(env: &Env) -> Self {
        let mut thresholds = Self::default();

        let db = match env.d1("DB") {
            Ok(db) => db,
            Err(_) => return thresholds,
        };

        // Helper: read an integer setting.
        async fn read_int(db: &worker::D1Database, key: &str) -> Option<i32> {
            let stmt = db.prepare("SELECT value FROM settings WHERE key = ?1");
            let bound = stmt.bind(&[JsValue::from_str(key)]).ok()?;
            let row = bound.first::<SettingRow>(None).await.ok()??;
            row.value.parse().ok()
        }

        if let Some(v) = read_int(&db, "tl1_days_active").await {
            thresholds.tl1_days_active = v;
        }
        if let Some(v) = read_int(&db, "tl1_posts_read").await {
            thresholds.tl1_posts_read = v;
        }
        if let Some(v) = read_int(&db, "tl1_posts_created").await {
            thresholds.tl1_posts_created = v;
        }
        if let Some(v) = read_int(&db, "tl2_days_active").await {
            thresholds.tl2_days_active = v;
        }
        if let Some(v) = read_int(&db, "tl2_posts_read").await {
            thresholds.tl2_posts_read = v;
        }
        if let Some(v) = read_int(&db, "tl2_posts_created").await {
            thresholds.tl2_posts_created = v;
        }
        if let Some(v) = read_int(&db, "demotion_hysteresis").await {
            thresholds.demotion_hysteresis_pct = v;
        }

        thresholds
    }
}

// ---------------------------------------------------------------------------
// D1 row type for whitelist trust data
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[allow(dead_code)]
pub struct WhitelistTrustRow {
    pub pubkey: String,
    pub trust_level: i32,
    pub days_active: i32,
    pub posts_read: i32,
    pub posts_created: i32,
    pub mod_actions_against: i32,
    pub last_active_at: Option<f64>,
    pub trust_level_updated_at: Option<f64>,
    pub is_admin: Option<i32>,
}

// ---------------------------------------------------------------------------
// Pure computation: determine trust level from activity metrics
// ---------------------------------------------------------------------------

/// Compute the trust level a user qualifies for based on their activity.
///
/// This is a pure function with no side effects. TL3 is never computed
/// automatically -- it requires explicit admin grant.
pub fn compute_trust_level(
    days_active: i32,
    posts_read: i32,
    posts_created: i32,
    mod_actions_against: i32,
    thresholds: &TrustThresholds,
) -> TrustLevel {
    // TL2: 14+ days, 50+ reads, 10+ posts, 0 mod actions
    if days_active >= thresholds.tl2_days_active
        && posts_read >= thresholds.tl2_posts_read
        && posts_created >= thresholds.tl2_posts_created
        && mod_actions_against == 0
    {
        return TrustLevel::Regular;
    }

    // TL1: 3+ days, 10+ reads, 1+ post
    if days_active >= thresholds.tl1_days_active
        && posts_read >= thresholds.tl1_posts_read
        && posts_created >= thresholds.tl1_posts_created
    {
        return TrustLevel::Member;
    }

    TrustLevel::Newcomer
}

// ---------------------------------------------------------------------------
// Promotion check
// ---------------------------------------------------------------------------

/// Check whether a user should be promoted and update their trust level in D1.
///
/// Returns the new trust level. Does not demote -- see `check_demotion`.
/// TL3 users are never modified by this function.
pub async fn check_promotion(pubkey: &str, env: &Env) -> Option<TrustLevel> {
    let db = env.d1("DB").ok()?;
    let thresholds = TrustThresholds::load(env).await;

    let stmt = db.prepare(
        "SELECT pubkey, trust_level, days_active, posts_read, posts_created, \
         mod_actions_against, last_active_at, trust_level_updated_at, is_admin \
         FROM whitelist WHERE pubkey = ?1",
    );
    let row = stmt
        .bind(&[JsValue::from_str(pubkey)])
        .ok()?
        .first::<WhitelistTrustRow>(None)
        .await
        .ok()??;

    let current = TrustLevel::from_i32(row.trust_level);

    // Never auto-modify TL3 (admin-granted)
    if current == TrustLevel::Trusted {
        return Some(TrustLevel::Trusted);
    }

    let computed = compute_trust_level(
        row.days_active,
        row.posts_read,
        row.posts_created,
        row.mod_actions_against,
        &thresholds,
    );

    // Only promote, never demote through this path
    if computed > current {
        let now = auth::js_now_secs();
        let _ = db
            .prepare(
                "UPDATE whitelist SET trust_level = ?1, trust_level_updated_at = ?2 WHERE pubkey = ?3",
            )
            .bind(&[
                JsValue::from_f64(computed.as_i32() as f64),
                JsValue::from_f64(now as f64),
                JsValue::from_str(pubkey),
            ])
            .ok()?
            .run()
            .await;

        // Log the promotion in admin_log
        let _ = db
            .prepare(
                "INSERT INTO admin_log (actor_pubkey, action, target_pubkey, previous_value, new_value, reason, created_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            )
            .bind(&[
                JsValue::from_str("system"),
                JsValue::from_str("trust_level_change"),
                JsValue::from_str(pubkey),
                JsValue::from_str(&current.as_i32().to_string()),
                JsValue::from_str(&computed.as_i32().to_string()),
                JsValue::from_str("auto-promotion"),
                JsValue::from_f64(now as f64),
            ])
            .ok()?
            .run()
            .await;

        return Some(computed);
    }

    Some(current)
}

// ---------------------------------------------------------------------------
// Demotion check with hysteresis
// ---------------------------------------------------------------------------

/// Check whether a user should be demoted, applying 90% hysteresis.
///
/// Demotion only occurs when:
/// 1. Activity drops below 90% of the promotion threshold for the current level.
/// 2. The user has been inactive for 6+ months (`inactivity_demotion_secs`).
///
/// TL3 users are never auto-demoted. TL1 users can be demoted to TL0.
/// TL2 users can be demoted to TL1 or TL0.
#[allow(dead_code)]
pub async fn check_demotion(pubkey: &str, env: &Env) -> Option<TrustLevel> {
    let db = env.d1("DB").ok()?;
    let thresholds = TrustThresholds::load(env).await;

    let stmt = db.prepare(
        "SELECT pubkey, trust_level, days_active, posts_read, posts_created, \
         mod_actions_against, last_active_at, trust_level_updated_at, is_admin \
         FROM whitelist WHERE pubkey = ?1",
    );
    let row = stmt
        .bind(&[JsValue::from_str(pubkey)])
        .ok()?
        .first::<WhitelistTrustRow>(None)
        .await
        .ok()??;

    let current = TrustLevel::from_i32(row.trust_level);

    // TL3 never auto-demoted; TL0 cannot be demoted further
    if current == TrustLevel::Trusted || current == TrustLevel::Newcomer {
        return Some(current);
    }

    let now = auth::js_now_secs() as i64;

    // Check inactivity: only demote if last_active_at is old enough
    let last_active = row.last_active_at.unwrap_or(0.0) as i64;
    let inactive_duration = now - last_active;
    if inactive_duration < thresholds.inactivity_demotion_secs {
        return Some(current);
    }

    let hysteresis = thresholds.demotion_hysteresis_pct as f64 / 100.0;

    let new_level = match current {
        TrustLevel::Regular => {
            // Demote from TL2 if below 90% of TL2 thresholds
            let needs_demote = (row.days_active as f64)
                < (thresholds.tl2_days_active as f64 * hysteresis)
                || (row.posts_read as f64) < (thresholds.tl2_posts_read as f64 * hysteresis)
                || (row.posts_created as f64)
                    < (thresholds.tl2_posts_created as f64 * hysteresis)
                || row.mod_actions_against > 0;

            if needs_demote {
                // Check if they still qualify for TL1
                let qualifies_tl1 = compute_trust_level(
                    row.days_active,
                    row.posts_read,
                    row.posts_created,
                    row.mod_actions_against,
                    &thresholds,
                );
                if qualifies_tl1 >= TrustLevel::Member {
                    TrustLevel::Member
                } else {
                    TrustLevel::Newcomer
                }
            } else {
                current
            }
        }
        TrustLevel::Member => {
            // Demote from TL1 if below 90% of TL1 thresholds
            let needs_demote = (row.days_active as f64)
                < (thresholds.tl1_days_active as f64 * hysteresis)
                || (row.posts_read as f64) < (thresholds.tl1_posts_read as f64 * hysteresis)
                || (row.posts_created as f64)
                    < (thresholds.tl1_posts_created as f64 * hysteresis);

            if needs_demote {
                TrustLevel::Newcomer
            } else {
                current
            }
        }
        _ => current,
    };

    if new_level != current {
        let now_u64 = now as u64;
        let _ = db
            .prepare(
                "UPDATE whitelist SET trust_level = ?1, trust_level_updated_at = ?2 WHERE pubkey = ?3",
            )
            .bind(&[
                JsValue::from_f64(new_level.as_i32() as f64),
                JsValue::from_f64(now_u64 as f64),
                JsValue::from_str(pubkey),
            ])
            .ok()?
            .run()
            .await;

        // Log the demotion
        let _ = db
            .prepare(
                "INSERT INTO admin_log (actor_pubkey, action, target_pubkey, previous_value, new_value, reason, created_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            )
            .bind(&[
                JsValue::from_str("system"),
                JsValue::from_str("trust_level_change"),
                JsValue::from_str(pubkey),
                JsValue::from_str(&current.as_i32().to_string()),
                JsValue::from_str(&new_level.as_i32().to_string()),
                JsValue::from_str("auto-demotion (hysteresis)"),
                JsValue::from_f64(now_u64 as f64),
            ])
            .ok()?
            .run()
            .await;
    }

    Some(new_level)
}

// ---------------------------------------------------------------------------
// Activity tracking helpers
// ---------------------------------------------------------------------------

/// Increment the `posts_created` counter for a pubkey.
pub async fn increment_posts_created(pubkey: &str, env: &Env) {
    if let Ok(db) = env.d1("DB") {
        if let Ok(bound) = db
            .prepare("UPDATE whitelist SET posts_created = posts_created + 1 WHERE pubkey = ?1")
            .bind(&[JsValue::from_str(pubkey)])
        {
            let _ = bound.run().await;
        }
    }
}

/// Increment the `posts_read` counter for a pubkey.
#[allow(dead_code)]
pub async fn increment_posts_read(pubkey: &str, env: &Env) {
    if let Ok(db) = env.d1("DB") {
        if let Ok(bound) = db
            .prepare("UPDATE whitelist SET posts_read = posts_read + 1 WHERE pubkey = ?1")
            .bind(&[JsValue::from_str(pubkey)])
        {
            let _ = bound.run().await;
        }
    }
}

/// Update the `last_active_at` timestamp and increment `days_active` if the
/// last activity was on a different UTC day.
pub async fn update_last_active(pubkey: &str, env: &Env) {
    let now = auth::js_now_secs();
    let db = match env.d1("DB") {
        Ok(db) => db,
        Err(_) => return,
    };

    // Read current last_active_at to determine if we need to increment days_active
    let current_last_active: Option<f64> = {
        #[derive(Deserialize)]
        struct Row {
            last_active_at: Option<f64>,
        }
        let stmt = db.prepare("SELECT last_active_at FROM whitelist WHERE pubkey = ?1");
        match stmt.bind(&[JsValue::from_str(pubkey)]) {
            Ok(s) => match s.first::<Row>(None).await {
                Ok(Some(row)) => row.last_active_at,
                _ => None,
            },
            Err(_) => None,
        }
    };

    // Check if last activity was on a different UTC day
    let should_increment_days = match current_last_active {
        Some(last_ts) => {
            let last_day = (last_ts as u64) / 86400;
            let today = now / 86400;
            today > last_day
        }
        None => true, // First activity ever
    };

    if should_increment_days {
        if let Ok(bound) = db
            .prepare(
                "UPDATE whitelist SET last_active_at = ?1, days_active = days_active + 1 WHERE pubkey = ?2",
            )
            .bind(&[
                JsValue::from_f64(now as f64),
                JsValue::from_str(pubkey),
            ])
        {
            let _ = bound.run().await;
        }
    } else {
        if let Ok(bound) = db
            .prepare("UPDATE whitelist SET last_active_at = ?1 WHERE pubkey = ?2")
            .bind(&[
                JsValue::from_f64(now as f64),
                JsValue::from_str(pubkey),
            ])
        {
            let _ = bound.run().await;
        }
    }
}

// ---------------------------------------------------------------------------
// Trust level query helper (used by nip_handlers)
// ---------------------------------------------------------------------------

/// Read the trust level for a pubkey from D1. Returns TL0 if not found.
pub async fn get_trust_level(pubkey: &str, env: &Env) -> TrustLevel {
    let db = match env.d1("DB") {
        Ok(db) => db,
        Err(_) => return TrustLevel::Newcomer,
    };

    #[derive(Deserialize)]
    struct Row {
        trust_level: i32,
    }

    let stmt = db.prepare("SELECT trust_level FROM whitelist WHERE pubkey = ?1");
    match stmt.bind(&[JsValue::from_str(pubkey)]) {
        Ok(s) => match s.first::<Row>(None).await {
            Ok(Some(row)) => TrustLevel::from_i32(row.trust_level),
            _ => TrustLevel::Newcomer,
        },
        Err(_) => TrustLevel::Newcomer,
    }
}

// ---------------------------------------------------------------------------
// Suspension check helper
// ---------------------------------------------------------------------------

/// Check if a pubkey is currently suspended or silenced.
///
/// Returns `(suspended, silenced)`:
/// - `suspended`: the relay should reject all events from this pubkey.
/// - `silenced`: the relay should reject write events but allow reads.
pub async fn check_suspension(pubkey: &str, env: &Env) -> (bool, bool) {
    let db = match env.d1("DB") {
        Ok(db) => db,
        Err(_) => return (false, false),
    };

    #[derive(Deserialize)]
    struct Row {
        suspended_until: Option<f64>,
        silenced: i32,
    }

    let now = auth::js_now_secs();
    let stmt = db.prepare("SELECT suspended_until, silenced FROM whitelist WHERE pubkey = ?1");
    match stmt.bind(&[JsValue::from_str(pubkey)]) {
        Ok(s) => match s.first::<Row>(None).await {
            Ok(Some(row)) => {
                let suspended = row
                    .suspended_until
                    .map(|ts| (ts as u64) > now)
                    .unwrap_or(false);
                let silenced = row.silenced != 0;
                (suspended, silenced)
            }
            _ => (false, false),
        },
        Err(_) => (false, false),
    }
}

// ---------------------------------------------------------------------------
// Channel zone lookup
// ---------------------------------------------------------------------------

/// Look up the zone for a channel from the `channel_zones` table.
///
/// Returns `None` if the channel is not in the table (defaults to "home").
pub async fn get_channel_zone(channel_id: &str, env: &Env) -> Option<String> {
    let db = env.d1("DB").ok()?;

    #[derive(Deserialize)]
    struct Row {
        zone: String,
    }

    let stmt = db.prepare("SELECT zone FROM channel_zones WHERE channel_id = ?1");
    match stmt.bind(&[JsValue::from_str(channel_id)]) {
        Ok(s) => match s.first::<Row>(None).await {
            Ok(Some(row)) => Some(row.zone),
            _ => None,
        },
        Err(_) => None,
    }
}

/// Check whether a pubkey has access to a given zone based on their cohorts.
pub async fn has_zone_access(pubkey: &str, zone: &str, env: &Env) -> bool {
    let db = match env.d1("DB") {
        Ok(db) => db,
        Err(_) => return false,
    };

    #[derive(Deserialize)]
    struct Row {
        cohorts: String,
        is_admin: Option<i32>,
    }

    let stmt = db.prepare("SELECT cohorts, is_admin FROM whitelist WHERE pubkey = ?1");
    match stmt.bind(&[JsValue::from_str(pubkey)]) {
        Ok(s) => match s.first::<Row>(None).await {
            Ok(Some(row)) => {
                // Admins have access to all zones
                if row.is_admin.unwrap_or(0) == 1 {
                    return true;
                }

                let cohorts: Vec<String> =
                    serde_json::from_str(&row.cohorts).unwrap_or_default();

                match zone {
                    "home" | "lobby" => cohorts.iter().any(|c| {
                        matches!(
                            c.as_str(),
                            "home" | "lobby" | "approved" | "cross-access" | "members"
                        )
                    }),
                    "members" => cohorts.iter().any(|c| {
                        matches!(
                            c.as_str(),
                            "members"
                                | "business"
                                | "business-only"
                                | "trainers"
                                | "trainees"
                                | "ai-agents"
                                | "agent"
                                | "visionflow-full"
                                | "cross-access"
                        )
                    }),
                    "private" => cohorts.iter().any(|c| {
                        matches!(
                            c.as_str(),
                            "private"
                                | "private-only"
                                | "private-business"
                                | "cross-access"
                        )
                    }),
                    // Unknown zone: deny by default
                    _ => false,
                }
            }
            _ => false,
        },
        Err(_) => false,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_level_from_i32_roundtrip() {
        assert_eq!(TrustLevel::from_i32(0), TrustLevel::Newcomer);
        assert_eq!(TrustLevel::from_i32(1), TrustLevel::Member);
        assert_eq!(TrustLevel::from_i32(2), TrustLevel::Regular);
        assert_eq!(TrustLevel::from_i32(3), TrustLevel::Trusted);
    }

    #[test]
    fn trust_level_from_i32_clamps() {
        assert_eq!(TrustLevel::from_i32(-1), TrustLevel::Newcomer);
        assert_eq!(TrustLevel::from_i32(99), TrustLevel::Trusted);
    }

    #[test]
    fn trust_level_ordering() {
        assert!(TrustLevel::Newcomer < TrustLevel::Member);
        assert!(TrustLevel::Member < TrustLevel::Regular);
        assert!(TrustLevel::Regular < TrustLevel::Trusted);
    }

    #[test]
    fn compute_tl0_when_no_activity() {
        let t = TrustThresholds::default();
        assert_eq!(compute_trust_level(0, 0, 0, 0, &t), TrustLevel::Newcomer);
    }

    #[test]
    fn compute_tl1_at_threshold() {
        let t = TrustThresholds::default();
        assert_eq!(compute_trust_level(3, 10, 1, 0, &t), TrustLevel::Member);
    }

    #[test]
    fn compute_tl1_below_threshold() {
        let t = TrustThresholds::default();
        // Missing 1 day
        assert_eq!(compute_trust_level(2, 10, 1, 0, &t), TrustLevel::Newcomer);
        // Missing reads
        assert_eq!(compute_trust_level(3, 9, 1, 0, &t), TrustLevel::Newcomer);
        // Missing posts
        assert_eq!(compute_trust_level(3, 10, 0, 0, &t), TrustLevel::Newcomer);
    }

    #[test]
    fn compute_tl2_at_threshold() {
        let t = TrustThresholds::default();
        assert_eq!(compute_trust_level(14, 50, 10, 0, &t), TrustLevel::Regular);
    }

    #[test]
    fn compute_tl2_blocked_by_mod_actions() {
        let t = TrustThresholds::default();
        // All thresholds met but has mod actions
        assert_eq!(compute_trust_level(14, 50, 10, 1, &t), TrustLevel::Member);
    }

    #[test]
    fn compute_tl2_below_threshold_falls_to_tl1() {
        let t = TrustThresholds::default();
        // Meets TL1 but not TL2
        assert_eq!(compute_trust_level(13, 50, 10, 0, &t), TrustLevel::Member);
    }

    #[test]
    fn compute_never_returns_tl3() {
        let t = TrustThresholds::default();
        // Even with extreme values, compute never returns TL3
        assert_eq!(
            compute_trust_level(10000, 10000, 10000, 0, &t),
            TrustLevel::Regular
        );
    }

    #[test]
    fn default_thresholds_match_prd() {
        let t = TrustThresholds::default();
        assert_eq!(t.tl1_days_active, 3);
        assert_eq!(t.tl1_posts_read, 10);
        assert_eq!(t.tl1_posts_created, 1);
        assert_eq!(t.tl2_days_active, 14);
        assert_eq!(t.tl2_posts_read, 50);
        assert_eq!(t.tl2_posts_created, 10);
        assert_eq!(t.demotion_hysteresis_pct, 90);
    }

    #[test]
    fn as_i32_roundtrip() {
        for v in 0..=3 {
            let tl = TrustLevel::from_i32(v);
            assert_eq!(tl.as_i32(), v);
        }
    }
}
