//! Zone group bindings and epoch-key uniqueness (ADR-2028 decisions 4, 6, 8).
//!
//! Everything here is behind the `ZONE_GROUPS_ENABLED` worker var, exactly
//! `"true"`. With it absent the relay behaves as before. The module holds the
//! pure rules (zk claim parsing, hint check, uniqueness verdict, which epoch
//! keys a viewer may read), the SQL as constants, and the D1 calls.
//!
//! The zone-to-group binding comes from `ZONE_CONFIG` only; the optional fifth
//! element of a `zk` tag is a hint that is checked against it, never trusted.

use wasm_bindgen::JsValue;
use worker::D1Database;

use crate::zone_config::ZoneConfig;

/// Name of the worker var that switches the feature on.
pub(crate) const ZONE_GROUPS_ENABLED_VAR: &str = "ZONE_GROUPS_ENABLED";

/// Refusal for a `zk` hint that names a group other than the zone's bound one.
pub(crate) const REASON_GROUP_MISMATCH: &str = "blocked: zone group mismatch";
/// Refusal for a second, different key claiming a stored (zone, epoch).
pub(crate) const REASON_EPOCH_CONFLICT: &str = "blocked: zone epoch key conflict";
/// Refusal when the uniqueness store cannot be read or written.
pub(crate) const REASON_EPOCH_UNAVAILABLE: &str = "error: zone epoch key check unavailable";

/// The `zone_epoch_keys` table. Held identical to
/// `migrations/0013_zone_epoch_keys.sql` by a test.
pub(crate) const ZONE_EPOCH_KEYS_CREATE_SQL: &str = "CREATE TABLE IF NOT EXISTS zone_epoch_keys (\
    zone       TEXT NOT NULL, \
    epoch      INTEGER NOT NULL, \
    pubkey     TEXT NOT NULL, \
    first_seen INTEGER NOT NULL, \
    PRIMARY KEY (zone, epoch)\
)";

/// Claim a (zone, epoch) for a key. Atomic: a concurrent claimant loses
/// silently and is then judged by [`SELECT_EPOCH_KEY_SQL`].
pub(crate) const INSERT_EPOCH_KEY_SQL: &str = "INSERT INTO zone_epoch_keys \
    (zone, epoch, pubkey, first_seen) VALUES (?1, ?2, ?3, ?4) \
    ON CONFLICT(zone, epoch) DO NOTHING";

/// The first key stored for a (zone, epoch).
pub(crate) const SELECT_EPOCH_KEY_SQL: &str =
    "SELECT pubkey FROM zone_epoch_keys WHERE zone = ?1 AND epoch = ?2 LIMIT 1";

/// Whether the feature is on. Exact match on `"true"`.
pub(crate) fn zone_groups_enabled_var(raw: Option<&str>) -> bool {
    raw == Some("true")
}

/// One `zk` claim on an event, for the zone the event is bound to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ZkClaim {
    /// Epoch, always `>= 1`.
    pub epoch: u32,
    /// The zone epoch public key (`zk[3]`), lowercase hex.
    pub pubkey: String,
    /// The optional fifth element (group pubkey hint), lowercase.
    pub hint: Option<String>,
}

fn hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Most `zk` claims honoured on one event. A legitimate post carries exactly
/// one; the cap bounds how many permanent `zone_epoch_keys` rows a single event
/// can create, so a member cannot post hundreds of junk claims at once (Phase 4
/// review finding 1, defence-in-depth; the real fix, an owner-only epoch
/// binding, is the hard pre-flag-on blocker recorded in ADR-2028).
pub(crate) const MAX_ZK_CLAIMS_PER_EVENT: usize = 8;

/// The `zk` claims on `tags` that name `zone`. Tags for other zones, epoch 0,
/// an unparseable epoch or a malformed key are ignored: they claim nothing. At
/// most [`MAX_ZK_CLAIMS_PER_EVENT`] are honoured.
pub(crate) fn zk_claims(zone: &str, tags: &[Vec<String>]) -> Vec<ZkClaim> {
    tags.iter()
        .filter(|t| t.len() >= 4 && t[0] == "zk" && t[1] == zone && hex64(&t[3]))
        .filter_map(|t| {
            let epoch = t[2].parse::<u32>().ok().filter(|e| *e >= 1)?;
            Some(ZkClaim {
                epoch,
                pubkey: t[3].to_ascii_lowercase(),
                hint: t.get(4).map(|h| h.to_ascii_lowercase()),
            })
        })
        .take(MAX_ZK_CLAIMS_PER_EVENT)
        .collect()
}

/// Decision 4: a hint must match the zone's bound group. Absent hint, or a zone
/// with no bound group, passes. With the feature off nothing is checked.
pub(crate) fn hint_verdict(
    enabled: bool,
    zones: &ZoneConfig,
    zone: &str,
    claims: &[ZkClaim],
) -> Result<(), &'static str> {
    if !enabled {
        return Ok(());
    }
    let Some(group) = zones.group_for(zone) else {
        return Ok(());
    };
    if claims
        .iter()
        .any(|c| c.hint.as_deref().is_some_and(|h| h != group))
    {
        Err(REASON_GROUP_MISMATCH)
    } else {
        Ok(())
    }
}

/// Decision 6: the stored key (if any) against the claimed one.
pub(crate) fn epoch_verdict(stored: Option<&str>, claimed: &str) -> Result<(), &'static str> {
    match stored {
        Some(s) if !s.eq_ignore_ascii_case(claimed) => Err(REASON_EPOCH_CONFLICT),
        _ => Ok(()),
    }
}

/// First key stored for (zone, epoch). `Err` is a D1 failure, `Ok(None)` is free.
pub(crate) async fn lookup_epoch_key(
    db: &D1Database,
    zone: &str,
    epoch: u32,
) -> Result<Option<String>, ()> {
    #[derive(serde::Deserialize)]
    struct Row {
        pubkey: String,
    }
    let stmt = db
        .prepare(SELECT_EPOCH_KEY_SQL)
        .bind(&[JsValue::from_str(zone), JsValue::from_f64(f64::from(epoch))])
        .map_err(|_| ())?;
    stmt.first::<Row>(None)
        .await
        .map(|r| r.map(|r| r.pubkey.to_ascii_lowercase()))
        .map_err(|_| ())
}

/// Claim (zone, epoch) for `pubkey` and return the key that now holds it. The
/// insert is conflict-ignoring, so two racing claimants both read the winner.
pub(crate) async fn claim_epoch_key(
    db: &D1Database,
    zone: &str,
    epoch: u32,
    pubkey: &str,
    now: u64,
) -> Result<String, ()> {
    let ins = db
        .prepare(INSERT_EPOCH_KEY_SQL)
        .bind(&[
            JsValue::from_str(zone),
            JsValue::from_f64(f64::from(epoch)),
            JsValue::from_str(pubkey),
            JsValue::from_f64(now as f64),
        ])
        .map_err(|_| ())?;
    ins.run().await.map_err(|_| ())?;
    lookup_epoch_key(db, zone, epoch).await?.ok_or(())
}

/// Decision 8, read side: from every registered epoch row `(key, zone)`, the
/// keys whose wraps this viewer may read: the viewer is signed in and passes
/// the zone read rule (public-read zone, admin, or a required cohort).
pub(crate) fn epoch_keys_for_viewer(
    rows: &[(String, String)],
    zones: &ZoneConfig,
    authed: bool,
    cohorts: &[String],
    is_admin: bool,
) -> Vec<String> {
    if !authed {
        return Vec::new();
    }
    rows.iter()
        .filter(|(_, zone)| {
            zones.is_public_read(zone) || is_admin || zones.cohorts_can_read(zone, cohorts)
        })
        .map(|(k, _)| k.to_ascii_lowercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::{params, Connection};

    const K1: &str = "11111111111111111111111111111111111111111111111111111111111111aa";
    const K2: &str = "22222222222222222222222222222222222222222222222222222222222222bb";
    const GROUP: &str = "33333333333333333333333333333333333333333333333333333333333333cc";

    fn tag(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    fn zones() -> ZoneConfig {
        ZoneConfig::from_json(&format!(
            r#"[{{"id":"family","required_cohorts":["family"],"group_pubkey":"{GROUP}"}},
                {{"id":"friends","required_cohorts":["friends"]}},
                {{"id":"open","required_cohorts":[],"visibility":"public"}}]"#
        ))
    }

    fn db() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute(ZONE_EPOCH_KEYS_CREATE_SQL, []).unwrap();
        c
    }

    /// The same two statements `claim_epoch_key` runs, with the verdict.
    fn claim(c: &Connection, zone: &str, epoch: u32, pk: &str) -> Result<(), &'static str> {
        c.execute(INSERT_EPOCH_KEY_SQL, params![zone, epoch, pk, 1])
            .unwrap();
        let stored: String = c
            .query_row(SELECT_EPOCH_KEY_SQL, params![zone, epoch], |r| r.get(0))
            .unwrap();
        epoch_verdict(Some(&stored), pk)
    }

    #[test]
    fn flag_is_exact_true_only() {
        assert!(zone_groups_enabled_var(Some("true")));
        for v in [
            None,
            Some(""),
            Some("false"),
            Some("TRUE"),
            Some(" true"),
            Some("1"),
        ] {
            assert!(!zone_groups_enabled_var(v), "{v:?}");
        }
    }

    #[test]
    fn migration_matches_the_create_constant() {
        let sql = include_str!("../migrations/0013_zone_epoch_keys.sql");
        let squash = |s: &str| s.split_whitespace().collect::<Vec<_>>().join("");
        assert!(squash(sql).contains(&squash(ZONE_EPOCH_KEYS_CREATE_SQL)));
    }

    #[test]
    fn claims_ignore_other_zones_epoch_zero_and_bad_keys() {
        let tags = vec![
            tag(&["zk", "family", "0", K1]),
            tag(&["zk", "other", "1", K1]),
            tag(&["zk", "family", "x", K1]),
            tag(&["zk", "family", "1", "abcd"]),
            tag(&["zk", "family", "2", &K1.to_uppercase()]),
        ];
        let c = zk_claims("family", &tags);
        assert_eq!(c.len(), 1);
        assert_eq!((c[0].epoch, c[0].pubkey.as_str()), (2, K1));
    }

    #[test]
    fn zk_claims_are_capped_per_event() {
        // One event carrying many valid claims is honoured only up to the cap,
        // so it cannot create an unbounded number of zone_epoch_keys rows.
        let tags: Vec<Vec<String>> = (1..=50)
            .map(|e| tag(&["zk", "family", &e.to_string(), K1]))
            .collect();
        assert_eq!(zk_claims("family", &tags).len(), MAX_ZK_CLAIMS_PER_EVENT);
    }

    #[test]
    fn hint_matching_passes_mismatch_refused_absent_passes() {
        let z = zones();
        let with = |h: &str| zk_claims("family", &[tag(&["zk", "family", "1", K1, h])]);
        assert_eq!(hint_verdict(true, &z, "family", &with(GROUP)), Ok(()));
        assert_eq!(
            hint_verdict(true, &z, "family", &with(&GROUP.to_uppercase())),
            Ok(())
        );
        assert_eq!(
            hint_verdict(true, &z, "family", &with(K2)),
            Err(REASON_GROUP_MISMATCH)
        );
        let none = zk_claims("family", &[tag(&["zk", "family", "1", K1])]);
        assert_eq!(hint_verdict(true, &z, "family", &none), Ok(()));
        // A zone with no bound group has nothing to mismatch.
        assert_eq!(hint_verdict(true, &z, "friends", &with(K2)), Ok(()));
    }

    #[test]
    fn flag_off_ignores_the_hint() {
        let c = zk_claims("family", &[tag(&["zk", "family", "1", K1, K2])]);
        assert_eq!(hint_verdict(false, &zones(), "family", &c), Ok(()));
    }

    #[test]
    fn first_key_is_stored_second_different_refused_same_accepted() {
        let c = db();
        assert_eq!(claim(&c, "family", 1, K1), Ok(()));
        assert_eq!(claim(&c, "family", 1, K2), Err(REASON_EPOCH_CONFLICT));
        assert_eq!(claim(&c, "family", 1, K1), Ok(()));
        // The loser did not overwrite the winner; other epochs and zones are free.
        let stored: String = c
            .query_row(SELECT_EPOCH_KEY_SQL, params!["family", 1], |r| r.get(0))
            .unwrap();
        assert_eq!(stored, K1);
        assert_eq!(claim(&c, "family", 2, K2), Ok(()));
        assert_eq!(claim(&c, "friends", 1, K2), Ok(()));
    }

    #[test]
    fn epoch_zero_is_never_a_claim() {
        assert!(zk_claims("family", &[tag(&["zk", "family", "0", K1])]).is_empty());
    }

    fn rows() -> Vec<(String, String)> {
        vec![
            ("EE01".into(), "family".into()),
            ("ee02".into(), "friends".into()),
            ("ee03".into(), "open".into()),
        ]
    }

    #[test]
    fn epoch_keys_go_to_cohort_members_only() {
        let z = zones();
        let fam = vec!["family".to_string()];
        assert_eq!(
            epoch_keys_for_viewer(&rows(), &z, true, &fam, false),
            vec!["ee01".to_string(), "ee03".to_string()]
        );
        // A non-member sees only the public-read zone's key.
        assert_eq!(
            epoch_keys_for_viewer(&rows(), &z, true, &[], false),
            vec!["ee03".to_string()]
        );
        assert!(epoch_keys_for_viewer(&rows(), &z, false, &fam, true).is_empty());
        assert_eq!(epoch_keys_for_viewer(&rows(), &z, true, &[], true).len(), 3);
    }
}
