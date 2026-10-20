//! Pure key selection over the zone keys a device holds (ADR-2028 decision 6).
//!
//! One number space per zone. Two keys claiming one `(zone, epoch)` with
//! different pubkeys make that epoch *inconsistent*, and while any epoch of a
//! zone is inconsistent there is no send key. The genesis epoch 0 of a derived
//! group is record-only, and a derived epoch at or below the highest legacy
//! epoch is never written to: the first live derived epoch is `n + 1` after
//! legacy `n`. Legacy keys (no group) behave exactly as before.
//!
//! Kept free of reactive and browser types so the rules run under plain
//! `cargo test`.

use std::collections::{BTreeMap, BTreeSet};

use super::ZoneKey;

/// Why no send key can be chosen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SendKeyError {
    /// These epochs of the zone are claimed by more than one pubkey. Sending
    /// stays refused until the conflict is resolved.
    Inconsistent(Vec<u32>),
}

impl std::fmt::Display for SendKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Inconsistent(epochs) => write!(
                f,
                "Two different keys claim epoch {} of this zone. Posting is paused until the zone owner resolves it.",
                epochs
                    .iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }
}

impl std::error::Error for SendKeyError {}

/// Epochs of `zone` claimed by more than one pubkey, across legacy and
/// derived keys alike, ascending.
pub fn inconsistent_epochs<'a>(
    keys: impl IntoIterator<Item = &'a ZoneKey>,
    zone: &str,
) -> Vec<u32> {
    let mut claims: BTreeMap<u32, BTreeSet<&str>> = BTreeMap::new();
    for k in keys.into_iter().filter(|k| k.zone == zone) {
        claims.entry(k.epoch).or_default().insert(k.pubkey.as_str());
    }
    claims
        .into_iter()
        .filter(|(_, pks)| pks.len() > 1)
        .map(|(e, _)| e)
        .collect()
}

/// The key to write the next message under, or `Ok(None)` when the zone has
/// no usable key. `Err` only while the epoch we would actually send at is
/// itself claimed by more than one pubkey.
///
/// Eligible: every legacy key, and derived keys at an epoch above both 0 and
/// the highest legacy epoch. The highest eligible epoch wins. A conflict at a
/// lower epoch does NOT block sending: NIP-171 resolves a conflict by issuing a
/// higher consistent epoch, and the owner's next rotation into a clean higher
/// epoch clears the lock with no delete mechanism. Only a contested *send*
/// epoch (the top one, with nothing higher to rotate to) pauses sending.
pub fn send_key<'a>(
    keys: impl IntoIterator<Item = &'a ZoneKey> + Clone,
    zone: &str,
) -> Result<Option<ZoneKey>, SendKeyError> {
    let mine = || keys.clone().into_iter().filter(|k| k.zone == zone);
    let legacy_max = mine()
        .filter(|k| k.group.is_none())
        .map(|k| k.epoch)
        .max()
        .unwrap_or(0);
    let candidate = mine()
        .filter(|k| k.group.is_none() || (k.epoch > 0 && k.epoch > legacy_max))
        .max_by_key(|k| k.epoch)
        .cloned();
    if let Some(ref c) = candidate {
        if inconsistent_epochs(keys.clone(), zone).contains(&c.epoch) {
            return Err(SendKeyError::Inconsistent(vec![c.epoch]));
        }
    }
    Ok(candidate)
}

/// The key for `(zone, epoch)` the read path should try, deterministically:
/// legacy before derived, then lowest pubkey. Only ambiguous while the epoch
/// is inconsistent, when [`send_key`] refuses anyway.
pub fn read_key<'a>(
    keys: impl IntoIterator<Item = &'a ZoneKey>,
    zone: &str,
    epoch: u32,
) -> Option<ZoneKey> {
    keys.into_iter()
        .filter(|k| k.zone == zone && k.epoch == epoch)
        .min_by(|a, b| (a.group.is_some(), &a.pubkey).cmp(&(b.group.is_some(), &b.pubkey)))
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(zone: &str, group: Option<&str>, epoch: u32, pk: &str) -> ZoneKey {
        ZoneKey {
            zone: zone.into(),
            epoch,
            secret: "11".repeat(32),
            pubkey: pk.repeat(64),
            granted_by: "ad".repeat(32),
            received_at: 0,
            group: group.map(|g| g.repeat(64)),
        }
    }

    #[test]
    fn legacy_keys_behave_as_before_highest_epoch_wins() {
        let ks = [
            key("z", None, 1, "a"),
            key("z", None, 2, "b"),
            key("y", None, 9, "c"),
        ];
        assert_eq!(send_key(&ks, "z").unwrap().unwrap().epoch, 2);
        assert_eq!(send_key(&ks, "none").unwrap(), None);
    }

    #[test]
    fn two_pubkeys_for_one_epoch_refuse_sending() {
        let ks = [
            key("z", None, 1, "a"),
            key("z", None, 2, "b"),
            key("z", None, 2, "c"),
        ];
        assert_eq!(inconsistent_epochs(&ks, "z"), vec![2]);
        assert_eq!(send_key(&ks, "z"), Err(SendKeyError::Inconsistent(vec![2])));
        // Other zones are unaffected.
        assert!(send_key(&ks, "elsewhere").unwrap().is_none());
    }

    #[test]
    fn an_inconsistency_below_the_send_epoch_does_not_block() {
        // Epoch 1 is contested (a and b) but epoch 2 is clean and higher, so a
        // message sends at epoch 2. NIP-171 resolves the conflict by the higher
        // epoch; a stale lower conflict must not freeze the zone (ADR-2028).
        let ks = [
            key("z", None, 1, "a"),
            key("z", None, 1, "b"),
            key("z", None, 2, "c"),
        ];
        assert_eq!(send_key(&ks, "z").unwrap().unwrap().epoch, 2);
    }

    #[test]
    fn a_contested_top_epoch_pauses_sending() {
        // Nothing higher than the contested epoch to rotate to: refuse.
        let ks = [key("z", None, 2, "a"), key("z", None, 2, "b")];
        assert_eq!(send_key(&ks, "z"), Err(SendKeyError::Inconsistent(vec![2])));
    }

    #[test]
    fn legacy_and_derived_claiming_one_epoch_is_a_conflict() {
        let ks = [key("z", None, 3, "a"), key("z", Some("g"), 3, "b")];
        assert!(send_key(&ks, "z").is_err());
    }

    #[test]
    fn the_same_key_held_twice_is_not_a_conflict() {
        let ks = [key("z", Some("g"), 2, "a"), key("z", Some("g"), 2, "a")];
        assert_eq!(send_key(&ks, "z").unwrap().unwrap().epoch, 2);
    }

    #[test]
    fn derived_epoch_zero_is_never_chosen_above_legacy() {
        let ks = [
            key("z", None, 1, "a"),
            key("z", None, 3, "b"),
            key("z", Some("g"), 0, "c"),
        ];
        let chosen = send_key(&ks, "z").unwrap().unwrap();
        assert_eq!((chosen.epoch, chosen.group), (3, None));
    }

    #[test]
    fn derived_epochs_at_or_below_legacy_max_are_not_written_to() {
        let ks = [
            key("z", None, 3, "a"),
            key("z", Some("g"), 2, "b"),
            key("z", Some("g"), 3, "a"),
        ];
        assert_eq!(send_key(&ks, "z").unwrap().unwrap().group, None);
    }

    #[test]
    fn first_live_derived_epoch_is_n_plus_one() {
        let ks = [
            key("z", None, 3, "a"),
            key("z", Some("g"), 0, "c"),
            key("z", Some("g"), 4, "d"),
        ];
        let chosen = send_key(&ks, "z").unwrap().unwrap();
        assert_eq!(chosen.epoch, 4);
        assert_eq!(chosen.group, Some("g".repeat(64)));
    }

    #[test]
    fn a_zone_holding_only_derived_epoch_zero_has_no_send_key() {
        let ks = [key("z", Some("g"), 0, "c")];
        assert_eq!(send_key(&ks, "z").unwrap(), None);
    }

    #[test]
    fn a_fresh_derived_zone_starts_at_epoch_one() {
        let ks = [key("z", Some("g"), 0, "c"), key("z", Some("g"), 1, "d")];
        assert_eq!(send_key(&ks, "z").unwrap().unwrap().epoch, 1);
    }

    #[test]
    fn read_key_is_deterministic_legacy_first() {
        let ks = [key("z", Some("g"), 2, "a"), key("z", None, 2, "b")];
        assert_eq!(read_key(&ks, "z", 2).unwrap().group, None);
        assert!(read_key(&ks, "z", 5).is_none());
    }

    #[test]
    fn store_id_separates_conflicting_keys_only_with_the_flag_on() {
        let (a, b) = (key("z", None, 2, "a"), key("z", None, 2, "b"));
        // Flag on: pubkey and group join the id, so conflicting keys separate.
        assert_ne!(a.store_id_with(true), b.store_id_with(true));
        assert_ne!(
            a.store_id_with(true),
            key("z", Some("g"), 2, "a").store_id_with(true)
        );
        // Flag off (the shipped default): legacy <zone>:<epoch>, so a second
        // grant for one epoch collapses onto the first (last-write-wins).
        assert_eq!(a.store_id_with(false), b.store_id_with(false));
        assert_eq!(a.store_id_with(false), "z:2");
    }
}
