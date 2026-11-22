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
    // A key still pending delivery decrypts but is never sent under: until its
    // grants land, sending under it would make the post readable only here.
    // A key pending in any row (a ticket copy of it lands under another store
    // id) is held back as a whole, matched on epoch and key pubkey.
    let pending: Vec<(u32, String)> = keys
        .clone()
        .into_iter()
        .filter(|k| k.zone == zone && k.pending_delivery)
        .map(|k| (k.epoch, k.pubkey.clone()))
        .collect();
    let mine = || {
        keys.clone().into_iter().filter(|k| {
            k.zone == zone
                && !k.pending_delivery
                && !pending.iter().any(|(e, p)| *e == k.epoch && *p == k.pubkey)
        })
    };
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

/// How far beyond the next local epoch a post's `zk` epoch may be and still
/// be trusted when choosing a new key's epoch. Each rotation adds one; a
/// device that missed a few is normal, a jump past this is not.
pub const MAX_EPOCH_SKIP: u32 = 8;

/// What Create / Rotate should do for a zone.
#[derive(Debug, PartialEq, Eq)]
pub enum MintPlan {
    /// The message sync has not finished: a cold device has seen no posts and
    /// could otherwise mint an epoch number already in use.
    Wait,
    /// Refused, with the reason: this device holds no key for the zone while
    /// its posts use an epoch too far ahead to place a new key safely.
    Blocked(String),
    /// Mint `epoch`; `note` explains a choice the admin should know about.
    Mint { epoch: u32, note: Option<String> },
}

/// Choose the epoch for a new key. `held_latest` is the newest epoch the
/// signed-in identity holds for the zone; `device_latest` the newest epoch any
/// row on this browser holds for it, whatever account it belongs to (epoch
/// numbers only: another account's key may be pending delivery, so it is in no
/// post yet); `seen` is every epoch named by a post of the zone (with one post
/// id each). A device behind the zone mints *above* what is in use, never a
/// second key for an epoch members or another account already hold, and a
/// forged far-ahead epoch is reported and ignored rather than obeyed, so no
/// single post can stop or steer a rotation.
pub fn plan_mint(
    held_latest: Option<u32>,
    device_latest: Option<u32>,
    seen: &[(u32, String)],
    synced: bool,
) -> MintPlan {
    if !synced {
        return MintPlan::Wait;
    }
    let mut notes = Vec::new();
    // Another account's rows raise the floor; they are local, so trusted like
    // the identity's own and never subject to the far-ahead rule.
    let floor = match (held_latest, device_latest) {
        (h, Some(d)) if h.is_none_or(|h| d > h) => {
            notes.push(format!(
                "Another account on this browser holds key epoch {d} of this zone. \
                 The new key will be above it, so the two cannot clash."
            ));
            Some(d)
        }
        (h, _) => h,
    };
    let base = floor.map_or(1, |e| e.saturating_add(1));
    let ceiling = base.saturating_add(MAX_EPOCH_SKIP);
    // The highest believable epoch in use, and the highest ignored one: a
    // far-ahead post must not hide a real epoch below it.
    let in_use = seen
        .iter()
        .filter(|(e, _)| *e < ceiling)
        .map(|(e, _)| *e)
        .max();
    let ignored = seen
        .iter()
        .filter(|(e, _)| *e >= ceiling)
        .max_by_key(|(e, _)| *e);
    // A device with no key for the zone and only far-ahead epochs in sight
    // cannot tell a forgery from a zone that has rotated many times: minting
    // epoch 1 there could clash with the zone's real epoch 1.
    if floor.is_none() && in_use.is_none() {
        if let Some((e, ev)) = ignored {
            return MintPlan::Blocked(format!(
                "This device holds no key for this zone, and post {}… names key epoch {e}. \
                 Create or rotate from a device that holds the zone's keys, or have its admin grant them to you. \
                 If the zone has never had a key, that post is not genuine: delete it, then reload.",
                ev.get(..12).unwrap_or(ev)
            ));
        }
    }
    let epoch = match in_use {
        Some(max) if max >= base => {
            notes.push(format!(
                "Messages here already use key epoch {max}, which this device does not hold. \
                 The new key will be epoch {}, so it cannot clash with the one members have.",
                max.saturating_add(1)
            ));
            max.saturating_add(1)
        }
        _ => base,
    };
    if let Some((e, ev)) = ignored {
        notes.push(format!(
            "Ignoring key epoch {e} named by post {}…: too far ahead of this device's keys to be genuine.",
            ev.get(..12).unwrap_or(ev)
        ));
    }
    MintPlan::Mint {
        epoch,
        note: (!notes.is_empty()).then(|| notes.join(" ")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minting_waits_for_the_message_sync() {
        assert_eq!(plan_mint(Some(2), None, &[], false), MintPlan::Wait);
        assert_eq!(
            plan_mint(None, None, &[], true),
            MintPlan::Mint {
                epoch: 1,
                note: None
            }
        );
    }

    #[test]
    fn a_device_behind_the_zone_mints_above_the_epoch_in_use() {
        // The house key held epochs 1-2 while posts used epoch 3.
        match plan_mint(Some(2), None, &[(3, "ev".to_string())], true) {
            MintPlan::Mint { epoch, note } => {
                assert_eq!(epoch, 4, "never a second epoch 3");
                assert!(note.unwrap().contains("epoch 3"));
            }
            p => panic!("{p:?}"),
        }
        // A cold device that holds nothing never mints epoch 1 over a used one.
        assert!(matches!(
            plan_mint(None, None, &[(3, "ev".to_string())], true),
            MintPlan::Mint { epoch: 4, .. }
        ));
        assert_eq!(
            plan_mint(Some(3), None, &[(3, "ev".to_string())], true),
            MintPlan::Mint {
                epoch: 4,
                note: None
            }
        );
    }

    #[test]
    fn a_forged_far_ahead_epoch_is_ignored_not_obeyed() {
        match plan_mint(
            Some(2),
            None,
            &[(u32::MAX, "forgedevent0001".to_string())],
            true,
        ) {
            MintPlan::Mint { epoch, note } => {
                assert_eq!(epoch, 3, "rotation still proceeds at the next real epoch");
                assert!(note.unwrap().contains("forgedevent0"));
            }
            p => panic!("{p:?}"),
        }
        // Held 2, so the next epoch is 3: a post's epoch is trusted up to
        // 3 + MAX_EPOCH_SKIP - 1 and ignored from 3 + MAX_EPOCH_SKIP.
        let next = 3;
        assert!(matches!(
            plan_mint(
                Some(2),
                None,
                &[(next + MAX_EPOCH_SKIP, "e".to_string())],
                true
            ),
            MintPlan::Mint { epoch: 3, .. }
        ));
        assert!(
            matches!(plan_mint(Some(2), None, &[(next + MAX_EPOCH_SKIP - 1, "e".to_string())], true), MintPlan::Mint { epoch, .. } if epoch == next + MAX_EPOCH_SKIP)
        );
    }

    #[test]
    fn a_far_ahead_post_cannot_hide_the_real_epoch_in_use() {
        // A member posts a forged epoch 999 beside the real epoch 3.
        let seen = [(3, "real".to_string()), (999, "forgedforged0".to_string())];
        match plan_mint(Some(2), None, &seen, true) {
            MintPlan::Mint { epoch, note } => {
                assert_eq!(epoch, 4, "still above the real epoch in use");
                let note = note.unwrap();
                assert!(note.contains("epoch 3") && note.contains("forgedforged"));
            }
            p => panic!("{p:?}"),
        }
    }

    #[test]
    fn a_keyless_device_never_mints_under_far_ahead_epochs() {
        let seen = [(12, "farpostid0001".to_string())];
        match plan_mint(None, None, &seen, true) {
            MintPlan::Blocked(why) => assert!(why.contains("farpostid000"), "names the post"),
            p => panic!("{p:?}"),
        }
        // With a believable epoch in view it mints above it, as before.
        assert!(matches!(
            plan_mint(None, None, &[(3, "e".to_string())], true),
            MintPlan::Mint { epoch: 4, .. }
        ));
        // A device holding keys is never blocked by a far-ahead post.
        assert!(matches!(
            plan_mint(Some(2), None, &seen, true),
            MintPlan::Mint { epoch: 3, .. }
        ));
    }

    #[test]
    fn another_accounts_epoch_on_this_browser_raises_the_mint() {
        // A holds a pending epoch 4 (in no post yet); B holds epoch 3.
        match plan_mint(Some(3), Some(4), &[], true) {
            MintPlan::Mint { epoch, note } => {
                assert_eq!(epoch, 5, "never a second epoch 4");
                assert!(note.unwrap().contains("Another account"));
            }
            p => panic!("{p:?}"),
        }
        // B holds nothing: still above A's epoch, and not blocked as keyless.
        assert!(matches!(
            plan_mint(None, Some(4), &[(40, "far".to_string())], true),
            MintPlan::Mint { epoch: 5, .. }
        ));
        // The identity's own keys alone add no note.
        assert_eq!(
            plan_mint(Some(3), Some(3), &[], true),
            MintPlan::Mint {
                epoch: 4,
                note: None
            }
        );
        // A post above both still wins.
        assert!(matches!(
            plan_mint(Some(3), Some(4), &[(6, "ev".to_string())], true),
            MintPlan::Mint { epoch: 7, .. }
        ));
        assert_eq!(plan_mint(Some(3), Some(4), &[], false), MintPlan::Wait);
    }

    #[test]
    fn a_key_pending_delivery_is_never_the_send_key() {
        let mut new = key("zone3", None, 3, "c");
        new.pending_delivery = true;
        let keys = [key("zone3", None, 2, "b"), new.clone()];
        let sent = send_key(keys.iter(), "zone3").unwrap().unwrap();
        assert_eq!(sent.epoch, 2, "the rotation is not adopted before delivery");
        new.pending_delivery = false;
        let keys = [key("zone3", None, 2, "b"), new];
        assert_eq!(send_key(keys.iter(), "zone3").unwrap().unwrap().epoch, 3);
    }

    #[test]
    fn a_ticket_copy_of_a_pending_key_is_held_back_too() {
        let mut pending = key("zone3", None, 3, "c");
        pending.pending_delivery = true;
        let mut ticket_copy = key("zone3", Some("g"), 3, "c");
        ticket_copy.pubkey = pending.pubkey.clone();
        let keys = [key("zone3", None, 2, "b"), pending, ticket_copy];
        assert_eq!(send_key(keys.iter(), "zone3").unwrap().unwrap().epoch, 2);
    }

    #[test]
    fn a_zone_whose_only_key_is_pending_has_no_send_key() {
        let mut only = key("zone3", None, 1, "a");
        only.pending_delivery = true;
        assert_eq!(send_key([only].iter(), "zone3").unwrap(), None);
    }

    #[test]
    fn a_pending_key_still_reads() {
        let mut k = key("zone3", None, 3, "c");
        k.pending_delivery = true;
        assert_eq!(read_key([k.clone()].iter(), "zone3", 3), Some(k));
    }

    fn key(zone: &str, group: Option<&str>, epoch: u32, pk: &str) -> ZoneKey {
        ZoneKey {
            zone: zone.into(),
            epoch,
            secret: "11".repeat(32),
            pubkey: pk.repeat(64),
            granted_by: "ad".repeat(32),
            received_at: 0,
            group: group.map(|g| g.repeat(64)),
            pending_delivery: false,
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
