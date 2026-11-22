//! Which signed-in identity a stored zone key belongs to.
//!
//! Zone keys are cached in the browser's IndexedDB, which every account that
//! signs in on one browser profile shares. Each row written now carries its
//! owner (the identity that received or created the key) in both its `owner`
//! field and its id, `"<owner>/<store id>"`, so:
//!
//! - an identity sees only its own rows, plus the legacy rows below;
//! - two identities' rows never share an id, so one cannot overwrite the
//!   other's key, whatever slot either writes;
//! - a key write cannot be expressed without an [`Owner`].
//!
//! **Legacy rows.** Rows written before this change have no owner, and nothing
//! on the device records which account received them. They stay where they
//! are, are never written again and never deleted, and every signed-in
//! identity on the device sees them, exactly as before the change; no one sees
//! them while signed out. An identity's own row for a slot hides the legacy
//! row for that slot. Isolation therefore covers keys received or created
//! from this change on; keys already on a shared profile stay shared.
//!
//! **What this is not.** Same-origin storage is not a security boundary
//! against anyone with the device: any script on the origin, the browser's
//! developer tools or a copy of the profile reads every row, unencrypted.
//! This is isolation between accounts in the forum's UI, not access control.
//!
//! Kept free of reactive and browser types so every rule runs under plain
//! `cargo test`; the IndexedDB layer and the store call these functions.

use std::collections::{BTreeSet, HashMap};

use super::ZoneKey;
use crate::stores::indexed_db::StoredZoneKey;

/// A signed-in identity that owns zone-key rows: 64 lowercase hex.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Owner(String);

impl Owner {
    /// `pubkey` as an owner, lowercased, or `None` unless it is 64 hex.
    pub fn parse(pubkey: &str) -> Option<Self> {
        (pubkey.len() == 64 && pubkey.bytes().all(|b| b.is_ascii_hexdigit()))
            .then(|| Self(pubkey.to_ascii_lowercase()))
    }

    /// The owner's pubkey hex.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Owner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The identity whose keys should be loaded for an auth state: the pubkey only
/// once the session is authenticated. A restored but locked session (a
/// passkey awaiting unlock, an extension not yet injected) loads no keys.
pub fn owner_from_auth(is_authenticated: bool, pubkey: Option<&str>) -> Option<Owner> {
    if !is_authenticated {
        return None;
    }
    pubkey.and_then(Owner::parse)
}

/// IndexedDB id of `owner`'s row for `store_id` (a [`ZoneKey::store_id`]).
/// A legacy row's id is the bare store id, which never contains `/`.
pub fn owned_row_id(owner: &Owner, store_id: &str) -> String {
    format!("{owner}/{store_id}")
}

/// The id a row should be stored under with the `ZONE_GROUPS_ENABLED` flag at
/// `zone_groups`, or `None` for a row whose `owner` is not a valid pubkey (left
/// untouched and invisible).
pub fn expected_row_id(row: &StoredZoneKey, zone_groups: bool) -> Option<String> {
    let store_id = row.to_zone_key().store_id_with(zone_groups);
    match row.owner.as_deref() {
        None => Some(store_id),
        Some(o) => Owner::parse(o)
            .filter(|p| p.as_str() == o)
            .map(|p| owned_row_id(&p, &store_id)),
    }
}

/// What storage holds for one slot as `owner` sees it: their own row, else
/// the legacy row.
pub fn slot_view(owned: Option<ZoneKey>, legacy: Option<ZoneKey>) -> Option<ZoneKey> {
    owned.or(legacy)
}

/// Whether a guarded write of `key` may go ahead, given the slot's view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PutDecision {
    /// No key or the same key is held: write.
    Write,
    /// A different key is held for the slot: refuse, keeping it.
    Conflict(ZoneKey),
}

/// The guard on every key write: refuse when the slot's view (owned row, else
/// legacy row) holds a different key. The legacy row counts, so a key the
/// device already held before rows had owners is never shadowed by a
/// conflicting one.
pub fn put_decision(view: Option<&ZoneKey>, key: &ZoneKey) -> PutDecision {
    match view {
        Some(held) if super::conflicts(held, key) => PutDecision::Conflict(held.clone()),
        _ => PutDecision::Write,
    }
}

use super::keyset::MAX_EPOCH_SKIP;

/// Whether a freshly minted key may be stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MintDecision {
    /// Store it.
    Write,
    /// The slot holds a different key (see [`put_decision`]).
    Conflict(ZoneKey),
    /// The identity holds a different key for the zone at this epoch or
    /// above, or another account on this browser does within
    /// [`MAX_EPOCH_SKIP`] of it: minting here could clash with a key that
    /// account holds but has not delivered yet.
    Superseded(u32),
}

/// The guard on storing a key this device just created: the slot guard, plus
/// a device-wide check over every row (all owners, legacy included) so two
/// accounts on one browser never mint different keys for one epoch.
pub fn mint_decision(
    rows: &[StoredZoneKey],
    owner: &Owner,
    key: &ZoneKey,
    zone_groups: bool,
) -> MintDecision {
    let view = visible_keys(rows.iter().cloned(), owner, zone_groups);
    if let PutDecision::Conflict(held) =
        put_decision(view.get(&key.store_id_with(zone_groups)), key)
    {
        return MintDecision::Conflict(held);
    }
    // A different key at this epoch or above that the identity itself holds
    // (its rows and the legacy rows it sees) always refuses. Another
    // account's counts only within MAX_EPOCH_SKIP of the mint, the bound
    // `plan_mint` believes it to: one far-ahead grant to some other account
    // must not refuse every mint for good (rows are never deleted).
    let bound = key.epoch.saturating_add(MAX_EPOCH_SKIP);
    let different = |zone: &str, epoch: u32, pubkey: &str| {
        zone == key.zone && epoch >= key.epoch && pubkey != key.pubkey
    };
    let own = view
        .values()
        .filter(|k| different(&k.zone, k.epoch, &k.pubkey))
        .map(|k| k.epoch);
    let others = rows
        .iter()
        .filter(|r| different(&r.zone, r.epoch, &r.pubkey) && r.epoch < bound)
        .map(|r| r.epoch);
    let clash = own.chain(others).max();
    match clash {
        Some(epoch) => MintDecision::Superseded(epoch),
        None => MintDecision::Write,
    }
}

/// The keys `owner` sees, by store id: their own rows, then legacy rows for
/// slots they have no row for. Other owners' rows are never included. When
/// two rows of one kind map to one store id (a row left under an old id after
/// the flag changed), the one already under its expected id wins, then the
/// lowest id, so the choice is deterministic.
pub fn visible_keys(
    rows: impl IntoIterator<Item = StoredZoneKey>,
    owner: &Owner,
    zone_groups: bool,
) -> HashMap<String, ZoneKey> {
    // (store id) -> (is owned, is canonical, row id, key); higher wins on
    // (owned, canonical), lower row id breaks ties.
    let mut best: HashMap<String, (bool, bool, String, ZoneKey)> = HashMap::new();
    for row in rows {
        let owned = match row.owner.as_deref() {
            None => false,
            Some(o) if o == owner.as_str() => true,
            Some(_) => continue,
        };
        let canonical = expected_row_id(&row, zone_groups).as_deref() == Some(row.id.as_str());
        let key = row.to_zone_key();
        let store_id = key.store_id_with(zone_groups);
        let replace = match best.get(&store_id) {
            None => true,
            Some((o, c, id, _)) => {
                (owned, canonical) > (*o, *c) || ((owned, canonical) == (*o, *c) && row.id < *id)
            }
        };
        if replace {
            best.insert(store_id, (owned, canonical, row.id, key));
        }
    }
    best.into_iter().map(|(id, (_, _, _, k))| (id, k)).collect()
}

/// Merge a freshly loaded view into memory for the same lease. An entry
/// already in memory was stored for this lease after the rows were read, so
/// it is at least as current and is kept. Returns whether anything was added.
pub fn merge_loaded(
    memory: &mut HashMap<String, ZoneKey>,
    loaded: HashMap<String, ZoneKey>,
) -> bool {
    let mut added = false;
    for (id, k) in loaded {
        if let std::collections::hash_map::Entry::Vacant(e) = memory.entry(id) {
            e.insert(k);
            added = true;
        }
    }
    added
}

/// Highest epoch held per zone across every row on the device, whatever its
/// owner. Epoch numbers only: [`keyset::plan_mint`](super::keyset::plan_mint)
/// mints above them, and no secret crosses accounts.
pub fn device_epochs<'a>(
    rows: impl IntoIterator<Item = &'a StoredZoneKey>,
) -> HashMap<String, BTreeSet<u32>> {
    let mut out: HashMap<String, BTreeSet<u32>> = HashMap::new();
    for r in rows {
        out.entry(r.zone.clone()).or_default().insert(r.epoch);
    }
    out
}

/// A row to move to the id it should have (the flag changed since it was
/// written). The record is copied verbatim apart from its id, owner included.
#[derive(Debug, Clone, PartialEq)]
pub struct Rename {
    /// Where the row is now.
    pub old_id: String,
    /// The row under its new id.
    pub row: StoredZoneKey,
}

/// Rows not stored under their expected id, with that id.
pub fn migration_plan(rows: &[StoredZoneKey], zone_groups: bool) -> Vec<Rename> {
    rows.iter()
        .filter_map(|r| {
            let want = expected_row_id(r, zone_groups)?;
            (want != r.id).then(|| Rename {
                old_id: r.id.clone(),
                row: StoredZoneKey {
                    id: want,
                    ..r.clone()
                },
            })
        })
        .collect()
}

/// `zone_kv` id of `owner`'s set of `(zone, epoch)` ids received through
/// their inbox key. The pre-owner set (one shared id) is not read: adopting it
/// for the wrong identity would let the grant sweep delete that identity's
/// only relay copy of a key, so it is rebuilt from the inbox wraps themselves.
pub fn inbox_granted_id(owner: &Owner) -> String {
    format!("inbox_granted:{owner}")
}

/// The entry recording that `key` arrived through the inbox key: its full
/// store id, so with `ZONE_GROUPS_ENABLED` two different keys claiming one
/// epoch never share an entry, and the inbox copy of one can never count as
/// the replacement that lets the sweep delete the identity copy of the other.
/// With the flag off this is `<zone>:<epoch>`, the form entries had before.
pub fn inbox_granted_entry(key: &ZoneKey, zone_groups: bool) -> String {
    key.store_id_with(zone_groups)
}

/// The identity whose keys the store holds in memory, and a counter bumped on
/// every change of identity. Work started for one identity carries a
/// [`Lease`] and touches memory, the relay or the UI only while that lease is
/// still current; its storage writes still land, under its own owner.
#[derive(Debug, Default, Clone)]
pub struct Session {
    owner: Option<Owner>,
    generation: u64,
}

/// Proof that work was started for `owner` in one [`Session`] generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    owner: Owner,
    generation: u64,
}

impl Lease {
    /// The identity the work belongs to.
    pub fn owner(&self) -> &Owner {
        &self.owner
    }
}

/// What a call to [`Session::switch`] means for the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Switch {
    /// Same identity as before: nothing to do.
    Unchanged,
    /// Signed out, or a different identity signed in: clear memory, then load
    /// for the lease if there is one.
    Changed(Option<Lease>),
}

impl Session {
    /// Move to `next`. Any change bumps the generation, so every lease handed
    /// out before is stale from here on.
    pub fn switch(&mut self, next: Option<Owner>) -> Switch {
        if self.owner == next {
            return Switch::Unchanged;
        }
        self.owner = next;
        self.generation += 1;
        Switch::Changed(self.lease())
    }

    /// A lease for the current identity, if one is signed in.
    pub fn lease(&self) -> Option<Lease> {
        self.owner.clone().map(|owner| Lease {
            owner,
            generation: self.generation,
        })
    }

    /// Whether `lease` was handed out in the current generation.
    pub fn is_current(&self, lease: &Lease) -> bool {
        lease.generation == self.generation && self.owner.as_ref() == Some(&lease.owner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zone_crypto::keyset::{plan_mint, MintPlan};

    fn owner(c: char) -> Owner {
        Owner::parse(&c.to_string().repeat(64)).expect("hex")
    }

    fn key(zone: &str, epoch: u32, secret: char) -> ZoneKey {
        let sk = secret.to_string().repeat(64);
        ZoneKey {
            zone: zone.into(),
            epoch,
            pubkey: format!("{epoch:0>2}").repeat(32),
            secret: sk,
            granted_by: "ad".repeat(32),
            received_at: 0,
            group: None,
            pending_delivery: false,
        }
    }

    fn with_pk(mut k: ZoneKey, pk: char) -> ZoneKey {
        k.pubkey = pk.to_string().repeat(64);
        k
    }

    fn owned(o: &Owner, k: &ZoneKey) -> StoredZoneKey {
        StoredZoneKey::owned(o, k)
    }

    /// `owner`'s row as it would be written with the flag at `flag` (the
    /// native flag is always off, so the id is built explicitly).
    fn owned_with(o: &Owner, k: &ZoneKey, flag: bool) -> StoredZoneKey {
        StoredZoneKey {
            id: owned_row_id(o, &k.store_id_with(flag)),
            ..StoredZoneKey::owned(o, k)
        }
    }

    /// A row as written before rows had owners.
    fn legacy(k: &ZoneKey, flag: bool) -> StoredZoneKey {
        StoredZoneKey {
            owner: None,
            id: k.store_id_with(flag),
            ..StoredZoneKey::owned(&owner('0'), k)
        }
    }

    #[test]
    fn owner_is_validated_and_lowercased() {
        let upper = "AB".repeat(32);
        assert_eq!(Owner::parse(&upper).unwrap().as_str(), "ab".repeat(32));
        assert!(Owner::parse("abc").is_none());
        assert!(Owner::parse(&"zz".repeat(32)).is_none());
        assert!(Owner::parse("").is_none());
    }

    #[test]
    fn only_an_authenticated_session_has_an_owner() {
        let pk = "a".repeat(64);
        assert_eq!(owner_from_auth(true, Some(&pk)), Some(owner('a')));
        assert_eq!(owner_from_auth(false, Some(&pk)), None, "locked session");
        assert_eq!(owner_from_auth(true, None), None);
        assert_eq!(owner_from_auth(true, Some("not-a-key")), None);
    }

    #[test]
    fn rows_of_different_owners_never_share_an_id() {
        let k = key("zone3", 2, '1');
        for flag in [false, true] {
            let sid = k.store_id_with(flag);
            let (a, b) = (
                owned_row_id(&owner('a'), &sid),
                owned_row_id(&owner('b'), &sid),
            );
            assert_ne!(a, b, "flag {flag}");
            assert_ne!(a, sid, "an owned id never equals a legacy id (flag {flag})");
            assert!(!sid.contains('/'), "legacy ids have no separator");
        }
    }

    #[test]
    fn stamping_puts_the_owner_in_the_field_and_the_id() {
        let k = key("zone3", 2, '1');
        let row = owned(&owner('a'), &k);
        assert_eq!(row.owner.as_deref(), Some(owner('a').as_str()));
        assert_eq!(Some(row.id.clone()), expected_row_id(&row, false));
        assert_eq!(row.to_zone_key(), k);
    }

    #[test]
    fn an_identity_sees_its_rows_and_legacy_rows_never_another_identitys() {
        let (a, b) = (owner('a'), owner('b'));
        let rows = vec![
            owned(&a, &key("zone3", 1, '1')),
            owned(&b, &key("zone3", 2, '2')),
            legacy(&key("zone3", 3, '3'), false),
        ];
        let seen_by_a = visible_keys(rows.clone(), &a, false);
        let mut epochs: Vec<u32> = seen_by_a.values().map(|k| k.epoch).collect();
        epochs.sort();
        assert_eq!(epochs, vec![1, 3]);
        let mut epochs_b: Vec<u32> = visible_keys(rows, &b, false)
            .values()
            .map(|k| k.epoch)
            .collect();
        epochs_b.sort();
        assert_eq!(epochs_b, vec![2, 3]);
    }

    #[test]
    fn an_owned_row_hides_the_legacy_row_for_its_slot() {
        let a = owner('a');
        let mut pending = key("zone3", 4, '4');
        pending.pending_delivery = true;
        let mut delivered = pending.clone();
        delivered.pending_delivery = false;
        // A legacy pending key later marked delivered: the delivered copy is
        // the owner's row, and must win, or the key stays held back forever.
        for flag in [false, true] {
            let rows = vec![legacy(&pending, flag), owned(&a, &delivered)];
            let v = visible_keys(rows, &a, flag);
            assert_eq!(v.len(), 1);
            assert!(
                !v[&delivered.store_id_with(flag)].pending_delivery,
                "flag {flag}"
            );
        }
    }

    #[test]
    fn the_guard_counts_the_legacy_row() {
        let held = key("zone3", 2, '1');
        let other = key("zone3", 2, '9');
        // No owned row: the legacy row is the view and refuses a different key.
        let view = slot_view(None, Some(held.clone()));
        assert_eq!(
            put_decision(view.as_ref(), &other),
            PutDecision::Conflict(held.clone())
        );
        assert_eq!(put_decision(view.as_ref(), &held), PutDecision::Write);
        assert_eq!(put_decision(None, &other), PutDecision::Write);
    }

    /// Finding 2 of the earlier attempt: a key hidden from B must not be
    /// overwritten when B writes the same slot.
    #[test]
    fn identity_b_writing_a_slot_never_touches_identity_as_row() {
        let (a, b) = (owner('a'), owner('b'));
        let a_key = key("zone3", 2, '1');
        let b_key = key("zone3", 2, '9');
        let mut rows = vec![owned(&a, &a_key)];
        // B's view of the slot is empty, so B's write goes ahead...
        let b_view = visible_keys(rows.clone(), &b, false);
        assert_eq!(
            put_decision(b_view.get(&b_key.store_id_with(false)), &b_key),
            PutDecision::Write
        );
        // ...under B's own id, beside A's row.
        let b_row = owned(&b, &b_key);
        assert!(rows.iter().all(|r| r.id != b_row.id));
        rows.push(b_row);
        assert_eq!(
            visible_keys(rows.clone(), &a, false).values().next(),
            Some(&a_key)
        );
        assert_eq!(visible_keys(rows, &b, false).values().next(), Some(&b_key));
    }

    #[test]
    fn a_mint_below_another_accounts_epoch_is_refused() {
        let (a, b) = (owner('a'), owner('b'));
        let mut a_pending = with_pk(key("zone3", 4, '4'), 'c');
        a_pending.pending_delivery = true;
        let rows = vec![owned(&a, &a_pending), owned(&b, &key("zone3", 3, '3'))];
        // B, seeing only epoch 3, tries epoch 4: refused, A holds epoch 4.
        let b_mint = with_pk(key("zone3", 4, '8'), 'd');
        assert_eq!(
            mint_decision(&rows, &b, &b_mint, false),
            MintDecision::Superseded(4)
        );
        // Epoch 5 is clear.
        let b_mint5 = with_pk(key("zone3", 5, '8'), 'd');
        assert_eq!(
            mint_decision(&rows, &b, &b_mint5, false),
            MintDecision::Write
        );
        // Another zone is unaffected.
        let other = with_pk(key("zone9", 1, '8'), 'd');
        assert_eq!(mint_decision(&rows, &b, &other, false), MintDecision::Write);
        // The device floor makes the card plan epoch 5 in the first place.
        let device: Vec<u32> = device_epochs(&rows)["zone3"].iter().copied().collect();
        assert!(matches!(
            plan_mint("zone3", Some(3), &device, &[], true),
            MintPlan::Mint {
                epoch: 5,
                note: Some(_)
            }
        ));
    }

    #[test]
    fn with_the_flag_on_a_mint_goes_above_two_keys_claiming_one_epoch() {
        let (a, b) = (owner('a'), owner('b'));
        // Flag on: two different keys at epoch 3 live under separate ids.
        let k1 = with_pk(key("zone3", 3, '1'), 'c');
        let k2 = with_pk(key("zone3", 3, '2'), 'd');
        assert_ne!(k1.store_id_with(true), k2.store_id_with(true));
        let rows = vec![owned_with(&a, &k1, true), owned_with(&b, &k2, true)];
        assert_eq!(
            visible_keys(rows.clone(), &a, true).values().next(),
            Some(&k1),
            "each identity sees only its own claim"
        );
        let at3 = with_pk(key("zone3", 3, '9'), 'e');
        assert_eq!(
            mint_decision(&rows, &b, &at3, true),
            MintDecision::Superseded(3)
        );
        let at4 = with_pk(key("zone3", 4, '9'), 'e');
        assert_eq!(mint_decision(&rows, &b, &at4, true), MintDecision::Write);
        assert!(matches!(
            plan_mint(
                "zone3",
                None,
                &device_epochs(&rows)["zone3"]
                    .iter()
                    .copied()
                    .collect::<Vec<_>>(),
                &[],
                true
            ),
            MintPlan::Mint { epoch: 4, .. }
        ));
    }

    #[test]
    fn a_load_never_replaces_what_memory_already_holds() {
        // Memory holds the key as delivered (an ack landed during the load);
        // the rows read before it still say pending.
        let a = key("zone3", 2, '1');
        let newer = a.clone();
        let mut mem = HashMap::from([(a.store_id_with(false), newer.clone())]);
        let mut stale = a.clone();
        stale.pending_delivery = true;
        let loaded = HashMap::from([
            (a.store_id_with(false), stale),
            ("zone3:3".to_string(), key("zone3", 3, '3')),
        ]);
        assert!(merge_loaded(&mut mem, loaded));
        assert_eq!(mem[&a.store_id_with(false)], newer, "memory wins");
        assert_eq!(mem.len(), 2);
        assert!(!merge_loaded(&mut mem, HashMap::new()));
    }

    /// Review finding: one valid grant at u32::MAX to any account that ever
    /// signed in here must not stop Create/Rotate for good.
    #[test]
    fn a_far_ahead_row_of_another_account_does_not_refuse_a_mint() {
        let (a, b) = (owner('a'), owner('b'));
        let poison = with_pk(key("zone3", u32::MAX, '9'), 'f');
        let rows = vec![owned(&a, &poison), owned(&b, &key("zone3", 3, '3'))];
        let b4 = with_pk(key("zone3", 4, '8'), 'd');
        assert_eq!(mint_decision(&rows, &b, &b4, false), MintDecision::Write);
        // Just inside the bound (4 + MAX_EPOCH_SKIP - 1) still refuses; just
        // outside it does not.
        for (epoch, refused) in [(4 + MAX_EPOCH_SKIP - 1, true), (4 + MAX_EPOCH_SKIP, false)] {
            let rows = vec![
                owned(&a, &with_pk(key("zone3", epoch, '9'), 'f')),
                owned(&b, &key("zone3", 3, '3')),
            ];
            let got = mint_decision(&rows, &b, &b4, false);
            assert_eq!(
                got == MintDecision::Superseded(epoch),
                refused,
                "epoch {epoch}: {got:?}"
            );
        }
        // The identity's own far-ahead key still refuses: it can see it.
        let own = vec![owned(&b, &poison), owned(&b, &key("zone3", 3, '3'))];
        assert_eq!(
            mint_decision(&own, &b, &b4, false),
            MintDecision::Superseded(u32::MAX)
        );
        // A legacy row the identity sees counts as its own.
        let legacy_rows = vec![legacy(&poison, false), owned(&b, &key("zone3", 3, '3'))];
        assert_eq!(
            mint_decision(&legacy_rows, &b, &b4, false),
            MintDecision::Superseded(u32::MAX)
        );
    }

    #[test]
    fn a_mint_conflicting_in_the_slot_reports_the_held_key() {
        let a = owner('a');
        let held = key("zone3", 2, '1');
        let rows = vec![legacy(&held, false)];
        let mint = key("zone3", 2, '9');
        assert_eq!(
            mint_decision(&rows, &a, &mint, false),
            MintDecision::Conflict(held)
        );
    }

    #[test]
    fn device_epochs_span_every_owner_and_legacy() {
        let rows = vec![
            owned(&owner('a'), &key("zone3", 4, '4')),
            owned(&owner('b'), &key("zone3", 2, '2')),
            legacy(&key("zone5", 7, '7'), false),
        ];
        let d = device_epochs(&rows);
        assert_eq!(d["zone3"].iter().copied().collect::<Vec<_>>(), vec![2, 4]);
        assert_eq!(d["zone5"].iter().copied().collect::<Vec<_>>(), vec![7]);
    }

    #[test]
    fn migration_leaves_canonical_rows_alone_and_keeps_owners() {
        let a = owner('a');
        let k = key("zone3", 2, '1');
        let rows = vec![legacy(&k, false), owned(&a, &k)];
        assert!(
            migration_plan(&rows, false).is_empty(),
            "nothing to do with the flag off"
        );
        // Flag turned on: both rows move to the long id, each keeping its owner.
        let plan = migration_plan(&rows, true);
        assert_eq!(plan.len(), 2);
        let legacy_move = plan.iter().find(|r| r.row.owner.is_none()).unwrap();
        assert_eq!(legacy_move.old_id, k.store_id_with(false));
        assert_eq!(legacy_move.row.id, k.store_id_with(true));
        let owned_move = plan.iter().find(|r| r.row.owner.is_some()).unwrap();
        assert_eq!(owned_move.row.id, owned_row_id(&a, &k.store_id_with(true)));
        assert_eq!(owned_move.row.secret, k.secret, "copied verbatim");
    }

    #[test]
    fn a_row_with_a_malformed_owner_is_never_moved_or_shown() {
        let k = key("zone3", 2, '1');
        let mut row = owned(&owner('a'), &k);
        row.owner = Some("A".repeat(64)); // not the canonical lowercase form
        assert!(migration_plan(std::slice::from_ref(&row), false).is_empty());
        assert!(visible_keys(vec![row], &owner('a'), false).is_empty());
    }

    #[test]
    fn rows_left_under_an_old_id_resolve_deterministically() {
        // A flag flip left two of A's rows on one short id; the canonical one wins.
        let a = owner('a');
        let k = key("zone3", 2, '1');
        let canonical = owned(&a, &k);
        let stale = StoredZoneKey {
            id: owned_row_id(&a, &with_pk(k.clone(), 'e').store_id_with(true)),
            ..owned(&a, &with_pk(k.clone(), 'e'))
        };
        let v = visible_keys(vec![stale.clone(), canonical.clone()], &a, false);
        assert_eq!(v.values().next().unwrap().pubkey, k.pubkey);
        let v2 = visible_keys(vec![canonical, stale], &a, false);
        assert_eq!(
            v2.values().next().unwrap().pubkey,
            k.pubkey,
            "order-independent"
        );
    }

    #[test]
    fn an_inbox_copy_of_one_key_never_replaces_another_at_the_same_epoch() {
        let k1 = with_pk(key("zone3", 3, '1'), 'c');
        let k2 = with_pk(key("zone3", 3, '2'), 'd');
        // Flag on: the inbox copy of k2 is recorded; the identity copy of k1
        // must not find a replacement.
        let granted: std::collections::HashSet<String> =
            [inbox_granted_entry(&k2, true)].into_iter().collect();
        assert!(!granted.contains(&inbox_granted_entry(&k1, true)));
        assert!(granted.contains(&inbox_granted_entry(&k2, true)));
        // Flag off: one key per epoch, and the entry is the old `<zone>:<epoch>`.
        assert_eq!(
            inbox_granted_entry(&k1, false),
            crate::zone_crypto::key_id("zone3", 3)
        );
    }

    #[test]
    fn inbox_granted_ids_are_per_owner() {
        assert_ne!(inbox_granted_id(&owner('a')), inbox_granted_id(&owner('b')));
        assert_ne!(inbox_granted_id(&owner('a')), "inbox_granted");
    }

    #[test]
    fn a_session_switch_makes_earlier_leases_stale() {
        let mut s = Session::default();
        assert_eq!(s.switch(None), Switch::Unchanged);
        let Switch::Changed(Some(la)) = s.switch(Some(owner('a'))) else {
            panic!("sign-in hands out a lease");
        };
        assert!(s.is_current(&la));
        assert_eq!(
            s.switch(Some(owner('a'))),
            Switch::Unchanged,
            "same identity"
        );
        assert!(s.is_current(&la));
        assert_eq!(s.switch(None), Switch::Changed(None));
        assert!(!s.is_current(&la), "logout invalidates");
        let Switch::Changed(Some(la2)) = s.switch(Some(owner('a'))) else {
            panic!("lease");
        };
        assert!(
            !s.is_current(&la),
            "a new sign-in of the same identity is a new lease"
        );
        assert!(s.is_current(&la2));
    }

    /// The logout → login sequence without a reload: memory is cleared on
    /// every change, the next identity's view is loaded from storage under a
    /// fresh lease, a load or write started for the old identity is not
    /// applied to memory, and minting waits until the new identity's view is
    /// ready. Finding 1 of the earlier attempt: after logout and login, the
    /// store was empty and Create offered epoch 1 over real keys.
    ///
    /// `Session`, `visible_keys`, `merge_loaded` and `plan_mint` are the
    /// functions the store calls; the clearing of memory and readiness on a
    /// switch is restated here from `ZoneKeyStore::switch_owner`, whose
    /// reactive signals have no native test harness.
    #[test]
    fn logout_then_login_without_reload_reloads_the_right_keys_before_minting() {
        let (a, b) = (owner('a'), owner('b'));
        let mut storage = vec![
            owned(&a, &key("zone3", 1, '1')),
            owned(&a, &key("zone3", 2, '2')),
            legacy(&key("zone3", 1, '1'), false),
        ];
        let mut session = Session::default();
        let mut memory: HashMap<String, ZoneKey> = HashMap::new();
        let mut ready_for: Option<Owner> = None;

        // Restates the clearing in ZoneKeyStore::switch_owner.
        let switch = |s: &mut Session,
                      mem: &mut HashMap<String, ZoneKey>,
                      ready: &mut Option<Owner>,
                      next: Option<Owner>| {
            match s.switch(next) {
                Switch::Unchanged => None,
                Switch::Changed(lease) => {
                    mem.clear();
                    *ready = None;
                    lease
                }
            }
        };
        let load = |s: &Session,
                    mem: &mut HashMap<String, ZoneKey>,
                    ready: &mut Option<Owner>,
                    lease: &Lease,
                    rows: &[StoredZoneKey]| {
            if !s.is_current(lease) {
                return;
            }
            merge_loaded(
                mem,
                visible_keys(rows.iter().cloned(), lease.owner(), false),
            );
            *ready = Some(lease.owner().clone());
        };
        let can_mint = |ready: &Option<Owner>, me: &Owner, mem: &HashMap<String, ZoneKey>| {
            let held = mem.values().map(|k| k.epoch).max();
            let synced = ready.as_ref() == Some(me);
            plan_mint("zone3", held, &[], &[], synced)
        };

        let la = switch(&mut session, &mut memory, &mut ready_for, Some(a.clone())).unwrap();
        assert_eq!(
            can_mint(&ready_for, &a, &memory),
            MintPlan::Wait,
            "before A's load"
        );
        load(&session, &mut memory, &mut ready_for, &la, &storage);
        assert!(matches!(
            can_mint(&ready_for, &a, &memory),
            MintPlan::Mint { epoch: 3, .. }
        ));

        // A signs out: nothing stays in memory.
        assert!(switch(&mut session, &mut memory, &mut ready_for, None).is_none());
        assert!(memory.is_empty() && ready_for.is_none());

        // A grant for A finishes after the logout: stored under A, not shown.
        let late = key("zone3", 3, '3');
        storage.push(owned(la.owner(), &late));
        assert!(!session.is_current(&la));

        // B signs in without a reload: memory holds B's view only, which is
        // the legacy row; never A's keys, and no Create before it loads.
        let lb = switch(&mut session, &mut memory, &mut ready_for, Some(b.clone())).unwrap();
        assert_eq!(can_mint(&ready_for, &b, &memory), MintPlan::Wait);
        load(&session, &mut memory, &mut ready_for, &la, &storage); // stale load
        assert!(
            memory.is_empty() && ready_for.is_none(),
            "a stale load is ignored"
        );
        load(&session, &mut memory, &mut ready_for, &lb, &storage);
        let epochs: Vec<u32> = memory.values().map(|k| k.epoch).collect();
        assert_eq!(epochs, vec![1], "B sees the legacy key only");
        assert_eq!(
            can_mint(&ready_for, &a, &memory),
            MintPlan::Wait,
            "readiness is per owner"
        );

        // A signs back in, again without a reload: all of A's keys, the late
        // one included, are loaded before minting is offered.
        switch(&mut session, &mut memory, &mut ready_for, None);
        let la2 = switch(&mut session, &mut memory, &mut ready_for, Some(a.clone())).unwrap();
        assert_eq!(can_mint(&ready_for, &a, &memory), MintPlan::Wait);
        load(&session, &mut memory, &mut ready_for, &la2, &storage);
        let mut epochs: Vec<u32> = memory.values().map(|k| k.epoch).collect();
        epochs.sort();
        assert_eq!(epochs, vec![1, 2, 3]);
        assert!(matches!(
            can_mint(&ready_for, &a, &memory),
            MintPlan::Mint { epoch: 4, .. }
        ));
    }
}
