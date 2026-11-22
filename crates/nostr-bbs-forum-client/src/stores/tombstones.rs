//! Who may delete which channel message: NIP-09 kind-5 tombstones scoped by
//! deleter.
//!
//! A tombstone records `(deleted id, deleter)`, never the id alone, and the
//! decision whether it hides a message is taken against the message itself:
//!
//! - **Ordinary post** (a kind-42 the relay stores under its own id): every
//!   tombstone counts. The relay's kind-5 gate is the authority there: a
//!   member may delete their own events, and deleting someone else's needs
//!   TL3 or admin, checked against the stored row.
//! - **Restored sealed original** (ADR-2017: an original recovered from a
//!   zone-encrypted envelope, whose plaintext row was purged): the relay has
//!   no row to check, and the envelope is encrypted, so it accepts a kind-5
//!   naming that id from anyone. Here a tombstone counts only when its
//!   deleter is the verified inner (original) author, or a pubkey the relay
//!   positively vouches is an admin (`/api/check-whitelist` `isAdmin`, see
//!   [`crate::stores::signer_admin`]). TL3 moderators cannot be identified by
//!   the client; their deletions of sealed originals are made real on the
//!   relay, by deleting the envelope.
//! - **Local deletion** ([`LOCAL_DELETER`]): the reader's own delete action,
//!   applied optimistically before the relay echoes it. Always counts; never
//!   persisted.
//!
//! A kind-5 that arrives before its target is held with its deleter and
//! judged when the target arrives, so arrival order changes nothing. This
//! mirrors the DM store's `(rumor id, sender)` tombstones.
//!
//! Kept free of Leptos so every rule is unit-tested natively.

use std::collections::{HashMap, HashSet};

use nostr_bbs_core::NostrEvent;

/// The deleter recorded for the reader's own optimistic delete. Not a valid
/// pubkey, so no kind-5 author can ever match it.
pub const LOCAL_DELETER: &str = "local";

/// What a message is, for deciding whose tombstone may hide it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target<'a> {
    /// Stored by the relay under its own id; the relay gated its deletion.
    Ordinary,
    /// Restored from a sealed envelope; `author` is the verified inner author.
    SealedOriginal {
        /// Lowercase hex pubkey of the original author.
        author: &'a str,
    },
}

impl<'a> Target<'a> {
    /// Classify `event`: a restored sealed original when `sealed`, otherwise
    /// ordinary. The author comes from the event, which for a restored
    /// original is the inner event whose signature the read path verified.
    pub fn of(event: &'a NostrEvent, sealed: bool) -> Self {
        if sealed {
            Self::SealedOriginal {
                author: &event.pubkey,
            }
        } else {
            Self::Ordinary
        }
    }
}

/// Deleted ids, each with every deleter that named it (all lowercase).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Tombstones {
    by_id: HashMap<String, HashSet<String>>,
}

impl Tombstones {
    /// Record that `deleter` asked for `id` to be deleted.
    pub fn record(&mut self, id: &str, deleter: &str) {
        self.by_id
            .entry(id.to_lowercase())
            .or_default()
            .insert(deleter.to_lowercase());
    }

    /// Every deleter recorded for `id` (any casing).
    pub fn deleters(&self, id: &str) -> impl Iterator<Item = &str> {
        self.by_id
            .get(&id.to_lowercase())
            .into_iter()
            .flatten()
            .map(String::as_str)
    }

    /// Whether any tombstone names `id`, whoever its deleter. Only tests ask:
    /// production code always decides through [`admits`], against a deleter.
    #[cfg(test)]
    pub fn names(&self, id: &str) -> bool {
        self.deleters(id).next().is_some()
    }

    /// Build from persisted `deleter -> {id -> deleted_at}` entries.
    pub fn from_persisted(persisted: &HashMap<String, HashMap<String, u64>>) -> Self {
        let mut t = Self::default();
        for (deleter, ids) in persisted {
            for id in ids.keys() {
                t.record(id, deleter);
            }
        }
        t
    }
}

/// Whether `deleter`'s tombstone hides a message of kind `target`.
///
/// `is_admin` must answer from the relay's vouching only and fail closed (an
/// unanswered pubkey is not an admin).
pub fn honoured(target: Target<'_>, deleter: &str, is_admin: impl Fn(&str) -> bool) -> bool {
    if deleter == LOCAL_DELETER {
        return true;
    }
    match target {
        Target::Ordinary => true,
        Target::SealedOriginal { author } => {
            deleter.eq_ignore_ascii_case(author) || is_admin(deleter)
        }
    }
}

/// Whether a message with `id`, of kind `target`, may be shown.
///
/// The single admission predicate for every insertion path (ADR-092): the
/// broad kind-42 subscription, `ensure_subscribed`, the deep-link replay and
/// the in-place restore after a zone key arrives.
pub fn admits(
    tombstones: &Tombstones,
    id: &str,
    target: Target<'_>,
    is_admin: impl Fn(&str) -> bool,
) -> bool {
    !tombstones
        .deleters(id)
        .any(|d| honoured(target, d, &is_admin))
}

/// Deleters of a sealed original whose standing the relay must be asked
/// about: everyone but the author and the local reader. Empty for an
/// ordinary post, which needs no client-side check.
pub fn deleters_to_verify(tombstones: &Tombstones, id: &str, target: Target<'_>) -> Vec<String> {
    match target {
        Target::Ordinary => Vec::new(),
        Target::SealedOriginal { author } => tombstones
            .deleters(id)
            .filter(|d| *d != LOCAL_DELETER && !d.eq_ignore_ascii_case(author))
            .map(str::to_string)
            .collect(),
    }
}

/// Apply one kind-5 from `deleter`: record a tombstone per target and remove
/// every stored message it is honoured against. Returns whether any message
/// was removed.
///
/// `is_sealed(id)` says whether the stored message with that id is a restored
/// sealed original. A tombstone that is not honoured now stays recorded, so a
/// later answer from the relay ([`prune`]) or a later arrival is still judged
/// against it.
pub fn fold_deletion(
    messages: &mut HashMap<String, Vec<NostrEvent>>,
    tombstones: &mut Tombstones,
    deleter: &str,
    targets: &[String],
    is_sealed: impl Fn(&str) -> bool,
    is_admin: impl Fn(&str) -> bool,
) -> bool {
    let mut removed = false;
    for id in targets {
        tombstones.record(id, deleter);
        for events in messages.values_mut() {
            let before = events.len();
            events.retain(|e| {
                !(e.id.eq_ignore_ascii_case(id)
                    && honoured(Target::of(e, is_sealed(&e.id)), deleter, &is_admin))
            });
            removed |= events.len() != before;
        }
    }
    removed
}

/// Remove every stored message that [`admits`] now refuses, for when the
/// relay has newly vouched for an admin. Returns whether anything changed.
pub fn prune(
    messages: &mut HashMap<String, Vec<NostrEvent>>,
    tombstones: &Tombstones,
    is_sealed: impl Fn(&str) -> bool,
    is_admin: impl Fn(&str) -> bool,
) -> bool {
    let mut removed = false;
    for events in messages.values_mut() {
        let before = events.len();
        events.retain(|e| {
            admits(
                tombstones,
                &e.id,
                Target::of(e, is_sealed(&e.id)),
                &is_admin,
            )
        });
        removed |= events.len() != before;
    }
    removed
}

/// Stored sealed originals named by `targets` whose author is not `deleter`:
/// the relay must be asked whether `deleter` is an admin before this kind-5
/// can hide them.
pub fn needs_admin_answer(
    messages: &HashMap<String, Vec<NostrEvent>>,
    deleter: &str,
    targets: &[String],
    is_sealed: impl Fn(&str) -> bool,
) -> bool {
    messages.values().flatten().any(|e| {
        targets.iter().any(|t| e.id.eq_ignore_ascii_case(t))
            && is_sealed(&e.id)
            && !e.pubkey.eq_ignore_ascii_case(deleter)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: &str = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
    const MALLORY: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    const ADMIN: &str = "adadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadad";

    fn post(id: &str, author: &str) -> NostrEvent {
        NostrEvent {
            id: id.to_string(),
            pubkey: author.to_string(),
            created_at: 1,
            kind: 42,
            tags: vec![],
            content: "hello".into(),
            sig: String::new(),
        }
    }

    fn store(events: Vec<NostrEvent>) -> HashMap<String, Vec<NostrEvent>> {
        HashMap::from([("chan".to_string(), events)])
    }

    fn ids(m: &HashMap<String, Vec<NostrEvent>>) -> Vec<String> {
        m["chan"].iter().map(|e| e.id.clone()).collect()
    }

    fn no_admin(_: &str) -> bool {
        false
    }

    fn admin_only(pk: &str) -> bool {
        pk == ADMIN
    }

    fn sealed(id: &'static str) -> impl Fn(&str) -> bool {
        move |x: &str| x == id
    }

    // --- the attack this module closes ---

    #[test]
    fn a_members_deletion_of_anothers_sealed_original_does_not_hide_it() {
        let mut m = store(vec![post("s1", ALICE)]);
        let mut t = Tombstones::default();
        let removed = fold_deletion(
            &mut m,
            &mut t,
            MALLORY,
            &["s1".into()],
            sealed("s1"),
            no_admin,
        );
        assert!(!removed);
        assert_eq!(ids(&m), vec!["s1"]);
        let ev = post("s1", ALICE);
        assert!(admits(&t, "s1", Target::of(&ev, true), no_admin));
    }

    #[test]
    fn the_authors_own_deletion_hides_their_sealed_original() {
        let mut m = store(vec![post("s1", ALICE)]);
        let mut t = Tombstones::default();
        assert!(fold_deletion(
            &mut m,
            &mut t,
            ALICE,
            &["s1".into()],
            sealed("s1"),
            no_admin
        ));
        assert!(ids(&m).is_empty());
    }

    #[test]
    fn a_relay_vouched_admin_hides_a_sealed_original() {
        let mut m = store(vec![post("s1", ALICE)]);
        let mut t = Tombstones::default();
        assert!(fold_deletion(
            &mut m,
            &mut t,
            ADMIN,
            &["s1".into()],
            sealed("s1"),
            admin_only
        ));
        assert!(ids(&m).is_empty());
    }

    #[test]
    fn author_comparison_ignores_case() {
        let ev = post("s1", ALICE);
        assert!(honoured(
            Target::of(&ev, true),
            &ALICE.to_uppercase(),
            no_admin
        ));
    }

    // --- ordering ---

    #[test]
    fn tombstone_first_target_later_member_deletion_is_ignored() {
        let mut m = store(vec![]);
        let mut t = Tombstones::default();
        fold_deletion(
            &mut m,
            &mut t,
            MALLORY,
            &["s1".into()],
            sealed("s1"),
            no_admin,
        );
        // The target arrives afterwards and is judged against the held deleter.
        let ev = post("s1", ALICE);
        assert!(admits(&t, "s1", Target::of(&ev, true), no_admin));
    }

    #[test]
    fn tombstone_first_target_later_author_deletion_holds() {
        let mut m = store(vec![]);
        let mut t = Tombstones::default();
        fold_deletion(
            &mut m,
            &mut t,
            ALICE,
            &["s1".into()],
            sealed("s1"),
            no_admin,
        );
        let ev = post("s1", ALICE);
        assert!(!admits(&t, "s1", Target::of(&ev, true), no_admin));
    }

    #[test]
    fn target_first_tombstone_later_both_ways() {
        let mut m = store(vec![post("s1", ALICE), post("s2", ALICE)]);
        let mut t = Tombstones::default();
        fold_deletion(&mut m, &mut t, MALLORY, &["s1".into()], |_| true, no_admin);
        fold_deletion(&mut m, &mut t, ALICE, &["s2".into()], |_| true, no_admin);
        assert_eq!(ids(&m), vec!["s1"]);
    }

    #[test]
    fn a_held_member_tombstone_does_not_mask_a_later_author_one() {
        let mut t = Tombstones::default();
        t.record("s1", MALLORY);
        t.record("s1", ALICE);
        let ev = post("s1", ALICE);
        assert!(!admits(&t, "s1", Target::of(&ev, true), no_admin));
    }

    // --- admin answers that arrive later ---

    #[test]
    fn prune_applies_a_held_deletion_once_the_relay_vouches_for_an_admin() {
        let mut m = store(vec![post("s1", ALICE)]);
        let mut t = Tombstones::default();
        fold_deletion(
            &mut m,
            &mut t,
            ADMIN,
            &["s1".into()],
            sealed("s1"),
            no_admin,
        );
        assert_eq!(ids(&m), vec!["s1"], "unanswered admin fails closed");
        assert!(needs_admin_answer(&m, ADMIN, &["s1".into()], sealed("s1")));
        assert!(!prune(&mut m, &t, sealed("s1"), no_admin));
        assert!(prune(&mut m, &t, sealed("s1"), admin_only));
        assert!(ids(&m).is_empty());
    }

    #[test]
    fn only_non_author_deleters_of_sealed_originals_need_verifying() {
        let mut t = Tombstones::default();
        t.record("s1", ALICE);
        t.record("s1", MALLORY);
        t.record("s1", LOCAL_DELETER);
        let ev = post("s1", ALICE);
        assert_eq!(
            deleters_to_verify(&t, "s1", Target::of(&ev, true)),
            vec![MALLORY]
        );
        assert!(deleters_to_verify(&t, "s1", Target::Ordinary).is_empty());
        assert!(!needs_admin_answer(
            &store(vec![post("s1", ALICE)]),
            ALICE,
            &["s1".into()],
            sealed("s1")
        ));
        assert!(!needs_admin_answer(
            &store(vec![post("s1", ALICE)]),
            MALLORY,
            &["s1".into()],
            |_| false
        ));
    }

    // --- ordinary posts keep the relay as the authority ---

    #[test]
    fn any_tombstone_hides_an_ordinary_post() {
        let mut m = store(vec![post("p1", ALICE)]);
        let mut t = Tombstones::default();
        assert!(fold_deletion(
            &mut m,
            &mut t,
            MALLORY,
            &["P1".into()],
            |_| false,
            no_admin
        ));
        assert!(ids(&m).is_empty());
        assert!(!admits(&t, "p1", Target::Ordinary, no_admin));
        assert!(!admits(&t, "P1", Target::Ordinary, no_admin));
        assert!(admits(&t, "p2", Target::Ordinary, no_admin));
    }

    #[test]
    fn a_local_delete_is_always_honoured() {
        let mut m = store(vec![post("s1", ALICE)]);
        let mut t = Tombstones::default();
        assert!(fold_deletion(
            &mut m,
            &mut t,
            LOCAL_DELETER,
            &["s1".into()],
            |_| true,
            no_admin
        ));
        assert!(ids(&m).is_empty());
    }

    #[test]
    fn a_deletion_of_an_unknown_id_removes_nothing_but_is_held() {
        let mut m = store(vec![post("p1", ALICE)]);
        let mut t = Tombstones::default();
        assert!(!fold_deletion(
            &mut m,
            &mut t,
            ALICE,
            &["zz".into()],
            |_| false,
            no_admin
        ));
        assert_eq!(ids(&m), vec!["p1"]);
        assert!(t.names("zz"));
    }

    #[test]
    fn persisted_entries_keep_their_deleter() {
        let persisted = HashMap::from([
            (MALLORY.to_string(), HashMap::from([("s1".to_string(), 5)])),
            (ALICE.to_string(), HashMap::from([("s2".to_string(), 6)])),
        ]);
        let t = Tombstones::from_persisted(&persisted);
        // After a reload: Mallory's entry naming Alice's sealed original does
        // not hide it; Alice's own entry does.
        let s1 = post("s1", ALICE);
        let s2 = post("s2", ALICE);
        assert!(admits(&t, "s1", Target::of(&s1, true), no_admin));
        assert!(!admits(&t, "s2", Target::of(&s2, true), no_admin));
    }
}
