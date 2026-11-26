//! Snapshot reconciliation for rendered event lists (ADR-091).
//!
//! A page that renders relay events keeps a local list of view models. The
//! naive way to fill it is to walk the store snapshot and append anything not
//! already rendered. That is append-only: an event the store has *removed* —
//! a NIP-09 tombstone, an EOSE prune, a channel reset — stays on screen
//! forever, and every count derived from the rendered list (post count, member
//! count) only ever goes up. ADR-091 removed the standalone counter in the
//! store; this module removes the same class of bug one layer up, in the view.
//!
//! The rule is: **the rendered set is a projection of the snapshot, not an
//! accumulation of everything ever seen.** Reconciliation is therefore two
//! moves, in this order:
//!
//! 1. drop rendered items whose id is absent from the snapshot ([`retain_present`]);
//! 2. append snapshot items not yet rendered ([`absent_from`]).
//!
//! Both preserve the order of items that are unchanged, and neither rebuilds
//! an item that survived. That matters for streaming: a keyed list re-renders
//! only the rows that actually appeared or disappeared, so appending a message
//! does not disturb scroll position, and a deletion removes exactly one row.
//!
//! Pure and `web_sys`-free, so it unit-tests natively.

use std::collections::HashSet;

/// What a reconciliation pass changed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Reconciliation {
    /// Rendered items dropped because the snapshot no longer contains them.
    pub removed: usize,
    /// Snapshot items appended because they were not yet rendered.
    pub added: usize,
}

impl Reconciliation {
    /// Whether the rendered list actually changed. Callers use this to skip a
    /// re-sort (and the signal write that would follow) when nothing moved.
    pub fn changed(&self) -> bool {
        self.removed > 0 || self.added > 0
    }
}

/// Collect the snapshot's ids into a set for O(1) membership tests.
pub fn id_set<'a, I>(snapshot: &'a [I], id_of: impl Fn(&'a I) -> &'a str) -> HashSet<&'a str> {
    snapshot.iter().map(id_of).collect()
}

/// Drop every rendered item whose id is absent from `present`.
///
/// Returns the number removed. Survivors keep their relative order and their
/// identity — they are not rebuilt, so any per-item reactive state (a thread's
/// replies signal, an expanded/collapsed flag) survives the pass.
pub fn retain_present<T>(
    rendered: &mut Vec<T>,
    present: &HashSet<&str>,
    id_of: impl Fn(&T) -> &str,
) -> usize {
    let before = rendered.len();
    rendered.retain(|item| present.contains(id_of(item)));
    before - rendered.len()
}

/// Snapshot items that are not yet rendered, in snapshot order.
pub fn absent_from<'a, I>(
    snapshot: &'a [I],
    rendered_ids: &HashSet<&str>,
    id_of: impl Fn(&'a I) -> &'a str,
) -> Vec<&'a I> {
    snapshot
        .iter()
        .filter(|item| !rendered_ids.contains(id_of(item)))
        .collect()
}

/// Reconcile a rendered id list against a snapshot id list.
///
/// The whole contract in its simplest form, and the shape the exhaustive tests
/// exercise: removals first, then appends, order of survivors preserved,
/// appended items in snapshot order. Callers with real view models compose
/// [`retain_present`] and [`absent_from`] directly (they must build each new
/// item themselves); this is the executable specification those two are held
/// to, so it is kept even where no runtime caller names it.
#[allow(dead_code)]
pub fn reconcile_ids(rendered: &mut Vec<String>, snapshot: &[String]) -> Reconciliation {
    let present: HashSet<&str> = snapshot.iter().map(String::as_str).collect();
    let removed = retain_present(rendered, &present, |s| s.as_str());

    let mut seen: HashSet<String> = rendered.iter().cloned().collect();
    let mut added = 0;
    for id in snapshot {
        if seen.insert(id.clone()) {
            rendered.push(id.clone());
            added += 1;
        }
    }

    Reconciliation { removed, added }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    /// A stand-in for a rendered view model: an id plus state that must not be
    /// rebuilt when the item survives a pass.
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Row {
        id: String,
        generation: u32,
    }

    #[test]
    fn empty_snapshot_clears_the_rendered_list() {
        let mut rendered = ids(&["a", "b", "c"]);
        let outcome = reconcile_ids(&mut rendered, &[]);
        assert!(rendered.is_empty());
        assert_eq!(
            outcome,
            Reconciliation {
                removed: 3,
                added: 0
            }
        );
        assert!(outcome.changed());
    }

    #[test]
    fn empty_rendered_takes_the_whole_snapshot() {
        let mut rendered: Vec<String> = Vec::new();
        let outcome = reconcile_ids(&mut rendered, &ids(&["a", "b"]));
        assert_eq!(rendered, ids(&["a", "b"]));
        assert_eq!(
            outcome,
            Reconciliation {
                removed: 0,
                added: 2
            }
        );
    }

    #[test]
    fn identical_lists_are_a_no_op() {
        let mut rendered = ids(&["a", "b", "c"]);
        let outcome = reconcile_ids(&mut rendered, &ids(&["a", "b", "c"]));
        assert_eq!(rendered, ids(&["a", "b", "c"]));
        assert_eq!(outcome, Reconciliation::default());
        assert!(!outcome.changed());
    }

    /// The ADR-091 defect in one test: an event removed upstream must vanish,
    /// so the count goes DOWN.
    #[test]
    fn a_deleted_event_disappears_and_the_count_decreases() {
        let mut rendered = ids(&["a", "b", "c"]);
        assert_eq!(rendered.len(), 3);
        // `b` was tombstoned upstream (NIP-09) and dropped from the store.
        let outcome = reconcile_ids(&mut rendered, &ids(&["a", "c"]));
        assert_eq!(rendered, ids(&["a", "c"]));
        assert_eq!(rendered.len(), 2);
        assert_eq!(outcome.removed, 1);
    }

    #[test]
    fn repeated_passes_over_the_same_snapshot_do_not_inflate() {
        let mut rendered: Vec<String> = Vec::new();
        let snapshot = ids(&["a", "b", "c"]);
        for _ in 0..10 {
            reconcile_ids(&mut rendered, &snapshot);
        }
        assert_eq!(rendered.len(), 3, "append-only accumulation reappeared");
    }

    /// A store replay that re-delivers history must not duplicate rows.
    #[test]
    fn replayed_history_is_deduplicated() {
        let mut rendered = ids(&["a", "b"]);
        let replay = ids(&["a", "b", "a", "b", "c"]);
        // The snapshot itself carries duplicates only in pathological cases;
        // reconciliation must still converge on the distinct set.
        let outcome = reconcile_ids(&mut rendered, &replay);
        assert_eq!(rendered, ids(&["a", "b", "c"]));
        assert_eq!(outcome.added, 1);
    }

    #[test]
    fn simultaneous_add_and_remove() {
        let mut rendered = ids(&["a", "b", "c"]);
        let outcome = reconcile_ids(&mut rendered, &ids(&["a", "c", "d"]));
        assert_eq!(rendered, ids(&["a", "c", "d"]));
        assert_eq!(
            outcome,
            Reconciliation {
                removed: 1,
                added: 1
            }
        );
    }

    #[test]
    fn survivors_keep_their_relative_order() {
        let mut rendered = ids(&["a", "b", "c", "d"]);
        reconcile_ids(&mut rendered, &ids(&["d", "c", "b", "a"]));
        // Nothing was added or removed, so nothing is reordered here — the
        // caller owns ordering (it re-sorts by timestamp).
        assert_eq!(rendered, ids(&["a", "b", "c", "d"]));
    }

    #[test]
    fn a_whole_channel_reset_then_refill_converges() {
        let mut rendered = ids(&["a", "b", "c"]);
        reconcile_ids(&mut rendered, &[]);
        assert!(rendered.is_empty());
        reconcile_ids(&mut rendered, &ids(&["x", "y"]));
        assert_eq!(rendered, ids(&["x", "y"]));
    }

    #[test]
    fn retain_present_does_not_rebuild_survivors() {
        let mut rendered = vec![
            Row {
                id: "a".into(),
                generation: 7,
            },
            Row {
                id: "b".into(),
                generation: 7,
            },
        ];
        let snapshot = ids(&["a"]);
        let present: HashSet<&str> = snapshot.iter().map(String::as_str).collect();
        let removed = retain_present(&mut rendered, &present, |r| r.id.as_str());
        assert_eq!(removed, 1);
        assert_eq!(
            rendered,
            vec![Row {
                id: "a".into(),
                generation: 7
            }],
            "surviving row lost its per-item state"
        );
    }

    #[test]
    fn absent_from_returns_snapshot_order() {
        let snapshot = ids(&["a", "b", "c", "d"]);
        let rendered: HashSet<&str> = ["b"].into_iter().collect();
        let missing = absent_from(&snapshot, &rendered, |s| s.as_str());
        assert_eq!(
            missing.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
            vec!["a", "c", "d"]
        );
    }

    #[test]
    fn id_set_collects_every_snapshot_id() {
        let snapshot = vec![
            Row {
                id: "a".into(),
                generation: 0,
            },
            Row {
                id: "b".into(),
                generation: 0,
            },
        ];
        let set = id_set(&snapshot, |r| r.id.as_str());
        assert!(set.contains("a") && set.contains("b"));
        assert_eq!(set.len(), 2);
    }

    /// Reconciliation must be idempotent: applying it twice to the same
    /// snapshot changes nothing the second time.
    #[test]
    fn reconciliation_is_idempotent() {
        let mut rendered = ids(&["a", "b"]);
        let snapshot = ids(&["b", "c"]);
        let first = reconcile_ids(&mut rendered, &snapshot);
        assert!(first.changed());
        let second = reconcile_ids(&mut rendered, &snapshot);
        assert!(!second.changed());
        assert_eq!(rendered, ids(&["b", "c"]));
    }
}
