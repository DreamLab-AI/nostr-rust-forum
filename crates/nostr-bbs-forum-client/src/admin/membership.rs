//! Pure membership derivations for the admin panel.
//!
//! Two things live here because they decide which members the admin panel
//! believes exist, and both must be testable natively (no DOM, no network):
//!
//! - [`WhitelistPager`] — walks the relay's paginated `GET /api/whitelist/list`
//!   until every row has been read.
//! - [`pending_registrations`] — the Pending set: auth-worker username
//!   reservations whose pubkey is not on the relay whitelist.

#[allow(unused_imports)]
pub(crate) use nostr_bbs_client_core::whitelist::{
    cohort_delta, pending_registrations, WhitelistPager, WHITELIST_PAGE_SIZE,
};

#[cfg(test)]
use super::{Registration, WhitelistUser};

#[cfg(test)]
mod tests {
    use super::*;

    /// In-memory model of the relay whitelist endpoints, reproducing the
    /// rules that matter here from `crates/nostr-bbs-relay-worker/src/whitelist.rs`:
    ///
    /// - `GET /api/whitelist/list`: `limit` defaults to 20 and is capped at
    ///   100; `offset` defaults to 0; rows are `ORDER BY added_at DESC`.
    /// - `POST /api/whitelist/add`: `nostr_bbs_core::whitelist_sql::
    ///   WHITELIST_GRANT_COHORTS_SQL` — granted cohorts are merged into an
    ///   existing row's set (ADR-2014 D2), which keeps its original `added_at`.
    struct FakeRelay {
        /// (pubkey, cohorts, added_at)
        rows: Vec<(String, Vec<String>, u64)>,
        clock: u64,
    }

    impl FakeRelay {
        fn new() -> Self {
            Self {
                rows: Vec::new(),
                clock: 1_700_000_000,
            }
        }

        fn add(&mut self, pubkey: &str, cohorts: &[&str]) {
            self.clock += 1;
            let cohorts: Vec<String> = cohorts.iter().map(|c| c.to_string()).collect();
            if let Some(row) = self.rows.iter_mut().find(|r| r.0 == pubkey) {
                // Merge, as the relay does; added_at deliberately untouched.
                for c in cohorts {
                    if !row.1.contains(&c) {
                        row.1.push(c);
                    }
                }
            } else {
                self.rows.push((pubkey.to_string(), cohorts, self.clock));
            }
        }

        fn list(&self, query: &str) -> String {
            let param = |name: &str| -> Option<u32> {
                query
                    .trim_start_matches('?')
                    .split('&')
                    .filter_map(|kv| kv.split_once('='))
                    .find(|(k, _)| *k == name)
                    .and_then(|(_, v)| v.parse().ok())
            };
            let limit = param("limit").unwrap_or(20).min(100) as usize;
            let offset = param("offset").unwrap_or(0) as usize;
            let mut sorted = self.rows.clone();
            sorted.sort_by_key(|r| std::cmp::Reverse(r.2));
            let users: Vec<serde_json::Value> = sorted
                .iter()
                .skip(offset)
                .take(limit)
                .map(|(pk, cohorts, added)| {
                    serde_json::json!({
                        "pubkey": pk,
                        "cohorts": cohorts,
                        "addedAt": added,
                        "addedBy": "admin",
                        "displayName": null,
                        "isAdmin": false,
                    })
                })
                .collect();
            serde_json::json!({
                "users": users,
                "total": self.rows.len(),
                "limit": limit,
                "offset": offset,
            })
            .to_string()
        }
    }

    /// What the admin store does on every whitelist refresh.
    fn fetch_all(relay: &FakeRelay) -> Vec<WhitelistUser> {
        let mut pager = WhitelistPager::new();
        let mut requests = 0;
        while let Some(q) = pager.next_query() {
            requests += 1;
            assert!(requests < 1_000, "pager failed to terminate");
            pager.absorb(&relay.list(&q)).expect("valid page");
        }
        pager.into_users()
    }

    fn pk(i: usize) -> String {
        format!("{i:064x}")
    }

    fn registration(i: usize) -> Registration {
        Registration {
            pubkey: pk(i),
            handle: Some(format!("user{i}")),
            real_name: None,
            created_at: 1_600_000_000 + i as u64,
        }
    }

    /// The operator's report: 28 members, every one auto-whitelisted at
    /// username claim (`auth-worker/src/username.rs`, `INSERT INTO whitelist …
    /// ON CONFLICT DO NOTHING`). The Pending tab shows the 8 oldest, and
    /// approving them — singly or in bulk — leaves them pending.
    #[test]
    fn approving_pending_members_removes_them_from_pending() {
        let mut relay = FakeRelay::new();
        let registrations: Vec<Registration> = (0..28).map(registration).collect();
        for r in &registrations {
            relay.add(&r.pubkey, &["members"]);
        }

        let pending = pending_registrations(&registrations, &fetch_all(&relay));
        for r in &pending {
            relay.add(&r.pubkey, &["friends"]);
        }
        let after = pending_registrations(&registrations, &fetch_all(&relay));

        assert!(
            after.is_empty(),
            "{} members still pending after approval: {:?}",
            after.len(),
            after.iter().map(|r| r.handle.clone()).collect::<Vec<_>>()
        );
    }

    /// Every whitelisted member is visible, however large the whitelist is.
    #[test]
    fn pager_reads_every_row_past_the_relay_page_cap() {
        let mut relay = FakeRelay::new();
        for i in 0..250 {
            relay.add(&pk(i), &["members"]);
        }
        let users = fetch_all(&relay);
        assert_eq!(users.len(), 250);
        let unique: std::collections::HashSet<_> = users.iter().map(|u| &u.pubkey).collect();
        assert_eq!(unique.len(), 250);
    }

    #[test]
    fn pager_handles_an_empty_whitelist() {
        assert!(fetch_all(&FakeRelay::new()).is_empty());
    }

    /// A genuinely new sign-up (reserved, never whitelisted) is pending.
    #[test]
    fn unwhitelisted_registration_is_pending() {
        let mut relay = FakeRelay::new();
        let registrations: Vec<Registration> = (0..3).map(registration).collect();
        relay.add(&registrations[0].pubkey, &["members"]);
        let pending = pending_registrations(&registrations, &fetch_all(&relay));
        let handles: Vec<_> = pending.iter().filter_map(|r| r.handle.clone()).collect();
        assert_eq!(handles, vec!["user2", "user1"]);
    }

    /// Hex case never splits one member into "whitelisted" and "pending".
    #[test]
    fn pending_comparison_ignores_hex_case() {
        let mut relay = FakeRelay::new();
        let mut reg = registration(0xab);
        relay.add(&reg.pubkey.to_uppercase(), &["members"]);
        reg.pubkey = reg.pubkey.to_lowercase();
        assert!(pending_registrations(&[reg], &fetch_all(&relay)).is_empty());
    }

    fn owned(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn cohort_delta_reports_only_what_the_editor_changed() {
        let (add, remove) = cohort_delta(
            &owned(&["home", "zone2", "agent"]),
            &owned(&["home", "agent", "zone3"]),
        );
        assert_eq!(add, ["zone3"]);
        assert_eq!(remove, ["zone2"]);
    }

    #[test]
    fn unchanged_editor_yields_an_empty_delta() {
        let (add, remove) = cohort_delta(&owned(&["home", "zone2"]), &owned(&["zone2", "home"]));
        assert!(add.is_empty() && remove.is_empty());
    }

    #[test]
    fn unticking_a_zone_group_removes_every_equivalent_name() {
        // The editor drops every name in a zone's equivalence group at once.
        let (add, remove) = cohort_delta(&owned(&["members", "zone2", "home"]), &owned(&["home"]));
        assert!(add.is_empty());
        assert_eq!(remove, ["members", "zone2"]);
    }

    #[test]
    fn approve_merges_into_cohorts_already_held() {
        let mut relay = FakeRelay::new();
        relay.add(&pk(1), &["zone2"]);
        relay.add(&pk(1), &["home"]);
        let users = fetch_all(&relay);
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].cohorts, ["zone2", "home"]);
    }
}
