//! Pure membership derivations for the admin panel.
//!
//! Two things live here because they decide which members the admin panel
//! believes exist, and both must be testable natively (no DOM, no network):
//!
//! - [`WhitelistPager`] — walks the relay's paginated `GET /api/whitelist/list`
//!   until every row has been read.
//! - [`pending_registrations`] — the Pending set: auth-worker username
//!   reservations whose pubkey is not on the relay whitelist.

use serde::Deserialize;

use super::{Registration, WhitelistUser};

/// Rows requested per page: the relay's hard cap on `limit`
/// (`crates/nostr-bbs-relay-worker/src/whitelist.rs`, `handle_whitelist_list`,
/// `.min(100)`). Asking for more is silently clamped, so asking for exactly
/// this makes a short page a reliable end-of-list signal.
pub(crate) const WHITELIST_PAGE_SIZE: u32 = 100;

/// Upper bound on requests per refresh, so a relay that ignores `offset`
/// cannot spin the client forever. 500 pages is 50 000 members.
const MAX_PAGES: u32 = 500;

/// Page shape of the relay's `GET /api/whitelist/list`.
#[derive(Deserialize)]
struct WhitelistPage {
    users: Vec<WhitelistUser>,
    /// Row count across all pages.
    #[serde(default)]
    total: Option<u64>,
}

/// Collects the whole relay whitelist, one page at a time.
///
/// The relay pages `GET /api/whitelist/list` with a default `limit` of 20.
/// Reading a single unparameterised page saw only the 20 most recently added
/// members: every older member was missing from the Members table and was
/// reported as Pending, and approving them could not help, because the
/// relay's upsert keeps the original `added_at` and so never moves the row
/// into the first page.
///
/// Drive it with `while let Some(q) = pager.next_query() { … pager.absorb(&body)?; }`.
pub(crate) struct WhitelistPager {
    users: Vec<WhitelistUser>,
    seen: std::collections::HashSet<String>,
    offset: u32,
    pages: u32,
    done: bool,
}

impl WhitelistPager {
    pub(crate) fn new() -> Self {
        Self {
            users: Vec::new(),
            seen: std::collections::HashSet::new(),
            offset: 0,
            pages: 0,
            done: false,
        }
    }

    /// Query string for the next request (`?limit=…&offset=…`), or `None`
    /// once the whitelist is fully read.
    pub(crate) fn next_query(&self) -> Option<String> {
        if self.done {
            None
        } else {
            Some(format!(
                "?limit={WHITELIST_PAGE_SIZE}&offset={}",
                self.offset
            ))
        }
    }

    /// Absorb one response body. Stops after a short or empty page, once
    /// `total` rows have been read, or at [`MAX_PAGES`]. A member seen on two
    /// pages (offset pages shift if a row is added mid-walk) is kept once.
    pub(crate) fn absorb(&mut self, body: &str) -> Result<(), String> {
        let page: WhitelistPage =
            serde_json::from_str(body).map_err(|e| format!("Failed to parse whitelist: {e}"))?;
        let returned = page.users.len() as u32;
        for user in page.users {
            if self.seen.insert(user.pubkey.to_ascii_lowercase()) {
                self.users.push(user);
            }
        }
        self.pages += 1;
        self.offset = self.offset.saturating_add(returned);
        let reached_total = page.total.is_some_and(|t| u64::from(self.offset) >= t);
        self.done = returned < WHITELIST_PAGE_SIZE || reached_total || self.pages >= MAX_PAGES;
        Ok(())
    }

    pub(crate) fn into_users(self) -> Vec<WhitelistUser> {
        self.users
    }
}

/// The Pending set: reservations whose pubkey is not on the whitelist,
/// newest first. Pubkeys compare case-insensitively: the relay stores
/// whatever hex case an admin typed (`/api/whitelist/add` validates but does
/// not lowercase), while the auth worker stores the NIP-98 signer's
/// lowercase hex.
pub(crate) fn pending_registrations(
    registrations: &[Registration],
    whitelist: &[WhitelistUser],
) -> Vec<Registration> {
    let whitelisted: std::collections::HashSet<String> = whitelist
        .iter()
        .map(|u| u.pubkey.to_ascii_lowercase())
        .collect();
    let mut pending: Vec<Registration> = registrations
        .iter()
        .filter(|r| !whitelisted.contains(&r.pubkey.to_ascii_lowercase()))
        .cloned()
        .collect();
    pending.sort_by_key(|r| std::cmp::Reverse(r.created_at));
    pending
}

#[cfg(test)]
mod tests {
    use super::*;

    /// In-memory model of the relay whitelist endpoints, reproducing the
    /// rules that matter here from `crates/nostr-bbs-relay-worker/src/whitelist.rs`:
    ///
    /// - `GET /api/whitelist/list`: `limit` defaults to 20 and is capped at
    ///   100; `offset` defaults to 0; rows are `ORDER BY added_at DESC`.
    /// - `POST /api/whitelist/add`: `INSERT … ON CONFLICT (pubkey) DO UPDATE SET
    ///   cohorts = excluded.cohorts, added_by = excluded.added_by` — an existing
    ///   row keeps its original `added_at`.
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
                row.1 = cohorts; // added_at deliberately untouched
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
}
