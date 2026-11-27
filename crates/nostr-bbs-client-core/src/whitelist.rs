//! Paginated relay whitelist reader & membership derivations.
//!
//! Shared between `stores::admin_alerts`, `zone_crypto::auto_grant`, and the
//! admin membership surface.

use serde::{Deserialize, Serialize};

use crate::auth::nip98::fetch_with_nip98_get_signer;
use nostr_bbs_core::signer::Signer;

/// A whitelisted user returned from the relay API.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WhitelistUser {
    pub pubkey: String,
    #[serde(default)]
    pub cohorts: Vec<String>,
    #[serde(default, alias = "displayName")]
    pub display_name: Option<String>,
    #[serde(default, alias = "addedAt")]
    pub added_at: Option<u64>,
    #[serde(default, alias = "isAdmin")]
    pub is_admin: bool,
    /// Admin-only real name, enriched from auth-worker `/api/admin/registrations`.
    #[serde(default, skip)]
    pub real_name: Option<String>,
    /// Claimed public handle (username), enriched from auth-worker.
    #[serde(default, skip)]
    pub handle: Option<String>,
}

/// A username reservation returned from the auth-worker
/// `GET /api/admin/registrations` route.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Registration {
    pub pubkey: String,
    #[serde(default)]
    pub handle: Option<String>,
    #[serde(default)]
    pub real_name: Option<String>,
    #[serde(default)]
    pub created_at: u64,
}

/// Rows requested per page (the relay caps `limit` at 100).
pub const WHITELIST_PAGE_SIZE: u32 = 100;

/// Upper bound on requests per refresh.
const MAX_PAGES: u32 = 500;

#[derive(Deserialize)]
struct WhitelistPage {
    users: Vec<WhitelistUser>,
    #[serde(default)]
    total: Option<u64>,
}

/// Collects the whole relay whitelist, one page at a time.
pub struct WhitelistPager {
    users: Vec<WhitelistUser>,
    seen: std::collections::HashSet<String>,
    offset: u32,
    pages: u32,
    done: bool,
}

impl Default for WhitelistPager {
    fn default() -> Self {
        Self::new()
    }
}

impl WhitelistPager {
    pub fn new() -> Self {
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
    pub fn next_query(&self) -> Option<String> {
        if self.done {
            None
        } else {
            Some(format!(
                "?limit={WHITELIST_PAGE_SIZE}&offset={}",
                self.offset
            ))
        }
    }

    /// Absorb one response body.
    pub fn absorb(&mut self, body: &str) -> Result<(), String> {
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

    pub fn into_users(self) -> Vec<WhitelistUser> {
        self.users
    }
}

/// Reservations whose pubkey is not on the whitelist, newest first.
pub fn pending_registrations(
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

/// Cohort delta `(add, remove)` for `/api/whitelist/update-cohorts`.
pub fn cohort_delta(original: &[String], edited: &[String]) -> (Vec<String>, Vec<String>) {
    let mut add: Vec<String> = Vec::new();
    for c in edited {
        if !original.contains(c) && !add.contains(c) {
            add.push(c.clone());
        }
    }
    let mut remove: Vec<String> = Vec::new();
    for c in original {
        if !edited.contains(c) && !remove.contains(c) {
            remove.push(c.clone());
        }
    }
    (add, remove)
}

/// Fetch every row of the relay whitelist via NIP-98 paginated GETs.
pub async fn fetch_whitelist_rows(signer: &dyn Signer) -> Result<Vec<WhitelistUser>, String> {
    let base = format!(
        "{}/api/whitelist/list",
        crate::utils::relay_url::relay_api_base()
    );
    let mut pager = WhitelistPager::new();
    while let Some(query) = pager.next_query() {
        let body = fetch_with_nip98_get_signer(&format!("{base}{query}"), signer)
            .await
            .map_err(|e| format!("Failed to fetch whitelist: {e}"))?;
        pager.absorb(&body)?;
    }
    Ok(pager.into_users())
}
