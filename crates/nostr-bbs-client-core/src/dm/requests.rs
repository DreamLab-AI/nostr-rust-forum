//! Message requests (ADR-2027 decision 1, behind `RECIPIENT_KEYS_ENABLED`).
//!
//! Once a member's inbox is public, anyone on Nostr can message them. A DM
//! from someone who is neither a member of this board nor someone the member
//! already knows lands in "Requests" instead of the main list, and raises no
//! notification until the member accepts it. Accepting remembers the key;
//! blocking mutes it.
//!
//! The routing rule ([`lane`]) is a pure function of its arguments so it is
//! tested natively. [`RequestsStore`] holds the reactive state and persists the
//! accepted keys in IndexedDB under the member's pubkey.

use std::collections::{HashMap, HashSet};

use leptos::prelude::*;

/// Where a conversation is shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lane {
    /// The main conversation list.
    Main,
    /// The Requests tab: not yet accepted, no notification.
    Requests,
    /// Blocked: shown nowhere.
    Hidden,
}

/// Route a conversation with `counterparty`.
///
/// `is_member` is the whitelist answer: `Some(true)` member, `Some(false)` a
/// definite outsider, `None` not known (yet). Only a definite outsider is
/// moved to Requests, so a slow or failed lookup can never hide a member's
/// message; the failure mode is today's behaviour. With the flag off every
/// conversation stays in the main list, exactly as before.
pub fn lane(
    flag_on: bool,
    muted: bool,
    accepted: bool,
    is_member: Option<bool>,
    counterparty_is_me: bool,
) -> Lane {
    if !flag_on || counterparty_is_me {
        return Lane::Main;
    }
    if muted {
        return Lane::Hidden;
    }
    if accepted {
        return Lane::Main;
    }
    match is_member {
        Some(false) => Lane::Requests,
        _ => Lane::Main,
    }
}

/// Whether an incoming DM from `sender` should raise a notification: not when
/// it sits in Requests or is blocked.
pub fn notifies(lane: Lane) -> bool {
    lane == Lane::Main
}

/// Whether blocking should add a mute (the mute store only toggles).
pub fn should_mute_on_block(already_muted: bool) -> bool {
    !already_muted
}

/// `zone_kv` id of the accepted keys for `owner`.
pub fn accepted_id(owner: &str) -> String {
    format!("dm_accepted:v1:{owner}")
}

/// Accepted keys from their stored JSON; empty when absent or unreadable.
pub fn parse_accepted(json: Option<&str>) -> HashSet<String> {
    json.and_then(|j| serde_json::from_str::<Vec<String>>(j).ok())
        .map(|v| v.into_iter().collect())
        .unwrap_or_default()
}

/// Whether the requests inbox is switched on.
pub fn enabled() -> bool {
    crate::zone_crypto::inbox_key::recipient_keys_enabled()
}

/// What the relay's `/api/check-whitelist` says about a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Access {
    /// On the whitelist (or an admin): a member.
    pub member: bool,
    /// An ingress recipient: the relay admits wraps addressed to it even when it
    /// is not whitelisted.
    pub ingress: bool,
}

impl Access {
    /// Parse the reply body. `None` when it carries neither answer.
    pub fn parse(body: &serde_json::Value) -> Option<Self> {
        let flag = |k: &str| body.get(k).and_then(|b| b.as_bool());
        if flag("isWhitelisted").is_none() && flag("ingressRecipient").is_none() {
            return None;
        }
        Some(Self {
            member: flag("isWhitelisted") == Some(true) || flag("isAdmin") == Some(true),
            ingress: flag("ingressRecipient") == Some(true),
        })
    }

    /// Whether the relay accepts a wrap addressed to this key (outbound).
    pub fn reachable(self) -> bool {
        self.member || self.ingress
    }
}

thread_local! {
    /// Definite answers for this page session.
    static ACCESS_CACHE: std::cell::RefCell<HashMap<String, Access>> =
        std::cell::RefCell::new(HashMap::new());
}

async fn access_cached(pubkey: &str) -> Option<Access> {
    if let Some(v) = ACCESS_CACHE.with(|c| c.borrow().get(pubkey).copied()) {
        return Some(v);
    }
    let v = fetch_access(pubkey).await?;
    ACCESS_CACHE.with(|c| c.borrow_mut().insert(pubkey.to_string(), v));
    Some(v)
}

/// Membership with a per-session cache, shared by the list and the
/// notification watcher so a backlog of wraps from one sender costs one
/// request. Inbound lane semantics: an ingress recipient who is not whitelisted
/// is NOT a member here.
pub async fn is_member_cached(pubkey: &str) -> Option<bool> {
    access_cached(pubkey).await.map(|a| a.member)
}

/// Whether our relay accepts a wrap addressed to `pubkey` (member or ingress
/// recipient), for the outbound path.
pub async fn reaches_our_relay_cached(pubkey: &str) -> Option<bool> {
    access_cached(pubkey).await.map(Access::reachable)
}

async fn fetch_access(pubkey: &str) -> Option<Access> {
    use wasm_bindgen::JsCast;
    use wasm_bindgen_futures::JsFuture;
    let url = format!(
        "{}/api/check-whitelist?pubkey={}",
        crate::utils::relay_url::relay_api_base(),
        pubkey
    );
    let win = web_sys::window()?;
    let resp: web_sys::Response = JsFuture::from(win.fetch_with_str(&url))
        .await
        .ok()?
        .dyn_into()
        .ok()?;
    if !resp.ok() {
        return None;
    }
    let text = JsFuture::from(resp.text().ok()?).await.ok()?.as_string()?;
    Access::parse(&serde_json::from_str(&text).ok()?)
}

/// The unread total for the badge: Requests and blocked conversations do not
/// count. Input is `(unread, lane)` per conversation.
pub fn unread_total(items: impl IntoIterator<Item = (u32, Lane)>) -> u32 {
    items
        .into_iter()
        .filter(|(_, l)| *l == Lane::Main)
        .map(|(n, _)| n)
        .sum()
}

/// Whether the app-wide watcher should raise a notification for a DM from
/// `sender` to `me`. Always true with the flag off; otherwise false for a
/// definite outsider the member has not accepted. The watcher has no reactive
/// owner, so this reads the accepted keys from IndexedDB itself.
pub async fn notifies_for(sender: &str, me: &str) -> bool {
    if !enabled() || sender == me {
        return true;
    }
    let json = match crate::stores::indexed_db::ForumDb::open().await {
        Ok(db) => db.get_zone_kv(&accepted_id(me)).await.ok().flatten(),
        Err(_) => None,
    };
    let accepted = parse_accepted(json.as_deref()).contains(sender);
    let member = if accepted {
        None
    } else {
        is_member_cached(sender).await
    };
    notifies(lane(true, false, accepted, member, false))
}

/// Reactive requests state: accepted keys and membership answers.
#[derive(Clone, Copy)]
pub struct RequestsStore {
    me: StoredValue<String>,
    accepted: RwSignal<HashSet<String>>,
    members: RwSignal<HashMap<String, bool>>,
    asked: StoredValue<HashSet<String>>,
}

impl RequestsStore {
    /// Create the store for member `me` and load their accepted keys.
    pub fn new(me: &str) -> Self {
        let store = Self {
            me: StoredValue::new(me.to_string()),
            accepted: RwSignal::new(HashSet::new()),
            members: RwSignal::new(HashMap::new()),
            asked: StoredValue::new(HashSet::new()),
        };
        if enabled() {
            let id = accepted_id(me);
            wasm_bindgen_futures::spawn_local(async move {
                let json = match crate::stores::indexed_db::ForumDb::open().await {
                    Ok(db) => db.get_zone_kv(&id).await.ok().flatten(),
                    Err(_) => None,
                };
                let loaded = parse_accepted(json.as_deref());
                store.accepted.update(|a| a.extend(loaded));
            });
        }
        store
    }

    /// Where `pubkey`'s conversation belongs (reactive).
    pub fn lane_of(&self, pubkey: &str, muted: bool) -> Lane {
        lane(
            enabled(),
            muted,
            self.accepted.with(|a| a.contains(pubkey)),
            self.members.with(|m| m.get(pubkey).copied()),
            self.me.with_value(|m| m == pubkey),
        )
    }

    /// Look up membership of every key not yet asked about.
    pub fn resolve(&self, pubkeys: &[String]) {
        if !enabled() {
            return;
        }
        for pk in pubkeys {
            if !self
                .asked
                .try_update_value(|s| s.insert(pk.clone()))
                .unwrap_or(false)
            {
                continue;
            }
            let (store, pk) = (*self, pk.clone());
            wasm_bindgen_futures::spawn_local(async move {
                match is_member_cached(&pk).await {
                    Some(v) => store.members.update(|m| {
                        m.insert(pk, v);
                    }),
                    // Unknown: allow another try on the next pass.
                    None => store.asked.update_value(|s| {
                        s.remove(&pk);
                    }),
                }
            });
        }
    }

    /// Accept `pubkey`: its conversation moves to the main list for good.
    pub fn accept(&self, pubkey: &str) {
        self.accepted.update(|a| {
            a.insert(pubkey.to_string());
        });
        let mut keys: Vec<String> = self.accepted.get_untracked().into_iter().collect();
        keys.sort();
        let id = accepted_id(&self.me.get_value());
        wasm_bindgen_futures::spawn_local(async move {
            if let (Ok(db), Ok(json)) = (
                crate::stores::indexed_db::ForumDb::open().await,
                serde_json::to_string(&keys),
            ) {
                let _ = db.put_zone_kv(&id, &json).await;
            }
        });
    }

    /// Block `pubkey`: hide the conversation and add it to the mute list.
    pub fn block(&self, pubkey: &str, mutes: crate::stores::mute::MuteStore) {
        if should_mute_on_block(mutes.is_user_muted(pubkey)) {
            mutes.toggle_mute_user(pubkey);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OUTSIDER: &str = "b";

    #[test]
    fn an_outsider_dm_lands_in_requests() {
        assert_eq!(lane(true, false, false, Some(false), false), Lane::Requests);
    }

    #[test]
    fn accepting_moves_it_to_the_main_list() {
        assert_eq!(lane(true, false, true, Some(false), false), Lane::Main);
    }

    #[test]
    fn blocking_hides_it_and_adds_one_mute() {
        assert_eq!(lane(true, true, false, Some(false), false), Lane::Hidden);
        assert!(should_mute_on_block(false));
        assert!(
            !should_mute_on_block(true),
            "an existing mute is not toggled off"
        );
    }

    #[test]
    fn a_member_dm_never_lands_in_requests() {
        for accepted in [false, true] {
            assert_eq!(lane(true, false, accepted, Some(true), false), Lane::Main);
        }
    }

    #[test]
    fn an_unknown_membership_keeps_today_behaviour() {
        assert_eq!(lane(true, false, false, None, false), Lane::Main);
    }

    #[test]
    fn flag_off_changes_nothing_even_for_a_muted_outsider() {
        assert_eq!(lane(false, true, false, Some(false), false), Lane::Main);
    }

    #[test]
    fn requests_and_blocked_conversations_raise_no_notification() {
        assert!(notifies(Lane::Main));
        assert!(!notifies(Lane::Requests));
        assert!(!notifies(Lane::Hidden));
    }

    #[test]
    fn accepted_keys_round_trip_and_survive_bad_json() {
        let json = serde_json::to_string(&[OUTSIDER]).unwrap();
        assert!(parse_accepted(Some(&json)).contains(OUTSIDER));
        assert!(parse_accepted(Some("{")).is_empty());
        assert!(parse_accepted(None).is_empty());
        assert_eq!(accepted_id("me"), "dm_accepted:v1:me");
    }

    #[test]
    fn an_ingress_recipient_is_reachable_but_not_a_member() {
        let a =
            Access::parse(&serde_json::json!({"isWhitelisted": false, "ingressRecipient": true}))
                .unwrap();
        assert!(!a.member, "inbound lane: still an outsider");
        assert!(a.reachable(), "outbound: our relay accepts the wrap");
        let m = Access::parse(&serde_json::json!({"isWhitelisted": true})).unwrap();
        assert!(m.member && m.reachable());
        let out = Access::parse(&serde_json::json!({"isWhitelisted": false})).unwrap();
        assert!(!out.reachable());
        assert!(Access::parse(&serde_json::json!({})).is_none());
    }

    #[test]
    fn requests_do_not_count_toward_the_unread_badge() {
        let total = unread_total([
            (2, Lane::Main),
            (5, Lane::Requests),
            (3, Lane::Hidden),
            (1, Lane::Main),
        ]);
        assert_eq!(total, 3);
    }

    #[test]
    fn a_note_to_self_is_never_a_request() {
        assert_eq!(lane(true, false, false, Some(false), true), Lane::Main);
    }
}
