//! Browser data is scoped to one relay.
//!
//! The forum caches (IndexedDB `members-forum`, the sealed-search index and a
//! few localStorage entries) hold events, ids and bookkeeping from the relay
//! they were read from. When a site moves its members to another relay on
//! the same origin, that data must not leak into the new relay's view: stale
//! channels and messages, an outbox of events signed for the old relay, or
//! "already unwrapped" marks that would hide the new relay's key grants.
//!
//! [`enforce`] runs before the app mounts. It compares the current scope
//! ([`current`]: the relay URL, plus an optional `VITE_RELAY_EPOCH` for a
//! relay replaced under the same URL) with the one recorded in localStorage,
//! and on any difference (including no record: data from before scoping)
//! clears the relay-scoped data, then records the scope. Identity keys,
//! zone keys, the inbox key, preferences, mutes, bookmarks and read
//! positions are kept: they belong to the member, not to the relay.

/// localStorage entry recording the scope the stored data belongs to.
const SCOPE_KEY: &str = "nostrbbs:relay_scope";

/// localStorage entries holding relay data, removed when the scope changes.
pub const RELAY_SCOPED_LOCAL_KEYS: &[&str] = &[
    "nostrbbs_channel_cache",
    "admin_settings_cache",
    "nostrbbs_admin_seen_joiners",
    "nostrbbs:push_refreshed_ms",
];

/// Prefixes of localStorage entries holding relay data, removed when the
/// scope changes: per-zone sealed-search high-water marks, per-identity
/// notification lists and sync cursors, deletion-sync cursors, and the
/// "DM relay list already published" marks (the new relay needs its own).
pub const RELAY_SCOPED_LOCAL_PREFIXES: &[&str] = &[
    "nbss:",
    "nostrbbs:notifications",
    "nostrbbs:notif_sync",
    "nostrbbs_deletion_sync",
    "nostr_bbs_dm_relay_published_",
];

/// Whether localStorage entry `key` holds relay data.
pub fn relay_scoped_local(key: &str) -> bool {
    RELAY_SCOPED_LOCAL_KEYS.contains(&key)
        || RELAY_SCOPED_LOCAL_PREFIXES
            .iter()
            .any(|p| key.starts_with(p))
}

/// The scope for relay `url` and deployment `epoch`: the URL lower-cased,
/// trimmed, without trailing slashes, then `#epoch` when one is set.
pub fn scope_of(url: &str, epoch: Option<&str>) -> String {
    let url = url.trim().trim_end_matches('/').to_ascii_lowercase();
    match epoch.map(str::trim).filter(|e| !e.is_empty()) {
        Some(e) => format!("{url}#{e}"),
        None => url,
    }
}

thread_local! {
    /// Set once the app has mounted without waiting for [`enforce`]: a clear
    /// still running then stops before its next step, so it never deletes
    /// what the live app writes; it is retried on the next load.
    static ABANDONED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Stop a still-running [`enforce`] before its next step (see `ABANDONED`).
pub fn abandon() {
    ABANDONED.with(|a| a.set(true));
}

fn go_on() -> bool {
    !ABANDONED.with(std::cell::Cell::get)
}

/// The current relay scope, from the URL the relay connection itself uses.
pub fn current() -> String {
    scope_of(
        &crate::relay::configured_relay_url(),
        crate::utils::relay_url::window_env("VITE_RELAY_EPOCH").as_deref(),
    )
}

/// Whether the recorded scope `stored` differs from `current`: absent counts
/// as different (data from before scoping existed is of unknown origin).
pub fn scope_changed(stored: Option<&str>, current: &str) -> bool {
    stored != Some(current)
}

/// Clear relay-scoped data if the scope changed, then record the current
/// scope. The scope is recorded only once every store cleared, so a failed
/// clear is retried on the next load.
pub async fn enforce() {
    let Some(storage) = web_sys::window().and_then(|w| w.local_storage().ok().flatten()) else {
        return;
    };
    let now = current();
    let stored = storage.get_item(SCOPE_KEY).ok().flatten();
    if !scope_changed(stored.as_deref(), &now) {
        return;
    }
    let mut ok = true;
    // No IndexedDB at all (blocked storage): nothing persisted there to clear.
    if let Ok(db) = crate::stores::indexed_db::ForumDb::open().await {
        match db.clear_relay_scoped(&go_on).await {
            Ok(true) => {}
            Ok(false) => return,
            Err(e) => {
                web_sys::console::warn_1(
                    &format!("[relay-scope] clearing cached relay data failed: {e:?}").into(),
                );
                ok = false;
            }
        }
    }
    if !go_on() {
        return;
    }
    crate::utils::sealed_search::wipe();
    let n = storage.length().unwrap_or(0);
    let doomed: Vec<String> = (0..n)
        .filter_map(|i| storage.key(i).ok().flatten())
        .filter(|k| relay_scoped_local(k))
        .collect();
    for k in doomed {
        if storage.remove_item(&k).is_err() {
            ok = false;
        }
    }
    if ok && storage.set_item(SCOPE_KEY, &now).is_err() {
        web_sys::console::warn_1(
            &"[relay-scope] could not record the relay scope; the clear repeats on the next load"
                .into(),
        );
        ok = false;
    }
    if ok {
        web_sys::console::log_1(
            &format!(
                "[relay-scope] relay changed ({} -> {now}): cleared cached relay data",
                stored.as_deref().unwrap_or("unrecorded")
            )
            .into(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_normalises_the_url_and_adds_the_epoch() {
        assert_eq!(
            scope_of(" WSS://Relay.Example/ ", None),
            "wss://relay.example"
        );
        assert_eq!(scope_of("wss://r.example//", Some("")), "wss://r.example");
        assert_eq!(
            scope_of("wss://r.example", Some("v2")),
            "wss://r.example#v2"
        );
    }

    #[test]
    fn a_new_url_a_new_epoch_or_no_record_is_a_change() {
        let v1 = scope_of("wss://old.example", None);
        let v2 = scope_of("wss://new.example", None);
        assert!(!scope_changed(Some(&v1), &v1));
        assert!(scope_changed(Some(&v1), &v2));
        assert!(scope_changed(None, &v1));
        let same_url_new_relay = scope_of("wss://old.example", Some("v2"));
        assert!(scope_changed(Some(&v1), &same_url_new_relay));
    }

    #[test]
    fn member_data_is_never_relay_scoped() {
        for kept in [
            "nostr_bbs_keys",
            "nostr_bbs_sk",
            "nostr_bbs_remember",
            "nostrbbs:preferences",
            "nostrbbs:mutes",
            "nostrbbs:read_positions",
            "nostrbbs_bookmarks",
            "nostrbbs:nsec_backup_dismissed",
        ] {
            assert!(!relay_scoped_local(kept), "{kept}");
        }
        assert!(relay_scoped_local("nbss:hw:zone2"));
        let o = "a".repeat(64);
        assert!(relay_scoped_local(&format!("nostrbbs:notifications:{o}")));
        assert!(relay_scoped_local(&format!("nostrbbs:notif_sync:{o}")));
        assert!(relay_scoped_local("nostrbbs_deletion_sync_v3_channels"));
        assert!(relay_scoped_local(&format!(
            "nostr_bbs_dm_relay_published_{o}"
        )));
        assert!(relay_scoped_local("nostrbbs_channel_cache"));
        use crate::stores::indexed_db::relay_scoped_kv;
        let o = "a".repeat(64);
        use crate::zone_crypto::grant_ledger::{approved_id, ledger_id, ledger_id_v1};
        for cleared in [
            "processed_wraps".to_string(),
            format!("processed_wraps:{}", scope_of("wss://x", None)),
            format!("inbox_granted:{o}"),
            format!("grant_cleanup_finished:v1:{o}"),
            ledger_id("zone2", 1),
            ledger_id_v1("zone2", 1),
        ] {
            assert!(relay_scoped_kv(&cleared), "{cleared}");
        }
        for kept in [
            format!("inbox_key:v1:{o}"),
            format!("dm_accepted:v1:{o}"),
            format!("dm-foreign-consent/v1/{o}/{o}"),
            format!("public_inbox:v1:{o}"),
            // Secrets and the first-grant gate are never relay data.
            format!("refused_keys:{o}"),
            approved_id("zone2"),
        ] {
            assert!(!relay_scoped_kv(&kept), "{kept}");
        }
    }
}
