//! Whether the SIGNER of a decision is an admin, as the relay says.
//!
//! The panel-level `acknowledge-alerts` rule counts a 31403 only when an admin
//! signed it — the same authority the relay's 31403 admission gate applies to a
//! case decision. The viewer's own admin flag (`ZoneAccess::is_admin`) cannot
//! answer that for somebody else, so this cache asks the relay's public
//! `GET /api/check-whitelist?pubkey=` per signer and records its `isAdmin`.
//!
//! **Fail-closed.** A signer not yet answered for, a failed fetch, or a
//! dev-auth/host build all read as "not an admin": the acknowledgement simply
//! does not show until the relay has vouched for the signer.

use std::collections::{HashMap, HashSet};

use leptos::prelude::*;

/// Reactive per-pubkey admin answers, keyed by lowercase hex pubkey.
#[derive(Clone, Copy)]
pub struct SignerAdminCache {
    known: RwSignal<HashMap<String, bool>>,
    requested: StoredValue<HashSet<String>>,
}

impl SignerAdminCache {
    /// An empty cache, owned by the calling reactive scope.
    pub fn new() -> Self {
        Self {
            known: RwSignal::new(HashMap::new()),
            requested: StoredValue::new(HashSet::new()),
        }
    }

    /// The relay's answer for `pubkey`; `false` until it has given one.
    /// Tracks, so a view recomputes when the answer arrives.
    pub fn is_admin(&self, pubkey: &str) -> bool {
        self.known
            .read()
            .get(&pubkey.to_ascii_lowercase())
            .copied()
            .unwrap_or(false)
    }

    /// Ask the relay about each pubkey not already asked about.
    pub fn request<'a>(&self, pubkeys: impl IntoIterator<Item = &'a str>) {
        for pk in pubkeys {
            let pk = pk.to_ascii_lowercase();
            if pk.len() != 64 || !pk.bytes().all(|b| b.is_ascii_hexdigit()) {
                continue;
            }
            let fresh = self.requested.try_update_value(|r| r.insert(pk.clone()));
            if fresh != Some(true) {
                continue;
            }
            self.fetch(pk);
        }
    }

    #[cfg(all(target_arch = "wasm32", not(feature = "dev-auth")))]
    fn fetch(&self, pubkey: String) {
        let known = self.known;
        leptos::task::spawn_local(async move {
            match fetch_is_admin(&pubkey).await {
                Ok(admin) => known.update(|k| {
                    k.insert(pubkey, admin);
                }),
                Err(e) => web_sys::console::warn_1(
                    &format!("[signer_admin] check-whitelist failed: {e}").into(),
                ),
            }
        });
    }

    #[cfg(not(all(target_arch = "wasm32", not(feature = "dev-auth"))))]
    fn fetch(&self, _pubkey: String) {}
}

impl Default for SignerAdminCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(all(target_arch = "wasm32", not(feature = "dev-auth")))]
async fn fetch_is_admin(pubkey: &str) -> Result<bool, String> {
    let url = format!(
        "{}/api/check-whitelist?pubkey={pubkey}",
        crate::utils::relay_url::relay_api_base()
    );
    let resp = gloo::net::http::Request::get(&url)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !resp.ok() {
        return Err(format!("HTTP {}", resp.status()));
    }
    let body: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
    Ok(parse_is_admin(&body))
}

/// `isAdmin` from a check-whitelist body; anything but `true` is `false`.
#[cfg_attr(
    not(all(target_arch = "wasm32", not(feature = "dev-auth"))),
    allow(dead_code)
)]
fn parse_is_admin(body: &serde_json::Value) -> bool {
    body.get("isAdmin").and_then(|v| v.as_bool()) == Some(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_an_explicit_true_is_an_admin() {
        assert!(parse_is_admin(&serde_json::json!({"isAdmin": true})));
        assert!(!parse_is_admin(&serde_json::json!({"isAdmin": false})));
        assert!(!parse_is_admin(&serde_json::json!({"isAdmin": "true"})));
        assert!(!parse_is_admin(&serde_json::json!({})));
    }

    #[test]
    fn an_unanswered_signer_is_not_an_admin() {
        let owner = Owner::new();
        owner.with(|| {
            let cache = SignerAdminCache::new();
            cache.request(["b41654017f6850b13857d19d8ae0e3f88f1365600cab0321e8101c9e92682f7a"]);
            assert!(
                !cache.is_admin("b41654017f6850b13857d19d8ae0e3f88f1365600cab0321e8101c9e92682f7a")
            );
        });
    }
}
