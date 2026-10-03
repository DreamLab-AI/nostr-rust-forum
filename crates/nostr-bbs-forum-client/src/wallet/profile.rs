//! Which chains this deployment's wallet offers, and how each is reached
//! (ADR-2021).
//!
//! A [`ChainProfile`] is one of the compiled-in locks ([`chain::PINS`]) with
//! what runtime config may set around it: the mirror, the relays, the asset
//! id and ticker, a label, and the house seat of its poker table. The pin
//! itself (id, parent, genesis, sealed document) never comes from config.
//!
//! The deployment lists its chains in `window.__ENV__.SIDESTR_CHAINS`, a JSON
//! array (a string or an already-parsed array) of
//! `{ "id", "mirror"?, "asset_id"?, "ticker"?, "label"?, "icon"?, "citizen_pubkey"?, "relays"? }`,
//! in the order the wallet offers them. An entry naming a chain that is not
//! pinned is ignored with a warning, as is any field that does not read
//! (a mirror that is not `https://`, an asset id that is not 64 hex digits);
//! the pin's default stands in for the field. Absent (or naming no pinned
//! chain), the wallet offers `sidestr:dreamlab` alone, as before.
//!
//! The older single-chain keys still work and apply to `sidestr:dreamlab`
//! wherever its entry does not say otherwise: `SIDESTR_MIRROR` and
//! `SIDESTR_RELAYS` (comma-separated `wss://` URLs).
//!
//! [`resolve`] is pure, so the rules are tested natively; [`profiles`] reads
//! the page's config once and keeps the answer for the session.

use std::sync::OnceLock;

use bitcoin::Txid;
use serde::Deserialize;

use super::chain::{self, Pin};

/// One chain the wallet offers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainProfile {
    /// The chain's lock.
    pin: &'static Pin,
    /// The chain id (the pin's).
    pub id: &'static str,
    /// The parent alias (`tbtc4`, `txbt4`; the pin's).
    pub parent: &'static str,
    /// The parent in words (`testnet4`, `BLAKE2b testnet4`).
    pub parent_name: &'static str,
    /// The genesis the chain seals (the pin's).
    pub genesis_hash: &'static str,
    /// What the chain's money is called in headings ("DREAM", "BLAKES7").
    pub label: String,
    /// The mirror base URL, `https://`, no trailing slash.
    pub mirror: String,
    /// The asset's id, lowercase hex of its issue's txid; `None` until the
    /// asset is issued and named, when the chain shows sats only.
    pub asset_id: Option<String>,
    /// The asset's ticker.
    pub ticker: String,
    /// An image for the asset (`https://`), drawn instead of the pin's
    /// built-in mark ([`chain::Mark`]).
    pub icon_url: Option<String>,
    /// The relays transactions and faucet requests go to.
    pub relays: Vec<String>,
    /// The house seat of this chain's poker table, when the entry names one
    /// (`POKER_CONFIG.citizens` takes precedence; see
    /// [`crate::poker::PokerConfig::citizen_for`]).
    pub citizen_pubkey: Option<String>,
}

impl ChainProfile {
    /// The pin's defaults, before any runtime config.
    pub fn from_pin(pin: &'static Pin) -> Self {
        Self {
            pin,
            id: pin.id,
            parent: pin.parent,
            parent_name: pin.parent_name,
            genesis_hash: pin.genesis_hash,
            label: pin.label.to_string(),
            mirror: pin.mirror.to_string(),
            asset_id: pin.asset_id.map(str::to_string),
            ticker: pin.ticker.to_string(),
            icon_url: None,
            relays: default_relays(),
            citizen_pubkey: None,
        }
    }

    /// The chain's lock: its sealed document and address prefix.
    pub fn pin(&self) -> &'static Pin {
        self.pin
    }

    /// The asset id, parsed; `None` when the chain has no asset named.
    pub fn asset(&self) -> Option<Txid> {
        self.asset_id.as_deref().and_then(|a| a.parse().ok())
    }

    /// The fragment that names this chain's section of a page:
    /// `sidestr-dreamlab-txbt4` for `sidestr:dreamlab-txbt4`.
    pub fn anchor(&self) -> String {
        anchor_of(self.id)
    }
}

/// The page fragment for a chain id (`:` is not welcome in one).
pub fn anchor_of(chain_id: &str) -> String {
    chain_id.replace(':', "-")
}

fn default_relays() -> Vec<String> {
    chain::DEFAULT_RELAYS
        .iter()
        .map(|r| r.to_string())
        .collect()
}

/// The older single-chain keys, which apply to `sidestr:dreamlab`.
#[derive(Debug, Clone, Copy, Default)]
pub struct Legacy<'a> {
    /// `SIDESTR_MIRROR`.
    pub mirror: Option<&'a str>,
    /// `SIDESTR_RELAYS`, comma-separated.
    pub relays: Option<&'a str>,
}

/// One `SIDESTR_CHAINS` entry as the deployment wrote it.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct Entry {
    id: String,
    mirror: Option<String>,
    asset_id: Option<String>,
    ticker: Option<String>,
    label: Option<String>,
    icon: Option<String>,
    citizen_pubkey: Option<String>,
    relays: Option<Vec<String>>,
}

fn https_url(m: &str) -> Option<String> {
    let m = m.trim();
    (m.starts_with("https://") && m.len() > "https://".len())
        .then(|| m.trim_end_matches('/').to_string())
}

fn wss_list<'a>(urls: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    urls.into_iter()
        .map(str::trim)
        .filter(|r| r.starts_with("wss://"))
        .map(str::to_string)
        .collect()
}

fn ticker_ok(t: &str) -> bool {
    (1..=16).contains(&t.len()) && t.bytes().all(|b| b.is_ascii_alphanumeric())
}

fn label_ok(l: &str) -> bool {
    (1..=32).contains(&l.chars().count()) && !l.chars().any(char::is_control)
}

/// Apply the legacy keys to the `sidestr:dreamlab` profile where its entry
/// set nothing of its own.
fn apply_legacy(
    p: &mut ChainProfile,
    legacy: Legacy<'_>,
    own_mirror: bool,
    own_relays: bool,
    warnings: &mut Vec<String>,
) {
    if p.id != chain::CHAIN_ID {
        return;
    }
    if let (false, Some(m)) = (own_mirror, legacy.mirror) {
        match https_url(m) {
            Some(m) => p.mirror = m,
            None => warnings.push(format!(
                "SIDESTR_MIRROR {m:?} is not an https:// URL; ignored"
            )),
        }
    }
    if let (false, Some(r)) = (own_relays, legacy.relays) {
        let list = wss_list(r.split(','));
        if !list.is_empty() {
            p.relays = list;
        }
    }
}

/// The profile one entry describes, with a warning for each field that does
/// not read. `None` (and a warning) for a chain that is not pinned.
fn profile_of(entry: Entry, warnings: &mut Vec<String>) -> Option<(ChainProfile, bool, bool)> {
    let id = entry.id.trim();
    let Some(pin) = chain::pin(id) else {
        warnings.push(format!(
            "SIDESTR_CHAINS names {id:?}, which this wallet does not pin; ignored"
        ));
        return None;
    };
    let mut p = ChainProfile::from_pin(pin);
    let mut own_mirror = false;
    if let Some(m) = entry.mirror.as_deref() {
        match https_url(m) {
            Some(m) => {
                p.mirror = m;
                own_mirror = true;
            }
            None => warnings.push(format!(
                "{id}: mirror {m:?} is not an https:// URL; using {}",
                p.mirror
            )),
        }
    }
    if let Some(a) = entry.asset_id.as_deref().map(str::trim) {
        if chain::is_hex64(a) {
            p.asset_id = Some(a.to_ascii_lowercase());
        } else if !a.is_empty() {
            warnings.push(format!(
                "{id}: asset_id {a:?} is not 64 hex digits; ignored"
            ));
        }
    }
    if let Some(t) = entry.ticker.as_deref().map(str::trim) {
        if ticker_ok(t) {
            p.ticker = t.to_string();
        } else {
            warnings.push(format!(
                "{id}: ticker {t:?} is not 1-16 letters and digits; ignored"
            ));
        }
    }
    match entry.label.as_deref().map(str::trim) {
        Some(l) if label_ok(l) => p.label = l.to_string(),
        Some(l) => warnings.push(format!("{id}: label {l:?} does not read; ignored")),
        // a ticker set without a label names the chain's money too
        None if entry.ticker.is_some() => p.label = p.ticker.clone(),
        None => {}
    }
    if let Some(i) = entry.icon.as_deref() {
        match https_url(i) {
            Some(url) => p.icon_url = Some(url),
            None => warnings.push(format!("{id}: icon {i:?} is not an https:// URL; ignored")),
        }
    }
    if let Some(pk) = entry.citizen_pubkey.as_deref().map(str::trim) {
        if chain::is_hex64(pk) {
            p.citizen_pubkey = Some(pk.to_ascii_lowercase());
        } else if !pk.is_empty() {
            warnings.push(format!(
                "{id}: citizen_pubkey is not 64 hex digits; ignored"
            ));
        }
    }
    let mut own_relays = false;
    if let Some(r) = entry.relays.as_ref() {
        let list = wss_list(r.iter().map(String::as_str));
        if list.is_empty() {
            warnings.push(format!(
                "{id}: relays lists no wss:// URL; using the defaults"
            ));
        } else {
            p.relays = list;
            own_relays = true;
        }
    }
    Some((p, own_mirror, own_relays))
}

/// The chains a deployment offers, from `SIDESTR_CHAINS` (as JSON text) and
/// the legacy keys, with a warning for everything that was ignored.
pub fn resolve(chains_json: Option<&str>, legacy: Legacy<'_>) -> (Vec<ChainProfile>, Vec<String>) {
    let mut warnings = Vec::new();
    let mut out: Vec<ChainProfile> = Vec::new();
    match chains_json.map(str::trim).filter(|j| !j.is_empty()) {
        None => {}
        Some(json) => match serde_json::from_str::<Vec<serde_json::Value>>(json) {
            Err(e) => warnings.push(format!("SIDESTR_CHAINS is not a JSON array ({e}); ignored")),
            Ok(items) => {
                for item in items {
                    let entry: Entry = match serde_json::from_value(item) {
                        Ok(e) => e,
                        Err(e) => {
                            warnings
                                .push(format!("SIDESTR_CHAINS entry does not read ({e}); ignored"));
                            continue;
                        }
                    };
                    let Some((mut p, own_mirror, own_relays)) = profile_of(entry, &mut warnings)
                    else {
                        continue;
                    };
                    if out.iter().any(|q| q.id == p.id) {
                        warnings.push(format!(
                            "SIDESTR_CHAINS names {} twice; the first entry stands",
                            p.id
                        ));
                        continue;
                    }
                    apply_legacy(&mut p, legacy, own_mirror, own_relays, &mut warnings);
                    out.push(p);
                }
                if out.is_empty() {
                    warnings.push(format!(
                        "SIDESTR_CHAINS names no pinned chain; offering {} alone",
                        chain::CHAIN_ID
                    ));
                }
            }
        },
    }
    if out.is_empty() {
        let mut p = ChainProfile::from_pin(&chain::DREAMLAB);
        apply_legacy(&mut p, legacy, false, false, &mut warnings);
        out.push(p);
    }
    (out, warnings)
}

static PROFILES: OnceLock<Vec<ChainProfile>> = OnceLock::new();

/// The chains this page offers, in order (never empty): resolved from the
/// page's config on first use, each warning written to the console once.
pub fn profiles() -> &'static [ChainProfile] {
    PROFILES.get_or_init(|| {
        use crate::utils::relay_url::{env_override, env_override_json};
        let chains = env_override_json("SIDESTR_CHAINS");
        let mirror = env_override("SIDESTR_MIRROR");
        let relays = env_override("SIDESTR_RELAYS");
        let (list, warnings) = resolve(
            chains.as_deref(),
            Legacy {
                mirror: mirror.as_deref(),
                relays: relays.as_deref(),
            },
        );
        for w in warnings {
            web_sys::console::warn_1(&format!("[wallet] {w}").into());
        }
        list
    })
}

/// The profile of a chain this page offers.
pub fn find(chain_id: &str) -> Option<&'static ChainProfile> {
    profiles().iter().find(|p| p.id == chain_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BLAKES7: &str = "0f0e0d0c0b0a09080706050403020100f0e0d0c0b0a090807060504030201000";
    const CITIZEN: &str = "2de44d5622eef79519ac078f6e227a85aecbaefd561e4e50c5f51dfadbf916e9";

    #[test]
    fn absent_config_is_todays_wallet() {
        for absent in [None, Some(""), Some("   ")] {
            let (list, warnings) = resolve(absent, Legacy::default());
            assert_eq!(list, vec![ChainProfile::from_pin(&chain::DREAMLAB)]);
            assert!(warnings.is_empty());
            let p = &list[0];
            assert_eq!(p.id, chain::CHAIN_ID);
            assert_eq!(p.asset_id.as_deref(), Some(chain::DREAM_ASSET_ID));
            assert_eq!((p.ticker.as_str(), p.label.as_str()), ("DREAM", "DREAM"));
            assert_eq!(p.mirror, chain::DEFAULT_MIRROR);
            assert_eq!(p.relays.len(), 5);
        }
    }

    #[test]
    fn the_legacy_keys_still_steer_dreamlab() {
        let legacy = Legacy {
            mirror: Some("https://mirror.example/dl/"),
            relays: Some(" wss://a.example , ws://plain.example,wss://b.example"),
        };
        let (list, warnings) = resolve(None, legacy);
        assert!(warnings.is_empty());
        assert_eq!(list[0].mirror, "https://mirror.example/dl");
        assert_eq!(list[0].relays, vec!["wss://a.example", "wss://b.example"]);
        // an http mirror is refused, as before
        let (list, warnings) = resolve(
            None,
            Legacy {
                mirror: Some("http://insecure.example"),
                relays: None,
            },
        );
        assert_eq!(list[0].mirror, chain::DEFAULT_MIRROR);
        assert_eq!(warnings.len(), 1);
        // they never touch the second chain, and an entry's own fields win
        let json = r#"[{"id":"sidestr:dreamlab","mirror":"https://own.example"},{"id":"sidestr:dreamlab-txbt4"}]"#;
        let (list, _) = resolve(Some(json), legacy);
        assert_eq!(list[0].mirror, "https://own.example");
        assert_eq!(list[0].relays, vec!["wss://a.example", "wss://b.example"]);
        assert_eq!(list[1].mirror, chain::TXBT4_DEFAULT_MIRROR);
        assert_eq!(list[1].relays.len(), 5);
    }

    #[test]
    fn two_chains_in_the_order_given() {
        let json = format!(
            r#"[
                {{"id":"sidestr:dreamlab-txbt4","asset_id":"{}","ticker":"BLAKES7","citizen_pubkey":"{}","mirror":"https://m.example/t","icon":"https://m.example/b7.svg"}},
                {{"id":"sidestr:dreamlab","label":"Dream","citizen_pubkey":"{}"}}
            ]"#,
            BLAKES7.to_ascii_uppercase(),
            CITIZEN,
            CITIZEN.to_ascii_uppercase()
        );
        let (list, warnings) = resolve(Some(&json), Legacy::default());
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(
            list.iter().map(|p| p.id).collect::<Vec<_>>(),
            ["sidestr:dreamlab-txbt4", "sidestr:dreamlab"]
        );
        let t = &list[0];
        assert_eq!((t.parent, t.parent_name), ("txbt4", "BLAKE2b testnet4"));
        assert_eq!(t.genesis_hash, chain::TXBT4_GENESIS_HASH);
        assert_eq!(t.asset_id.as_deref(), Some(BLAKES7), "lowercased");
        assert_eq!(t.asset().unwrap().to_string().len(), 64);
        assert_eq!(
            (t.ticker.as_str(), t.label.as_str()),
            ("BLAKES7", "BLAKES7")
        );
        assert_eq!(t.citizen_pubkey.as_deref(), Some(CITIZEN));
        assert_eq!(t.icon_url.as_deref(), Some("https://m.example/b7.svg"));
        assert_eq!(t.pin(), &chain::DREAMLAB_TXBT4);
        assert_eq!(t.anchor(), "sidestr-dreamlab-txbt4");
        let d = &list[1];
        assert_eq!(d.label, "Dream");
        assert_eq!(d.ticker, "DREAM");
        assert_eq!(d.asset_id.as_deref(), Some(chain::DREAM_ASSET_ID));
        assert_eq!(d.citizen_pubkey.as_deref(), Some(CITIZEN));
    }

    /// The env can name another asset id for dreamlab, but never another
    /// chain, and txbt4 has no asset until the env names one.
    #[test]
    fn asset_ids_come_from_the_env_or_the_pin() {
        let json = format!(
            r#"[{{"id":"sidestr:dreamlab","asset_id":"{BLAKES7}"}},{{"id":"sidestr:dreamlab-txbt4"}}]"#
        );
        let (list, _) = resolve(Some(&json), Legacy::default());
        assert_eq!(list[0].asset_id.as_deref(), Some(BLAKES7));
        assert_eq!(list[1].asset_id, None);
        assert_eq!(list[1].asset(), None);
        assert_eq!(list[1].ticker, "BLAKES7");
    }

    #[test]
    fn entries_naming_unknown_chains_are_ignored() {
        let json = r#"[
            {"id":"sidestr:melchain","mirror":"https://evil.example"},
            {"id":"sidestr:dreamlab-txbt4"},
            {"id":"sidestr:dreamlab-txbt4","mirror":"https://second.example"},
            {"mirror":"https://no-id.example"},
            "not an object"
        ]"#;
        let (list, warnings) = resolve(Some(json), Legacy::default());
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, chain::TXBT4_CHAIN_ID);
        assert_eq!(
            list[0].mirror,
            chain::TXBT4_DEFAULT_MIRROR,
            "the first entry stands"
        );
        assert!(
            warnings.iter().any(|w| w.contains("sidestr:melchain")),
            "{warnings:?}"
        );
        assert!(warnings.iter().any(|w| w.contains("twice")), "{warnings:?}");
        assert_eq!(warnings.len(), 4, "{warnings:?}");
        // nothing pinned at all: today's wallet, said so
        let (list, warnings) = resolve(Some(r#"[{"id":"sidestr:other"}]"#), Legacy::default());
        assert_eq!(list, vec![ChainProfile::from_pin(&chain::DREAMLAB)]);
        assert!(warnings.iter().any(|w| w.contains("no pinned chain")));
        // not an array: today's wallet, said so
        let (list, warnings) = resolve(
            Some(r#"{"id":"sidestr:dreamlab-txbt4"}"#),
            Legacy::default(),
        );
        assert_eq!(list[0].id, chain::CHAIN_ID);
        assert_eq!(warnings.len(), 1);
    }

    #[test]
    fn fields_that_do_not_read_fall_back_to_the_pin() {
        let json = r#"[{"id":"sidestr:dreamlab-txbt4","mirror":"http://plain.example","asset_id":"xyz","ticker":"BLAKES 7!","icon":"javascript:alert(1)","citizen_pubkey":"nope","relays":["ws://plain.example"]}]"#;
        let (list, warnings) = resolve(Some(json), Legacy::default());
        let p = &list[0];
        assert_eq!(p.mirror, chain::TXBT4_DEFAULT_MIRROR);
        assert_eq!(p.asset_id, None);
        assert_eq!(p.ticker, "BLAKES7");
        assert_eq!(p.citizen_pubkey, None);
        assert_eq!(p.icon_url, None);
        assert_eq!(p.relays.len(), 5);
        assert_eq!(warnings.len(), 6, "{warnings:?}");
    }
}
