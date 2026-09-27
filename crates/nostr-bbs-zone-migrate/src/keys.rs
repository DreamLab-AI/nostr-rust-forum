//! Zone keys: the key-file format, and the merged key ring the migrator seals
//! and verifies with.
//!
//! Keys come from two optional sources that are merged: a JSON key file
//! ([`parse_key_file`]) and zone-key grants addressed to the migrator
//! ([`crate::grants`]). Sealing always uses the **highest epoch** held for a
//! zone ([`KeyRing::current`]); verification uses the exact epoch recorded
//! for each envelope ([`KeyRing::get`]).
//!
//! # Key-file schema
//!
//! The same schema as agentbox `zone-keys.json`:
//!
//! ```json
//! {"version": 1,
//!  "owner": "<64-hex pubkey of the key holder>",
//!  "keys": [{"zone": "zone3", "epoch": 2, "secret": "<64 hex>", "pubkey": "<64 hex>"}]}
//! ```
//!
//! Extra fields on a key entry (such as `granted_by` or `received_at`) are
//! ignored. Every entry must have a non-empty zone, an epoch of at least 1,
//! and a secret that derives to the stated x-only pubkey.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

/// The only key-file `version` this build reads.
pub const KEY_FILE_VERSION: u32 = 1;

/// Errors from building a key, parsing a key file or merging keys.
///
/// Messages name zones and epochs, never secrets.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum KeyError {
    /// The key file is not valid JSON of the documented shape.
    #[error("key file is not valid JSON: {0}")]
    Json(String),
    /// The key file's `version` is not [`KEY_FILE_VERSION`].
    #[error("key file version {0} is not supported (expected 1)")]
    Version(u32),
    /// The key file's `owner` is not 64 hex characters.
    #[error("key file owner is not a 64-hex pubkey")]
    Owner,
    /// A key entry is malformed: empty zone, epoch 0, or a secret or pubkey
    /// that is not 64 hex characters or not a valid key.
    #[error("zone key {zone}:{epoch} is malformed: {why}")]
    Malformed {
        /// Zone named by the entry.
        zone: String,
        /// Epoch named by the entry.
        epoch: u32,
        /// What is wrong with it.
        why: &'static str,
    },
    /// A key entry's secret does not derive to its stated pubkey.
    #[error("zone key {zone}:{epoch}: secret does not derive to the stated pubkey")]
    SecretMismatch {
        /// Zone named by the entry.
        zone: String,
        /// Epoch named by the entry.
        epoch: u32,
    },
    /// Two sources hold different keys for the same zone and epoch. The
    /// migrator refuses to guess which one members hold.
    #[error("conflicting keys for {zone}:{epoch} ({first} vs {second})")]
    Conflict {
        /// Zone with the conflict.
        zone: String,
        /// Epoch with the conflict.
        epoch: u32,
        /// Pubkey already held.
        first: String,
        /// Pubkey offered in conflict.
        second: String,
    },
}

/// Where a zone key came from. Reported in summaries; never secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "source")]
pub enum KeySource {
    /// Read from `--keys-file`.
    KeyFile,
    /// Received as a zone-key grant sealed by this admin pubkey.
    Grant {
        /// Admin pubkey that sealed the grant.
        granted_by: String,
    },
}

/// One zone epoch key. The secret is zeroised on drop and redacted from
/// `Debug`.
#[derive(Clone)]
pub struct ZoneKey {
    zone: String,
    epoch: u32,
    pubkey: String,
    secret: Zeroizing<[u8; 32]>,
    source: KeySource,
}

impl ZoneKey {
    /// Build a key from hex, checking the zone, the epoch and that the secret
    /// derives to `pubkey_hex`. The stored pubkey is the derived one
    /// (lowercase).
    ///
    /// ```
    /// use nostr_bbs_zone_migrate::keys::{KeySource, ZoneKey};
    /// let secret = "33".repeat(32);
    /// let pubkey = nostr_bbs_core::keys::pubkey_hex(&[0x33; 32]).unwrap();
    /// let key = ZoneKey::new("zone3", 1, &secret, &pubkey, KeySource::KeyFile).unwrap();
    /// assert_eq!(key.pubkey(), pubkey);
    /// assert!(!format!("{key:?}").contains(&secret));
    /// ```
    pub fn new(
        zone: &str,
        epoch: u32,
        secret_hex: &str,
        pubkey_hex: &str,
        source: KeySource,
    ) -> Result<Self, KeyError> {
        let malformed = |why| KeyError::Malformed {
            zone: zone.to_string(),
            epoch,
            why,
        };
        if zone.is_empty() {
            return Err(malformed("empty zone"));
        }
        if epoch == 0 {
            return Err(malformed("epoch must be >= 1"));
        }
        if !is_hex64(pubkey_hex) {
            return Err(malformed("pubkey is not 64 hex"));
        }
        if !is_hex64(secret_hex) {
            return Err(malformed("secret is not 64 hex"));
        }
        let mut secret = Zeroizing::new([0u8; 32]);
        hex::decode_to_slice(secret_hex, secret.as_mut())
            .map_err(|_| malformed("secret is not 64 hex"))?;
        let derived = nostr_bbs_core::keys::pubkey_hex(&secret)
            .map_err(|_| malformed("secret is not a valid scalar"))?;
        if !derived.eq_ignore_ascii_case(pubkey_hex) {
            return Err(KeyError::SecretMismatch {
                zone: zone.to_string(),
                epoch,
            });
        }
        Ok(Self {
            zone: zone.to_string(),
            epoch,
            pubkey: derived,
            secret,
            source,
        })
    }

    /// Zone id, such as `"zone3"`.
    pub fn zone(&self) -> &str {
        &self.zone
    }

    /// Key epoch, from 1.
    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    /// Lowercase 64-hex x-only zone public key (the `zk` tag value).
    pub fn pubkey(&self) -> &str {
        &self.pubkey
    }

    /// The 32 secret bytes. Never print or persist them.
    pub fn secret(&self) -> &[u8; 32] {
        &self.secret
    }

    /// Where this key came from.
    pub fn source(&self) -> &KeySource {
        &self.source
    }
}

impl fmt::Debug for ZoneKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ZoneKey")
            .field("zone", &self.zone)
            .field("epoch", &self.epoch)
            .field("pubkey", &self.pubkey)
            .field("secret", &"<redacted>")
            .field("source", &self.source)
            .finish()
    }
}

/// Public description of a held key, safe to print or serialise.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KeySummary {
    /// Zone id.
    pub zone: String,
    /// Epoch.
    pub epoch: u32,
    /// Zone public key.
    pub pubkey: String,
    /// Origin of the key.
    #[serde(flatten)]
    pub source: KeySource,
}

/// All zone keys the migrator holds, keyed by `(zone, epoch)`.
#[derive(Debug, Default, Clone)]
pub struct KeyRing {
    keys: BTreeMap<(String, u32), ZoneKey>,
}

impl KeyRing {
    /// An empty ring.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a key. The same key offered twice (for example by the key file and
    /// by a grant) is kept once; a *different* key for an already-held
    /// `(zone, epoch)` is a [`KeyError::Conflict`].
    pub fn insert(&mut self, key: ZoneKey) -> Result<(), KeyError> {
        let slot = (key.zone.clone(), key.epoch);
        if let Some(held) = self.keys.get(&slot) {
            if held.pubkey == key.pubkey {
                return Ok(());
            }
            return Err(KeyError::Conflict {
                zone: key.zone.clone(),
                epoch: key.epoch,
                first: held.pubkey.clone(),
                second: key.pubkey.clone(),
            });
        }
        self.keys.insert(slot, key);
        Ok(())
    }

    /// The key for exactly `(zone, epoch)`.
    pub fn get(&self, zone: &str, epoch: u32) -> Option<&ZoneKey> {
        self.keys.get(&(zone.to_string(), epoch))
    }

    /// The highest-epoch key held for `zone`: the one used for sealing.
    ///
    /// ```
    /// use nostr_bbs_zone_migrate::keys::{KeyRing, KeySource, ZoneKey};
    /// let key = |byte: u8, epoch| {
    ///     let pk = nostr_bbs_core::keys::pubkey_hex(&[byte; 32]).unwrap();
    ///     ZoneKey::new("zone3", epoch, &hex::encode([byte; 32]), &pk, KeySource::KeyFile).unwrap()
    /// };
    /// let mut ring = KeyRing::new();
    /// ring.insert(key(0x31, 1)).unwrap();
    /// ring.insert(key(0x32, 2)).unwrap();
    /// assert_eq!(ring.current("zone3").unwrap().epoch(), 2);
    /// assert!(ring.current("zone4").is_none());
    /// ```
    pub fn current(&self, zone: &str) -> Option<&ZoneKey> {
        self.keys
            .range((zone.to_string(), 0)..=(zone.to_string(), u32::MAX))
            .next_back()
            .map(|(_, k)| k)
    }

    /// Number of keys held.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether no keys are held.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Public summaries of every key held, ordered by zone then epoch.
    pub fn summaries(&self) -> Vec<KeySummary> {
        self.keys
            .values()
            .map(|k| KeySummary {
                zone: k.zone.clone(),
                epoch: k.epoch,
                pubkey: k.pubkey.clone(),
                source: k.source.clone(),
            })
            .collect()
    }
}

/// A parsed key file.
#[derive(Debug)]
pub struct KeyFile {
    /// The `owner` pubkey recorded in the file (lowercase hex). Informational:
    /// the CLI warns when it differs from the migrator's own pubkey.
    pub owner: String,
    /// The keys, each already validated.
    pub keys: Vec<ZoneKey>,
}

#[derive(Deserialize)]
struct KeyFileWire {
    version: u32,
    owner: String,
    keys: Vec<KeyEntryWire>,
}

#[derive(Deserialize)]
struct KeyEntryWire {
    zone: String,
    epoch: u32,
    secret: String,
    pubkey: String,
}

impl Drop for KeyEntryWire {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// Parse and validate a key file (see the module docs for the schema).
///
/// ```
/// use nostr_bbs_zone_migrate::keys::parse_key_file;
/// let pk = nostr_bbs_core::keys::pubkey_hex(&[0x33; 32]).unwrap();
/// let json = format!(
///     r#"{{"version":1,"owner":"{}","keys":[{{"zone":"zone3","epoch":1,"secret":"{}","pubkey":"{pk}","granted_by":"x"}}]}}"#,
///     "a".repeat(64),
///     "33".repeat(32),
/// );
/// let file = parse_key_file(&json).unwrap();
/// assert_eq!(file.keys[0].zone(), "zone3");
/// ```
pub fn parse_key_file(json: &str) -> Result<KeyFile, KeyError> {
    let wire: KeyFileWire = serde_json::from_str(json).map_err(|e| {
        // serde_json's messages can quote the offending value, which may be a
        // secret; report only the error category and line.
        KeyError::Json(format!("{} at line {}", e.classify_str(), e.line()))
    })?;
    if wire.version != KEY_FILE_VERSION {
        return Err(KeyError::Version(wire.version));
    }
    if !is_hex64(&wire.owner) {
        return Err(KeyError::Owner);
    }
    let keys = wire
        .keys
        .iter()
        .map(|e| ZoneKey::new(&e.zone, e.epoch, &e.secret, &e.pubkey, KeySource::KeyFile))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(KeyFile {
        owner: wire.owner.to_ascii_lowercase(),
        keys,
    })
}

trait ClassifyStr {
    fn classify_str(&self) -> &'static str;
}

impl ClassifyStr for serde_json::Error {
    fn classify_str(&self) -> &'static str {
        match self.classify() {
            serde_json::error::Category::Io => "I/O error",
            serde_json::error::Category::Syntax => "syntax error",
            serde_json::error::Category::Data => "unexpected shape",
            serde_json::error::Category::Eof => "unexpected end of file",
        }
    }
}

pub(crate) fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(byte: u8) -> String {
        nostr_bbs_core::keys::pubkey_hex(&[byte; 32]).unwrap()
    }

    fn key(zone: &str, epoch: u32, byte: u8) -> ZoneKey {
        ZoneKey::new(
            zone,
            epoch,
            &hex::encode([byte; 32]),
            &pk(byte),
            KeySource::KeyFile,
        )
        .unwrap()
    }

    fn file(entries: &str) -> String {
        format!(
            r#"{{"version":1,"owner":"{}","keys":[{entries}]}}"#,
            "a".repeat(64)
        )
    }

    fn entry(zone: &str, epoch: u32, byte: u8) -> String {
        format!(
            r#"{{"zone":"{zone}","epoch":{epoch},"secret":"{}","pubkey":"{}"}}"#,
            hex::encode([byte; 32]),
            pk(byte)
        )
    }

    #[test]
    fn key_file_parses_multiple_zones_and_ignores_extra_fields() {
        let json = file(&format!(
            "{},{},{}",
            entry("zone3", 1, 0x31),
            entry("zone3", 2, 0x32),
            r#"{"zone":"zone4","epoch":1,"secret":"4141414141414141414141414141414141414141414141414141414141414141","pubkey":"PK","granted_by":"b","received_at":5}"#
                .replace("PK", &pk(0x41))
        ));
        let kf = parse_key_file(&json).unwrap();
        assert_eq!(kf.owner, "a".repeat(64));
        assert_eq!(kf.keys.len(), 3);
        let mut ring = KeyRing::new();
        for k in kf.keys {
            ring.insert(k).unwrap();
        }
        assert_eq!(ring.current("zone3").unwrap().epoch(), 2);
        assert_eq!(ring.current("zone4").unwrap().pubkey(), pk(0x41));
        assert!(ring.get("zone3", 1).is_some());
        assert!(ring.get("zone3", 3).is_none());
    }

    #[test]
    fn key_file_rejects_bad_version_owner_and_entries() {
        let good = entry("zone3", 1, 0x31);
        assert_eq!(
            parse_key_file(&file(&good).replace("\"version\":1", "\"version\":2")).unwrap_err(),
            KeyError::Version(2)
        );
        assert_eq!(
            parse_key_file(&file(&good).replace(&"a".repeat(64), "abc")).unwrap_err(),
            KeyError::Owner
        );
        assert!(matches!(
            parse_key_file(&file(&entry("", 1, 0x31))).unwrap_err(),
            KeyError::Malformed { .. }
        ));
        assert!(matches!(
            parse_key_file(&file(&entry("zone3", 0, 0x31))).unwrap_err(),
            KeyError::Malformed { .. }
        ));
        // secret for one key, pubkey for another
        let swapped = entry("zone3", 1, 0x31).replace(&pk(0x31), &pk(0x32));
        assert_eq!(
            parse_key_file(&file(&swapped)).unwrap_err(),
            KeyError::SecretMismatch {
                zone: "zone3".into(),
                epoch: 1
            }
        );
        assert!(matches!(
            parse_key_file("{not json").unwrap_err(),
            KeyError::Json(_)
        ));
    }

    #[test]
    fn json_errors_do_not_echo_secret_material() {
        let secret = "5".repeat(64);
        let json = format!(
            r#"{{"version":1,"owner":"{}","keys":[{{"zone":"z","epoch":"one","secret":"{secret}","pubkey":"x"}}]}}"#,
            "a".repeat(64)
        );
        let err = parse_key_file(&json).unwrap_err().to_string();
        assert!(!err.contains(&secret), "{err}");
    }

    #[test]
    fn ring_dedupes_identical_keys_and_refuses_conflicts() {
        let mut ring = KeyRing::new();
        ring.insert(key("zone3", 1, 0x31)).unwrap();
        ring.insert(key("zone3", 1, 0x31)).unwrap();
        assert_eq!(ring.len(), 1);
        assert!(matches!(
            ring.insert(key("zone3", 1, 0x39)).unwrap_err(),
            KeyError::Conflict { epoch: 1, .. }
        ));
        // `zone30` must not be treated as a later epoch of `zone3`.
        ring.insert(key("zone30", 9, 0x3a)).unwrap();
        assert_eq!(ring.current("zone3").unwrap().epoch(), 1);
    }

    #[test]
    fn debug_and_summaries_never_show_the_secret() {
        let k = key("zone3", 1, 0x31);
        let secret_hex = hex::encode([0x31; 32]);
        assert!(!format!("{k:?}").contains(&secret_hex));
        let mut ring = KeyRing::new();
        ring.insert(k).unwrap();
        let json = serde_json::to_string(&ring.summaries()).unwrap();
        assert!(!json.contains(&secret_hex));
        assert!(json.contains("\"source\":\"key_file\""));
    }
}
