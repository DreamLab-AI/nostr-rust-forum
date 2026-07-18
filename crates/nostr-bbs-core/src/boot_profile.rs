//! Zone-bound PWA boot profile — the shared contract between the forum client
//! (which BAKES a device-resident key + boot profile at install time) and the
//! BBS client (which READS them for the one-shot boot). See ADR-109 and
//! `docs/prd/prd-zone-bound-bbs-pwa.md`.
//!
//! Everything here is portable pure Rust (no web-sys) so it compiles for the
//! workers too and both clients reference ONE source of truth — the storage
//! key names and crypto parameters below are load-bearing: if the writer and
//! reader ever disagreed, the installed app would silently boot signed-out.
//!
//! Storage model (browser origin, same for both SPAs):
//! - `BOOTPROFILE_KEY` in localStorage holds the serialized [`BootProfile`]
//!   (non-secret; read synchronously at BBS boot).
//! - IndexedDB `BAKED_DB`/`BAKED_STORE` record `BAKED_RECORD_ID` holds the
//!   non-extractable AES-GCM `CryptoKey` handle plus the
//!   [`WrappedKeyEnvelope`] ciphertext of the 32-byte secp256k1 secret. The
//!   `CryptoKey` itself is never serialized here — each crate's wasm layer
//!   stores the handle via structured clone.

use serde::{Deserialize, Serialize};

/// Query flag that marks a PWA one-shot boot (`start_url` carries `?pwa=1`).
pub const PWA_QUERY_FLAG: &str = "pwa";
/// The only value of [`PWA_QUERY_FLAG`] that activates the one-shot boot.
pub const PWA_QUERY_VALUE: &str = "1";
/// localStorage key holding the serialized [`BootProfile`] (non-secret).
pub const BOOTPROFILE_KEY: &str = "nostr_bbs_bootprofile";
/// IndexedDB database name holding the baked key material.
pub const BAKED_DB: &str = "nostr_bbs_secure";
/// IndexedDB object store within [`BAKED_DB`].
pub const BAKED_STORE: &str = "baked_keys";
/// Fixed record id within [`BAKED_STORE`] (one baked key per origin).
pub const BAKED_RECORD_ID: &str = "default";
/// WebCrypto algorithm name for the wrapping key.
pub const AES_ALG: &str = "AES-GCM";
/// Wrapping key length in bits.
pub const AES_KEY_BITS: u32 = 256;
/// AES-GCM IV length in bytes.
pub const AES_IV_LEN: usize = 12;
/// The only `mode` a valid boot profile may carry.
pub const BOOTPROFILE_MODE: &str = "zone-app";
/// Current boot-profile schema version.
pub const BOOTPROFILE_V: u8 = 1;

/// The device-resident record binding an installed app to ONE zone.
///
/// Non-secret: it names the zone and when the bake happened; the key material
/// lives separately in IndexedDB. Invariants are enforced by [`Self::validate`]
/// (see the DDD doc's BootProfile aggregate).
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct BootProfile {
    /// Schema version ([`BOOTPROFILE_V`]).
    pub v: u8,
    /// Always [`BOOTPROFILE_MODE`] — anything else is not a zone-app profile.
    pub mode: String,
    /// The bound zone's config id (must be a member zone at bake time).
    pub zone: String,
    /// Unix seconds when the bake was consented to and performed.
    pub created_at: i64,
}

impl BootProfile {
    /// A fresh v1 zone-app profile for `zone`.
    pub fn new(zone: String, created_at: i64) -> Self {
        Self {
            v: BOOTPROFILE_V,
            mode: BOOTPROFILE_MODE.to_string(),
            zone,
            created_at,
        }
    }

    /// Structural validity — version, mode, non-blank zone, sane timestamp.
    pub fn validate(&self) -> bool {
        self.v == BOOTPROFILE_V
            && self.mode == BOOTPROFILE_MODE
            && !self.zone.trim().is_empty()
            && self.created_at > 0
    }
}

/// The AES-GCM ciphertext of the 32-byte secp256k1 secret, hex-encoded.
///
/// Stored alongside the non-extractable wrapping `CryptoKey` in IndexedDB.
/// The wrapping key handle is NOT part of this envelope — it cannot be
/// serialized (that is the point of non-extractable keys).
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct WrappedKeyEnvelope {
    /// Hex-encoded AES-GCM IV ([`AES_IV_LEN`] bytes).
    pub iv_hex: String,
    /// Hex-encoded ciphertext (secret + GCM tag).
    pub ct_hex: String,
}

/// Does a raw `location.search` (with or without the leading `?`) request the
/// PWA one-shot boot? True only when `pwa=1` appears as a parameter.
pub fn is_pwa_boot(query_string: &str) -> bool {
    query_string
        .trim_start_matches('?')
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .any(|(k, v)| k == PWA_QUERY_FLAG && v == PWA_QUERY_VALUE)
}

/// Parse + validate a stored boot profile. `None` on any failure — a corrupt
/// or foreign record must read as "no profile", never panic the boot.
pub fn parse_boot_profile(json: &str) -> Option<BootProfile> {
    serde_json::from_str::<BootProfile>(json)
        .ok()
        .filter(BootProfile::validate)
}

/// Resolve the bound zone id to its index in the deployment's zone list.
///
/// `None` when the zone was renamed or removed since the bake — callers fall
/// back to an unpinned boot (never a widened one; server-side cohort
/// enforcement remains the real boundary).
pub fn resolve_pinned_zone_index(zone_id: &str, zone_ids: &[String]) -> Option<usize> {
    zone_ids.iter().position(|id| id == zone_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_pwa_boot_matrix() {
        assert!(is_pwa_boot("?pwa=1"));
        assert!(is_pwa_boot("pwa=1"));
        assert!(is_pwa_boot("?a=b&pwa=1&c=d"));
        assert!(!is_pwa_boot(""));
        assert!(!is_pwa_boot("?"));
        assert!(!is_pwa_boot("?pwa=0"));
        assert!(!is_pwa_boot("?pwa="));
        assert!(!is_pwa_boot("?x=1"));
        assert!(!is_pwa_boot("?notpwa=1"));
    }

    #[test]
    fn boot_profile_roundtrip_and_validate() {
        let p = BootProfile::new("minimoonoir".into(), 1_784_000_000);
        assert!(p.validate());
        let json = serde_json::to_string(&p).unwrap();
        let back = parse_boot_profile(&json).expect("roundtrip");
        assert_eq!(back, p);
    }

    #[test]
    fn validate_rejects_bad_profiles() {
        let good = BootProfile::new("z".into(), 1);
        let mut wrong_mode = good.clone();
        wrong_mode.mode = "app".into();
        assert!(!wrong_mode.validate());
        let mut empty_zone = good.clone();
        empty_zone.zone = "  ".into();
        assert!(!empty_zone.validate());
        let mut bad_ts = good.clone();
        bad_ts.created_at = 0;
        assert!(!bad_ts.validate());
        let mut wrong_v = good;
        wrong_v.v = 2;
        assert!(!wrong_v.validate());
    }

    #[test]
    fn parse_boot_profile_rejects_malformed() {
        assert!(parse_boot_profile("not json").is_none());
        assert!(parse_boot_profile("{}").is_none());
        // Structurally valid JSON but invalid profile (wrong mode).
        assert!(
            parse_boot_profile(r#"{"v":1,"mode":"other","zone":"z","created_at":1}"#).is_none()
        );
    }

    #[test]
    fn resolve_pinned_zone_index_hit_and_miss() {
        let ids = vec!["landing".to_string(), "minimoonoir".to_string()];
        assert_eq!(resolve_pinned_zone_index("minimoonoir", &ids), Some(1));
        assert_eq!(resolve_pinned_zone_index("gone", &ids), None);
        assert_eq!(resolve_pinned_zone_index("minimoonoir", &[]), None);
    }

    #[test]
    fn wrapped_envelope_roundtrip() {
        let e = WrappedKeyEnvelope {
            iv_hex: "00".repeat(AES_IV_LEN),
            ct_hex: "ab".repeat(48),
        };
        let json = serde_json::to_string(&e).unwrap();
        let back: WrappedKeyEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(back, e);
    }
}
