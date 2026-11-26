//! The per-(zone, epoch) search key.
//!
//! ```text
//! okm = HKDF-SHA256(salt = "nostr-bbs/sealed-search/v1",
//!                   ikm  = zone epoch secret (32 bytes),
//!                   info = "age-x25519\0" || zone || "\0" || be32(epoch) || zone_pk)
//! ```
//!
//! The browser's main thread derives `okm` here (this module needs no age)
//! and transfers only `okm` to the search worker; [`crate::seal`] turns it
//! into an age X25519 identity.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

const SALT: &[u8] = b"nostr-bbs/sealed-search/v1";

/// The derived per-(zone, epoch) search key (`okm`). Zeroised on drop.
#[derive(Clone)]
pub struct SearchKey(Zeroizing<[u8; 32]>);

impl SearchKey {
    /// Derive from the zone epoch secret. `zone_pk` is the x-only public key
    /// of that secret, so builder and client can only agree when they hold
    /// the same epoch key (review M3).
    pub fn derive(zone_secret: &[u8; 32], zone: &str, epoch: u32, zone_pk: &[u8; 32]) -> Self {
        let mut info = Vec::with_capacity(48 + zone.len());
        info.extend_from_slice(b"age-x25519\0");
        info.extend_from_slice(zone.as_bytes());
        info.push(0);
        info.extend_from_slice(&epoch.to_be_bytes());
        info.extend_from_slice(zone_pk);
        let mut okm = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha256>::new(Some(SALT), zone_secret)
            .expand(&info, okm.as_mut())
            .expect("32 bytes is a valid HKDF-SHA256 length");
        Self(okm)
    }

    /// Wrap raw `okm` bytes (as received by the worker).
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(Zeroizing::new(b))
    }

    /// Raw `okm` bytes (to post to the worker).
    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(zone: &str, epoch: u32) -> SearchKey {
        SearchKey::derive(&[9u8; 32], zone, epoch, &[1u8; 32])
    }

    #[test]
    fn derivation_is_domain_separated() {
        let a = key("zone2", 1);
        assert_eq!(a.bytes(), key("zone2", 1).bytes());
        assert_ne!(a.bytes(), key("zone2", 2).bytes());
        assert_ne!(a.bytes(), key("zone3", 1).bytes());
        assert_ne!(
            a.bytes(),
            SearchKey::derive(&[8u8; 32], "zone2", 1, &[1u8; 32]).bytes()
        );
        assert_ne!(
            a.bytes(),
            SearchKey::derive(&[9u8; 32], "zone2", 1, &[2u8; 32]).bytes()
        );
        // okm is not the zone secret.
        assert_ne!(a.bytes(), &[9u8; 32]);
    }

    #[test]
    fn hkdf_known_answer() {
        // RFC 5869 test case 1, through the same hkdf crate path.
        let ikm = [0x0bu8; 22];
        let salt: Vec<u8> = (0x00..=0x0c).collect();
        let info: Vec<u8> = (0xf0..=0xf9).collect();
        let mut okm = [0u8; 42];
        Hkdf::<Sha256>::new(Some(&salt), &ikm)
            .expand(&info, &mut okm)
            .unwrap();
        assert_eq!(
            hex::encode(okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }
}
