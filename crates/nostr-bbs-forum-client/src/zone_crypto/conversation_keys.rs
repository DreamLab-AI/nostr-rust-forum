//! NIP-44 conversation keys of the zone read path, cached per
//! `(zone secret, peer pubkey)` for the signed-in identity.
//!
//! Every sealed envelope of an import shares one author (the migrator), and
//! every live encrypted post in a zone is decrypted with the same zone secret
//! against its author's key, yet `nip44::decrypt` re-derived the conversation
//! key (ECDH + HKDF, ~400 µs in wasm) for each message. The key depends only
//! on the pair, so it is derived once here and reused with
//! [`nostr_bbs_core::nip44::decrypt_with_conversation_key`].
//!
//! **Keying and lifetime.** The cache key is `(SHA-256(zone secret), peer
//! pubkey)`: the secret itself, not its `(zone, epoch)` label or stated
//! pubkey, so a key set where an epoch resolves to a different secret can
//! never be served another secret's conversation key, and no extra copy of
//! the secret is held. A conversation key opens everything between that
//! secret and that peer, so it is treated like the secret: memory only, never
//! persisted, zeroised and dropped by [`clear`], which
//! [`ZoneKeyStore::switch_owner`](super::store::ZoneKeyStore::switch_owner)
//! calls on every sign-out and identity change, and bounded to
//! [`CAPACITY`] entries (cleared whole when full).

use std::cell::RefCell;
use std::collections::HashMap;

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Most conversation keys held at once. One per (zone secret, author): an
/// import is one entry; live posts add one per author per epoch.
pub const CAPACITY: usize = 4096;

type Key = ([u8; 32], [u8; 32]);

thread_local! {
    static CACHE: RefCell<HashMap<Key, Zeroizing<[u8; 32]>>> = RefCell::new(HashMap::new());
}

/// The conversation key of `secret` and `peer`, derived on first use and
/// cached; `None` when `peer` is not a valid x-only public key (the caller
/// then treats the message as undecryptable, as `nip44::decrypt` would).
pub fn conversation_key(secret: &[u8; 32], peer: &[u8; 32]) -> Option<Zeroizing<[u8; 32]>> {
    let fingerprint: [u8; 32] = Sha256::digest(secret).into();
    let key = (fingerprint, *peer);
    if let Some(ck) = CACHE.with(|c| c.borrow().get(&key).cloned()) {
        return Some(ck);
    }
    let ck = Zeroizing::new(nostr_bbs_core::nip44::conversation_key(secret, peer).ok()?);
    CACHE.with(|c| {
        let mut c = c.borrow_mut();
        if c.len() >= CAPACITY {
            c.clear();
        }
        c.insert(key, ck.clone());
    });
    Some(ck)
}

/// Drop (and zeroise) every cached conversation key.
pub fn clear() {
    CACHE.with(|c| c.borrow_mut().clear());
}

/// How many keys are cached (tests).
#[cfg(test)]
pub fn len() -> usize {
    CACHE.with(|c| c.borrow().len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(sk: [u8; 32]) -> [u8; 32] {
        *nostr_bbs_core::keys::SecretKey::from_bytes(sk)
            .unwrap()
            .public_key()
            .as_bytes()
    }

    #[test]
    fn caches_per_secret_and_peer_and_matches_a_fresh_derivation() {
        clear();
        let (z1, z2, a, b) = ([1u8; 32], [2u8; 32], pk([3; 32]), pk([4; 32]));
        let k1a = conversation_key(&z1, &a).unwrap();
        assert_eq!(
            *k1a,
            nostr_bbs_core::nip44::conversation_key(&z1, &a).unwrap()
        );
        assert_eq!(*conversation_key(&z1, &a).unwrap(), *k1a, "cached");
        assert_eq!(len(), 1);
        assert_ne!(*conversation_key(&z1, &b).unwrap(), *k1a, "other peer");
        assert_ne!(*conversation_key(&z2, &a).unwrap(), *k1a, "other secret");
        assert_eq!(len(), 3);
        clear();
        assert_eq!(len(), 0);
    }

    #[test]
    fn an_invalid_peer_yields_none() {
        assert!(conversation_key(&[1u8; 32], &[0u8; 32]).is_none());
    }
}
