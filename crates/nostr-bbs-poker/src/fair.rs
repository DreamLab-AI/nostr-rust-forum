//! The fair deal: commitments that fix the deck before anyone sees a card.
//!
//! A hand's shuffle seed is derived from **two** contributions. The house
//! seat (the citizen) draws a 32-byte secret and publishes its commitment,
//! `sha256(secret)`, in its offer; the member (the hero) answers with a
//! 32-byte nonce of their own in the clear. The seed is then
//! `sha256(secret ‖ nonce)` ([`seed_of`]). The citizen cannot change its
//! secret after committing, and the hero cannot predict the seed without the
//! secret, so neither side chooses the deck. When the hand ends the citizen
//! reveals the secret; the hero checks the commitment ([`check_commit`]) and
//! replays the hand from the seed ([`crate::verify`]).
//!
//! The house bot's own randomness is derived from the seed and how far the
//! hand has gone ([`bot_seed`]), so the revealed seed replays every house
//! decision exactly and a member can check the house played by the book.

use sha2::{Digest, Sha256};

/// Whether `s` is 64 lowercase hex characters: a seed, a secret, a nonce or
/// a commitment.
pub fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The commitment to a secret or a seed: SHA-256 of its 64-character hex
/// text, so `printf %s <hex> | sha256sum` checks it.
pub fn commit(hex64: &str) -> String {
    hex::encode(Sha256::digest(hex64.as_bytes()))
}

/// Whether a revealed secret matches its commitment.
pub fn check_commit(secret_hex: &str, commitment_hex: &str) -> bool {
    is_hex64(secret_hex) && commit(secret_hex) == commitment_hex
}

/// The shuffle seed both parties fixed: `sha256(secret ‖ nonce)` over the
/// two hex texts, as 64 lowercase hex characters.
pub fn seed_of(secret_hex: &str, nonce_hex: &str) -> String {
    seed_of_many(secret_hex, &[nonce_hex])
}

/// The shuffle seed the dealer's secret and every player's nonce fix, in
/// seat order: `sha256(secret ‖ nonce₀ ‖ nonce₁ ‖ …)` over the hex texts.
/// With one nonce this is [`seed_of`]. A hand between two members dealt by
/// the house uses both members' nonces, so neither member nor the dealer
/// chooses the deck.
pub fn seed_of_many(secret_hex: &str, nonces_hex: &[&str]) -> String {
    let mut h = Sha256::new();
    h.update(secret_hex.as_bytes());
    for n in nonces_hex {
        h.update(n.as_bytes());
    }
    hex::encode(h.finalize())
}

/// The house bot's per-decision randomness: `sha256("<seed>:bot:<step>")`
/// where `step` is the length of the hand log when it decides. The same
/// derivation the practice table uses, so a hand replays the bot exactly.
pub fn bot_seed(seed_hex: &str, step: usize) -> String {
    hex::encode(Sha256::digest(format!("{seed_hex}:bot:{step}").as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commitment_is_sha256_of_the_text() {
        let secret = "ab".repeat(32);
        // sha256 of the 64 ASCII characters, not of the 32 bytes
        assert_eq!(
            commit(&secret),
            hex::encode(Sha256::digest(secret.as_bytes()))
        );
        assert!(check_commit(&secret, &commit(&secret)));
        assert!(!check_commit(&"ac".repeat(32), &commit(&secret)));
        assert!(!check_commit("short", &commit("short")));
    }

    #[test]
    fn seed_binds_both_contributions() {
        let s = seed_of(&"01".repeat(32), &"02".repeat(32));
        assert!(is_hex64(&s));
        assert_ne!(s, seed_of(&"01".repeat(32), &"03".repeat(32)));
        assert_ne!(s, seed_of(&"02".repeat(32), &"01".repeat(32)));
    }

    #[test]
    fn a_match_seed_takes_every_nonce_in_order() {
        let (s, a, b) = ("01".repeat(32), "02".repeat(32), "03".repeat(32));
        assert_eq!(seed_of_many(&s, &[&a]), seed_of(&s, &a));
        assert_ne!(seed_of_many(&s, &[&a, &b]), seed_of_many(&s, &[&b, &a]));
        assert_ne!(seed_of_many(&s, &[&a, &b]), seed_of(&s, &a));
    }

    #[test]
    fn bot_seed_matches_the_practice_table_derivation() {
        let seed = "cd".repeat(32);
        assert_eq!(
            bot_seed(&seed, 7),
            hex::encode(Sha256::digest(format!("{seed}:bot:7").as_bytes()))
        );
        assert_ne!(bot_seed(&seed, 7), bot_seed(&seed, 8));
    }

    #[test]
    fn hex64_is_strict() {
        assert!(is_hex64(&"0".repeat(64)));
        assert!(!is_hex64(&"A".repeat(64)));
        assert!(!is_hex64(&"0".repeat(63)));
    }
}
