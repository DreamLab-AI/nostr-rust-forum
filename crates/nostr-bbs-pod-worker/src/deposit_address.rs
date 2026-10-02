//! Per-user deposit addresses for the `/pay/` ledger — LIVE, frozen.
//!
//! Every account (`did:nostr:<x>`) has one taproot deposit address derived
//! from the pod's `MASTER_SECRET` and the account's x-only key. Addresses
//! derived here have been handed to users by `GET /pay/.address` in
//! production, so the construction is frozen byte for byte: the
//! known-answer vectors in this module's tests were captured from the
//! original k256 implementation before it was ported to rust-bitcoin, and
//! must never be regenerated.
//!
//! The construction is a **raw additive tweak, not BIP 341**:
//!
//! 1. `P = master_secret · G` (the full point, whatever its parity).
//! 2. `t = SHA256(x(P) ‖ user_x) mod n` — a plain SHA-256, not a tagged hash.
//! 3. `Q = P + t·G` (added to the full point; never lifted to even y).
//! 4. `k = tagged_hash("TapTweak", x(Q)) mod n` and `O = Q + k·G`, again on
//!    the **unlifted** `Q`. BIP 341 lifts `Q` to its even-y point first, so
//!    the two agree only when `Q` has even y.
//! 5. The address is the bech32m segwit v1 program `x(O)` under hrp `bc`;
//!    the script is `OP_1 <x(O)>` (`5120 ‖ x(O)`), the same bytes on every
//!    Bitcoin network.
//!
//! The operator spends a deposit with `master_secret + t + k` (with the
//! parity handled at signing). Any new scheme follows `sidestr/spec`
//! `keys.mjs` and the teller's tagged, ledger-scoped tweak
//! (`webledgers/deposit`) under a new route; it never replaces this one in
//! place (ADR-2012 D6).

use bitcoin::hashes::{sha256, Hash};
use bitcoin::key::{TweakedPublicKey, XOnlyPublicKey};
use bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use bitcoin::taproot::TapTweakHash;
use bitcoin::{Address, KnownHrp, ScriptBuf};

/// The keys of one account's deposit output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DepositKeys {
    /// The tweaked internal key `Q = P + t·G`, with its own parity.
    pub internal: PublicKey,
    /// The x-only output key `x(Q + k·G)` committed to by the address.
    pub output: XOnlyPublicKey,
}

/// Reduce a 32-byte big-endian integer modulo the group order `n`.
///
/// The original implementation reduced with k256's `Reduce<U256>`; libsecp256k1
/// exposes no wide reduction, so the out-of-range case (probability about
/// 2^-128 for a hash) is folded with its own modular addition: for `h ≥ n`,
/// `h − 2^255 < n` and `h ≡ (h − 2^255) + 2^255 (mod n)`.
fn reduce_mod_n(h: [u8; 32]) -> Scalar {
    if let Ok(s) = Scalar::from_be_bytes(h) {
        return s;
    }
    // h ≥ n > 2^255, so its top bit is set: clearing it subtracts 2^255.
    let mut low = h;
    low[0] &= 0x7f;
    let low = Scalar::from_be_bytes(low).expect("h - 2^255 < 2^255 < n");
    let mut two_255 = [0u8; 32];
    two_255[0] = 0x80;
    let two_255 = SecretKey::from_slice(&two_255).expect("2^255 is a valid scalar");
    match two_255.add_tweak(&low) {
        Ok(sum) => Scalar::from(sum),
        // The sum is ≡ 0 (mod n) exactly when h = n.
        Err(_) => Scalar::ZERO,
    }
}

/// Derive the deposit keys for `user_pubkey` (64 hex chars, x-only).
///
/// # Errors
///
/// Returns a message for a malformed user key, an invalid master secret
/// (zero or not below `n`), or a tweak that lands on the point at infinity.
pub fn deposit_keys(master_secret: &[u8; 32], user_pubkey: &str) -> Result<DepositKeys, String> {
    if user_pubkey.len() != 64 || !user_pubkey.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "invalid user pubkey: expected 64 hex chars, got {} chars",
            user_pubkey.len()
        ));
    }
    let user_bytes =
        hex::decode(user_pubkey).map_err(|e| format!("invalid user pubkey hex: {e}"))?;

    let secp = Secp256k1::new();
    let master_sk =
        SecretKey::from_slice(master_secret).map_err(|e| format!("invalid master secret: {e}"))?;
    let master_pk = PublicKey::from_secret_key(&secp, &master_sk);
    let (master_x, _) = master_pk.x_only_public_key();

    // t = SHA256(x(P) || user_x) mod n
    let mut preimage = Vec::with_capacity(64);
    preimage.extend_from_slice(&master_x.serialize());
    preimage.extend_from_slice(&user_bytes);
    let t = reduce_mod_n(sha256::Hash::hash(&preimage).to_byte_array());

    // Q = P + t·G on the full point.
    let internal = master_pk
        .add_exp_tweak(&secp, &t)
        .map_err(|_| "tweaked key is point at infinity".to_string())?;
    let (internal_x, _) = internal.x_only_public_key();

    // O = Q + tagged_hash("TapTweak", x(Q))·G, Q NOT lifted to even y.
    let k = reduce_mod_n(TapTweakHash::from_key_and_tweak(internal_x, None).to_byte_array());
    let output = internal
        .add_exp_tweak(&secp, &k)
        .map_err(|_| "output key is point at infinity".to_string())?;
    let (output, _) = output.x_only_public_key();

    Ok(DepositKeys { internal, output })
}

/// Derive the live per-user deposit address (`bc1p…`, hrp `bc`).
///
/// See the module documentation for the construction: a raw additive tweak
/// followed by a TapTweak on the unlifted internal key — **not BIP 341**.
///
/// # Errors
///
/// As [`deposit_keys`].
pub fn derive_deposit_address(
    master_secret: &[u8; 32],
    user_pubkey: &str,
) -> Result<String, String> {
    let keys = deposit_keys(master_secret, user_pubkey)?;
    let output = TweakedPublicKey::dangerous_assume_tweaked(keys.output);
    Ok(Address::p2tr_tweaked(output, KnownHrp::Mainnet).to_string())
}

/// The scriptPubKey (`5120 ‖ x(O)`) of the account's deposit address — what a
/// deposit output must carry before it is credited.
///
/// # Errors
///
/// As [`deposit_keys`].
pub fn derive_deposit_script(
    master_secret: &[u8; 32],
    user_pubkey: &str,
) -> Result<Vec<u8>, String> {
    let keys = deposit_keys(master_secret, user_pubkey)?;
    let output = TweakedPublicKey::dangerous_assume_tweaked(keys.output);
    Ok(ScriptBuf::new_p2tr_tweaked(output).into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    // -----------------------------------------------------------------------
    // Known-answer vectors for the LIVE deposit-address derivation.
    //
    // Captured from the k256 implementation before the rust-bitcoin port
    // (commit ce9cdda) and never regenerated: addresses already handed to
    // users must keep paying the same script. Pair 1 and pair 3 give an odd-y
    // internal key Q (where this raw construction parts company with
    // BIP 341), pair 2 an even-y Q; pair 3 also has an odd-y master point P.
    // -----------------------------------------------------------------------

    /// `(MASTER_SECRET hex, user x-only pubkey hex, address, Q parity byte)`.
    const DEPOSIT_KAT: [(&str, &str, &str, u8); 3] = [
        (
            "b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef",
            "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
            "bc1p0z7ve4ph6v4tfumrffgzmm5lhwzca2gq3gyl38yagyfdsuuddudsap2q2h",
            0x03,
        ),
        (
            "b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef",
            "dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8",
            "bc1pc2ugfcac2yl9atk7u6s65tmp072jutcn7k7emywmkr0ah40sm5zqnlac5v",
            0x02,
        ),
        (
            "0b432b2677937381aef05bb02a66ecd012773062cf3fa2549e44f58ed2401710",
            "25d1dff95105f5253c4022f628a996ad3a0d95fbf21d468a1b33f8c160d8f517",
            "bc1pyesjlxgnvpawzr7w7e9na27pvyn49a3y5glxzvpnjkw2z2hvau6szcxa7v",
            0x03,
        ),
    ];

    fn kat_secret(hex_secret: &str) -> [u8; 32] {
        let mut s = [0u8; 32];
        s.copy_from_slice(&hex::decode(hex_secret).expect("valid hex"));
        s
    }

    fn user_a() -> &'static str {
        DEPOSIT_KAT[0].1
    }

    fn user_b() -> &'static str {
        DEPOSIT_KAT[1].1
    }

    fn test_master_secret() -> [u8; 32] {
        kat_secret(DEPOSIT_KAT[0].0)
    }

    #[test]
    fn deposit_address_known_answers_are_frozen() {
        for (secret, user, expected, _) in DEPOSIT_KAT {
            let got = derive_deposit_address(&kat_secret(secret), user).expect("derivation");
            assert_eq!(got, expected, "live deposit address drifted for {user}");
        }
    }

    #[test]
    fn known_answers_cover_both_parities_of_q() {
        let mut seen = [false; 2];
        for (secret, user, _, parity) in DEPOSIT_KAT {
            let keys = deposit_keys(&kat_secret(secret), user).expect("derivation");
            assert_eq!(keys.internal.serialize()[0], parity, "Q parity for {user}");
            seen[usize::from(parity == 0x03)] = true;
        }
        assert_eq!(seen, [true, true], "vectors must cover even-y and odd-y Q");
        // Pair 3's master point itself is odd-y.
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&kat_secret(DEPOSIT_KAT[2].0)).expect("valid");
        assert_eq!(PublicKey::from_secret_key(&secp, &sk).serialize()[0], 0x03);
    }

    /// The live construction is not BIP 341: for an odd-y `Q` it differs from
    /// `Address::p2tr(Q)` (which lifts `Q` first); for an even-y `Q` it agrees.
    #[test]
    fn live_construction_is_not_bip341_for_odd_q() {
        let secp = Secp256k1::new();
        for (secret, user, expected, parity) in DEPOSIT_KAT {
            let keys = deposit_keys(&kat_secret(secret), user).expect("derivation");
            let (q_x, _) = keys.internal.x_only_public_key();
            let bip341 = Address::p2tr(&secp, q_x, None, KnownHrp::Mainnet).to_string();
            if parity == 0x03 {
                assert_ne!(bip341, expected, "odd-y Q must differ from BIP 341");
            } else {
                assert_eq!(bip341, expected, "even-y Q coincides with BIP 341");
            }
        }
    }

    #[test]
    fn script_is_op1_push32_of_the_address_program() {
        for (secret, user, expected, _) in DEPOSIT_KAT {
            let script = derive_deposit_script(&kat_secret(secret), user).expect("derivation");
            let addr = Address::from_str(expected)
                .expect("valid address")
                .require_network(bitcoin::Network::Bitcoin)
                .expect("mainnet");
            assert_eq!(script, addr.script_pubkey().into_bytes());
            assert_eq!(script.len(), 34);
            assert_eq!(&script[..2], &[0x51, 0x20]);
        }
    }

    /// The modular reduction agrees with k256's `Reduce<U256>` (the original
    /// implementation's) on the edge values where libsecp256k1 would refuse.
    #[test]
    fn reduce_mod_n_matches_k256_reduce() {
        use k256::elliptic_curve::ops::Reduce;
        use k256::{FieldBytes, U256};
        let n = hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
            .expect("hex");
        let mut cases: Vec<[u8; 32]> = Vec::new();
        let mut push = |h: &[u8]| {
            let mut a = [0u8; 32];
            a.copy_from_slice(h);
            cases.push(a);
        };
        push(&[0u8; 32]);
        push(&[0xff; 32]);
        push(&n);
        let mut n_plus_1 = n.clone();
        n_plus_1[31] += 1;
        push(&n_plus_1);
        let mut n_minus_1 = n.clone();
        n_minus_1[31] -= 1;
        push(&n_minus_1);
        let mut top = [0u8; 32];
        top[0] = 0x80;
        push(&top);
        push(&sha256::Hash::hash(b"deposit").to_byte_array());
        for h in cases {
            let ours = reduce_mod_n(h).to_be_bytes();
            let theirs = <k256::Scalar as Reduce<U256>>::reduce_bytes(FieldBytes::from_slice(&h));
            assert_eq!(
                ours.as_slice(),
                theirs.to_bytes().as_slice(),
                "{}",
                hex::encode(h)
            );
        }
    }

    #[test]
    fn determinism_same_inputs_same_address() {
        let secret = test_master_secret();
        let addr1 = derive_deposit_address(&secret, user_a()).expect("derivation should succeed");
        let addr2 = derive_deposit_address(&secret, user_a()).expect("derivation should succeed");
        assert_eq!(addr1, addr2, "same inputs must produce the same address");
    }

    #[test]
    fn uniqueness_different_users_different_addresses() {
        let secret = test_master_secret();
        let addr_a = derive_deposit_address(&secret, user_a()).expect("derivation should succeed");
        let addr_b = derive_deposit_address(&secret, user_b()).expect("derivation should succeed");
        assert_ne!(addr_a, addr_b);
    }

    #[test]
    fn format_bc1p_prefix_and_length() {
        let addr = derive_deposit_address(&test_master_secret(), user_a()).expect("derivation");
        assert!(
            addr.starts_with("bc1p"),
            "taproot address must start with bc1p: {addr}"
        );
        assert_eq!(addr.len(), 62, "bc1p (4) + 58 data chars: {addr}");
    }

    #[test]
    fn error_empty_pubkey() {
        let err = derive_deposit_address(&test_master_secret(), "").unwrap_err();
        assert!(err.contains("invalid user pubkey"), "got: {err}");
    }

    #[test]
    fn error_short_pubkey() {
        assert!(derive_deposit_address(&test_master_secret(), "abcd").is_err());
    }

    #[test]
    fn error_non_hex_pubkey() {
        let bad_pk = "z".repeat(64);
        assert!(derive_deposit_address(&test_master_secret(), &bad_pk).is_err());
    }

    #[test]
    fn error_zero_master_secret() {
        assert!(derive_deposit_address(&[0u8; 32], user_a()).is_err());
    }

    #[test]
    fn error_master_secret_not_below_n() {
        assert!(derive_deposit_address(&[0xff; 32], user_a()).is_err());
    }

    #[test]
    fn different_master_secrets_produce_different_addresses() {
        let secret2 =
            kat_secret("c90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b14e5c9");
        let addr1 = derive_deposit_address(&test_master_secret(), user_a()).expect("derivation");
        let addr2 = derive_deposit_address(&secret2, user_a()).expect("derivation");
        assert_ne!(addr1, addr2);
    }
}
