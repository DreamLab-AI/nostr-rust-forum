//! Executes the official BIP-340 test vectors (`fixtures/bip340-schnorr.json`,
//! pinned from bitcoin/bips `bip-0340/test-vectors.csv`) against the Schnorr
//! implementation underneath the crate (RustCrypto `k256`).
//!
//! `upstream_vectors` only checks that the fixture loads; this file proves the
//! signatures: every signing vector must reproduce byte for byte, and every
//! verification vector must give the published accept/reject result, both via
//! `k256` directly and via the crate's own `keys::PublicKey::verify`.

use k256::schnorr::{Signature, SigningKey, VerifyingKey};
use nostr_bbs_core::keys::{PublicKey, Signature as CoreSignature};
use serde_json::Value;

fn hex32(s: &str) -> [u8; 32] {
    hex::decode(s).unwrap().try_into().unwrap()
}

fn vectors() -> Vec<Value> {
    let raw = include_str!("fixtures/bip340-schnorr.json");
    let doc: Value = serde_json::from_str(raw).unwrap();
    doc["vectors"].as_array().unwrap().clone()
}

/// Verify with `k256` directly; any parse failure counts as a rejection.
fn k256_accepts(pk: &str, msg: &[u8], sig: &str) -> bool {
    let Ok(pk_bytes) = hex::decode(pk) else {
        return false;
    };
    let Ok(pk_arr) = <[u8; 32]>::try_from(pk_bytes.as_slice()) else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_bytes((&pk_arr).into()) else {
        return false;
    };
    let Ok(sig) = Signature::try_from(hex::decode(sig).unwrap().as_slice()) else {
        return false;
    };
    vk.verify_raw(msg, &sig).is_ok()
}

#[test]
fn bip340_fixture_has_all_19_vectors() {
    assert_eq!(vectors().len(), 19);
}

#[test]
fn bip340_verification_matches_published_results() {
    for v in vectors() {
        let idx = v["index"].as_u64().unwrap();
        let expected = v["verification_result"].as_bool().unwrap();
        let msg = hex::decode(v["message_hex"].as_str().unwrap()).unwrap();
        let got = k256_accepts(
            v["public_key_hex"].as_str().unwrap(),
            &msg,
            v["signature_hex"].as_str().unwrap(),
        );
        assert_eq!(got, expected, "vector {idx} ({})", v["comment"]);
    }
}

#[test]
fn bip340_signing_reproduces_published_signatures() {
    let mut signed = 0;
    for v in vectors() {
        let Some(sk_hex) = v["secret_key_hex"].as_str() else {
            continue;
        };
        let idx = v["index"].as_u64().unwrap();
        let sk = SigningKey::from_bytes((&hex32(sk_hex)).into()).unwrap();
        assert_eq!(
            hex::encode(sk.verifying_key().to_bytes()),
            v["public_key_hex"].as_str().unwrap().to_lowercase(),
            "vector {idx}: derived x-only public key"
        );
        let aux = hex32(v["aux_rand_hex"].as_str().unwrap());
        let msg = hex::decode(v["message_hex"].as_str().unwrap()).unwrap();
        let sig = sk.sign_raw(&msg, &aux).unwrap();
        assert_eq!(
            hex::encode(sig.to_bytes()),
            v["signature_hex"].as_str().unwrap().to_lowercase(),
            "vector {idx}: signature"
        );
        signed += 1;
    }
    assert_eq!(signed, 8, "vectors 0-3 and 15-18 carry secret keys");
}

#[test]
fn bip340_crate_public_key_verify_matches_published_results() {
    // `keys::PublicKey::verify` takes a 32-byte message, so it covers the
    // vectors whose message is 32 bytes (all but 15-18).
    for v in vectors() {
        let idx = v["index"].as_u64().unwrap();
        let msg = hex::decode(v["message_hex"].as_str().unwrap()).unwrap();
        let Ok(msg) = <[u8; 32]>::try_from(msg.as_slice()) else {
            continue;
        };
        let expected = v["verification_result"].as_bool().unwrap();
        let pk = PublicKey::from_hex(v["public_key_hex"].as_str().unwrap());
        let accepted = match (
            PublicKey::from_hex(v["public_key_hex"].as_str().unwrap()),
            <[u8; 64]>::try_from(hex::decode(v["signature_hex"].as_str().unwrap()).unwrap()),
        ) {
            (Ok(pk), Ok(sig)) => pk.verify(&msg, &CoreSignature::from_bytes(sig)).is_ok(),
            _ => false,
        };
        assert_eq!(accepted, expected, "vector {idx} ({})", v["comment"]);
    }
}
