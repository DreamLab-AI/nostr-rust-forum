//! Generate a VAPID key pair for Web Push (ADR-2023).
//!
//! ```text
//! cargo run -p nostr-bbs-relay-worker --example vapid_keygen
//! ```
//!
//! Prints the public key (goes in `VAPID_PUBLIC_KEY` in the relay's
//! `wrangler.toml`) and the private key (store it with
//! `wrangler secret put VAPID_PRIVATE_KEY`; never commit it). Both are the
//! unpadded base64url form that browsers and `VapidKeys::from_private_b64`
//! expect. The scalar comes from the operating system's CSPRNG.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine};
use p256::ecdsa::SigningKey;

fn main() {
    let signing = loop {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).expect("OS entropy unavailable");
        // Rejects the (astronomically unlikely) zero / out-of-range scalar.
        if let Ok(key) = SigningKey::from_slice(&bytes) {
            break key;
        }
    };
    let public = signing.verifying_key().to_encoded_point(false);
    println!("VAPID_PUBLIC_KEY={}", B64URL.encode(public.as_bytes()));
    println!("VAPID_PRIVATE_KEY={}", B64URL.encode(signing.to_bytes()));
}
