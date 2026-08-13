//! Dev tool: sign arbitrary Nostr events with the crate's own signing path.
//!
//! Usage:
//!   cargo run -p nostr-bbs-core --example sign_tool -- <priv-hex> <kind> <tags-json> [content]
//!
//! Prints the signed event JSON on stdout. Used by live-test probes so the
//! wire bytes match `verify_event_strict` exactly.

use k256::schnorr::SigningKey;
use nostr_bbs_core::{sign_event, UnsignedEvent};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("usage: sign_tool <priv-hex> <kind> <tags-json> [content]");
        std::process::exit(2);
    }
    let sk_bytes: [u8; 32] = hex::decode(&args[1])
        .expect("priv hex")
        .try_into()
        .expect("32 bytes");
    let sk = SigningKey::from_bytes(&sk_bytes).expect("valid key");
    let pubkey = hex::encode(sk.verifying_key().to_bytes());
    let kind: u64 = args[2].parse().expect("kind");
    let tags: Vec<Vec<String>> = serde_json::from_str(&args[3]).expect("tags json");
    let content = args.get(4).cloned().unwrap_or_default();
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs();

    let unsigned = UnsignedEvent {
        pubkey,
        created_at,
        kind,
        tags,
        content,
    };
    let event = sign_event(unsigned, &sk).expect("sign");
    println!("{}", serde_json::to_string(&event).expect("json"));
}
