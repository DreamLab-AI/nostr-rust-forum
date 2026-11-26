//! Grant paging against a LOCAL relay worker, end to end over the wire.
//!
//! Ignored by default. `scripts/tests/grant-paging-local-relay.sh` builds
//! the relay worker, starts it with `wrangler dev --local` (workerd and
//! miniflare: the relay Durable Object and a local D1 in a throwaway
//! directory), whitelists two throwaway keys and runs this test. It refuses
//! any relay URL that is not `ws://127.0.0.1:…` or `ws://localhost:…`, so
//! it can never seed a deployed relay.
//!
//! It seeds, over NIP-42-authenticated EVENT frames, more than two pages of
//! gift wraps addressed to the throwaway member: DMs from strangers in groups
//! sharing one `created_at` (so page boundaries fall inside and between
//! groups), zone-key grants sealed by the throwaway admin (some on the first
//! page boundary's timestamp, the rest the oldest wraps), and one junk wrap
//! addressed to the member that the member's key cannot decrypt. Then it
//! runs the grant sync's pure driver (`grant_sync_sim::Session`: the store's
//! [`super::grant_paging::ScopePager`], unwrap queue, open-and-classify step
//! and backlog verdict) against the relay's real REQ/EOSE answers, with the
//! relay's real `/api/check-whitelist` as the admin check, once with a local
//! key and once with a mock NIP-07 signer that denies its first prompts. It
//! asserts every wrap is delivered, every grant's key arrives, the backlog
//! settles and the backfill marker comes due.
//!
//! Not covered: the browser glue (IndexedDB, `spawn_local`, the forum's
//! `RelayConnection`), which no native test can run.
//!
//! Environment: `GRANT_PAGING_LOCAL_RELAY` (the ws:// URL, also the relay's
//! `RELAY_URL`), `GRANT_PAGING_MEMBER_SK` and `GRANT_PAGING_ADMIN_SK`
//! (throwaway 64-hex secrets), `GRANT_PAGING_PHASE` = `keys` (print the two
//! pubkeys, for the script to whitelist) or `run`.

use std::cell::RefCell;
use std::collections::HashSet;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use nostr_bbs_core::keys::{generate_keypair, Keypair, SecretKey};
use nostr_bbs_core::signer::{PrfSigner, Signer};
use nostr_bbs_core::{NostrEvent, UnsignedEvent};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use super::grant_backlog::SignerKind;
use super::grant_paging::{GrantScope, PagerAction};
use super::grant_sync_sim::{Ext, PageSource, Session};
use super::{build_grant_wrap, generate_zone_key};

const DMS: usize = 2_200;
/// DMs sharing each `created_at`: 1000 / 40 = 25, so page 0 ends exactly
/// on a group and later boundaries fall inside one.
const DMS_PER_TS: usize = 40;
const BOUNDARY_GRANTS: usize = 5;
const OLD_GRANTS: usize = 25;
const GRANTS: usize = BOUNDARY_GRANTS + OLD_GRANTS;
/// The single junk wrap.
const JUNK: usize = 1;

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    futures::executor::block_on(f)
}

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set"))
}

/// The relay URL, refusing anything but a loopback ws:// address.
fn local_relay_url() -> String {
    let url = env("GRANT_PAGING_LOCAL_RELAY");
    assert!(
        url.starts_with("ws://127.0.0.1:") || url.starts_with("ws://localhost:"),
        "refusing {url}: this test seeds wraps and only ever talks to a local relay"
    );
    url
}

fn signer_from_env(name: &str) -> PrfSigner {
    let hex = env(name);
    let bytes: [u8; 32] = (0..32)
        .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("hex secret"))
        .collect::<Vec<u8>>()
        .try_into()
        .expect("32-byte secret");
    let secret = SecretKey::from_bytes(bytes).expect("valid secp256k1 secret");
    let public = secret.public_key();
    PrfSigner::new(Keypair { secret, public })
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A gift wrap of `seal_json` with a chosen `created_at`, `p`-tagged to
/// `recipient` and encrypted to `encrypt_to` (the same key, except for the
/// junk wrap). `wrap_seal` randomises the timestamp; the order is what is
/// under test, so it is set here.
fn wrap_at(seal_json: &str, recipient: &str, encrypt_to: &str, created_at: u64) -> NostrEvent {
    let eph = PrfSigner::new(generate_keypair().unwrap());
    let content = block_on(eph.nip44_encrypt(encrypt_to, seal_json)).unwrap();
    block_on(eph.sign_event(UnsignedEvent {
        pubkey: eph.public_key().to_string(),
        created_at,
        kind: nostr_bbs_core::gift_wrap::KIND_GIFT_WRAP,
        tags: vec![vec!["p".to_string(), recipient.to_string()]],
        content,
    }))
    .unwrap()
}

/// The seal inside a wrap addressed to `member`.
fn seal_of(wrap: &NostrEvent, member: &PrfSigner) -> String {
    block_on(member.nip44_decrypt(&wrap.pubkey, &wrap.content)).unwrap()
}

/// The seeded wraps and the keys their grants carry.
fn seed_set(member: &PrfSigner, admin: &PrfSigner) -> (Vec<NostrEvent>, HashSet<(String, u32)>) {
    let me = member.public_key();
    let now = now_secs();
    // Inside the relay's 7-day `created_at` drift bound.
    let top = now - 3 * 24 * 3600;
    let mut wraps = Vec::new();
    for i in 0..DMS {
        let stranger = generate_keypair().unwrap();
        let dm = nostr_bbs_core::gift_wrap::gift_wrap(
            stranger.secret.as_bytes(),
            &stranger.public.to_hex(),
            me,
            &format!("dm {i}"),
        )
        .unwrap();
        let ts = top - (i / DMS_PER_TS) as u64;
        wraps.push(wrap_at(&seal_of(&dm, member), me, me, ts));
    }
    let boundary_ts = top - (1_000 / DMS_PER_TS - 1) as u64;
    let oldest_dm_ts = top - ((DMS - 1) / DMS_PER_TS) as u64;
    let mut keys = HashSet::new();
    for j in 0..GRANTS {
        let zone = format!("local{j}");
        let key = generate_zone_key(&zone, 1, admin.public_key(), now).unwrap();
        let grant = block_on(build_grant_wrap(admin, me, &key, now)).unwrap();
        let ts = if j < BOUNDARY_GRANTS {
            boundary_ts
        } else {
            oldest_dm_ts - 1 - ((j - BOUNDARY_GRANTS) / 3) as u64
        };
        wraps.push(wrap_at(&seal_of(&grant, member), me, me, ts));
        keys.insert((zone, 1));
    }
    // Junk: addressed to the member, encrypted to a key nobody holds.
    let dm = nostr_bbs_core::gift_wrap::gift_wrap(
        generate_keypair().unwrap().secret.as_bytes(),
        &generate_keypair().unwrap().public.to_hex(),
        me,
        "junk",
    )
    .unwrap();
    let nobody = generate_keypair().unwrap().public.to_hex();
    wraps.push(wrap_at(&seal_of(&dm, member), me, &nobody, top - 7));
    (wraps, keys)
}

type Stream = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// One NIP-42-authenticated connection to the local relay.
struct Ws {
    rt: tokio::runtime::Runtime,
    stream: Stream,
    member: String,
    subs: u32,
}

impl Ws {
    fn connect(url: &str, signer: &PrfSigner) -> Self {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (stream, _) = rt
            .block_on(tokio_tungstenite::connect_async(url))
            .expect("connect to the local relay");
        let mut ws = Self {
            rt,
            stream,
            member: signer.public_key().to_string(),
            subs: 0,
        };
        let challenge = loop {
            let m = ws.recv();
            if m[0] == "AUTH" {
                break m[1].as_str().unwrap().to_string();
            }
        };
        let auth = block_on(signer.sign_event(UnsignedEvent {
            pubkey: signer.public_key().to_string(),
            created_at: now_secs(),
            kind: 22242,
            tags: vec![
                vec!["relay".into(), url.into()],
                vec!["challenge".into(), challenge],
            ],
            content: String::new(),
        }))
        .unwrap();
        ws.send(json!(["AUTH", auth]));
        loop {
            let m = ws.recv();
            if m[0] == "OK" && m[1] == auth.id {
                assert_eq!(m[2], true, "AUTH refused: {m}");
                break;
            }
        }
        ws
    }

    fn send(&mut self, v: Value) {
        self.rt
            .block_on(self.stream.send(Message::text(v.to_string())))
            .unwrap();
    }

    fn recv(&mut self) -> Value {
        loop {
            let next = self.rt.block_on(async {
                tokio::time::timeout(Duration::from_secs(60), self.stream.next()).await
            });
            match next.expect("relay answered within 60 s") {
                Some(Ok(Message::Text(t))) => return serde_json::from_str(&t).unwrap(),
                Some(Ok(_)) => continue,
                other => panic!("relay connection ended: {other:?}"),
            }
        }
    }

    /// Publish every wrap; each must be accepted.
    fn seed(&mut self, wraps: &[NostrEvent]) {
        for chunk in wraps.chunks(200) {
            let mut pending: HashSet<String> = HashSet::new();
            for w in chunk {
                pending.insert(w.id.clone());
                self.send(json!(["EVENT", w]));
            }
            while !pending.is_empty() {
                let m = self.recv();
                if m[0] == "OK" {
                    let id = m[1].as_str().unwrap().to_string();
                    assert_eq!(m[2], true, "wrap refused: {m}");
                    pending.remove(&id);
                }
            }
        }
    }
}

impl PageSource for Ws {
    /// REQ the page as the store's grant filter does, collect to EOSE, and
    /// CLOSE it if it is a page subscription (page 0 stays open, as the
    /// long-lived subscription does).
    fn page(&mut self, until: Option<u64>) -> Vec<(NostrEvent, u64)> {
        let sub = format!("grants-{}", self.subs);
        self.subs += 1;
        let mut filter = json!({"kinds": [1059], "#p": [self.member], "limit": 1000});
        if let Some(u) = until {
            filter["until"] = json!(u);
        }
        self.send(json!(["REQ", sub, filter]));
        let mut rows = Vec::new();
        loop {
            let m = self.recv();
            match m[0].as_str() {
                Some("EVENT") if m[1] == sub.as_str() => {
                    let ev: NostrEvent = serde_json::from_value(m[2].clone()).unwrap();
                    let ts = ev.created_at;
                    rows.push((ev, ts));
                }
                Some("EOSE") if m[1] == sub.as_str() => break,
                Some("CLOSED") if m[1] == sub.as_str() => panic!("page refused: {m}"),
                _ => {}
            }
        }
        if until.is_some() {
            self.send(json!(["CLOSE", sub]));
        }
        rows
    }
}

/// The relay's own admin check (`GET /api/check-whitelist`), as the store
/// asks it; `None` when it does not answer.
fn check_whitelist(relay_ws: &str, pubkey: &str) -> Option<bool> {
    let host = relay_ws.trim_start_matches("ws://").trim_end_matches('/');
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .ok()?;
    rt.block_on(async {
        let mut s = TcpStream::connect(host).await.ok()?;
        let req = format!(
            "GET /api/check-whitelist?pubkey={pubkey} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        );
        s.write_all(req.as_bytes()).await.ok()?;
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.ok()?;
        let text = String::from_utf8_lossy(&buf);
        if !text.starts_with("HTTP/1.1 200") {
            return None;
        }
        Some(text.contains("\"isAdmin\":true"))
    })
}

#[test]
#[ignore = "needs a local relay worker; run scripts/tests/grant-paging-local-relay.sh"]
fn grant_paging_against_a_local_relay() {
    let url = local_relay_url();
    let member = signer_from_env("GRANT_PAGING_MEMBER_SK");
    let admin = signer_from_env("GRANT_PAGING_ADMIN_SK");
    if env("GRANT_PAGING_PHASE") == "keys" {
        println!("MEMBER_PK={}", member.public_key());
        println!("ADMIN_PK={}", admin.public_key());
        return;
    }
    assert_eq!(check_whitelist(&url, admin.public_key()), Some(true));
    assert_eq!(check_whitelist(&url, member.public_key()), Some(false));

    let (wraps, want_keys) = seed_set(&member, &admin);
    let mut publisher = Ws::connect(&url, &member);
    publisher.seed(&wraps);
    println!("seeded {} wraps", wraps.len());

    let is_admin = |pk: &str| check_whitelist(&url, pk);

    // Control: one REQ (the grant sync before paging) gets the relay's cap
    // of 1000 rows and none of the old grants.
    let mut one = Ws::connect(&url, &member);
    let first: HashSet<String> = one.page(None).into_iter().map(|(e, _)| e.id).collect();
    let old_grants = &wraps[DMS + BOUNDARY_GRANTS..DMS + GRANTS];
    println!(
        "control: page 0 alone has {} rows and {} of {} old grants",
        first.len(),
        old_grants.iter().filter(|w| first.contains(&w.id)).count(),
        old_grants.len()
    );
    assert_eq!(first.len(), 1000);
    assert!(old_grants.iter().all(|w| !first.contains(&w.id)));

    // A local key.
    let processed = RefCell::new(HashSet::new());
    let mut relay = Ws::connect(&url, &member);
    let o = Session::new(&member, SignerKind::Local, &is_admin, &processed).sync(&mut relay, None);
    println!(
        "local key: {} pages, {} delivered, {} keys, end {:?}, settled {}, markers {:?}",
        o.pages,
        o.delivered,
        o.keys.len(),
        o.end,
        o.backlog.settled(),
        o.markers
    );
    assert_eq!(o.end, PagerAction::Done { verified: true });
    assert_eq!(o.delivered, DMS + GRANTS + JUNK, "every wrap delivered");
    assert!(o.pages >= 3, "{} pages", o.pages);
    assert_eq!(o.keys, want_keys, "every grant settled");
    assert!(o.backlog.settled());
    assert_eq!(o.markers, vec![GrantScope::Identity]);
    assert_eq!(processed.borrow().len(), DMS + GRANTS, "junk left unmarked");

    // A NIP-07 signer whose first four prompts are denied.
    let processed = RefCell::new(HashSet::new());
    let ext = Ext::new(member, |n, _| n < 4);
    let mut relay = Ws::connect(&url, &signer_from_env("GRANT_PAGING_MEMBER_SK"));
    let o = Session::new(&ext, SignerKind::CanRefuse, &is_admin, &processed).sync(&mut relay, None);
    println!(
        "nip-07 (4 denied): {} pages, {} delivered, {} keys, settled {}, markers {:?}, decrypt calls {}",
        o.pages,
        o.delivered,
        o.keys.len(),
        o.backlog.settled(),
        o.markers,
        ext.calls.get()
    );
    assert_eq!(o.delivered, DMS + GRANTS + JUNK);
    assert_eq!(o.keys, want_keys);
    assert!(o.backlog.settled(), "junk unreadable after one retry");
    assert_eq!(o.markers, vec![GrantScope::Identity]);
    // Two decrypts per readable wrap; the four denied first attempts once
    // more; the junk wrap's outer layer twice (refused, then unreadable).
    assert_eq!(ext.calls.get(), 2 * (DMS + GRANTS) as u64 + 4 + 2);
}
