//! Handler fixtures for the `/pay/*` routes: the production dispatcher and
//! SQL against a real SQLite (the engine D1 runs on) and a fixture explorer.

use super::*;
use crate::deposit_address::derive_deposit_script;
use rusqlite::types::{Value as SqlV, ValueRef};
use solid_pod_rs::payments::TokenConfig;
use std::collections::HashMap;
use std::future::Future;
use std::task::{Context, Poll, Waker};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// The fixtures never pend (SQLite and the explorer map are synchronous).
fn block_on<F: Future>(f: F) -> F::Output {
    let mut f = std::pin::pin!(f);
    match f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(v) => v,
        Poll::Pending => panic!("fixture future pended"),
    }
}

struct Sqlite(rusqlite::Connection);

impl Sqlite {
    fn new() -> Self {
        let conn = rusqlite::Connection::open_in_memory().expect("sqlite");
        for ddl in SCHEMA {
            // ALTERs fail on a fresh table that already has the column, as on D1.
            let _ = conn.execute(ddl, []);
        }
        Self(conn)
    }

    fn exec(&self, sql: &str) {
        self.0.execute_batch(sql).expect("fixture sql");
    }

    fn count(&self, sql: &str) -> i64 {
        self.0.query_row(sql, [], |r| r.get(0)).expect("count")
    }
}

fn to_sql(v: &SqlValue) -> SqlV {
    match v {
        SqlValue::Text(s) => SqlV::Text(s.clone()),
        SqlValue::Int(i) => SqlV::Integer(*i),
        SqlValue::Null => SqlV::Null,
    }
}

fn to_json(v: ValueRef<'_>) -> Value {
    match v {
        ValueRef::Null => Value::Null,
        ValueRef::Integer(i) => json!(i),
        ValueRef::Real(f) => json!(f),
        ValueRef::Text(t) => json!(String::from_utf8_lossy(t)),
        ValueRef::Blob(b) => json!(hex::encode(b)),
    }
}

#[async_trait::async_trait(?Send)]
impl LedgerDb for Sqlite {
    async fn batch(&self, stmts: Vec<Stmt>) -> Result<Vec<u64>, String> {
        let tx = self.0.unchecked_transaction().map_err(|e| e.to_string())?;
        let mut changed = Vec::with_capacity(stmts.len());
        for s in &stmts {
            let n = tx
                .execute(
                    s.sql,
                    rusqlite::params_from_iter(s.params.iter().map(to_sql)),
                )
                .map_err(|e| format!("{e} in {}", s.sql))?;
            changed.push(n as u64);
        }
        tx.commit().map_err(|e| e.to_string())?;
        Ok(changed)
    }

    async fn first(&self, stmt: Stmt) -> Result<Option<Value>, String> {
        Ok(self.all(stmt).await?.into_iter().next())
    }

    async fn all(&self, stmt: Stmt) -> Result<Vec<Value>, String> {
        let mut q = self.0.prepare(stmt.sql).map_err(|e| e.to_string())?;
        let names: Vec<String> = q.column_names().iter().map(|s| s.to_string()).collect();
        let rows = q
            .query_map(
                rusqlite::params_from_iter(stmt.params.iter().map(to_sql)),
                |row| {
                    let mut obj = serde_json::Map::new();
                    for (i, name) in names.iter().enumerate() {
                        obj.insert(name.clone(), to_json(row.get_ref(i)?));
                    }
                    Ok(Value::Object(obj))
                },
            )
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())
    }
}

/// Explorer fixture: `(explorer_api, txid)` → transaction JSON.
#[derive(Default)]
struct Explorer(HashMap<(String, String), Value>);

impl Explorer {
    fn with(mut self, api: &str, tx: Value) -> Self {
        let txid = tx["txid"].as_str().expect("txid").to_ascii_lowercase();
        self.0.insert((api.to_string(), txid), tx);
        self
    }
}

#[async_trait::async_trait(?Send)]
impl TxSource for Explorer {
    async fn transaction(&self, api: &str, txid: &str) -> Result<Value, String> {
        self.0
            .get(&(api.to_string(), txid.to_ascii_lowercase()))
            .cloned()
            .ok_or_else(|| "explorer answered 404".to_string())
    }
}

const MAINNET_API: &str = "https://mempool.space/api";
const MIRROR_API: &str = "https://mirror.example/api";

/// The production pay config (`lib.rs` `load_pay_config` with the live
/// `PAY_TOKEN_TICKER=DREAM`, `PAY_TOKEN_RATE=10`).
fn live_config() -> PayConfig {
    PayConfig {
        enabled: true,
        cost_sats: 1,
        token: Some(TokenConfig {
            ticker: "DREAM".into(),
            rate: 10,
            supply: 1_000_000,
            issuer: String::new(),
        }),
        chains: vec![
            ChainConfig::bitcoin_mainnet(),
            ChainConfig::bitcoin_testnet4(),
            ChainConfig::bitcoin_signet(),
        ],
    }
}

/// A second chain counted in sats, to show receipts keep the chain.
fn two_sat_chains() -> PayConfig {
    let mut c = live_config();
    c.chains.push(ChainConfig {
        id: "btc-mirror".into(),
        unit: "sat".into(),
        name: "Mirror".into(),
        explorer_api: MIRROR_API.into(),
    });
    c
}

const MASTER: [u8; 32] = [
    0xb7, 0xe1, 0x51, 0x62, 0x8a, 0xed, 0x2a, 0x6a, 0xbf, 0x71, 0x58, 0x80, 0x9c, 0xf4, 0xf3, 0xc7,
    0x62, 0xe7, 0x16, 0x0f, 0x38, 0xb4, 0xda, 0x56, 0xa7, 0x84, 0xd9, 0x04, 0x51, 0x90, 0xcf, 0xef,
];
const ALICE: &str = "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659";
const BOB: &str = "dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8";
const NOW: i64 = 1_759_300_000;

fn alice() -> Caller<'static> {
    Caller {
        pubkey: ALICE,
        request_id: "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
    }
}

fn bob() -> Caller<'static> {
    Caller {
        pubkey: BOB,
        request_id: "b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0",
    }
}

fn did(pk: &str) -> String {
    format!("did:nostr:{pk}")
}

fn script_hex(pk: &str) -> String {
    hex::encode(derive_deposit_script(&MASTER, pk).expect("script"))
}

fn tx(txid: &str, outputs: &[(&str, u64)], confirmed: bool) -> Value {
    json!({
        "txid": txid,
        "vout": outputs
            .iter()
            .map(|(s, v)| json!({ "scriptpubkey": s, "value": v }))
            .collect::<Vec<_>>(),
        "status": { "confirmed": confirmed },
    })
}

const TXID: &str = "abababababababababababababababababababababababababababababababab";
const TXID2: &str = "1111111111111111111111111111111111111111111111111111111111111111";

struct World {
    db: Sqlite,
    explorer: Explorer,
    config: PayConfig,
    now: i64,
    expiry: i64,
    master: Option<[u8; 32]>,
}

impl World {
    fn new() -> Self {
        Self {
            db: Sqlite::new(),
            explorer: Explorer::default(),
            config: live_config(),
            now: NOW,
            expiry: DEFAULT_JOB_EXPIRY_SECS,
            master: Some(MASTER),
        }
    }

    fn call(
        &self,
        method: PayMethod,
        path: &str,
        caller: Option<Caller<'_>>,
        body: &str,
    ) -> PayReply {
        let ctx = PayContext {
            config: &self.config,
            now: self.now,
            master_secret: self.master.as_ref(),
            job_expiry_secs: self.expiry,
        };
        block_on(dispatch(
            &self.db,
            &self.explorer,
            &ctx,
            method,
            path,
            caller,
            body.as_bytes(),
        ))
    }

    fn post(&self, path: &str, caller: Caller<'_>, body: &str) -> PayReply {
        self.call(PayMethod::Post, path, Some(caller), body)
    }

    fn balance(&self, pk: &str) -> u64 {
        block_on(read_balance(&self.db, &did(pk))).expect("balance")
    }

    fn credits(&self) -> i64 {
        self.db.count("SELECT COUNT(*) FROM pay_credits")
    }

    /// Fund an account the only way there is: a confirmed deposit.
    fn fund(&mut self, caller: Caller<'_>, txid: &str, value: u64) {
        let s = script_hex(caller.pubkey);
        let explorer = std::mem::take(&mut self.explorer);
        self.explorer = explorer.with(MAINNET_API, tx(txid, &[(s.as_str(), value)], true));
        let r = self.post(".deposit", caller, &format!("{{\"txo\":\"{txid}:0\"}}"));
        assert_eq!(r.status, 200, "{r:?}");
    }
}

fn status(r: &PayReply) -> u16 {
    r.status
}

// ---------------------------------------------------------------------------
// Deposits: evidence, script, once by outpoint
// ---------------------------------------------------------------------------

#[test]
fn deposit_with_amount_sats_is_refused_and_credits_nothing() {
    let w = World::new();
    let r = w.post(".deposit", alice(), r#"{"amount_sats":100000}"#);
    assert_eq!(status(&r), 400, "{r:?}");
    assert!(r.body["error"].as_str().unwrap().contains("amount_sats"));
    assert_eq!(w.balance(ALICE), 0);
    assert_eq!(w.credits(), 0);
    assert_eq!(w.db.count("SELECT COUNT(*) FROM webledger_accounts"), 0);
}

#[test]
fn deposit_with_amount_sats_beside_a_txo_is_refused() {
    let s = script_hex(ALICE);
    let mut w = World::new();
    w.explorer = Explorer::default().with(MAINNET_API, tx(TXID, &[(&s, 5_000)], true));
    let r = w.post(
        ".deposit",
        alice(),
        &format!(r#"{{"txo":"{TXID}:0","amount_sats":999999}}"#),
    );
    assert_eq!(status(&r), 400);
    assert_eq!(w.balance(ALICE), 0);
}

#[test]
fn deposit_without_a_txo_is_refused() {
    let w = World::new();
    assert_eq!(status(&w.post(".deposit", alice(), "{}")), 400);
    assert_eq!(status(&w.post(".deposit", alice(), "")), 400);
    assert_eq!(status(&w.post(".deposit", alice(), "not-a-txo")), 400);
}

#[test]
fn deposit_to_another_accounts_script_is_refused() {
    let bob_script = script_hex(BOB);
    let mut w = World::new();
    w.explorer = Explorer::default().with(MAINNET_API, tx(TXID, &[(&bob_script, 50_000)], true));
    let r = w.post(".deposit", alice(), &format!(r#"{{"txo":"{TXID}:0"}}"#));
    assert_eq!(status(&r), 403, "{r:?}");
    assert_eq!(w.balance(ALICE), 0);
    assert_eq!(w.credits(), 0);
    // The owner of the script can claim it (teller: credited to its account).
    let r = w.post(".deposit", bob(), &format!(r#"{{"txo":"{TXID}:0"}}"#));
    assert_eq!(status(&r), 200, "{r:?}");
    assert_eq!(w.balance(BOB), 50_000);
}

#[test]
fn deposit_to_an_arbitrary_script_is_refused() {
    let mut w = World::new();
    let p2wpkh = format!("0014{}", "77".repeat(20));
    w.explorer = Explorer::default().with(MAINNET_API, tx(TXID, &[(&p2wpkh, 50_000)], true));
    let r = w.post(".deposit", alice(), &format!("{TXID}:0"));
    assert_eq!(status(&r), 403);
    assert_eq!(w.balance(ALICE), 0);
}

/// teller 7c00cea `credit`: "a deposit credits its account once: the
/// outpoint is the receipt" — 50000 credited, the replay not applied, the
/// balance unchanged, the receipt recorded.
#[test]
fn teller_credit_once_by_outpoint_at_the_derived_address() {
    let s = script_hex(ALICE);
    let mut w = World::new();
    w.explorer = Explorer::default().with(
        MAINNET_API,
        tx(
            TXID,
            &[(&format!("0014{}", "00".repeat(20)), 7), (&s, 50_000)],
            true,
        ),
    );
    let r = w.post(".deposit", alice(), &format!(r#"{{"txo":"{TXID}:1"}}"#));
    assert_eq!(status(&r), 200, "{r:?}");
    assert_eq!(r.body["credited"], 50_000);
    assert_eq!(r.body["balance"], 50_000);
    assert_eq!(r.body["outpoint"], format!("txo:btc:{TXID}:1"));
    assert_eq!(w.balance(ALICE), 50_000);

    for replay in [
        format!(r#"{{"txo":"{TXID}:1"}}"#),
        format!("{TXID}:1"),
        format!("bitcoin:{TXID}:1"),
        format!("txo:btc:{TXID}:1"),
        format!("txo:BTC:{}:1", TXID.to_ascii_uppercase()),
    ] {
        let r = w.post(".deposit", alice(), &replay);
        assert_eq!(status(&r), 409, "{replay}: {r:?}");
    }
    assert_eq!(w.balance(ALICE), 50_000);
    assert_eq!(w.credits(), 1);

    let row = block_on(w.db.first(Stmt::new(
        "SELECT did, amount_sats, kind, chain, txid, vout, request_id, applied FROM pay_credits",
        vec![],
    )))
    .expect("row")
    .expect("one row");
    assert_eq!(row["did"], did(ALICE));
    assert_eq!(row["amount_sats"], 50_000);
    assert_eq!(row["kind"], "deposit");
    assert_eq!(row["chain"], "btc");
    assert_eq!(row["txid"], TXID);
    assert_eq!(row["vout"], 1);
    assert_eq!(row["request_id"], alice().request_id);
    assert_eq!(row["applied"], 1);
}

#[test]
fn the_same_outpoint_on_two_chains_is_two_receipts() {
    let s = script_hex(ALICE);
    let mut w = World::new();
    w.config = two_sat_chains();
    w.explorer = Explorer::default()
        .with(MAINNET_API, tx(TXID, &[(&s, 1_000)], true))
        .with(MIRROR_API, tx(TXID, &[(&s, 2_000)], true));
    assert_eq!(
        status(&w.post(".deposit", alice(), &format!("txo:btc:{TXID}:0"))),
        200
    );
    assert_eq!(
        status(&w.post(".deposit", alice(), &format!("txo:btc-mirror:{TXID}:0"))),
        200
    );
    assert_eq!(w.balance(ALICE), 3_000);
    assert_eq!(w.credits(), 2);
    // And each is still credited once.
    assert_eq!(
        status(&w.post(".deposit", alice(), &format!("txo:btc-mirror:{TXID}:0"))),
        409
    );
    assert_eq!(w.balance(ALICE), 3_000);
}

#[test]
fn replay_keys_keep_the_chain() {
    let btc = Outpoint::from_txo_uri(&format!("txo:btc:{TXID}:0")).expect("key");
    let signet = Outpoint::from_txo_uri(&format!("txo:signet:{TXID}:0")).expect("key");
    assert_ne!(btc, signet);
    assert_ne!(btc.replay_key(), signet.replay_key());
    assert_eq!(signet.replay_key(), format!("txo:signet:{TXID}:0"));
    // One outpoint spelled several ways is one key.
    for spelling in [
        format!("{TXID}:0"),
        format!("bitcoin:{TXID}:0"),
        format!(" txo:BTC:{}:0 ", TXID.to_ascii_uppercase()),
        TXID.to_ascii_uppercase() + ":0",
    ] {
        assert_eq!(
            Outpoint::from_txo_uri(&spelling).expect("key"),
            btc,
            "{spelling}"
        );
    }
    assert_eq!(btc.replay_key(), format!("txo:btc:{TXID}:0"));
    assert!(Outpoint::from_txo_uri("txo:btc:nothex:0").is_err());
    assert!(Outpoint::from_txo_uri(&format!("{TXID}:x")).is_err());
    assert!(Outpoint::from_txo_uri(&format!("txo:b@d:{TXID}:0")).is_err());
}

#[test]
fn a_deposit_on_a_test_chain_is_not_credited_as_sats() {
    let s = script_hex(ALICE);
    let mut w = World::new();
    w.explorer = Explorer::default().with(
        "https://mempool.space/signet/api",
        tx(TXID, &[(&s, 1_000_000)], true),
    );
    for chain in ["signet", "tbtc4"] {
        let r = w.post(".deposit", alice(), &format!("txo:{chain}:{TXID}:0"));
        assert_eq!(status(&r), 400, "{chain}: {r:?}");
    }
    let r = w.post(".deposit", alice(), &format!("txo:dogecoin:{TXID}:0"));
    assert_eq!(status(&r), 400);
    assert_eq!(w.balance(ALICE), 0);
}

#[test]
fn an_unconfirmed_output_is_not_credited() {
    let s = script_hex(ALICE);
    let mut w = World::new();
    w.explorer = Explorer::default().with(MAINNET_API, tx(TXID, &[(&s, 9_000)], false));
    assert_eq!(
        status(&w.post(".deposit", alice(), &format!("{TXID}:0"))),
        409
    );
    // No status at all is not confirmation either.
    let mut bare = tx(TXID2, &[(&s, 9_000)], true);
    bare.as_object_mut().unwrap().remove("status");
    w.explorer = Explorer::default().with(MAINNET_API, bare);
    assert_eq!(
        status(&w.post(".deposit", alice(), &format!("{TXID2}:0"))),
        409
    );
    assert_eq!(w.balance(ALICE), 0);
    assert_eq!(w.credits(), 0);
}

#[test]
fn explorer_faults_are_refused() {
    let s = script_hex(ALICE);
    let mut w = World::new();
    // Unknown transaction.
    assert_eq!(
        status(&w.post(".deposit", alice(), &format!("{TXID}:0"))),
        502
    );
    // An explorer answering for another txid.
    let mut other = tx(TXID2, &[(&s, 9_000)], true);
    other["txid"] = json!(TXID2);
    w.explorer
        .0
        .insert((MAINNET_API.into(), TXID.into()), other);
    assert_eq!(
        status(&w.post(".deposit", alice(), &format!("{TXID}:0"))),
        502
    );
    // An output index past the end.
    w.explorer = Explorer::default().with(MAINNET_API, tx(TXID, &[(&s, 9_000)], true));
    assert_eq!(
        status(&w.post(".deposit", alice(), &format!("{TXID}:3"))),
        400
    );
    assert_eq!(w.balance(ALICE), 0);
}

#[test]
fn a_legacy_chainless_receipt_blocks_a_second_credit() {
    let s = script_hex(ALICE);
    let mut w = World::new();
    w.db.exec(&format!(
        "INSERT INTO txo_deposits (txid, vout, did, amount_sats, deposited_at) \
         VALUES ('{}', 0, '{}', 4000, 1700000000)",
        TXID.to_ascii_uppercase(),
        did(ALICE)
    ));
    w.explorer = Explorer::default().with(MAINNET_API, tx(TXID, &[(&s, 4_000)], true));
    assert_eq!(
        status(&w.post(".deposit", alice(), &format!("{TXID}:0"))),
        409
    );
    assert_eq!(w.balance(ALICE), 0);
    // The credit batch guards it too, not just the pre-check.
    let o = Outpoint::from_txo_uri(&format!("{TXID}:0")).unwrap();
    assert!(!block_on(credit_deposit(&w.db, &did(ALICE), &o, 4_000, None, NOW)).unwrap());
    assert_eq!(w.balance(ALICE), 0);
}

#[test]
fn deposit_and_address_need_the_master_secret() {
    let mut w = World::new();
    w.master = None;
    assert_eq!(
        status(&w.post(".deposit", alice(), &format!("{TXID}:0"))),
        503
    );
    assert_eq!(
        status(&w.call(PayMethod::Get, ".address", Some(alice()), "")),
        503
    );
}

#[test]
fn address_route_serves_the_frozen_derivation() {
    let w = World::new();
    let r = w.call(PayMethod::Get, ".address", Some(alice()), "");
    assert_eq!(status(&r), 200);
    assert_eq!(
        r.body["address"],
        "bc1p0z7ve4ph6v4tfumrffgzmm5lhwzca2gq3gyl38yagyfdsuuddudsap2q2h"
    );
    assert_eq!(r.body["chain"], "btc");
}

#[test]
fn a_credit_without_evidence_cannot_be_written() {
    let w = World::new();
    let err = w.db.0.execute(
        "INSERT INTO pay_credits (credit_ref, did, amount_sats, kind, applied, created_at) \
         VALUES ('free', 'did:nostr:x', 100, 'deposit', 0, 0)",
        [],
    );
    assert!(
        err.is_err(),
        "CHECK must refuse a credit naming no evidence"
    );
}

// ---------------------------------------------------------------------------
// Token routes: no DREAM balance in D1, so no exchange
// ---------------------------------------------------------------------------

#[test]
fn dream_withdraw_on_zero_balance_is_refused_and_credits_nothing() {
    let w = World::new();
    let r = w.post(".withdraw", alice(), r#"{"amount":1000}"#);
    assert_eq!(status(&r), 410, "{r:?}");
    assert_eq!(w.balance(ALICE), 0);
    assert_eq!(w.credits(), 0);
    assert_eq!(w.db.count("SELECT COUNT(*) FROM webledger_accounts"), 0);
}

#[test]
fn dream_withdraw_never_moves_a_funded_balance() {
    let mut w = World::new();
    w.fund(alice(), TXID, 500);
    for body in [r#"{"amount":1000}"#, r#"{"amount":10}"#, "{}"] {
        assert_eq!(status(&w.post(".withdraw", alice(), body)), 410);
    }
    assert_eq!(w.balance(ALICE), 500);
    assert_eq!(w.credits(), 1);
}

#[test]
fn dream_buy_no_longer_burns_sats() {
    let mut w = World::new();
    w.fund(alice(), TXID, 500);
    assert_eq!(status(&w.post(".buy", alice(), r#"{"amount":100}"#)), 410);
    assert_eq!(w.balance(ALICE), 500);
}

#[test]
fn info_no_longer_advertises_unserved_routes() {
    let w = World::new();
    let r = w.call(PayMethod::Get, ".info", None, "");
    assert_eq!(status(&r), 200);
    assert_eq!(r.body["token"]["ticker"], "DREAM");
    assert_eq!(r.body["token"]["rate"], 10);
    assert!(r.body["token"].get("buy").is_none());
    assert!(r.body["token"].get("withdraw").is_none());
    assert!(r.body.get("pool").is_none());
    assert_eq!(r.body["deposit"], "/pay/.deposit");
    assert_eq!(r.body["chains"].as_array().unwrap().len(), 3);
}

// ---------------------------------------------------------------------------
// Auth, balance, metered resources
// ---------------------------------------------------------------------------

#[test]
fn routes_other_than_info_need_a_signed_caller() {
    let w = World::new();
    for (m, p) in [
        (PayMethod::Get, ".balance"),
        (PayMethod::Get, ".address"),
        (PayMethod::Post, ".deposit"),
        (PayMethod::Post, ".withdraw"),
        (PayMethod::Post, ".jobs.create"),
        (PayMethod::Get, "some/resource"),
    ] {
        assert_eq!(status(&w.call(m, p, None, "")), 401, "{p}");
    }
    assert_eq!(status(&w.call(PayMethod::Post, ".offers", None, "")), 200);
}

#[test]
fn metered_resource_debits_and_refuses_without_funds() {
    let mut w = World::new();
    let r = w.call(PayMethod::Get, "doc", Some(alice()), "");
    assert_eq!(status(&r), 402);
    assert_eq!(r.body["balance"], 0);
    w.fund(alice(), TXID, 3);
    let r = w.call(PayMethod::Get, "doc", Some(alice()), "");
    assert_eq!(status(&r), 200);
    assert_eq!(r.body["balance"], 2);
    let r = w.call(PayMethod::Get, ".balance", Some(alice()), "");
    assert_eq!(r.body["balance"], 2);
    assert_eq!(
        status(&w.call(PayMethod::Other, ".balance", Some(alice()), "")),
        405
    );
}

// ---------------------------------------------------------------------------
// Agent jobs: holds are debits; releases are journalled credits, once
// ---------------------------------------------------------------------------

fn agent_did() -> String {
    did(BOB)
}

fn create_job(w: &World) -> PayReply {
    w.post(
        ".jobs.create",
        alice(),
        &json!({ "agent_did": agent_did(), "endpoint": "/api/inference/run" }).to_string(),
    )
}

#[test]
fn job_create_without_funds_holds_nothing() {
    let w = World::new();
    let r = create_job(&w);
    assert_eq!(status(&r), 402, "{r:?}");
    assert_eq!(r.body["required"], 12);
    assert_eq!(w.db.count("SELECT COUNT(*) FROM agent_jobs"), 0);
    assert_eq!(w.balance(ALICE), 0);
}

#[test]
fn job_create_validates_the_agent() {
    let mut w = World::new();
    w.fund(alice(), TXID, 100);
    let r = w.post(
        ".jobs.create",
        alice(),
        r#"{"agent_did":"did:nostr:abc","endpoint":"/x"}"#,
    );
    assert_eq!(status(&r), 400);
    assert_eq!(status(&w.post(".jobs.create", alice(), "nope")), 400);
    assert_eq!(w.balance(ALICE), 100);
}

#[test]
fn job_settle_returns_the_unused_hold_once_with_its_request_id() {
    let mut w = World::new();
    w.fund(alice(), TXID, 1_000);
    let r = create_job(&w);
    assert_eq!(status(&r), 200, "{r:?}");
    let job = r.body["job_id"].as_str().unwrap().to_string();
    assert_eq!(r.body["held_sats"], 12);
    assert_eq!(w.balance(ALICE), 988);

    let body = json!({ "job_id": job }).to_string();
    // Only the agent starts it.
    assert_eq!(status(&w.post(".jobs.start", alice(), &body)), 404);
    assert_eq!(status(&w.post(".jobs.start", bob(), &body)), 200);

    let settle = json!({ "job_id": job, "actual_sats": 4 }).to_string();
    assert_eq!(status(&w.post(".jobs.settle", alice(), &settle)), 403);
    let over = json!({ "job_id": job, "actual_sats": 13 }).to_string();
    assert_eq!(status(&w.post(".jobs.settle", bob(), &over)), 400);
    let r = w.post(".jobs.settle", bob(), &settle);
    assert_eq!(status(&r), 200, "{r:?}");
    assert_eq!(r.body["refund"], 8);
    assert_eq!(w.balance(ALICE), 996);

    // Settling again, or cancelling after, returns nothing more.
    assert_eq!(status(&w.post(".jobs.settle", bob(), &settle)), 409);
    assert_eq!(status(&w.post(".jobs.cancel", alice(), &body)), 409);
    assert_eq!(w.balance(ALICE), 996);

    let row = block_on(w.db.first(Stmt::new(
        "SELECT did, amount_sats, kind, request_id, txid, applied FROM pay_credits WHERE credit_ref = ?1",
        vec![release_ref(&job).into()],
    )))
    .unwrap()
    .expect("release row");
    assert_eq!(row["did"], did(ALICE));
    assert_eq!(row["amount_sats"], 8);
    assert_eq!(row["kind"], "job-release");
    assert_eq!(row["request_id"], bob().request_id);
    assert_eq!(row["txid"], Value::Null);
    assert_eq!(row["applied"], 1);

    let got = w.post(".jobs.get", alice(), &body);
    assert_eq!(got.body["status"], "settled");
    let stranger = Caller {
        pubkey: "cc".repeat(32).leak(),
        request_id: "cc",
    };
    assert_eq!(status(&w.post(".jobs.get", stranger, &body)), 403);
    let list = w.call(PayMethod::Get, ".jobs", Some(alice()), "");
    assert_eq!(list.body["count"], 1);
}

#[test]
fn job_cancel_returns_the_whole_hold_once() {
    let mut w = World::new();
    w.fund(alice(), TXID, 100);
    let job = create_job(&w).body["job_id"].as_str().unwrap().to_string();
    assert_eq!(w.balance(ALICE), 88);
    let body = json!({ "job_id": job }).to_string();
    let stranger = Caller {
        pubkey: "dd".repeat(32).leak(),
        request_id: "dd",
    };
    assert_eq!(status(&w.post(".jobs.cancel", stranger, &body)), 403);
    let r = w.post(".jobs.cancel", alice(), &body);
    assert_eq!(status(&r), 200, "{r:?}");
    assert_eq!(r.body["refund"], 12);
    assert_eq!(w.balance(ALICE), 100);
    assert_eq!(status(&w.post(".jobs.cancel", bob(), &body)), 409);
    assert_eq!(w.balance(ALICE), 100);
    assert_eq!(
        status(&w.post(".jobs.cancel", alice(), r#"{"job_id":"job_0_missing"}"#)),
        404
    );
}

/// A job failed and refunded before `release_ref` existed has no journal
/// row; nothing may refund it again.
#[test]
fn a_job_released_before_the_journal_is_never_released_again() {
    let w = World::new();
    w.db.exec(&format!(
        "INSERT INTO agent_jobs (job_id, requester_did, agent_did, endpoint, status, \
         estimated_sats, held_sats, created_at, completed_at, error, expires_at) \
         VALUES ('job_legacy', '{}', '{}', '/x', 'failed', 40, 50, 1, 2, 'expired', \
         '2020-01-01T00:00:00.000Z')",
        did(ALICE),
        agent_did()
    ));
    let body = r#"{"job_id":"job_legacy"}"#;
    assert_eq!(status(&w.post(".jobs.cancel", alice(), body)), 409);
    assert_eq!(
        block_on(recover_orphaned_jobs(&w.db, "ee", NOW)).unwrap(),
        0
    );
    assert_eq!(w.balance(ALICE), 0);
    assert_eq!(w.credits(), 0);
}

#[test]
fn orphan_recovery_returns_each_expired_hold_once() {
    let mut w = World::new();
    w.fund(alice(), TXID, 100);
    w.expiry = -60; // already expired when created
    let job = create_job(&w).body["job_id"].as_str().unwrap().to_string();
    assert_eq!(w.balance(ALICE), 88);

    // .cleanup is admin-only.
    w.db.exec("CREATE TABLE members (pubkey TEXT PRIMARY KEY, is_admin INTEGER)");
    w.db.exec("CREATE TABLE whitelist (pubkey TEXT PRIMARY KEY, is_admin INTEGER)");
    assert_eq!(status(&w.post(".cleanup", alice(), "")), 403);
    w.db.exec(&format!("INSERT INTO members VALUES ('{BOB}', 0)"));
    w.db.exec(&format!("INSERT INTO whitelist VALUES ('{BOB}', 1)"));
    let r = w.post(".cleanup", bob(), "");
    assert_eq!(status(&r), 200, "{r:?}");
    assert_eq!(r.body["recovered_jobs"], 1);
    assert_eq!(w.balance(ALICE), 100);
    let r = w.post(".cleanup", bob(), "");
    assert_eq!(r.body["recovered_jobs"], 0);
    assert_eq!(w.balance(ALICE), 100);
    let row = block_on(w.db.first(Stmt::new(
        "SELECT request_id, amount_sats FROM pay_credits WHERE credit_ref = ?1",
        vec![release_ref(&job).into()],
    )))
    .unwrap()
    .expect("release row");
    assert_eq!(row["request_id"], bob().request_id);
    assert_eq!(row["amount_sats"], 12);
}

/// After a mixed run every credit row names an outpoint or a signed
/// request, and every balance is the sum of its credits less its debits.
#[test]
fn every_credit_row_names_its_evidence() {
    let mut w = World::new();
    w.fund(alice(), TXID, 1_000);
    w.fund(bob(), TXID2, 50);
    let job = create_job(&w).body["job_id"].as_str().unwrap().to_string();
    w.post(
        ".jobs.cancel",
        alice(),
        &json!({ "job_id": job }).to_string(),
    );
    w.call(PayMethod::Get, "doc", Some(bob()), "");
    assert_eq!(
        w.db.count(
            "SELECT COUNT(*) FROM pay_credits WHERE NOT \
             ((chain IS NOT NULL AND txid IS NOT NULL AND vout IS NOT NULL) \
              OR request_id IS NOT NULL)"
        ),
        0
    );
    assert_eq!(
        w.db.count("SELECT COUNT(*) FROM pay_credits WHERE applied = 0"),
        0
    );
    assert_eq!(w.balance(ALICE), 1_000);
    assert_eq!(w.balance(BOB), 49);
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

#[test]
fn schema_is_idempotent_and_additive() {
    let w = World::new();
    w.db.exec(&format!(
        "INSERT INTO webledger_accounts VALUES ('{}', 777, 1)",
        did(ALICE)
    ));
    for ddl in SCHEMA {
        let _ = w.db.0.execute(ddl, []);
    }
    assert_eq!(
        w.balance(ALICE),
        777,
        "re-running the schema keeps balances"
    );
}

#[test]
fn schema_upgrades_a_pre_journal_database_without_touching_rows() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    // The tables as the code before ADR-2012 D6 created them.
    conn.execute_batch(
        "CREATE TABLE webledger_accounts (did TEXT PRIMARY KEY, balance_sats INTEGER NOT NULL DEFAULT 0, updated_at INTEGER NOT NULL);
         CREATE TABLE txo_deposits (txid TEXT NOT NULL, vout INTEGER NOT NULL, did TEXT NOT NULL, amount_sats INTEGER NOT NULL, deposited_at INTEGER NOT NULL, PRIMARY KEY (txid, vout));
         CREATE TABLE agent_jobs (job_id TEXT PRIMARY KEY, requester_did TEXT NOT NULL, agent_did TEXT NOT NULL, endpoint TEXT NOT NULL, params_json TEXT, status TEXT NOT NULL DEFAULT 'held', estimated_sats INTEGER NOT NULL DEFAULT 0, held_sats INTEGER NOT NULL DEFAULT 0, actual_sats INTEGER, created_at INTEGER NOT NULL, started_at INTEGER, completed_at INTEGER, error TEXT, expires_at TEXT);
         INSERT INTO webledger_accounts VALUES ('did:nostr:old', 4242, 1);
         INSERT INTO txo_deposits VALUES ('ab', 0, 'did:nostr:old', 4242, 1);
         INSERT INTO agent_jobs (job_id, requester_did, agent_did, endpoint, created_at) VALUES ('j', 'a', 'b', '/x', 1);",
    )
    .unwrap();
    for ddl in SCHEMA {
        let _ = conn.execute(ddl, []);
    }
    let bal: i64 = conn
        .query_row("SELECT balance_sats FROM webledger_accounts", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(bal, 4242);
    let n: i64 = conn
        .query_row("SELECT COUNT(*) FROM txo_deposits", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 1);
    let rref: Option<String> = conn
        .query_row("SELECT release_ref FROM agent_jobs", [], |r| r.get(0))
        .unwrap();
    assert_eq!(rref, None);
}

/// Auth-worker migration `0004_pay_credits.sql` (same D1) creates exactly
/// the journal the worker's runtime DDL creates.
#[test]
fn checked_in_migration_matches_the_runtime_ddl() {
    let migration = include_str!("../../../nostr-bbs-auth-worker/migrations/0004_pay_credits.sql");
    let normalise = |s: &str| s.split_whitespace().collect::<String>();
    let schema = |conn: &rusqlite::Connection| -> Vec<String> {
        let mut q = conn
            .prepare("SELECT sql FROM sqlite_master WHERE tbl_name = 'pay_credits' AND sql IS NOT NULL ORDER BY name")
            .unwrap();
        q.query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .map(|s| normalise(&s.unwrap()))
            .collect()
    };
    let from_migration = rusqlite::Connection::open_in_memory().unwrap();
    from_migration.execute_batch(migration).unwrap();
    let from_runtime = rusqlite::Connection::open_in_memory().unwrap();
    from_runtime.execute(DDL_PAY_CREDITS, []).unwrap();
    from_runtime.execute(DDL_PAY_CREDITS_DID_INDEX, []).unwrap();
    assert_eq!(schema(&from_migration), schema(&from_runtime));
    assert_eq!(schema(&from_runtime).len(), 2);
}

// ---------------------------------------------------------------------------
// Pure helpers (carried over from the pre-D6 suite)
// ---------------------------------------------------------------------------

#[test]
fn estimate_costs_by_endpoint() {
    assert_eq!(estimate_endpoint_cost("/api/inference/run", 1), 10);
    assert_eq!(estimate_endpoint_cost("/api/inference/batch", 2), 20);
    assert_eq!(estimate_endpoint_cost("/api/image-gen/submit", 1), 100);
    assert_eq!(estimate_endpoint_cost("/api/analytics/pagerank", 1), 5);
    assert_eq!(estimate_endpoint_cost("/api/health", 3), 3);
    assert_eq!(estimate_endpoint_cost("/some/other", 1), 1);
}

#[test]
fn estimate_route_answers_without_touching_the_ledger() {
    let w = World::new();
    let r = w.post(
        ".estimate",
        alice(),
        r#"{"endpoint":"/api/image-gen/x","params":{}}"#,
    );
    assert_eq!(status(&r), 200);
    assert_eq!(r.body["estimated_sats"], 100);
    assert_eq!(status(&w.post(".estimate", alice(), "{}")), 400);
}

#[test]
fn hold_is_estimate_plus_twenty_percent_rounded_up() {
    assert_eq!(hold_for(100), 120);
    assert_eq!(hold_for(10), 12);
    assert_eq!(hold_for(7), 9);
}

#[test]
fn job_bodies_deserialise() {
    let b: JobCreateBody = serde_json::from_str(
        r#"{"agent_did":"did:nostr:abc123","endpoint":"/api/inference/run","params":{"model":"gpt4"}}"#,
    )
    .unwrap();
    assert_eq!(b.params.unwrap()["model"], "gpt4");
    let b: JobCreateBody =
        serde_json::from_str(r#"{"agent_did":"did:nostr:abc","endpoint":"/api/health"}"#).unwrap();
    assert!(b.params.is_none());
    let b: JobActionBody = serde_json::from_str(r#"{"job_id":"job_1_ab"}"#).unwrap();
    assert_eq!(b.job_id, "job_1_ab");
    let b: JobSettleBody = serde_json::from_str(r#"{"job_id":"j","actual_sats":42}"#).unwrap();
    assert_eq!(b.actual_sats, 42);
}

#[test]
fn job_ids_are_timestamped_and_random() {
    let id = generate_job_id(1_715_443_200).unwrap();
    let parts: Vec<&str> = id.splitn(3, '_').collect();
    assert_eq!(parts[0], "job");
    assert_eq!(parts[1], "1715443200");
    assert_eq!(parts[2].len(), 16);
    assert!(parts[2].bytes().all(|b| b.is_ascii_hexdigit()));
    assert_ne!(id, generate_job_id(1_715_443_200).unwrap());
}

#[test]
fn iso8601_matches_javascript_to_iso_string() {
    assert_eq!(iso8601_from_epoch(0), "1970-01-01T00:00:00.000Z");
    assert_eq!(
        iso8601_from_epoch(1_715_443_200),
        "2024-05-11T16:00:00.000Z"
    );
    assert_eq!(iso8601_from_epoch(951_782_400), "2000-02-29T00:00:00.000Z");
    assert_eq!(
        iso8601_from_epoch(1_735_689_599),
        "2024-12-31T23:59:59.000Z"
    );
    assert_eq!(
        iso8601_from_epoch(4_102_444_800),
        "2100-01-01T00:00:00.000Z"
    );
    assert!(iso8601_from_epoch(NOW) < iso8601_from_epoch(NOW + 1));
}
