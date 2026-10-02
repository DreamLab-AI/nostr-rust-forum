//! HTTP 402 Payment Required — CF Workers adapter for the `/pay/` ledger.
//!
//! The ledger rules live in [`crate::pay_ledger`] and the deposit-address
//! derivation in [`crate::deposit_address`]; this module binds them to the
//! Workers runtime: D1 (`REPLAY_DB`) through [`D1Ledger`], the mempool
//! explorer through [`MempoolTxSource`], and `MASTER_SECRET` from the env.
//!
//! All accounts are keyed by `did:nostr:<hex-pubkey>` — users and agents are
//! indistinguishable, enabling user-user, user-agent, agent-agent payments.
//! Sats enter an account only from a confirmed output paid to that account's
//! derived deposit address, credited once by outpoint (ADR-2012 D6).
//!
//! @see <https://webledgers.org>
//! @see JSS `src/handlers/pay.js`
//!
//! ## Reference
//!
//! The payment primitives consumed here are documented in Melvin Carvalho's
//! *Practical Guide to Solid* — a 10-part walkthrough of the JavaScript Solid
//! Server's HTTP 402, WebLedger, MRC20, and blocktrail features:
//! <https://melvin.me/public/solid/>; the credit rule follows his teller
//! (solidpayorg/teller `lib/teller.mjs`).

use nostr_bbs_core::d1_helpers::{js_i64, js_str};
use serde_json::Value;
use wasm_bindgen::JsValue;
use worker::*;
use zeroize::Zeroizing;

use crate::pay_ledger::{
    self, Caller, LedgerDb, PayContext, PayMethod, PayReply, SqlValue, Stmt, TxSource,
};

pub use solid_pod_rs::payments::{webledgers_discovery, ChainConfig, PayConfig, TokenConfig};

// ---------------------------------------------------------------------------
// Schema initialisation (idempotent — runs on every worker startup)
// ---------------------------------------------------------------------------

/// Create the payment/quota D1 tables and additive columns if missing.
///
/// Idempotent (`IF NOT EXISTS`; an `ALTER … ADD COLUMN` that already ran
/// fails harmlessly). Nothing is pruned: deposit receipts are replay
/// evidence and are kept for good.
pub async fn ensure_payment_schema(env: &Env, db_binding: &str) {
    let db = match env.d1(db_binding) {
        Ok(db) => db,
        Err(_) => return,
    };
    for ddl in pay_ledger::SCHEMA {
        let _ = db.prepare(*ddl).run().await;
    }
}

// ---------------------------------------------------------------------------
// D1 binding of the ledger seam
// ---------------------------------------------------------------------------

/// [`LedgerDb`] over a D1 database; `batch` is a D1 batch, which D1 runs
/// as one SQL transaction.
pub struct D1Ledger<'a>(pub &'a D1Database);

fn js_value(v: &SqlValue) -> JsValue {
    match v {
        SqlValue::Text(s) => js_str(s),
        SqlValue::Int(i) => js_i64(*i),
        SqlValue::Null => JsValue::NULL,
    }
}

impl D1Ledger<'_> {
    fn prepare(&self, stmt: &Stmt) -> std::result::Result<D1PreparedStatement, String> {
        let params: Vec<JsValue> = stmt.params.iter().map(js_value).collect();
        self.0
            .prepare(stmt.sql)
            .bind(&params)
            .map_err(|e| format!("d1 bind: {e:?}"))
    }
}

#[async_trait::async_trait(?Send)]
impl LedgerDb for D1Ledger<'_> {
    async fn batch(&self, stmts: Vec<Stmt>) -> std::result::Result<Vec<u64>, String> {
        let prepared = stmts
            .iter()
            .map(|s| self.prepare(s))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let results = self
            .0
            .batch(prepared)
            .await
            .map_err(|e| format!("d1 batch: {e:?}"))?;
        Ok(results
            .iter()
            .map(|r| {
                r.meta()
                    .ok()
                    .flatten()
                    .and_then(|m| m.changes.or(m.rows_written))
                    .unwrap_or(0) as u64
            })
            .collect())
    }

    async fn first(&self, stmt: Stmt) -> std::result::Result<Option<Value>, String> {
        self.prepare(&stmt)?
            .first::<Value>(None)
            .await
            .map_err(|e| format!("d1 first: {e:?}"))
    }

    async fn all(&self, stmt: Stmt) -> std::result::Result<Vec<Value>, String> {
        self.prepare(&stmt)?
            .all()
            .await
            .map_err(|e| format!("d1 all: {e:?}"))?
            .results::<Value>()
            .map_err(|e| format!("d1 rows: {e:?}"))
    }
}

// ---------------------------------------------------------------------------
// Explorer
// ---------------------------------------------------------------------------

/// [`TxSource`] over a mempool.space / esplora HTTP API.
pub struct MempoolTxSource;

#[async_trait::async_trait(?Send)]
impl TxSource for MempoolTxSource {
    async fn transaction(
        &self,
        explorer_api: &str,
        txid: &str,
    ) -> std::result::Result<Value, String> {
        let url = format!("{}/tx/{txid}", explorer_api.trim_end_matches('/'));
        let mut resp = Fetch::Url(worker::Url::parse(&url).map_err(|e| e.to_string())?)
            .send()
            .await
            .map_err(|e| format!("fetch: {e}"))?;
        if resp.status_code() != 200 {
            return Err(format!("explorer answered {}", resp.status_code()));
        }
        resp.json().await.map_err(|e| format!("json: {e}"))
    }
}

// ---------------------------------------------------------------------------
// /pay/ route handler
// ---------------------------------------------------------------------------

/// Handle all `/pay/*` routes. Returns `None` when payments are disabled or
/// the path is not a pay route.
///
/// `caller` is the NIP-98 verified signer and the signed request's event id;
/// the id is recorded on every credit the request causes.
pub async fn handle_pay_route(
    path: &str,
    method: &Method,
    caller: Option<Caller<'_>>,
    body_bytes: Option<&[u8]>,
    db: &D1Database,
    env: &Env,
    config: &PayConfig,
) -> Option<std::result::Result<Response, Error>> {
    if !config.enabled {
        return None;
    }
    let pay_path = path.strip_prefix("/pay/")?;

    let method = match *method {
        Method::Get => PayMethod::Get,
        Method::Post => PayMethod::Post,
        _ => PayMethod::Other,
    };

    // The master secret is read only for the two routes that derive from it,
    // and wiped when the request is done.
    let master_secret = if caller.is_some() && pay_ledger::route_needs_master_secret(pay_path) {
        match load_master_secret(env) {
            Ok(s) => Some(s),
            Err(e) => {
                worker::console_error!("pay: {e}");
                None
            }
        }
    } else {
        None
    };

    let ctx = PayContext {
        config,
        now: now_epoch_secs(),
        master_secret: master_secret.as_deref(),
        job_expiry_secs: job_expiry_secs(env),
    };
    let reply = pay_ledger::dispatch(
        &D1Ledger(db),
        &MempoolTxSource,
        &ctx,
        method,
        pay_path,
        caller,
        body_bytes.unwrap_or_default(),
    )
    .await;
    Some(reply_to_response(&reply))
}

fn reply_to_response(reply: &PayReply) -> std::result::Result<Response, Error> {
    let json_str =
        serde_json::to_string(&reply.body).map_err(|e| Error::RustError(e.to_string()))?;
    let resp = Response::ok(json_str)?.with_status(reply.status);
    resp.headers().set("Content-Type", "application/json").ok();
    Ok(resp)
}

/// Read the 32-byte `MASTER_SECRET` (64 hex chars) into a buffer that is
/// zeroed on drop.
fn load_master_secret(env: &Env) -> std::result::Result<Zeroizing<[u8; 32]>, String> {
    let master_hex = Zeroizing::new(
        env.secret("MASTER_SECRET")
            .map_err(|_| "MASTER_SECRET not configured".to_string())?
            .to_string(),
    );
    if master_hex.len() != 64 {
        return Err("MASTER_SECRET must be exactly 64 hex characters (32 bytes)".into());
    }
    let mut secret = Zeroizing::new([0u8; 32]);
    hex::decode_to_slice(master_hex.as_bytes(), secret.as_mut_slice())
        .map_err(|e| format!("MASTER_SECRET hex invalid: {e}"))?;
    Ok(secret)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Current epoch timestamp in seconds (JS runtime).
fn now_epoch_secs() -> i64 {
    (js_sys::Date::now() / 1000.0) as i64
}

/// The configurable job expiry (`JOB_EXPIRY_SECS`), falling back to
/// [`pay_ledger::DEFAULT_JOB_EXPIRY_SECS`] (1 hour).
fn job_expiry_secs(env: &Env) -> i64 {
    env.var("JOB_EXPIRY_SECS")
        .ok()
        .and_then(|v| v.to_string().parse::<i64>().ok())
        .unwrap_or(pay_ledger::DEFAULT_JOB_EXPIRY_SECS)
}
