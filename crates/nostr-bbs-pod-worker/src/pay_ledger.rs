//! The `/pay/*` ledger rules, free of the Workers runtime.
//!
//! Every balance change in the pod's sats ledger goes through this module,
//! over the [`LedgerDb`] seam: the worker binds it to D1
//! (`payments::D1Ledger`), the tests to a real SQLite running the same SQL.
//!
//! The credit rule is the teller's (solidpayorg/teller `lib/teller.mjs`
//! `credit`, 7c00cea): **a deposit seen on-chain credits its account once,
//! and the outpoint is the receipt.** Here that means:
//!
//! - a deposit is credited only from a confirmed output whose scriptPubKey
//!   is the depositor's own derived deposit script
//!   ([`crate::deposit_address::derive_deposit_script`]); there is no other
//!   way to put sats into an account;
//! - the receipt key keeps the chain: `txo:<chain>:<txid>:<vout>`, with the
//!   txid lower-cased, so one outpoint on two chains is two receipts and one
//!   outpoint spelled two ways is one;
//! - every credit is a row in `pay_credits` that names its evidence (an
//!   outpoint, or the id of the NIP-98 signed request that released a job
//!   hold), and the balance moves in the same D1 batch (one transaction)
//!   that writes the row, reading the amount and account back from the row.
//!
//! Debits need no chain evidence (the caller's NIP-98 signature authorises
//! them) but never overdraw: `UPDATE … WHERE balance_sats >= cost`.
//!
//! There is no DREAM (or any token) balance in D1, so `/pay/.buy` and
//! `/pay/.withdraw` answer 410: the first debited sats for a token nothing
//! recorded, the second credited sats for a token nothing debited.

use serde::Deserialize;
use serde_json::{json, Value};
use solid_pod_rs::payments::{
    balance_response, parse_txo_uri, pay_info, payment_required_body, pubkey_to_did, ChainConfig,
    PayConfig,
};

use crate::deposit_address::{derive_deposit_address, derive_deposit_script};

/// The unit this ledger counts in. A deposit on a chain whose unit differs
/// (test coins) is refused rather than credited as sats.
pub const LEDGER_UNIT: &str = "sat";

/// The chain a TXO URI without an explicit chain (`txid:vout`,
/// `bitcoin:txid:vout`) is read on.
pub const DEFAULT_CHAIN: &str = "btc";

/// Default job expiry duration: 1 hour (3600 seconds).
///
/// Configurable via the `JOB_EXPIRY_SECS` env var.
pub const DEFAULT_JOB_EXPIRY_SECS: i64 = 3600;

// ---------------------------------------------------------------------------
// Schema (idempotent; the worker runs it at startup, the tests on SQLite)
// ---------------------------------------------------------------------------

/// Per-DID satoshi balance.
pub const DDL_WEBLEDGER_ACCOUNTS: &str = "CREATE TABLE IF NOT EXISTS webledger_accounts (\
     did TEXT PRIMARY KEY, \
     balance_sats INTEGER NOT NULL DEFAULT 0, \
     updated_at INTEGER NOT NULL)";

/// Legacy deposit receipts, keyed `(txid, vout)` without the chain. Written
/// by the code before ADR-2012 D6; now only read, as a guard so that no
/// outpoint credited then can be credited again. Never pruned.
pub const DDL_TXO_DEPOSITS: &str = "CREATE TABLE IF NOT EXISTS txo_deposits (\
     txid TEXT NOT NULL, \
     vout INTEGER NOT NULL, \
     did TEXT NOT NULL, \
     amount_sats INTEGER NOT NULL, \
     deposited_at INTEGER NOT NULL, \
     PRIMARY KEY (txid, vout))";

/// Per-pubkey storage quota (see `quota.rs`).
pub const DDL_QUOTA_USAGE: &str = "CREATE TABLE IF NOT EXISTS quota_usage (\
     pubkey TEXT PRIMARY KEY, \
     limit_bytes INTEGER NOT NULL DEFAULT 52428800, \
     used_bytes INTEGER NOT NULL DEFAULT 0, \
     updated_at INTEGER NOT NULL)";

/// Agent jobs with the hold/settle lifecycle. `expires_at` is ISO 8601 text;
/// `release_ref` names the `pay_credits` row that returns the hold.
pub const DDL_AGENT_JOBS: &str = "CREATE TABLE IF NOT EXISTS agent_jobs (\
     job_id TEXT PRIMARY KEY, \
     requester_did TEXT NOT NULL, \
     agent_did TEXT NOT NULL, \
     endpoint TEXT NOT NULL, \
     params_json TEXT, \
     status TEXT NOT NULL DEFAULT 'held', \
     estimated_sats INTEGER NOT NULL DEFAULT 0, \
     held_sats INTEGER NOT NULL DEFAULT 0, \
     actual_sats INTEGER, \
     created_at INTEGER NOT NULL, \
     started_at INTEGER, \
     completed_at INTEGER, \
     error TEXT, \
     expires_at TEXT, \
     release_ref TEXT)";

/// Additive column for `agent_jobs` tables created before `expires_at`.
pub const DDL_AGENT_JOBS_EXPIRES_AT: &str = "ALTER TABLE agent_jobs ADD COLUMN expires_at TEXT";

/// Additive column for `agent_jobs` tables created before `release_ref`.
/// Existing rows keep `NULL`, so no job released before this column existed
/// can be released (refunded) again.
pub const DDL_AGENT_JOBS_RELEASE_REF: &str = "ALTER TABLE agent_jobs ADD COLUMN release_ref TEXT";

/// The credit journal: one row per credit, naming its evidence. The CHECK
/// makes a credit without an outpoint or a signed-request id unwritable.
/// Mirrored by auth-worker migration `0004_pay_credits.sql` (same D1).
pub const DDL_PAY_CREDITS: &str = "CREATE TABLE IF NOT EXISTS pay_credits (\
     credit_ref TEXT PRIMARY KEY, \
     did TEXT NOT NULL, \
     amount_sats INTEGER NOT NULL CHECK (amount_sats >= 0), \
     kind TEXT NOT NULL CHECK (kind IN ('deposit', 'job-release')), \
     chain TEXT, \
     txid TEXT, \
     vout INTEGER, \
     request_id TEXT, \
     applied INTEGER NOT NULL DEFAULT 0, \
     created_at INTEGER NOT NULL, \
     CHECK ((chain IS NOT NULL AND txid IS NOT NULL AND vout IS NOT NULL) \
            OR request_id IS NOT NULL))";

/// Lookup of an account's credits.
pub const DDL_PAY_CREDITS_DID_INDEX: &str =
    "CREATE INDEX IF NOT EXISTS pay_credits_did ON pay_credits (did)";

/// Every schema statement, in order. `ALTER` statements fail harmlessly when
/// the column exists; callers ignore per-statement errors.
pub const SCHEMA: &[&str] = &[
    DDL_WEBLEDGER_ACCOUNTS,
    DDL_TXO_DEPOSITS,
    DDL_QUOTA_USAGE,
    DDL_AGENT_JOBS,
    DDL_AGENT_JOBS_EXPIRES_AT,
    DDL_AGENT_JOBS_RELEASE_REF,
    DDL_PAY_CREDITS,
    DDL_PAY_CREDITS_DID_INDEX,
];

// ---------------------------------------------------------------------------
// SQL
// ---------------------------------------------------------------------------

const SQL_READ_BALANCE: &str = "SELECT balance_sats FROM webledger_accounts WHERE did = ?1";

const SQL_DEBIT: &str = "UPDATE webledger_accounts \
     SET balance_sats = balance_sats - ?1, updated_at = ?2 \
     WHERE did = ?3 AND balance_sats >= ?1";

/// A deposit receipt, written only if neither the chain-keyed journal nor
/// the legacy chain-less table already holds the outpoint.
const SQL_JOURNAL_DEPOSIT: &str = "INSERT OR IGNORE INTO pay_credits \
     (credit_ref, did, amount_sats, kind, chain, txid, vout, request_id, applied, created_at) \
     SELECT ?1, ?2, ?3, 'deposit', ?4, ?5, ?6, ?7, 0, ?8 \
     WHERE NOT EXISTS (SELECT 1 FROM txo_deposits WHERE lower(txid) = ?5 AND vout = ?6)";

/// A job-hold release receipt, written only for a job whose transition in
/// the same batch stamped `release_ref`; the amount is read from the job.
const SQL_JOURNAL_RELEASE: &str = "INSERT OR IGNORE INTO pay_credits \
     (credit_ref, did, amount_sats, kind, request_id, applied, created_at) \
     SELECT release_ref, requester_did, held_sats - COALESCE(actual_sats, 0), 'job-release', ?3, 0, ?4 \
     FROM agent_jobs \
     WHERE job_id = ?1 AND release_ref = ?2 AND held_sats - COALESCE(actual_sats, 0) > 0";

/// Apply a journalled credit to its account: account and amount come from
/// the journal row, and only while it is unapplied.
const SQL_APPLY_CREDIT: &str = "INSERT INTO webledger_accounts (did, balance_sats, updated_at) \
     SELECT did, amount_sats, ?2 FROM pay_credits WHERE credit_ref = ?1 AND applied = 0 \
     ON CONFLICT(did) DO UPDATE SET \
       balance_sats = balance_sats + excluded.balance_sats, \
       updated_at = excluded.updated_at";

const SQL_MARK_APPLIED: &str =
    "UPDATE pay_credits SET applied = 1 WHERE credit_ref = ?1 AND applied = 0";

const SQL_CREDIT_EXISTS: &str = "SELECT 1 AS hit FROM pay_credits WHERE credit_ref = ?1 \
     UNION ALL SELECT 1 FROM txo_deposits WHERE lower(txid) = ?2 AND vout = ?3 LIMIT 1";

const SQL_JOBS_LIST: &str = "SELECT job_id, requester_did, agent_did, endpoint, params_json, \
     status, estimated_sats, held_sats, actual_sats, \
     created_at, started_at, completed_at, error, expires_at \
     FROM agent_jobs WHERE requester_did = ?1 \
     ORDER BY created_at DESC LIMIT 50";

const SQL_JOB_GET: &str = "SELECT job_id, requester_did, agent_did, endpoint, params_json, \
     status, estimated_sats, held_sats, actual_sats, \
     created_at, started_at, completed_at, error, expires_at \
     FROM agent_jobs WHERE job_id = ?1";

/// Insert a held job only while the requester can cover the hold.
const SQL_JOB_INSERT_IF_FUNDED: &str = "INSERT INTO agent_jobs \
     (job_id, requester_did, agent_did, endpoint, params_json, \
      status, estimated_sats, held_sats, created_at, expires_at) \
     SELECT ?1, ?2, ?3, ?4, ?5, 'held', ?6, ?7, ?8, ?9 \
     WHERE (SELECT balance_sats FROM webledger_accounts WHERE did = ?2) >= ?7";

/// Debit the hold only for the job the previous statement inserted.
const SQL_JOB_DEBIT_HOLD: &str = "UPDATE webledger_accounts \
     SET balance_sats = balance_sats - ?1, updated_at = ?2 \
     WHERE did = ?3 AND balance_sats >= ?1 \
       AND EXISTS (SELECT 1 FROM agent_jobs WHERE job_id = ?4 AND requester_did = ?3)";

const SQL_JOB_START: &str = "UPDATE agent_jobs SET status = 'running', started_at = ?1 \
     WHERE job_id = ?2 AND status = 'held' AND agent_did = ?3";

const SQL_JOB_SETTLE: &str = "UPDATE agent_jobs \
     SET status = 'settled', actual_sats = ?1, completed_at = ?2, release_ref = ?5 \
     WHERE job_id = ?3 AND status = 'running' AND agent_did = ?4 AND held_sats >= ?1";

const SQL_JOB_CANCEL: &str = "UPDATE agent_jobs \
     SET status = 'failed', error = 'cancelled', completed_at = ?1, release_ref = ?4 \
     WHERE job_id = ?2 AND (status = 'held' OR status = 'running') \
       AND (requester_did = ?3 OR agent_did = ?3)";

const SQL_JOB_EXPIRE: &str = "UPDATE agent_jobs \
     SET status = 'failed', error = 'expired', completed_at = ?1, release_ref = ?3 \
     WHERE job_id = ?2 AND (status = 'held' OR status = 'running')";

const SQL_JOBS_EXPIRED: &str = "SELECT job_id FROM agent_jobs \
     WHERE (status = 'held' OR status = 'running') \
       AND expires_at IS NOT NULL AND expires_at < ?1";

// ---------------------------------------------------------------------------
// The database seam
// ---------------------------------------------------------------------------

/// A bound SQL parameter.
#[derive(Debug, Clone, PartialEq)]
pub enum SqlValue {
    /// TEXT.
    Text(String),
    /// INTEGER.
    Int(i64),
    /// NULL.
    Null,
}

impl From<&str> for SqlValue {
    fn from(s: &str) -> Self {
        SqlValue::Text(s.to_string())
    }
}

impl From<String> for SqlValue {
    fn from(s: String) -> Self {
        SqlValue::Text(s)
    }
}

impl From<i64> for SqlValue {
    fn from(v: i64) -> Self {
        SqlValue::Int(v)
    }
}

impl From<Option<&str>> for SqlValue {
    fn from(v: Option<&str>) -> Self {
        v.map_or(SqlValue::Null, SqlValue::from)
    }
}

/// Satoshi amounts are stored as SQLite INTEGER (i64); anything above
/// `i64::MAX` is beyond 21e14 sat by many orders and is clamped.
fn sats(v: u64) -> SqlValue {
    SqlValue::Int(i64::try_from(v).unwrap_or(i64::MAX))
}

/// One SQL statement and its parameters (`?1`, `?2`, …).
#[derive(Debug, Clone)]
pub struct Stmt {
    /// The SQL text.
    pub sql: &'static str,
    /// Its parameters, `?1` first.
    pub params: Vec<SqlValue>,
}

impl Stmt {
    fn new(sql: &'static str, params: Vec<SqlValue>) -> Self {
        Self { sql, params }
    }
}

/// The ledger's view of a SQL database (D1 in the worker, SQLite in tests).
// rustc 1.99 clippy flags the `#[must_use]` that `async_trait` itself emits on the
// boxed future (clippy::double_must_use); the expansion is not ours to edit.
#[allow(clippy::double_must_use)]
#[async_trait::async_trait(?Send)]
pub trait LedgerDb {
    /// Run the statements as one transaction (D1 `batch`); return the number
    /// of rows each statement changed.
    async fn batch(&self, stmts: Vec<Stmt>) -> Result<Vec<u64>, String>;
    /// The first row of a query, as a JSON object keyed by column name.
    async fn first(&self, stmt: Stmt) -> Result<Option<Value>, String>;
    /// Every row of a query.
    async fn all(&self, stmt: Stmt) -> Result<Vec<Value>, String>;
}

/// The explorer's view of a transaction (mempool.space / esplora JSON).
// rustc 1.99 clippy flags the `#[must_use]` that `async_trait` itself emits on the
// boxed future (clippy::double_must_use); the expansion is not ours to edit.
#[allow(clippy::double_must_use)]
#[async_trait::async_trait(?Send)]
pub trait TxSource {
    /// `GET {explorer_api}/tx/{txid}` as JSON.
    async fn transaction(&self, explorer_api: &str, txid: &str) -> Result<Value, String>;
}

// ---------------------------------------------------------------------------
// Replies
// ---------------------------------------------------------------------------

/// An HTTP status and JSON body; the worker turns it into a `Response`.
#[derive(Debug, Clone, PartialEq)]
pub struct PayReply {
    /// HTTP status.
    pub status: u16,
    /// JSON body.
    pub body: Value,
}

impl PayReply {
    fn ok(body: Value) -> Self {
        Self { status: 200, body }
    }

    fn err(status: u16, msg: impl Into<String>) -> Self {
        Self {
            status,
            body: json!({ "error": msg.into() }),
        }
    }

    fn store(e: String) -> Self {
        Self::err(500, format!("payment store: {e}"))
    }
}

// ---------------------------------------------------------------------------
// Outpoints and receipt keys
// ---------------------------------------------------------------------------

/// A canonical outpoint: chain id and txid lower-case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outpoint {
    /// Chain id (`btc`, `tbtc4`, `signet`, …).
    pub chain: String,
    /// 64 lower-case hex chars.
    pub txid: String,
    /// Output index.
    pub vout: u32,
}

impl Outpoint {
    fn new(chain: &str, txid: &str, vout: u32) -> Result<Self, String> {
        let chain = chain.trim().to_ascii_lowercase();
        if chain.is_empty()
            || !chain
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(format!("bad chain id: {chain:?}"));
        }
        if txid.len() != 64 || !txid.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("txid must be 64 hex chars".into());
        }
        Ok(Self {
            chain,
            txid: txid.to_ascii_lowercase(),
            vout,
        })
    }

    /// The receipt (replay) key: `txo:<chain>:<txid>:<vout>`.
    pub fn replay_key(&self) -> String {
        format!("txo:{}:{}:{}", self.chain, self.txid, self.vout)
    }

    /// Read a TXO URI as the deposit route takes it (`txid:vout`,
    /// `bitcoin:txid:vout`, `txo:<chain>:txid:vout`; upstream
    /// `parse_txo_uri`), defaulting the chain to [`DEFAULT_CHAIN`].
    pub fn from_txo_uri(uri: &str) -> Result<Self, String> {
        let txo = parse_txo_uri(uri).map_err(|e| e.to_string())?;
        Self::new(
            txo.chain.as_deref().unwrap_or(DEFAULT_CHAIN),
            &txo.txid,
            txo.vout,
        )
    }
}

/// The receipt key of a job's hold release.
fn release_ref(job_id: &str) -> String {
    format!("job:{job_id}:release")
}

// ---------------------------------------------------------------------------
// Ledger operations
// ---------------------------------------------------------------------------

fn u64_field(row: &Value, key: &str) -> u64 {
    row.get(key)
        .and_then(|v| v.as_u64().or_else(|| v.as_f64().map(|f| f as u64)))
        .unwrap_or(0)
}

fn str_field<'v>(row: &'v Value, key: &str) -> &'v str {
    row.get(key).and_then(|v| v.as_str()).unwrap_or("")
}

/// The account's balance (0 for an unknown account).
pub async fn read_balance<D: LedgerDb + ?Sized>(db: &D, did: &str) -> Result<u64, String> {
    let row = db
        .first(Stmt::new(SQL_READ_BALANCE, vec![did.into()]))
        .await?;
    Ok(row.map(|r| u64_field(&r, "balance_sats")).unwrap_or(0))
}

/// The outcome of a debit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Debit {
    /// Debited; the remaining balance.
    Done(u64),
    /// Refused; nothing changed.
    Insufficient {
        /// The balance at refusal.
        balance: u64,
        /// What was asked.
        cost: u64,
    },
}

/// Debit `cost` sats, never overdrawing.
pub async fn debit<D: LedgerDb + ?Sized>(
    db: &D,
    did: &str,
    cost: u64,
    now: i64,
) -> Result<Debit, String> {
    let changed = db
        .batch(vec![Stmt::new(
            SQL_DEBIT,
            vec![sats(cost), now.into(), did.into()],
        )])
        .await?;
    let balance = read_balance(db, did).await?;
    if changed.first().copied().unwrap_or(0) == 0 {
        return Ok(Debit::Insufficient { balance, cost });
    }
    Ok(Debit::Done(balance))
}

/// Has this outpoint been credited (chain-keyed journal, or the legacy
/// chain-less table)?
pub async fn outpoint_credited<D: LedgerDb + ?Sized>(
    db: &D,
    outpoint: &Outpoint,
) -> Result<bool, String> {
    Ok(db
        .first(Stmt::new(
            SQL_CREDIT_EXISTS,
            vec![
                outpoint.replay_key().into(),
                outpoint.txid.as_str().into(),
                i64::from(outpoint.vout).into(),
            ],
        ))
        .await?
        .is_some())
}

/// The two statements that apply a journalled credit: apply, then mark.
fn apply_stmts(credit_ref: &str, now: i64) -> [Stmt; 2] {
    [
        Stmt::new(SQL_APPLY_CREDIT, vec![credit_ref.into(), now.into()]),
        Stmt::new(SQL_MARK_APPLIED, vec![credit_ref.into()]),
    ]
}

/// Credit a verified deposit once, by outpoint (teller `credit`). Returns
/// `false` (and changes nothing) when the outpoint was already credited.
pub async fn credit_deposit<D: LedgerDb + ?Sized>(
    db: &D,
    did: &str,
    outpoint: &Outpoint,
    value: u64,
    request_id: Option<&str>,
    now: i64,
) -> Result<bool, String> {
    let key = outpoint.replay_key();
    let [apply, mark] = apply_stmts(&key, now);
    let changed = db
        .batch(vec![
            Stmt::new(
                SQL_JOURNAL_DEPOSIT,
                vec![
                    key.as_str().into(),
                    did.into(),
                    sats(value),
                    outpoint.chain.as_str().into(),
                    outpoint.txid.as_str().into(),
                    i64::from(outpoint.vout).into(),
                    request_id.into(),
                    now.into(),
                ],
            ),
            apply,
            mark,
        ])
        .await?;
    Ok(changed.get(2).copied().unwrap_or(0) == 1)
}

// ---------------------------------------------------------------------------
// Deposit evidence
// ---------------------------------------------------------------------------

/// The TXO URI in a deposit body: `{"txo": "…"}` or the bare URI as text.
///
/// `amount_sats` is refused outright: a balance is never credited on the
/// caller's say-so.
pub fn deposit_txo_from_body(body: &[u8]) -> Result<String, PayReply> {
    let text =
        std::str::from_utf8(body).map_err(|_| PayReply::err(400, "Deposit body is not UTF-8"))?;
    let text = text.trim();
    if text.is_empty() {
        return Err(PayReply::err(400, "Empty deposit body"));
    }
    if !text.starts_with('{') {
        return Ok(text.to_string());
    }
    let obj: serde_json::Map<String, Value> = serde_json::from_str(text)
        .map_err(|e| PayReply::err(400, format!("Deposit body is not a JSON object: {e}")))?;
    if obj.contains_key("amount_sats") {
        return Err(PayReply::err(
            400,
            "amount_sats is not accepted: a deposit is credited only from a confirmed output \
             paid to your deposit address (GET /pay/.address); send {\"txo\": \"txid:vout\"}",
        ));
    }
    match obj.get("txo") {
        Some(Value::String(t)) if !t.trim().is_empty() => Ok(t.trim().to_string()),
        _ => Err(PayReply::err(
            400,
            "No txo in body: send {\"txo\": \"txid:vout\"}",
        )),
    }
}

/// The configured chain for `id`; `btc` falls back to mainnet when the
/// config lists no chains (the pre-D6 default explorer).
fn resolve_chain(config: &PayConfig, id: &str) -> Result<ChainConfig, PayReply> {
    if let Some(c) = config.chains.iter().find(|c| c.id == id) {
        return Ok(c.clone());
    }
    if id == DEFAULT_CHAIN && config.chains.is_empty() {
        return Ok(ChainConfig::bitcoin_mainnet());
    }
    Err(PayReply::err(400, format!("unsupported chain: {id}")))
}

/// Check the explorer's transaction against the claimed outpoint and the
/// depositor's script; return the output's value.
pub fn qualifying_output(
    tx: &Value,
    outpoint: &Outpoint,
    expected_script: &[u8],
) -> Result<u64, PayReply> {
    if let Some(txid) = tx.get("txid").and_then(|v| v.as_str()) {
        if !txid.eq_ignore_ascii_case(&outpoint.txid) {
            return Err(PayReply::err(502, "explorer returned another transaction"));
        }
    }
    let outputs = tx
        .get("vout")
        .and_then(|v| v.as_array())
        .ok_or_else(|| PayReply::err(502, "explorer returned no vout array"))?;
    let output = outputs
        .get(outpoint.vout as usize)
        .ok_or_else(|| PayReply::err(400, "vout index out of range"))?;
    let script = output
        .get("scriptpubkey")
        .and_then(|v| v.as_str())
        .ok_or_else(|| PayReply::err(502, "explorer returned no scriptpubkey"))?;
    if !script.eq_ignore_ascii_case(&hex::encode(expected_script)) {
        return Err(PayReply::err(
            403,
            "output does not pay your deposit address (GET /pay/.address)",
        ));
    }
    let confirmed = tx
        .get("status")
        .and_then(|s| s.get("confirmed"))
        .and_then(|c| c.as_bool())
        == Some(true);
    if !confirmed {
        return Err(PayReply::err(409, "transaction is not confirmed yet"));
    }
    output
        .get("value")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| PayReply::err(502, "explorer returned no output value"))
}

/// Who is claiming a deposit, and the script their deposit must pay.
#[derive(Debug, Clone, Copy)]
pub struct Depositor<'a> {
    /// `did:nostr:<x>` of the caller.
    pub did: &'a str,
    /// The caller's derived deposit scriptPubKey.
    pub script: &'a [u8],
    /// The NIP-98 signed request's id, recorded beside the outpoint.
    pub request_id: Option<&'a str>,
}

/// `POST /pay/.deposit`: credit a confirmed output paid to the caller's own
/// deposit script, once, by outpoint.
pub async fn deposit<D: LedgerDb + ?Sized, T: TxSource + ?Sized>(
    db: &D,
    txs: &T,
    config: &PayConfig,
    depositor: Depositor<'_>,
    body: &[u8],
    now: i64,
) -> PayReply {
    let Depositor {
        did,
        script: expected_script,
        request_id,
    } = depositor;
    let uri = match deposit_txo_from_body(body) {
        Ok(u) => u,
        Err(r) => return r,
    };
    let outpoint = match Outpoint::from_txo_uri(&uri) {
        Ok(o) => o,
        Err(e) => return PayReply::err(400, format!("invalid TXO: {e}")),
    };
    let chain = match resolve_chain(config, &outpoint.chain) {
        Ok(c) => c,
        Err(r) => return r,
    };
    if chain.unit != LEDGER_UNIT {
        return PayReply::err(
            400,
            format!(
                "chain {} pays in {}, and this ledger credits {LEDGER_UNIT} only",
                chain.id, chain.unit
            ),
        );
    }
    match outpoint_credited(db, &outpoint).await {
        Ok(true) => return PayReply::err(409, "TXO already credited"),
        Ok(false) => {}
        Err(e) => return PayReply::store(e),
    }
    let tx = match txs.transaction(&chain.explorer_api, &outpoint.txid).await {
        Ok(tx) => tx,
        Err(e) => return PayReply::err(502, format!("TXO lookup failed: {e}")),
    };
    let value = match qualifying_output(&tx, &outpoint, expected_script) {
        Ok(v) => v,
        Err(r) => return r,
    };
    match credit_deposit(db, did, &outpoint, value, request_id, now).await {
        Ok(true) => {}
        Ok(false) => return PayReply::err(409, "TXO already credited"),
        Err(e) => return PayReply::store(e),
    }
    let balance = match read_balance(db, did).await {
        Ok(b) => b,
        Err(e) => return PayReply::store(e),
    };
    PayReply::ok(json!({
        "status": "deposited",
        "did": did,
        "credited": value,
        "balance": balance,
        "unit": LEDGER_UNIT,
        "outpoint": outpoint.replay_key(),
    }))
}

// ---------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------

/// The HTTP method, as far as the pay routes care.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayMethod {
    /// GET.
    Get,
    /// POST.
    Post,
    /// Anything else.
    Other,
}

/// The authenticated caller: the NIP-98 signer and the signed request's id.
#[derive(Debug, Clone, Copy)]
pub struct Caller<'a> {
    /// Hex x-only pubkey.
    pub pubkey: &'a str,
    /// The NIP-98 event id (replay-protected, so unique per request).
    pub request_id: &'a str,
}

/// Everything a pay route needs besides the database and the explorer.
pub struct PayContext<'a> {
    /// The pay configuration.
    pub config: &'a PayConfig,
    /// Unix seconds.
    pub now: i64,
    /// The pod's deposit master secret, when configured and needed.
    pub master_secret: Option<&'a [u8; 32]>,
    /// Job expiry, seconds.
    pub job_expiry_secs: i64,
}

/// Does this route need the master secret? (Only these two read it.)
pub fn route_needs_master_secret(pay_path: &str) -> bool {
    matches!(pay_path, ".address" | ".deposit")
}

/// `/pay/.info`: upstream `pay_info`, less the routes this pod does not
/// serve (`.buy`, `.withdraw`, `.pool`).
pub fn info_body(config: &PayConfig) -> Value {
    let mut info = pay_info(config);
    if let Some(token) = info.get_mut("token").and_then(|t| t.as_object_mut()) {
        token.remove("buy");
        token.remove("withdraw");
    }
    if let Some(obj) = info.as_object_mut() {
        obj.remove("pool");
    }
    info
}

/// Serve a `/pay/<pay_path>` request.
#[allow(clippy::too_many_arguments)]
pub async fn dispatch<D: LedgerDb + ?Sized, T: TxSource + ?Sized>(
    db: &D,
    txs: &T,
    ctx: &PayContext<'_>,
    method: PayMethod,
    pay_path: &str,
    caller: Option<Caller<'_>>,
    body: &[u8],
) -> PayReply {
    if matches!(pay_path, ".info" | ".offers") {
        return PayReply::ok(info_body(ctx.config));
    }
    let caller = match caller {
        Some(c) => c,
        None => return PayReply::err(401, "Authentication required"),
    };
    let did = pubkey_to_did(caller.pubkey);
    let rid = caller.request_id;
    match (method, pay_path) {
        (PayMethod::Get, ".address") => address(ctx, caller.pubkey),
        (PayMethod::Get, ".balance") => match read_balance(db, &did).await {
            Ok(b) => PayReply::ok(balance_response(&did, b, ctx.config.cost_sats)),
            Err(e) => PayReply::store(e),
        },
        (PayMethod::Post, ".deposit") => {
            let secret = match ctx.master_secret {
                Some(s) => s,
                None => return PayReply::err(503, "Deposits are not configured on this pod"),
            };
            let script = match derive_deposit_script(secret, caller.pubkey) {
                Ok(s) => s,
                Err(e) => return PayReply::err(400, e),
            };
            deposit(
                db,
                txs,
                ctx.config,
                Depositor {
                    did: &did,
                    script: &script,
                    request_id: Some(rid),
                },
                body,
                ctx.now,
            )
            .await
        }
        (PayMethod::Post, ".buy" | ".withdraw") => token_exchange_gone(pay_path),
        (PayMethod::Post, ".estimate") => estimate(ctx, &did, body),
        (PayMethod::Get, ".jobs") => jobs_list(db, &did).await,
        (PayMethod::Post, ".jobs.create") => job_create(db, ctx, &did, body).await,
        (PayMethod::Post, ".jobs.start") => job_start(db, ctx, &did, body).await,
        (PayMethod::Post, ".jobs.settle") => job_settle(db, ctx, &did, rid, body).await,
        (PayMethod::Post, ".jobs.cancel") => job_cancel(db, ctx, &did, rid, body).await,
        (PayMethod::Post, ".jobs.get") => job_get(db, &did, body).await,
        (PayMethod::Post, ".cleanup") => cleanup(db, ctx, caller).await,
        (PayMethod::Get, resource) => paid_resource(db, ctx, &did, resource).await,
        _ => PayReply::err(405, "Method not allowed on pay route"),
    }
}

fn address(ctx: &PayContext<'_>, pubkey: &str) -> PayReply {
    let secret = match ctx.master_secret {
        Some(s) => s,
        None => return PayReply::err(503, "MASTER_SECRET not configured"),
    };
    match derive_deposit_address(secret, pubkey) {
        Ok(address) => PayReply::ok(json!({ "address": address, "chain": DEFAULT_CHAIN })),
        Err(e) => PayReply::err(400, format!("address derivation failed: {e}")),
    }
}

/// `.buy` and `.withdraw`: there is no token balance in D1 to debit or
/// credit, so neither route can move value honestly. Nothing is read or
/// written.
pub fn token_exchange_gone(pay_path: &str) -> PayReply {
    PayReply::err(
        410,
        format!(
            "{pay_path} is withdrawn: this pod keeps no token balance, so it can neither sell \
             tokens for sats nor redeem them; token state lives on its trail, read-only here"
        ),
    )
}

async fn paid_resource<D: LedgerDb + ?Sized>(
    db: &D,
    ctx: &PayContext<'_>,
    did: &str,
    resource: &str,
) -> PayReply {
    match debit(db, did, ctx.config.cost_sats, ctx.now).await {
        Ok(Debit::Done(remaining)) => PayReply::ok(json!({
            "resource": resource,
            "charged": ctx.config.cost_sats,
            "balance": remaining,
            "unit": LEDGER_UNIT,
        })),
        Ok(Debit::Insufficient { balance, cost }) => PayReply {
            status: 402,
            body: payment_required_body(balance, cost),
        },
        Err(e) => PayReply::store(e),
    }
}

// ---------------------------------------------------------------------------
// Agent jobs
// ---------------------------------------------------------------------------

/// Agent job estimate request body.
#[derive(Debug, Deserialize)]
pub struct EstimateBody {
    /// The endpoint to be called.
    pub endpoint: String,
    // Accepted (mirrors `JobCreateBody::params`, so callers can reuse the
    // same body for `/estimate` and `/create`) but not yet read:
    // `estimate_endpoint_cost` only varies cost by endpoint today.
    #[serde(default)]
    #[allow(dead_code)]
    params: Option<Value>,
}

/// Agent job creation request body.
#[derive(Debug, Deserialize)]
pub struct JobCreateBody {
    /// `did:nostr:<64 hex>` of the agent.
    pub agent_did: String,
    /// The endpoint the job calls.
    pub endpoint: String,
    /// Optional parameters, stored as JSON.
    #[serde(default)]
    pub params: Option<Value>,
}

/// Agent job action request body (start, cancel, get).
#[derive(Debug, Deserialize)]
pub struct JobActionBody {
    /// The job.
    pub job_id: String,
}

/// Agent job settlement request body.
#[derive(Debug, Deserialize)]
pub struct JobSettleBody {
    /// The job.
    pub job_id: String,
    /// What the job actually cost.
    pub actual_sats: u64,
}

fn parse_body<T: for<'de> Deserialize<'de>>(body: &[u8]) -> Result<T, PayReply> {
    serde_json::from_slice(body).map_err(|e| PayReply::err(400, format!("parse: {e}")))
}

/// Per-endpoint cost table for agent job estimation.
pub fn estimate_endpoint_cost(endpoint: &str, base_cost: u64) -> u64 {
    match endpoint {
        e if e.starts_with("/api/inference/") => base_cost * 10,
        e if e.starts_with("/api/image-gen/") => base_cost * 100,
        e if e.starts_with("/api/analytics/") => base_cost * 5,
        _ => base_cost,
    }
}

/// The hold for an estimate: estimate × 1.2, rounded up.
pub fn hold_for(estimated_sats: u64) -> u64 {
    (estimated_sats as f64 * 1.2).ceil() as u64
}

fn estimate(ctx: &PayContext<'_>, did: &str, body: &[u8]) -> PayReply {
    let req: EstimateBody = match parse_body(body) {
        Ok(r) => r,
        Err(r) => return r,
    };
    PayReply::ok(json!({
        "did": did,
        "endpoint": req.endpoint,
        "estimated_sats": estimate_endpoint_cost(&req.endpoint, ctx.config.cost_sats),
        "unit": LEDGER_UNIT,
        "note": "Pre-execution estimate. Final cost may differ for GPU-metered endpoints."
    }))
}

/// `job_<epoch_secs>_<16 hex>` from 8 CSPRNG bytes (no ID enumeration).
fn generate_job_id(now: i64) -> Result<String, String> {
    let mut buf = [0u8; 8];
    getrandom::getrandom(&mut buf).map_err(|e| format!("CSPRNG failure: {e}"))?;
    Ok(format!("job_{now}_{}", hex::encode(buf)))
}

/// ISO 8601 UTC with milliseconds, as JavaScript's `Date#toISOString`
/// writes it (`expires_at` rows are compared as text).
pub fn iso8601_from_epoch(epoch_secs: i64) -> String {
    let days = epoch_secs.div_euclid(86_400);
    let sod = epoch_secs.rem_euclid(86_400);
    // Civil date from days since 1970-01-01 (Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.000Z",
        sod / 3600,
        (sod % 3600) / 60,
        sod % 60
    )
}

async fn jobs_list<D: LedgerDb + ?Sized>(db: &D, did: &str) -> PayReply {
    match db.all(Stmt::new(SQL_JOBS_LIST, vec![did.into()])).await {
        Ok(jobs) => PayReply::ok(json!({ "count": jobs.len(), "jobs": jobs })),
        Err(e) => PayReply::store(e),
    }
}

fn valid_agent_did(agent_did: &str) -> Result<(), PayReply> {
    let pk = agent_did
        .strip_prefix("did:nostr:")
        .ok_or_else(|| PayReply::err(400, "agent_did must start with did:nostr:"))?;
    if pk.len() != 64 || !pk.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(PayReply::err(
            400,
            "agent_did pubkey must be exactly 64 hex characters after did:nostr:",
        ));
    }
    Ok(())
}

/// Create a job: estimate, then insert the job and debit its hold in one
/// transaction (both or neither).
async fn job_create<D: LedgerDb + ?Sized>(
    db: &D,
    ctx: &PayContext<'_>,
    requester_did: &str,
    body: &[u8],
) -> PayReply {
    let req: JobCreateBody = match parse_body(body) {
        Ok(r) => r,
        Err(r) => return r,
    };
    if let Err(r) = valid_agent_did(&req.agent_did) {
        return r;
    }
    let estimated_sats = estimate_endpoint_cost(&req.endpoint, ctx.config.cost_sats);
    if estimated_sats == 0 {
        return PayReply::err(400, "Estimated cost is zero; check endpoint");
    }
    let held_sats = hold_for(estimated_sats);
    let job_id = match generate_job_id(ctx.now) {
        Ok(id) => id,
        Err(e) => return PayReply::err(500, e),
    };
    let expires_at = iso8601_from_epoch(ctx.now + ctx.job_expiry_secs);
    let params_json = req
        .params
        .as_ref()
        .map(|p| serde_json::to_string(p).unwrap_or_default());

    let changed = db
        .batch(vec![
            Stmt::new(
                SQL_JOB_INSERT_IF_FUNDED,
                vec![
                    job_id.as_str().into(),
                    requester_did.into(),
                    req.agent_did.as_str().into(),
                    req.endpoint.as_str().into(),
                    params_json.as_deref().into(),
                    sats(estimated_sats),
                    sats(held_sats),
                    ctx.now.into(),
                    expires_at.as_str().into(),
                ],
            ),
            Stmt::new(
                SQL_JOB_DEBIT_HOLD,
                vec![
                    sats(held_sats),
                    ctx.now.into(),
                    requester_did.into(),
                    job_id.as_str().into(),
                ],
            ),
        ])
        .await;
    match changed {
        Ok(c) if c.first() == Some(&1) && c.get(1) == Some(&1) => {}
        Ok(_) => {
            let balance = read_balance(db, requester_did).await.unwrap_or(0);
            return PayReply {
                status: 402,
                body: json!({
                    "error": "Insufficient balance for job hold",
                    "balance": balance,
                    "required": held_sats,
                    "unit": LEDGER_UNIT,
                }),
            };
        }
        Err(e) => return PayReply::store(e),
    }
    PayReply::ok(json!({
        "job_id": job_id,
        "requester_did": requester_did,
        "agent_did": req.agent_did,
        "endpoint": req.endpoint,
        "status": "held",
        "estimated_sats": estimated_sats,
        "held_sats": held_sats,
        "created_at": ctx.now,
        "expires_at": expires_at,
    }))
}

/// Start a held job (the agent only).
async fn job_start<D: LedgerDb + ?Sized>(
    db: &D,
    ctx: &PayContext<'_>,
    agent_did: &str,
    body: &[u8],
) -> PayReply {
    let req: JobActionBody = match parse_body(body) {
        Ok(r) => r,
        Err(r) => return r,
    };
    let changed = db
        .batch(vec![Stmt::new(
            SQL_JOB_START,
            vec![ctx.now.into(), req.job_id.as_str().into(), agent_did.into()],
        )])
        .await;
    match changed {
        Ok(c) if c.first() == Some(&1) => PayReply::ok(json!({
            "job_id": req.job_id,
            "status": "running",
            "started_at": ctx.now,
        })),
        Ok(_) => PayReply::err(
            404,
            "Job not found, not in 'held' status, or caller is not the agent",
        ),
        Err(e) => PayReply::store(e),
    }
}

/// The transition statement plus the release journal/apply/mark statements,
/// as one batch. Returns (transition changed, release applied).
async fn transition_and_release<D: LedgerDb + ?Sized>(
    db: &D,
    transition: Stmt,
    job_id: &str,
    request_id: &str,
    now: i64,
) -> Result<(bool, bool), String> {
    let rref = release_ref(job_id);
    let [apply, mark] = apply_stmts(&rref, now);
    let changed = db
        .batch(vec![
            transition,
            Stmt::new(
                SQL_JOURNAL_RELEASE,
                vec![
                    job_id.into(),
                    rref.as_str().into(),
                    request_id.into(),
                    now.into(),
                ],
            ),
            apply,
            mark,
        ])
        .await?;
    Ok((
        changed.first().copied().unwrap_or(0) == 1,
        changed.get(3).copied().unwrap_or(0) == 1,
    ))
}

async fn job_row<D: LedgerDb + ?Sized>(db: &D, job_id: &str) -> Result<Option<Value>, String> {
    db.first(Stmt::new(SQL_JOB_GET, vec![job_id.into()])).await
}

/// Settle a running job (the agent only); the unused hold returns to the
/// requester in the same transaction, journalled with this request's id.
async fn job_settle<D: LedgerDb + ?Sized>(
    db: &D,
    ctx: &PayContext<'_>,
    agent_did: &str,
    request_id: &str,
    body: &[u8],
) -> PayReply {
    let req: JobSettleBody = match parse_body(body) {
        Ok(r) => r,
        Err(r) => return r,
    };
    let transition = Stmt::new(
        SQL_JOB_SETTLE,
        vec![
            sats(req.actual_sats),
            ctx.now.into(),
            req.job_id.as_str().into(),
            agent_did.into(),
            release_ref(&req.job_id).into(),
        ],
    );
    let settled =
        match transition_and_release(db, transition, &req.job_id, request_id, ctx.now).await {
            Ok((settled, _)) => settled,
            Err(e) => return PayReply::store(e),
        };
    let job = match job_row(db, &req.job_id).await {
        Ok(j) => j,
        Err(e) => return PayReply::store(e),
    };
    let Some(job) = job else {
        return PayReply::err(404, "Job not found");
    };
    let held = u64_field(&job, "held_sats");
    if !settled {
        let status = str_field(&job, "status");
        return if str_field(&job, "agent_did") != agent_did {
            PayReply::err(403, "Only the agent can settle this job")
        } else if status != "running" {
            PayReply::err(409, format!("Job is '{status}', expected 'running'"))
        } else {
            PayReply::err(
                400,
                format!(
                    "actual_sats ({}) exceeds held_sats ({held})",
                    req.actual_sats
                ),
            )
        };
    }
    PayReply::ok(json!({
        "job_id": req.job_id,
        "status": "settled",
        "actual_sats": req.actual_sats,
        "held_sats": held,
        "refund": held.saturating_sub(req.actual_sats),
        "completed_at": ctx.now,
    }))
}

/// Cancel a held or running job (requester or agent); the whole hold
/// returns to the requester in the same transaction.
async fn job_cancel<D: LedgerDb + ?Sized>(
    db: &D,
    ctx: &PayContext<'_>,
    caller_did: &str,
    request_id: &str,
    body: &[u8],
) -> PayReply {
    let req: JobActionBody = match parse_body(body) {
        Ok(r) => r,
        Err(r) => return r,
    };
    let transition = Stmt::new(
        SQL_JOB_CANCEL,
        vec![
            ctx.now.into(),
            req.job_id.as_str().into(),
            caller_did.into(),
            release_ref(&req.job_id).into(),
        ],
    );
    let cancelled =
        match transition_and_release(db, transition, &req.job_id, request_id, ctx.now).await {
            Ok((cancelled, _)) => cancelled,
            Err(e) => return PayReply::store(e),
        };
    let job = match job_row(db, &req.job_id).await {
        Ok(j) => j,
        Err(e) => return PayReply::store(e),
    };
    let Some(job) = job else {
        return PayReply::err(404, "Job not found");
    };
    if !cancelled {
        return if caller_did != str_field(&job, "requester_did")
            && caller_did != str_field(&job, "agent_did")
        {
            PayReply::err(403, "Only the requester or agent can cancel this job")
        } else {
            PayReply::err(
                409,
                format!(
                    "Cannot cancel job in '{}' status",
                    str_field(&job, "status")
                ),
            )
        };
    }
    PayReply::ok(json!({
        "job_id": req.job_id,
        "status": "failed",
        "error": "cancelled",
        "refund": u64_field(&job, "held_sats"),
        "completed_at": ctx.now,
    }))
}

/// One job, to its requester or agent.
async fn job_get<D: LedgerDb + ?Sized>(db: &D, caller_did: &str, body: &[u8]) -> PayReply {
    let req: JobActionBody = match parse_body(body) {
        Ok(r) => r,
        Err(r) => return r,
    };
    match job_row(db, &req.job_id).await {
        Ok(Some(job)) => {
            if caller_did != str_field(&job, "requester_did")
                && caller_did != str_field(&job, "agent_did")
            {
                PayReply::err(403, "Only the requester or agent can view this job")
            } else {
                PayReply::ok(job)
            }
        }
        Ok(None) => PayReply::err(404, "Job not found"),
        Err(e) => PayReply::store(e),
    }
}

/// Expire jobs stuck in `held`/`running` past `expires_at`, returning each
/// hold once (journalled with the id of the signed request that ran the
/// sweep). Returns how many jobs were expired.
pub async fn recover_orphaned_jobs<D: LedgerDb + ?Sized>(
    db: &D,
    request_id: &str,
    now: i64,
) -> Result<u64, String> {
    let rows = db
        .all(Stmt::new(
            SQL_JOBS_EXPIRED,
            vec![iso8601_from_epoch(now).into()],
        ))
        .await?;
    let mut recovered = 0;
    for row in rows {
        let job_id = str_field(&row, "job_id");
        if job_id.is_empty() {
            continue;
        }
        let transition = Stmt::new(
            SQL_JOB_EXPIRE,
            vec![now.into(), job_id.into(), release_ref(job_id).into()],
        );
        let (expired, _) = transition_and_release(db, transition, job_id, request_id, now).await?;
        if expired {
            recovered += 1;
        }
    }
    Ok(recovered)
}

/// Admin check: `members.is_admin`, then `whitelist.is_admin` (shared SQL
/// from [`nostr_bbs_core::admin_shared`]).
async fn is_admin<D: LedgerDb + ?Sized>(db: &D, pubkey: &str) -> bool {
    let member = db
        .first(Stmt::new(
            nostr_bbs_core::MEMBERS_IS_ADMIN_SQL,
            vec![pubkey.into()],
        ))
        .await;
    if let Ok(Some(row)) = member {
        if u64_field(&row, "is_admin") == 1 {
            return true;
        }
    }
    let listed = db
        .first(Stmt::new(
            nostr_bbs_core::WHITELIST_IS_ADMIN_SQL,
            vec![pubkey.into()],
        ))
        .await;
    matches!(listed, Ok(Some(row)) if u64_field(&row, "is_admin") == 1)
}

/// `POST /pay/.cleanup`: admin-only orphan recovery.
async fn cleanup<D: LedgerDb + ?Sized>(
    db: &D,
    ctx: &PayContext<'_>,
    caller: Caller<'_>,
) -> PayReply {
    if !is_admin(db, caller.pubkey).await {
        return PayReply::err(403, "Admin access required");
    }
    match recover_orphaned_jobs(db, caller.request_id, ctx.now).await {
        Ok(n) => PayReply::ok(json!({ "status": "ok", "recovered_jobs": n })),
        Err(e) => PayReply::store(e),
    }
}

#[cfg(test)]
mod tests;
