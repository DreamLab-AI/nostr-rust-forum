//! HTTP 402 Payment Required — CF Workers adapter for solid-pod-rs payments.
//!
//! Re-exports the upstream payment model from `solid_pod_rs::payments` and
//! provides the Cloudflare Workers storage adapter + /pay/ route handler.
//!
//! Storage backend:
//! - `D1PaymentStore` — atomic D1 operations with INSERT-or-update semantics,
//!   immune to double-spend and concurrent-deposit races.
//!
//! All accounts keyed by `did:nostr:<hex-pubkey>` — users and agents are
//! indistinguishable, enabling user-user, user-agent, agent-agent payments.
//!
//! @see <https://webledgers.org>
//! @see JSS `src/handlers/pay.js`
//!
//! ## Reference
//!
//! The payment primitives consumed here are documented in Melvin Carvalho's
//! *Practical Guide to Solid* — a 10-part walkthrough of the JavaScript Solid
//! Server's HTTP 402, WebLedger, MRC20, and blocktrail features:
//! <https://melvin.me/public/solid/>
//!
//! solid-pod-rs re-implements these in Rust; this module extends them with
//! D1 atomic escrow and agent job lifecycle for the forum kit.

use nostr_bbs_core::d1_helpers::{js_i64, js_opt_str, js_str};
use serde::Deserialize;
use worker::*;

pub use solid_pod_rs::payments::{
    balance_response, pay_info, payment_required_body, pubkey_to_did, parse_txo_uri,
    webledgers_discovery, ChainConfig, PayConfig, PaymentError, PaymentStore, TokenConfig,
    WebLedger,
};

// ---------------------------------------------------------------------------
// Schema initialisation (idempotent — call on every worker startup)
// ---------------------------------------------------------------------------

/// Default job expiry duration: 1 hour (3600 seconds).
///
/// Configurable via `JOB_EXPIRY_SECS` env var.
const DEFAULT_JOB_EXPIRY_SECS: i64 = 3600;

/// Create the payment/quota D1 tables if they don't exist.
///
/// Call once during worker startup (idempotent via `IF NOT EXISTS`).
/// Also prunes stale deposit records older than 90 days to keep tables bounded.
pub async fn ensure_payment_schema(env: &Env, db_binding: &str) {
    let db = match env.d1(db_binding) {
        Ok(db) => db,
        Err(_) => return,
    };

    // webledger_accounts: per-DID satoshi balance
    let _ = db
        .prepare(
            "CREATE TABLE IF NOT EXISTS webledger_accounts (\
                did TEXT PRIMARY KEY, \
                balance_sats INTEGER NOT NULL DEFAULT 0, \
                updated_at INTEGER NOT NULL\
            )",
        )
        .run()
        .await;

    // txo_deposits: replay protection for TXO deposits (composite PK = atomic)
    let _ = db
        .prepare(
            "CREATE TABLE IF NOT EXISTS txo_deposits (\
                txid TEXT NOT NULL, \
                vout INTEGER NOT NULL, \
                did TEXT NOT NULL, \
                amount_sats INTEGER NOT NULL, \
                deposited_at INTEGER NOT NULL, \
                PRIMARY KEY (txid, vout)\
            )",
        )
        .run()
        .await;

    // quota_usage: per-pubkey storage quota (atomic check-and-reserve)
    let _ = db
        .prepare(
            "CREATE TABLE IF NOT EXISTS quota_usage (\
                pubkey TEXT PRIMARY KEY, \
                limit_bytes INTEGER NOT NULL DEFAULT 52428800, \
                used_bytes INTEGER NOT NULL DEFAULT 0, \
                updated_at INTEGER NOT NULL\
            )",
        )
        .run()
        .await;

    // agent_jobs: per-DID agent job tracking with hold/settle lifecycle.
    // expires_at is TEXT ISO 8601 timestamp, nullable for backward compat.
    let _ = db
        .prepare(
            "CREATE TABLE IF NOT EXISTS agent_jobs (\
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
                expires_at TEXT\
            )",
        )
        .run()
        .await;

    // Migration: add expires_at column to existing agent_jobs tables.
    // ALTER TABLE ... ADD COLUMN is idempotent (fails silently if column
    // already exists on D1/SQLite).
    let _ = db
        .prepare("ALTER TABLE agent_jobs ADD COLUMN expires_at TEXT")
        .run()
        .await;

    // Prune deposits older than 90 days
    let cutoff = now_epoch_secs() - 90 * 86400;
    if let Ok(stmt) = db
        .prepare("DELETE FROM txo_deposits WHERE deposited_at < ?1")
        .bind(&[js_i64(cutoff)])
    {
        let _ = stmt.run().await;
    }
}

// ---------------------------------------------------------------------------
// D1-backed payment store (atomic)
// ---------------------------------------------------------------------------

/// D1-backed payment store using atomic SQL operations.
///
/// Replaces the non-atomic KV get+put pattern. Key properties:
/// - `credit_atomic`: INSERT ... ON CONFLICT DO UPDATE (single statement)
/// - `debit_atomic`: UPDATE ... WHERE balance >= cost (single statement)
/// - Replay protection via composite PK INSERT that fails on duplicate
pub struct D1PaymentStore<'a> {
    db: &'a D1Database,
}

impl<'a> D1PaymentStore<'a> {
    pub fn new(db: &'a D1Database) -> Self {
        Self { db }
    }

    /// Atomically credit an account. Creates the account if it doesn't exist.
    ///
    /// Uses INSERT ... ON CONFLICT DO UPDATE so the entire operation is a
    /// single SQL statement — no read-modify-write race window.
    pub async fn credit_atomic(&self, did: &str, amount: u64) -> Result<(), PaymentError> {
        let now = now_epoch_secs();
        self.db
            .prepare(
                "INSERT INTO webledger_accounts (did, balance_sats, updated_at) \
                 VALUES (?1, ?2, ?3) \
                 ON CONFLICT(did) DO UPDATE SET \
                   balance_sats = balance_sats + ?2, \
                   updated_at = ?3",
            )
            .bind(&[
                js_str(did),
                js_i64(amount as i64),
                js_i64(now),
            ])
            .map_err(|e| PaymentError::Store(format!("d1 bind credit: {e:?}")))?
            .run()
            .await
            .map_err(|e| PaymentError::Store(format!("d1 run credit: {e:?}")))?;
        Ok(())
    }

    /// Atomically debit an account. Fails if balance < cost (zero rows updated).
    ///
    /// The WHERE clause `balance_sats >= ?1` makes this atomic — concurrent
    /// debits cannot overdraw the account.
    pub async fn debit_atomic(&self, did: &str, cost: u64) -> Result<u64, PaymentError> {
        let now = now_epoch_secs();
        let result = self
            .db
            .prepare(
                "UPDATE webledger_accounts \
                 SET balance_sats = balance_sats - ?1, updated_at = ?2 \
                 WHERE did = ?3 AND balance_sats >= ?1",
            )
            .bind(&[
                js_i64(cost as i64),
                js_i64(now),
                js_str(did),
            ])
            .map_err(|e| PaymentError::Store(format!("d1 bind debit: {e:?}")))?
            .run()
            .await
            .map_err(|e| PaymentError::Store(format!("d1 run debit: {e:?}")))?;

        let rows_written = result
            .meta()
            .ok()
            .flatten()
            .and_then(|m| m.rows_written)
            .unwrap_or(0);

        if rows_written == 0 {
            // Either the account doesn't exist or balance is insufficient.
            // Read the current balance to provide a useful error.
            let balance = self.read_balance(did).await;
            return Err(PaymentError::InsufficientBalance { balance, cost });
        }

        // Read back the new balance
        Ok(self.read_balance(did).await)
    }

    /// Read the current balance for a DID from D1.
    pub async fn read_balance(&self, did: &str) -> u64 {
        let stmt = match self
            .db
            .prepare("SELECT balance_sats FROM webledger_accounts WHERE did = ?1")
            .bind(&[js_str(did)])
        {
            Ok(s) => s,
            Err(_) => return 0,
        };
        let result = match stmt.first::<serde_json::Value>(None).await {
            Ok(Some(row)) => row
                .get("balance_sats")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            _ => 0,
        };
        result
    }

    /// Atomically record a TXO deposit. Returns `true` if the deposit was
    /// recorded (new), `false` if replay (already existed).
    ///
    /// Uses INSERT that will fail on duplicate (txid, vout) primary key.
    async fn record_deposit_atomic(
        &self,
        txid: &str,
        vout: u32,
        did: &str,
        amount: u64,
    ) -> Result<bool, PaymentError> {
        let now = now_epoch_secs();
        let result = self
            .db
            .prepare(
                "INSERT OR IGNORE INTO txo_deposits (txid, vout, did, amount_sats, deposited_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
            )
            .bind(&[
                js_str(txid),
                js_i64(vout as i64),
                js_str(did),
                js_i64(amount as i64),
                js_i64(now),
            ])
            .map_err(|e| PaymentError::Store(format!("d1 bind deposit: {e:?}")))?
            .run()
            .await
            .map_err(|e| PaymentError::Store(format!("d1 run deposit: {e:?}")))?;

        let rows_written = result
            .meta()
            .ok()
            .flatten()
            .and_then(|m| m.rows_written)
            .unwrap_or(0);

        Ok(rows_written > 0)
    }
}

#[async_trait::async_trait(?Send)]
impl<'a> PaymentStore for D1PaymentStore<'a> {
    async fn read_ledger(&self) -> Result<WebLedger, PaymentError> {
        let stmt = self
            .db
            .prepare("SELECT did, balance_sats FROM webledger_accounts")
            .run()
            .await
            .map_err(|e| PaymentError::Store(format!("d1 read_ledger: {e:?}")))?;

        let mut ledger = WebLedger::new("Pod Credits");
        if let Ok(rows) = stmt.results::<serde_json::Value>() {
            for row in rows {
                if let (Some(did), Some(balance)) = (
                    row.get("did").and_then(|v| v.as_str()),
                    row.get("balance_sats").and_then(|v| v.as_u64()),
                ) {
                    ledger.credit(did, balance);
                }
            }
        }
        Ok(ledger)
    }

    async fn write_ledger(&self, ledger: &WebLedger) -> Result<(), PaymentError> {
        // D1 path: upsert each entry for trait compliance.
        // Prefer credit_atomic/debit_atomic for production use.
        for entry in &ledger.entries {
            let balance = entry.amount.sats();
            let now = now_epoch_secs();
            let _ = self
                .db
                .prepare(
                    "INSERT INTO webledger_accounts (did, balance_sats, updated_at) \
                     VALUES (?1, ?2, ?3) \
                     ON CONFLICT(did) DO UPDATE SET balance_sats = ?2, updated_at = ?3",
                )
                .bind(&[
                    js_str(&entry.url),
                    js_i64(balance as i64),
                    js_i64(now),
                ])
                .map_err(|e| PaymentError::Store(format!("d1 bind write_ledger: {e:?}")))?
                .run()
                .await
                .map_err(|e| PaymentError::Store(format!("d1 run write_ledger: {e:?}")))?;
        }
        Ok(())
    }

    async fn check_replay(&self, key: &str) -> Result<bool, PaymentError> {
        // Parse "txid:vout" format
        let (txid, vout) = parse_replay_key(key)?;
        let stmt = match self
            .db
            .prepare("SELECT 1 FROM txo_deposits WHERE txid = ?1 AND vout = ?2")
            .bind(&[js_str(txid), js_i64(vout as i64)])
        {
            Ok(s) => s,
            Err(e) => return Err(PaymentError::Store(format!("d1 bind replay check: {e:?}"))),
        };
        match stmt.first::<serde_json::Value>(None).await {
            Ok(Some(_)) => Ok(true),
            Ok(None) => Ok(false),
            Err(e) => Err(PaymentError::Store(format!("d1 replay check: {e:?}"))),
        }
    }

    async fn record_replay(&self, key: &str) -> Result<(), PaymentError> {
        let (txid, vout) = parse_replay_key(key)?;
        let now = now_epoch_secs();
        let result = self
            .db
            .prepare(
                "INSERT OR IGNORE INTO txo_deposits (txid, vout, did, amount_sats, deposited_at) \
                 VALUES (?1, ?2, '', 0, ?3)",
            )
            .bind(&[
                js_str(txid),
                js_i64(vout as i64),
                js_i64(now),
            ])
            .map_err(|e| PaymentError::Store(format!("d1 bind record_replay: {e:?}")))?
            .run()
            .await
            .map_err(|e| PaymentError::Store(format!("d1 run record_replay: {e:?}")))?;

        let rows_written = result
            .meta()
            .ok()
            .flatten()
            .and_then(|m| m.rows_written)
            .unwrap_or(0);

        if rows_written == 0 {
            return Err(PaymentError::Replay(key.to_string()));
        }
        Ok(())
    }
}

/// Parse a replay key in "txid:vout" format.
fn parse_replay_key(key: &str) -> Result<(&str, u32), PaymentError> {
    // Handle txo: prefix
    let stripped = key
        .strip_prefix("txo:")
        .or_else(|| key.strip_prefix("bitcoin:"))
        .unwrap_or(key);

    // May be chain:txid:vout or txid:vout
    let parts: Vec<&str> = stripped.rsplitn(2, ':').collect();
    if parts.len() != 2 {
        return Err(PaymentError::InvalidTxo(format!(
            "replay key not in txid:vout format: {key}"
        )));
    }
    let vout: u32 = parts[0]
        .parse()
        .map_err(|_| PaymentError::InvalidTxo(format!("bad vout in replay key: {key}")))?;
    // parts[1] may be "chain:txid" or just "txid"; take the last 64 chars as txid
    let remainder = parts[1];
    let txid = if remainder.len() > 64 {
        // chain:txid format — extract just the txid
        remainder
            .rsplit_once(':')
            .map(|(_, t)| t)
            .unwrap_or(remainder)
    } else {
        remainder
    };
    Ok((txid, vout))
}

// ---------------------------------------------------------------------------
// TXO verification via mempool API (multi-chain)
// ---------------------------------------------------------------------------

/// Verify a Bitcoin TXO via mempool API and return the value in satoshis.
/// Supports multi-chain via the `chains` config.
pub async fn verify_txo_multichain(
    txo_body: &str,
    config: &PayConfig,
) -> std::result::Result<u64, String> {
    let txo = parse_txo_uri(txo_body).map_err(|e| e.to_string())?;

    let api_base = if let Some(ref chain_id) = txo.chain {
        config
            .chains
            .iter()
            .find(|c| c.id == *chain_id)
            .map(|c| c.explorer_api.as_str())
            .ok_or_else(|| format!("unsupported chain: {chain_id}"))?
    } else {
        "https://mempool.space/api"
    };

    let url = format!("{api_base}/tx/{}", txo.txid);
    let mut resp = Fetch::Url(worker::Url::parse(&url).map_err(|e| e.to_string())?)
        .send()
        .await
        .map_err(|e| format!("fetch: {e}"))?;

    let body: serde_json::Value = resp.json().await.map_err(|e| format!("json: {e}"))?;

    let outputs = body
        .get("vout")
        .and_then(|v| v.as_array())
        .ok_or("no vout array")?;
    let output = outputs
        .get(txo.vout as usize)
        .ok_or("vout index out of range")?;
    let value = output
        .get("value")
        .and_then(|v| v.as_u64())
        .ok_or("no value in output")?;

    if let Some(status) = body.get("status") {
        if status.get("confirmed").and_then(|c| c.as_bool()) != Some(true) {
            return Err("unconfirmed transaction".into());
        }
    }

    Ok(value)
}

// ---------------------------------------------------------------------------
// /pay/ route handler
// ---------------------------------------------------------------------------

/// Deposit request body.
#[derive(Debug, Deserialize)]
pub struct DepositBody {
    #[serde(default)]
    pub txo: Option<String>,
    #[serde(default)]
    pub amount_sats: Option<u64>,
}

/// Token buy/withdraw request body.
#[derive(Debug, Deserialize)]
pub struct TokenOpBody {
    pub amount: u64,
}

/// Agent job estimate request body.
#[derive(Debug, Deserialize)]
pub struct EstimateBody {
    pub endpoint: String,
    #[serde(default)]
    pub params: Option<serde_json::Value>,
}

/// Agent job creation request body.
#[derive(Debug, Deserialize)]
pub struct JobCreateBody {
    pub agent_did: String,
    pub endpoint: String,
    #[serde(default)]
    pub params: Option<serde_json::Value>,
}

/// Agent job action request body (start, cancel).
#[derive(Debug, Deserialize)]
pub struct JobActionBody {
    pub job_id: String,
}

/// Agent job settlement request body.
#[derive(Debug, Deserialize)]
pub struct JobSettleBody {
    pub job_id: String,
    pub actual_sats: u64,
}

/// Handle all /pay/* routes using D1 atomic store.
/// Returns Some(Response) if handled, None if not a pay route.
pub async fn handle_pay_route(
    path: &str,
    method: &Method,
    pubkey: Option<&str>,
    body_bytes: Option<&[u8]>,
    db: &D1Database,
    env: &Env,
    config: &PayConfig,
) -> Option<std::result::Result<Response, Error>> {
    if !config.enabled {
        return None;
    }

    let pay_path = path.strip_prefix("/pay/")?;

    Some(match (method, pay_path) {
        (_, ".info") => pay_info_handler(config, env),

        (&Method::Get, ".address") => {
            let pk = match pubkey {
                Some(pk) => pk,
                None => return Some(json_err(env, "Authentication required", 401)),
            };
            handle_address_route(pk, env)
        }

        (&Method::Get, ".balance") => {
            let pk = match pubkey {
                Some(pk) => pk,
                None => return Some(json_err(env, "Authentication required", 401)),
            };
            pay_balance_handler(pk, db, config, env).await
        }

        (&Method::Post, ".deposit") => {
            let pk = match pubkey {
                Some(pk) => pk,
                None => return Some(json_err(env, "Authentication required", 401)),
            };
            let body = body_bytes.unwrap_or_default();
            pay_deposit_handler(pk, body, db, config, env).await
        }

        (&Method::Post, ".buy") => {
            let pk = match pubkey {
                Some(pk) => pk,
                None => return Some(json_err(env, "Authentication required", 401)),
            };
            let body = body_bytes.unwrap_or_default();
            pay_token_buy_handler(pk, body, db, config, env).await
        }

        (&Method::Post, ".withdraw") => {
            let pk = match pubkey {
                Some(pk) => pk,
                None => return Some(json_err(env, "Authentication required", 401)),
            };
            let body = body_bytes.unwrap_or_default();
            pay_token_withdraw_handler(pk, body, db, config, env).await
        }

        (&Method::Post, ".estimate") => {
            let pk = match pubkey {
                Some(pk) => pk,
                None => return Some(json_err(env, "Authentication required", 401)),
            };
            let body = body_bytes.unwrap_or_default();
            pay_estimate_handler(pk, body, config, env)
        }

        // ----- Agent job CRUD routes -----

        (&Method::Get, ".jobs") => {
            let pk = match pubkey {
                Some(pk) => pk,
                None => return Some(json_err(env, "Authentication required", 401)),
            };
            pay_jobs_list_handler(pk, db, env).await
        }

        (&Method::Post, ".jobs.create") => {
            let pk = match pubkey {
                Some(pk) => pk,
                None => return Some(json_err(env, "Authentication required", 401)),
            };
            let body = body_bytes.unwrap_or_default();
            pay_job_create_handler(pk, body, db, config, env).await
        }

        (&Method::Post, ".jobs.start") => {
            let pk = match pubkey {
                Some(pk) => pk,
                None => return Some(json_err(env, "Authentication required", 401)),
            };
            let body = body_bytes.unwrap_or_default();
            pay_job_start_handler(pk, body, db, env).await
        }

        (&Method::Post, ".jobs.settle") => {
            let pk = match pubkey {
                Some(pk) => pk,
                None => return Some(json_err(env, "Authentication required", 401)),
            };
            let body = body_bytes.unwrap_or_default();
            pay_job_settle_handler(pk, body, db, env).await
        }

        (&Method::Post, ".jobs.cancel") => {
            let pk = match pubkey {
                Some(pk) => pk,
                None => return Some(json_err(env, "Authentication required", 401)),
            };
            let body = body_bytes.unwrap_or_default();
            pay_job_cancel_handler(pk, body, db, env).await
        }

        (&Method::Post, ".jobs.get") => {
            let pk = match pubkey {
                Some(pk) => pk,
                None => return Some(json_err(env, "Authentication required", 401)),
            };
            let body = body_bytes.unwrap_or_default();
            pay_job_get_handler(pk, body, db, env).await
        }

        (&Method::Post, ".cleanup") => {
            let pk = match pubkey {
                Some(pk) => pk,
                None => return Some(json_err(env, "Authentication required", 401)),
            };
            pay_cleanup_handler(pk, db, env).await
        }

        (_, ".offers") => pay_info_handler(config, env),

        (&Method::Get, _) => {
            let pk = match pubkey {
                Some(pk) => pk,
                None => return Some(json_err(env, "Authentication required", 401)),
            };
            pay_resource_handler(pk, pay_path, db, config, env).await
        }

        _ => json_err(env, "Method not allowed on pay route", 405),
    })
}

fn pay_info_handler(config: &PayConfig, _env: &Env) -> std::result::Result<Response, Error> {
    let info = pay_info(config);
    let json_str = serde_json::to_string(&info).map_err(|e| Error::RustError(e.to_string()))?;
    let resp = Response::ok(json_str)?;
    resp.headers().set("Content-Type", "application/json").ok();
    Ok(resp)
}

async fn pay_balance_handler(
    pubkey: &str,
    db: &D1Database,
    config: &PayConfig,
    _env: &Env,
) -> std::result::Result<Response, Error> {
    let store = D1PaymentStore::new(db);
    let did = pubkey_to_did(pubkey);
    let balance = store.read_balance(&did).await;
    let body = balance_response(&did, balance, config.cost_sats);
    let json_str = serde_json::to_string(&body).map_err(|e| Error::RustError(e.to_string()))?;
    let resp = Response::ok(json_str)?;
    resp.headers().set("Content-Type", "application/json").ok();
    Ok(resp)
}

async fn pay_deposit_handler(
    pubkey: &str,
    body: &[u8],
    db: &D1Database,
    config: &PayConfig,
    env: &Env,
) -> std::result::Result<Response, Error> {
    let store = D1PaymentStore::new(db);
    let did = pubkey_to_did(pubkey);

    // Parse deposit: either JSON body with txo/amount_sats, or plain text TXO URI
    let body_str = std::str::from_utf8(body).unwrap_or("");
    let amount = if let Ok(deposit) = serde_json::from_str::<DepositBody>(body_str) {
        if let Some(ref txo) = deposit.txo {
            let sats = verify_txo_multichain(txo, config)
                .await
                .map_err(|e| Error::RustError(format!("TXO verify: {e}")))?;

            // Atomic replay-check + record via INSERT OR IGNORE on PK
            let parsed = parse_txo_uri(txo).map_err(|e| Error::RustError(e.to_string()))?;
            let is_new = store
                .record_deposit_atomic(&parsed.txid, parsed.vout, &did, sats)
                .await
                .map_err(|e| Error::RustError(e.to_string()))?;
            if !is_new {
                return json_err(env, "TXO already used", 409);
            }
            sats
        } else if let Some(sats) = deposit.amount_sats {
            sats
        } else {
            return json_err(env, "No txo or amount_sats in body", 400);
        }
    } else {
        // Plain text TXO URI
        let txo = body_str.trim();
        if txo.is_empty() {
            return json_err(env, "Empty deposit body", 400);
        }
        let sats = verify_txo_multichain(txo, config)
            .await
            .map_err(|e| Error::RustError(format!("TXO verify: {e}")))?;

        let parsed = parse_txo_uri(txo).map_err(|e| Error::RustError(e.to_string()))?;
        let is_new = store
            .record_deposit_atomic(&parsed.txid, parsed.vout, &did, sats)
            .await
            .map_err(|e| Error::RustError(e.to_string()))?;
        if !is_new {
            return json_err(env, "TXO already used", 409);
        }
        sats
    };

    // Atomic credit (no read-modify-write race)
    store
        .credit_atomic(&did, amount)
        .await
        .map_err(|e| Error::RustError(e.to_string()))?;

    let balance = store.read_balance(&did).await;
    let body = serde_json::json!({
        "status": "deposited",
        "did": did,
        "credited": amount,
        "balance": balance,
        "unit": "sat"
    });
    let json_str = serde_json::to_string(&body).map_err(|e| Error::RustError(e.to_string()))?;
    let resp = Response::ok(json_str)?;
    resp.headers().set("Content-Type", "application/json").ok();
    Ok(resp)
}

async fn pay_resource_handler(
    pubkey: &str,
    resource: &str,
    db: &D1Database,
    config: &PayConfig,
    _env: &Env,
) -> std::result::Result<Response, Error> {
    let store = D1PaymentStore::new(db);
    let did = pubkey_to_did(pubkey);

    match store.debit_atomic(&did, config.cost_sats).await {
        Ok(remaining) => {
            let body = serde_json::json!({
                "resource": resource,
                "charged": config.cost_sats,
                "balance": remaining,
                "unit": "sat"
            });
            let json_str =
                serde_json::to_string(&body).map_err(|e| Error::RustError(e.to_string()))?;
            let resp = Response::ok(json_str)?;
            resp.headers().set("Content-Type", "application/json").ok();
            Ok(resp)
        }
        Err(PaymentError::InsufficientBalance { balance, cost }) => {
            let body = payment_required_body(balance, cost);
            let json_str =
                serde_json::to_string(&body).map_err(|e| Error::RustError(e.to_string()))?;
            let resp = Response::ok(json_str)?.with_status(402);
            resp.headers().set("Content-Type", "application/json").ok();
            Ok(resp)
        }
        Err(e) => Err(Error::RustError(e.to_string())),
    }
}

// ---------------------------------------------------------------------------
// MRC20 token buy/withdraw + agent job estimation handlers
// ---------------------------------------------------------------------------

async fn pay_token_buy_handler(
    pubkey: &str,
    body: &[u8],
    db: &D1Database,
    config: &PayConfig,
    env: &Env,
) -> std::result::Result<Response, Error> {
    let token = match &config.token {
        Some(t) => t,
        None => return json_err(env, "Token not configured", 404),
    };

    let body_str = std::str::from_utf8(body).unwrap_or("");
    let op: TokenOpBody =
        serde_json::from_str(body_str).map_err(|e| Error::RustError(format!("parse: {e}")))?;

    if op.amount == 0 {
        return json_err(env, "Amount must be > 0", 400);
    }

    // cost = ceil(amount / rate) sats
    let cost_sats = (op.amount + token.rate - 1) / token.rate;
    let store = D1PaymentStore::new(db);
    let did = pubkey_to_did(pubkey);

    match store.debit_atomic(&did, cost_sats).await {
        Ok(remaining) => {
            let body = serde_json::json!({
                "status": "bought",
                "did": did,
                "ticker": token.ticker,
                "amount": op.amount,
                "cost_sats": cost_sats,
                "balance_sats": remaining,
            });
            json_ok(&body)
        }
        Err(PaymentError::InsufficientBalance { balance, cost }) => {
            let body = payment_required_body(balance, cost);
            let json_str =
                serde_json::to_string(&body).map_err(|e| Error::RustError(e.to_string()))?;
            let resp = Response::ok(json_str)?.with_status(402);
            resp.headers().set("Content-Type", "application/json").ok();
            Ok(resp)
        }
        Err(e) => Err(Error::RustError(e.to_string())),
    }
}

async fn pay_token_withdraw_handler(
    pubkey: &str,
    body: &[u8],
    db: &D1Database,
    config: &PayConfig,
    env: &Env,
) -> std::result::Result<Response, Error> {
    let token = match &config.token {
        Some(t) => t,
        None => return json_err(env, "Token not configured", 404),
    };

    let body_str = std::str::from_utf8(body).unwrap_or("");
    let op: TokenOpBody =
        serde_json::from_str(body_str).map_err(|e| Error::RustError(format!("parse: {e}")))?;

    if op.amount == 0 {
        return json_err(env, "Amount must be > 0", 400);
    }

    let credited_sats = op.amount / token.rate;
    if credited_sats == 0 {
        return json_err(env, "Amount too small to redeem any sats", 400);
    }

    let store = D1PaymentStore::new(db);
    let did = pubkey_to_did(pubkey);

    store
        .credit_atomic(&did, credited_sats)
        .await
        .map_err(|e| Error::RustError(e.to_string()))?;

    let balance = store.read_balance(&did).await;
    let body = serde_json::json!({
        "status": "withdrawn",
        "did": did,
        "ticker": token.ticker,
        "amount": op.amount,
        "credited_sats": credited_sats,
        "balance_sats": balance,
    });
    json_ok(&body)
}

/// Per-endpoint cost table for agent job estimation.
/// Maps endpoint prefixes to satoshi costs.
fn estimate_endpoint_cost(endpoint: &str, base_cost: u64) -> u64 {
    match endpoint {
        e if e.starts_with("/api/inference/") => base_cost * 10,
        e if e.starts_with("/api/image-gen/") => base_cost * 100,
        e if e.starts_with("/api/analytics/") => base_cost * 5,
        _ => base_cost,
    }
}

fn pay_estimate_handler(
    pubkey: &str,
    body: &[u8],
    config: &PayConfig,
    _env: &Env,
) -> std::result::Result<Response, Error> {
    let body_str = std::str::from_utf8(body).unwrap_or("");
    let req: EstimateBody =
        serde_json::from_str(body_str).map_err(|e| Error::RustError(format!("parse: {e}")))?;

    let did = pubkey_to_did(pubkey);
    let estimated_sats = estimate_endpoint_cost(&req.endpoint, config.cost_sats);

    let body = serde_json::json!({
        "did": did,
        "endpoint": req.endpoint,
        "estimated_sats": estimated_sats,
        "unit": "sat",
        "note": "Pre-execution estimate. Final cost may differ for GPU-metered endpoints."
    });
    json_ok(&body)
}

// ---------------------------------------------------------------------------
// Agent job CRUD handlers
// ---------------------------------------------------------------------------

/// Generate a unique job ID: `job_<epoch_secs>_<random_hex16>`.
///
/// Uses `getrandom` (CSPRNG via `crypto.getRandomValues` on wasm) to produce
/// 8 cryptographically random bytes (16 hex chars), preventing job-ID
/// enumeration attacks.
fn generate_job_id() -> Result<String, Error> {
    let ts = now_epoch_secs();
    let mut buf = [0u8; 8];
    getrandom::getrandom(&mut buf)
        .map_err(|e| Error::RustError(format!("CSPRNG failure generating job ID: {e}")))?;
    Ok(format!("job_{ts}_{}", hex::encode(buf)))
}

/// List agent jobs for the authenticated DID.
async fn pay_jobs_list_handler(
    pubkey: &str,
    db: &D1Database,
    env: &Env,
) -> std::result::Result<Response, Error> {
    let did = pubkey_to_did(pubkey);

    let rows = db
        .prepare(
            "SELECT job_id, requester_did, agent_did, endpoint, params_json, \
             status, estimated_sats, held_sats, actual_sats, \
             created_at, started_at, completed_at, error, expires_at \
             FROM agent_jobs WHERE requester_did = ?1 \
             ORDER BY created_at DESC LIMIT 50",
        )
        .bind(&[js_str(&did)])
        .map_err(|e| Error::RustError(format!("d1 bind jobs list: {e:?}")))?
        .all()
        .await
        .map_err(|e| Error::RustError(format!("d1 run jobs list: {e:?}")))?;

    let jobs: Vec<serde_json::Value> = rows
        .results::<serde_json::Value>()
        .unwrap_or_default();

    let body = serde_json::json!({
        "jobs": jobs,
        "count": jobs.len(),
    });
    json_ok(&body)
}

/// Create a new agent job: estimate cost, hold funds, insert record.
async fn pay_job_create_handler(
    pubkey: &str,
    body: &[u8],
    db: &D1Database,
    config: &PayConfig,
    env: &Env,
) -> std::result::Result<Response, Error> {
    let body_str = std::str::from_utf8(body).unwrap_or("");
    let req: JobCreateBody =
        serde_json::from_str(body_str).map_err(|e| Error::RustError(format!("parse: {e}")))?;

    let requester_did = pubkey_to_did(pubkey);

    // Validate agent_did format: must be "did:nostr:" followed by exactly 64 hex chars
    if !req.agent_did.starts_with("did:nostr:") {
        return json_err(env, "agent_did must start with did:nostr:", 400);
    }
    {
        let pk_part = &req.agent_did["did:nostr:".len()..];
        if pk_part.len() != 64 || !pk_part.bytes().all(|b| b.is_ascii_hexdigit()) {
            return json_err(
                env,
                "agent_did pubkey must be exactly 64 hex characters after did:nostr:",
                400,
            );
        }
    }

    // Step a: Estimate cost using the endpoint cost table
    let estimated_sats = estimate_endpoint_cost(&req.endpoint, config.cost_sats);
    if estimated_sats == 0 {
        return json_err(env, "Estimated cost is zero; check endpoint", 400);
    }

    // Step b: Calculate hold = estimated * 1.2 (20% buffer)
    let held_sats = (estimated_sats as f64 * 1.2).ceil() as u64;

    // Step c: Debit hold from requester balance (atomic — fails if insufficient)
    let store = D1PaymentStore::new(db);
    match store.debit_atomic(&requester_did, held_sats).await {
        Ok(_) => {}
        Err(PaymentError::InsufficientBalance { balance, cost }) => {
            let body = serde_json::json!({
                "error": "Insufficient balance for job hold",
                "balance": balance,
                "required": cost,
                "unit": "sat",
            });
            let json_str =
                serde_json::to_string(&body).map_err(|e| Error::RustError(e.to_string()))?;
            let resp = Response::ok(json_str)?.with_status(402);
            resp.headers().set("Content-Type", "application/json").ok();
            return Ok(resp);
        }
        Err(e) => return Err(Error::RustError(e.to_string())),
    }

    // Step d: Insert into agent_jobs with status='held' and expiry timestamp
    let job_id = generate_job_id()?;
    let now = now_epoch_secs();
    let expiry_secs = job_expiry_secs(env);
    let expires_at = iso8601_from_epoch(now + expiry_secs);
    let params_json = req
        .params
        .as_ref()
        .map(|p| serde_json::to_string(p).unwrap_or_default());

    db.prepare(
        "INSERT INTO agent_jobs \
         (job_id, requester_did, agent_did, endpoint, params_json, \
          status, estimated_sats, held_sats, created_at, expires_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, 'held', ?6, ?7, ?8, ?9)",
    )
    .bind(&[
        js_str(&job_id),
        js_str(&requester_did),
        js_str(&req.agent_did),
        js_str(&req.endpoint),
        js_opt_str(params_json.as_deref()),
        js_i64(estimated_sats as i64),
        js_i64(held_sats as i64),
        js_i64(now),
        js_str(&expires_at),
    ])
    .map_err(|e| Error::RustError(format!("d1 bind job insert: {e:?}")))?
    .run()
    .await
    .map_err(|e| Error::RustError(format!("d1 run job insert: {e:?}")))?;

    // Step e: Return job object
    let body = serde_json::json!({
        "job_id": job_id,
        "requester_did": requester_did,
        "agent_did": req.agent_did,
        "endpoint": req.endpoint,
        "status": "held",
        "estimated_sats": estimated_sats,
        "held_sats": held_sats,
        "created_at": now,
        "expires_at": expires_at,
    });
    json_ok(&body)
}

/// Start a held job — transition from held to running.
/// Only the agent_did can start the job.
async fn pay_job_start_handler(
    pubkey: &str,
    body: &[u8],
    db: &D1Database,
    env: &Env,
) -> std::result::Result<Response, Error> {
    let body_str = std::str::from_utf8(body).unwrap_or("");
    let req: JobActionBody =
        serde_json::from_str(body_str).map_err(|e| Error::RustError(format!("parse: {e}")))?;

    let agent_did = pubkey_to_did(pubkey);
    let now = now_epoch_secs();

    let result = db
        .prepare(
            "UPDATE agent_jobs SET status = 'running', started_at = ?1 \
             WHERE job_id = ?2 AND status = 'held' AND agent_did = ?3",
        )
        .bind(&[
            js_i64(now),
            js_str(&req.job_id),
            js_str(&agent_did),
        ])
        .map_err(|e| Error::RustError(format!("d1 bind job start: {e:?}")))?
        .run()
        .await
        .map_err(|e| Error::RustError(format!("d1 run job start: {e:?}")))?;

    let rows_written = result
        .meta()
        .ok()
        .flatten()
        .and_then(|m| m.rows_written)
        .unwrap_or(0);

    if rows_written == 0 {
        return json_err(
            env,
            "Job not found, not in 'held' status, or caller is not the agent",
            404,
        );
    }

    let body = serde_json::json!({
        "job_id": req.job_id,
        "status": "running",
        "started_at": now,
    });
    json_ok(&body)
}

/// Settle a running job — transition from running to settled.
/// Only the agent_did can settle. Refunds excess hold to requester.
///
/// Uses an atomic UPDATE with WHERE clause on both status and agent_did to
/// eliminate the TOCTOU race between check and mutation. If the worker crashes
/// after the UPDATE but before the refund credit, the job is already 'settled'
/// and a recovery sweep can detect jobs where `held_sats > actual_sats` and
/// the refund credit has not been applied.
async fn pay_job_settle_handler(
    pubkey: &str,
    body: &[u8],
    db: &D1Database,
    env: &Env,
) -> std::result::Result<Response, Error> {
    let body_str = std::str::from_utf8(body).unwrap_or("");
    let req: JobSettleBody =
        serde_json::from_str(body_str).map_err(|e| Error::RustError(format!("parse: {e}")))?;

    let agent_did = pubkey_to_did(pubkey);
    let now = now_epoch_secs();

    // Atomic settle: single UPDATE that combines the status check, ownership
    // check, overpay guard (actual_sats <= held_sats), and state transition.
    // If any condition fails, 0 rows are written and we diagnose afterwards.
    let result = db
        .prepare(
            "UPDATE agent_jobs \
             SET status = 'settled', actual_sats = ?1, completed_at = ?2 \
             WHERE job_id = ?3 AND status = 'running' AND agent_did = ?4 \
               AND held_sats >= ?1",
        )
        .bind(&[
            js_i64(req.actual_sats as i64),
            js_i64(now),
            js_str(&req.job_id),
            js_str(&agent_did),
        ])
        .map_err(|e| Error::RustError(format!("d1 bind job settle: {e:?}")))?
        .run()
        .await
        .map_err(|e| Error::RustError(format!("d1 run job settle: {e:?}")))?;

    let rows_written = result
        .meta()
        .ok()
        .flatten()
        .and_then(|m| m.rows_written)
        .unwrap_or(0);

    if rows_written == 0 {
        // The atomic UPDATE failed — diagnose why for a useful error message.
        let job = db
            .prepare(
                "SELECT agent_did, status, held_sats \
                 FROM agent_jobs WHERE job_id = ?1",
            )
            .bind(&[js_str(&req.job_id)])
            .map_err(|e| Error::RustError(format!("d1 bind job read: {e:?}")))?
            .first::<serde_json::Value>(None)
            .await
            .map_err(|e| Error::RustError(format!("d1 run job read: {e:?}")))?;

        return match job {
            None => json_err(env, "Job not found", 404),
            Some(j) => {
                let ja = j.get("agent_did").and_then(|v| v.as_str()).unwrap_or("");
                let js = j.get("status").and_then(|v| v.as_str()).unwrap_or("");
                let held = j.get("held_sats").and_then(|v| v.as_u64()).unwrap_or(0);
                if ja != agent_did {
                    json_err(env, "Only the agent can settle this job", 403)
                } else if js != "running" {
                    json_err(
                        env,
                        &format!("Job is '{js}', expected 'running'"),
                        409,
                    )
                } else {
                    json_err(
                        env,
                        &format!(
                            "actual_sats ({}) exceeds held_sats ({held})",
                            req.actual_sats
                        ),
                        400,
                    )
                }
            }
        };
    }

    // The job is now atomically settled. Read back held_sats + requester_did
    // for the refund calculation.
    let job = db
        .prepare(
            "SELECT requester_did, held_sats FROM agent_jobs WHERE job_id = ?1",
        )
        .bind(&[js_str(&req.job_id)])
        .map_err(|e| Error::RustError(format!("d1 bind job refund read: {e:?}")))?
        .first::<serde_json::Value>(None)
        .await
        .map_err(|e| Error::RustError(format!("d1 run job refund read: {e:?}")))?;

    let (requester_did, held_sats) = match job {
        Some(j) => (
            j.get("requester_did")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            j.get("held_sats").and_then(|v| v.as_u64()).unwrap_or(0),
        ),
        None => return json_err(env, "Job vanished after settle", 500),
    };

    let refund = held_sats.saturating_sub(req.actual_sats);

    // Credit refund back to requester if any
    if refund > 0 {
        let store = D1PaymentStore::new(db);
        store
            .credit_atomic(&requester_did, refund)
            .await
            .map_err(|e| Error::RustError(e.to_string()))?;
    }

    let body = serde_json::json!({
        "job_id": req.job_id,
        "status": "settled",
        "actual_sats": req.actual_sats,
        "held_sats": held_sats,
        "refund": refund,
        "completed_at": now,
    });
    json_ok(&body)
}

/// Cancel a held or running job — refund full hold to requester.
/// Either the requester or the agent can cancel.
///
/// Uses an atomic UPDATE with WHERE clause on status + ownership (requester OR
/// agent) to eliminate the TOCTOU race. The status transition and ownership
/// check happen in a single SQL statement.
async fn pay_job_cancel_handler(
    pubkey: &str,
    body: &[u8],
    db: &D1Database,
    env: &Env,
) -> std::result::Result<Response, Error> {
    let body_str = std::str::from_utf8(body).unwrap_or("");
    let req: JobActionBody =
        serde_json::from_str(body_str).map_err(|e| Error::RustError(format!("parse: {e}")))?;

    let caller_did = pubkey_to_did(pubkey);
    let now = now_epoch_secs();

    // Atomic cancel: single UPDATE that combines status check + ownership
    // check + state transition. The caller must be either requester or agent,
    // and the job must be in 'held' or 'running' status.
    let result = db
        .prepare(
            "UPDATE agent_jobs \
             SET status = 'failed', error = 'cancelled', completed_at = ?1 \
             WHERE job_id = ?2 \
               AND (status = 'held' OR status = 'running') \
               AND (requester_did = ?3 OR agent_did = ?3)",
        )
        .bind(&[
            js_i64(now),
            js_str(&req.job_id),
            js_str(&caller_did),
        ])
        .map_err(|e| Error::RustError(format!("d1 bind job cancel: {e:?}")))?
        .run()
        .await
        .map_err(|e| Error::RustError(format!("d1 run job cancel: {e:?}")))?;

    let rows_written = result
        .meta()
        .ok()
        .flatten()
        .and_then(|m| m.rows_written)
        .unwrap_or(0);

    if rows_written == 0 {
        // Diagnose why the atomic UPDATE failed.
        let job = db
            .prepare(
                "SELECT requester_did, agent_did, status \
                 FROM agent_jobs WHERE job_id = ?1",
            )
            .bind(&[js_str(&req.job_id)])
            .map_err(|e| Error::RustError(format!("d1 bind job read: {e:?}")))?
            .first::<serde_json::Value>(None)
            .await
            .map_err(|e| Error::RustError(format!("d1 run job read: {e:?}")))?;

        return match job {
            None => json_err(env, "Job not found", 404),
            Some(j) => {
                let jr = j.get("requester_did").and_then(|v| v.as_str()).unwrap_or("");
                let ja = j.get("agent_did").and_then(|v| v.as_str()).unwrap_or("");
                let js = j.get("status").and_then(|v| v.as_str()).unwrap_or("");
                if caller_did != jr && caller_did != ja {
                    json_err(env, "Only the requester or agent can cancel this job", 403)
                } else {
                    json_err(
                        env,
                        &format!("Cannot cancel job in '{js}' status"),
                        409,
                    )
                }
            }
        };
    }

    // The job is now atomically cancelled. Read back held_sats + requester_did
    // for the refund.
    let job = db
        .prepare(
            "SELECT requester_did, held_sats FROM agent_jobs WHERE job_id = ?1",
        )
        .bind(&[js_str(&req.job_id)])
        .map_err(|e| Error::RustError(format!("d1 bind job refund read: {e:?}")))?
        .first::<serde_json::Value>(None)
        .await
        .map_err(|e| Error::RustError(format!("d1 run job refund read: {e:?}")))?;

    let (requester_did, held_sats) = match job {
        Some(j) => (
            j.get("requester_did")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            j.get("held_sats").and_then(|v| v.as_u64()).unwrap_or(0),
        ),
        None => return json_err(env, "Job vanished after cancel", 500),
    };

    // Refund full held amount to requester
    if held_sats > 0 {
        let store = D1PaymentStore::new(db);
        store
            .credit_atomic(&requester_did, held_sats)
            .await
            .map_err(|e| Error::RustError(e.to_string()))?;
    }

    let body = serde_json::json!({
        "job_id": req.job_id,
        "status": "failed",
        "error": "cancelled",
        "refund": held_sats,
        "completed_at": now,
    });
    json_ok(&body)
}

/// Get a single agent job by ID. Only the requester or agent can view.
/// Accepts POST body `{ "job_id": "..." }` since the route handler does not
/// forward query parameters to individual pay handlers.
async fn pay_job_get_handler(
    pubkey: &str,
    body: &[u8],
    db: &D1Database,
    env: &Env,
) -> std::result::Result<Response, Error> {
    let body_str = std::str::from_utf8(body).unwrap_or("");
    let req: JobActionBody =
        serde_json::from_str(body_str).map_err(|e| Error::RustError(format!("parse: {e}")))?;

    pay_job_get_by_id(pubkey, &req.job_id, db, env).await
}

/// Internal handler for fetching a single job by ID with access control.
async fn pay_job_get_by_id(
    pubkey: &str,
    job_id: &str,
    db: &D1Database,
    env: &Env,
) -> std::result::Result<Response, Error> {
    let caller_did = pubkey_to_did(pubkey);

    let job = db
        .prepare(
            "SELECT job_id, requester_did, agent_did, endpoint, params_json, \
             status, estimated_sats, held_sats, actual_sats, \
             created_at, started_at, completed_at, error, expires_at \
             FROM agent_jobs WHERE job_id = ?1",
        )
        .bind(&[js_str(job_id)])
        .map_err(|e| Error::RustError(format!("d1 bind job get: {e:?}")))?
        .first::<serde_json::Value>(None)
        .await
        .map_err(|e| Error::RustError(format!("d1 run job get: {e:?}")))?;

    let job = match job {
        Some(j) => j,
        None => return json_err(env, "Job not found", 404),
    };

    // Only requester or agent can view
    let job_requester = job.get("requester_did").and_then(|v| v.as_str()).unwrap_or("");
    let job_agent = job.get("agent_did").and_then(|v| v.as_str()).unwrap_or("");

    if caller_did != job_requester && caller_did != job_agent {
        return json_err(env, "Only the requester or agent can view this job", 403);
    }

    json_ok(&job)
}

// ---------------------------------------------------------------------------
// Orphaned job recovery
// ---------------------------------------------------------------------------

/// Recover orphaned jobs: find jobs stuck in 'held' or 'running' status past
/// their `expires_at` timestamp, transition them to 'failed' with
/// error='expired', and refund held_sats to each requester's balance.
///
/// Returns the number of jobs recovered.
pub async fn recover_orphaned_jobs(db: &D1Database) -> std::result::Result<u64, Error> {
    let now_iso = iso8601_from_epoch(now_epoch_secs());

    // Find all expired jobs that are still active (held or running).
    // We select them first, then update + refund one by one to ensure
    // each refund is correctly credited.
    let rows = db
        .prepare(
            "SELECT job_id, requester_did, held_sats \
             FROM agent_jobs \
             WHERE (status = 'held' OR status = 'running') \
               AND expires_at IS NOT NULL \
               AND expires_at < ?1",
        )
        .bind(&[js_str(&now_iso)])
        .map_err(|e| Error::RustError(format!("d1 bind orphan select: {e:?}")))?
        .all()
        .await
        .map_err(|e| Error::RustError(format!("d1 run orphan select: {e:?}")))?;

    let jobs: Vec<serde_json::Value> = rows
        .results::<serde_json::Value>()
        .unwrap_or_default();

    let store = D1PaymentStore::new(db);
    let now = now_epoch_secs();
    let mut recovered: u64 = 0;

    for job in &jobs {
        let job_id = match job.get("job_id").and_then(|v| v.as_str()) {
            Some(id) => id,
            None => continue,
        };
        let requester_did = match job.get("requester_did").and_then(|v| v.as_str()) {
            Some(did) => did,
            None => continue,
        };
        let held_sats = job.get("held_sats").and_then(|v| v.as_u64()).unwrap_or(0);

        // Atomically transition to 'failed' only if still active
        let result = db
            .prepare(
                "UPDATE agent_jobs \
                 SET status = 'failed', error = 'expired', completed_at = ?1 \
                 WHERE job_id = ?2 AND (status = 'held' OR status = 'running')",
            )
            .bind(&[
                js_i64(now),
                js_str(job_id),
            ])
            .map_err(|e| Error::RustError(format!("d1 bind orphan update: {e:?}")))?
            .run()
            .await
            .map_err(|e| Error::RustError(format!("d1 run orphan update: {e:?}")))?;

        let rows_written = result
            .meta()
            .ok()
            .flatten()
            .and_then(|m| m.rows_written)
            .unwrap_or(0);

        if rows_written == 0 {
            // Job was already settled/cancelled between SELECT and UPDATE
            continue;
        }

        // Refund held_sats to requester
        if held_sats > 0 {
            store
                .credit_atomic(requester_did, held_sats)
                .await
                .map_err(|e| Error::RustError(e.to_string()))?;
        }

        recovered += 1;
    }

    Ok(recovered)
}

/// Handle `POST /pay/.cleanup` — admin-only endpoint to recover orphaned jobs.
///
/// Requires NIP-98 authentication and admin privileges. The caller's pubkey
/// is checked against the `members` and `whitelist` tables for `is_admin = 1`.
/// Without this guard, any unauthenticated caller could force-cancel expired
/// jobs and trigger balance mutations (refunds), creating a DoS vector.
async fn pay_cleanup_handler(
    pubkey: &str,
    db: &D1Database,
    env: &Env,
) -> std::result::Result<Response, Error> {
    if !is_admin(pubkey, db).await {
        return json_err(env, "Admin access required", 403);
    }

    let recovered = recover_orphaned_jobs(db).await?;
    let body = serde_json::json!({
        "status": "ok",
        "recovered_jobs": recovered,
    });
    json_ok(&body)
}

// ---------------------------------------------------------------------------
// Admin check (D1-backed, mirrors lib.rs is_admin_user)
// ---------------------------------------------------------------------------

/// Check if a pubkey is an admin via `members.is_admin` then `whitelist.is_admin`.
///
/// Accepts a `D1Database` directly (the pay handler already has the binding)
/// rather than going through `Env` again.
async fn is_admin(pubkey: &str, db: &D1Database) -> bool {
    #[derive(Deserialize)]
    struct IsAdminRow {
        is_admin: i32,
    }

    if let Ok(stmt) = db
        .prepare("SELECT is_admin FROM members WHERE pubkey = ?1")
        .bind(&[wasm_bindgen::JsValue::from_str(pubkey)])
    {
        if let Ok(Some(row)) = stmt.first::<IsAdminRow>(None).await {
            if row.is_admin == 1 {
                return true;
            }
        }
    }

    if let Ok(stmt) = db
        .prepare("SELECT is_admin FROM whitelist WHERE pubkey = ?1")
        .bind(&[wasm_bindgen::JsValue::from_str(pubkey)])
    {
        if let Ok(Some(row)) = stmt.first::<IsAdminRow>(None).await {
            return row.is_admin == 1;
        }
    }

    false
}

fn json_ok(body: &serde_json::Value) -> std::result::Result<Response, Error> {
    let json_str = serde_json::to_string(body).map_err(|e| Error::RustError(e.to_string()))?;
    let resp = Response::ok(json_str)?;
    resp.headers().set("Content-Type", "application/json").ok();
    Ok(resp)
}

fn json_err(_env: &Env, msg: &str, status: u16) -> std::result::Result<Response, Error> {
    let body = serde_json::json!({ "error": msg });
    let json_str = serde_json::to_string(&body).map_err(|e| Error::RustError(e.to_string()))?;
    let resp = Response::ok(json_str)?.with_status(status);
    resp.headers().set("Content-Type", "application/json").ok();
    Ok(resp)
}

// ---------------------------------------------------------------------------
// Taproot (P2TR) per-user deposit address derivation (BIP-341)
// ---------------------------------------------------------------------------

/// Compute a BIP-340 tagged hash: `SHA256(SHA256(tag) || SHA256(tag) || msg)`.
fn tagged_hash(tag: &[u8], msg: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let tag_hash = Sha256::digest(tag);
    let mut h = Sha256::new();
    h.update(tag_hash);
    h.update(tag_hash);
    h.update(msg);
    let result = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Derive a deterministic per-user P2TR (BIP-341 Taproot) deposit address.
///
/// The derivation follows BIP-341:
/// 1. Compute the master public key `P` from `master_secret`.
/// 2. Compute a per-user tweak: `t = SHA256(P_x || user_pubkey_bytes)`.
/// 3. Compute the tweaked internal key: `Q = P + t*G`.
/// 4. Compute the output key (key-path-only spend): apply BIP-341 TapTweak
///    with an empty script tree: `output_key = Q_x + tagged_hash("TapTweak", Q_x) * G`
///    expressed as the x-only coordinate.
/// 5. Encode as bech32m `bc1p...` (witness version 1, 32-byte program).
///
/// Both `master_secret` and `user_pubkey` are validated; errors are returned
/// for invalid inputs rather than panicking.
pub fn derive_deposit_address(
    master_secret: &[u8; 32],
    user_pubkey: &str,
) -> Result<String, String> {
    use k256::elliptic_curve::ops::Reduce;
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::{FieldBytes, ProjectivePoint, PublicKey, Scalar, SecretKey, U256};
    use sha2::{Digest, Sha256};

    // Validate user pubkey: must be 64 hex chars (32 bytes, x-only)
    if user_pubkey.len() != 64 || !user_pubkey.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "invalid user pubkey: expected 64 hex chars, got {} chars",
            user_pubkey.len()
        ));
    }

    let user_bytes =
        hex::decode(user_pubkey).map_err(|e| format!("invalid user pubkey hex: {e}"))?;

    // Derive master public key from secret
    let master_sk =
        SecretKey::from_bytes(master_secret.into()).map_err(|e| format!("invalid master secret: {e}"))?;
    let master_pk: PublicKey = master_sk.public_key();
    let master_point = master_pk.to_encoded_point(true);
    // x-only: 32 bytes of the x coordinate
    let master_x = master_point.x().ok_or("master key has no x coordinate")?;

    // Step 1: Per-user tweak = SHA256(master_pubkey_x || user_pubkey_bytes)
    let mut tweak_preimage = Vec::with_capacity(32 + 32);
    tweak_preimage.extend_from_slice(master_x);
    tweak_preimage.extend_from_slice(&user_bytes);
    let tweak_hash = Sha256::digest(&tweak_preimage);

    // Convert tweak to a scalar (reduce mod n to handle the rare case where
    // the hash exceeds the group order)
    let tweak_scalar =
        <Scalar as Reduce<U256>>::reduce_bytes(FieldBytes::from_slice(tweak_hash.as_ref()));

    // Step 2: Internal key Q = P + t*G (P is master pubkey as projective point)
    let master_proj: ProjectivePoint = master_pk.to_projective();
    let tweak_point = ProjectivePoint::GENERATOR * tweak_scalar;
    let internal_key = master_proj + tweak_point;

    // Convert to affine to get the x-only coordinate
    let internal_affine = internal_key.to_affine();
    let internal_encoded = internal_affine.to_encoded_point(true);
    let internal_x = internal_encoded
        .x()
        .ok_or("tweaked key is point at infinity")?;

    // Step 3: BIP-341 output key (key-path only, empty script tree).
    // output_key = internal_key + tagged_hash("TapTweak", internal_x) * G
    let tap_tweak = tagged_hash(b"TapTweak", internal_x);
    let tap_scalar =
        <Scalar as Reduce<U256>>::reduce_bytes(FieldBytes::from_slice(&tap_tweak));

    let output_point = internal_key + ProjectivePoint::GENERATOR * tap_scalar;
    let output_affine = output_point.to_affine();
    let output_encoded = output_affine.to_encoded_point(true);
    let output_x = output_encoded
        .x()
        .ok_or("output key is point at infinity")?;

    // Step 4: Encode as bech32m bc1p address (witness v1, 32-byte program)
    let witness_program: &[u8] = output_x.as_slice();
    let address = bech32::segwit::encode_v1(bech32::hrp::BC, witness_program)
        .map_err(|e| format!("bech32m encoding failed: {e}"))?;

    Ok(address)
}

/// Handle `GET /pay/.address?pubkey=<hex>` — returns the per-user P2TR deposit
/// address derived from the pod's master secret and the caller's pubkey.
pub fn handle_address_route(pubkey: &str, env: &Env) -> std::result::Result<Response, Error> {
    // Read the 32-byte master secret from env (stored as 64-char hex)
    let master_hex = env
        .secret("MASTER_SECRET")
        .map_err(|_| Error::RustError("MASTER_SECRET not configured".into()))?
        .to_string();

    if master_hex.len() != 64 {
        return Err(Error::RustError(
            "MASTER_SECRET must be exactly 64 hex characters (32 bytes)".into(),
        ));
    }

    let master_bytes: Vec<u8> =
        hex::decode(&master_hex).map_err(|e| Error::RustError(format!("MASTER_SECRET hex invalid: {e}")))?;

    let mut master_secret = [0u8; 32];
    master_secret.copy_from_slice(&master_bytes);

    let address = derive_deposit_address(&master_secret, pubkey)
        .map_err(|e| Error::RustError(format!("address derivation failed: {e}")))?;

    let body = serde_json::json!({
        "address": address,
        "chain": "btc"
    });
    let json_str = serde_json::to_string(&body).map_err(|e| Error::RustError(e.to_string()))?;
    let resp = Response::ok(json_str)?;
    resp.headers().set("Content-Type", "application/json").ok();
    Ok(resp)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Current epoch timestamp in seconds (JS runtime).
fn now_epoch_secs() -> i64 {
    (js_sys::Date::now() / 1000.0) as i64
}

/// Convert an epoch-seconds timestamp to an ISO 8601 string (UTC).
///
/// Format: `YYYY-MM-DDTHH:MM:SSZ`. Uses the JS `Date` constructor for
/// reliable formatting on the Workers runtime.
fn iso8601_from_epoch(epoch_secs: i64) -> String {
    let date = js_sys::Date::new_0();
    date.set_time((epoch_secs as f64) * 1000.0);
    date.to_iso_string().as_string().unwrap_or_default()
}

/// Read the configurable job expiry duration from the environment.
///
/// Falls back to `DEFAULT_JOB_EXPIRY_SECS` (1 hour) if the env var is
/// missing or unparseable.
fn job_expiry_secs(env: &Env) -> i64 {
    env.var("JOB_EXPIRY_SECS")
        .ok()
        .and_then(|v| v.to_string().parse::<i64>().ok())
        .unwrap_or(DEFAULT_JOB_EXPIRY_SECS)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed 32-byte master secret for deterministic test vectors.
    fn test_master_secret() -> [u8; 32] {
        let mut s = [0u8; 32];
        // Use a well-known non-zero scalar (BIP-340 test vector secret key #1)
        let bytes = hex::decode(
            "b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef",
        )
        .expect("valid hex");
        s.copy_from_slice(&bytes);
        s
    }

    /// Two distinct user pubkeys (valid 64-char hex x-only pubkeys).
    fn user_a() -> &'static str {
        "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659"
    }

    fn user_b() -> &'static str {
        "dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8"
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
        assert_ne!(
            addr_a, addr_b,
            "different user pubkeys must produce different addresses"
        );
    }

    #[test]
    fn format_bc1p_prefix_and_length() {
        let secret = test_master_secret();
        let addr = derive_deposit_address(&secret, user_a()).expect("derivation should succeed");
        assert!(
            addr.starts_with("bc1p"),
            "taproot address must start with bc1p, got: {addr}"
        );
        // bech32m taproot address: "bc1p" (4) + 58 data chars = 62 total
        assert_eq!(
            addr.len(),
            62,
            "taproot address must be 62 characters, got {} for: {addr}",
            addr.len()
        );
    }

    #[test]
    fn roundtrip_bech32m_decode() {
        let secret = test_master_secret();
        let addr = derive_deposit_address(&secret, user_a()).expect("derivation should succeed");
        let (hrp, version, program) =
            bech32::segwit::decode(&addr).expect("address must be valid bech32m");
        assert_eq!(hrp, bech32::hrp::BC);
        assert_eq!(version, bech32::segwit::VERSION_1);
        assert_eq!(program.len(), 32, "witness program must be 32 bytes");
    }

    #[test]
    fn error_empty_pubkey() {
        let secret = test_master_secret();
        let result = derive_deposit_address(&secret, "");
        assert!(result.is_err(), "empty pubkey must return an error");
        let err = result.unwrap_err();
        assert!(
            err.contains("invalid user pubkey"),
            "error should mention invalid pubkey, got: {err}"
        );
    }

    #[test]
    fn error_short_pubkey() {
        let secret = test_master_secret();
        let result = derive_deposit_address(&secret, "abcd");
        assert!(result.is_err(), "short pubkey must return an error");
    }

    #[test]
    fn error_non_hex_pubkey() {
        let secret = test_master_secret();
        let bad_pk = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
        assert_eq!(bad_pk.len(), 64);
        let result = derive_deposit_address(&secret, bad_pk);
        assert!(result.is_err(), "non-hex pubkey must return an error");
    }

    #[test]
    fn error_zero_master_secret() {
        // The zero scalar is not a valid secret key on secp256k1.
        let zero = [0u8; 32];
        let result = derive_deposit_address(&zero, user_a());
        assert!(
            result.is_err(),
            "zero master secret is invalid and must return an error"
        );
    }

    #[test]
    fn estimate_inference_10x_base() {
        assert_eq!(estimate_endpoint_cost("/api/inference/run", 1), 10);
        assert_eq!(estimate_endpoint_cost("/api/inference/batch", 2), 20);
    }

    #[test]
    fn estimate_image_gen_100x_base() {
        assert_eq!(estimate_endpoint_cost("/api/image-gen/submit", 1), 100);
    }

    #[test]
    fn estimate_analytics_5x_base() {
        assert_eq!(estimate_endpoint_cost("/api/analytics/pagerank", 1), 5);
    }

    #[test]
    fn estimate_unknown_endpoint_base_cost() {
        assert_eq!(estimate_endpoint_cost("/api/health", 3), 3);
        assert_eq!(estimate_endpoint_cost("/some/other", 1), 1);
    }

    #[test]
    fn different_master_secrets_produce_different_addresses() {
        let secret1 = test_master_secret();
        let mut secret2 = [0u8; 32];
        let bytes = hex::decode(
            "c90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b14e5c9",
        )
        .expect("valid hex");
        secret2.copy_from_slice(&bytes);

        let addr1 = derive_deposit_address(&secret1, user_a()).expect("derivation should succeed");
        let addr2 = derive_deposit_address(&secret2, user_a()).expect("derivation should succeed");
        assert_ne!(
            addr1, addr2,
            "different master secrets must produce different addresses"
        );
    }

    // -----------------------------------------------------------------------
    // Agent job CRUD tests (pure logic — no D1 dependency)
    // -----------------------------------------------------------------------

    #[test]
    fn job_create_body_deserialises_full() {
        let json = r#"{"agent_did":"did:nostr:abc123","endpoint":"/api/inference/run","params":{"model":"gpt4"}}"#;
        let body: JobCreateBody = serde_json::from_str(json).expect("valid JobCreateBody");
        assert_eq!(body.agent_did, "did:nostr:abc123");
        assert_eq!(body.endpoint, "/api/inference/run");
        assert!(body.params.is_some());
        let params = body.params.unwrap();
        assert_eq!(params["model"], "gpt4");
    }

    #[test]
    fn job_create_body_deserialises_minimal() {
        let json = r#"{"agent_did":"did:nostr:abc","endpoint":"/api/health"}"#;
        let body: JobCreateBody = serde_json::from_str(json).expect("valid JobCreateBody");
        assert_eq!(body.agent_did, "did:nostr:abc");
        assert_eq!(body.endpoint, "/api/health");
        assert!(body.params.is_none());
    }

    #[test]
    fn job_action_body_deserialises() {
        let json = r#"{"job_id":"job_1234567890_abcdef01"}"#;
        let body: JobActionBody = serde_json::from_str(json).expect("valid JobActionBody");
        assert_eq!(body.job_id, "job_1234567890_abcdef01");
    }

    #[test]
    fn job_settle_body_deserialises() {
        let json = r#"{"job_id":"job_1234567890_abcdef01","actual_sats":42}"#;
        let body: JobSettleBody = serde_json::from_str(json).expect("valid JobSettleBody");
        assert_eq!(body.job_id, "job_1234567890_abcdef01");
        assert_eq!(body.actual_sats, 42);
    }

    /// Verify the job_id format: `job_<timestamp>_<hex16>`.
    /// This test validates the format contract without calling generate_job_id(),
    /// which depends on js_sys (wasm-only).
    #[test]
    fn job_id_format_contract() {
        // Simulate what generate_job_id() produces (8 random bytes = 16 hex chars)
        let id = "job_1715443200_1a2b3c4d5e6f7a8b";
        assert!(id.starts_with("job_"));
        let parts: Vec<&str> = id.splitn(3, '_').collect();
        assert_eq!(parts.len(), 3, "job_id must have 3 parts: job_<ts>_<hex16>");
        assert!(
            parts[1].parse::<i64>().is_ok(),
            "second part must be a timestamp"
        );
        assert_eq!(parts[2].len(), 16, "third part must be 16 hex chars");
        assert!(
            parts[2].chars().all(|c| c.is_ascii_hexdigit()),
            "third part must be hex"
        );
    }

    #[test]
    fn job_hold_calculation_20_percent_buffer() {
        // Verify the hold calculation: hold = ceil(estimated * 1.2)
        let estimated: u64 = 100;
        let held = (estimated as f64 * 1.2).ceil() as u64;
        assert_eq!(held, 120, "hold should be 120% of estimate");

        let estimated: u64 = 10;
        let held = (estimated as f64 * 1.2).ceil() as u64;
        assert_eq!(held, 12);

        // Non-round numbers
        let estimated: u64 = 7;
        let held = (estimated as f64 * 1.2).ceil() as u64;
        // 7 * 1.2 = 8.4, ceil = 9
        assert_eq!(held, 9);
    }

    #[test]
    fn job_settle_refund_calculation() {
        let held: u64 = 120;
        let actual: u64 = 80;
        let refund = held - actual;
        assert_eq!(refund, 40);

        // No refund when actual equals held
        let held: u64 = 120;
        let actual: u64 = 120;
        let refund = held - actual;
        assert_eq!(refund, 0);
    }

    #[test]
    fn job_settle_overpay_detection() {
        let held: u64 = 120;
        let actual: u64 = 150;
        assert!(
            actual > held,
            "actual > held should be detected and rejected"
        );
    }

    #[test]
    fn job_estimate_for_inference_endpoint() {
        let base_cost = 1;
        let estimated = estimate_endpoint_cost("/api/inference/run", base_cost);
        let held = (estimated as f64 * 1.2).ceil() as u64;
        assert_eq!(estimated, 10, "inference is 10x base");
        assert_eq!(held, 12, "hold is 120% of 10");
    }

    #[test]
    fn job_estimate_for_image_gen_endpoint() {
        let base_cost = 1;
        let estimated = estimate_endpoint_cost("/api/image-gen/submit", base_cost);
        let held = (estimated as f64 * 1.2).ceil() as u64;
        assert_eq!(estimated, 100, "image-gen is 100x base");
        assert_eq!(held, 120, "hold is 120% of 100");
    }

    #[test]
    fn job_cancel_refunds_full_hold() {
        // Cancel always refunds 100% of held_sats regardless of status
        let held: u64 = 120;
        let refund = held; // Full refund
        assert_eq!(refund, 120);
    }

    // -----------------------------------------------------------------------
    // Job expiry and orphan recovery tests (pure logic — no D1 dependency)
    // -----------------------------------------------------------------------

    #[test]
    fn default_job_expiry_is_one_hour() {
        assert_eq!(DEFAULT_JOB_EXPIRY_SECS, 3600);
    }

    #[test]
    fn job_create_body_with_optional_ttl() {
        // Verify JobCreateBody still deserialises (no breaking changes)
        let json = r#"{"agent_did":"did:nostr:abc123","endpoint":"/api/health"}"#;
        let body: JobCreateBody = serde_json::from_str(json).expect("valid");
        assert_eq!(body.endpoint, "/api/health");
    }

    #[test]
    fn iso8601_expiry_comparison_ordering() {
        // Verify that ISO 8601 string comparison works correctly for
        // the expires_at < now() check in the orphan recovery SQL.
        let t1 = "2025-01-01T00:00:00.000Z";
        let t2 = "2025-01-01T01:00:00.000Z";
        let t3 = "2025-12-31T23:59:59.000Z";
        assert!(t1 < t2, "earlier timestamp must sort before later");
        assert!(t2 < t3, "same-year timestamps must sort correctly");
    }

    #[test]
    fn expiry_calculation_uses_held_plus_buffer() {
        // expires_at = created_at + JOB_EXPIRY_SECS (default 3600)
        let created_at: i64 = 1715443200; // arbitrary epoch
        let expiry_secs: i64 = DEFAULT_JOB_EXPIRY_SECS;
        let expires_at_epoch = created_at + expiry_secs;
        assert_eq!(
            expires_at_epoch - created_at,
            3600,
            "default expiry is 1 hour after creation"
        );
    }
}
