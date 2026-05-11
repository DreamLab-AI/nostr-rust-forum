//! HTTP 402 Payment Required — CF Workers adapter for solid-pod-rs payments.
//!
//! Re-exports the upstream payment model from `solid_pod_rs::payments` and
//! provides the Cloudflare Workers storage adapter + /pay/ route handler.
//!
//! Two storage backends:
//! - `KvPaymentStore` (deprecated) — non-atomic KV get+put, vulnerable to
//!   race conditions.
//! - `D1PaymentStore` — atomic D1 operations with INSERT-or-update semantics,
//!   immune to double-spend and concurrent-deposit races.
//!
//! All accounts keyed by `did:nostr:<hex-pubkey>` — users and agents are
//! indistinguishable, enabling user-user, user-agent, agent-agent payments.
//!
//! @see <https://webledgers.org>
//! @see JSS `src/handlers/pay.js`

use nostr_bbs_core::d1_helpers::{js_i64, js_str};
use serde::Deserialize;
use worker::*;

pub use solid_pod_rs::payments::{
    balance_response, pay_info, payment_required_body, pubkey_to_did, parse_txo_uri,
    webledgers_discovery, ChainConfig, PayConfig, PaymentError, PaymentStore, WebLedger,
};

#[allow(dead_code)] // Used by deprecated KvPaymentStore
const LEDGER_KV_KEY: &str = "webledger:main";
#[allow(dead_code)] // Used by deprecated KvPaymentStore
const REPLAY_PREFIX: &str = "txo-replay:";

// ---------------------------------------------------------------------------
// Schema initialisation (idempotent — call on every worker startup)
// ---------------------------------------------------------------------------

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
// KV-backed payment store (DEPRECATED — non-atomic)
// ---------------------------------------------------------------------------

/// KV-backed payment store for Cloudflare Workers.
///
/// **Deprecated**: Use `D1PaymentStore` for atomic operations. This
/// implementation is retained for backward compatibility during migration.
#[deprecated(note = "Use D1PaymentStore for atomic payment operations")]
#[allow(dead_code)]
pub struct KvPaymentStore<'a> {
    kv: &'a kv::KvStore,
}

#[allow(deprecated, dead_code)]
impl<'a> KvPaymentStore<'a> {
    pub fn new(kv: &'a kv::KvStore) -> Self {
        Self { kv }
    }
}

#[allow(deprecated)]
#[async_trait::async_trait(?Send)]
impl<'a> PaymentStore for KvPaymentStore<'a> {
    async fn read_ledger(&self) -> Result<WebLedger, PaymentError> {
        match self.kv.get(LEDGER_KV_KEY).text().await {
            Ok(Some(json)) => serde_json::from_str(&json)
                .map_err(|e| PaymentError::Store(format!("ledger parse: {e}"))),
            Ok(None) => Ok(WebLedger::new("Pod Credits")),
            Err(e) => Err(PaymentError::Store(format!("KV read: {e}"))),
        }
    }

    async fn write_ledger(&self, ledger: &WebLedger) -> Result<(), PaymentError> {
        let json = serde_json::to_string(ledger)
            .map_err(|e| PaymentError::Store(format!("serialize: {e}")))?;
        self.kv
            .put(LEDGER_KV_KEY, &json)
            .map_err(|e| PaymentError::Store(format!("KV put: {e}")))?
            .execute()
            .await
            .map_err(|e| PaymentError::Store(format!("KV exec: {e}")))?;
        Ok(())
    }

    async fn check_replay(&self, key: &str) -> Result<bool, PaymentError> {
        let kv_key = format!("{REPLAY_PREFIX}{key}");
        match self.kv.get(&kv_key).text().await {
            Ok(Some(_)) => Ok(true),
            Ok(None) => Ok(false),
            Err(e) => Err(PaymentError::Store(format!("replay check: {e}"))),
        }
    }

    async fn record_replay(&self, key: &str) -> Result<(), PaymentError> {
        let kv_key = format!("{REPLAY_PREFIX}{key}");
        self.kv
            .put(&kv_key, "1")
            .map_err(|e| PaymentError::Store(format!("replay put: {e}")))?
            .expiration_ttl(86400 * 30) // 30 days
            .execute()
            .await
            .map_err(|e| PaymentError::Store(format!("replay exec: {e}")))?;
        Ok(())
    }
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

        (_, ".offers") => pay_info_handler(config, env), // stub: list offers

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
}
