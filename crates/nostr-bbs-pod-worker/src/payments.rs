//! HTTP 402 Payment Required — CF Workers adapter for solid-pod-rs payments.
//!
//! Re-exports the upstream payment model from `solid_pod_rs::payments` and
//! provides the Cloudflare Workers storage adapter + /pay/ route handler.
//!
//! All accounts keyed by `did:nostr:<hex-pubkey>` — users and agents are
//! indistinguishable, enabling user↔user, user↔agent, agent↔agent payments.
//!
//! @see <https://webledgers.org>
//! @see JSS `src/handlers/pay.js`

use serde::Deserialize;
use worker::*;

pub use solid_pod_rs::payments::{
    balance_response, pay_info, payment_required_body, pubkey_to_did, parse_txo_uri,
    webledgers_discovery, ChainConfig, PayConfig, PaymentError, PaymentStore, WebLedger,
};

const LEDGER_KV_KEY: &str = "webledger:main";
const REPLAY_PREFIX: &str = "txo-replay:";

// ---------------------------------------------------------------------------
// CF Workers PaymentStore implementation
// ---------------------------------------------------------------------------

/// KV-backed payment store for Cloudflare Workers.
pub struct KvPaymentStore<'a> {
    kv: &'a kv::KvStore,
}

impl<'a> KvPaymentStore<'a> {
    pub fn new(kv: &'a kv::KvStore) -> Self {
        Self { kv }
    }
}

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

/// Handle all /pay/* routes. Returns Some(Response) if handled, None if not a pay route.
pub async fn handle_pay_route(
    path: &str,
    method: &Method,
    pubkey: Option<&str>,
    body_bytes: Option<&[u8]>,
    kv: &kv::KvStore,
    env: &Env,
    config: &PayConfig,
) -> Option<std::result::Result<Response, Error>> {
    if !config.enabled {
        return None;
    }

    let pay_path = path.strip_prefix("/pay/")?;

    Some(match (method, pay_path) {
        (_, ".info") => pay_info_handler(config, env),

        (&Method::Get, ".balance") => {
            let pk = match pubkey {
                Some(pk) => pk,
                None => return Some(json_err(env, "Authentication required", 401)),
            };
            pay_balance_handler(pk, kv, config, env).await
        }

        (&Method::Post, ".deposit") => {
            let pk = match pubkey {
                Some(pk) => pk,
                None => return Some(json_err(env, "Authentication required", 401)),
            };
            let body = body_bytes.unwrap_or_default();
            pay_deposit_handler(pk, body, kv, config, env).await
        }

        (_, ".offers") => pay_info_handler(config, env), // stub: list offers

        (&Method::Get, _) => {
            let pk = match pubkey {
                Some(pk) => pk,
                None => return Some(json_err(env, "Authentication required", 401)),
            };
            pay_resource_handler(pk, pay_path, kv, config, env).await
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
    kv: &kv::KvStore,
    config: &PayConfig,
    _env: &Env,
) -> std::result::Result<Response, Error> {
    let store = KvPaymentStore::new(kv);
    let ledger = store
        .read_ledger()
        .await
        .map_err(|e| Error::RustError(e.to_string()))?;
    let did = pubkey_to_did(pubkey);
    let balance = ledger.get_balance(&did);
    let body = balance_response(&did, balance, config.cost_sats);
    let json_str = serde_json::to_string(&body).map_err(|e| Error::RustError(e.to_string()))?;
    let resp = Response::ok(json_str)?;
    resp.headers().set("Content-Type", "application/json").ok();
    Ok(resp)
}

async fn pay_deposit_handler(
    pubkey: &str,
    body: &[u8],
    kv: &kv::KvStore,
    config: &PayConfig,
    env: &Env,
) -> std::result::Result<Response, Error> {
    let store = KvPaymentStore::new(kv);
    let did = pubkey_to_did(pubkey);

    // Parse deposit: either JSON body with txo/amount_sats, or plain text TXO URI
    let body_str = std::str::from_utf8(body).unwrap_or("");
    let amount = if let Ok(deposit) = serde_json::from_str::<DepositBody>(body_str) {
        if let Some(ref txo) = deposit.txo {
            // Replay check
            if store.check_replay(txo).await.unwrap_or(false) {
                return json_err(env, "TXO already used", 409);
            }
            let sats = verify_txo_multichain(txo, config)
                .await
                .map_err(|e| Error::RustError(format!("TXO verify: {e}")))?;
            store.record_replay(txo).await.ok();
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
        if store.check_replay(txo).await.unwrap_or(false) {
            return json_err(env, "TXO already used", 409);
        }
        let sats = verify_txo_multichain(txo, config)
            .await
            .map_err(|e| Error::RustError(format!("TXO verify: {e}")))?;
        store.record_replay(txo).await.ok();
        sats
    };

    // Credit the ledger
    let mut ledger = store
        .read_ledger()
        .await
        .map_err(|e| Error::RustError(e.to_string()))?;
    ledger.credit(&did, amount);
    store
        .write_ledger(&ledger)
        .await
        .map_err(|e| Error::RustError(e.to_string()))?;

    let balance = ledger.get_balance(&did);
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
    kv: &kv::KvStore,
    config: &PayConfig,
    _env: &Env,
) -> std::result::Result<Response, Error> {
    let store = KvPaymentStore::new(kv);
    let did = pubkey_to_did(pubkey);
    let mut ledger = store
        .read_ledger()
        .await
        .map_err(|e| Error::RustError(e.to_string()))?;

    match ledger.debit(&did, config.cost_sats) {
        Ok(remaining) => {
            store
                .write_ledger(&ledger)
                .await
                .map_err(|e| Error::RustError(e.to_string()))?;
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
