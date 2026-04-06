//! HTTP 402 Payment Required — Agent micropayment infrastructure.
//!
//! Enables pay-gated access to pod resources under `/pay/` namespace.
//! Balances tracked via Web Ledgers spec at `/.well-known/webledgers/webledgers.json`.
//! Deposits accepted via Bitcoin TXO URI with mempool API verification.
//!
//! @see https://webledgers.org
//! @see JSS PR #168

use serde::{Deserialize, Serialize};
use worker::*;

/// Default cost per request in satoshis.
pub const DEFAULT_COST_SATS: u64 = 1;

/// Ledger entry for a single agent/user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerEntry {
    /// Nostr pubkey (hex) of the account holder.
    pub pubkey: String,
    /// Balance in satoshis.
    pub balance_sats: u64,
    /// Total deposited (lifetime).
    pub total_deposited: u64,
    /// Total spent (lifetime).
    pub total_spent: u64,
    /// Last activity timestamp.
    pub last_activity: u64,
}

impl LedgerEntry {
    pub fn new(pubkey: &str) -> Self {
        Self {
            pubkey: pubkey.to_string(),
            balance_sats: 0,
            total_deposited: 0,
            total_spent: 0,
            last_activity: now_secs(),
        }
    }
}

/// Payment configuration for the pod worker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayConfig {
    /// Whether payment is enabled.
    pub enabled: bool,
    /// Cost per request in satoshis.
    pub cost_sats: u64,
    /// Bitcoin address for deposits (for display/verification).
    pub deposit_address: Option<String>,
}

impl Default for PayConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cost_sats: DEFAULT_COST_SATS,
            deposit_address: None,
        }
    }
}

/// HTTP 402 response body.
pub fn payment_required_body(balance: u64, cost: u64) -> serde_json::Value {
    serde_json::json!({
        "error": "Payment Required",
        "balance": balance,
        "cost": cost,
        "unit": "sat",
        "deposit": "/pay/.deposit",
        "balance_endpoint": "/pay/.balance",
        "spec": "https://webledgers.org"
    })
}

/// Get or create a ledger entry from KV.
pub async fn get_ledger(kv: &kv::KvStore, pubkey: &str) -> Result<LedgerEntry> {
    let key = format!("ledger:{pubkey}");
    match kv.get(&key).text().await? {
        Some(json) => serde_json::from_str(&json)
            .map_err(|e| Error::RustError(format!("ledger parse: {e}"))),
        None => Ok(LedgerEntry::new(pubkey)),
    }
}

/// Save a ledger entry to KV.
pub async fn save_ledger(kv: &kv::KvStore, entry: &LedgerEntry) -> Result<()> {
    let key = format!("ledger:{}", entry.pubkey);
    let json = serde_json::to_string(entry)
        .map_err(|e| Error::RustError(format!("ledger serialize: {e}")))?;
    kv.put(&key, &json)?.execute().await?;
    Ok(())
}

/// Check if a request can proceed (has sufficient balance).
/// Returns Ok(remaining_balance) or Err with (current_balance, cost).
pub async fn check_payment(
    kv: &kv::KvStore,
    pubkey: &str,
    cost: u64,
) -> std::result::Result<u64, (u64, u64)> {
    let entry = get_ledger(kv, pubkey)
        .await
        .unwrap_or_else(|_| LedgerEntry::new(pubkey));
    if entry.balance_sats >= cost {
        Ok(entry.balance_sats - cost)
    } else {
        Err((entry.balance_sats, cost))
    }
}

/// Deduct payment from an account after successful resource access.
pub async fn deduct_payment(
    kv: &kv::KvStore,
    pubkey: &str,
    cost: u64,
) -> Result<LedgerEntry> {
    let mut entry = get_ledger(kv, pubkey).await?;
    entry.balance_sats = entry.balance_sats.saturating_sub(cost);
    entry.total_spent += cost;
    entry.last_activity = now_secs();
    save_ledger(kv, &entry).await?;
    Ok(entry)
}

/// Process a deposit. In production, this would verify the Bitcoin TXO via mempool API.
/// For now, accepts a deposit amount directly (admin/test mode) or a TXO URI for verification.
#[derive(Debug, Deserialize)]
pub struct DepositRequest {
    /// Amount in satoshis (for direct/admin deposits).
    pub amount_sats: Option<u64>,
    /// Bitcoin TXO URI (e.g., "bitcoin:txid:vout") for on-chain verification.
    pub txo_uri: Option<String>,
}

/// Verify a Bitcoin TXO via mempool.space API and return the value in satoshis.
/// Returns None if verification fails or the TXO is unconfirmed.
pub async fn verify_txo(txo_uri: &str) -> Option<u64> {
    // Parse TXO URI: "txid:vout" or "bitcoin:txid:vout"
    let cleaned = txo_uri.strip_prefix("bitcoin:").unwrap_or(txo_uri);
    let parts: Vec<&str> = cleaned.split(':').collect();
    if parts.len() != 2 {
        return None;
    }
    let txid = parts[0];
    let vout: u32 = parts[1].parse().ok()?;

    // Validate txid format (64 hex chars)
    if txid.len() != 64 || !txid.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }

    // Query mempool.space API for transaction details
    let url = format!("https://mempool.space/api/tx/{txid}");
    let mut resp = Fetch::Url(worker::Url::parse(&url).ok()?)
        .send()
        .await
        .ok()?;
    let body: serde_json::Value = resp.json().await.ok()?;

    // Extract the output value at the specified vout index
    let outputs = body.get("vout")?.as_array()?;
    let output = outputs.get(vout as usize)?;
    let value = output.get("value")?.as_u64()?;

    // Check if the transaction is confirmed
    if let Some(status) = body.get("status") {
        if status.get("confirmed").and_then(|c| c.as_bool()) != Some(true) {
            return None; // Unconfirmed transaction
        }
    }

    Some(value)
}

/// Process a deposit and credit the account.
pub async fn process_deposit(
    kv: &kv::KvStore,
    pubkey: &str,
    request: &DepositRequest,
) -> Result<LedgerEntry> {
    let amount = if let Some(amount) = request.amount_sats {
        // Direct deposit (admin/test mode)
        amount
    } else if let Some(ref txo) = request.txo_uri {
        // Bitcoin TXO verification
        match verify_txo(txo).await {
            Some(sats) => sats,
            None => return Err(Error::RustError("Invalid or unconfirmed TXO".into())),
        }
    } else {
        return Err(Error::RustError("No amount_sats or txo_uri provided".into()));
    };

    let mut entry = get_ledger(kv, pubkey).await?;
    entry.balance_sats += amount;
    entry.total_deposited += amount;
    entry.last_activity = now_secs();
    save_ledger(kv, &entry).await?;
    Ok(entry)
}

/// Get the Web Ledgers discovery document.
pub fn webledgers_discovery(pod_base: &str) -> serde_json::Value {
    serde_json::json!({
        "@context": "https://webledgers.org/ns/v1",
        "type": "WebLedger",
        "name": "Nostr BBS Micropayments",
        "description": "Satoshi-denominated micropayments for pod resource access",
        "unit": "sat",
        "endpoints": {
            "balance": "/pay/.balance",
            "deposit": "/pay/.deposit",
            "ledger": "/.well-known/webledgers/webledgers.json"
        },
        "verification": {
            "method": "mempool-api",
            "url": "https://mempool.space/api/"
        },
        "server": pod_base
    })
}

fn now_secs() -> u64 {
    #[cfg(target_arch = "wasm32")]
    {
        (js_sys::Date::now() / 1000.0) as u64
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_ledger_has_zero_balance() {
        let entry = LedgerEntry::new("abc123");
        assert_eq!(entry.balance_sats, 0);
        assert_eq!(entry.total_deposited, 0);
        assert_eq!(entry.total_spent, 0);
    }

    #[test]
    fn payment_required_body_format() {
        let body = payment_required_body(0, 10);
        assert_eq!(body["error"], "Payment Required");
        assert_eq!(body["balance"], 0);
        assert_eq!(body["cost"], 10);
        assert_eq!(body["unit"], "sat");
    }

    #[test]
    fn ledger_serialization_roundtrip() {
        let entry = LedgerEntry {
            pubkey: "abc".into(),
            balance_sats: 1000,
            total_deposited: 5000,
            total_spent: 4000,
            last_activity: 1700000000,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: LedgerEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.balance_sats, 1000);
        assert_eq!(parsed.total_deposited, 5000);
    }

    #[test]
    fn webledgers_discovery_format() {
        let doc = webledgers_discovery("https://pods.example.com");
        assert_eq!(doc["unit"], "sat");
        assert!(doc["endpoints"]["balance"]
            .as_str()
            .unwrap()
            .contains(".balance"));
    }

    #[test]
    fn default_config_disabled() {
        let config = PayConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.cost_sats, 1);
    }

    #[test]
    fn deposit_request_deserialize() {
        let json = r#"{"amount_sats": 100}"#;
        let req: DepositRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.amount_sats, Some(100));
        assert!(req.txo_uri.is_none());
    }

    #[test]
    fn deposit_request_txo() {
        let json = r#"{"txo_uri": "abc123def456:0"}"#;
        let req: DepositRequest = serde_json::from_str(json).unwrap();
        assert!(req.amount_sats.is_none());
        assert_eq!(req.txo_uri.as_deref(), Some("abc123def456:0"));
    }
}
