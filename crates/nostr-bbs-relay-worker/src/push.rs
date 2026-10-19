//! Content-free Web Push (ADR-2023).
//!
//! The relay wakes a member's installed PWA with an **empty, VAPID-signed push**
//! (RFC 8292). Nothing about the message (text, author, channel) crosses the
//! push service. On wake the service worker calls `POST /api/push/drain` over
//! HTTPS with a per-subscription bearer token and receives only counters and
//! `/go/<event-id>` deep links, from which it composes a generic notification.
//!
//! | Method | Path                    | Auth                        |
//! |--------|-------------------------|-----------------------------|
//! | GET    | /api/push/config        | none                        |
//! | POST   | /api/push/subscribe     | NIP-98 (+ whitelisted)      |
//! | POST   | /api/push/unsubscribe   | NIP-98                      |
//! | GET    | /api/push/prefs         | NIP-98                      |
//! | POST   | /api/push/prefs         | NIP-98                      |
//! | POST   | /api/push/drain         | subscription bearer token   |
//!
//! The module has three layers: pure logic (categories, preferences, quiet
//! hours, endpoint allow-list, VAPID signing, token hashing, recipient
//! classification), HTTP handlers, and [`deliver`], the fan-out the relay
//! Durable Object runs inside `wait_until` after the sender's `OK`.
//!
//! Cryptography is RustCrypto only: `p256` ES256 for VAPID, `sha2` for token
//! hashes, `getrandom` for tokens. No payload is encrypted because no payload
//! is sent; adopting RFC 8291 needs a new ADR.

use std::collections::{HashMap, HashSet};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine};
use nostr_bbs_core::d1_helpers::{js_f64, js_str};
use nostr_bbs_core::NostrEvent;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use worker::{
    console_error, console_log, Env, Fetch, Headers, Method, Request, RequestInit, Response,
    Result, Url,
};

use crate::auth;
pub use nostr_bbs_core::push::{Category, PushPrefs, QuietHours};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Largest request body the push endpoints accept.
const MAX_BODY_BYTES: usize = 8 * 1024;
/// Longest accepted push-service endpoint URL.
const MAX_ENDPOINT_LEN: usize = 2048;
/// Subscriptions kept per member; registering an 11th evicts the oldest.
const MAX_SUBS_PER_PUBKEY: usize = 10;
/// `p`-tagged recipients considered per event.
const MAX_TAGGED_RECIPIENTS: usize = 20;
/// Opt-in broadcast subscribers read per kind-40/42 event.
const MAX_BROADCAST_CANDIDATES: usize = 500;
/// Default cap on pushes sent for one event (`PUSH_MAX_FANOUT` overrides).
const DEFAULT_MAX_FANOUT: usize = 100;
/// Consecutive failed sends before a subscription is dropped.
const MAX_FAILURES: i64 = 5;
/// Subscriptions not refreshed by the app for this long are swept by cron.
pub const STALE_AFTER_SECS: u64 = 90 * 24 * 60 * 60;
/// Lifetime of one VAPID JWT (RFC 8292 caps it at 24 h).
const VAPID_JWT_TTL_SECS: u64 = 12 * 60 * 60;

/// Push-service host suffixes a subscription endpoint may use. Anything else
/// is refused so the worker can never be steered into fetching arbitrary URLs.
const ALLOWED_PUSH_HOSTS: [&str; 4] = [
    "fcm.googleapis.com",
    "push.apple.com",
    "push.services.mozilla.com",
    "notify.windows.com",
];

/// DDL applied idempotently by `ensure_schema` (mirrors `migrations/0010_push.sql`).
pub const PUSH_SCHEMA_SQL: [&str; 3] = [
    "CREATE TABLE IF NOT EXISTS push_subscriptions (\
        id TEXT PRIMARY KEY, pubkey TEXT NOT NULL, endpoint TEXT NOT NULL, \
        token_hash TEXT NOT NULL, created_at INTEGER NOT NULL, refreshed_at INTEGER NOT NULL, \
        last_push_at INTEGER NOT NULL DEFAULT 0, failures INTEGER NOT NULL DEFAULT 0, \
        pending_dm INTEGER NOT NULL DEFAULT 0, pending_reply INTEGER NOT NULL DEFAULT 0, \
        pending_topic INTEGER NOT NULL DEFAULT 0, pending_post INTEGER NOT NULL DEFAULT 0, \
        link_reply TEXT, link_topic TEXT, link_post TEXT)",
    "CREATE INDEX IF NOT EXISTS idx_push_subscriptions_pubkey ON push_subscriptions(pubkey)",
    "CREATE TABLE IF NOT EXISTS push_prefs (\
        pubkey TEXT PRIMARY KEY, replies INTEGER NOT NULL DEFAULT 1, dms INTEGER NOT NULL DEFAULT 1, \
        new_topics INTEGER NOT NULL DEFAULT 0, new_posts INTEGER NOT NULL DEFAULT 0, \
        muted_channels TEXT NOT NULL DEFAULT '[]', quiet_start INTEGER, quiet_end INTEGER, \
        tz_offset INTEGER NOT NULL DEFAULT 0, updated_at INTEGER NOT NULL DEFAULT 0)",
];

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

// ---------------------------------------------------------------------------
// SQL (shared by the handlers and the SQLite tests)
// ---------------------------------------------------------------------------

/// Keep a member's newest `?3` other subscriptions; delete the rest. The row
/// being (re)registered, `?2`, is exempt so a re-subscribe never evicts itself.
const SQL_EVICT_OLDEST: &str =
    "DELETE FROM push_subscriptions WHERE pubkey = ?1 AND id != ?2 AND id NOT IN (\
       SELECT id FROM push_subscriptions WHERE pubkey = ?1 AND id != ?2 \
       ORDER BY refreshed_at DESC LIMIT ?3)";

/// Register or refresh a subscription: new bearer token, counters reset.
const SQL_UPSERT_SUBSCRIPTION: &str =
    "INSERT INTO push_subscriptions (id, pubkey, endpoint, token_hash, created_at, refreshed_at) \
     VALUES (?1, ?2, ?3, ?4, ?5, ?5) \
     ON CONFLICT(id) DO UPDATE SET pubkey = excluded.pubkey, token_hash = excluded.token_hash, \
       refreshed_at = excluded.refreshed_at, failures = 0, \
       pending_dm = 0, pending_reply = 0, pending_topic = 0, pending_post = 0";

/// Insert or replace a member's preferences.
const SQL_UPSERT_PREFS: &str = "INSERT INTO push_prefs (pubkey, replies, dms, new_topics, new_posts, muted_channels, \
       quiet_start, quiet_end, tz_offset, updated_at) \
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10) \
     ON CONFLICT(pubkey) DO UPDATE SET replies = excluded.replies, dms = excluded.dms, \
       new_topics = excluded.new_topics, new_posts = excluded.new_posts, \
       muted_channels = excluded.muted_channels, quiet_start = excluded.quiet_start, \
       quiet_end = excluded.quiet_end, tz_offset = excluded.tz_offset, updated_at = excluded.updated_at";

/// Read a subscription's token hash, counters and links for the drain.
const SQL_DRAIN_SELECT: &str =
    "SELECT token_hash, pending_dm, pending_reply, pending_topic, pending_post, \
       link_reply, link_topic, link_post FROM push_subscriptions WHERE id = ?1";

/// Subtract what the drain read (not "= 0") so a push that lands mid-drain is kept.
const SQL_DRAIN_SUBTRACT: &str =
    "UPDATE push_subscriptions SET pending_dm = MAX(pending_dm - ?2, 0), \
       pending_reply = MAX(pending_reply - ?3, 0), pending_topic = MAX(pending_topic - ?4, 0), \
       pending_post = MAX(pending_post - ?5, 0) WHERE id = ?1";

/// Devices with undelivered counters whose last push is older than `?1`:
/// throttled alerts the trailing flush must still wake them for.
const SQL_PENDING_DUE: &str = "SELECT id, pubkey, endpoint, last_push_at, \
       pending_dm, pending_reply, pending_topic, pending_post \
     FROM push_subscriptions \
     WHERE (pending_dm + pending_reply + pending_topic + pending_post) > 0 AND last_push_at <= ?1 \
     ORDER BY last_push_at ASC LIMIT ?2";

/// A device is flushed once its last push is at least this old, which is longer
/// than every per-category throttle, so a flush never itself spams.
const FLUSH_AFTER_SECS: u64 = 120;
/// Devices woken per cron tick.
const FLUSH_BATCH: usize = 100;

/// Delete subscriptions the app has not refreshed since `?1`.
const SQL_SWEEP_STALE: &str = "DELETE FROM push_subscriptions WHERE refreshed_at < ?1";

/// Delete subscriptions that failed `?1` times in a row.
const SQL_DELETE_FAILED: &str = "DELETE FROM push_subscriptions WHERE failures >= ?1";

/// The counter bump for `category`: DMs only count; the rest also keep the
/// newest deep link (`?2`).
fn bump_sql(category: Category) -> String {
    if category.has_link() {
        format!(
            "UPDATE push_subscriptions SET pending_{0} = pending_{0} + 1, link_{0} = ?2 WHERE id = ?1",
            category.as_str()
        )
    } else {
        "UPDATE push_subscriptions SET pending_dm = pending_dm + 1 WHERE id = ?1".to_string()
    }
}

// ---------------------------------------------------------------------------
// Endpoint allow-list
// ---------------------------------------------------------------------------

/// Validate a subscription endpoint and return its origin (the VAPID `aud`).
///
/// Accepts only `https` URLs on an allow-listed push-service host, without
/// credentials and on the default port.
pub fn validate_endpoint(endpoint: &str) -> std::result::Result<String, &'static str> {
    if endpoint.is_empty() || endpoint.len() > MAX_ENDPOINT_LEN {
        return Err("endpoint missing or too long");
    }
    let url = Url::parse(endpoint).map_err(|_| "endpoint is not a valid URL")?;
    if url.scheme() != "https" {
        return Err("endpoint must be https");
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("endpoint must not carry credentials");
    }
    if url.port().is_some() {
        return Err("endpoint must use the default port");
    }
    let host = url
        .host_str()
        .ok_or("endpoint has no host")?
        .to_ascii_lowercase();
    let allowed = ALLOWED_PUSH_HOSTS
        .iter()
        .any(|s| host == *s || host.ends_with(&format!(".{s}")));
    if !allowed {
        return Err("endpoint host is not a known push service");
    }
    Ok(format!("https://{host}"))
}

// ---------------------------------------------------------------------------
// Tokens and ids
// ---------------------------------------------------------------------------

/// Lowercase hex SHA-256 of `input`.
pub fn sha256_hex(input: &str) -> String {
    hex::encode(Sha256::digest(input.as_bytes()))
}

/// Stable subscription id: SHA-256 of the endpoint URL.
pub fn subscription_id(endpoint: &str) -> String {
    sha256_hex(endpoint)
}

/// A fresh 256-bit bearer token, base64url, from the platform CSPRNG.
pub fn new_token() -> std::result::Result<String, getrandom::Error> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes)?;
    Ok(B64URL.encode(bytes))
}

/// Constant-time equality for two hex digests.
pub fn digests_equal(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

// ---------------------------------------------------------------------------
// VAPID (RFC 8292)
// ---------------------------------------------------------------------------

/// The relay's VAPID identity.
pub struct VapidKeys {
    signing: SigningKey,
    public_b64: String,
    subject: String,
}

impl VapidKeys {
    /// Build from the base64url raw 32-byte P-256 private scalar (the format
    /// `web-push generate-vapid-keys` prints) and the contact `subject`
    /// (`mailto:` or `https:` URL).
    pub fn from_private_b64(
        private_b64: &str,
        subject: &str,
    ) -> std::result::Result<Self, &'static str> {
        if !(subject.starts_with("mailto:") || subject.starts_with("https://")) {
            return Err("VAPID_SUBJECT must be a mailto: or https: URL");
        }
        let raw = B64URL
            .decode(private_b64.trim().trim_end_matches('='))
            .map_err(|_| "VAPID_PRIVATE_KEY is not base64url")?;
        let signing =
            SigningKey::from_slice(&raw).map_err(|_| "VAPID_PRIVATE_KEY is not a P-256 scalar")?;
        let public_b64 = B64URL.encode(signing.verifying_key().to_encoded_point(false).as_bytes());
        Ok(Self {
            signing,
            public_b64,
            subject: subject.to_string(),
        })
    }

    /// Uncompressed public key, base64url: the browser's `applicationServerKey`
    /// and the `k=` parameter of the `Authorization` header.
    pub fn public_key_b64(&self) -> &str {
        &self.public_b64
    }

    /// Sign a VAPID JWT for push-service origin `aud`, valid for 12 h from `now`.
    pub fn sign_jwt(&self, aud: &str, now_secs: u64) -> String {
        let header = B64URL.encode(br#"{"typ":"JWT","alg":"ES256"}"#);
        let claims = json!({
            "aud": aud,
            "exp": now_secs + VAPID_JWT_TTL_SECS,
            "sub": self.subject,
        });
        let payload = B64URL.encode(claims.to_string());
        let signing_input = format!("{header}.{payload}");
        let sig: Signature = self.signing.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", B64URL.encode(sig.to_bytes()))
    }

    /// The `Authorization` header value for a push to origin `aud`.
    pub fn authorization(&self, aud: &str, now_secs: u64) -> String {
        format!(
            "vapid t={}, k={}",
            self.sign_jwt(aud, now_secs),
            self.public_b64
        )
    }
}

// ---------------------------------------------------------------------------
// Recipient classification (pure)
// ---------------------------------------------------------------------------

/// The channel a kind-42 event belongs to: its `root`-marked `e` tag, else the
/// first `e` tag.
pub fn channel_of(event: &NostrEvent) -> Option<String> {
    let e_tags = || event.tags.iter().filter(|t| t.len() >= 2 && t[0] == "e");
    e_tags()
        .find(|t| t.get(3).map(String::as_str) == Some("root"))
        .or_else(|| e_tags().next())
        .map(|t| t[1].to_ascii_lowercase())
        .filter(|c| is_hex64(c))
}

/// The category an opt-in broadcast of this event would use, if any.
pub fn broadcast_category(event: &NostrEvent) -> Option<Category> {
    match event.kind {
        40 => Some(Category::Topic),
        42 => Some(Category::Post),
        _ => None,
    }
}

/// Recipients addressed by name: the gift-wrap target of a kind-1059 (DM), or
/// the `p`-tagged members of a kind-42 (reply/mention).
///
/// `submitter` is the pubkey the submitting session authenticated as. A wrap
/// addressed to its own submitter is the NIP-17 *sender copy* and alerts
/// nobody; likewise nobody is alerted about their own post.
pub fn explicit_recipients(event: &NostrEvent, submitter: Option<&str>) -> Vec<(String, Category)> {
    let p_tags = event
        .tags
        .iter()
        .filter(|t| t.len() >= 2 && t[0] == "p")
        .map(|t| t[1].to_ascii_lowercase())
        .filter(|p| is_hex64(p));
    match event.kind {
        1059 => {
            let Some(to) = p_tags.into_iter().next() else {
                return Vec::new();
            };
            if submitter.is_some_and(|s| s.eq_ignore_ascii_case(&to)) {
                return Vec::new();
            }
            vec![(to, Category::Dm)]
        }
        42 => {
            let author = event.pubkey.to_ascii_lowercase();
            let mut seen = HashSet::new();
            p_tags
                .filter(|p| *p != author && seen.insert(p.clone()))
                .take(MAX_TAGGED_RECIPIENTS)
                .map(|p| (p, Category::Reply))
                .collect()
        }
        _ => Vec::new(),
    }
}

/// How a push-service response should be treated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendOutcome {
    /// Accepted for delivery.
    Delivered,
    /// The subscription is gone (404/410): delete it.
    Gone,
    /// Anything else: count a failure.
    Failed,
}

/// Map a push-service HTTP status to an outcome (RFC 8030 §5).
pub fn classify_status(status: u16) -> SendOutcome {
    match status {
        200..=299 => SendOutcome::Delivered,
        404 | 410 => SendOutcome::Gone,
        _ => SendOutcome::Failed,
    }
}

/// Whether a push to a device last pushed at `last_push_at` is held back.
pub fn throttled(category: Category, last_push_at: u64, now_secs: u64) -> bool {
    let min = category.min_interval_secs();
    min > 0 && last_push_at != 0 && now_secs.saturating_sub(last_push_at) < min
}

// ---------------------------------------------------------------------------
// Fan-out plan + delivery
// ---------------------------------------------------------------------------

/// One device to wake, with the counter it should bump.
#[derive(Clone, Debug)]
pub struct PushJob {
    /// Subscription id.
    pub id: String,
    /// Push-service URL.
    pub endpoint: String,
    /// What the alert is about.
    pub category: Category,
    /// Deep link (`/go/<event id>`) for categories that have one.
    pub link: Option<String>,
    /// When this device was last pushed to (0 = never).
    pub last_push_at: u64,
}

/// Read the `PUSH_MAX_FANOUT` cap.
pub fn max_fanout(env: &Env) -> usize {
    env.var("PUSH_MAX_FANOUT")
        .ok()
        .and_then(|v| v.to_string().parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_MAX_FANOUT)
}

/// Whether Web Push is switched on (`PUSH_ENABLED="true"`).
pub fn enabled(env: &Env) -> bool {
    env.var("PUSH_ENABLED")
        .map(|v| v.to_string() == "true")
        .unwrap_or(false)
}

/// Load the VAPID identity from the environment, verifying that the configured
/// public key matches the private one. `None` (and a logged error) otherwise.
pub fn vapid_from_env(env: &Env) -> Option<VapidKeys> {
    let private = env.secret("VAPID_PRIVATE_KEY").ok()?.to_string();
    let subject = env.var("VAPID_SUBJECT").ok()?.to_string();
    let keys = match VapidKeys::from_private_b64(&private, &subject) {
        Ok(k) => k,
        Err(e) => {
            console_error!("push: invalid VAPID configuration: {e}");
            return None;
        }
    };
    if let Ok(public) = env.var("VAPID_PUBLIC_KEY") {
        if public.to_string().trim() != keys.public_key_b64() {
            console_error!("push: VAPID_PUBLIC_KEY does not match VAPID_PRIVATE_KEY");
            return None;
        }
    }
    Some(keys)
}

/// Bump counters for every job, then send the un-throttled ones. Runs inside the
/// Durable Object's `wait_until`, after the sender has its `OK`. Failures are
/// logged, never propagated.
pub async fn deliver(env: Env, jobs: Vec<PushJob>, bump_counters: bool) {
    if jobs.is_empty() {
        return;
    }
    let Some(vapid) = vapid_from_env(&env) else {
        return;
    };
    let db = match env.d1("DB") {
        Ok(db) => db,
        Err(e) => {
            console_error!("push: no DB binding: {e}");
            return;
        }
    };
    let now = auth::js_now_secs();

    // 1. Counters + deep links, one batch. (The cron trailing flush re-wakes
    //    devices whose counters were already bumped, so it skips this step.)
    let mut bumps = Vec::with_capacity(jobs.len());
    for job in jobs.iter().filter(|_| bump_counters) {
        let sql = bump_sql(job.category);
        let stmt = db.prepare(sql);
        let bound = if job.category.has_link() {
            stmt.bind(&[js_str(&job.id), js_str(job.link.as_deref().unwrap_or(""))])
        } else {
            stmt.bind(&[js_str(&job.id)])
        };
        match bound {
            Ok(s) => bumps.push(s),
            Err(e) => console_error!("push: bind failed: {e}"),
        }
    }
    if !bumps.is_empty() {
        if let Err(e) = db.batch(bumps).await {
            console_error!("push: counter batch failed: {e}");
        }
    }

    // 2. One wake-up per device (several categories collapse into one push).
    let mut per_device: HashMap<String, (String, u64, Vec<Category>)> = HashMap::new();
    for job in &jobs {
        let entry = per_device
            .entry(job.id.clone())
            .or_insert_with(|| (job.endpoint.clone(), job.last_push_at, Vec::new()));
        entry.2.push(job.category);
    }

    let mut auth_by_aud: HashMap<String, String> = HashMap::new();
    let mut results = Vec::new();
    for (id, (endpoint, last_push_at, cats)) in per_device {
        // Strongest category sets urgency/TTL/topic; the device is throttled
        // only when every category on it is.
        let Some(lead) = cats.iter().copied().min_by_key(|c| match c {
            Category::Dm => 0,
            Category::Reply => 1,
            Category::Topic => 2,
            Category::Post => 3,
        }) else {
            continue;
        };
        if cats.iter().all(|c| throttled(*c, last_push_at, now)) {
            continue;
        }
        let Ok(aud) = validate_endpoint(&endpoint) else {
            results.push((id, SendOutcome::Gone));
            continue;
        };
        let authorization = auth_by_aud
            .entry(aud.clone())
            .or_insert_with(|| vapid.authorization(&aud, now))
            .clone();
        let outcome = match send_empty_push(&endpoint, &authorization, lead).await {
            Ok(status) => classify_status(status),
            Err(e) => {
                console_error!("push: send to {id:.8} failed: {e}");
                SendOutcome::Failed
            }
        };
        results.push((id, outcome));
    }

    // 3. Book-keeping, one batch.
    let mut stmts = Vec::new();
    for (id, outcome) in &results {
        let stmt = match outcome {
            SendOutcome::Delivered => db
                .prepare(
                    "UPDATE push_subscriptions SET last_push_at = ?2, failures = 0 WHERE id = ?1",
                )
                .bind(&[js_str(id), js_f64(now as f64)]),
            SendOutcome::Gone => db
                .prepare("DELETE FROM push_subscriptions WHERE id = ?1")
                .bind(&[js_str(id)]),
            SendOutcome::Failed => db
                .prepare("UPDATE push_subscriptions SET failures = failures + 1 WHERE id = ?1")
                .bind(&[js_str(id)]),
        };
        if let Ok(s) = stmt {
            stmts.push(s);
        }
    }
    if let Ok(s) = db
        .prepare(SQL_DELETE_FAILED)
        .bind(&[js_f64(MAX_FAILURES as f64)])
    {
        stmts.push(s);
    }
    if let Err(e) = db.batch(stmts).await {
        console_error!("push: result batch failed: {e}");
    }
}

/// POST an empty, VAPID-signed push and return the push service's status.
async fn send_empty_push(endpoint: &str, authorization: &str, lead: Category) -> Result<u16> {
    let headers = Headers::new();
    headers.set("Authorization", authorization)?;
    headers.set("TTL", &lead.ttl_secs().to_string())?;
    headers.set("Urgency", lead.urgency())?;
    headers.set("Topic", lead.as_str())?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post).with_headers(headers);
    let req = Request::new_with_init(endpoint, &init)?;
    let resp = Fetch::Request(req).send().await?;
    Ok(resp.status_code())
}

/// Trailing flush, run from the cron tick: wake devices that still hold
/// undelivered counters because a burst was throttled. Without it the second of
/// two quick DMs would stay silent until the next event.
pub async fn flush_pending(env: &Env) {
    if !enabled(env) {
        return;
    }
    let Ok(db) = env.d1("DB") else { return };
    let cutoff = auth::js_now_secs().saturating_sub(FLUSH_AFTER_SECS);
    let Ok(stmt) = db
        .prepare(SQL_PENDING_DUE)
        .bind(&[js_f64(cutoff as f64), js_f64(FLUSH_BATCH as f64)])
    else {
        return;
    };
    let rows = match stmt.all().await {
        Ok(res) => res.results::<DueRow>().unwrap_or_default(),
        Err(e) => {
            console_error!("push: pending flush query failed: {e}");
            return;
        }
    };
    let jobs: Vec<PushJob> = rows.into_iter().map(DueRow::into_job).collect();
    if !jobs.is_empty() {
        console_log!("push: trailing flush waking {} device(s)", jobs.len());
        deliver(env.clone(), jobs, false).await;
    }
}

/// A device with undelivered counters, as the flush reads it.
#[derive(Deserialize)]
struct DueRow {
    id: String,
    endpoint: String,
    last_push_at: f64,
    pending_dm: f64,
    pending_reply: f64,
    pending_topic: f64,
    pending_post: f64,
}

impl DueRow {
    /// The wake-up job: the strongest pending category leads (urgency/topic).
    fn into_job(self) -> PushJob {
        let category = if self.pending_dm > 0.0 {
            Category::Dm
        } else if self.pending_reply > 0.0 {
            Category::Reply
        } else if self.pending_topic > 0.0 {
            Category::Topic
        } else {
            Category::Post
        };
        PushJob {
            id: self.id,
            endpoint: self.endpoint,
            category,
            link: None,
            last_push_at: self.last_push_at as u64,
        }
    }
}

/// Delete subscriptions the app has not refreshed for [`STALE_AFTER_SECS`].
/// Called from the cron tick; returns how many rows were removed (best effort).
pub async fn sweep_stale(env: &Env) {
    if !enabled(env) {
        return;
    }
    let Ok(db) = env.d1("DB") else { return };
    let cutoff = auth::js_now_secs().saturating_sub(STALE_AFTER_SECS);
    let stmt = db.prepare(SQL_SWEEP_STALE).bind(&[js_f64(cutoff as f64)]);
    match stmt {
        Ok(s) => match s.run().await {
            Ok(_) => console_log!("push: stale subscription sweep ran (cutoff {cutoff})"),
            Err(e) => console_error!("push: stale sweep failed: {e}"),
        },
        Err(e) => console_error!("push: stale sweep bind failed: {e}"),
    }
}

// ---------------------------------------------------------------------------
// Preference rows
// ---------------------------------------------------------------------------

/// `push_prefs` row as stored.
#[derive(Deserialize)]
pub struct PrefsRow {
    pubkey: String,
    replies: f64,
    dms: f64,
    new_topics: f64,
    new_posts: f64,
    muted_channels: String,
    quiet_start: Option<f64>,
    quiet_end: Option<f64>,
    tz_offset: f64,
}

impl PrefsRow {
    /// The owner.
    pub fn pubkey(&self) -> &str {
        &self.pubkey
    }

    /// Convert to the in-memory form; a corrupt `muted_channels` blob degrades
    /// to "none muted".
    pub fn into_prefs(self) -> PushPrefs {
        let quiet = match (self.quiet_start, self.quiet_end) {
            (Some(s), Some(e)) => Some(QuietHours {
                start_min: s as u16,
                end_min: e as u16,
                tz_offset_min: self.tz_offset as i16,
            }),
            _ => None,
        };
        PushPrefs {
            replies: self.replies != 0.0,
            dms: self.dms != 0.0,
            new_topics: self.new_topics != 0.0,
            new_posts: self.new_posts != 0.0,
            muted_channels: serde_json::from_str(&self.muted_channels).unwrap_or_default(),
            quiet,
        }
    }
}

/// `push_subscriptions` row as the fan-out reads it.
#[derive(Deserialize)]
pub struct SubRow {
    id: String,
    pubkey: String,
    endpoint: String,
    last_push_at: f64,
}

impl SubRow {
    /// Owner of the subscription.
    pub fn pubkey(&self) -> &str {
        &self.pubkey
    }

    /// Build the job for `category`/`link`.
    pub fn into_job(self, category: Category, link: Option<String>) -> PushJob {
        PushJob {
            id: self.id,
            endpoint: self.endpoint,
            category,
            link,
            last_push_at: self.last_push_at as u64,
        }
    }
}

/// Load preferences for `pubkeys` (missing rows are absent from the map; the
/// caller applies [`PushPrefs::default`]).
pub async fn load_prefs(env: &Env, pubkeys: &[String]) -> HashMap<String, PushPrefs> {
    let mut out = HashMap::new();
    if pubkeys.is_empty() {
        return out;
    }
    let Ok(db) = env.d1("DB") else { return out };
    let placeholders = (1..=pubkeys.len())
        .map(|i| format!("?{i}"))
        .collect::<Vec<_>>()
        .join(",");
    let sql = format!(
        "SELECT pubkey, replies, dms, new_topics, new_posts, muted_channels, quiet_start, quiet_end, tz_offset \
         FROM push_prefs WHERE pubkey IN ({placeholders})"
    );
    let binds: Vec<_> = pubkeys.iter().map(|p| js_str(p)).collect();
    let Ok(stmt) = db.prepare(sql).bind(&binds) else {
        return out;
    };
    if let Ok(res) = stmt.all().await {
        if let Ok(rows) = res.results::<PrefsRow>() {
            for row in rows {
                let pk = row.pubkey().to_string();
                out.insert(pk, row.into_prefs());
            }
        }
    }
    out
}

/// Pubkeys that have both a subscription and the given opt-in column set.
pub async fn broadcast_candidates(env: &Env, category: Category) -> Vec<String> {
    let column = match category {
        Category::Topic => "new_topics",
        Category::Post => "new_posts",
        _ => return Vec::new(),
    };
    let Ok(db) = env.d1("DB") else {
        return Vec::new();
    };
    let sql = format!(
        "SELECT pubkey FROM push_prefs WHERE {column} = 1 \
         AND EXISTS (SELECT 1 FROM push_subscriptions s WHERE s.pubkey = push_prefs.pubkey) LIMIT {MAX_BROADCAST_CANDIDATES}"
    );
    #[derive(Deserialize)]
    struct Pk {
        pubkey: String,
    }
    match db.prepare(sql).all().await {
        Ok(res) => res
            .results::<Pk>()
            .map(|rows| rows.into_iter().map(|r| r.pubkey).collect())
            .unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

/// Subscriptions belonging to any of `pubkeys`.
pub async fn load_subscriptions(env: &Env, pubkeys: &[String]) -> Vec<SubRow> {
    if pubkeys.is_empty() {
        return Vec::new();
    }
    let Ok(db) = env.d1("DB") else {
        return Vec::new();
    };
    let placeholders = (1..=pubkeys.len())
        .map(|i| format!("?{i}"))
        .collect::<Vec<_>>()
        .join(",");
    let sql = format!(
        "SELECT id, pubkey, endpoint, last_push_at FROM push_subscriptions WHERE pubkey IN ({placeholders})"
    );
    let binds: Vec<_> = pubkeys.iter().map(|p| js_str(p)).collect();
    let Ok(stmt) = db.prepare(sql).bind(&binds) else {
        return Vec::new();
    };
    match stmt.all().await {
        Ok(res) => res.results::<SubRow>().unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// HTTP handlers
// ---------------------------------------------------------------------------

fn respond(req: &Request, env: &Env, body: &serde_json::Value, status: u16) -> Result<Response> {
    crate::json_response(req, env, body, status)
}

/// Route `/api/push/<rest>`.
pub async fn handle(mut req: Request, env: &Env, rest: &str) -> Result<Response> {
    let method = req.method();
    if rest == "config" && method == Method::Get {
        return config(&req, env);
    }
    if !enabled(env) {
        return respond(
            &req,
            env,
            &json!({ "error": "push notifications are not enabled" }),
            404,
        );
    }
    let body = if method == Method::Post {
        let bytes = req.bytes().await?;
        if bytes.len() > MAX_BODY_BYTES {
            return respond(
                &req,
                env,
                &json!({ "error": "request body too large" }),
                413,
            );
        }
        bytes
    } else {
        Vec::new()
    };
    match (rest, method) {
        ("subscribe", Method::Post) => subscribe(&req, env, &body).await,
        ("unsubscribe", Method::Post) => unsubscribe(&req, env, &body).await,
        ("prefs", Method::Get) => prefs_get(&req, env).await,
        ("prefs", Method::Post) => prefs_set(&req, env, &body).await,
        ("drain", Method::Post) => drain(&req, env, &body).await,
        _ => respond(&req, env, &json!({ "error": "not found" }), 404),
    }
}

fn config(req: &Request, env: &Env) -> Result<Response> {
    let keys = if enabled(env) {
        vapid_from_env(env)
    } else {
        None
    };
    match keys {
        Some(k) => respond(
            req,
            env,
            &json!({ "enabled": true, "public_key": k.public_key_b64() }),
            200,
        ),
        None => respond(req, env, &json!({ "enabled": false }), 200),
    }
}

/// NIP-98-authenticate the request and return the caller's pubkey.
async fn authenticate(
    req: &Request,
    env: &Env,
    method: &str,
    body: Option<&[u8]>,
) -> std::result::Result<String, (serde_json::Value, u16)> {
    let header = req
        .headers()
        .get("Authorization")
        .ok()
        .flatten()
        .ok_or((json!({ "error": "NIP-98 authentication required" }), 401u16))?;
    let url = req
        .url()
        .map_err(|_| (json!({ "error": "bad request URL" }), 400u16))?
        .to_string();
    let token = auth::verify_nip98_replay(&header, &url, method, body, env)
        .await
        .map_err(|_| (json!({ "error": "Invalid NIP-98 token" }), 401u16))?;
    Ok(token.pubkey)
}

async fn is_whitelisted(env: &Env, pubkey: &str) -> bool {
    let Ok(db) = env.d1("DB") else { return false };
    let Ok(stmt) = db
        .prepare("SELECT 1 AS ok FROM whitelist WHERE pubkey = ?1")
        .bind(&[js_str(pubkey)])
    else {
        return false;
    };
    stmt.first::<serde_json::Value>(None)
        .await
        .ok()
        .flatten()
        .is_some()
}

#[derive(Deserialize)]
struct EndpointBody {
    endpoint: String,
}

async fn subscribe(req: &Request, env: &Env, body: &[u8]) -> Result<Response> {
    let pubkey = match authenticate(req, env, "POST", Some(body)).await {
        Ok(pk) => pk,
        Err((b, s)) => return respond(req, env, &b, s),
    };
    if !is_whitelisted(env, &pubkey).await {
        return respond(req, env, &json!({ "error": "Not authorized" }), 403);
    }
    let parsed: EndpointBody = match serde_json::from_slice(body) {
        Ok(b) => b,
        Err(_) => {
            return respond(
                req,
                env,
                &json!({ "error": "expected {\"endpoint\": ...}" }),
                400,
            )
        }
    };
    if let Err(e) = validate_endpoint(&parsed.endpoint) {
        return respond(req, env, &json!({ "error": e }), 400);
    }
    let Ok(token) = new_token() else {
        return respond(req, env, &json!({ "error": "entropy unavailable" }), 500);
    };
    let id = subscription_id(&parsed.endpoint);
    let now = auth::js_now_secs() as f64;
    let db = env.d1("DB")?;

    // Cap per member: evict the oldest beyond the limit (this endpoint's own
    // row is exempt, a re-subscribe must not evict itself).
    let evict = db.prepare(SQL_EVICT_OLDEST).bind(&[
        js_str(&pubkey),
        js_str(&id),
        js_f64((MAX_SUBS_PER_PUBKEY - 1) as f64),
    ])?;
    let upsert = db.prepare(SQL_UPSERT_SUBSCRIPTION).bind(&[
        js_str(&id),
        js_str(&pubkey),
        js_str(&parsed.endpoint),
        js_str(&sha256_hex(&token)),
        js_f64(now),
    ])?;
    db.batch(vec![evict, upsert]).await?;

    let prefs = load_prefs(env, std::slice::from_ref(&pubkey))
        .await
        .remove(&pubkey)
        .unwrap_or_default();
    respond(
        req,
        env,
        &json!({ "id": id, "token": token, "prefs": prefs }),
        200,
    )
}

async fn unsubscribe(req: &Request, env: &Env, body: &[u8]) -> Result<Response> {
    let pubkey = match authenticate(req, env, "POST", Some(body)).await {
        Ok(pk) => pk,
        Err((b, s)) => return respond(req, env, &b, s),
    };
    let parsed: EndpointBody = match serde_json::from_slice(body) {
        Ok(b) => b,
        Err(_) => {
            return respond(
                req,
                env,
                &json!({ "error": "expected {\"endpoint\": ...}" }),
                400,
            )
        }
    };
    let id = subscription_id(&parsed.endpoint);
    env.d1("DB")?
        .prepare("DELETE FROM push_subscriptions WHERE id = ?1 AND pubkey = ?2")
        .bind(&[js_str(&id), js_str(&pubkey)])?
        .run()
        .await?;
    respond(req, env, &json!({ "ok": true }), 200)
}

async fn prefs_get(req: &Request, env: &Env) -> Result<Response> {
    let pubkey = match authenticate(req, env, "GET", None).await {
        Ok(pk) => pk,
        Err((b, s)) => return respond(req, env, &b, s),
    };
    let prefs = load_prefs(env, std::slice::from_ref(&pubkey))
        .await
        .remove(&pubkey)
        .unwrap_or_default();
    respond(req, env, &json!({ "prefs": prefs }), 200)
}

async fn prefs_set(req: &Request, env: &Env, body: &[u8]) -> Result<Response> {
    let pubkey = match authenticate(req, env, "POST", Some(body)).await {
        Ok(pk) => pk,
        Err((b, s)) => return respond(req, env, &b, s),
    };
    let mut prefs: PushPrefs = match serde_json::from_slice(body) {
        Ok(p) => p,
        Err(_) => return respond(req, env, &json!({ "error": "invalid preferences" }), 400),
    };
    if let Err(e) = prefs.sanitize() {
        return respond(req, env, &json!({ "error": e }), 400);
    }
    let muted = serde_json::to_string(&prefs.muted_channels).unwrap_or_else(|_| "[]".into());
    let (qs, qe, tz) = match prefs.quiet {
        Some(q) => (
            js_f64(f64::from(q.start_min)),
            js_f64(f64::from(q.end_min)),
            js_f64(f64::from(q.tz_offset_min)),
        ),
        None => (
            wasm_bindgen::JsValue::NULL,
            wasm_bindgen::JsValue::NULL,
            js_f64(0.0),
        ),
    };
    env.d1("DB")?
        .prepare(SQL_UPSERT_PREFS)
        .bind(&[
            js_str(&pubkey),
            js_f64(f64::from(u8::from(prefs.replies))),
            js_f64(f64::from(u8::from(prefs.dms))),
            js_f64(f64::from(u8::from(prefs.new_topics))),
            js_f64(f64::from(u8::from(prefs.new_posts))),
            js_str(&muted),
            qs,
            qe,
            tz,
            js_f64(auth::js_now_secs() as f64),
        ])?
        .run()
        .await?;
    respond(req, env, &json!({ "prefs": prefs }), 200)
}

#[derive(Deserialize)]
struct DrainBody {
    id: String,
    token: String,
}

#[derive(Deserialize)]
struct DrainRow {
    token_hash: String,
    pending_dm: f64,
    pending_reply: f64,
    pending_topic: f64,
    pending_post: f64,
    link_reply: Option<String>,
    link_topic: Option<String>,
    link_post: Option<String>,
}

/// Hand the service worker its pending counters and clear them.
async fn drain(req: &Request, env: &Env, body: &[u8]) -> Result<Response> {
    let parsed: DrainBody = match serde_json::from_slice(body) {
        Ok(b) => b,
        Err(_) => return respond(req, env, &json!({ "error": "expected {id, token}" }), 400),
    };
    let db = env.d1("DB")?;
    let row = db
        .prepare(SQL_DRAIN_SELECT)
        .bind(&[js_str(&parsed.id)])?
        .first::<DrainRow>(None)
        .await?;
    let Some(row) = row else {
        return respond(req, env, &json!({ "error": "unknown subscription" }), 404);
    };
    if !digests_equal(&row.token_hash, &sha256_hex(&parsed.token)) {
        return respond(req, env, &json!({ "error": "invalid token" }), 401);
    }
    // Subtract what was read (not "= 0") so a push that lands mid-drain is kept.
    db.prepare(SQL_DRAIN_SUBTRACT)
        .bind(&[
            js_str(&parsed.id),
            js_f64(row.pending_dm),
            js_f64(row.pending_reply),
            js_f64(row.pending_topic),
            js_f64(row.pending_post),
        ])?
        .run()
        .await?;
    respond(
        req,
        env,
        &json!({
            "dm": row.pending_dm as u64,
            "reply": row.pending_reply as u64,
            "topic": row.pending_topic as u64,
            "post": row.pending_post as u64,
            "link_reply": row.link_reply,
            "link_topic": row.link_topic,
            "link_post": row.link_post,
        }),
        200,
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Verifier, VerifyingKey};

    const PK_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const PK_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const PK_C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const CHAN: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    fn event(kind: u64, pubkey: &str, tags: Vec<Vec<&str>>) -> NostrEvent {
        NostrEvent {
            id: "1".repeat(64),
            pubkey: pubkey.into(),
            created_at: 1_700_000_000,
            kind,
            tags: tags
                .into_iter()
                .map(|t| t.into_iter().map(String::from).collect())
                .collect(),
            content: String::new(),
            sig: "00".repeat(64),
        }
    }

    // -- VAPID ---------------------------------------------------------------

    /// RFC 8292 section 2, Figure 1: the specification's own example JWT and
    /// the public key it names. Our verification path must accept it, which
    /// proves the JWT layout (`header.payload.r||s`, base64url, ES256) is the
    /// one push services expect.
    #[test]
    fn rfc8292_example_jwt_verifies_under_its_published_key() {
        let jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJodHRwczovL3B1c2guZXhhbXBsZS5uZXQiLCJleHAiOjE0NTM1MjM3NjgsInN1YiI6Im1haWx0bzpwdXNoQGV4YW1wbGUuY29tIn0.i3CYb7t4xfxCDquptFOepC9GAu_HLGkMlMuCGSK2rpiUfnK9ojFwDXb1JrErtmysazNjjvW2L9OkSSHzvoD1oA";
        let k = "BA1Hxzyi1RUM1b5wjxsn7nGxAszw2u61m164i3MrAIxHF6YK5h4SDYic-dRuU_RCPCfA5aq9ojSwk5Y2EmClBPs";
        let (signing_input, sig_b64) = jwt.rsplit_once('.').unwrap();
        let vk = VerifyingKey::from_sec1_bytes(&B64URL.decode(k).unwrap()).unwrap();
        let sig = Signature::from_slice(&B64URL.decode(sig_b64).unwrap()).unwrap();
        vk.verify(signing_input.as_bytes(), &sig)
            .expect("RFC 8292 example JWT must verify");
    }

    const TEST_PRIVATE: &str = "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw";

    #[test]
    fn signed_jwt_verifies_and_carries_the_claims() {
        let keys = VapidKeys::from_private_b64(TEST_PRIVATE, "mailto:ops@example.com").unwrap();
        let jwt = keys.sign_jwt("https://fcm.googleapis.com", 1_000);
        let (signing_input, sig_b64) = jwt.rsplit_once('.').unwrap();
        let vk =
            VerifyingKey::from_sec1_bytes(&B64URL.decode(keys.public_key_b64()).unwrap()).unwrap();
        let sig = Signature::from_slice(&B64URL.decode(sig_b64).unwrap()).unwrap();
        vk.verify(signing_input.as_bytes(), &sig).unwrap();

        let (header_b64, payload_b64) = signing_input.split_once('.').unwrap();
        let header: serde_json::Value =
            serde_json::from_slice(&B64URL.decode(header_b64).unwrap()).unwrap();
        assert_eq!(header, json!({ "typ": "JWT", "alg": "ES256" }));
        let claims: serde_json::Value =
            serde_json::from_slice(&B64URL.decode(payload_b64).unwrap()).unwrap();
        assert_eq!(claims["aud"], "https://fcm.googleapis.com");
        assert_eq!(claims["sub"], "mailto:ops@example.com");
        assert_eq!(claims["exp"], 1_000 + VAPID_JWT_TTL_SECS);
        const {
            assert!(
                VAPID_JWT_TTL_SECS <= 24 * 60 * 60,
                "RFC 8292 caps exp at 24 h"
            )
        };
    }

    #[test]
    fn public_key_is_an_uncompressed_p256_point() {
        let keys = VapidKeys::from_private_b64(TEST_PRIVATE, "mailto:ops@example.com").unwrap();
        let raw = B64URL.decode(keys.public_key_b64()).unwrap();
        assert_eq!(raw.len(), 65);
        assert_eq!(raw[0], 0x04);
    }

    #[test]
    fn authorization_header_has_the_vapid_shape() {
        let keys =
            VapidKeys::from_private_b64(TEST_PRIVATE, "https://example.com/contact").unwrap();
        let h = keys.authorization("https://web.push.apple.com", 5);
        assert!(h.starts_with("vapid t="));
        assert!(h.contains(&format!(", k={}", keys.public_key_b64())));
    }

    #[test]
    fn bad_vapid_config_is_refused() {
        assert!(VapidKeys::from_private_b64("not base64 !!", "mailto:a@b.c").is_err());
        assert!(
            VapidKeys::from_private_b64("AAAA", "mailto:a@b.c").is_err(),
            "wrong length"
        );
        assert!(
            VapidKeys::from_private_b64(TEST_PRIVATE, "ops@example.com").is_err(),
            "subject scheme"
        );
    }

    // -- endpoint allow-list -------------------------------------------------

    #[test]
    fn known_push_services_are_accepted() {
        for (url, aud) in [
            (
                "https://fcm.googleapis.com/fcm/send/abc",
                "https://fcm.googleapis.com",
            ),
            (
                "https://updates.push.services.mozilla.com/wpush/v2/abc",
                "https://updates.push.services.mozilla.com",
            ),
            (
                "https://web.push.apple.com/QWxs",
                "https://web.push.apple.com",
            ),
            (
                "https://wns2-par02p.notify.windows.com/w/?token=x",
                "https://wns2-par02p.notify.windows.com",
            ),
        ] {
            assert_eq!(validate_endpoint(url).as_deref(), Ok(aud), "{url}");
        }
    }

    #[test]
    fn hostile_endpoints_are_refused() {
        for url in [
            "http://fcm.googleapis.com/x",
            "https://evil.example.com/x",
            "https://fcm.googleapis.com.evil.example/x",
            "https://notfcm.googleapis.com.attacker.io/x",
            "https://xfcm.googleapis.com/x",
            "https://user:pw@fcm.googleapis.com/x",
            "https://fcm.googleapis.com:8443/x",
            "https://127.0.0.1/x",
            "https://169.254.169.254/latest/meta-data",
            "ftp://fcm.googleapis.com/x",
            "not a url",
            "",
        ] {
            assert!(validate_endpoint(url).is_err(), "{url} must be refused");
        }
        let long = format!(
            "https://fcm.googleapis.com/{}",
            "a".repeat(MAX_ENDPOINT_LEN)
        );
        assert!(validate_endpoint(&long).is_err());
    }

    // -- tokens --------------------------------------------------------------

    #[test]
    fn token_hashing_is_sha256_and_comparison_is_exact() {
        // FIPS 180-2 test vector for "abc".
        assert_eq!(
            sha256_hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(digests_equal(&sha256_hex("t"), &sha256_hex("t")));
        assert!(!digests_equal(&sha256_hex("t"), &sha256_hex("u")));
        assert!(!digests_equal("ab", "abc"));
    }

    #[test]
    fn tokens_are_256_bit_and_distinct() {
        let (a, b) = (new_token().unwrap(), new_token().unwrap());
        assert_ne!(a, b);
        assert_eq!(B64URL.decode(&a).unwrap().len(), 32);
    }

    #[test]
    fn subscription_id_is_stable_per_endpoint() {
        assert_eq!(
            subscription_id("https://fcm.googleapis.com/a"),
            subscription_id("https://fcm.googleapis.com/a")
        );
        assert_ne!(
            subscription_id("https://fcm.googleapis.com/a"),
            subscription_id("https://fcm.googleapis.com/b")
        );
    }

    // -- recipient classification --------------------------------------------

    #[test]
    fn a_dm_wrap_alerts_its_recipient() {
        let wrap = event(1059, &"e".repeat(64), vec![vec!["p", PK_B]]);
        assert_eq!(
            explicit_recipients(&wrap, Some(PK_A)),
            vec![(PK_B.to_string(), Category::Dm)]
        );
    }

    #[test]
    fn the_sender_copy_of_a_dm_alerts_nobody() {
        // NIP-17 sender copy: wrapped to the sender and submitted by the sender.
        let self_copy = event(1059, &"e".repeat(64), vec![vec!["p", PK_A]]);
        assert!(explicit_recipients(&self_copy, Some(PK_A)).is_empty());
        // The same wrap submitted by someone else is a real DM to A.
        assert_eq!(explicit_recipients(&self_copy, Some(PK_B)).len(), 1);
        // Unauthenticated submission cannot prove it is a self-copy.
        assert_eq!(explicit_recipients(&self_copy, None).len(), 1);
    }

    #[test]
    fn replies_alert_p_tagged_members_but_never_the_author() {
        let post = event(
            42,
            PK_A,
            vec![
                vec!["e", CHAN, "", "root"],
                vec!["p", PK_A],
                vec!["p", PK_B],
                vec!["p", PK_B],
                vec!["p", "short"],
            ],
        );
        assert_eq!(
            explicit_recipients(&post, Some(PK_A)),
            vec![(PK_B.to_string(), Category::Reply)]
        );
    }

    #[test]
    fn tagged_recipients_are_capped() {
        let tags: Vec<Vec<String>> = (0..50)
            .map(|i| vec!["p".to_string(), format!("{i:064x}")])
            .collect();
        let mut post = event(42, PK_A, vec![]);
        post.tags = tags;
        assert_eq!(
            explicit_recipients(&post, None).len(),
            MAX_TAGGED_RECIPIENTS
        );
    }

    #[test]
    fn other_kinds_alert_nobody_by_name() {
        assert!(explicit_recipients(&event(1, PK_A, vec![vec!["p", PK_B]]), None).is_empty());
        assert!(explicit_recipients(&event(40, PK_A, vec![vec!["p", PK_B]]), None).is_empty());
    }

    #[test]
    fn channel_prefers_the_root_marker() {
        let reply = event(
            42,
            PK_A,
            vec![vec!["e", PK_C, "", "reply"], vec!["e", CHAN, "", "root"]],
        );
        assert_eq!(channel_of(&reply).as_deref(), Some(CHAN));
        let bare = event(42, PK_A, vec![vec!["e", CHAN]]);
        assert_eq!(channel_of(&bare).as_deref(), Some(CHAN));
        assert_eq!(channel_of(&event(42, PK_A, vec![vec!["e", "xyz"]])), None);
    }

    #[test]
    fn broadcast_categories() {
        assert_eq!(
            broadcast_category(&event(40, PK_A, vec![])),
            Some(Category::Topic)
        );
        assert_eq!(
            broadcast_category(&event(42, PK_A, vec![])),
            Some(Category::Post)
        );
        assert_eq!(broadcast_category(&event(1059, PK_A, vec![])), None);
    }

    // -- delivery policy -----------------------------------------------------

    #[test]
    fn push_service_statuses_map_to_outcomes() {
        assert_eq!(classify_status(201), SendOutcome::Delivered);
        assert_eq!(classify_status(404), SendOutcome::Gone);
        assert_eq!(classify_status(410), SendOutcome::Gone);
        assert_eq!(classify_status(429), SendOutcome::Failed);
        assert_eq!(classify_status(500), SendOutcome::Failed);
    }

    #[test]
    fn every_category_is_throttled_background_chatter_most() {
        // Addressed alerts get a short floor (5 s) so a stranger's burst of
        // gift wraps cannot buzz a phone 30 times a second; the trailing flush
        // delivers what the floor held back.
        assert!(throttled(Category::Dm, 1_000, 1_001));
        assert!(throttled(Category::Reply, 1_000, 1_004));
        assert!(!throttled(Category::Dm, 1_000, 1_005));
        assert!(throttled(Category::Post, 1_000, 1_030));
        assert!(!throttled(Category::Post, 1_000, 1_060));
        assert!(!throttled(Category::Post, 0, 5), "never pushed before");
    }

    #[test]
    fn schema_matches_the_migration_file() {
        let migration = include_str!("../migrations/0010_push.sql");
        for table in ["push_subscriptions", "push_prefs"] {
            assert!(migration.contains(&format!("CREATE TABLE IF NOT EXISTS {table}")));
        }
        assert!(PUSH_SCHEMA_SQL
            .iter()
            .any(|s| s.contains("push_subscriptions")));
        assert!(PUSH_SCHEMA_SQL.iter().any(|s| s.contains("push_prefs")));
    }

    // -- SQL, run against SQLite (the engine D1 is built on) ------------------

    fn db() -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        for ddl in PUSH_SCHEMA_SQL {
            conn.execute(ddl, []).unwrap();
        }
        conn
    }

    fn subscribe_row(conn: &rusqlite::Connection, id: &str, pubkey: &str, at: i64, token: &str) {
        conn.execute(
            SQL_UPSERT_SUBSCRIPTION,
            rusqlite::params![
                id,
                pubkey,
                format!("https://fcm.googleapis.com/{id}"),
                sha256_hex(token),
                at
            ],
        )
        .unwrap();
    }

    fn count(conn: &rusqlite::Connection, sql: &str) -> i64 {
        conn.query_row(sql, [], |r| r.get(0)).unwrap()
    }

    #[test]
    fn resubscribing_rotates_the_token_and_clears_counters() {
        let conn = db();
        subscribe_row(&conn, "s1", PK_A, 100, "old");
        conn.execute(&bump_sql(Category::Dm), rusqlite::params!["s1"])
            .unwrap();
        conn.execute(
            &bump_sql(Category::Reply),
            rusqlite::params!["s1", "/go/abc"],
        )
        .unwrap();
        conn.execute("UPDATE push_subscriptions SET failures = 3", [])
            .unwrap();

        subscribe_row(&conn, "s1", PK_B, 200, "new");
        let (owner, hash, refreshed, dm, reply, failures): (String, String, i64, i64, i64, i64) = conn
            .query_row(
                "SELECT pubkey, token_hash, refreshed_at, pending_dm, pending_reply, failures FROM push_subscriptions WHERE id = 's1'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
            )
            .unwrap();
        assert_eq!(
            owner, PK_B,
            "a browser handed to another member is re-owned"
        );
        assert_eq!(hash, sha256_hex("new"), "token rotated");
        assert_eq!(refreshed, 200);
        assert_eq!(
            (dm, reply, failures),
            (0, 0, 0),
            "the previous owner's counters never leak"
        );
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM push_subscriptions"), 1);
    }

    #[test]
    fn a_member_keeps_at_most_ten_devices_and_the_newest_survive() {
        let conn = db();
        for i in 0..MAX_SUBS_PER_PUBKEY {
            subscribe_row(&conn, &format!("d{i}"), PK_A, 100 + i as i64, "t");
        }
        subscribe_row(&conn, "other", PK_B, 1, "t");
        // The 11th device registers: evict first (exempting itself), then upsert.
        conn.execute(
            SQL_EVICT_OLDEST,
            rusqlite::params![PK_A, "d10", (MAX_SUBS_PER_PUBKEY - 1) as i64],
        )
        .unwrap();
        subscribe_row(&conn, "d10", PK_A, 500, "t");

        assert_eq!(
            count(
                &conn,
                &format!("SELECT COUNT(*) FROM push_subscriptions WHERE pubkey = '{PK_A}'")
            ),
            MAX_SUBS_PER_PUBKEY as i64
        );
        assert_eq!(
            count(
                &conn,
                "SELECT COUNT(*) FROM push_subscriptions WHERE id = 'd0'"
            ),
            0,
            "oldest evicted"
        );
        assert_eq!(
            count(
                &conn,
                "SELECT COUNT(*) FROM push_subscriptions WHERE id = 'd10'"
            ),
            1
        );
        assert_eq!(
            count(
                &conn,
                "SELECT COUNT(*) FROM push_subscriptions WHERE id = 'other'"
            ),
            1,
            "other members untouched"
        );
    }

    #[test]
    fn re_registering_at_the_cap_does_not_evict_itself() {
        let conn = db();
        for i in 0..MAX_SUBS_PER_PUBKEY {
            subscribe_row(&conn, &format!("d{i}"), PK_A, 100 + i as i64, "t");
        }
        conn.execute(
            SQL_EVICT_OLDEST,
            rusqlite::params![PK_A, "d0", (MAX_SUBS_PER_PUBKEY - 1) as i64],
        )
        .unwrap();
        subscribe_row(&conn, "d0", PK_A, 900, "t2");
        assert_eq!(
            count(
                &conn,
                &format!("SELECT COUNT(*) FROM push_subscriptions WHERE pubkey = '{PK_A}'")
            ),
            MAX_SUBS_PER_PUBKEY as i64,
            "refreshing an existing device must not cost another device"
        );
    }

    #[test]
    fn counters_accumulate_and_the_drain_subtracts_exactly_what_it_read() {
        let conn = db();
        subscribe_row(&conn, "s1", PK_A, 100, "tok");
        for _ in 0..3 {
            conn.execute(&bump_sql(Category::Dm), rusqlite::params!["s1"])
                .unwrap();
        }
        conn.execute(
            &bump_sql(Category::Reply),
            rusqlite::params!["s1", "/go/first"],
        )
        .unwrap();
        conn.execute(
            &bump_sql(Category::Reply),
            rusqlite::params!["s1", "/go/second"],
        )
        .unwrap();

        type Drained = (
            String,
            i64,
            i64,
            i64,
            i64,
            Option<String>,
            Option<String>,
            Option<String>,
        );
        let read = |conn: &rusqlite::Connection| -> Drained {
            conn.query_row(SQL_DRAIN_SELECT, rusqlite::params!["s1"], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                ))
            })
            .unwrap()
        };
        let d = read(&conn);
        assert_eq!(d.0, sha256_hex("tok"));
        assert_eq!((d.1, d.2, d.3, d.4), (3, 2, 0, 0));
        assert_eq!(d.5.as_deref(), Some("/go/second"), "newest link wins");

        // A push lands between the SELECT and the UPDATE: it must survive.
        conn.execute(&bump_sql(Category::Dm), rusqlite::params!["s1"])
            .unwrap();
        conn.execute(
            SQL_DRAIN_SUBTRACT,
            rusqlite::params!["s1", d.1, d.2, d.3, d.4],
        )
        .unwrap();
        let after = read(&conn);
        assert_eq!((after.1, after.2, after.3, after.4), (1, 0, 0, 0));
    }

    #[test]
    fn drain_never_goes_negative() {
        let conn = db();
        subscribe_row(&conn, "s1", PK_A, 1, "t");
        conn.execute(SQL_DRAIN_SUBTRACT, rusqlite::params!["s1", 5, 5, 5, 5])
            .unwrap();
        assert_eq!(count(&conn, "SELECT pending_dm FROM push_subscriptions"), 0);
    }

    #[test]
    fn bump_sql_only_names_the_category_column() {
        assert!(!bump_sql(Category::Dm).contains("link_"));
        for c in [Category::Reply, Category::Topic, Category::Post] {
            let sql = bump_sql(c);
            assert!(sql.contains(&format!("pending_{0} = pending_{0} + 1", c.as_str())));
            assert!(sql.contains(&format!("link_{} = ?2", c.as_str())));
        }
    }

    #[test]
    fn failures_and_staleness_sweep() {
        let conn = db();
        subscribe_row(&conn, "fresh", PK_A, 1_000, "t");
        subscribe_row(&conn, "stale", PK_A, 10, "t");
        subscribe_row(&conn, "flaky", PK_B, 1_000, "t");
        for _ in 0..MAX_FAILURES {
            conn.execute(
                "UPDATE push_subscriptions SET failures = failures + 1 WHERE id = 'flaky'",
                [],
            )
            .unwrap();
        }
        conn.execute(SQL_DELETE_FAILED, rusqlite::params![MAX_FAILURES])
            .unwrap();
        assert_eq!(
            count(
                &conn,
                "SELECT COUNT(*) FROM push_subscriptions WHERE id = 'flaky'"
            ),
            0
        );
        conn.execute(SQL_SWEEP_STALE, rusqlite::params![500])
            .unwrap();
        assert_eq!(
            count(
                &conn,
                "SELECT COUNT(*) FROM push_subscriptions WHERE id = 'stale'"
            ),
            0
        );
        assert_eq!(
            count(
                &conn,
                "SELECT COUNT(*) FROM push_subscriptions WHERE id = 'fresh'"
            ),
            1
        );
    }

    #[test]
    fn prefs_upsert_round_trips_through_the_row_type() {
        let conn = db();
        let write = |p: &PushPrefs, at: i64| {
            let (qs, qe, tz) = match p.quiet {
                Some(q) => (
                    Some(i64::from(q.start_min)),
                    Some(i64::from(q.end_min)),
                    i64::from(q.tz_offset_min),
                ),
                None => (None, None, 0),
            };
            conn.execute(
                SQL_UPSERT_PREFS,
                rusqlite::params![
                    PK_A,
                    i64::from(p.replies),
                    i64::from(p.dms),
                    i64::from(p.new_topics),
                    i64::from(p.new_posts),
                    serde_json::to_string(&p.muted_channels).unwrap(),
                    qs,
                    qe,
                    tz,
                    at
                ],
            )
            .unwrap();
        };
        let read = || -> PushPrefs {
            let (replies, dms, topics, posts, muted, qs, qe, tz): (f64, f64, f64, f64, String, Option<f64>, Option<f64>, f64) =
                conn.query_row(
                    "SELECT replies, dms, new_topics, new_posts, muted_channels, quiet_start, quiet_end, tz_offset FROM push_prefs WHERE pubkey = ?1",
                    [PK_A],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?)),
                )
                .unwrap();
            PrefsRow {
                pubkey: PK_A.into(),
                replies,
                dms,
                new_topics: topics,
                new_posts: posts,
                muted_channels: muted,
                quiet_start: qs,
                quiet_end: qe,
                tz_offset: tz,
            }
            .into_prefs()
        };

        let first = PushPrefs {
            replies: false,
            dms: true,
            new_topics: true,
            new_posts: true,
            muted_channels: vec![CHAN.into()],
            quiet: Some(QuietHours {
                start_min: 1320,
                end_min: 420,
                tz_offset_min: -300,
            }),
        };
        write(&first, 1);
        assert_eq!(read(), first);

        let second = PushPrefs::default();
        write(&second, 2);
        assert_eq!(read(), second, "second write replaces, never duplicates");
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM push_prefs"), 1);
    }

    #[test]
    fn a_corrupt_muted_blob_degrades_to_nothing_muted() {
        let row = PrefsRow {
            pubkey: PK_A.into(),
            replies: 1.0,
            dms: 1.0,
            new_topics: 0.0,
            new_posts: 0.0,
            muted_channels: "not json".into(),
            quiet_start: None,
            quiet_end: None,
            tz_offset: 0.0,
        };
        assert!(row.into_prefs().muted_channels.is_empty());
    }

    #[test]
    fn the_trailing_flush_finds_only_devices_with_stale_undelivered_counters() {
        let conn = db();
        subscribe_row(&conn, "quiet", PK_A, 1, "t");
        subscribe_row(&conn, "recent", PK_A, 1, "t");
        subscribe_row(&conn, "due", PK_B, 1, "t");
        subscribe_row(&conn, "never", PK_B, 1, "t");
        conn.execute(&bump_sql(Category::Dm), rusqlite::params!["recent"])
            .unwrap();
        conn.execute(
            "UPDATE push_subscriptions SET last_push_at = 990 WHERE id = 'recent'",
            [],
        )
        .unwrap();
        conn.execute(
            &bump_sql(Category::Reply),
            rusqlite::params!["due", "/go/x"],
        )
        .unwrap();
        conn.execute(
            "UPDATE push_subscriptions SET last_push_at = 100 WHERE id = 'due'",
            [],
        )
        .unwrap();
        conn.execute(
            &bump_sql(Category::Post),
            rusqlite::params!["never", "/go/y"],
        )
        .unwrap();

        let cutoff = 1_000 - FLUSH_AFTER_SECS as i64;
        let mut stmt = conn.prepare(SQL_PENDING_DUE).unwrap();
        let ids: Vec<String> = stmt
            .query_map(rusqlite::params![cutoff, 10], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        // "quiet" has nothing pending; "recent" pushed 10 s ago (inside the
        // window); "due" and "never" (last_push_at 0) are owed a wake-up.
        assert_eq!(
            ids,
            vec!["never".to_string(), "due".to_string()],
            "oldest push first"
        );
    }

    #[test]
    fn a_flush_job_leads_with_the_strongest_pending_category() {
        let row = |dm, reply, topic, post| DueRow {
            id: "s".into(),
            endpoint: "https://fcm.googleapis.com/x".into(),
            last_push_at: 5.0,
            pending_dm: dm,
            pending_reply: reply,
            pending_topic: topic,
            pending_post: post,
        };
        assert_eq!(row(1.0, 1.0, 1.0, 1.0).into_job().category, Category::Dm);
        assert_eq!(row(0.0, 2.0, 1.0, 1.0).into_job().category, Category::Reply);
        assert_eq!(row(0.0, 0.0, 3.0, 1.0).into_job().category, Category::Topic);
        assert_eq!(row(0.0, 0.0, 0.0, 9.0).into_job().category, Category::Post);
        assert!(
            row(0.0, 0.0, 0.0, 1.0).into_job().link.is_none(),
            "counters already hold the links"
        );
    }
}
