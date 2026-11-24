//! nostr-bbs Search Worker (Rust)
//!
//! Cloudflare Workers-based vector search with:
//! - In-memory cosine k-NN over 384-dim embeddings
//! - RVF binary format persistence to R2
//! - id↔label mapping in KV
//! - NIP-98 authenticated ingest
//! - Semantic embeddings via Cloudflare Workers AI (bge-small-en-v1.5),
//!   with a deterministic hash fallback when the AI binding is absent
//!
//! ## Architecture
//!
//! - `lib.rs`   -- HTTP router, CORS, entry point
//! - `store.rs` -- In-memory vector store, RVF serialization
//! - `embed.rs` -- Workers AI BGE-small embeddings + hash fallback
//! - `auth.rs`  -- NIP-98 admin verification

mod auth;
mod embed;
mod index_v2;
mod shard;
mod store;

use embed::DIM;
use serde::Deserialize;
use worker::*;

// ---------------------------------------------------------------------------
// CORS
// ---------------------------------------------------------------------------

fn allowed_origins(env: &Env) -> Vec<String> {
    env.var("ALLOWED_ORIGINS")
        .or_else(|_| env.var("ALLOWED_ORIGIN"))
        .map(|v| v.to_string())
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn cors_origin(req: &Request, env: &Env) -> String {
    let origins = allowed_origins(env);
    let origin = req
        .headers()
        .get("Origin")
        .ok()
        .flatten()
        .unwrap_or_default();
    if origins.iter().any(|o| o == &origin) {
        origin
    } else {
        origins.into_iter().next().unwrap_or_default()
    }
}

fn cors_headers(req: &Request, env: &Env) -> Headers {
    let headers = Headers::new();
    headers
        .set("Access-Control-Allow-Origin", &cors_origin(req, env))
        .ok();
    headers
        .set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        .ok();
    headers
        .set(
            "Access-Control-Allow-Headers",
            "Content-Type, Authorization",
        )
        .ok();
    headers.set("Access-Control-Max-Age", "86400").ok();
    headers.set("Vary", "Origin").ok();
    headers
}

fn json_response(
    req: &Request,
    env: &Env,
    body: &serde_json::Value,
    status: u16,
) -> Result<Response> {
    let json_str = serde_json::to_string(body).map_err(|e| Error::RustError(e.to_string()))?;
    let headers = cors_headers(req, env);
    headers.set("Content-Type", "application/json").ok();
    Ok(Response::ok(json_str)?
        .with_status(status)
        .with_headers(headers))
}

// ---------------------------------------------------------------------------
// Request/Response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct SearchRequest {
    #[serde(default)]
    embedding: Vec<f32>,
    #[serde(default)]
    query: Option<String>,
    #[serde(default = "default_k")]
    k: usize,
    #[serde(default, rename = "minScore")]
    min_score: f32,
    /// Optional model identity of a caller-supplied `embedding`. When the
    /// caller sends a raw vector (rather than `query` text we embed
    /// ourselves) this is the only way we can verify it was produced by the
    /// same model as the index. See `check_model_match`.
    #[serde(default)]
    model: Option<String>,
}

fn default_k() -> usize {
    10
}

/// Whether a stored vector may be returned to an anonymous `/search` caller.
///
/// **Fail-closed by design, and deliberately left that way.** Membership of
/// `public_labels` is the only thing that makes a vector visible: a label that
/// was never ingested with `public: true` — or whose visibility predates the
/// `publicLabels` set entirely — is invisible. The alternative (default-visible)
/// would turn any ingest bug, any legacy mapping, or any dropped field into a
/// disclosure of private-channel content, which is a far worse failure than an
/// empty result set. The correct place to fix "search returns nothing" is the
/// ingest caller declaring `public: true`, never a relaxation here.
fn is_search_visible(public_labels: &std::collections::HashSet<u64>, label: u64) -> bool {
    public_labels.contains(&label)
}

/// How many extra candidates to pull out of the k-NN store per requested hit.
///
/// `VectorStore::search` truncates to its `k` *before* this module applies the
/// public-visibility filter, so asking for exactly `k` and then filtering can
/// only ever shrink the result set — in an index where the top-`k` neighbours
/// happen to be private, a perfectly good public match ranked `k+1` is never
/// considered and search returns fewer hits (or none) for no visible reason.
/// Over-fetching gives the filter something to consume.
const OVERFETCH_FACTOR: usize = 4;

/// Absolute ceiling on the over-fetch, so a large `k` cannot make the worker
/// score-and-sort an unbounded slice on every request. `k` is already clamped to
/// 100 by the handler, so this only ever binds at the top of that range.
const OVERFETCH_CAP: usize = 400;

/// Candidate count to request from the store for a caller-requested `k`.
///
/// Never returns less than `k` (a cap below `k` would reintroduce the starvation
/// it exists to prevent) and saturates rather than overflowing.
fn overfetch_k(k: usize) -> usize {
    k.saturating_mul(OVERFETCH_FACTOR).min(OVERFETCH_CAP).max(k)
}

/// Apply the public-visibility filter to over-fetched candidates, then cut to
/// the `k` the caller actually asked for.
///
/// Order matters and is the whole point: filter first, truncate second. The
/// candidates arrive already sorted by descending score, and both operations
/// preserve that order, so the result is the top `k` *visible* hits.
fn visible_top_k(
    candidates: &[(u64, f32)],
    public_labels: &std::collections::HashSet<u64>,
    k: usize,
) -> Vec<(u64, f32)> {
    candidates
        .iter()
        .filter(|(label, _)| is_search_visible(public_labels, *label))
        .take(k)
        .copied()
        .collect()
}

/// Trim a caller-supplied query and reject it if nothing is left.
///
/// A whitespace-only query is not "a query with no results" — it is not a query
/// at all. Without the trim it slips past the empty check, `embed_texts` yields
/// an all-zero vector for it (see `embed.rs`), and cosine similarity against an
/// all-zero query is `0.0` for every stored vector. Because `minScore` defaults
/// to `0.0` and `VectorStore::search` compares with `>=`, that returns the
/// ENTIRE index, ranked arbitrarily, as "matches". Rejecting here is the only
/// place that costs nothing and cannot be bypassed by a stale client.
fn normalise_query(raw: &str) -> Option<&str> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

/// Reject an ingest batch in which no entry is publicly searchable.
///
/// Vectors ingested with `public: false` are filtered out of every `/search`
/// response by [`is_search_visible`], so a batch that is entirely private
/// consumes R2/KV storage and index scan time while being unreachable by
/// construction. In practice this has always meant a caller bug (a hardcoded
/// `public: false` at the call site), and the old behaviour — accept, persist,
/// report `accepted: N` — made that bug indistinguishable from success.
///
/// Returns the caller-facing error body when the batch should be refused, or
/// `None` when it may proceed. Deliberate un-publishing (re-ingesting known ids
/// as private to retract them) is still supported: the caller opts in with
/// `"allowPrivate": true`, which is an explicit statement of intent rather than
/// an accident.
fn all_private_ingest_rejection(
    total_valid: u32,
    public_count: u32,
    allow_private: bool,
) -> Option<serde_json::Value> {
    if allow_private || total_valid == 0 || public_count > 0 {
        return None;
    }
    Some(serde_json::json!({
        "error": "Every entry in this batch is non-public",
        "detail": "Vectors ingested with `public: false` are filtered out of all /search \
                   results, so this batch would index content that no search can ever \
                   return. Set `public: true` on entries posted to publicly readable \
                   channels. If you really intend to index (or retract) private-only \
                   vectors, resend with `\"allowPrivate\": true`.",
        "entries": total_valid,
        "public": public_count,
    }))
}

#[derive(Deserialize)]
struct IngestEntry {
    id: String,
    embedding: Vec<f32>,
    /// Whether this event is safe to expose through anonymous search. Missing
    /// visibility fails closed for legacy callers.
    #[serde(default)]
    public: bool,
    /// Zone the event belongs to (`[a-z0-9-]{1,32}`); routes it to that
    /// zone's shards. Defaults to the unzoned shard set. Search is still
    /// gated only by `public`.
    #[serde(default)]
    zone: Option<String>,
}

#[derive(Deserialize)]
struct IngestRequest {
    entries: Vec<IngestEntry>,
    /// Model identity that produced `entries[].embedding`. Recorded alongside
    /// the index so a later query with a different embedding model can be
    /// detected instead of silently producing meaningless cosine scores.
    /// Defaults to the worker's own currently-active embedding model when
    /// omitted (back-compat with callers that pre-date this field).
    #[serde(default)]
    model: Option<String>,
    /// Explicit opt-in to an all-private batch. Off by default so the common
    /// case -- a caller that forgot to set `public` -- is caught rather than
    /// silently indexing vectors that `/search` can never return. See
    /// [`all_private_ingest_rejection`].
    #[serde(default, rename = "allowPrivate")]
    allow_private: bool,
}

/// Sentinel used when the model that produced a set of vectors is not known
/// (e.g. entries persisted before this field existed). Comparisons never
/// fail loudly against "unknown" on either side, since there is nothing
/// verifiable to compare.
const MODEL_UNKNOWN: &str = "unknown";

/// Compare the model tag recorded at index time against the model tag for
/// the current query. Returns `Err` with a caller-facing JSON error body
/// when both sides are known and disagree -- mixing vectors from different
/// embedding models produces cosine scores that are numerically well-formed
/// but semantically meaningless, so this must fail loudly rather than
/// silently returning garbage rankings.
fn check_model_match(indexed: &str, queried: &str) -> std::result::Result<(), serde_json::Value> {
    if indexed == MODEL_UNKNOWN || queried == MODEL_UNKNOWN || indexed == queried {
        return Ok(());
    }
    Err(serde_json::json!({
        "error": "Embedding model mismatch between index and query",
        "indexModel": indexed,
        "queryModel": queried,
        "detail": "The stored vectors were embedded with a different model than this query. \
                   Cosine scores across embedding spaces are not comparable. Re-embed the \
                   query with the index's model, or re-ingest the index with the query's model.",
    }))
}

#[derive(Deserialize)]
struct EmbedRequest {
    text: Option<String>,
    texts: Option<Vec<String>>,
}

// ---------------------------------------------------------------------------
// Store lifecycle (R2 + KV)
// ---------------------------------------------------------------------------

fn store_key(env: &Env) -> String {
    env.var("RVF_STORE_KEY")
        .map(|v| v.to_string())
        .unwrap_or_else(|_| "nostr-bbs.rvf".to_string())
}

/// First-stage candidates rescored exactly per query (`SEARCH_RESCORE`, default
/// [`index_v2::DEFAULT_RESCORE`], clamped to 10..=1000).
fn rescore_n(env: &Env) -> usize {
    env.var("SEARCH_RESCORE")
        .ok()
        .and_then(|v| v.to_string().trim().parse::<usize>().ok())
        .unwrap_or(index_v2::DEFAULT_RESCORE)
        .clamp(10, 1000)
}

/// Vector count of a v1 store from its first segment header only (64 bytes),
/// so `/status` never downloads the whole object.
async fn v1_count(env: &Env, key: &str) -> Result<usize> {
    let obj = env
        .bucket("VECTORS")?
        .get(key)
        .range(Range::OffsetWithLength { offset: 0, length: 64 })
        .execute()
        .await?;
    let Some(body) = obj.as_ref().and_then(|o| o.body()) else {
        return Ok(0);
    };
    Ok(store::rvf_count_from_first_header(&body.bytes().await?))
}

/// Fetch the raw RVF bytes from R2 (empty when the object does not exist).
async fn load_store_bytes(env: &Env) -> Result<Vec<u8>> {
    let bucket = env.bucket("VECTORS")?;
    match bucket.get(store_key(env)).execute().await? {
        // Sprint v9 D5: never panic on a missing body. R2 can in principle
        // return an object with no body (e.g. zero-length write race or
        // bucket inconsistency); surface a typed worker::Error instead so
        // the caller returns a 5xx rather than crashing the isolate.
        Some(obj) => obj
            .body()
            .ok_or_else(|| worker::Error::RustError("R2 object missing body".into()))?
            .bytes()
            .await,
        None => Ok(Vec::new()),
    }
}

/// Load id↔label mapping (+ recorded index-time model identity) from KV.
async fn load_mapping(
    env: &Env,
) -> Result<(
    std::collections::HashMap<String, u64>,
    std::collections::HashMap<u64, String>,
    u64,
    String,
    std::collections::HashSet<u64>,
)> {
    let store_key = env
        .var("RVF_STORE_KEY")
        .map(|v| v.to_string())
        .unwrap_or_else(|_| "nostr-bbs.rvf".to_string());

    let kv = env.kv("SEARCH_CONFIG")?;
    let mapping_key = format!("{store_key}:mapping");

    if let Some(json_str) = kv.get(&mapping_key).text().await? {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&json_str) {
            let next = val["next"].as_u64().unwrap_or(1);
            // Mappings persisted before this field existed have no "model"
            // key; treat that as unknown rather than assuming a value.
            let model = val["model"].as_str().unwrap_or(MODEL_UNKNOWN).to_string();
            let mut id_to_label = std::collections::HashMap::new();
            let mut label_to_id = std::collections::HashMap::new();
            let public_labels = val["publicLabels"]
                .as_array()
                .map(|labels| labels.iter().filter_map(|label| label.as_u64()).collect())
                .unwrap_or_default();

            if let Some(pairs) = val["pairs"].as_array() {
                for pair in pairs {
                    if let (Some(id), Some(label)) = (pair[0].as_str(), pair[1].as_u64()) {
                        id_to_label.insert(id.to_string(), label);
                        label_to_id.insert(label, id.to_string());
                    }
                }
            }

            return Ok((id_to_label, label_to_id, next, model, public_labels));
        }
    }

    Ok((
        std::collections::HashMap::new(),
        std::collections::HashMap::new(),
        1,
        MODEL_UNKNOWN.to_string(),
        std::collections::HashSet::new(),
    ))
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn handle_search(req: &Request, env: &Env) -> Result<Response> {
    // No public search (sealed-search design): zone1 gets no search, encrypted
    // zones are searched in the browser, and server mode for unencrypted
    // private zones (Phase 3) will add the cohort check. Until then: admins.
    if let Some(denied) = require_admin(req, env).await? {
        return Ok(denied);
    }
    let mut req_clone = req.clone()?;
    let body: SearchRequest = match req_clone.json().await {
        Ok(b) => b,
        Err(_) => {
            return json_response(
                req,
                env,
                &serde_json::json!({ "error": "Invalid request. Provide 'embedding' (384-dim vector) or 'query' (text string)." }),
                400,
            );
        }
    };

    // Track the model that actually produced `embedding` so we can verify
    // it matches the model the index was built with (see `check_model_match`).
    let (embedding, query_model): (Vec<f32>, String) = if !body.embedding.is_empty() {
        // Caller supplied a raw vector; its model is only known if they told
        // us via the optional `model` field.
        (
            body.embedding,
            body.model.unwrap_or_else(|| MODEL_UNKNOWN.to_string()),
        )
    } else if let Some(ref raw_text) = body.query {
        // Trim BEFORE the empty check -- see `normalise_query` for why an
        // untrimmed "   " would otherwise return the entire index.
        let Some(text) = normalise_query(raw_text) else {
            return json_response(
                req,
                env,
                &serde_json::json!({ "error": "Empty query string" }),
                400,
            );
        };
        // Embed the *trimmed* query with the same model used at ingest time so
        // the query vector lives in the same space as the stored vectors.
        let text = text.to_string();
        let (mut embs, model) = embed::embed_texts(env, std::slice::from_ref(&text)).await;
        (embs.pop().unwrap_or_default(), model.to_string())
    } else {
        return json_response(
            req,
            env,
            &serde_json::json!({ "error": "Provide 'embedding' (384-dim vector) or 'query' (text string)." }),
            400,
        );
    };

    if embedding.len() != DIM {
        return json_response(
            req,
            env,
            &serde_json::json!({ "error": format!("Expected {DIM}-dim embedding") }),
            400,
        );
    }

    let k = body.k.clamp(1, 100);
    let key = store_key(env);

    // RVF v2 (sharded, quantised) when a manifest exists; otherwise the v1
    // single-object store, read in place.
    let (results, label_to_id, total_vectors) = match index_v2::search(
        env,
        &key,
        &embedding,
        k,
        body.min_score,
        rescore_n(env),
    )
    .await?
    {
        Some(out) => {
            if let Err(err_body) = check_model_match(&out.model, &query_model) {
                console_error!(
                    "Search worker: embedding model mismatch (index={}, query={query_model})",
                    out.model
                );
                return json_response(req, env, &err_body, 409);
            }
            // v2 hits are already visible (the first stage skips non-public
            // rows) and cut to k; give them positional labels so the response
            // code below stays shared with v1.
            let mut label_to_id = std::collections::HashMap::new();
            let mut results = Vec::with_capacity(out.hits.len());
            for (i, (id, score)) in out.hits.into_iter().enumerate() {
                label_to_id.insert(i as u64, id);
                results.push((i as u64, score));
            }
            (results, label_to_id, out.total)
        }
        None => {
            // Search the persisted bytes in place: decoding them into a
            // VectorStore first doubled peak memory for no benefit.
            let store_bytes = load_store_bytes(env).await?;
            let total_vectors = store::rvf_count(&store_bytes);
            if total_vectors == 0 {
                return json_response(
                    req,
                    env,
                    &serde_json::json!({ "results": [], "totalVectors": 0 }),
                    200,
                );
            }
            let (_, label_to_id, _, indexed_model, public_labels) = load_mapping(env).await?;
            // Fail loudly rather than returning numerically valid but
            // semantically meaningless cosine scores across mismatched spaces.
            if let Err(err_body) = check_model_match(&indexed_model, &query_model) {
                console_error!(
                    "Search worker: embedding model mismatch (index={indexed_model}, query={query_model})"
                );
                return json_response(req, env, &err_body, 409);
            }
            // Over-fetch candidates, THEN apply the public-visibility filter,
            // THEN cut to `k` (filtering a set already truncated to `k` could
            // only shrink it).
            let candidates =
                store::search_rvf(&store_bytes, &embedding, overfetch_k(k), body.min_score);
            drop(store_bytes);
            (visible_top_k(&candidates, &public_labels, k), label_to_id, total_vectors)
        }
    };

    json_response(
        req,
        env,
        &search_body(&results, &label_to_id, total_vectors),
        200,
    )
}

/// Build the `/search` 200 body.
fn search_body(
    results: &[(u64, f32)],
    label_to_id: &std::collections::HashMap<u64, String>,
    total_vectors: usize,
) -> serde_json::Value {
    let results_json: Vec<serde_json::Value> = results
        .iter()
        .map(|(label, score)| {
            let id = label_to_id
                .get(label)
                .cloned()
                .unwrap_or_else(|| label.to_string());
            serde_json::json!({
                "id": id,
                "distance": 1.0 - score,
                "score": score,
            })
        })
        .collect();
    serde_json::json!({
        "results": results_json,
        "totalVectors": total_vectors,
        "engine": "rvf-rust",
        "dimensions": DIM,
    })
}

async fn handle_embed(req: &Request, env: &Env) -> Result<Response> {
    // The browser embeds queries on the device; only operators may spend
    // embedding capacity here.
    if let Some(denied) = require_admin(req, env).await? {
        return Ok(denied);
    }
    let mut req_clone = req.clone()?;
    let body: EmbedRequest = req_clone.json().await?;

    let texts: Vec<String> = match (body.texts, body.text) {
        (Some(texts), _) => texts,
        (None, Some(text)) => vec![text],
        (None, None) => {
            return json_response(
                req,
                env,
                &serde_json::json!({ "error": "Missing text or texts field" }),
                400,
            );
        }
    };

    if texts.is_empty() {
        return json_response(
            req,
            env,
            &serde_json::json!({ "error": "Missing text or texts field" }),
            400,
        );
    }
    if texts.len() > 100 {
        return json_response(
            req,
            env,
            &serde_json::json!({ "error": "Maximum 100 texts per request" }),
            400,
        );
    }

    let (embeddings, model) = embed::embed_texts(env, &texts).await;
    let semantic = model != embed::MODEL_LABEL_FALLBACK;

    json_response(
        req,
        env,
        &serde_json::json!({
            "embeddings": embeddings,
            "dimensions": DIM,
            "model": model,
            "semantic": semantic,
            "note": if model == embed::MODEL_LABEL_SEMANTIC {
                "Cloudflare Workers AI bge-small-en-v1.5 (384-dim, L2-normalized)."
            } else if semantic {
                "OpenAI-compatible EMBED_URL backend (384-dim, L2-normalized)."
            } else {
                "Hash-based fallback embedding (AI binding unavailable). Vectors are NOT semantic."
            },
        }),
        200,
    )
}

async fn handle_ingest(req: &Request, env: &Env) -> Result<Response> {
    // NIP-98 admin auth
    let url = req.url()?;
    let request_url = url.to_string();
    let auth_header = req.headers().get("Authorization")?;
    let mut req_clone = req.clone()?;
    let raw_body = req_clone.bytes().await?;

    if let Err((err_body, status)) = auth::require_nip98_admin(
        auth_header.as_deref(),
        &request_url,
        "POST",
        Some(&raw_body),
        env,
    )
    .await
    {
        return json_response(req, env, &err_body, status);
    }

    let body: IngestRequest =
        serde_json::from_slice(&raw_body).map_err(|e| Error::RustError(e.to_string()))?;

    if body.entries.is_empty() {
        return json_response(
            req,
            env,
            &serde_json::json!({ "error": "Missing entries array" }),
            400,
        );
    }

    // The caller-declared model for these entries' embeddings; falls back to
    // this worker's currently-active embedding model for older callers that
    // pre-date the `model` field (best-effort -- matches historical behavior
    // where ingested vectors were assumed to come from whatever `/embed`
    // would currently produce).
    let ingest_model = body
        .model
        .clone()
        .unwrap_or_else(|| embed::active_model_label(env));

    // Refuse a batch that could never be found before mutating anything. The
    // check runs on the caller's declared flags (not on post-insert state) so
    // nothing is written to R2/KV when it fails.
    let valid_entries = body.entries.iter().filter(|e| entry_valid(e)).count() as u32;
    let public_entries = body
        .entries
        .iter()
        .filter(|e| entry_valid(e) && e.public)
        .count() as u32;
    if let Some(err_body) =
        all_private_ingest_rejection(valid_entries, public_entries, body.allow_private)
    {
        console_warn!(
            "Search worker: ingest rejected, all {valid_entries} entries non-public \
             (they would be invisible to /search). Resend with allowPrivate:true if deliberate."
        );
        return json_response(req, env, &err_body, 400);
    }

    let mut rejected = 0u32;
    let mut entries: Vec<index_v2::NewEntry> = Vec::with_capacity(body.entries.len());
    for entry in &body.entries {
        if !entry_valid(entry) {
            rejected += 1;
            continue;
        }
        let mut vec = [0f32; DIM];
        vec.copy_from_slice(&entry.embedding);
        entries.push(index_v2::NewEntry {
            id: entry.id.clone(),
            zone: entry.zone.clone().unwrap_or_else(|| shard::DEFAULT_ZONE.to_string()),
            public: entry.public,
            vec,
        });
    }
    let accepted = entries.len() as u32;
    drop(body);
    if entries.is_empty() {
        // Nothing valid to store: answer without touching the index (a commit
        // here would rewrite the manifest for no change).
        return json_response(
            req,
            env,
            &serde_json::json!({ "accepted": 0, "rejected": rejected, "public": 0, "engine": "rvf-rust" }),
            200,
        );
    }

    // RVF v2: copy-on-write shards + conditional manifest commit. The first
    // v2 ingest migrates an existing v1 store (object + KV mapping).
    let store_key = store_key(env);
    // Write-attempt nonce for shard keys: uniqueness, not secrecy, is needed.
    let nonce = format!(
        "{:x}{:08x}",
        js_sys::Date::now() as u64,
        (js_sys::Math::random() * f64::from(u32::MAX)) as u32
    );
    let outcome = match index_v2::ingest(env, &store_key, &ingest_model, entries, &nonce, || v1_rows(env)).await {
        Ok(o) => o,
        Err(index_v2::IngestError::ModelMismatch(indexed)) => {
            console_error!(
                "Search worker: ingest rejected, embedding model mismatch (index={indexed}, ingest={ingest_model})"
            );
            let err_body = check_model_match(&indexed, &ingest_model)
                .err()
                .unwrap_or_else(|| serde_json::json!({ "error": "Embedding model mismatch" }));
            return json_response(req, env, &err_body, 409);
        }
        Err(index_v2::IngestError::Conflict) => {
            return json_response(
                req,
                env,
                &serde_json::json!({ "error": "Concurrent ingest; retry" }),
                409,
            );
        }
        Err(index_v2::IngestError::Worker(e)) => return Err(e),
    };


    json_response(
        req,
        env,
        &serde_json::json!({
            "accepted": accepted,
            "rejected": rejected,
            // Surfaced so a caller can see at a glance how many of its entries
            // are actually reachable by /search.
            "public": public_entries,
            "totalVectors": outcome.total,
            "shards": outcome.shards,
            "migratedFromV1": outcome.migrated,
            "engine": "rvf-rust",
            "format": shard::MANIFEST_FORMAT,
            "model": ingest_model,
        }),
        200,
    )
}

/// Whether an ingest entry can be stored: non-empty id that fits a v2 row,
/// a 384-dim vector, and (if given) a valid zone name.
fn entry_valid(e: &IngestEntry) -> bool {
    !e.id.is_empty()
        && e.id.len() <= shard::MAX_ID_LEN
        && e.embedding.len() == DIM
        && e.zone.as_deref().is_none_or(shard::valid_zone)
}

/// Rows of the v1 store (R2 object + KV mapping), for migration to v2.
/// Vectors whose label has no id in the mapping cannot be addressed and are
/// skipped; ids too long for a v2 row are skipped too.
async fn v1_rows(env: &Env) -> Result<Vec<shard::Row>> {
    let bytes = load_store_bytes(env).await?;
    if store::rvf_count(&bytes) == 0 {
        return Ok(Vec::new());
    }
    let (_, label_to_id, _, _, public_labels) = load_mapping(env).await?;
    Ok(store::rvf_entries(&bytes)
        .filter_map(|(label, vec)| {
            let id = label_to_id.get(&label)?;
            (id.len() <= shard::MAX_ID_LEN).then(|| shard::Row {
                id: id.clone(),
                public: public_labels.contains(&label),
                vec,
            })
        })
        .collect())
}

/// NIP-98 admin check for a request (body hashed when present). `Ok(None)`
/// lets the request through; `Ok(Some(resp))` is the 401/403 to return.
async fn require_admin(req: &Request, env: &Env) -> Result<Option<Response>> {
    let url = req.url()?.to_string();
    let auth = req.headers().get("Authorization")?;
    let mut clone = req.clone()?;
    let body = clone.bytes().await.unwrap_or_default();
    let method = req.method().to_string();
    match auth::require_nip98_admin(
        auth.as_deref(),
        &url,
        &method,
        (!body.is_empty()).then_some(body.as_slice()),
        env,
    )
    .await
    {
        Ok(_) => Ok(None),
        Err((err_body, status)) => Ok(Some(json_response(req, env, &err_body, status)?)),
    }
}

/// `POST /admin/purge` (NIP-98 admin): delete every stored vector, id
/// mapping and snippet — the v1 object, its KV mapping and snippet keys, and
/// every v2 shard and manifest (security review H2: locking `/search` does
/// not remove what was already indexed).
async fn handle_purge(req: &Request, env: &Env) -> Result<Response> {
    if let Some(denied) = require_admin(req, env).await? {
        return Ok(denied);
    }
    let key = store_key(env);
    let bucket = env.bucket("VECTORS")?;
    let mut deleted = 0u32;
    if bucket.head(key.clone()).await?.is_some() {
        bucket.delete(key.clone()).await?;
        deleted += 1;
    }
    let prefix = format!("{key}.v2/");
    let mut cursor: Option<String> = None;
    loop {
        let mut list = bucket.list().prefix(prefix.clone()).limit(1000);
        if let Some(c) = cursor.take() {
            list = list.cursor(c);
        }
        let page = list.execute().await?;
        for o in page.objects() {
            bucket.delete(o.key()).await?;
            deleted += 1;
        }
        match page.cursor() {
            Some(c) if page.truncated() => cursor = Some(c),
            _ => break,
        }
    }
    let kv = env.kv("SEARCH_CONFIG")?;
    for k in [format!("{key}:mapping"), format!("{key}:snippets")] {
        kv.delete(&k).await?;
    }
    console_log!("Search worker: purged {deleted} R2 objects and KV mapping/snippets");
    json_response(req, env, &serde_json::json!({ "purged": deleted, "kv": ["mapping", "snippets"] }), 200)
}

async fn handle_status(req: &Request, env: &Env) -> Result<Response> {
    let key = store_key(env);
    let (total_vectors, format, shards) = match index_v2::manifest(env, &key, false).await? {
        Some(m) => (m.total(), shard::MANIFEST_FORMAT, m.shards.len()),
        None => (v1_count(env, &key).await?, "rvf-v1", 0),
    };

    // Report the model actually in use, not a hardcoded string. When the
    // Workers AI binding is configured we serve real BGE-small embeddings;
    // otherwise the worker degrades to the deterministic hash fallback.
    let ai_live = embed::ai_binding_available(env);
    let model = embed::active_model_label(env);
    let semantic = model != embed::MODEL_LABEL_FALLBACK;
    let embed_backend = if embed::openai_config(env).is_some() {
        "openai-compat"
    } else if ai_live {
        "workers-ai"
    } else {
        "hash"
    };

    json_response(
        req,
        env,
        &serde_json::json!({
            "status": "healthy",
            "totalVectors": total_vectors,
            "dimensions": DIM,
            "metric": "cosine",
            "model": model,
            "semantic": semantic,
            "aiBinding": ai_live,
            "embedBackend": embed_backend,
            "engine": "rvf-rust",
            "runtime": "workers-rs",
            "format": format,
            "shards": shards,
        }),
        200,
    )
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

// Invoked via wasm-bindgen glue generated by the `#[event(fetch)]` macro;
// appears unreferenced on native (non-wasm32) builds.
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    nostr_bbs_rate_limit::ensure_replay_schema(&env, "REPLAY_DB").await;

    // CORS preflight
    if req.method() == Method::Options {
        return Ok(Response::empty()?
            .with_status(204)
            .with_headers(cors_headers(&req, &env)));
    }

    // Rate limit: 100 requests per 60 seconds per IP
    let ip = nostr_bbs_rate_limit::client_ip(&req);
    if !nostr_bbs_rate_limit::check_rate_limit(&env, "SEARCH_CONFIG", &ip, 100, 60).await {
        return json_response(
            &req,
            &env,
            &serde_json::json!({ "error": "Too many requests" }),
            429,
        );
    }

    let url = req.url()?;
    let path = url.path();

    index_v2::take_r2_ops();
    let result = route(&req, &env, path).await;
    match result {
        Ok(mut resp) => {
            // Measurement aid, off unless SEARCH_DEBUG_OPS=1: R2 calls made
            // through the v2 index during this request. The counter is per
            // isolate, so concurrent requests on one isolate blur it.
            let ops = index_v2::take_r2_ops();
            if env.var("SEARCH_DEBUG_OPS").map(|v| v.to_string() == "1").unwrap_or(false) {
                let _ = resp.headers_mut().set("X-Search-R2-Ops", &ops.to_string());
            }
            Ok(resp)
        }
        Err(e) => {
            console_error!("Search worker error: {e}");
            let msg = e.to_string();
            if msg.contains("JSON")
                || msg.contains("json")
                || msg.contains("Syntax")
                || msg.contains("missing field")
                || msg.contains("invalid type")
                || msg.contains("expected")
            {
                json_response(
                    &req,
                    &env,
                    &serde_json::json!({ "error": "Invalid JSON body" }),
                    400,
                )
            } else {
                json_response(
                    &req,
                    &env,
                    &serde_json::json!({ "error": "Internal error" }),
                    500,
                )
            }
        }
    }
}

async fn route(req: &Request, env: &Env, path: &str) -> Result<Response> {
    let method = req.method();

    // Health / status
    if (path == "/health" || path == "/status" || path == "/") && method == Method::Get {
        return handle_status(req, env).await;
    }

    // Search
    if path == "/search" && method == Method::Post {
        return handle_search(req, env).await;
    }

    // Embed
    if path == "/embed" && method == Method::Post {
        return handle_embed(req, env).await;
    }

    // Ingest (NIP-98 admin only)
    if path == "/ingest" && method == Method::Post {
        return handle_ingest(req, env).await;
    }

    // Purge every stored vector (NIP-98 admin only)
    if path == "/admin/purge" && method == Method::Post {
        return handle_purge(req, env).await;
    }

    json_response(req, env, &serde_json::json!({ "error": "Not found" }), 404)
}

// ---------------------------------------------------------------------------
// Cron keep-warm
// ---------------------------------------------------------------------------

// Invoked via wasm-bindgen glue generated by the `#[event(scheduled)]` macro;
// appears unreferenced on native (non-wasm32) builds.
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
#[event(scheduled)]
async fn scheduled(_event: ScheduledEvent, env: Env, _ctx: ScheduleContext) {
    // Touch R2 to keep the connection warm. A HEAD, not a full GET: the
    // object is ~1.5 KB per vector, and this fires every 5 minutes.
    if let Ok(bucket) = env.bucket("VECTORS") {
        let _ = bucket.head(store_key(&env)).await;
    }
}

#[cfg(test)]
mod model_match_tests {
    use super::*;

    #[test]
    fn matching_models_pass() {
        assert!(check_model_match("bge-small-en-v1.5", "bge-small-en-v1.5").is_ok());
    }

    #[test]
    fn differing_known_models_fail_loudly() {
        let err = check_model_match("bge-small-en-v1.5", "hash-fallback-v1")
            .expect_err("mismatched known models must be rejected");
        assert_eq!(
            err["error"],
            "Embedding model mismatch between index and query"
        );
        assert_eq!(err["indexModel"], "bge-small-en-v1.5");
        assert_eq!(err["queryModel"], "hash-fallback-v1");
    }

    #[test]
    fn unknown_index_model_does_not_block() {
        // Entries persisted before the model field existed: nothing to
        // verify against, so the happy path proceeds.
        assert!(check_model_match(MODEL_UNKNOWN, "bge-small-en-v1.5").is_ok());
    }

    #[test]
    fn unknown_query_model_does_not_block() {
        // Caller supplied a raw embedding without declaring its model:
        // cannot verify, so we let it through rather than blocking all
        // legacy/unlabeled callers.
        assert!(check_model_match("bge-small-en-v1.5", MODEL_UNKNOWN).is_ok());
    }

    #[test]
    fn both_unknown_does_not_block() {
        assert!(check_model_match(MODEL_UNKNOWN, MODEL_UNKNOWN).is_ok());
    }

    /// Build `n` descending-score candidates with labels `0..n`, the shape
    /// `VectorStore::search` returns.
    fn candidates(n: u64) -> Vec<(u64, f32)> {
        (0..n).map(|i| (i, 1.0 - (i as f32) * 0.001)).collect()
    }

    #[test]
    fn overfetch_pulls_more_candidates_than_requested() {
        assert_eq!(overfetch_k(10), 40);
        assert_eq!(overfetch_k(1), 4);
        // Capped so a large k cannot make the worker sort an unbounded slice...
        assert_eq!(overfetch_k(100), 400);
        // ...but the cap can never drop below k itself.
        assert!(overfetch_k(500) >= 500);
        // And it must not overflow on an absurd input: the multiply saturates,
        // the cap clamps to OVERFETCH_CAP, and the final `.max(k)` restores k.
        assert_eq!(overfetch_k(usize::MAX), usize::MAX);
    }

    #[test]
    fn overfetch_then_filter_returns_k_visible_hits() {
        // 40 candidates, only every 4th public. Asking the store for exactly
        // k=10 would have yielded 10 candidates of which just 2-3 survive the
        // filter; over-fetching 4x gives the filter enough to return a full k.
        let public: std::collections::HashSet<u64> = (0..40).filter(|l| l % 4 == 0).collect();
        let all = candidates(overfetch_k(10) as u64);
        let hits = visible_top_k(&all, &public, 10);
        assert_eq!(hits.len(), 10, "public filter starved the result set");
        assert!(hits.iter().all(|(l, _)| l % 4 == 0));
        // Still ordered by descending score, and headed by the best public hit.
        assert_eq!(hits[0].0, 0);
        assert!(hits.windows(2).all(|w| w[0].1 >= w[1].1));
    }

    #[test]
    fn visible_top_k_filters_before_truncating() {
        // Labels 0..9 are all private, 10..19 public. A filter applied AFTER a
        // truncate-to-10 would return nothing; filtering first returns 10.
        let public: std::collections::HashSet<u64> = (10..20).collect();
        let hits = visible_top_k(&candidates(20), &public, 10);
        assert_eq!(hits.len(), 10);
        assert_eq!(hits[0].0, 10);
    }

    #[test]
    fn visible_top_k_returns_empty_when_nothing_is_public() {
        let public = std::collections::HashSet::new();
        assert!(visible_top_k(&candidates(40), &public, 10).is_empty());
    }

    #[test]
    fn whitespace_only_query_is_rejected() {
        // The bug: only `""` was rejected, so "   " reached the embedder, became
        // an all-zero vector, scored 0.0 against everything and -- with the
        // default minScore of 0.0 and a `>=` comparison -- matched the whole index.
        assert_eq!(normalise_query("   "), None);
        assert_eq!(normalise_query("\t\n  \r"), None);
        assert_eq!(normalise_query(""), None);
    }

    #[test]
    fn non_empty_query_is_trimmed_not_rejected() {
        assert_eq!(normalise_query("  hello world  "), Some("hello world"));
        assert_eq!(normalise_query("a"), Some("a"));
    }

    #[test]
    fn all_private_batch_is_rejected_with_a_warning_body() {
        let err = all_private_ingest_rejection(3, 0, false)
            .expect("an all-private batch must be refused");
        assert_eq!(err["error"], "Every entry in this batch is non-public");
        assert_eq!(err["entries"], 3);
        assert_eq!(err["public"], 0);
        assert!(err["detail"].as_str().unwrap().contains("allowPrivate"));
    }

    #[test]
    fn mixed_and_opted_in_batches_are_accepted() {
        // One public entry is enough -- the batch is not unreachable.
        assert!(all_private_ingest_rejection(3, 1, false).is_none());
        // Deliberate private-only ingest / retraction opts in explicitly.
        assert!(all_private_ingest_rejection(3, 0, true).is_none());
        // Nothing valid to judge: the existing "Missing entries" / per-entry
        // rejection paths own that case.
        assert!(all_private_ingest_rejection(0, 0, false).is_none());
    }

    #[test]
    fn anonymous_results_fail_closed_without_explicit_public_visibility() {
        let mut public = std::collections::HashSet::new();
        assert!(!is_search_visible(&public, 7));
        public.insert(7);
        assert!(is_search_visible(&public, 7));
        assert!(!is_search_visible(&public, 8));
    }
}

