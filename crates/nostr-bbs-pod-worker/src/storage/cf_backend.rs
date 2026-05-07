//! Cloudflare R2 + KV storage adapter.
//!
//! Wraps `worker::Bucket` (R2 object store) into a simple async interface
//! used by the provisioning and resource-serving layers. This adapter is the
//! pod-worker replacement for solid-pod-rs's `Storage` trait: same
//! conceptual contract, implemented with Cloudflare Worker bindings that
//! compile to WASM.
//!
//! Key layout: `pods/{pubkey_hex}{resource_path}` in R2.

use worker::{Bucket, Error as WorkerError, HttpMetadata};

/// Cloudflare R2-backed pod storage.
///
/// One instance is created per incoming Worker request from the bound `PODS`
/// R2 bucket. KV operations go directly through `worker::kv::KvStore` where
/// needed; this type handles R2.
pub struct CloudflareStorage {
    pub bucket: Bucket,
}

impl CloudflareStorage {
    /// Wrap an R2 `Bucket` binding.
    pub fn new(bucket: Bucket) -> Self {
        Self { bucket }
    }

    /// Fetch an object body as bytes.
    ///
    /// Returns `Ok(None)` when the key does not exist.
    pub async fn get_object(&self, key: &str) -> Result<Option<Vec<u8>>, WorkerError> {
        match self.bucket.get(key).execute().await? {
            Some(obj) => {
                let body = obj
                    .body()
                    .ok_or_else(|| WorkerError::RustError("R2 object has no body".into()))?;
                Ok(Some(body.bytes().await?))
            }
            None => Ok(None),
        }
    }

    /// Write an object. Creates or overwrites.
    pub async fn put_object(
        &self,
        key: &str,
        data: Vec<u8>,
        content_type: &str,
    ) -> Result<(), WorkerError> {
        self.bucket
            .put(key, data)
            .http_metadata(HttpMetadata {
                content_type: Some(content_type.to_string()),
                ..Default::default()
            })
            .execute()
            .await?;
        Ok(())
    }

    /// Delete an object. Succeeds even if the key does not exist.
    pub async fn delete_object(&self, key: &str) -> Result<(), WorkerError> {
        self.bucket.delete(key).await
    }

    /// List all object keys sharing a prefix.
    ///
    /// R2 `list()` returns up to 1 000 results by default; this helper
    /// fetches only the first page. For large containers the caller should
    /// paginate, but pod containers are expected to remain small.
    pub async fn list_objects(&self, prefix: &str) -> Result<Vec<String>, WorkerError> {
        let result = self.bucket.list().prefix(prefix).execute().await?;
        Ok(result
            .objects()
            .iter()
            .map(|o| o.key().to_string())
            .collect())
    }

    /// Return `true` if the key exists in R2.
    pub async fn object_exists(&self, key: &str) -> bool {
        self.bucket.head(key).await.unwrap_or(None).is_some()
    }

    /// Fetch object metadata (ETag, size, content-type) without the body.
    pub async fn head_object(&self, key: &str) -> Result<Option<worker::Object>, WorkerError> {
        self.bucket.head(key).await
    }
}

/// Build an R2 key from the standard pod storage convention.
///
/// `pods/{owner_pubkey}{resource_path}` — `resource_path` always starts with
/// `/`. Container keys end with `/`.
pub fn pod_r2_key(owner_pubkey: &str, resource_path: &str) -> String {
    format!("pods/{owner_pubkey}{resource_path}")
}
