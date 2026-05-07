//! Provider-abstracted operator-onboarding skill for nostr-bbs deployments.
//!
//! Implements [ADR-079]: a single skill that walks an operator from
//! `git clone` to "running forum" across five custody tiers / hosting
//! providers. The skill emits a populated `forum.toml`, provisions the
//! upstream resources (D1, KV, R2, Routes, Domains), and writes back the
//! per-worker `wrangler.toml` overlay.
//!
//! # Status
//!
//! Sprint v9-v11: scaffold only. Each [`Provider`] impl carries a `todo!()`
//! body documenting the contract; full implementation lands in Sprint v12+
//! per the PRD-012 Phase X3 plan.
//!
//! # Provider matrix (per ADR-079 §4)
//!
//! | Tier   | Provider                      | Custody             |
//! |--------|-------------------------------|---------------------|
//! | tier-1 | [`SelfHostProvider`]          | Operator-managed VM |
//! | tier-2 | [`CloudflareWorkersProvider`] | CF Workers Secrets  |
//! | tier-3 | [`FlyDotIoProvider`]          | Fly.io Secrets      |
//! | tier-4 | [`TurnkeyProvider`]           | Hosted (this kit)   |
//! | tier-x | [`KubernetesProvider`]        | K8s Secret resource |
//!
//! [ADR-079]: https://github.com/DreamLab-AI/nostr-rust-forum/blob/main/docs/adr/ADR-079.md

#![warn(missing_docs)]

use async_trait::async_trait;
use thiserror::Error;

use nostr_bbs_config::ForumConfig;

/// Errors raised by setup providers.
#[derive(Debug, Error)]
pub enum SetupError {
    /// Provider-specific API error.
    #[error("provider: {0}")]
    Provider(String),
    /// Configuration validation error.
    #[error("config: {0}")]
    Config(String),
    /// I/O error.
    #[error("io: {0}")]
    Io(String),
    /// Operation not supported by this provider.
    #[error("unsupported")]
    Unsupported,
}

/// One-shot record describing a provisioned resource.
#[derive(Debug, Clone)]
pub struct ProvisionedResource {
    /// Logical resource type (`"d1"`, `"kv"`, `"r2"`, `"route"`, ...).
    pub kind: String,
    /// Provider-assigned resource identifier.
    pub id: String,
    /// Display name (e.g. `"nostr-bbs-auth"` for D1).
    pub name: String,
}

/// Abstract setup provider — one impl per custody tier.
#[async_trait(?Send)]
pub trait Provider {
    /// Provider tier identifier (`"tier-1"` .. `"tier-4"` or custom).
    fn tier(&self) -> &'static str;

    /// Provision deployment resources defined by `cfg`.
    async fn provision(
        &self,
        cfg: &ForumConfig,
    ) -> Result<Vec<ProvisionedResource>, SetupError>;

    /// Render the per-worker `wrangler.toml` overlay (or equivalent for the
    /// provider) given a populated `cfg` and the resources from `provision`.
    async fn render_wrangler(
        &self,
        cfg: &ForumConfig,
        resources: &[ProvisionedResource],
    ) -> Result<String, SetupError>;
}

/// Self-hosted (operator-managed VM) provider stub.
pub struct SelfHostProvider;

#[async_trait(?Send)]
impl Provider for SelfHostProvider {
    fn tier(&self) -> &'static str {
        "tier-1"
    }

    async fn provision(
        &self,
        _cfg: &ForumConfig,
    ) -> Result<Vec<ProvisionedResource>, SetupError> {
        // Provisions: nothing (operator already runs the host).
        // Returns an empty vec; render_wrangler still writes a manifest.
        Ok(Vec::new())
    }

    async fn render_wrangler(
        &self,
        _cfg: &ForumConfig,
        _resources: &[ProvisionedResource],
    ) -> Result<String, SetupError> {
        // Self-host emits a docker-compose.yml or systemd unit instead of
        // a wrangler manifest. Implementation: Sprint v12.
        todo!("SelfHostProvider::render_wrangler — emit docker-compose.yml / systemd unit")
    }
}

/// Cloudflare Workers (default tier-2) provider stub.
pub struct CloudflareWorkersProvider;

#[async_trait(?Send)]
impl Provider for CloudflareWorkersProvider {
    fn tier(&self) -> &'static str {
        "tier-2"
    }

    async fn provision(
        &self,
        _cfg: &ForumConfig,
    ) -> Result<Vec<ProvisionedResource>, SetupError> {
        // Provisions: D1 db, KV namespaces (admin + nip98-replay + admin-ro),
        // R2 bucket, Routes, Custom Domain. Implementation: Sprint v12+.
        todo!(
            "CloudflareWorkersProvider::provision — wrangler v3 REST API or terraform-cf-workers"
        )
    }

    async fn render_wrangler(
        &self,
        _cfg: &ForumConfig,
        _resources: &[ProvisionedResource],
    ) -> Result<String, SetupError> {
        todo!("CloudflareWorkersProvider::render_wrangler — emit wrangler.toml per worker")
    }
}

/// Fly.io (tier-3) provider stub.
pub struct FlyDotIoProvider;

#[async_trait(?Send)]
impl Provider for FlyDotIoProvider {
    fn tier(&self) -> &'static str {
        "tier-3"
    }

    async fn provision(
        &self,
        _cfg: &ForumConfig,
    ) -> Result<Vec<ProvisionedResource>, SetupError> {
        todo!("FlyDotIoProvider::provision — flyctl + Fly Postgres + Tigris")
    }

    async fn render_wrangler(
        &self,
        _cfg: &ForumConfig,
        _resources: &[ProvisionedResource],
    ) -> Result<String, SetupError> {
        todo!("FlyDotIoProvider::render_wrangler — emit fly.toml")
    }
}

/// Turnkey hosted (tier-4) provider stub.
pub struct TurnkeyProvider;

#[async_trait(?Send)]
impl Provider for TurnkeyProvider {
    fn tier(&self) -> &'static str {
        "tier-4"
    }

    async fn provision(
        &self,
        _cfg: &ForumConfig,
    ) -> Result<Vec<ProvisionedResource>, SetupError> {
        todo!("TurnkeyProvider::provision — kit-managed onboarding API")
    }

    async fn render_wrangler(
        &self,
        _cfg: &ForumConfig,
        _resources: &[ProvisionedResource],
    ) -> Result<String, SetupError> {
        // Turnkey deploy never writes wrangler.toml on the operator's
        // machine; the kit operator manages it. Return Unsupported.
        Err(SetupError::Unsupported)
    }
}

/// Kubernetes (tier-x) provider stub.
pub struct KubernetesProvider;

#[async_trait(?Send)]
impl Provider for KubernetesProvider {
    fn tier(&self) -> &'static str {
        "tier-x"
    }

    async fn provision(
        &self,
        _cfg: &ForumConfig,
    ) -> Result<Vec<ProvisionedResource>, SetupError> {
        todo!("KubernetesProvider::provision — kubectl apply via Helm chart")
    }

    async fn render_wrangler(
        &self,
        _cfg: &ForumConfig,
        _resources: &[ProvisionedResource],
    ) -> Result<String, SetupError> {
        todo!("KubernetesProvider::render_wrangler — emit Helm chart values.yaml")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_tiers_match_taxonomy() {
        assert_eq!(SelfHostProvider.tier(), "tier-1");
        assert_eq!(CloudflareWorkersProvider.tier(), "tier-2");
        assert_eq!(FlyDotIoProvider.tier(), "tier-3");
        assert_eq!(TurnkeyProvider.tier(), "tier-4");
        assert_eq!(KubernetesProvider.tier(), "tier-x");
    }
}
