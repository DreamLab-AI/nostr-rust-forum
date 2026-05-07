//! NIP-90: Data Vending Machines (DVMs).
//!
//! Implements types for the NIP-90 job request/result/feedback protocol.
//!
//! Kind ranges:
//! - 5000-5999: Job request events (from customers to DVMs)
//! - 6000-6999: Job result events (from DVMs to customers)
//! - 7000:      Job feedback events (intermediate status from DVMs)
//! - 31990:     DVM handler information (kind-31990 parameterized replaceable)
//!
//! Reference: https://github.com/nostr-protocol/nostr/blob/master/nips/90.md

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::event::{sign_event, NostrEvent, UnsignedEvent};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Kind range start for DVM job requests.
pub const KIND_JOB_REQUEST_MIN: u64 = 5000;
/// Kind range end for DVM job requests.
pub const KIND_JOB_REQUEST_MAX: u64 = 5999;
/// Kind range start for DVM job results.
pub const KIND_JOB_RESULT_MIN: u64 = 6000;
/// Kind range end for DVM job results.
pub const KIND_JOB_RESULT_MAX: u64 = 6999;
/// Kind for DVM job feedback (intermediate status updates).
pub const KIND_JOB_FEEDBACK: u64 = 7000;
/// Kind for DVM handler information (NIP-31 parameterized replaceable).
pub const KIND_HANDLER_INFO: u64 = 31990;

// ── Error ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum Nip90Error {
    #[error("invalid job kind {0}: must be in range 5000-5999 for requests")]
    InvalidJobKind(u64),
    #[error("invalid result kind {0}: must be in range 6000-6999")]
    InvalidResultKind(u64),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("signing error: {0}")]
    Signing(String),
    #[error("invalid event: {0}")]
    InvalidEvent(String),
}

// ── Job status ────────────────────────────────────────────────────────────────

/// Status values for NIP-90 job feedback events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JobStatus {
    /// Job is queued and waiting to be processed.
    Queued,
    /// Job is currently being processed.
    Processing,
    /// Job requires payment before proceeding.
    PaymentRequired,
    /// Job has been completed successfully (use kind 6xxx result event).
    Success,
    /// DVM cannot or will not process this job.
    Error,
    /// DVM is partially processing (for streaming results).
    Partial,
}

impl JobStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Processing => "processing",
            Self::PaymentRequired => "payment-required",
            Self::Success => "success",
            Self::Error => "error",
            Self::Partial => "partial",
        }
    }
}

// ── JobInput ──────────────────────────────────────────────────────────────────

/// A single input to a DVM job request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobInput {
    /// Input type: "event", "job", "text", "url".
    pub input_type: String,
    /// Input value (event ID hex, job request ID, text string, or URL).
    pub value: String,
    /// Optional relay where the input event can be found.
    pub relay: Option<String>,
    /// Optional marker for multi-input jobs.
    pub marker: Option<String>,
}

impl JobInput {
    pub fn event(event_id: &str, relay: Option<&str>) -> Self {
        Self {
            input_type: "event".into(),
            value: event_id.into(),
            relay: relay.map(|s| s.into()),
            marker: None,
        }
    }

    pub fn text(content: &str) -> Self {
        Self {
            input_type: "text".into(),
            value: content.into(),
            relay: None,
            marker: None,
        }
    }

    pub fn url(url: &str) -> Self {
        Self {
            input_type: "url".into(),
            value: url.into(),
            relay: None,
            marker: None,
        }
    }

    /// Encode as a NIP-90 `i` tag: `["i", value, type, relay?, marker?]`.
    pub fn to_tag(&self) -> Vec<String> {
        let mut tag = vec!["i".into(), self.value.clone(), self.input_type.clone()];
        if let Some(ref relay) = self.relay {
            tag.push(relay.clone());
        } else if self.marker.is_some() {
            tag.push(String::new()); // relay placeholder
        }
        if let Some(ref marker) = self.marker {
            tag.push(marker.clone());
        }
        tag
    }
}

// ── DvmJobRequest ─────────────────────────────────────────────────────────────

/// A NIP-90 DVM job request event (kind 5000-5999).
#[derive(Debug, Clone)]
pub struct DvmJobRequest {
    /// Job kind (5000-5999).
    pub kind: u64,
    /// Job inputs.
    pub inputs: Vec<JobInput>,
    /// Desired output MIME type (optional).
    pub output_type: Option<String>,
    /// Bid in millisatoshis (optional).
    pub bid_msats: Option<u64>,
    /// Relay URLs for the result (optional).
    pub relays: Vec<String>,
    /// Target DVM pubkeys (if empty, any DVM may pick up the job).
    pub dvm_pubkeys: Vec<String>,
    /// Additional tags.
    pub extra_tags: Vec<Vec<String>>,
}

impl DvmJobRequest {
    pub fn new(kind: u64) -> Result<Self, Nip90Error> {
        if !(KIND_JOB_REQUEST_MIN..=KIND_JOB_REQUEST_MAX).contains(&kind) {
            return Err(Nip90Error::InvalidJobKind(kind));
        }
        Ok(Self {
            kind,
            inputs: Vec::new(),
            output_type: None,
            bid_msats: None,
            relays: Vec::new(),
            dvm_pubkeys: Vec::new(),
            extra_tags: Vec::new(),
        })
    }

    pub fn with_input(mut self, input: JobInput) -> Self {
        self.inputs.push(input);
        self
    }

    pub fn with_output_type(mut self, mime: &str) -> Self {
        self.output_type = Some(mime.into());
        self
    }

    pub fn with_bid(mut self, msats: u64) -> Self {
        self.bid_msats = Some(msats);
        self
    }

    pub fn with_relay(mut self, relay: &str) -> Self {
        self.relays.push(relay.into());
        self
    }

    pub fn targeting_dvm(mut self, dvm_pubkey: &str) -> Self {
        self.dvm_pubkeys.push(dvm_pubkey.into());
        self
    }

    /// Build the NIP-90 tag list for a job request event.
    fn build_tags(&self) -> Vec<Vec<String>> {
        let mut tags = Vec::new();

        for input in &self.inputs {
            tags.push(input.to_tag());
        }

        if let Some(ref output) = self.output_type {
            tags.push(vec!["output".into(), output.clone()]);
        }

        if let Some(bid) = self.bid_msats {
            tags.push(vec!["bid".into(), bid.to_string()]);
        }

        if !self.relays.is_empty() {
            let mut relay_tag = vec!["relays".into()];
            relay_tag.extend(self.relays.iter().cloned());
            tags.push(relay_tag);
        }

        for dvm_pk in &self.dvm_pubkeys {
            tags.push(vec!["p".into(), dvm_pk.clone()]);
        }

        for tag in &self.extra_tags {
            tags.push(tag.clone());
        }

        tags
    }

    /// Sign this job request with the given secret key.
    pub fn sign(
        &self,
        requester_sk: &[u8; 32],
        requester_pubkey: &str,
        created_at: u64,
    ) -> Result<NostrEvent, Nip90Error> {
        let signing_key = k256::schnorr::SigningKey::from_bytes(requester_sk)
            .map_err(|e| Nip90Error::Signing(e.to_string()))?;

        let unsigned = UnsignedEvent {
            pubkey: requester_pubkey.into(),
            created_at,
            kind: self.kind,
            tags: self.build_tags(),
            content: String::new(), // Job request content is typically empty
        };

        sign_event(unsigned, &signing_key).map_err(|e| Nip90Error::Signing(e.to_string()))
    }
}

// ── DvmJobResult ──────────────────────────────────────────────────────────────

/// A NIP-90 DVM job result event (kind 6000-6999).
#[derive(Debug, Clone)]
pub struct DvmJobResult {
    /// Result kind (6000-6999, corresponding to request kind 5000-5999).
    pub kind: u64,
    /// The job request event ID this is a result for.
    pub request_event_id: String,
    /// The requester's pubkey.
    pub requester_pubkey: String,
    /// Result content (the actual output).
    pub content: String,
    /// Amount requested in millisatoshis (for payment).
    pub amount_msats: Option<u64>,
    /// Payment bolt11 invoice (if payment required).
    pub bolt11: Option<String>,
    /// Additional tags.
    pub extra_tags: Vec<Vec<String>>,
}

impl DvmJobResult {
    pub fn new(
        request_kind: u64,
        request_event_id: &str,
        requester_pubkey: &str,
        content: &str,
    ) -> Result<Self, Nip90Error> {
        if !(KIND_JOB_REQUEST_MIN..=KIND_JOB_REQUEST_MAX).contains(&request_kind) {
            return Err(Nip90Error::InvalidJobKind(request_kind));
        }
        let result_kind = request_kind - KIND_JOB_REQUEST_MIN + KIND_JOB_RESULT_MIN;
        Ok(Self {
            kind: result_kind,
            request_event_id: request_event_id.into(),
            requester_pubkey: requester_pubkey.into(),
            content: content.into(),
            amount_msats: None,
            bolt11: None,
            extra_tags: Vec::new(),
        })
    }

    fn build_tags(&self) -> Vec<Vec<String>> {
        let mut tags = vec![
            vec!["request".into(), self.request_event_id.clone()],
            vec!["p".into(), self.requester_pubkey.clone()],
        ];

        if let Some(msats) = self.amount_msats {
            let mut amt_tag = vec!["amount".into(), msats.to_string()];
            if let Some(ref invoice) = self.bolt11 {
                amt_tag.push(invoice.clone());
            }
            tags.push(amt_tag);
        }

        for tag in &self.extra_tags {
            tags.push(tag.clone());
        }

        tags
    }

    pub fn sign(
        &self,
        dvm_sk: &[u8; 32],
        dvm_pubkey: &str,
        created_at: u64,
    ) -> Result<NostrEvent, Nip90Error> {
        let signing_key = k256::schnorr::SigningKey::from_bytes(dvm_sk)
            .map_err(|e| Nip90Error::Signing(e.to_string()))?;

        let unsigned = UnsignedEvent {
            pubkey: dvm_pubkey.into(),
            created_at,
            kind: self.kind,
            tags: self.build_tags(),
            content: self.content.clone(),
        };

        sign_event(unsigned, &signing_key).map_err(|e| Nip90Error::Signing(e.to_string()))
    }
}

// ── DvmJobFeedback ────────────────────────────────────────────────────────────

/// A NIP-90 DVM job feedback event (kind 7000).
#[derive(Debug, Clone)]
pub struct DvmJobFeedback {
    /// The job request event ID.
    pub request_event_id: String,
    /// The requester's pubkey.
    pub requester_pubkey: String,
    /// Current job status.
    pub status: JobStatus,
    /// Optional extra information (error message, partial result, etc.).
    pub extra_info: Option<String>,
    /// Optional amount in millisatoshis (for payment-required status).
    pub amount_msats: Option<u64>,
}

impl DvmJobFeedback {
    pub fn new(request_event_id: &str, requester_pubkey: &str, status: JobStatus) -> Self {
        Self {
            request_event_id: request_event_id.into(),
            requester_pubkey: requester_pubkey.into(),
            status,
            extra_info: None,
            amount_msats: None,
        }
    }

    fn build_tags(&self) -> Vec<Vec<String>> {
        let mut tags = vec![
            vec!["status".into(), self.status.as_str().into()],
            vec!["e".into(), self.request_event_id.clone()],
            vec!["p".into(), self.requester_pubkey.clone()],
        ];

        if let Some(msats) = self.amount_msats {
            tags.push(vec!["amount".into(), msats.to_string()]);
        }

        tags
    }

    pub fn sign(
        &self,
        dvm_sk: &[u8; 32],
        dvm_pubkey: &str,
        created_at: u64,
    ) -> Result<NostrEvent, Nip90Error> {
        let signing_key = k256::schnorr::SigningKey::from_bytes(dvm_sk)
            .map_err(|e| Nip90Error::Signing(e.to_string()))?;

        let content = self.extra_info.clone().unwrap_or_default();
        let unsigned = UnsignedEvent {
            pubkey: dvm_pubkey.into(),
            created_at,
            kind: KIND_JOB_FEEDBACK,
            tags: self.build_tags(),
            content,
        };

        sign_event(unsigned, &signing_key).map_err(|e| Nip90Error::Signing(e.to_string()))
    }
}

// ── DvmCapabilityAd (kind-31990) ──────────────────────────────────────────────

/// A NIP-90 DVM capability advertisement (kind 31990, parameterized replaceable).
///
/// DVMs publish these to announce the job kinds they support, their pricing,
/// and metadata for discovery via NIP-89 handler information.
#[derive(Debug, Clone)]
pub struct DvmCapabilityAd {
    /// DVM's pubkey (64-char hex).
    pub pubkey: String,
    /// Human-readable name of this DVM.
    pub name: String,
    /// Human-readable description.
    pub about: String,
    /// Job kinds this DVM supports (5000-5999).
    pub supported_kinds: Vec<u64>,
    /// Price in millisatoshis per job (0 = free).
    pub price_msats: u64,
    /// Optional payment bolt11 template.
    pub encryption_supported: bool,
    /// d-tag identifier (e.g. "text-summarizer-v1").
    pub d_tag: String,
}

impl DvmCapabilityAd {
    fn build_tags(&self) -> Vec<Vec<String>> {
        let mut tags = vec![
            vec!["d".into(), self.d_tag.clone()],
            vec!["name".into(), self.name.clone()],
            vec!["about".into(), self.about.clone()],
        ];

        for kind in &self.supported_kinds {
            tags.push(vec!["k".into(), kind.to_string()]);
        }

        if self.encryption_supported {
            tags.push(vec!["encryption".into(), "nip44".into()]);
        }

        if self.price_msats > 0 {
            tags.push(vec![
                "amount".into(),
                self.price_msats.to_string(),
                "msats".into(),
            ]);
        }

        tags
    }

    pub fn sign(&self, dvm_sk: &[u8; 32], created_at: u64) -> Result<NostrEvent, Nip90Error> {
        let signing_key = k256::schnorr::SigningKey::from_bytes(dvm_sk)
            .map_err(|e| Nip90Error::Signing(e.to_string()))?;

        let unsigned = UnsignedEvent {
            pubkey: self.pubkey.clone(),
            created_at,
            kind: KIND_HANDLER_INFO,
            tags: self.build_tags(),
            content: self.about.clone(),
        };

        sign_event(unsigned, &signing_key).map_err(|e| Nip90Error::Signing(e.to_string()))
    }
}

// ── Helper: parse request from event ─────────────────────────────────────────

/// Parse inputs from a job request event's tags.
pub fn parse_job_inputs(event: &NostrEvent) -> Vec<JobInput> {
    event
        .tags
        .iter()
        .filter(|t| t.first().map(|s| s == "i").unwrap_or(false))
        .map(|t| {
            let value = t.get(1).cloned().unwrap_or_default();
            let input_type = t.get(2).cloned().unwrap_or_else(|| "text".into());
            let relay = t
                .get(3)
                .and_then(|s| if s.is_empty() { None } else { Some(s.clone()) });
            let marker = t.get(4).cloned();
            JobInput {
                input_type,
                value,
                relay,
                marker,
            }
        })
        .collect()
}

/// Check whether an event is a NIP-90 job request.
pub fn is_job_request(event: &NostrEvent) -> bool {
    event.kind >= KIND_JOB_REQUEST_MIN && event.kind <= KIND_JOB_REQUEST_MAX
}

/// Check whether an event is a NIP-90 job result.
pub fn is_job_result(event: &NostrEvent) -> bool {
    event.kind >= KIND_JOB_RESULT_MIN && event.kind <= KIND_JOB_RESULT_MAX
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::generate_keypair;

    fn test_keypair() -> ([u8; 32], String) {
        let kp = generate_keypair().unwrap();
        let sk = *kp.secret.as_bytes();
        let pk = kp.public.to_hex();
        (sk, pk)
    }

    #[test]
    fn job_request_kind_validation() {
        assert!(DvmJobRequest::new(5000).is_ok());
        assert!(DvmJobRequest::new(5999).is_ok());
        assert!(DvmJobRequest::new(4999).is_err());
        assert!(DvmJobRequest::new(6000).is_err());
    }

    #[test]
    fn job_request_signing() {
        let (sk, pk) = test_keypair();
        let req = DvmJobRequest::new(5100)
            .unwrap()
            .with_input(JobInput::text("Summarize this text please"))
            .with_output_type("text/plain");

        let event = req.sign(&sk, &pk, 1_700_000_000).unwrap();
        assert_eq!(event.kind, 5100);
        assert_eq!(event.pubkey, pk);
        assert!(crate::event::verify_event(&event));
    }

    #[test]
    fn job_result_kind_derived_from_request() {
        let (sk, pk) = test_keypair();
        let (_, req_pk) = test_keypair();
        let req_id = "a".repeat(64);

        let result = DvmJobResult::new(5100, &req_id, &req_pk, "Summary: done").unwrap();
        assert_eq!(result.kind, 6100); // 5100 - 5000 + 6000
        let event = result.sign(&sk, &pk, 1_700_000_000).unwrap();
        assert_eq!(event.kind, 6100);
        assert!(crate::event::verify_event(&event));
    }

    #[test]
    fn job_feedback_status_as_str() {
        assert_eq!(JobStatus::Queued.as_str(), "queued");
        assert_eq!(JobStatus::Processing.as_str(), "processing");
        assert_eq!(JobStatus::PaymentRequired.as_str(), "payment-required");
        assert_eq!(JobStatus::Error.as_str(), "error");
    }

    #[test]
    fn capability_ad_signs() {
        let (sk, pk) = test_keypair();
        let ad = DvmCapabilityAd {
            pubkey: pk.clone(),
            name: "Text Summarizer".into(),
            about: "Summarizes text using AI".into(),
            supported_kinds: vec![5100],
            price_msats: 0,
            encryption_supported: true,
            d_tag: "text-summarizer-v1".into(),
        };
        let event = ad.sign(&sk, 1_700_000_000).unwrap();
        assert_eq!(event.kind, KIND_HANDLER_INFO);
        assert!(crate::event::verify_event(&event));
    }

    #[test]
    fn input_to_tag_event_type() {
        let input = JobInput::event("abc", Some("wss://relay.example.com"));
        let tag = input.to_tag();
        assert_eq!(tag[0], "i");
        assert_eq!(tag[1], "abc");
        assert_eq!(tag[2], "event");
        assert_eq!(tag[3], "wss://relay.example.com");
    }

    #[test]
    fn is_job_request_range() {
        let (sk, pk) = test_keypair();
        let sk_k256 = k256::schnorr::SigningKey::from_bytes(&sk).unwrap();
        let ev = crate::event::sign_event(
            UnsignedEvent {
                pubkey: pk,
                created_at: 1_700_000_000,
                kind: 5050,
                tags: vec![],
                content: String::new(),
            },
            &sk_k256,
        )
        .unwrap();
        assert!(is_job_request(&ev));
        assert!(!is_job_result(&ev));
    }
}
