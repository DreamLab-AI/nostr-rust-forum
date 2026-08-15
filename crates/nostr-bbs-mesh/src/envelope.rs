//! IS-Envelope v1 — the unified inter-system message contract (ADR-075).
//!
//! Every cross-system message on the DreamLab mesh (forum ⇄ agentbox ⇄
//! VisionClaw) carries an [`Envelope`] as the `content` of a NIP-59 kind-14
//! rumor, sealed (kind-13) and gift-wrapped (kind-1059). This module is the
//! *reference implementation* of that contract for the forum substrate — the
//! shape the other substrates conform to.
//!
//! The wire shape, per ADR-075 §D1:
//!
//! ```jsonc
//! {
//!   "v":      1,
//!   "to":     "did:nostr:<hex>",
//!   "from":   "did:nostr:<hex>",
//!   "via":    ["did:nostr:<bridge_hex>"],   // optional
//!   "subj":   "urn:visionclaw:bead:...",    // optional
//!   "thread": "<event_id_hex>",             // optional
//!   "ttl":    1763000000,                   // optional
//!   "kind":   "chat" | "tool_invoke" | ...,
//!   "lang":   "text/markdown" | ...,        // optional
//!   "body":   "<string|object>",
//!   "hint":   { ... },                      // optional
//!   "delegation": { ... }                   // optional
//! }
//! ```
//!
//! # Ambiguity decisions (flagged per ADR-075 leaving fields under-specified)
//!
//! * **`v` handling.** ADR-075 §D11 says future versions coexist and receivers
//!   ignore unknown *fields*; it does not say what a v1 implementation does with
//!   a `v != 1` envelope. Decision: [`Envelope::validate`] **rejects** any major
//!   version other than `1` with [`EnvelopeError::UnsupportedVersion`], because
//!   this implementation only understands v1 semantics and silently mis-handling
//!   a v2 body would be worse than a clean rejection. When v2 lands, its parser
//!   is added alongside, not by loosening this check.
//! * **`body` non-null.** §D2 lists `body` as required but the per-kind shapes
//!   in §D3 never make it nullable. Decision: a JSON `null` body is treated as a
//!   missing required field (`envelope-malformed: body`).
//! * **Default TTL.** §D7 says "created_at + 7 days" when TTL is absent, made
//!   configurable via `mesh.envelope_default_ttl_s`. This module exposes
//!   [`DEFAULT_TTL_SECS`] and [`Envelope::is_expired_with_default`]; the
//!   *creation timestamp* is supplied by the caller (the outer event's
//!   `created_at`) since the envelope itself carries no birth timestamp.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use nostr_bbs_core::event::NostrEvent;

use crate::delegation::DelegationToken;
use crate::jcs;

/// Current IS-Envelope schema version.
pub const ENVELOPE_VERSION: u8 = 1;

/// Maximum `via` re-attribution chain length (ADR-075 §D9). Envelopes with a
/// longer chain are rejected with [`EnvelopeError::ViaTooLong`].
pub const MAX_VIA_HOPS: usize = 4;

/// Maximum JCS-encoded `body` size in bytes (ADR-075 §D13). Larger payloads
/// must use `body.attachments[]` referencing pod-hosted resources.
pub const MAX_BODY_BYTES: usize = 64 * 1024;

/// Default envelope TTL in seconds when the `ttl` field is absent
/// (ADR-075 §D7: created_at + 7 days).
pub const DEFAULT_TTL_SECS: u64 = 7 * 24 * 60 * 60;

/// Nostr kind for a plain (non-gift-wrapped) mesh control event
/// (ADR-075 §D4 — new allocation, parameterised replaceable).
pub const KIND_MESH_EVENT: u64 = 30050;

/// Nostr kind for a mesh service-list event (ADR-074 §D9 / ADR-075 §D4).
pub const KIND_MESH_SERVICES: u64 = 30033;

/// The seven enumerated envelope kinds (ADR-075 §D3). The wire form is the
/// snake_case string; unknown kinds are rejected at parse time (a strict fence,
/// per the §D3 "seven kinds is a fence" consequence).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvelopeKind {
    /// Human/agent chat message. `body` is a string or `{text, attachments}`.
    Chat,
    /// Request to run a tool/skill on the recipient. `body` is `{tool, args, reply_to}`.
    ToolInvoke,
    /// Response to a [`EnvelopeKind::ToolInvoke`]. `body` is `{tool, status, result, error, in_reply_to}`.
    ToolResult,
    /// Notification that content was indexed/linked in a knowledge graph.
    KnowledgeLink,
    /// Cross-system moderation sidecar (the real mod event rides the relay).
    Moderation,
    /// Relay-to-relay presence / peer service-list ping.
    MeshPing,
}

impl EnvelopeKind {
    /// The ActivityStreams 2.0 outer activity type this kind maps to at the LDN
    /// boundary (ADR-075 §D3/§D10).
    pub fn as2_type(self) -> &'static str {
        match self {
            EnvelopeKind::Chat => "Create",
            EnvelopeKind::ToolInvoke => "Offer",
            EnvelopeKind::ToolResult => "Add",
            EnvelopeKind::KnowledgeLink => "Announce",
            EnvelopeKind::Moderation => "Block",
            EnvelopeKind::MeshPing => "View",
        }
    }
}

/// Optional rendering / routing hints (ADR-075 §D1 `hint`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvelopeHint {
    /// Preferred viewer id for the receiving UI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub render_with: Option<String>,
    /// Whether the receiver should render the payload inline.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub render_inline: Option<bool>,
    /// Priority hint: `"low" | "normal" | "high"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<String>,
}

/// Errors raised when constructing, validating, or parsing an [`Envelope`].
///
/// The `Display` strings deliberately match the `OK false "<reason>"` codes
/// mandated by ADR-075 §D2/§D9 so relays can relay them verbatim.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EnvelopeError {
    /// A required field is missing or null.
    #[error("envelope-malformed: {0}")]
    MissingField(&'static str),
    /// A `did:nostr:` value is not a canonical `did:nostr:<64-lowercase-hex>`.
    #[error("envelope-malformed: invalid did: {0}")]
    InvalidDid(String),
    /// The envelope major version is not understood by this implementation.
    #[error("envelope-unsupported-version: {0}")]
    UnsupportedVersion(u8),
    /// The `via` chain exceeds [`MAX_VIA_HOPS`].
    #[error("envelope-via-too-long")]
    ViaTooLong(usize),
    /// The JCS-encoded body exceeds [`MAX_BODY_BYTES`].
    #[error("envelope-body-too-large: {0}")]
    BodyTooLarge(usize),
    /// The `body` shape does not match its `kind`.
    #[error("envelope-malformed: body: {0}")]
    MalformedBody(String),
    /// The embedded `delegation` token is structurally invalid.
    #[error("delegation-invalid: {0}")]
    InvalidDelegation(String),
    /// The content is not valid JSON / not a valid envelope object.
    #[error("envelope-malformed: {0}")]
    Json(String),
}

/// An IS-Envelope v1 message (ADR-075 §D1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Envelope {
    /// Schema version (currently always [`ENVELOPE_VERSION`]).
    pub v: u8,
    /// Recipient identity, canonical `did:nostr:<hex>` (REQUIRED).
    pub to: String,
    /// Origin identity, canonical `did:nostr:<hex>` (REQUIRED even under delegation).
    pub from: String,
    /// Optional re-attribution chain (breadcrumb of forwarding bridges).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub via: Vec<String>,
    /// Optional URN of the originating context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subj: Option<String>,
    /// Optional reply-to event id (mirrors the Nostr `e` tag).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread: Option<String>,
    /// Optional hard-cutoff unix timestamp; MUST NOT be processed past this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u64>,
    /// The message kind (REQUIRED).
    pub kind: EnvelopeKind,
    /// Optional MIME/lang hint for the body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lang: Option<String>,
    /// The payload (REQUIRED; shape per [`EnvelopeKind`]).
    pub body: Value,
    /// Optional rendering / routing hints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint: Option<EnvelopeHint>,
    /// Optional NIP-26 delegation token (mirrored from the seal's tag).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation: Option<DelegationToken>,
}

impl Envelope {
    /// Construct a minimal valid envelope. `from`/`to` may be given either as
    /// bare 64-hex pubkeys or as full `did:nostr:<hex>` — both are normalised
    /// to the canonical `did:nostr:<hex>` form.
    pub fn new(from: &str, to: &str, kind: EnvelopeKind, body: Value) -> Self {
        Envelope {
            v: ENVELOPE_VERSION,
            to: normalise_did(to),
            from: normalise_did(from),
            via: Vec::new(),
            subj: None,
            thread: None,
            ttl: None,
            kind,
            lang: None,
            body,
            hint: None,
            delegation: None,
        }
    }

    /// Convenience: a plain-text [`EnvelopeKind::Chat`] envelope.
    pub fn chat(from: &str, to: &str, text: &str) -> Self {
        let mut e = Envelope::new(from, to, EnvelopeKind::Chat, Value::String(text.to_string()));
        e.lang = Some("text/plain".to_string());
        e
    }

    /// Set the TTL (builder style).
    pub fn with_ttl(mut self, ttl: u64) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Set the originating-context URN (builder style).
    pub fn with_subj(mut self, subj: impl Into<String>) -> Self {
        self.subj = Some(subj.into());
        self
    }

    /// Append a bridge DID to the `via` re-attribution chain (ADR-075 §D9).
    pub fn push_via(&mut self, bridge_did: &str) {
        self.via.push(normalise_did(bridge_did));
    }

    /// The recipient's bare 64-hex pubkey (strips the `did:nostr:` prefix).
    pub fn recipient_hex(&self) -> Result<String, EnvelopeError> {
        did_to_hex(&self.to)
    }

    /// The origin's bare 64-hex pubkey (strips the `did:nostr:` prefix).
    pub fn origin_hex(&self) -> Result<String, EnvelopeError> {
        did_to_hex(&self.from)
    }

    /// Validate the envelope structurally (ADR-075 §D2, §D9, §D13).
    ///
    /// This checks *structure* — required fields, DID canonicality, chain and
    /// size caps, and body/kind coherence. Cryptographic verification of an
    /// embedded delegation token against the seal signer is a separate step
    /// (see [`crate::delegation`]) performed during receive.
    pub fn validate(&self) -> Result<(), EnvelopeError> {
        if self.v != ENVELOPE_VERSION {
            return Err(EnvelopeError::UnsupportedVersion(self.v));
        }
        validate_did(&self.to).map_err(EnvelopeError::InvalidDid)?;
        validate_did(&self.from).map_err(EnvelopeError::InvalidDid)?;

        if self.via.len() > MAX_VIA_HOPS {
            return Err(EnvelopeError::ViaTooLong(self.via.len()));
        }
        for v in &self.via {
            validate_did(v).map_err(EnvelopeError::InvalidDid)?;
        }

        if self.body.is_null() {
            return Err(EnvelopeError::MissingField("body"));
        }

        // Body size cap on the JCS-encoded body (§D13).
        let body_len = jcs::canonicalize(&self.body).len();
        if body_len > MAX_BODY_BYTES {
            return Err(EnvelopeError::BodyTooLarge(body_len));
        }

        self.validate_body_shape()?;

        if let Some(d) = &self.delegation {
            d.validate_structure()
                .map_err(|e| EnvelopeError::InvalidDelegation(e.to_string()))?;
            // §D6 / Alt-D: the mirrored field and the delegator must be a
            // canonical DID too.
            validate_did(&normalise_did(&d.delegator)).map_err(EnvelopeError::InvalidDid)?;
        }

        Ok(())
    }

    /// Per-kind body-shape validation (ADR-075 §D3). Kept lenient: required
    /// discriminant fields are checked; extra fields are ignored (forward-compat).
    fn validate_body_shape(&self) -> Result<(), EnvelopeError> {
        let obj = |name: &str| -> Result<&serde_json::Map<String, Value>, EnvelopeError> {
            self.body
                .as_object()
                .ok_or_else(|| EnvelopeError::MalformedBody(format!("{name} body must be an object")))
        };
        match self.kind {
            EnvelopeKind::Chat => {
                // string OR { text, attachments? }
                if self.body.is_string() {
                    Ok(())
                } else if let Some(map) = self.body.as_object() {
                    if map.get("text").map(Value::is_string).unwrap_or(false) {
                        Ok(())
                    } else {
                        Err(EnvelopeError::MalformedBody("chat object requires string `text`".into()))
                    }
                } else {
                    Err(EnvelopeError::MalformedBody("chat body must be string or object".into()))
                }
            }
            EnvelopeKind::ToolInvoke => {
                let m = obj("tool_invoke")?;
                require_string(m, "tool", "tool_invoke")
            }
            EnvelopeKind::ToolResult => {
                let m = obj("tool_result")?;
                require_string(m, "status", "tool_result")
            }
            EnvelopeKind::KnowledgeLink => {
                let m = obj("knowledge_link")?;
                require_string(m, "subject_urn", "knowledge_link")?;
                require_string(m, "claim", "knowledge_link")
            }
            EnvelopeKind::Moderation => {
                let m = obj("moderation")?;
                require_string(m, "action", "moderation")?;
                require_string(m, "target", "moderation")
            }
            EnvelopeKind::MeshPing => {
                let _ = obj("mesh_ping")?;
                Ok(())
            }
        }
    }

    /// Serialise to a canonical JCS string (ADR-075 §D5) — the bytes that
    /// become the kind-14 rumor `content`.
    pub fn to_jcs_string(&self) -> String {
        let value = serde_json::to_value(self).expect("envelope serialization is infallible");
        jcs::canonicalize(&value)
    }

    /// Parse and validate an envelope from a rumor `content` string.
    pub fn from_jcs_str(s: &str) -> Result<Self, EnvelopeError> {
        let env: Envelope =
            serde_json::from_str(s).map_err(|e| EnvelopeError::Json(e.to_string()))?;
        env.validate()?;
        Ok(env)
    }

    /// True if this envelope's explicit `ttl` is strictly before `now`
    /// (ADR-075 §D7). Envelopes without a `ttl` are never expired by this
    /// method — use [`Envelope::is_expired_with_default`] to apply the default.
    pub fn is_expired(&self, now: u64) -> bool {
        matches!(self.ttl, Some(ttl) if ttl < now)
    }

    /// TTL check applying the §D7 default of `created_at + 7 days` when the
    /// `ttl` field is absent. `created_at` is the outer event timestamp.
    pub fn is_expired_with_default(&self, now: u64, created_at: u64) -> bool {
        match self.ttl {
            Some(ttl) => ttl < now,
            None => created_at.saturating_add(DEFAULT_TTL_SECS) < now,
        }
    }

    /// Map to the Linked Data Notification AS2 payload for pod-inbox writes
    /// (ADR-075 §D10, PRD-010 F19). `original_event` is the signed outer event
    /// whose full JSON is preserved under `x:nostrEvent` for verifier re-runs.
    pub fn to_ldn_as2(&self, original_event: &NostrEvent) -> Value {
        let from_hex = self.origin_hex().unwrap_or_else(|_| self.from.clone());
        let to_hex = self.recipient_hex().unwrap_or_else(|_| self.to.clone());
        let mut doc = json!({
            "@context": [
                "https://www.w3.org/ns/activitystreams",
                "https://w3id.org/dreamlab/mesh/v1"
            ],
            "type": self.kind.as2_type(),
            "actor": format!("did:nostr:{from_hex}"),
            "target": format!("did:nostr:{to_hex}"),
            "object": self.as2_object(),
            "id": format!("urn:nostr:event:{}", original_event.id),
            "published": iso8601_utc(original_event.created_at),
            "x:envelope": serde_json::to_value(self).expect("envelope to value"),
            "x:nostrEvent": serde_json::to_value(original_event).expect("event to value"),
        });
        if !self.via.is_empty() {
            doc["x:via"] = Value::Array(self.via.iter().cloned().map(Value::String).collect());
        }
        doc
    }

    /// Best-effort AS2 `object` translation of the body per kind (§D3). Falls
    /// back to the raw body when the expected sub-fields are absent — full
    /// fidelity is always preserved under `x:envelope`.
    fn as2_object(&self) -> Value {
        match self.kind {
            EnvelopeKind::Chat => {
                let (text, attachments) = match &self.body {
                    Value::String(s) => (s.clone(), Value::Null),
                    Value::Object(m) => (
                        m.get("text").and_then(Value::as_str).unwrap_or_default().to_string(),
                        m.get("attachments").cloned().unwrap_or(Value::Null),
                    ),
                    _ => (String::new(), Value::Null),
                };
                let mut note = json!({ "type": "Note", "content": text });
                if !attachments.is_null() {
                    note["attachment"] = attachments;
                }
                note
            }
            EnvelopeKind::ToolInvoke => {
                let tool = self.body.get("tool").cloned().unwrap_or(Value::Null);
                json!({
                    "type": "Tool",
                    "id": tool,
                    "instrument": self.body.get("args").cloned().unwrap_or(Value::Null),
                })
            }
            EnvelopeKind::KnowledgeLink => self
                .body
                .get("subject_urn")
                .cloned()
                .unwrap_or_else(|| self.body.clone()),
            EnvelopeKind::Moderation => self
                .body
                .get("target")
                .cloned()
                .unwrap_or_else(|| self.body.clone()),
            EnvelopeKind::ToolResult | EnvelopeKind::MeshPing => self.body.clone(),
        }
    }
}

// ── DID / hex helpers ────────────────────────────────────────────────────────

/// Prefix of a canonical DreamLab identity URI.
pub const DID_NOSTR_PREFIX: &str = "did:nostr:";

/// Normalise a pubkey-ish string to `did:nostr:<hex>`. Accepts a bare 64-hex
/// pubkey or an already-prefixed DID; lowercases the hex tail.
pub fn normalise_did(s: &str) -> String {
    let hex = s.strip_prefix(DID_NOSTR_PREFIX).unwrap_or(s);
    format!("{DID_NOSTR_PREFIX}{}", hex.to_ascii_lowercase())
}

/// Validate that `s` is a canonical `did:nostr:<64-lowercase-hex>`.
fn validate_did(s: &str) -> Result<(), String> {
    let hex = s
        .strip_prefix(DID_NOSTR_PREFIX)
        .ok_or_else(|| format!("missing did:nostr: prefix: {s}"))?;
    if hex.len() != 64 {
        return Err(format!("expected 64 hex chars, got {}", hex.len()));
    }
    if !hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err(format!("non-lowercase-hex in did: {s}"));
    }
    Ok(())
}

/// Extract the bare hex pubkey from a canonical `did:nostr:<hex>`.
fn did_to_hex(s: &str) -> Result<String, EnvelopeError> {
    validate_did(s).map_err(EnvelopeError::InvalidDid)?;
    Ok(s[DID_NOSTR_PREFIX.len()..].to_string())
}

fn require_string(
    map: &serde_json::Map<String, Value>,
    key: &'static str,
    kind: &str,
) -> Result<(), EnvelopeError> {
    match map.get(key) {
        Some(Value::String(_)) => Ok(()),
        _ => Err(EnvelopeError::MalformedBody(format!(
            "{kind} requires string `{key}`"
        ))),
    }
}

/// Format a unix-seconds timestamp as an ISO-8601 / RFC-3339 UTC string
/// (`YYYY-MM-DDThh:mm:ssZ`). Dependency-free (no `chrono`) so it compiles for
/// `wasm32`. Uses Howard Hinnant's `civil_from_days` algorithm.
fn iso8601_utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (hh, mm, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);

    // civil_from_days: days since 1970-01-01 → (year, month, day).
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };

    format!("{year:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEX_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const HEX_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[test]
    fn chat_round_trips_through_jcs() {
        let env = Envelope::chat(HEX_A, HEX_B, "hello mesh");
        let s = env.to_jcs_string();
        let back = Envelope::from_jcs_str(&s).unwrap();
        assert_eq!(env, back);
        assert_eq!(back.kind, EnvelopeKind::Chat);
        assert_eq!(back.from, format!("did:nostr:{HEX_A}"));
    }

    #[test]
    fn missing_required_field_rejected() {
        // hand-build content missing `to`
        let bad = format!(r#"{{"v":1,"from":"did:nostr:{HEX_A}","kind":"chat","body":"x"}}"#);
        let err = Envelope::from_jcs_str(&bad).unwrap_err();
        assert!(matches!(err, EnvelopeError::Json(_)));
    }

    #[test]
    fn unsupported_version_rejected() {
        let mut env = Envelope::chat(HEX_A, HEX_B, "x");
        env.v = 2;
        assert_eq!(env.validate(), Err(EnvelopeError::UnsupportedVersion(2)));
    }

    #[test]
    fn via_chain_cap_enforced() {
        let mut env = Envelope::chat(HEX_A, HEX_B, "x");
        for _ in 0..5 {
            env.push_via(HEX_A);
        }
        assert_eq!(env.validate(), Err(EnvelopeError::ViaTooLong(5)));
    }

    #[test]
    fn tool_invoke_requires_tool() {
        let env = Envelope::new(
            HEX_A,
            HEX_B,
            EnvelopeKind::ToolInvoke,
            serde_json::json!({ "args": {} }),
        );
        assert!(matches!(env.validate(), Err(EnvelopeError::MalformedBody(_))));
    }

    #[test]
    fn iso8601_formats_epoch() {
        assert_eq!(iso8601_utc(0), "1970-01-01T00:00:00Z");
        // 2021-01-01T00:00:00Z = 1609459200
        assert_eq!(iso8601_utc(1_609_459_200), "2021-01-01T00:00:00Z");
    }
}
