//! NIP-specific protocol handlers for the Nostr relay.
//!
//! - NIP-01: EVENT, REQ, CLOSE
//! - NIP-09: Deletion processing
//! - NIP-42: AUTH challenge/response
//! - NIP-45: COUNT
//! - Event validation.
//! - Trust-level gating (TL0-TL3) for event kinds.
//! - Zone enforcement on EVENT and REQ.
//! - F11 (PRD-010): Federated kind allowlist filtering for mesh peers.

use nostr_bbs_core::event::NostrEvent;
use nostr_bbs_core::governance;
use nostr_bbs_core::{KIND_BAN, KIND_MUTE, KIND_REPORT_NIP56, KIND_UNBAN, KIND_UNMUTE};
use wasm_bindgen::JsValue;
use worker::*;

use crate::auth;
use crate::moderation;
use crate::trust::{self, TrustLevel};
use crate::zone_config::ZoneConfig;

use super::broadcast::{event_treatment, EventTreatment};
use super::calendar_projection;
use super::filter::{self, NostrFilter};
use super::NostrRelayDO;

use nostr_bbs_core::KIND_CALENDAR_RSVP;

// ---------------------------------------------------------------------------
// Security limits
// ---------------------------------------------------------------------------

const MAX_CONTENT_SIZE: usize = 64 * 1024;
const MAX_REGISTRATION_CONTENT_SIZE: usize = 8 * 1024;
const MAX_TAG_COUNT: usize = 2000;
const MAX_TAG_VALUE_SIZE: usize = 1024;
const MAX_TIMESTAMP_DRIFT: u64 = 60 * 60 * 24 * 7;
const MAX_SUBSCRIPTIONS: usize = 20;

/// NIP-59: gift-wrap event kind. Signed by a fresh ephemeral key per message;
/// recipient-gated via the first `["p", <hex>]` tag rather than the author.
const GIFT_WRAP_KIND: u64 = 1059;

/// NIP-29: Admin-only group management/moderation kinds.
fn is_nip29_admin_kind(kind: u64) -> bool {
    (9000..=9020).contains(&kind) || (39000..=39002).contains(&kind)
}

/// Phase C (write side): whether an RSVP (kind 31925) is permitted to be written,
/// given the AUTHOR's resolved projection tier for the RSVP's TARGET event.
///
/// An RSVP attaches its author to a target event. If the author can only see that
/// target as free/busy (`FreeBusy`) or not at all (`Omit`), accepting the RSVP is a
/// privacy/integrity leak. Only a `Full` tier (which already covers admins/owners
/// via `project_tier`'s short-circuit) is write-permitted.
///
/// Pure predicate over the already-resolved tier so the gate decision is
/// unit-testable without a `worker::Env` / D1. The caller resolves the target
/// zone/venue from D1 and computes the tier via
/// [`calendar_projection::project_tier`].
pub fn rsvp_write_permitted(tier: &calendar_projection::Projection) -> bool {
    matches!(tier, calendar_projection::Projection::Full)
}

/// Phase C (write side): whether a zone-tagged calendar event (31922/31923) is
/// permitted to be written. A zone-tagged event requires the author to hold write
/// access to that zone; an untagged event is unscoped and always permitted here.
///
/// `has_write` is the already-resolved
/// [`trust::has_zone_write_access`](crate::trust::has_zone_write_access) result.
/// Pure predicate so the decision is unit-testable without a `worker::Env`.
pub fn calendar_write_permitted(zone: Option<&str>, has_write: bool) -> bool {
    match zone {
        Some(_) => has_write,
        None => true,
    }
}

/// NIP-59: extract the gift-wrap (kind-1059) RECIPIENT pubkey from the first
/// `["p", <hex>]` tag. Returns `None` when the event is not a gift wrap, or when
/// no non-empty `p` tag is present. The recipient — not the ephemeral author —
/// is the principal the membership gate is applied to.
///
/// Pure over the event so the routing decision is unit-testable without an
/// `is_whitelisted` D1 lookup / `worker::Env`.
pub fn gift_wrap_recipient(event: &NostrEvent) -> Option<String> {
    if event.kind != GIFT_WRAP_KIND {
        return None;
    }
    match filter::tag_value(event, "p") {
        Some(pk) if !pk.is_empty() => Some(pk),
        _ => None,
    }
}

/// P1-6: whether an event must be rejected by the governance ActionResponse
/// admin gate. Returns `true` when the event is kind-31403 (approve/reject of
/// an agent action request) and the signer is NOT an admin.
///
/// Extracted as a pure predicate so the gate decision is unit-testable without
/// a `worker::Env` / `WebSocket`.
pub fn governance_response_blocked(kind: u64, is_admin: bool) -> bool {
    kind == governance::KIND_ACTION_RESPONSE && !is_admin
}

/// The `broker_cases` columns the 31403 projection reads to hydrate a case
/// aggregate (COM-16). Deserialised straight from a D1 row.
#[derive(serde::Deserialize)]
pub(crate) struct BrokerCaseRow {
    pub category: String,
    pub state: String,
    pub created_by: String,
    pub from_share_state: Option<String>,
    pub to_share_state: Option<String>,
}

/// The persistable result of projecting a 31403 onto a case: the row to append
/// to `broker_decisions` and the new `broker_cases.state`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResponseProjection {
    pub decision_id: String,
    /// `broker_decisions.outcome` — the canonical action string.
    pub outcome: String,
    /// `broker_decisions.outcome_detail` — delegate target / pattern id /
    /// precedent scope / amend diff; `None` for approve/reject.
    pub outcome_detail: Option<String>,
    pub prior_decision_id: Option<String>,
    /// `broker_cases.state` after the decision — never `under_review` for a
    /// well-formed outcome.
    pub new_state: governance::broker::CaseState,
    pub reasoning: String,
}

/// Plan the 31403 ActionResponse projection (COM-16 / F3).
///
/// This is the relay's consumer of the tested escalation state machine: it
/// hydrates a `BrokerCase` from the case's D1 row (or a sensible default when
/// the row is absent — a response can arrive before its request projected) and
/// routes the parsed outcome through **`DecisionOrchestrator::decide`**, so a
/// `delegate`/`promote`/`precedent` outcome reaches the matching `CaseState`
/// instead of the former fixed `under_review` fallback. The `Env`/D1 read + write
/// stay in [`NostrRelayDO::project_action_response`]; this pure seam is what makes
/// the lifecycle unit-testable in the worker crate without a live D1.
pub(crate) fn plan_action_response(
    case_id: &str,
    case_row: Option<&BrokerCaseRow>,
    event_id: &str,
    content: &str,
    responder_pubkey: &str,
    latest_decision_id: Option<String>,
    now: u64,
) -> std::result::Result<ResponseProjection, governance::broker::OrchestrationError> {
    use governance::broker::{
        CaseCategory, CaseSnapshot, CaseState, DecisionOrchestrator, DecisionOutcome, ShareState,
    };

    // Parse the typed outcome from the signed 31403 content; a malformed or
    // unknown action is rejected (the case is left untouched, never parked).
    let outcome = DecisionOutcome::from_response_content(content).ok_or_else(|| {
        governance::broker::OrchestrationError::ShareTransitionRejected(
            "unrecognised or malformed 31403 action response".to_string(),
        )
    })?;
    let reasoning = serde_json::from_str::<serde_json::Value>(content)
        .ok()
        .and_then(|v| {
            v.get("reasoning")
                .and_then(|r| r.as_str())
                .map(str::to_string)
        })
        .unwrap_or_default();
    let decision_id = format!("dec-{}", &event_id[..16.min(event_id.len())]);

    let snapshot = match case_row {
        Some(row) => CaseSnapshot {
            id: case_id.to_string(),
            category: CaseCategory::parse(&row.category),
            created_by: row.created_by.clone(),
            state: CaseState::parse(&row.state),
            from_state: row.from_share_state.as_deref().and_then(ShareState::parse),
            to_state: row.to_share_state.as_deref().and_then(ShareState::parse),
            latest_decision_id,
        },
        None => CaseSnapshot {
            id: case_id.to_string(),
            category: CaseCategory::ManualSubmission,
            created_by: String::new(),
            state: CaseState::Open,
            from_state: None,
            to_state: None,
            latest_decision_id,
        },
    };

    // Hydrate the aggregate and route through the tested orchestrator.
    let mut case = snapshot.hydrate(now);
    let orch = DecisionOrchestrator;
    let report = orch.decide(
        &mut case,
        decision_id.clone(),
        outcome.clone(),
        responder_pubkey,
        reasoning.clone(),
        now,
    )?;

    Ok(ResponseProjection {
        decision_id,
        outcome: outcome.action_str().to_string(),
        outcome_detail: outcome.detail().map(str::to_string),
        prior_decision_id: report.entry.prior_decision_id.clone(),
        new_state: case.state,
        reasoning,
    })
}

/// F6 (DDD §7a): the derived decision id the relay assigns a governance event.
///
/// The 31403 projection keys `broker_decisions.decision_id` as `dec-<first 16
/// hex of the event id>`. Supersession references a *prior decision event* by
/// `e`-tag; resolving that event id to its decision id is this same deterministic
/// derivation, so the superseded row can be located without a second lookup.
pub(crate) fn decision_id_for_event(event_id: &str) -> String {
    format!("dec-{}", &event_id[..16.min(event_id.len())])
}

/// The persistable result of projecting a *superseding* 31403 onto a case
/// (F6, `DDD-judgment-broker-context.md` §7a). Distinct from
/// [`ResponseProjection`]: it also names the decision it supersedes, so the
/// projection can mark that prior row `superseded_by` (retained, auditable —
/// never mutated) while appending this one and moving the case to `Superseded`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SupersessionProjection {
    /// `broker_decisions.decision_id` of the superseding decision.
    pub decision_id: String,
    /// The decision id this supersedes: the superseding row's
    /// `prior_decision_id` AND the value written to the superseded row's
    /// `superseded_by` column.
    pub superseded_decision_id: String,
    pub outcome: String,
    pub outcome_detail: Option<String>,
    pub reasoning: String,
    /// `broker_cases.state` after the supersession — always `Superseded` for a
    /// well-formed, authorised supersede.
    pub new_state: governance::broker::CaseState,
}

/// Why a superseding 31403 was rejected at the projection (F6, DDD §7a).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SupersessionError {
    /// The superseder is neither the original signer nor a higher governance
    /// role (§7a.1). The `RelayGovernanceGate` rejects this on ingest.
    Unauthorised { superseder: String },
    /// The superseding content carried no recognised `DecisionOutcome`.
    MalformedOutcome,
    /// No stated reason (§7a.2 point 3).
    MissingReason,
    /// The `supersedes` `e`-tag did not resolve to a prior decision.
    MissingSupersededDecision,
}

/// Plan the *supersession* projection for a superseding kind-31403 (F6,
/// `DDD-judgment-broker-context.md` §7a).
///
/// Pure seam behind the async [`NostrRelayDO::project_supersession`] and the
/// ingest-time authority gate, mirroring how [`plan_action_response`] is the pure
/// seam over `DecisionOrchestrator::decide`. It:
///
/// 1. computes the §7a.1 authority (`supersede_authority`) from the original
///    signer + role ranks the relay supplies;
/// 2. routes the superseding decision through the single-sourced aggregate
///    `BrokerCase::supersede`, which enforces authority, a stated reason and
///    outcome-detail completeness, appends the superseding decision **without
///    mutating the prior one**, and moves the case to `Superseded`.
///
/// An unauthorised superseder yields `Err(Unauthorised)` — the testable rejection
/// the canon requires (§7a.4). `superseded_event_id` is the `e`-tag target;
/// `original_signer`/`original_rank`/`superseder_rank`/`case_created_by` are read
/// from D1 by the async caller.
#[allow(clippy::too_many_arguments)]
pub(crate) fn plan_supersession(
    superseding_event_id: &str,
    superseded_event_id: Option<&str>,
    content: &str,
    superseder_pubkey: &str,
    original_signer: &str,
    original_rank: u8,
    superseder_rank: u8,
    case_created_by: &str,
    now: u64,
) -> std::result::Result<SupersessionProjection, SupersessionError> {
    use governance::broker::{
        supersede_authority, CaseCategory, CaseSnapshot, CaseState, DecisionOutcome,
    };

    let superseded_event_id =
        superseded_event_id.ok_or(SupersessionError::MissingSupersededDecision)?;
    if superseded_event_id.is_empty() {
        return Err(SupersessionError::MissingSupersededDecision);
    }
    let superseded_decision_id = decision_id_for_event(superseded_event_id);

    let outcome =
        DecisionOutcome::from_response_content(content).ok_or(SupersessionError::MalformedOutcome)?;
    let reasoning = serde_json::from_str::<serde_json::Value>(content)
        .ok()
        .and_then(|v| {
            v.get("reasoning")
                .and_then(|r| r.as_str())
                .map(str::to_string)
        })
        .unwrap_or_default();

    let authority =
        supersede_authority(original_signer, superseder_pubkey, original_rank, superseder_rank);

    // Route through the single-sourced aggregate: a hydrated Decided case that
    // the superseding decision acts on. The snapshot's created_by preserves the
    // self-review guard; state=Decided is a superseding-eligible terminal state.
    let snapshot = CaseSnapshot {
        id: String::new(),
        category: CaseCategory::ManualSubmission,
        created_by: case_created_by.to_string(),
        state: CaseState::Decided,
        from_state: None,
        to_state: None,
        latest_decision_id: Some(superseded_decision_id.clone()),
    };
    let mut case = snapshot.hydrate(now);
    let superseding_decision_id = decision_id_for_event(superseding_event_id);

    case.supersede(
        superseding_decision_id.clone(),
        superseded_decision_id.clone(),
        outcome.clone(),
        superseder_pubkey,
        reasoning.clone(),
        authority,
        now,
    )
    .map_err(|e| match e {
        governance::broker::CaseError::UnauthorisedSupersession { superseder } => {
            SupersessionError::Unauthorised { superseder }
        }
        governance::broker::CaseError::MissingSupersessionReason => {
            SupersessionError::MissingReason
        }
        _ => SupersessionError::MalformedOutcome,
    })?;

    Ok(SupersessionProjection {
        decision_id: superseding_decision_id,
        superseded_decision_id,
        outcome: outcome.action_str().to_string(),
        outcome_detail: outcome.detail().map(str::to_string),
        reasoning,
        new_state: case.state,
    })
}

/// ADR-099: resolve the EFFECTIVE principal a session's access derives from.
///
/// When device keys are enabled and the authing `pubkey` is a registered,
/// non-revoked device key, its session "acts as" the OWNER for READ scope and
/// the OWNER is the principal the write-gate allowlist is checked against. The
/// device's own signature is verified UNCHANGED upstream — this only rebinds
/// *who is treated as the principal* for access, never the event's pubkey/sig.
///
/// `device_owner` is the already-resolved `device_owner(pubkey)` D1 lookup
/// (`Some(owner)` for a non-revoked device row, `None` otherwise). `enabled` is
/// `DEVICE_KEYS_ENABLED == "true"`.
///
/// Gate-off (`enabled == false`) ⇒ identity passthrough: returns `pubkey`
/// verbatim, so a device key is just an unknown pubkey and every existing gate
/// behaves exactly as before. Gate-on with no device row ⇒ also passthrough.
///
/// Pure over its inputs so the resolution is unit-testable without a
/// `worker::Env` / D1.
pub fn effective_principal(pubkey: &str, device_owner: Option<&str>, enabled: bool) -> String {
    if enabled {
        if let Some(owner) = device_owner {
            return owner.to_string();
        }
    }
    pubkey.to_string()
}

// ---------------------------------------------------------------------------
// NIP-01: EVENT handling
// ---------------------------------------------------------------------------

impl NostrRelayDO {
    pub(crate) async fn handle_event(&self, ws: &WebSocket, ip: &str, event: NostrEvent) {
        // Rate limit
        if !self.check_rate_limit(ip) {
            Self::send_notice(ws, "rate limit exceeded");
            return;
        }

        // Validate event structure
        if !Self::validate_event(&event) {
            Self::send_ok(ws, &event.id, false, "invalid: event validation failed");
            return;
        }

        // NIP-40: Reject events with an expired `expiration` tag
        if let Some(exp) = filter::tag_value(&event, "expiration") {
            if let Ok(exp_ts) = exp.parse::<u64>() {
                if exp_ts < auth::js_now_secs() {
                    Self::send_ok(ws, &event.id, false, "invalid: event expired");
                    return;
                }
            }
        }

        // Verify event ID and Schnorr signature before any side effects
        // including admission state changes or activity tracking.
        if nostr_bbs_core::verify_event_strict(&event).is_err() {
            Self::send_ok(
                ws,
                &event.id,
                false,
                "invalid: event id or signature verification failed",
            );
            return;
        }

        // NIP-59 gift wraps (kind-1059) are signed by a fresh ephemeral key per
        // message, so the author is intentionally NOT a member and the standard
        // author-membership check would always reject them. Instead, gate on the
        // RECIPIENT carried in the first `["p", <hex>]` tag: accept only if that
        // recipient is a whitelisted member. This bounds gift-wrap acceptance to
        // messages addressed to existing members (no spam to non-members) while
        // permitting the ephemeral author.
        if event.kind == GIFT_WRAP_KIND {
            let recipient_ok = match gift_wrap_recipient(&event) {
                Some(pk) => self.is_whitelisted(&pk).await,
                None => false,
            };
            if !recipient_ok {
                Self::send_ok(
                    ws,
                    &event.id,
                    false,
                    "blocked: gift-wrap recipient not whitelisted",
                );
                return;
            }
        } else {
            // ADR-099: a device-authored event is admitted under its OWNER's
            // allowlist. `effective_pubkey` returns the owner for a registered
            // non-revoked device key when DEVICE_KEYS_ENABLED, else the author
            // pubkey verbatim (gate-off / non-device ⇒ unchanged behaviour). The
            // event's signature was already verified strictly above against the
            // device's own key; we only rebind WHO the allowlist is checked for.
            let allowlist_pubkey = self.effective_pubkey(&event.pubkey).await;
            if !self.is_whitelisted(&allowlist_pubkey).await {
                Self::send_ok(ws, &event.id, false, "blocked: pubkey not whitelisted");
                return;
            }
        }

        // F11 (PRD-010): When mesh federation is active, events arriving from
        // a recognised mesh peer (listed in MESH_ALLOWED_REMOTE_DIDS) are
        // filtered against the federated_kinds allowlist. Local clients whose
        // pubkey is NOT in the remote DIDs list bypass this check entirely.
        if self.is_mesh_peer(&event.pubkey) && !self.is_federated_kind_allowed(event.kind) {
            Self::send_ok(
                ws,
                &event.id,
                false,
                "blocked: event kind not in federated_kinds allowlist",
            );
            return;
        }

        // Suspension and silence check
        let (suspended, silenced) = trust::check_suspension(&event.pubkey, &self.env).await;
        if suspended {
            Self::send_ok(ws, &event.id, false, "blocked: account suspended");
            return;
        }
        if silenced {
            Self::send_ok(
                ws,
                &event.id,
                false,
                "blocked: account silenced (read-only)",
            );
            return;
        }

        // WI-2: kind-1 / kind-42 ingress check against moderation_actions
        // (60s DO cache). Applies to any content-producing kind we care
        // about. Admins bypass so they can e.g. publish warnings even
        // while under moderation for other reasons.
        //
        // P2-03: use admin_cache to avoid redundant D1 queries on every event.
        if matches!(event.kind, 1 | 42)
            && !self.admin_cache.is_admin(&event.pubkey, &self.env).await
            && self.mod_cache.is_blocked(&event.pubkey, &self.env).await
        {
            Self::send_ok(ws, &event.id, false, "blocked: author is banned or muted");
            return;
        }

        // Trust-level gating for specific event kinds
        // P2-03: cached lookup — same TTL entry reused from above if still fresh.
        let is_admin = self.admin_cache.is_admin(&event.pubkey, &self.env).await;
        if !is_admin {
            let trust_level = trust::get_trust_level(&event.pubkey, &self.env).await;

            // kind-40 (channel creation): TL2+ required
            if event.kind == 40 && trust_level < TrustLevel::Regular {
                Self::send_ok(
                    ws,
                    &event.id,
                    false,
                    "restricted: TL2+ required for channel creation",
                );
                return;
            }

            // kind-41 (channel metadata/pin): TL2+ for own channel, TL3+ for any
            if event.kind == 41 {
                let Some(channel_id) = filter::tag_value(&event, "e") else {
                    Self::send_ok(ws, &event.id, false, "invalid: missing channel tag");
                    return;
                };
                if trust_level < TrustLevel::Regular {
                    Self::send_ok(
                        ws,
                        &event.id,
                        false,
                        "restricted: TL2+ required for channel metadata",
                    );
                    return;
                }
                // If TL2 (not TL3), verify they are the channel creator
                if trust_level < TrustLevel::Trusted
                    && !self.is_channel_creator(&event.pubkey, &channel_id).await
                {
                    Self::send_ok(
                        ws,
                        &event.id,
                        false,
                        "restricted: TL3+ required to modify others' channels",
                    );
                    return;
                }
            }

            // kind-1984 (report): TL1+ required
            if event.kind == KIND_REPORT_NIP56 && trust_level < TrustLevel::Member {
                Self::send_ok(
                    ws,
                    &event.id,
                    false,
                    "restricted: TL1+ required to report content",
                );
                return;
            }

            // kind-5 (deletion): own events always allowed; others' events require TL3+
            if event.kind == 5 {
                let targets_others = self.deletion_targets_others(&event).await;
                if targets_others && trust_level < TrustLevel::Trusted {
                    Self::send_ok(
                        ws,
                        &event.id,
                        false,
                        "restricted: TL3+ required to delete others' events",
                    );
                    return;
                }
            }
        }

        // NIP-29: Admin-only group management kinds
        if is_nip29_admin_kind(event.kind) {
            // NIP-29 TODO: This enforces the h-tag/admin gate, but full group
            // metadata should be relay-key-generated rather than accepted from
            // arbitrary clients.
            if filter::tag_value(&event, "h").is_none() {
                Self::send_ok(ws, &event.id, false, "invalid: missing group tag");
                return;
            }
            if !is_admin {
                Self::send_ok(ws, &event.id, false, "blocked: admin-only group action");
                return;
            }
        }

        // Agent Control Surface Protocol: governance kinds (31400-31405) are
        // only accepted from pubkeys registered in the agent_registry table.
        // Human responses (kind 31403, approve/reject of agent action requests)
        // are exempt from the agent-registry gate but, per P1-6, MUST come from
        // an admin -- they are privileged decisions, not generic member actions.
        if governance::is_governance_kind(event.kind)
            && event.kind != governance::KIND_ACTION_RESPONSE
            && !self.is_registered_agent(&event.pubkey).await
        {
            Self::send_ok(
                ws,
                &event.id,
                false,
                "blocked: pubkey not in agent registry",
            );
            return;
        }

        // P1-6: kind-31403 ActionResponse (approve/reject) is admin-only. Uses
        // the same admin check as the moderation mirror. Reject non-admins.
        if governance_response_blocked(event.kind, is_admin) {
            Self::send_ok(
                ws,
                &event.id,
                false,
                "blocked: admin-only governance action response",
            );
            return;
        }

        // F6 (DDD §7a.1): a *superseding* kind-31403 — one carrying an `e`-tag
        // with the `supersedes` marker — is additionally authority-gated. Only
        // the original decision's signer, or a human of a strictly higher
        // governance role, may supersede a published decision. The
        // `RelayGovernanceGate` rejects any other superseder here, exactly as it
        // rejects an orphan response under Invariant 2 — before the event is
        // saved or projected.
        if event.kind == governance::KIND_ACTION_RESPONSE {
            if let Some(superseded_event_id) =
                governance::extract_supersedes_target(&event.tags)
            {
                if !self
                    .supersession_authorised(&event.pubkey, superseded_event_id)
                    .await
                {
                    Self::send_ok(
                        ws,
                        &event.id,
                        false,
                        "blocked: unauthorised supersession",
                    );
                    return;
                }
            }
        }

        // Zone enforcement for channel messages (kind-42)
        if event.kind == 42 {
            let Some(channel_id) = filter::tag_value(&event, "e") else {
                Self::send_ok(ws, &event.id, false, "invalid: missing channel tag");
                return;
            };
            let zone = trust::get_channel_zone(&channel_id, &self.env)
                .await
                .unwrap_or_else(|| "home".to_string());
            // Writes route through the write gate (write_cohorts ?? required_cohorts)
            // so a public zone can be read-by-all yet write-restricted.
            if !is_admin && !trust::has_zone_write_access(&event.pubkey, &zone, &self.env).await {
                Self::send_ok(ws, &event.id, false, "zone access denied");
                return;
            }
        }

        // Phase C (write side): NIP-52 calendar kinds carry their access binding
        // natively, not via a channel-id lookup. The READ path projects them
        // per-tier; the WRITE path must validate the author against the SAME
        // data-tier rules so a lower-tier author cannot inject an RSVP into, or a
        // calendar event onto, a zone they cannot fully see/write.
        //
        //   - 31925 RSVP: an RSVP attaches the author to a target event. If the
        //     author can only see that target as free/busy (or not at all), the
        //     RSVP is a privacy/integrity leak — it surfaces participation in an
        //     event the author isn't a full participant of. We resolve the TARGET
        //     from D1 (never an author-mirrored tag, which is spoofable) and
        //     compute the AUTHOR's projection tier for it; accept only on Full.
        //     Admins/owners are inherently Full. An unresolvable target denies for
        //     non-admins (deny-by-default: blocks pre-publishing RSVPs to a target
        //     that isn't visible yet).
        //
        //   - 31922/31923 calendar events: a zone-tagged event must come from an
        //     author with write access to that zone (mirrors kind-42). Untagged
        //     calendar events are unscoped and keep prior behaviour.
        if event.kind == KIND_CALENDAR_RSVP && !is_admin {
            let permitted = match self.resolve_rsvp_target(&event).await {
                Some((zone, venue)) => {
                    // `is_owner=false`: a non-admin author is never the relay owner.
                    // `project_tier` short-circuits admins/owners to Full anyway;
                    // here we ask the author's own tier for the TARGET's real zone.
                    let (author_cohorts, author_cohort_admin) =
                        trust::get_viewer_cohorts(&event.pubkey, &self.env).await;
                    let tier = calendar_projection::project_tier(
                        &author_cohorts,
                        &zone,
                        venue.as_deref(),
                        false,
                        author_cohort_admin,
                    );
                    rsvp_write_permitted(&tier)
                }
                // Target not resolvable: deny by default for non-admins. Prevents
                // pre-publishing an RSVP to an event that is not yet visible.
                None => false,
            };
            if !permitted {
                Self::send_ok(ws, &event.id, false, "blocked: rsvp not permitted");
                return;
            }
        } else if matches!(
            event.kind,
            nostr_bbs_core::KIND_CALENDAR_DATE_EVENT | nostr_bbs_core::KIND_CALENDAR_EVENT
        ) && !is_admin
        {
            // Only zone-tagged calendar events are write-gated; untagged events
            // are unscoped and retain prior behaviour.
            let zone = nostr_bbs_core::read_zone_tag(&event);
            let has_write = match zone {
                Some(z) => trust::has_zone_write_access(&event.pubkey, z, &self.env).await,
                None => false,
            };
            if !calendar_write_permitted(zone, has_write) {
                Self::send_ok(ws, &event.id, false, "blocked: zone access denied");
                return;
            }
        }

        // NIP-16 event treatment
        let treatment = event_treatment(event.kind);

        if treatment == EventTreatment::Ephemeral {
            Self::send_ok(ws, &event.id, true, "");
            self.broadcast_event(&event).await;
            return;
        }

        // Save to D1
        if self.save_event(&event, treatment).await {
            Self::send_ok(ws, &event.id, true, "");
            self.broadcast_event(&event).await;

            // Activity tracking: increment posts_created and update last_active
            // for content-producing event kinds (kind-1 text, kind-42 channel msg,
            // kind-40 channel create, kind-7 reaction, kind-1984 report).
            if matches!(event.kind, 1 | 7 | 40 | 42 | KIND_REPORT_NIP56) {
                trust::increment_posts_created(&event.pubkey, &self.env).await;
            }
            trust::update_last_active(&event.pubkey, &self.env).await;

            // After activity update, check for trust promotion
            let _ = trust::check_promotion(&event.pubkey, &self.env).await;

            // NIP-09: Process deletion events -- remove targeted events by same author
            if event.kind == 5 {
                self.process_deletion(&event).await;
            }

            // NIP-56: Process report events -- insert into reports table and check auto-hide
            if event.kind == KIND_REPORT_NIP56 {
                self.process_report(&event).await;
            }

            // WI-2 + P0-4(a): mirror moderation-action Nostr events (kind 30910
            // ban, 30911 mute, 30915 unban, 30916 unmute) into the local
            // `moderation_actions` table so the ingress gate can reject content
            // from muted/banned authors AND so a lifted ban/mute stops being
            // enforced. Only respected when the signer is an admin on this relay.
            if matches!(event.kind, KIND_BAN | KIND_MUTE | KIND_UNBAN | KIND_UNMUTE) && is_admin {
                self.mirror_moderation_action(&event).await;
                if let Some(target) = filter::tag_value(&event, "p") {
                    self.mod_cache.invalidate(&target);
                }
            }

            // Agent Control Surface: project ActionRequest events (31402)
            // into the broker_cases table for D1-queryable governance inbox.
            // F6 (DDD §7a.2): an ActionRequest carrying an `appeal` `e`-tag
            // marker is an *appeal* — it reopens the cited case rather than
            // opening a fresh one.
            if event.kind == governance::KIND_ACTION_REQUEST {
                if governance::extract_appeal_target(&event.tags).is_some() {
                    self.project_appeal(&event).await;
                } else {
                    self.project_action_request(&event).await;
                }
            }

            // Agent Control Surface: project ActionResponse events (31403)
            // into broker_decisions and update the broker_cases state. F6 (DDD
            // §7a): a *superseding* response (with a `supersedes` `e`-tag) marks
            // the superseded decision `Superseded` and chains forward, rather
            // than recording a first-order decision.
            if event.kind == governance::KIND_ACTION_RESPONSE {
                if governance::extract_supersedes_target(&event.tags).is_some() {
                    self.project_supersession(&event).await;
                } else {
                    self.project_action_response(&event).await;
                }
            }
        } else {
            Self::send_ok(ws, &event.id, false, "error: failed to save event");
        }
    }

    fn validate_event(event: &NostrEvent) -> bool {
        if event.id.len() != 64 || event.pubkey.len() != 64 || event.sig.len() != 128 {
            return false;
        }

        let is_reg = event.kind == 0 || event.kind == 9024;
        let max_content = if is_reg {
            MAX_REGISTRATION_CONTENT_SIZE
        } else {
            MAX_CONTENT_SIZE
        };
        if event.content.len() > max_content {
            return false;
        }

        if event.tags.len() > MAX_TAG_COUNT {
            return false;
        }
        for tag in &event.tags {
            for v in tag {
                if v.len() > MAX_TAG_VALUE_SIZE {
                    return false;
                }
            }
        }

        let now = auth::js_now_secs();
        let drift = now.abs_diff(event.created_at);
        if drift > MAX_TIMESTAMP_DRIFT {
            return false;
        }

        true
    }
}

// ---------------------------------------------------------------------------
// NIP-01: REQ / CLOSE handling
// ---------------------------------------------------------------------------

impl NostrRelayDO {
    pub(crate) async fn handle_req(
        &self,
        session_id: u64,
        ip: &str,
        sub_id: &str,
        filters: Vec<NostrFilter>,
    ) {
        let ws = {
            let sessions = self.sessions.borrow();
            match sessions.get(&session_id) {
                Some(s) => s.ws.clone(),
                None => return,
            }
        };

        // Per-IP rate limit, consistent with the EVENT path. REQ was previously
        // ungated, letting one IP drive unbounded D1 scans; gate it identically.
        if !self.check_rate_limit(ip) {
            Self::send_notice(&ws, "rate limit exceeded");
            return;
        }

        // Check subscription limit
        {
            let sessions = self.sessions.borrow();
            if let Some(session) = sessions.get(&session_id) {
                if session.subscriptions.len() >= MAX_SUBSCRIPTIONS {
                    Self::send_notice(&ws, "too many subscriptions");
                    return;
                }
            }
        }

        // Store subscription in memory
        {
            let mut sessions = self.sessions.borrow_mut();
            if let Some(session) = sessions.get_mut(&session_id) {
                session
                    .subscriptions
                    .insert(sub_id.to_string(), filters.clone());
            }
        }

        // Persist subscriptions to DO storage so they survive hibernation
        self.save_subscriptions(session_id).await;

        // Determine the requesting session's pubkey and zone access for filtering
        let session_pubkey = {
            let sessions = self.sessions.borrow();
            sessions
                .get(&session_id)
                .and_then(|s| s.authed_pubkey.clone())
        };

        // NIP-59: kind-1059 (Sealed DM) read gate + mandatory #p rewrite. Shared
        // with the COUNT path so both reject unauthenticated kind-1059 reads and
        // bind results to the authed recipient identically.
        let filters = match Self::gate_kind_1059_filters(filters, &session_pubkey) {
            Some(f) => f,
            None => {
                Self::send_notice(
                    &ws,
                    "auth-required: must authenticate to receive kind-1059 DMs",
                );
                return;
            }
        };

        // Query D1 for matching events
        let events = self.query_events(&filters).await;

        // Resolve the viewer's effective read scope once (ADR-099 device→owner
        // rebinding, admin status, calendar cohorts), then apply the SHARED
        // per-event zone/cohort/NIP-52-calendar gate (`authorize_event`). The
        // exact same gate runs on the COUNT and live-broadcast paths, so the
        // three read paths can never diverge on what a viewer may read.
        let zones = ZoneConfig::load(&self.env);
        let ctx = self.resolve_viewer_context(session_pubkey.clone()).await;

        // Count events actually DELIVERED to the reader this REQ (post-gate). An
        // event withheld by zone access was never read, so we tally survivors and
        // batch a single `posts_read` increment at EOSE for the TL0→TL1 promotion.
        let mut delivered: i32 = 0;
        for event in &events {
            match self.authorize_event(event, &ctx, &zones).await {
                ReadDecision::Deliver => {
                    Self::send_event(&ws, sub_id, event);
                    delivered += 1;
                }
                ReadDecision::DeliverAs(out) => {
                    Self::send_event(&ws, sub_id, &out);
                    delivered += 1;
                }
                ReadDecision::Withhold => {}
            }
        }
        Self::send_eose(&ws, sub_id);

        // O1: count this REQ's reads toward TL0→TL1 promotion. Gate on an
        // authenticated session and at least one delivered event; the
        // `increment_posts_read_by` UPDATE is whitelist-scoped, so a
        // non-member authed pubkey is a harmless no-op. We charge the read to
        // the literal session pubkey (the identity that subscribed), not the
        // device→owner `access_pubkey` rebinding used for zone reads. After the
        // batched increment, run the same `check_promotion` the EVENT path uses
        // so a reader can cross the threshold without needing to also write.
        if delivered > 0 {
            if let Some(pk) = &session_pubkey {
                trust::increment_posts_read_by(pk, delivered, &self.env).await;
                // ADR-102: a delivered read is activity. Stamp `last_active_at`
                // so a read-only member's inactivity clock resets, mirroring
                // the EVENT path's `update_last_active`. Without this, an active
                // lurker who never writes would drift past the ~6-month
                // inactivity gate and be demoted by the cron sweep despite
                // reading daily. The UPDATE is whitelist-scoped, so a non-member
                // authed pubkey is a harmless no-op.
                trust::update_last_active(pk, &self.env).await;
                let _ = trust::check_promotion(pk, &self.env).await;
            }
        }
    }

    /// Phase C: project a single NIP-52 calendar event for one viewer.
    ///
    /// The projector is the COMPLETE access decision — there is no upstream zone
    /// read-gate for calendar kinds. A live probe proved a gate-then-project
    /// ordering wrong: the gate omitted any event in a zone the viewer was not a
    /// member of, so the FreeBusy / cross-zone-Full tiers never ran. The pure
    /// projector applies the operator-approved matrix end to end
    /// (full / free-busy-redacted / omit), deny-by-default for unknown zones.
    ///
    /// For RSVPs (kind 31925) the target event's zone AND venue are resolved from
    /// the STORED referenced event (never from an author-mirrored tag on the RSVP,
    /// which is spoofable with the gate removed). The RSVP is served only when the
    /// viewer's tier for the target is `Full` — an RSVP leaks participants, so a
    /// free/busy tier omits it. If the target cannot be resolved, the RSVP is
    /// served only to admin or the RSVP's owner (deny-by-default).
    async fn project_calendar_for_viewer(
        &self,
        event: &NostrEvent,
        session_pubkey: &Option<String>,
        viewer_cohorts: &[String],
        viewer_is_admin: bool,
        _zones: &ZoneConfig,
    ) -> Option<NostrEvent> {
        let is_owner = session_pubkey
            .as_deref()
            .map(|pk| pk == event.pubkey)
            .unwrap_or(false);

        // RSVPs: the TARGET event's tier decides. Resolve zone + venue from the
        // stored referenced event (spoof-resistant). Serve only on a Full tier;
        // a FreeBusy/Omit tier would leak the participant list.
        if event.kind == KIND_CALENDAR_RSVP {
            let Some((zone, venue)) = self.resolve_rsvp_target(event).await else {
                // Target unresolvable: deny by default, admin/owner only.
                return if viewer_is_admin || is_owner {
                    Some(event.clone())
                } else {
                    None
                };
            };
            let tier = calendar_projection::project_tier(
                viewer_cohorts,
                &zone,
                venue.as_deref(),
                is_owner,
                viewer_is_admin,
            );
            return match tier {
                calendar_projection::Projection::Full => Some(event.clone()),
                // FreeBusy or Omit ⇒ withhold the RSVP entirely (it would leak
                // participation in an event the viewer only sees as a busy block,
                // or not at all).
                _ => None,
            };
        }

        // Calendar events (31922/31923): the projector decides everything.
        calendar_projection::project_calendar_event(
            viewer_cohorts,
            event,
            is_owner,
            viewer_is_admin,
        )
    }

    /// Resolve the owning zone slug AND venue of a calendar RSVP's TARGET event by
    /// reading the referenced event's stored `zone`/`venue` tags from D1. The RSVP
    /// references its target via an `e` (event id) tag.
    ///
    /// SECURITY: the target's zone/venue are read from the STORED event, never
    /// from any tag the RSVP author mirrored onto the RSVP itself — with the read
    /// gate removed, an author-mirrored `zone=public` on an RSVP targeting a
    /// family event would otherwise leak that event. Returns `None` when the
    /// target cannot be resolved.
    async fn resolve_rsvp_target(&self, rsvp: &NostrEvent) -> Option<(String, Option<String>)> {
        let db = self.env.d1("DB").ok()?;

        #[derive(serde::Deserialize)]
        struct TagsRow {
            tags: String,
        }

        // Look up the referenced calendar event and read its zone + venue tags.
        let target_id = filter::tag_value(rsvp, "e")?;
        let stmt = db.prepare("SELECT tags FROM events WHERE id = ?1 LIMIT 1");
        let row = stmt
            .bind(&[JsValue::from_str(&target_id)])
            .ok()?
            .first::<TagsRow>(None)
            .await
            .ok()??;
        let tags: Vec<Vec<String>> = serde_json::from_str(&row.tags).ok()?;
        let zone = tags
            .iter()
            .find(|t| t.len() >= 2 && t[0] == nostr_bbs_core::ZONE_TAG)
            .map(|t| t[1].clone())?;
        let venue = tags
            .iter()
            .find(|t| t.len() >= 2 && t[0] == nostr_bbs_core::VENUE_TAG)
            .map(|t| t[1].clone());
        Some((zone, venue))
    }

    pub(crate) async fn handle_close(&self, session_id: u64, sub_id: &str) {
        {
            let mut sessions = self.sessions.borrow_mut();
            if let Some(session) = sessions.get_mut(&session_id) {
                session.subscriptions.remove(sub_id);
            }
        }

        // Persist updated subscriptions to DO storage
        self.save_subscriptions(session_id).await;
    }
}

// ---------------------------------------------------------------------------
// NIP-42: AUTH challenge/response
// ---------------------------------------------------------------------------

impl NostrRelayDO {
    /// Handle an AUTH response from a client (kind 22242 event).
    pub(crate) async fn handle_auth(&self, session_id: u64, ws: &WebSocket, event: NostrEvent) {
        // Must be kind 22242
        if event.kind != 22242 {
            Self::send_ok(ws, &event.id, false, "invalid: expected kind 22242");
            return;
        }

        // Verify signature
        if nostr_bbs_core::verify_event_strict(&event).is_err() {
            Self::send_ok(
                ws,
                &event.id,
                false,
                "invalid: signature verification failed",
            );
            return;
        }

        // Verify challenge tag matches session challenge
        let challenge_tag = filter::tag_value(&event, "challenge");
        let expected_challenge = {
            let sessions = self.sessions.borrow();
            sessions.get(&session_id).map(|s| s.challenge.clone())
        };

        match (challenge_tag, expected_challenge) {
            (Some(c), Some(expected)) if c == expected => {}
            _ => {
                Self::send_ok(ws, &event.id, false, "invalid: challenge mismatch");
                return;
            }
        }

        // Timestamp must be within 10 minutes
        let now = auth::js_now_secs();
        if now.abs_diff(event.created_at) > 600 {
            Self::send_ok(ws, &event.id, false, "invalid: auth event too old");
            return;
        }

        // Mark session as authenticated
        {
            let mut sessions = self.sessions.borrow_mut();
            if let Some(session) = sessions.get_mut(&session_id) {
                session.authed_pubkey = Some(event.pubkey.clone());
            }
        }

        // Persist auth state to DO storage so it survives hibernation
        self.save_auth(session_id, &event.pubkey).await;

        Self::send_ok(ws, &event.id, true, "");
    }
}

// ---------------------------------------------------------------------------
// Shared read-authorization (REQ / COUNT / live broadcast)
// ---------------------------------------------------------------------------

/// Resolved read scope for one viewer (session). Computed once per REQ/COUNT,
/// or once per candidate session on the broadcast path, then reused for every
/// event so the three read paths apply identical zone/cohort gating.
pub(crate) struct ViewerContext {
    pub session_pubkey: Option<String>,
    pub access_pubkey: Option<String>,
    pub is_admin: bool,
    pub viewer_cohorts: Vec<String>,
    pub viewer_is_admin: bool,
}

/// Per-event read decision shared by every read path.
pub(crate) enum ReadDecision {
    /// Deliver the event verbatim.
    Deliver,
    /// Deliver this calendar-projected / redacted replacement instead.
    DeliverAs(NostrEvent),
    /// Withhold the event from this viewer (zone/cohort/projection denial).
    Withhold,
}

impl NostrRelayDO {
    /// NIP-59 kind-1059 (Sealed DM) read gate + mandatory `#p` rewrite.
    ///
    /// If any filter requests kind-1059, the session must be authenticated; each
    /// such filter is rewritten to require `#p == authed pubkey`, preventing a
    /// client from reading another user's sealed DMs. Returns `None` when the
    /// request must be rejected (kind-1059 requested by an unauthenticated
    /// session). Shared by REQ and COUNT so neither can leak DMs.
    fn gate_kind_1059_filters(
        filters: Vec<NostrFilter>,
        session_pubkey: &Option<String>,
    ) -> Option<Vec<NostrFilter>> {
        let needs_kind_1059 = filters
            .iter()
            .any(|f| f.kinds.as_ref().is_some_and(|k| k.contains(&1059)));
        if !needs_kind_1059 {
            return Some(filters);
        }
        session_pubkey.as_ref().map(|authed_pk| {
            filters
                .into_iter()
                .map(|mut f| {
                    if f.kinds.as_ref().is_some_and(|k| k.contains(&1059)) {
                        f.extra
                            .insert("#p".to_string(), serde_json::json!([authed_pk]));
                    }
                    f
                })
                .collect::<Vec<_>>()
        })
    }

    /// Resolve a viewer's effective read scope (ADR-099 device→owner rebinding,
    /// admin status, calendar cohorts). The kind-1059 DM `#p` filter is bound to
    /// the literal `session_pubkey` upstream and deliberately NOT rebound here —
    /// only cohort/zone READ scope is rebound to the owner.
    pub(crate) async fn resolve_viewer_context(
        &self,
        session_pubkey: Option<String>,
    ) -> ViewerContext {
        let access_pubkey: Option<String> = match &session_pubkey {
            Some(pk) => Some(self.effective_pubkey(pk).await),
            None => None,
        };
        let is_admin = match &access_pubkey {
            Some(pk) => self.admin_cache.is_admin(pk, &self.env).await,
            None => false,
        };
        let (viewer_cohorts, cohort_admin) = match &access_pubkey {
            Some(pk) => trust::get_viewer_cohorts(pk, &self.env).await,
            None => (Vec::new(), false),
        };
        let viewer_is_admin = is_admin || cohort_admin;
        ViewerContext {
            session_pubkey,
            access_pubkey,
            is_admin,
            viewer_cohorts,
            viewer_is_admin,
        }
    }

    /// Apply the zone / cohort / NIP-52-calendar read gate to a single event for
    /// one resolved viewer. THE single source of truth for read authorization,
    /// shared by REQ, COUNT, and live broadcast.
    ///
    /// Decision matrix for a NON-member (non-admin), per zone visibility:
    ///   Public : defs + content served to everyone (incl. unauth).
    ///   Locked : defs served (tile renders) but content withheld.
    ///   Hidden : defs AND content omitted.
    /// Members (cohort match) and admins always receive both. NIP-52 calendar
    /// kinds are decided entirely by `project_calendar_for_viewer` (the per-tier
    /// projection IS the access decision), deny-by-default for unknown zones.
    pub(crate) async fn authorize_event(
        &self,
        event: &NostrEvent,
        ctx: &ViewerContext,
        zones: &ZoneConfig,
    ) -> ReadDecision {
        if calendar_projection::is_projected_calendar_kind(event.kind) {
            return match self
                .project_calendar_for_viewer(
                    event,
                    &ctx.session_pubkey,
                    &ctx.viewer_cohorts,
                    ctx.viewer_is_admin,
                    zones,
                )
                .await
            {
                Some(out) => ReadDecision::DeliverAs(out),
                None => ReadDecision::Withhold,
            };
        }

        // Zone-scoped channel kinds: kind-40 defs (channel id == event id),
        // kind-42 content (channel id == `e` tag).
        let channel_id: Option<String> = match event.kind {
            40 => Some(event.id.clone()),
            42 => filter::tag_value(event, "e"),
            _ => None,
        };

        if let Some(cid) = channel_id {
            let zone = trust::get_channel_zone(&cid, &self.env)
                .await
                .unwrap_or_else(|| "home".to_string());

            if !ctx.is_admin {
                let is_member = match &ctx.access_pubkey {
                    Some(pk) => trust::has_zone_access(pk, &zone, &self.env).await,
                    None => zones.is_public_read(&zone),
                };
                if !is_member {
                    if event.kind == 40 {
                        // Channel definition: served only if the zone is not
                        // Hidden (Locked/Public tiles render).
                        if !zones.defs_visible_to_nonmember(&zone) {
                            return ReadDecision::Withhold;
                        }
                    } else {
                        // Channel content (kind-42): withheld from non-members of
                        // Locked/Hidden zones.
                        return ReadDecision::Withhold;
                    }
                }
            }
        }

        ReadDecision::Deliver
    }
}

// ---------------------------------------------------------------------------
// NIP-45: COUNT
// ---------------------------------------------------------------------------

impl NostrRelayDO {
    /// Handle a COUNT request: return the number of matching events the session
    /// is AUTHORIZED to read.
    ///
    /// Applies the same read authorization as REQ (kind-1059 auth gate + `#p`
    /// rewrite, then the per-event zone/cohort/calendar gate). Without this,
    /// COUNT is an existence/count oracle that leaks how many sealed DMs a pubkey
    /// has received and message counts for Locked/Hidden zones and gated calendar
    /// events — all of which REQ correctly withholds.
    pub(crate) async fn handle_count(
        &self,
        session_id: u64,
        ip: &str,
        ws: &WebSocket,
        sub_id: &str,
        filters: Vec<NostrFilter>,
    ) {
        // Per-IP rate limit, consistent with the EVENT/REQ paths. COUNT was
        // previously ungated and is an equally cheap way to force unbounded D1
        // scans; gate it identically.
        if !self.check_rate_limit(ip) {
            Self::send_notice(ws, "rate limit exceeded");
            return;
        }

        let session_pubkey = {
            let sessions = self.sessions.borrow();
            sessions
                .get(&session_id)
                .and_then(|s| s.authed_pubkey.clone())
        };

        // kind-1059 gate identical to REQ; deny-by-default → count 0 on reject.
        let filters = match Self::gate_kind_1059_filters(filters, &session_pubkey) {
            Some(f) => f,
            None => {
                Self::send_count(ws, sub_id, 0);
                return;
            }
        };

        let events = self.query_events(&filters).await;
        let zones = ZoneConfig::load(&self.env);
        let ctx = self.resolve_viewer_context(session_pubkey).await;

        let mut count: u64 = 0;
        for event in &events {
            match self.authorize_event(event, &ctx, &zones).await {
                ReadDecision::Deliver | ReadDecision::DeliverAs(_) => count += 1,
                ReadDecision::Withhold => {}
            }
        }
        Self::send_count(ws, sub_id, count);
    }
}

// ---------------------------------------------------------------------------
// NIP-09: Deletion processing
// ---------------------------------------------------------------------------

impl NostrRelayDO {
    /// Process a kind-5 deletion event: delete targeted events by the same author.
    pub(crate) async fn process_deletion(&self, deletion_event: &NostrEvent) {
        let db = match self.env.d1("DB") {
            Ok(db) => db,
            Err(_) => return,
        };

        // Collect "e" tags (direct event ID targets)
        let target_ids: Vec<&str> = deletion_event
            .tags
            .iter()
            .filter(|t| t.len() >= 2 && t[0] == "e")
            .map(|t| t[1].as_str())
            .collect();

        // Delete events owned by the same pubkey
        for target_id in &target_ids {
            let stmt = db.prepare("DELETE FROM events WHERE id = ?1 AND pubkey = ?2");
            let _ = match stmt.bind(&[
                JsValue::from_str(target_id),
                JsValue::from_str(&deletion_event.pubkey),
            ]) {
                Ok(s) => s.run().await,
                Err(_) => continue,
            };
        }

        // Collect "a" tags (parameterized replaceable targets: "kind:pubkey:d-tag")
        let a_targets: Vec<&str> = deletion_event
            .tags
            .iter()
            .filter(|t| t.len() >= 2 && t[0] == "a")
            .map(|t| t[1].as_str())
            .collect();

        for a_ref in &a_targets {
            let parts: Vec<&str> = a_ref.split(':').collect();
            if parts.len() < 3 {
                continue;
            }
            let kind: f64 = match parts[0].parse() {
                Ok(k) => k,
                Err(_) => continue,
            };
            let pubkey = parts[1];
            let d_tag = parts[2];

            // Only allow deletion of own events
            if pubkey != deletion_event.pubkey {
                continue;
            }

            let stmt =
                db.prepare("DELETE FROM events WHERE kind = ?1 AND pubkey = ?2 AND d_tag = ?3");
            let _ = match stmt.bind(&[
                JsValue::from_f64(kind),
                JsValue::from_str(pubkey),
                JsValue::from_str(d_tag),
            ]) {
                Ok(s) => s.run().await,
                Err(_) => continue,
            };
        }
    }
}

// ---------------------------------------------------------------------------
// Trust / zone helper methods
// ---------------------------------------------------------------------------

impl NostrRelayDO {
    /// Check whether a pubkey is the creator of a channel (kind-40 event).
    pub(crate) async fn is_channel_creator(&self, pubkey: &str, channel_id: &str) -> bool {
        let db = match self.env.d1("DB") {
            Ok(db) => db,
            Err(_) => return false,
        };

        #[derive(serde::Deserialize)]
        struct ChannelCreatorRow {
            pubkey: String,
        }

        let stmt = db.prepare("SELECT pubkey FROM events WHERE id = ?1 AND kind = 40 LIMIT 1");
        match stmt.bind(&[JsValue::from_str(channel_id)]) {
            Ok(s) => match s.first::<ChannelCreatorRow>(None).await {
                Ok(Some(row)) => row.pubkey == pubkey,
                _ => false,
            },
            Err(_) => false,
        }
    }

    /// ADR-099: whether device-key honouring is enabled. Reads the
    /// `DEVICE_KEYS_ENABLED` Worker var; only the exact string `"true"` enables
    /// the feature. Absent/empty/any-other value ⇒ disabled (default off).
    pub(crate) fn device_keys_enabled(&self) -> bool {
        match self.env.var("DEVICE_KEYS_ENABLED") {
            Ok(val) => val.to_string() == "true",
            Err(_) => false,
        }
    }

    /// ADR-099 (read-only here; the auth-worker owns writes): resolve the OWNER
    /// account for a registered, non-revoked device key.
    ///
    /// Returns `Some(owner_pubkey)` for a `device_keys` row whose `revoked = 0`,
    /// else `None`. Fail-safe: a missing `device_keys` table (not provisioned
    /// yet) or any D1 error yields `None` — a device key then resolves to no
    /// owner and is treated as an ordinary unknown pubkey.
    pub(crate) async fn device_owner(&self, pubkey: &str) -> Option<String> {
        let db = self.env.d1("DB").ok()?;

        #[derive(serde::Deserialize)]
        struct OwnerRow {
            owner_pubkey: String,
        }

        let stmt = db.prepare(
            "SELECT owner_pubkey FROM device_keys WHERE device_pubkey = ?1 AND revoked = 0 LIMIT 1",
        );
        // A missing table surfaces as a prepare/bind/exec error; `.ok()?` maps it
        // to `None` (fail-safe), so the relay behaves as if no device exists.
        let bound = stmt.bind(&[JsValue::from_str(pubkey)]).ok()?;
        match bound.first::<OwnerRow>(None).await {
            Ok(Some(row)) => Some(row.owner_pubkey),
            _ => None,
        }
    }

    /// ADR-099: resolve the EFFECTIVE principal for `pubkey`, applied to read
    /// scope (cohorts/zone access) and the write-gate allowlist check.
    ///
    /// Gated by `DEVICE_KEYS_ENABLED`. When off, this is a pure identity
    /// passthrough (no D1 read at all) — guaranteeing zero behaviour change. When
    /// on, a registered non-revoked device key resolves to its OWNER; otherwise
    /// the input pubkey is returned unchanged.
    pub(crate) async fn effective_pubkey(&self, pubkey: &str) -> String {
        if !self.device_keys_enabled() {
            return pubkey.to_string();
        }
        let owner = self.device_owner(pubkey).await;
        effective_principal(pubkey, owner.as_deref(), true)
    }

    pub(crate) async fn is_registered_agent(&self, pubkey: &str) -> bool {
        let db = match self.env.d1("DB") {
            Ok(db) => db,
            Err(_) => return false,
        };

        #[derive(serde::Deserialize)]
        struct AgentActiveRow {
            active: u32,
        }

        let stmt = db.prepare("SELECT active FROM agent_registry WHERE pubkey = ?1 LIMIT 1");
        match stmt.bind(&[JsValue::from_str(pubkey)]) {
            Ok(s) => match s.first::<AgentActiveRow>(None).await {
                Ok(Some(row)) => row.active == 1,
                _ => false,
            },
            Err(_) => false,
        }
    }

    pub(crate) async fn project_action_request(&self, event: &NostrEvent) {
        let db = match self.env.d1("DB") {
            Ok(db) => db,
            Err(_) => return,
        };

        let d_tag = governance::extract_d_tag(&event.tags).unwrap_or(&event.id);
        let category =
            governance::extract_tag(&event.tags, "category").unwrap_or("manual_submission");
        let subject_kind = governance::extract_tag(&event.tags, "subject-kind").unwrap_or("opaque");
        let subject_id = governance::extract_tag(&event.tags, "subject-id").unwrap_or("");
        let title = governance::extract_tag(&event.tags, "title").unwrap_or("Untitled");
        let priority: u32 = governance::extract_tag(&event.tags, "priority")
            .and_then(|p| p.parse().ok())
            .unwrap_or(50);

        let stmt = db.prepare(
            "INSERT OR REPLACE INTO broker_cases \
             (id, category, subject_kind, subject_id, title, summary, state, priority, \
              created_by, nostr_event_id, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'open', ?7, ?8, ?9, ?10, ?10)",
        );
        if let Ok(bound) = stmt.bind(&[
            JsValue::from_str(d_tag),
            JsValue::from_str(category),
            JsValue::from_str(subject_kind),
            JsValue::from_str(subject_id),
            JsValue::from_str(title),
            JsValue::from_str(&event.content),
            JsValue::from_f64(priority as f64),
            JsValue::from_str(&event.pubkey),
            JsValue::from_str(&event.id),
            JsValue::from_f64(event.created_at as f64),
        ]) {
            let _ = bound.run().await;
        }
    }

    /// Project a signed 31403 ActionResponse onto `broker_decisions` and the
    /// case's state (COM-16 / F3).
    ///
    /// The parsed outcome — including the non-binary `delegate`/`promote`/
    /// `precedent` forms — is routed through the tested `DecisionOrchestrator`
    /// (via [`plan_action_response`], which calls `DecisionOrchestrator::decide`),
    /// so the resulting `CaseState` matches the outcome instead of the former
    /// projection's fixed `under_review` fallback. A malformed, terminal or
    /// self-review response yields an error and persists nothing — the case is
    /// left unchanged, never parked.
    pub(crate) async fn project_action_response(&self, event: &NostrEvent) {
        let db = match self.env.d1("DB") {
            Ok(db) => db,
            Err(_) => return,
        };

        let case_id = governance::extract_d_tag(&event.tags).unwrap_or("");
        if case_id.is_empty() {
            return;
        }

        // Hydrate the case aggregate from its D1 projection: the orchestrator
        // reads category/state/created_by/share-states, and the latest decision
        // id links the provenance chain.
        let case_row = db
            .prepare(
                "SELECT category, state, created_by, from_share_state, to_share_state \
                 FROM broker_cases WHERE id = ?1 LIMIT 1",
            )
            .bind(&[JsValue::from_str(case_id)])
            .ok();
        let case_row = match case_row {
            Some(stmt) => stmt.first::<BrokerCaseRow>(None).await.ok().flatten(),
            None => None,
        };

        #[derive(serde::Deserialize)]
        struct LatestDecisionRow {
            decision_id: String,
        }
        let latest_stmt = db
            .prepare(
                "SELECT decision_id FROM broker_decisions \
                 WHERE case_id = ?1 ORDER BY decided_at DESC LIMIT 1",
            )
            .bind(&[JsValue::from_str(case_id)])
            .ok();
        let latest_decision_id = match latest_stmt {
            Some(stmt) => stmt
                .first::<LatestDecisionRow>(None)
                .await
                .ok()
                .flatten()
                .map(|r| r.decision_id),
            None => None,
        };

        let proj = match plan_action_response(
            case_id,
            case_row.as_ref(),
            &event.id,
            &event.content,
            &event.pubkey,
            latest_decision_id,
            event.created_at,
        ) {
            Ok(proj) => proj,
            Err(_) => return,
        };

        let detail_val = proj
            .outcome_detail
            .as_deref()
            .map(JsValue::from_str)
            .unwrap_or(JsValue::NULL);
        let prior_val = proj
            .prior_decision_id
            .as_deref()
            .map(JsValue::from_str)
            .unwrap_or(JsValue::NULL);

        let stmt = db.prepare(
            "INSERT OR IGNORE INTO broker_decisions \
             (decision_id, case_id, outcome, outcome_detail, broker_pubkey, reasoning, \
              prior_decision_id, decided_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        );
        if let Ok(bound) = stmt.bind(&[
            JsValue::from_str(&proj.decision_id),
            JsValue::from_str(case_id),
            JsValue::from_str(&proj.outcome),
            detail_val,
            JsValue::from_str(&event.pubkey),
            JsValue::from_str(&proj.reasoning),
            prior_val,
            JsValue::from_f64(event.created_at as f64),
        ]) {
            let _ = bound.run().await;
        }

        // Move the case to the CaseState the orchestrator produced — never
        // `under_review` for a well-formed non-binary outcome.
        let update_stmt = db.prepare(
            "UPDATE broker_cases SET state = ?1, assigned_to = ?2, updated_at = ?3 WHERE id = ?4",
        );
        if let Ok(bound) = update_stmt.bind(&[
            JsValue::from_str(proj.new_state.as_str()),
            JsValue::from_str(&event.pubkey),
            JsValue::from_f64(event.created_at as f64),
            JsValue::from_str(case_id),
        ]) {
            let _ = bound.run().await;
        }
    }

    /// F6 (DDD §7a.1): the governance-role rank of a pubkey for the
    /// supersession-authority gradient.
    ///
    /// Combines the relay's own admin status (a whitelist admin ranks at least
    /// `admin`) with any explicit `broker_roles` grant (e.g. `owner`), taking the
    /// maximum. The absolute number is meaningless; only the ordering matters
    /// (`governance::broker::governance_role_rank`).
    pub(crate) async fn governance_rank(&self, pubkey: &str) -> u8 {
        use governance::broker::governance_role_rank;
        let mut rank = 0u8;
        if self.admin_cache.is_admin(pubkey, &self.env).await {
            rank = rank.max(governance_role_rank("admin"));
        }
        if let Ok(db) = self.env.d1("DB") {
            #[derive(serde::Deserialize)]
            struct RoleRow {
                role: String,
            }
            if let Ok(stmt) = db
                .prepare("SELECT role FROM broker_roles WHERE pubkey = ?1")
                .bind(&[JsValue::from_str(pubkey)])
            {
                if let Ok(result) = stmt.all().await {
                    if let Ok(rows) = result.results::<RoleRow>() {
                        for row in rows {
                            rank = rank.max(governance_role_rank(&row.role));
                        }
                    }
                }
            }
        }
        rank
    }

    /// F6 (DDD §7a.1): whether `superseder` may supersede the decision published
    /// on `superseded_event_id`.
    ///
    /// Deny-by-default: if the superseded decision cannot be located (so its
    /// original signer is unknown), authority cannot be established and the
    /// supersession is rejected. Otherwise the pure
    /// `governance::broker::supersede_authority` decides from the two role ranks.
    pub(crate) async fn supersession_authorised(
        &self,
        superseder: &str,
        superseded_event_id: &str,
    ) -> bool {
        let db = match self.env.d1("DB") {
            Ok(db) => db,
            Err(_) => return false,
        };
        let superseded_decision_id = decision_id_for_event(superseded_event_id);

        #[derive(serde::Deserialize)]
        struct SignerRow {
            broker_pubkey: String,
        }
        let original_signer = match db
            .prepare("SELECT broker_pubkey FROM broker_decisions WHERE decision_id = ?1 LIMIT 1")
            .bind(&[JsValue::from_str(&superseded_decision_id)])
        {
            Ok(stmt) => stmt
                .first::<SignerRow>(None)
                .await
                .ok()
                .flatten()
                .map(|r| r.broker_pubkey),
            Err(_) => None,
        };
        let Some(original_signer) = original_signer else {
            return false;
        };

        let original_rank = self.governance_rank(&original_signer).await;
        let superseder_rank = self.governance_rank(superseder).await;
        governance::broker::supersede_authority(
            &original_signer,
            superseder,
            original_rank,
            superseder_rank,
        )
        .is_authorised()
    }

    /// Project a *superseding* kind-31403 onto `broker_decisions` and the case
    /// (F6, `DDD-judgment-broker-context.md` §7a).
    ///
    /// The authority was already enforced at ingest by the `RelayGovernanceGate`
    /// (`supersession_authorised`); this re-derives it as defence-in-depth and
    /// persists nothing on an unauthorised or malformed supersession — the prior
    /// decision stands, unmutated. On success it: appends the superseding
    /// decision row (its `prior_decision_id` = the superseded decision), marks
    /// the superseded row `superseded_by` this decision (retained, auditable —
    /// the Nostr event itself is never touched), and moves the case to
    /// `Superseded`.
    pub(crate) async fn project_supersession(&self, event: &NostrEvent) {
        let db = match self.env.d1("DB") {
            Ok(db) => db,
            Err(_) => return,
        };

        let case_id = governance::extract_d_tag(&event.tags).unwrap_or("");
        if case_id.is_empty() {
            return;
        }
        let superseded_event_id = match governance::extract_supersedes_target(&event.tags) {
            Some(id) => id,
            None => return,
        };
        let superseded_decision_id = decision_id_for_event(superseded_event_id);

        // Original signer of the superseded decision + the two role ranks.
        #[derive(serde::Deserialize)]
        struct SignerRow {
            broker_pubkey: String,
        }
        let original_signer = match db
            .prepare("SELECT broker_pubkey FROM broker_decisions WHERE decision_id = ?1 LIMIT 1")
            .bind(&[JsValue::from_str(&superseded_decision_id)])
        {
            Ok(stmt) => stmt
                .first::<SignerRow>(None)
                .await
                .ok()
                .flatten()
                .map(|r| r.broker_pubkey),
            Err(_) => None,
        };
        let Some(original_signer) = original_signer else {
            return;
        };

        // Case creator (self-review guard input).
        #[derive(serde::Deserialize)]
        struct CreatorRow {
            created_by: String,
        }
        let case_created_by = match db
            .prepare("SELECT created_by FROM broker_cases WHERE id = ?1 LIMIT 1")
            .bind(&[JsValue::from_str(case_id)])
        {
            Ok(stmt) => stmt
                .first::<CreatorRow>(None)
                .await
                .ok()
                .flatten()
                .map(|r| r.created_by)
                .unwrap_or_default(),
            Err(_) => String::new(),
        };

        let original_rank = self.governance_rank(&original_signer).await;
        let superseder_rank = self.governance_rank(&event.pubkey).await;

        let proj = match plan_supersession(
            &event.id,
            Some(superseded_event_id),
            &event.content,
            &event.pubkey,
            &original_signer,
            original_rank,
            superseder_rank,
            &case_created_by,
            event.created_at,
        ) {
            Ok(proj) => proj,
            // Unauthorised / malformed: persist nothing; the prior decision stands.
            Err(_) => return,
        };

        let detail_val = proj
            .outcome_detail
            .as_deref()
            .map(JsValue::from_str)
            .unwrap_or(JsValue::NULL);

        // Append the superseding decision, referencing the one it supersedes.
        let insert_stmt = db.prepare(
            "INSERT OR IGNORE INTO broker_decisions \
             (decision_id, case_id, outcome, outcome_detail, broker_pubkey, reasoning, \
              prior_decision_id, decided_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        );
        if let Ok(bound) = insert_stmt.bind(&[
            JsValue::from_str(&proj.decision_id),
            JsValue::from_str(case_id),
            JsValue::from_str(&proj.outcome),
            detail_val,
            JsValue::from_str(&event.pubkey),
            JsValue::from_str(&proj.reasoning),
            JsValue::from_str(&proj.superseded_decision_id),
            JsValue::from_f64(event.created_at as f64),
        ]) {
            let _ = bound.run().await;
        }

        // Mark the superseded decision Superseded (retained/auditable). This is a
        // projection-state edit to a derived column — the Nostr event on the
        // relay is never mutated (Invariant 5).
        let mark_stmt = db.prepare(
            "UPDATE broker_decisions SET superseded_by = ?1 WHERE decision_id = ?2",
        );
        if let Ok(bound) = mark_stmt.bind(&[
            JsValue::from_str(&proj.decision_id),
            JsValue::from_str(&proj.superseded_decision_id),
        ]) {
            let _ = bound.run().await;
        }

        // Move the case to Superseded.
        let update_stmt = db.prepare(
            "UPDATE broker_cases SET state = ?1, assigned_to = ?2, updated_at = ?3 WHERE id = ?4",
        );
        if let Ok(bound) = update_stmt.bind(&[
            JsValue::from_str(proj.new_state.as_str()),
            JsValue::from_str(&event.pubkey),
            JsValue::from_f64(event.created_at as f64),
            JsValue::from_str(case_id),
        ]) {
            let _ = bound.run().await;
        }
    }

    /// Project an *appeal* kind-31402 (F6, `DDD-judgment-broker-context.md`
    /// §7a.2/§7a.3): reopen the cited case for a fresh human decision.
    ///
    /// An appeal reopens; it does not overturn. Only a terminal
    /// (`decided`/`delegated`/`promoted`/`precedent`/`superseded`) case is
    /// reopened — the `WHERE state IN (...)` guard makes this the domain
    /// `reopen` transition (an already-open case is untouched). The overturning,
    /// if any, is a subsequent authorised kind-31403 on the now-`reopened` case.
    pub(crate) async fn project_appeal(&self, event: &NostrEvent) {
        let db = match self.env.d1("DB") {
            Ok(db) => db,
            Err(_) => return,
        };
        let case_id = governance::extract_d_tag(&event.tags).unwrap_or("");
        if case_id.is_empty() {
            return;
        }
        let stmt = db.prepare(
            "UPDATE broker_cases SET state = 'reopened', updated_at = ?1 \
             WHERE id = ?2 AND state IN \
             ('decided','delegated','promoted','precedent','superseded')",
        );
        if let Ok(bound) = stmt.bind(&[
            JsValue::from_f64(event.created_at as f64),
            JsValue::from_str(case_id),
        ]) {
            let _ = bound.run().await;
        }
    }

    /// Check whether a kind-5 deletion event targets events by other authors.
    ///
    /// Returns `true` if any `e` tag references an event not authored by the
    /// deletion event's pubkey.
    pub(crate) async fn deletion_targets_others(&self, event: &NostrEvent) -> bool {
        let db = match self.env.d1("DB") {
            Ok(db) => db,
            Err(_) => return false,
        };

        #[derive(serde::Deserialize)]
        struct EventPubkeyRow {
            pubkey: String,
        }

        let target_ids: Vec<&str> = event
            .tags
            .iter()
            .filter(|t| t.len() >= 2 && t[0] == "e")
            .map(|t| t[1].as_str())
            .collect();

        for target_id in &target_ids {
            let stmt = db.prepare("SELECT pubkey FROM events WHERE id = ?1 LIMIT 1");
            match stmt.bind(&[JsValue::from_str(target_id)]) {
                Ok(s) => {
                    if let Ok(Some(row)) = s.first::<EventPubkeyRow>(None).await {
                        if row.pubkey != event.pubkey {
                            return true;
                        }
                    }
                }
                Err(_) => continue,
            }
        }

        false
    }
}

// ---------------------------------------------------------------------------
// F11 (PRD-010): Federated kind allowlist helpers
// ---------------------------------------------------------------------------

impl NostrRelayDO {
    /// Check whether the event's pubkey belongs to a known mesh peer.
    ///
    /// Returns `true` when:
    ///   1. `MESH_MODE` is set to a value other than `"standalone"` (or empty), AND
    ///   2. `MESH_ALLOWED_REMOTE_DIDS` contains the pubkey.
    ///
    /// When `MESH_MODE` is `"standalone"` (the default) or the env var is absent,
    /// this always returns `false` — all events are treated as local.
    pub(crate) fn is_mesh_peer(&self, pubkey: &str) -> bool {
        let mesh_mode = match self.env.var("MESH_MODE") {
            Ok(val) => val.to_string(),
            Err(_) => return false,
        };

        if mesh_mode.is_empty() || mesh_mode == "standalone" {
            return false;
        }

        let allowed_dids = match self.env.var("MESH_ALLOWED_REMOTE_DIDS") {
            Ok(val) => val.to_string(),
            Err(_) => return false,
        };

        if allowed_dids.is_empty() {
            return false;
        }

        allowed_dids.split(',').any(|did| did.trim() == pubkey)
    }

    /// Check whether a given event kind is in the `MESH_FEDERATED_KINDS`
    /// allowlist.
    ///
    /// Reads `MESH_FEDERATED_KINDS` from the Worker env (comma-separated list
    /// of u64 values). When the env var is absent or empty, returns `false`
    /// (fail-closed: no kinds allowed from peers by default).
    pub(crate) fn is_federated_kind_allowed(&self, kind: u64) -> bool {
        let kinds_str = match self.env.var("MESH_FEDERATED_KINDS") {
            Ok(val) => val.to_string(),
            Err(_) => return false,
        };

        if kinds_str.is_empty() {
            return false;
        }

        kinds_str
            .split(',')
            .filter_map(|s| s.trim().parse::<u64>().ok())
            .any(|k| k == kind)
    }
}

// ---------------------------------------------------------------------------
// NIP-56: Report processing
// ---------------------------------------------------------------------------

impl NostrRelayDO {
    /// Process a kind-1984 report event.
    ///
    /// Extracts the `e` tag (reported event), `p` tag (reported pubkey), and
    /// reason from the `report` tag or content. Inserts into the `reports`
    /// table and triggers auto-hide if the threshold is reached.
    pub(crate) async fn process_report(&self, report_event: &NostrEvent) {
        // Extract the reported event ID from the `e` tag
        let reported_event_id = match filter::tag_value(report_event, "e") {
            Some(id) => id,
            None => return, // Invalid report: no `e` tag
        };

        // Extract the reported pubkey from the `p` tag
        let reported_pubkey = match filter::tag_value(report_event, "p") {
            Some(pk) => pk,
            None => return, // Invalid report: no `p` tag
        };

        // Extract reason from `report` tag first, fall back to content
        let reason = filter::tag_value(report_event, "report").unwrap_or_else(|| {
            if report_event.content.is_empty() {
                "other".to_string()
            } else {
                report_event.content.clone()
            }
        });

        // Separate structured reason from free-text
        let (reason_code, reason_text) = match reason.as_str() {
            r @ ("nudity" | "profanity" | "illegal" | "spam" | "impersonation") => {
                // Structured reason; content may hold additional free-text
                let text = if report_event.content.is_empty() {
                    None
                } else {
                    Some(report_event.content.as_str())
                };
                (r.to_string(), text)
            }
            _ => {
                // Free-text reason
                ("other".to_string(), Some(reason.as_str()))
            }
        };

        let _ = moderation::insert_report(
            &self.env,
            &report_event.id,
            &report_event.pubkey,
            &reported_event_id,
            &reported_pubkey,
            &reason_code,
            reason_text,
        )
        .await;
    }

    /// WI-2 + P0-4(a): mirror a kind-30910 (ban), 30911 (mute), 30915 (unban),
    /// or 30916 (unmute) event into the local `moderation_actions` table.
    /// Idempotent via `event_id` dedup -- re-receiving the same event is a
    /// no-op. Missing target pubkey (no `p` tag) silently drops the mirror.
    /// Unban/unmute rows are written as their own action rows (preserving
    /// signer + target + created_at) so `load_state` can apply latest-wins and
    /// cancel a prior ban/mute.
    pub(crate) async fn mirror_moderation_action(&self, event: &NostrEvent) {
        let action = match event.kind {
            KIND_BAN => "ban",
            KIND_MUTE => "mute",
            KIND_UNBAN => "unban",
            KIND_UNMUTE => "unmute",
            _ => return,
        };

        let Some(target) = filter::tag_value(event, "p") else {
            return;
        };

        // expires_at: mutes may carry a NIP-40 style `expiration` tag. Bans,
        // unbans and unmutes never expire; we persist NULL.
        let expires_at: Option<i64> = if action == "mute" {
            filter::tag_value(event, "expiration").and_then(|s| s.parse::<i64>().ok())
        } else {
            None
        };

        let reason: Option<&str> = if event.content.is_empty() {
            None
        } else {
            Some(event.content.as_str())
        };

        let Ok(db) = self.env.d1("DB") else {
            return;
        };

        let row_id = format!("mirror:{}", event.id);
        // P0-4(a): persist the event's signed `created_at` (not receipt time) so
        // `load_state` latest-wins ordering between ban/unban (and mute/unmute)
        // follows the admin's intended sequence even under out-of-order delivery.
        let created_at = event.created_at;

        let sql = "INSERT INTO moderation_actions \
             (id, action, target_pubkey, performed_by, reason, expires_at, event_id, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) \
             ON CONFLICT (id) DO NOTHING";
        let Ok(stmt) = db.prepare(sql).bind(&[
            JsValue::from_str(&row_id),
            JsValue::from_str(action),
            JsValue::from_str(&target),
            JsValue::from_str(&event.pubkey),
            reason.map(JsValue::from_str).unwrap_or(JsValue::NULL),
            expires_at
                .map(|v| JsValue::from_f64(v as f64))
                .unwrap_or(JsValue::NULL),
            JsValue::from_str(&event.id),
            JsValue::from_f64(created_at as f64),
        ]) else {
            return;
        };
        let _ = stmt.run().await;
    }
}

// ---------------------------------------------------------------------------
// Phase C (write side): data-tier write validation tests
// ---------------------------------------------------------------------------
//
// The EVENT (write) gate for calendar kinds mirrors the READ projection. These
// tests drive the same decision the handler executes: the AUTHOR's projection
// tier for an RSVP's TARGET (resolved zone/venue from D1) feeds `project_tier`,
// then `rsvp_write_permitted` accepts only `Full`; a zone-tagged calendar event
// feeds `calendar_write_permitted` with the author's resolved write access. The
// D1 lookups themselves are exercised by integration tests; here we pin the
// pure decision boundary that those lookups feed into.
#[cfg(test)]
mod count_auth_tests {
    //! Read-authorization gate shared by REQ and COUNT. COUNT previously called
    //! `query_events` directly with no gating, leaking existence/counts of sealed
    //! DMs and zone-private content; it now routes through this same gate.
    use super::*;

    fn filter(json: serde_json::Value) -> NostrFilter {
        serde_json::from_value(json).expect("valid filter")
    }

    #[test]
    fn non_dm_filter_passes_through_unauthenticated() {
        let filters = vec![filter(serde_json::json!({ "kinds": [1] }))];
        assert!(NostrRelayDO::gate_kind_1059_filters(filters, &None).is_some());
    }

    #[test]
    fn kind_1059_rejected_when_unauthenticated() {
        let filters = vec![filter(serde_json::json!({ "kinds": [1059] }))];
        // Deny-by-default: an unauthenticated COUNT/REQ for sealed DMs is rejected.
        assert!(NostrRelayDO::gate_kind_1059_filters(filters, &None).is_none());
    }

    #[test]
    fn kind_1059_injects_p_tag_for_authed_pubkey() {
        let pk = "a".repeat(64);
        let filters = vec![filter(serde_json::json!({ "kinds": [1059] }))];
        let out = NostrRelayDO::gate_kind_1059_filters(filters, &Some(pk.clone()))
            .expect("authed kind-1059 read allowed");
        assert_eq!(out[0].extra.get("#p"), Some(&serde_json::json!([pk])));
    }

    #[test]
    fn kind_1059_overrides_client_supplied_p_tag() {
        let pk = "a".repeat(64);
        let attacker_target = "b".repeat(64);
        let filters = vec![filter(
            serde_json::json!({ "kinds": [1059], "#p": [attacker_target] }),
        )];
        let out = NostrRelayDO::gate_kind_1059_filters(filters, &Some(pk.clone()))
            .expect("authed kind-1059 read allowed");
        // The #p constraint must be rebound to the authed pubkey so a client
        // cannot count/read another user's sealed DMs.
        assert_eq!(out[0].extra.get("#p"), Some(&serde_json::json!([pk])));
    }
}

#[cfg(test)]
mod governance_projection_tests {
    //! COM-16 / F3: the 31403 ActionResponse projection routes non-binary
    //! outcomes through the tested `DecisionOrchestrator`. These exercise the
    //! pure `plan_action_response` seam — the worker-side assembly of a
    //! `CaseSnapshot` from a D1 row plus the orchestrator call — without a live
    //! D1. The env-bound read/write in `project_action_response` is a thin shell
    //! over this.
    use super::*;
    use nostr_bbs_core::governance::broker::{CaseState, OrchestrationError};

    fn open_case_row() -> BrokerCaseRow {
        BrokerCaseRow {
            category: "manual_submission".into(),
            state: "open".into(),
            created_by: "agent-alice".into(),
            from_share_state: None,
            to_share_state: None,
        }
    }

    #[test]
    fn delegate_response_reaches_delegated_not_under_review() {
        let row = open_case_row();
        let proj = plan_action_response(
            "case-1",
            Some(&row),
            &"e".repeat(64),
            r#"{"action":"delegate","delegate_to":"human-carol","reasoning":"reassign"}"#,
            "human-bob",
            None,
            2_000,
        )
        .expect("delegate projects");
        assert_eq!(proj.outcome, "delegate");
        assert_eq!(proj.outcome_detail.as_deref(), Some("human-carol"));
        assert_eq!(proj.new_state, CaseState::Delegated);
        // The falsification target for WP-4.
        assert_ne!(proj.new_state, CaseState::UnderReview);
    }

    #[test]
    fn promote_and_precedent_reach_matching_states() {
        let row = open_case_row();
        let promote = plan_action_response(
            "case-1",
            Some(&row),
            &"a".repeat(64),
            r#"{"action":"promote","pattern_id":"pat-9"}"#,
            "human-bob",
            None,
            2_000,
        )
        .expect("promote projects");
        assert_eq!(promote.new_state, CaseState::Promoted);

        let precedent = plan_action_response(
            "case-1",
            Some(&open_case_row()),
            &"b".repeat(64),
            r#"{"action":"precedent","scope":"org-wide"}"#,
            "human-bob",
            None,
            2_000,
        )
        .expect("precedent projects");
        assert_eq!(precedent.new_state, CaseState::Precedent);
    }

    #[test]
    fn binary_outcomes_reach_decided_with_no_detail() {
        let proj = plan_action_response(
            "case-1",
            Some(&open_case_row()),
            &"c".repeat(64),
            r#"{"action":"approve","reasoning":"ok"}"#,
            "human-bob",
            None,
            2_000,
        )
        .expect("approve projects");
        assert_eq!(proj.new_state, CaseState::Decided);
        assert_eq!(proj.outcome_detail, None);
    }

    #[test]
    fn absent_case_row_defaults_to_open_and_still_projects() {
        // A 31403 that arrives before its 31402 projected: no row yet. The
        // planner defaults to an open ManualSubmission case so the decision is
        // still recorded rather than dropped.
        let proj = plan_action_response(
            "case-unknown",
            None,
            &"d".repeat(64),
            r#"{"action":"reject","reasoning":"no"}"#,
            "human-bob",
            None,
            2_000,
        )
        .expect("projects against default snapshot");
        assert_eq!(proj.new_state, CaseState::Decided);
    }

    #[test]
    fn terminal_case_row_rejects_second_response() {
        let mut row = open_case_row();
        row.state = "decided".into();
        let err = plan_action_response(
            "case-1",
            Some(&row),
            &"f".repeat(64),
            r#"{"action":"approve","reasoning":"again"}"#,
            "human-bob",
            None,
            2_000,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            OrchestrationError::Case(
                nostr_bbs_core::governance::broker::CaseError::AlreadyTerminal(_)
            )
        ));
    }

    #[test]
    fn malformed_response_is_rejected() {
        let err = plan_action_response(
            "case-1",
            Some(&open_case_row()),
            &"0".repeat(64),
            r#"{"action":"escalate"}"#,
            "human-bob",
            None,
            2_000,
        )
        .unwrap_err();
        assert!(matches!(err, OrchestrationError::ShareTransitionRejected(_)));
    }

    // ── F6: supersession-authority projection (DDD §7a) ──────────────────
    //
    // These exercise the pure `plan_supersession` seam — the worker-side
    // authority computation + aggregate supersede — that the env-bound
    // `project_supersession` shell wraps. The ingest-time gate
    // (`supersession_authorised`) is the same `supersede_authority` call over the
    // same ranks, so an unauthorised supersession is rejected here exactly as the
    // relay rejects it before save (canon §7a.4: "an unauthorised supersede
    // rejected by RelayGovernanceGate").

    /// admin-rank = 3 (`governance_role_rank("admin")`); owner-rank = 4.
    const ADMIN_RANK: u8 = 3;
    const OWNER_RANK: u8 = 4;

    #[test]
    fn authorised_supersede_by_original_signer_accepted() {
        let superseded_event = "a".repeat(64);
        let superseding_event = "b".repeat(64);
        // bob (the original signer) revokes his own prior Approve with a Reject.
        let proj = plan_supersession(
            &superseding_event,
            Some(&superseded_event),
            r#"{"action":"reject","reasoning":"revoked: grant no longer holds"}"#,
            "human-bob",     // superseder
            "human-bob",     // original signer — same ⇒ OriginalSigner authority
            ADMIN_RANK,      // original rank
            ADMIN_RANK,      // superseder rank
            "agent-alice",   // case creator (self-review guard)
            3_000,
        )
        .expect("original signer may supersede");
        assert_eq!(proj.outcome, "reject");
        // The superseding decision references the one it supersedes (§7a.2).
        assert_eq!(
            proj.superseded_decision_id,
            decision_id_for_event(&superseded_event)
        );
        assert_eq!(proj.decision_id, decision_id_for_event(&superseding_event));
        // The case moves to Superseded (§7a.3).
        assert_eq!(proj.new_state, CaseState::Superseded);
    }

    #[test]
    fn authorised_supersede_by_higher_role_accepted() {
        let superseded_event = "a".repeat(64);
        let superseding_event = "c".repeat(64);
        // carol (owner, rank 4) supersedes bob's (admin, rank 3) decision.
        let proj = plan_supersession(
            &superseding_event,
            Some(&superseded_event),
            r#"{"action":"reject","reasoning":"overridden by governance"}"#,
            "human-carol",
            "human-bob",
            ADMIN_RANK,
            OWNER_RANK,
            "agent-alice",
            3_000,
        )
        .expect("higher role may supersede");
        assert_eq!(proj.new_state, CaseState::Superseded);
    }

    #[test]
    fn unauthorised_supersede_by_equal_role_rejected() {
        let superseded_event = "a".repeat(64);
        let superseding_event = "d".repeat(64);
        // mallory (a different admin, equal rank) may NOT supersede bob's
        // decision — the authority gradient is not collapsed (§7a.1).
        let err = plan_supersession(
            &superseding_event,
            Some(&superseded_event),
            r#"{"action":"reject","reasoning":"I disagree"}"#,
            "human-mallory",
            "human-bob",
            ADMIN_RANK,
            ADMIN_RANK,
            "agent-alice",
            3_000,
        )
        .unwrap_err();
        assert_eq!(
            err,
            SupersessionError::Unauthorised {
                superseder: "human-mallory".into()
            }
        );
    }

    #[test]
    fn unauthorised_supersede_by_lower_role_rejected() {
        let superseded_event = "a".repeat(64);
        let superseding_event = "e".repeat(64);
        // A lower-rank different signer is rejected.
        let err = plan_supersession(
            &superseding_event,
            Some(&superseded_event),
            r#"{"action":"reject","reasoning":"nope"}"#,
            "human-dave",
            "human-carol",
            OWNER_RANK,   // original outranks superseder
            ADMIN_RANK,
            "agent-alice",
            3_000,
        )
        .unwrap_err();
        assert!(matches!(err, SupersessionError::Unauthorised { .. }));
    }

    #[test]
    fn supersede_without_reason_rejected() {
        let superseded_event = "a".repeat(64);
        let superseding_event = "f".repeat(64);
        let err = plan_supersession(
            &superseding_event,
            Some(&superseded_event),
            r#"{"action":"reject"}"#, // no reasoning field
            "human-bob",
            "human-bob",
            ADMIN_RANK,
            ADMIN_RANK,
            "agent-alice",
            3_000,
        )
        .unwrap_err();
        assert_eq!(err, SupersessionError::MissingReason);
    }

    #[test]
    fn supersede_without_referenced_event_rejected() {
        let err = plan_supersession(
            &"b".repeat(64),
            None, // no supersedes e-tag target
            r#"{"action":"reject","reasoning":"x"}"#,
            "human-bob",
            "human-bob",
            ADMIN_RANK,
            ADMIN_RANK,
            "agent-alice",
            3_000,
        )
        .unwrap_err();
        assert_eq!(err, SupersessionError::MissingSupersededDecision);
    }

    #[test]
    fn supersession_chain_renders_effective_and_superseded_decisions() {
        // Two supersessions chained: dec(A) --superseded_by--> dec(B)
        // --superseded_by--> dec(C). The projection expresses the chain via the
        // superseding row's prior_decision_id link + the superseded row's
        // superseded_by mark; the client renders the newest as effective and the
        // earlier ones as history. Here we assert the projection produces the
        // chain data a renderer consumes.
        let ev_a = "a".repeat(64);
        let ev_b = "b".repeat(64);
        let ev_c = "c".repeat(64);
        let dec_a = decision_id_for_event(&ev_a);
        let dec_b = decision_id_for_event(&ev_b);
        let dec_c = decision_id_for_event(&ev_c);

        // B supersedes A (original signer bob).
        let first = plan_supersession(
            &ev_b,
            Some(&ev_a),
            r#"{"action":"reject","reasoning":"revoke"}"#,
            "human-bob",
            "human-bob",
            ADMIN_RANK,
            ADMIN_RANK,
            "agent-alice",
            3_000,
        )
        .expect("B supersedes A");
        assert_eq!(first.decision_id, dec_b);
        assert_eq!(first.superseded_decision_id, dec_a);
        assert_eq!(first.new_state, CaseState::Superseded);

        // C supersedes B (higher-role owner carol) — forward-chaining (§7a.3).
        let second = plan_supersession(
            &ev_c,
            Some(&ev_b),
            r#"{"action":"approve","reasoning":"re-granted on review"}"#,
            "human-carol",
            "human-bob",
            ADMIN_RANK,
            OWNER_RANK,
            "agent-alice",
            3_100,
        )
        .expect("C supersedes B");
        assert_eq!(second.decision_id, dec_c);
        assert_eq!(second.superseded_decision_id, dec_b);
        // The effective decision is the newest (C); A and B are retained history.
        assert_eq!(second.new_state, CaseState::Superseded);
        assert_eq!(second.outcome, "approve");
    }
}

#[cfg(test)]
mod write_gate_tests {
    use super::super::calendar_projection::{
        project_tier, Projection, COHORT_BUSINESS, COHORT_FAMILY, COHORT_FRIENDS, ZONE_BUSINESS,
        ZONE_FAMILY,
    };
    use super::*;

    fn cohorts(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    /// Helper: compute the author's RSVP write decision exactly as `handle_event`
    /// does — resolved target (zone, venue) + author cohorts → tier → permitted.
    fn rsvp_decision(
        author_cohorts: &[String],
        author_cohort_admin: bool,
        target_zone: &str,
        target_venue: Option<&str>,
    ) -> bool {
        let tier = project_tier(
            author_cohorts,
            target_zone,
            target_venue,
            false,
            author_cohort_admin,
        );
        rsvp_write_permitted(&tier)
    }

    // ---- RSVP write gate (kind 31925) --------------------------------------

    #[test]
    fn friends_author_rsvp_to_business_venue_target_rejected() {
        // EVIDENCE replay: a friends-cohort author RSVPs to a business-zone event
        // she only sees as free/busy (business@primary venue). Author tier =
        // FreeBusy ⇒ write rejected.
        assert!(
            !rsvp_decision(
                &cohorts(&[COHORT_FRIENDS]),
                false,
                ZONE_BUSINESS,
                Some("primary"),
            ),
            "friends author must not RSVP to a business target she only sees as free/busy"
        );
        // Off-site business target (no shared venue): friends tier = Omit ⇒ reject.
        assert!(!rsvp_decision(
            &cohorts(&[COHORT_FRIENDS]),
            false,
            ZONE_BUSINESS,
            None
        ));
    }

    #[test]
    fn family_author_rsvp_to_business_target_accepted() {
        // family tier is Full on every zone, including business ⇒ RSVP permitted.
        assert!(rsvp_decision(
            &cohorts(&[COHORT_FAMILY]),
            false,
            ZONE_BUSINESS,
            Some("primary"),
        ));
        assert!(rsvp_decision(
            &cohorts(&[COHORT_FAMILY]),
            false,
            ZONE_BUSINESS,
            None
        ));
    }

    #[test]
    fn owner_admin_author_rsvp_accepted() {
        // Admin author (cohort_admin flag) → project_tier short-circuits to Full,
        // regardless of target zone ⇒ permitted. (A non-cohort author flagged
        // admin in the handler bypasses this gate entirely; this asserts the tier
        // short-circuit for the cohort-admin path.)
        assert!(rsvp_decision(&[], true, ZONE_FAMILY, None));
        assert!(rsvp_decision(&[], true, ZONE_BUSINESS, Some("primary")));
    }

    #[test]
    fn business_author_rsvp_to_own_business_zone_accepted() {
        // A business author RSVPing to a business-zone target sees it Full ⇒ ok.
        assert!(rsvp_decision(
            &cohorts(&[COHORT_BUSINESS]),
            false,
            ZONE_BUSINESS,
            None
        ));
        // ...but a business author RSVPing to a FAMILY target sees Omit ⇒ reject.
        assert!(!rsvp_decision(
            &cohorts(&[COHORT_BUSINESS]),
            false,
            ZONE_FAMILY,
            None
        ));
    }

    #[test]
    fn rsvp_write_permitted_only_on_full_tier() {
        assert!(rsvp_write_permitted(&Projection::Full));
        assert!(!rsvp_write_permitted(&Projection::FreeBusy));
        assert!(!rsvp_write_permitted(&Projection::Omit));
    }

    // ---- Calendar event write gate (kind 31922/31923) ----------------------

    #[test]
    fn calendar_write_into_non_member_zone_rejected() {
        // Zone-tagged event, author lacks write access ⇒ rejected.
        assert!(!calendar_write_permitted(Some(ZONE_BUSINESS), false));
    }

    #[test]
    fn calendar_write_into_member_zone_accepted() {
        // Zone-tagged event, author holds write access ⇒ accepted.
        assert!(calendar_write_permitted(Some(ZONE_BUSINESS), true));
    }

    #[test]
    fn untagged_calendar_event_keeps_prior_behaviour() {
        // No zone tag → unscoped → permitted regardless of zone-write resolution.
        assert!(calendar_write_permitted(None, false));
        assert!(calendar_write_permitted(None, true));
    }

    // ---- NIP-59 gift-wrap (kind 1059) recipient routing --------------------
    //
    // The handler's recipient gate is `is_whitelisted(recipient)`, which needs a
    // `worker::Env` / D1 and so cannot run in isolation. These tests pin the PURE
    // decision the handler feeds into that lookup: `gift_wrap_recipient` resolves
    // the principal the membership check is applied to. `Some(pk)` ⇒ the gate runs
    // against `pk` (admitted iff whitelisted); `None` ⇒ fail-closed reject; for a
    // normal kind ⇒ `None`, so the author `is_whitelisted` branch runs as before.

    fn mk_event(kind: u64, tags: Vec<Vec<String>>) -> NostrEvent {
        NostrEvent {
            id: "00".repeat(32),
            pubkey: "ab".repeat(32),
            created_at: 0,
            kind,
            tags,
            content: String::new(),
            sig: "cd".repeat(64),
        }
    }

    fn p(hex: &str) -> Vec<String> {
        vec!["p".to_string(), hex.to_string()]
    }

    #[test]
    fn gift_wrap_with_p_tag_routes_membership_to_recipient() {
        // kind-1059 carrying a #p recipient ⇒ gate that recipient (not the
        // ephemeral author). The handler then admits iff that recipient is
        // whitelisted; here we pin the recipient resolution + the boolean gate.
        let recipient = "11".repeat(32);
        let ev = mk_event(GIFT_WRAP_KIND, vec![p(&recipient)]);
        assert_eq!(
            gift_wrap_recipient(&ev).as_deref(),
            Some(recipient.as_str())
        );
        // Whitelisted recipient ⇒ admitted; non-whitelisted ⇒ rejected.
        let admitted = |whitelisted: bool| gift_wrap_recipient(&ev).is_some() && whitelisted;
        assert!(admitted(true));
        assert!(!admitted(false));
    }

    #[test]
    fn gift_wrap_without_or_empty_p_tag_rejected() {
        // No #p tag ⇒ no resolvable recipient ⇒ fail-closed reject.
        let ev_missing = mk_event(GIFT_WRAP_KIND, vec![vec!["e".to_string(), "ff".repeat(32)]]);
        assert_eq!(gift_wrap_recipient(&ev_missing), None);
        // Empty #p value ⇒ treated as absent ⇒ reject.
        let ev_empty = mk_event(GIFT_WRAP_KIND, vec![p("")]);
        assert_eq!(gift_wrap_recipient(&ev_empty), None);
    }

    #[test]
    fn normal_kind_does_not_route_to_recipient_gate() {
        // A normal kind (e.g. kind-1) with a #p tag is NOT recipient-gated; the
        // author `is_whitelisted` branch still applies (gift_wrap_recipient → None).
        let ev = mk_event(1, vec![p(&"22".repeat(32))]);
        assert_eq!(gift_wrap_recipient(&ev), None);
    }
}

// ---------------------------------------------------------------------------
// ADR-099: revocable device-key access resolution tests
// ---------------------------------------------------------------------------
//
// The async `device_owner` / `effective_pubkey` / `is_whitelisted` methods need
// a `worker::Env` / D1 and cannot run in isolation. These tests pin the PURE
// decision the handler feeds those lookups into:
//   - `effective_principal` resolves the principal access derives from (the
//     device→owner mapping, gated). This is the exact function the async
//     `effective_pubkey` calls after resolving `device_owner(pubkey)` from D1.
//   - `access_admitted` replays the write-gate boolean the handler computes:
//     `is_whitelisted(effective_principal(author, owner, enabled))`.
// The D1 `device_owner` query (missing-table → None) and the env gate read are
// exercised by integration tests against a real D1; here we pin the resolution
// and the access boundary those feed.
#[cfg(test)]
mod device_key_tests {
    use super::*;

    const DEVICE: &str = "de";
    const OWNER: &str = "01";
    const OTHER: &str = "99";

    fn dev() -> String {
        DEVICE.repeat(32)
    }
    fn owner() -> String {
        OWNER.repeat(32)
    }

    // ---- pure resolution: effective_principal -----------------------------

    #[test]
    fn device_resolves_to_owner_when_enabled() {
        // Registered, non-revoked device row (device_owner → Some(owner)) and the
        // feature on ⇒ the session acts as the OWNER for access.
        assert_eq!(
            effective_principal(&dev(), Some(&owner()), true),
            owner(),
            "an enabled, registered device key must resolve to its owner"
        );
    }

    #[test]
    fn revoked_or_unknown_device_resolves_to_self() {
        // `device_owner` returns `None` for a revoked row (the query filters
        // `revoked = 0`) AND for an unknown pubkey AND for a missing table
        // (fail-safe). All three reach here as `None` ⇒ identity passthrough.
        assert_eq!(effective_principal(&dev(), None, true), dev());
    }

    #[test]
    fn gate_off_is_identity_passthrough() {
        // DEVICE_KEYS_ENABLED off ⇒ even a known device→owner mapping is ignored;
        // the device key is just an unknown pubkey, current behaviour unchanged.
        assert_eq!(effective_principal(&dev(), Some(&owner()), false), dev());
        // And a non-device pubkey is of course unchanged too.
        assert_eq!(effective_principal(&dev(), None, false), dev());
    }

    // ---- access decision: write-gate allowlist replay ---------------------
    //
    // The handler admits a (non-gift-wrap) event iff
    // `is_whitelisted(effective_pubkey(author))`. We model `is_whitelisted` as a
    // membership set and replay the exact composition.

    /// Replay of the handler's write-gate: admit iff the EFFECTIVE principal is
    /// whitelisted. `whitelisted` models the `is_whitelisted` D1 set.
    fn access_admitted(
        author: &str,
        device_owner: Option<&str>,
        enabled: bool,
        whitelisted: &[String],
    ) -> bool {
        let principal = effective_principal(author, device_owner, enabled);
        whitelisted.contains(&principal)
    }

    #[test]
    fn device_event_admitted_iff_owner_whitelisted() {
        // Owner IS whitelisted, device is NOT ⇒ enabled device event admitted
        // under the owner's allowlist.
        let wl = vec![owner()];
        assert!(
            access_admitted(&dev(), Some(&owner()), true, &wl),
            "device-authored event must be admitted when its owner is whitelisted"
        );
    }

    #[test]
    fn device_event_rejected_when_owner_not_whitelisted() {
        // Owner NOT whitelisted ⇒ rejected even though it is a valid device row.
        let wl = vec![OTHER.repeat(32)];
        assert!(!access_admitted(&dev(), Some(&owner()), true, &wl));
    }

    #[test]
    fn device_event_rejected_when_gate_off_even_if_owner_whitelisted() {
        // Gate off ⇒ the device pubkey itself is checked. Owner whitelisted but
        // device not ⇒ rejected. This is the "fully inert" guarantee: a device
        // key is just an unknown pubkey.
        let wl = vec![owner()];
        assert!(!access_admitted(&dev(), Some(&owner()), false, &wl));
    }

    #[test]
    fn revoked_device_rejected_even_when_enabled() {
        // Revoked ⇒ `device_owner` is None ⇒ the device pubkey is checked, not
        // the owner ⇒ rejected (owner whitelisted but device not).
        let wl = vec![owner()];
        assert!(!access_admitted(&dev(), None, true, &wl));
    }

    #[test]
    fn non_device_author_unchanged() {
        // An ordinary author (no device row) is checked against itself in both
        // gate states — no behaviour change for the common path.
        let author = "ab".repeat(32);
        let wl = vec![author.clone()];
        assert!(access_admitted(&author, None, true, &wl));
        assert!(access_admitted(&author, None, false, &wl));
        // ...and a non-whitelisted ordinary author is rejected, gate on or off.
        let wl_empty: Vec<String> = vec![];
        assert!(!access_admitted(&author, None, true, &wl_empty));
        assert!(!access_admitted(&author, None, false, &wl_empty));
    }
}
