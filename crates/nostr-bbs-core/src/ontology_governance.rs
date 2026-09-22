//! The `ontology-governance` panel — a profile over the Agent Control Surface
//! Protocol for signed corpus promotion (ADR-2013, VisionFlow
//! `PRD-sovereign-corpus.md` §3.3).
//!
//! Nothing here is a new protocol. It is a *named profile* over the generic
//! governance types in [`crate::governance`]: one 31400 panel definition with
//! operator-declared task properties, three extra tags on the 31402
//! ActionRequest it raises, and one arithmetic rule that turns a schema-level
//! proposal into a `High`-tier case. Keeping the profile in its own module is
//! what lets the protocol stay generic while the corpus's rules stay explicit
//! and testable in one place.
//!
//! ## The three tags
//!
//! | Tag | Value | Read by |
//! |---|---|---|
//! | `context_url` | the subject's OKF `resource` IRI | the reviewer's surface, the apply path |
//! | `d` (second `d`-like tag: `digest`) | `sha256:…` of the proposed frontmatter | the ledger correlation |
//! | `level` | `content` \| `schema` \| `demotion` | [`ProposalLevel`], which sets the tier floor |
//!
//! ## Why the tier floor is a *property*, not a tier
//!
//! ADR-2011 makes the operator's task-property triple the boundary and the
//! `RiskTier` a derived reading of it. A profile that stamped `risk-tier: high`
//! on its own requests would be an agent declaring its own boundary — exactly
//! what the tightening-only merge exists to prevent. So a schema-level or
//! demotion-level proposal contributes `stakes: critical` to the merge instead,
//! and [`crate::governance::TaskProperties::tier_floor`] does the rest. The
//! reviewer then sees *why* the case is `High` (its stakes) rather than only
//! that it is, and an auditor reading `broker_cases.tp_stakes` sees the same
//! reason.

use crate::governance::{
    ActionDef, ActionStyle, FieldDef, FieldType, LayoutHint, PanelDefinition, PanelSchema, Stakes,
    TaskProperties, Verifiability,
};
use serde::{Deserialize, Serialize};

/// The `d`-tag identifying the one panel this profile defines.
pub const PANEL_ONTOLOGY_GOVERNANCE: &str = "ontology-governance";

/// Tag carrying the subject's OKF `resource` IRI on a 31402.
pub const TAG_CONTEXT_URL: &str = "context_url";

/// Tag carrying the proposed frontmatter's content digest on a 31402.
pub const TAG_DIGEST: &str = "digest";

/// Tag carrying the [`ProposalLevel`] on a 31402.
pub const TAG_LEVEL: &str = "level";

/// Field name in a `PatchProposal` carrying the proposal's expiry instant.
pub const FIELD_STALE_AFTER: &str = "stale_after";

/// How far into the corpus a proposal reaches, and therefore what it costs to
/// get wrong (contract C5, PRD §2 Q6/Q7).
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProposalLevel {
    /// A change to one page's own assertions. The default, and the loosest.
    #[default]
    Content,
    /// A change to the vocabulary or to a page's place in the class hierarchy —
    /// it changes what every other page *means*.
    Schema,
    /// Lowering a stable subject to `deprecated`. Reaches as far as a schema
    /// change because every consumer that resolved the subject stops resolving
    /// it.
    Demotion,
}

impl ProposalLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Content => "content",
            Self::Schema => "schema",
            Self::Demotion => "demotion",
        }
    }

    /// Parse a `level` tag value.
    ///
    /// An unrecognised value falls back to `Content` — the **loosest** level —
    /// for the same reason [`crate::governance::Verifiability::parse`] does: the
    /// profile's floor is merged in tightening-only, so a loose fallback can
    /// only ever defer to the operator's panel declaration, never lower it. A
    /// misspelled `level` therefore loses this profile's extra floor and keeps
    /// the panel's, rather than silently escaping oversight.
    pub fn parse(s: &str) -> Self {
        match s {
            "schema" => Self::Schema,
            "demotion" => Self::Demotion,
            _ => Self::Content,
        }
    }

    /// Read the level from a 31402's tags. `None` when the request carries no
    /// `level` tag at all, which is a request that is not using this profile.
    pub fn from_tags(tags: &[Vec<String>]) -> Option<Self> {
        crate::governance::extract_tag(tags, TAG_LEVEL).map(Self::parse)
    }

    /// Whether this level requires a human-signed decision at `High` or above.
    pub fn is_schema_tier(self) -> bool {
        matches!(self, Self::Schema | Self::Demotion)
    }

    /// The task-property floor this level contributes to the ADR-2011 merge.
    ///
    /// `Schema` and `Demotion` contribute `stakes: critical`, whose
    /// [`TaskProperties::tier_floor`] is `High` — the PRD §2 Q7 rule ("Schema
    /// floored at tier High") expressed in the units ADR-2011 actually reasons
    /// in. `Content` contributes nothing: it is governed by the panel's own
    /// declaration like any other request.
    ///
    /// The other two legs stay at their loosest so the merge defers to the
    /// panel on them. A content proposal *is* inspectable (the diff is right
    /// there) and reversible (git), so claiming otherwise here would raise
    /// every case in the estate for no reason.
    pub fn property_floor(self) -> Option<TaskProperties> {
        self.is_schema_tier().then(|| TaskProperties {
            stakes: Stakes::Critical,
            ..TaskProperties::default()
        })
    }
}

/// The property floor a 31402's `level` tag contributes, ready to be merged
/// into the ADR-2011 boundary.
///
/// This is the single entry point the relay calls: it takes the raw request
/// tags and returns something [`TaskProperties::merge_opt`] can absorb, so the
/// relay's boundary code gains one merge and no branching.
pub fn level_property_floor(request_tags: &[Vec<String>]) -> Option<TaskProperties> {
    ProposalLevel::from_tags(request_tags).and_then(ProposalLevel::property_floor)
}

/// The canonical `ontology-governance` 31400 PanelDefinition.
///
/// The operator publishes this once. Its task properties are the *panel's*
/// declaration — the floor under every proposal the corpus raises, before any
/// individual request's `level` tightens it further:
///
/// - `verifiability: partial` — a reviewer can read the diff and the digest,
///   but cannot check the Whelk closure the proposer ran by eye.
/// - `reversibility: reversible` — git is the rollback, and a `Demote` undoes a
///   `Promote`. This is the one leg the corpus can honestly claim is loose, and
///   claiming it honestly is what keeps `High` meaningful for the cases that
///   earn it.
/// - `stakes: significant` — a wrong `status: stable` is published to
///   narrativegoldmine.com and consumed by every downstream reader.
///
/// `max_pending_hours` is 336 (14 days), matching the `stale_after` a
/// `PatchProposal` carries (PRD §2 Q7), so the escalate-on-age receipt lands at
/// the same moment the expiry sweep closes the case rather than a day either
/// side of it.
pub fn ontology_governance_panel() -> PanelDefinition {
    PanelDefinition {
        title: "Ontology governance".to_string(),
        description: "Human-signed promotion, demotion and expiry of corpus pages. \
                      Each case carries the proposed frontmatter diff, its content \
                      digest and the hypothesis the proposer is testing."
            .to_string(),
        version: "1.0.0".to_string(),
        schema: PanelSchema::ActionInbox,
        fields: vec![
            FieldDef {
                name: "iri".to_string(),
                field_type: FieldType::String,
                label: "Subject IRI".to_string(),
            },
            FieldDef {
                name: "page".to_string(),
                field_type: FieldType::String,
                label: "Vault page".to_string(),
            },
            FieldDef {
                name: "level".to_string(),
                field_type: FieldType::Enum,
                label: "Level".to_string(),
            },
            FieldDef {
                name: "hypothesis".to_string(),
                field_type: FieldType::String,
                label: "Hypothesis".to_string(),
            },
            FieldDef {
                name: "diff".to_string(),
                field_type: FieldType::String,
                label: "Frontmatter diff".to_string(),
            },
            FieldDef {
                name: "digest".to_string(),
                field_type: FieldType::String,
                label: "Content digest".to_string(),
            },
            FieldDef {
                name: "generation".to_string(),
                field_type: FieldType::String,
                label: "Generation".to_string(),
            },
            FieldDef {
                name: FIELD_STALE_AFTER.to_string(),
                field_type: FieldType::Timestamp,
                label: "Expires".to_string(),
            },
        ],
        actions: vec![
            ActionDef {
                id: "promote".to_string(),
                label: "Promote to stable".to_string(),
                style: ActionStyle::Primary,
            },
            ActionDef {
                id: "demote".to_string(),
                label: "Demote to deprecated".to_string(),
                style: ActionStyle::Destructive,
            },
            ActionDef {
                id: "reject".to_string(),
                label: "Reject".to_string(),
                style: ActionStyle::Secondary,
            },
        ],
        layout: LayoutHint::SplitDetail,
        capabilities: vec![],
        refresh_secs: 300,
        task_properties: Some(TaskProperties {
            verifiability: Verifiability::Partial,
            reversibility: crate::governance::Reversibility::Reversible,
            stakes: Stakes::Significant,
        }),
        calibration_sample_rate: None,
        max_pending_hours: Some(STALE_AFTER_DEFAULT_HOURS),
        probe_agent: None,
    }
}

/// The 14 days a `PatchProposal` is live for (PRD §2 Q7), in hours.
pub const STALE_AFTER_DEFAULT_HOURS: u32 = 14 * 24;

// ── Proposal expiry ─────────────────────────────────────────────────────────

/// Read the `stale_after` instant out of a `PatchProposal` JSON body (contract
/// C4), as a Unix timestamp in seconds.
///
/// Returns `None` when the content is not JSON, carries no `stale_after`, or
/// carries one this parser will not vouch for. A proposal whose expiry cannot
/// be read is one the sweep leaves alone: silently treating an unparseable
/// instant as "expired now" would close cases nobody decided, and treating it
/// as "never" at least leaves the escalate-on-age receipt to surface it.
pub fn stale_after_from_content(content: &str) -> Option<i64> {
    let value: serde_json::Value = serde_json::from_str(content).ok()?;
    let raw = value.get(FIELD_STALE_AFTER)?;
    if let Some(n) = raw.as_i64() {
        return Some(n);
    }
    parse_rfc3339_utc(raw.as_str()?)
}

/// Whether a proposal has passed its expiry instant.
///
/// Pure over its inputs so the arithmetic is testable without a clock. A
/// proposal exactly *at* its expiry has not yet passed it, matching
/// [`crate::governance`]'s ageing predicate.
pub fn is_expired(stale_after: i64, now: i64) -> bool {
    now > stale_after
}

/// Parse the RFC 3339 / ISO 8601 profile a `PatchProposal` emits into Unix
/// seconds.
///
/// Deliberately narrow: `YYYY-MM-DDTHH:MM:SS` with an optional fractional part
/// and a `Z` or `±HH:MM` offset, which is what `vault propose` writes and what
/// JavaScript's `Date#toISOString` produces. Anything else returns `None`
/// rather than a guess, because a guessed expiry closes a case a human was
/// still looking at.
///
/// This exists instead of a date crate because `nostr-bbs-core` compiles to
/// `wasm32-unknown-unknown` for the relay worker and carries no calendar
/// dependency; the conversion is proleptic-Gregorian day arithmetic with no
/// leap seconds, which is exactly Unix time's definition.
pub fn parse_rfc3339_utc(s: &str) -> Option<i64> {
    let bytes = s.as_bytes();
    if bytes.len() < 19 {
        return None;
    }
    let num = |a: usize, b: usize| -> Option<i64> { s.get(a..b)?.parse::<i64>().ok() };
    // Reject sign-prefixed or space-padded numerics that `parse` would accept.
    if !s[..19]
        .bytes()
        .enumerate()
        .all(|(i, c)| matches!(i, 4 | 7 | 10 | 13 | 16) || c.is_ascii_digit())
    {
        return None;
    }
    if bytes[4] != b'-' || bytes[7] != b'-' || bytes[13] != b':' || bytes[16] != b':' {
        return None;
    }
    if bytes[10] != b'T' && bytes[10] != b't' && bytes[10] != b' ' {
        return None;
    }
    let (year, month, day) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
    let (hour, minute, second) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    if day > days_in_month(year, month) || hour > 23 || minute > 59 || second > 60 {
        return None;
    }

    // Offset suffix: `Z`, `z`, `+HH:MM`, `-HH:MM`, or absent (treated as UTC,
    // which is what an absent offset means for every producer we accept from).
    let mut rest = &s[19..];
    if let Some(stripped) = rest.strip_prefix('.') {
        let digits = stripped.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 {
            return None;
        }
        rest = &stripped[digits..];
    }
    let offset_secs = match rest.as_bytes() {
        [] | [b'Z'] | [b'z'] => 0,
        [sign @ (b'+' | b'-'), ..] if rest.len() == 6 => {
            let oh: i64 = rest.get(1..3)?.parse().ok()?;
            let om: i64 = rest.get(4..6)?.parse().ok()?;
            if rest.as_bytes()[3] != b':' || oh > 23 || om > 59 {
                return None;
            }
            let magnitude = oh * 3_600 + om * 60;
            if *sign == b'-' {
                -magnitude
            } else {
                magnitude
            }
        }
        _ => return None,
    };

    let days = days_from_civil(year, month, day);
    Some(days * 86_400 + hour * 3_600 + minute * 60 + second - offset_secs)
}

fn is_leap(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(year) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Days since 1970-01-01 for a proleptic-Gregorian date (Howard Hinnant's
/// `days_from_civil`, the same algorithm `chrono` and `time` use).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governance::{effective_tier, RiskTier};

    // ── The tier floor (PRD §2 Q7, ADR-2011) ────────────────────────────

    #[test]
    fn schema_and_demotion_floor_the_case_at_high() {
        for level in [ProposalLevel::Schema, ProposalLevel::Demotion] {
            let floor = level.property_floor().expect("schema tier has a floor");
            assert_eq!(floor.stakes, Stakes::Critical);
            assert_eq!(floor.tier_floor(), RiskTier::High, "{}", level.as_str());
        }
    }

    #[test]
    fn content_contributes_no_floor_of_its_own() {
        assert!(ProposalLevel::Content.property_floor().is_none());
    }

    #[test]
    fn a_schema_request_reaches_high_even_when_the_agent_declares_low() {
        let tags = vec![vec![TAG_LEVEL.to_string(), "schema".to_string()]];
        let floor = level_property_floor(&tags);
        // The agent declares `Low`; the panel declares the ontology panel's
        // own (loose-on-reversibility) triple. Neither can lower the floor.
        let panel = ontology_governance_panel().task_properties.unwrap();
        let tier = effective_tier(
            Some(&panel),
            floor.as_ref(),
            Some(RiskTier::Low),
            RiskTier::Medium,
        );
        assert_eq!(tier, RiskTier::High);
    }

    #[test]
    fn a_content_request_is_not_dragged_up_to_high() {
        let tags = vec![vec![TAG_LEVEL.to_string(), "content".to_string()]];
        let panel = ontology_governance_panel().task_properties.unwrap();
        let tier = effective_tier(
            Some(&panel),
            level_property_floor(&tags).as_ref(),
            None,
            RiskTier::Medium,
        );
        assert_eq!(tier, RiskTier::Medium);
    }

    #[test]
    fn an_unrecognised_level_falls_back_to_content_not_to_schema() {
        let tags = vec![vec![TAG_LEVEL.to_string(), "SCHEMA".to_string()]];
        assert_eq!(
            ProposalLevel::from_tags(&tags),
            Some(ProposalLevel::Content)
        );
        assert!(level_property_floor(&tags).is_none());
    }

    #[test]
    fn a_request_without_a_level_tag_is_not_using_this_profile() {
        assert_eq!(ProposalLevel::from_tags(&[]), None);
        assert!(level_property_floor(&[]).is_none());
    }

    // ── The panel ───────────────────────────────────────────────────────

    #[test]
    fn the_panel_declares_promote_demote_and_reject() {
        let panel = ontology_governance_panel();
        let ids: Vec<&str> = panel.actions.iter().map(|a| a.id.as_str()).collect();
        assert_eq!(ids, ["promote", "demote", "reject"]);
        // Approve is deliberately absent: an ontology decision names the IRI it
        // acted on, and a bare `approve` carries no subject for the apply path.
        assert!(!ids.contains(&"approve"));
    }

    #[test]
    fn the_panel_deadline_matches_the_proposal_expiry() {
        let panel = ontology_governance_panel();
        assert_eq!(panel.policy().max_pending_hours, STALE_AFTER_DEFAULT_HOURS);
        assert_eq!(STALE_AFTER_DEFAULT_HOURS, 336);
    }

    #[test]
    fn the_panel_alone_does_not_floor_a_content_case_at_high() {
        // The falsification target for the floor tests above: if the panel
        // itself declared `Critical`, every case would be `High` and the
        // `level` rule would be untestable theatre.
        let panel = ontology_governance_panel().task_properties.unwrap();
        assert_ne!(panel.tier_floor(), RiskTier::High);
    }

    // ── Expiry ──────────────────────────────────────────────────────────

    #[test]
    fn stale_after_reads_the_patch_proposal_field() {
        let content = r#"{"level":"content","iri":"urn:ngm:class:x",
                          "stale_after":"2026-10-06T00:00:00Z"}"#;
        assert_eq!(stale_after_from_content(content), Some(1_791_244_800));
    }

    #[test]
    fn stale_after_accepts_a_numeric_unix_instant() {
        assert_eq!(
            stale_after_from_content(r#"{"stale_after":1791244800}"#),
            Some(1_791_244_800)
        );
    }

    #[test]
    fn stale_after_is_none_when_unreadable() {
        assert_eq!(stale_after_from_content("not json"), None);
        assert_eq!(stale_after_from_content("{}"), None);
        assert_eq!(stale_after_from_content(r#"{"stale_after":"soon"}"#), None);
        assert_eq!(
            stale_after_from_content(r#"{"stale_after":"2026-13-01T00:00:00Z"}"#),
            None
        );
        assert_eq!(
            stale_after_from_content(r#"{"stale_after":"2026-02-30T00:00:00Z"}"#),
            None
        );
    }

    #[test]
    fn expiry_is_strictly_past_the_instant() {
        assert!(!is_expired(1_000, 999));
        assert!(!is_expired(1_000, 1_000));
        assert!(is_expired(1_000, 1_001));
    }

    #[test]
    fn rfc3339_handles_offsets_fractions_and_leap_years() {
        assert_eq!(parse_rfc3339_utc("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            parse_rfc3339_utc("2026-09-22T12:00:00Z"),
            Some(1_790_078_400)
        );
        assert_eq!(
            parse_rfc3339_utc("2026-09-22T12:00:00.123Z"),
            Some(1_790_078_400)
        );
        // +01:00 is one hour EAST, so the same wall clock is an hour EARLIER.
        assert_eq!(
            parse_rfc3339_utc("2026-09-22T13:00:00+01:00"),
            Some(1_790_078_400)
        );
        assert_eq!(
            parse_rfc3339_utc("2026-09-22T11:00:00-01:00"),
            Some(1_790_078_400)
        );
        // 2024 is a leap year; 2100 is not.
        assert_eq!(
            parse_rfc3339_utc("2024-02-29T00:00:00Z"),
            Some(1_709_164_800)
        );
        assert_eq!(parse_rfc3339_utc("2100-02-29T00:00:00Z"), None);
        // Malformed shapes are refused rather than guessed.
        assert_eq!(parse_rfc3339_utc("2026-09-22"), None);
        assert_eq!(parse_rfc3339_utc("2026-09-22T12:00:00+1:00"), None);
        assert_eq!(parse_rfc3339_utc("2026-09-22T12:00:00."), None);
        assert_eq!(parse_rfc3339_utc("+026-09-22T12:00:00Z"), None);
    }
}
