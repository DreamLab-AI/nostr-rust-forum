//! Public agent-disclosure read endpoint (COM-13/F2, ADR-106 Decision 3).
//!
//! `GET /api/agents/disclosure` returns the minimal, unauthenticated-safe view
//! of the active agent set: `pubkey`, `name`, and the authorising principal
//! (`registered_by`). The forum client's disclosure badge reads this to mark
//! agent-authored items, sourcing the authorising principal server-side from
//! `agent_registry.registered_by` — never from an event self-claim.
//!
//! This is deliberately narrower than the auth-worker's NIP-98-gated
//! `GET /api/governance/agents` (which lists ALL agents with full columns for
//! roster admin): the badge needs only the active set and the three public
//! fields, and it must render for any reader — including an unauthenticated
//! visitor browsing posts. Active-only projection means a revoked agent
//! (`active = 0`) drops out of the disclosure on the next client refresh, so
//! its authored items stop carrying a badge.

use serde::{Deserialize, Serialize};
use serde_json::json;
use worker::{Env, Response, Result};

use crate::cors::json_response;

/// One `agent_registry` row, read for disclosure. Only the columns the public
/// badge needs are selected; `active` drives the projection. D1 returns the
/// SQLite `INTEGER active` as an `f64`, matching the auth-worker's `AgentRow`.
#[derive(Deserialize)]
struct AgentRegistryRow {
    pubkey: String,
    name: String,
    registered_by: String,
    active: f64,
}

/// The minimal public disclosure shape rendered by the client badge. Carries
/// only the three fields a reader needs to see who authorised an agent — no
/// `description`, `rate_limit_per_min` or `registered_at`.
#[derive(Serialize, PartialEq, Debug)]
struct AgentDisclosure {
    pubkey: String,
    name: String,
    registered_by: String,
}

/// Pure projection: keep only active agents and drop every column the public
/// badge does not need. This is the authoritative disclosure contract; the
/// handler's SQL `WHERE active = 1` is the query-time optimisation over the
/// same rule. Splitting it out keeps the active filter and the minimal-field
/// shape unit-testable without a D1 binding (mirrors `governance_api.rs`).
fn active_disclosures(rows: Vec<AgentRegistryRow>) -> Vec<AgentDisclosure> {
    rows.into_iter()
        .filter(|r| r.active != 0.0)
        .map(|r| AgentDisclosure {
            pubkey: r.pubkey,
            name: r.name,
            registered_by: r.registered_by,
        })
        .collect()
}

/// Merge config-declared ingress recipients into the registry's disclosures.
///
/// Read-time and write-free: nothing is stored, so the entries cannot be lost
/// to an operator reset of D1. A registry row for the same pubkey **wins** (it
/// records who actually signed the registration), config only fills gaps. An
/// entry with no `authorised_by` is left out: the disclosure exists to name the
/// authorising principal, and an empty one would mislead. Result is ordered by
/// name, as the SQL `ORDER BY name` already orders the registry rows.
fn merge_ingress_disclosures(
    mut disclosed: Vec<AgentDisclosure>,
    ingress: &[nostr_bbs_config::ingress::IngressRecipient],
) -> Vec<AgentDisclosure> {
    for entry in ingress {
        if entry.authorised_by.is_empty() {
            continue;
        }
        if disclosed
            .iter()
            .any(|d| d.pubkey.eq_ignore_ascii_case(&entry.pubkey))
        {
            continue;
        }
        disclosed.push(AgentDisclosure {
            pubkey: entry.pubkey.clone(),
            name: entry.label.clone(),
            registered_by: entry.authorised_by.clone(),
        });
    }
    disclosed.sort_by(|a, b| a.name.cmp(&b.name));
    disclosed
}

/// `GET /api/agents/disclosure` (public).
///
/// Lists the active agent set for the disclosure badge. No auth: the response
/// carries only the three public fields, for agents the relay currently treats
/// as active plus any config-declared ingress recipient that names an
/// authorising principal (see [`merge_ingress_disclosures`]).
pub async fn handle_agent_disclosure(env: &Env) -> Result<Response> {
    let db = env.d1("DB")?;
    let result = db
        .prepare(
            "SELECT pubkey, name, registered_by, active FROM agent_registry \
             WHERE active = 1 ORDER BY name",
        )
        .all()
        .await?;
    let rows = result.results::<AgentRegistryRow>()?;
    let agents = merge_ingress_disclosures(
        active_disclosures(rows),
        &crate::ingress::ingress_from_env(env),
    );

    json_response(env, &json!({ "agents": agents }), 200)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
//
// The handler itself is Env/D1-bound (it needs the `DB` binding), so its wire
// path is exercised end-to-end in the worker deploy. These cover the pure
// projection: active-only filtering and the minimal-field shape — the two
// predicates COM-13/F2's falsification statement turns on (a revoked/human
// pubkey renders no badge; the principal is a registry field, not content).
#[cfg(test)]
mod tests {
    use super::*;

    fn row(pubkey: &str, name: &str, registered_by: &str, active: f64) -> AgentRegistryRow {
        AgentRegistryRow {
            pubkey: pubkey.to_string(),
            name: name.to_string(),
            registered_by: registered_by.to_string(),
            active,
        }
    }

    #[test]
    fn active_agent_is_disclosed_with_authorising_principal() {
        let agent_pk = "a".repeat(64);
        let principal = "b".repeat(64);
        let out = active_disclosures(vec![row(&agent_pk, "scribe-bot", &principal, 1.0)]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].pubkey, agent_pk);
        assert_eq!(out[0].name, "scribe-bot");
        // The named principal is the registry `registered_by` column, verbatim.
        assert_eq!(out[0].registered_by, principal);
    }

    #[test]
    fn inactive_agent_is_excluded() {
        // A revoked agent (active = 0) must not appear in the disclosure set,
        // so its authored items render no badge (ADR-106 Decision 3 consequence
        // + WP-2 falsification: a non-active pubkey carries no badge).
        let out = active_disclosures(vec![
            row(&"a".repeat(64), "live-bot", &"b".repeat(64), 1.0),
            row(&"c".repeat(64), "revoked-bot", &"b".repeat(64), 0.0),
        ]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "live-bot");
        assert!(out.iter().all(|d| d.name != "revoked-bot"));
    }

    #[test]
    fn disclosure_serialises_only_the_minimal_public_fields() {
        let d = AgentDisclosure {
            pubkey: "a".repeat(64),
            name: "scribe-bot".to_string(),
            registered_by: "b".repeat(64),
        };
        let v = serde_json::to_value(&d).unwrap();
        let obj = v.as_object().expect("object");
        // Exactly the three public fields — nothing leaks from the wider row.
        assert_eq!(obj.len(), 3);
        assert!(obj.contains_key("pubkey"));
        assert!(obj.contains_key("name"));
        assert!(obj.contains_key("registered_by"));
        assert!(!obj.contains_key("description"));
        assert!(!obj.contains_key("rate_limit_per_min"));
        assert!(!obj.contains_key("registered_at"));
        assert!(!obj.contains_key("active"));
    }

    #[test]
    fn parses_d1_shaped_row_with_numeric_active() {
        // D1 hands back the INTEGER `active` as a JSON number; ensure the row
        // deserialises and projects (active = 1 → disclosed).
        let raw = format!(
            r#"[{{"pubkey":"{}","name":"n","registered_by":"{}","active":1}}]"#,
            "a".repeat(64),
            "b".repeat(64)
        );
        let rows: Vec<AgentRegistryRow> = serde_json::from_str(&raw).unwrap();
        let out = active_disclosures(rows);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn empty_registry_discloses_nothing() {
        let out = active_disclosures(Vec::new());
        assert!(out.is_empty());
    }
    fn declared(
        label: &str,
        pubkey: &str,
        authorised_by: &str,
    ) -> nostr_bbs_config::ingress::IngressRecipient {
        nostr_bbs_config::ingress::IngressRecipient {
            label: label.into(),
            pubkey: pubkey.into(),
            role: nostr_bbs_config::ingress::IngressRole::Copy,
            description: String::new(),
            authorised_by: authorised_by.into(),
        }
    }

    #[test]
    fn declared_recipient_is_disclosed_with_its_principal() {
        let out = merge_ingress_disclosures(
            vec![],
            &[declared("site-inbox", &"a".repeat(64), &"b".repeat(64))],
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "site-inbox");
        assert_eq!(out[0].registered_by, "b".repeat(64));
    }

    #[test]
    fn registry_row_wins_over_config() {
        let pk = "a".repeat(64);
        let rows = active_disclosures(vec![row(&pk, "registered-name", &"c".repeat(64), 1.0)]);
        let out = merge_ingress_disclosures(
            rows,
            &[declared("config-name", &pk.to_uppercase(), &"b".repeat(64))],
        );
        assert_eq!(
            out.len(),
            1,
            "no duplicate for the same key, case-insensitively"
        );
        assert_eq!(out[0].name, "registered-name");
        assert_eq!(out[0].registered_by, "c".repeat(64));
    }

    #[test]
    fn counter_example_entry_without_a_principal_is_not_disclosed() {
        let out = merge_ingress_disclosures(vec![], &[declared("anon", &"a".repeat(64), "")]);
        assert!(out.is_empty());
    }

    #[test]
    fn no_config_leaves_the_registry_projection_unchanged() {
        let rows = active_disclosures(vec![row(
            &"a".repeat(64),
            "scribe-bot",
            &"b".repeat(64),
            1.0,
        )]);
        let out = merge_ingress_disclosures(rows, &[]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "scribe-bot");
    }

    #[test]
    fn merged_list_is_ordered_by_name() {
        let rows = active_disclosures(vec![row(&"a".repeat(64), "zeta", &"b".repeat(64), 1.0)]);
        let out =
            merge_ingress_disclosures(rows, &[declared("alpha", &"c".repeat(64), &"b".repeat(64))]);
        assert_eq!(
            out.iter().map(|d| d.name.as_str()).collect::<Vec<_>>(),
            ["alpha", "zeta"]
        );
    }
}
