//! Config-declared gift-wrap recipients (`INGRESS_RECIPIENTS`).
//!
//! The relay admits a kind-1059 wrap only if its recipient is whitelisted in D1,
//! and `POST /api/admin/reset-db` empties that table. A recipient declared in
//! the deployment's `[[ingress]]` config reaches the worker as the
//! `INGRESS_RECIPIENTS` binding and is admitted without a D1 row, so it survives
//! a reset.
//!
//! This only widens who a *wrap may be addressed to*. It grants no cohort, admin
//! right or zone key, and it is consulted only inside the kind-1059 branch of
//! the admission gate: events an ingress key *authors* are checked against the
//! whitelist exactly as before (`gate_consults_ingress_only_for_gift_wraps`).

use nostr_bbs_config::ingress::{parse_ingress_relay_var, IngressRecipient};
use worker::Env;

/// Name of the worker binding that carries the rendered `[[ingress]]` list.
pub(crate) const INGRESS_VAR: &str = "INGRESS_RECIPIENTS";

/// Parse the binding value. Absent, empty or malformed ⇒ no recipients, so the
/// gate behaves exactly as it did before this binding existed. Never panics.
pub(crate) fn ingress_from_var(raw: Option<&str>) -> Vec<IngressRecipient> {
    raw.map(parse_ingress_relay_var).unwrap_or_default()
}

/// Read the declared recipients from the worker environment.
pub(crate) fn ingress_from_env(env: &Env) -> Vec<IngressRecipient> {
    ingress_from_var(env.var(INGRESS_VAR).ok().map(|v| v.to_string()).as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr_bbs_config::ingress::{ingress_relay_var, is_ingress_recipient, IngressRole};

    fn declared(pubkey: &str) -> String {
        ingress_relay_var(&[IngressRecipient {
            label: "inbox".into(),
            pubkey: pubkey.into(),
            role: IngressRole::Primary,
            description: String::new(),
            authorised_by: String::new(),
        }])
    }

    #[test]
    fn absent_var_behaves_as_before() {
        assert!(ingress_from_var(None).is_empty());
        assert!(ingress_from_var(Some("")).is_empty());
        assert!(ingress_from_var(Some("[]")).is_empty());
    }

    #[test]
    fn declared_recipient_is_admitted_without_a_whitelist_row() {
        let list = ingress_from_var(Some(&declared(&"ab".repeat(32))));
        assert!(is_ingress_recipient(&list, &"ab".repeat(32)));
        assert!(is_ingress_recipient(&list, &"AB".repeat(32)));
    }

    #[test]
    fn counter_example_stranger_is_not_admitted() {
        let list = ingress_from_var(Some(&declared(&"ab".repeat(32))));
        assert!(!is_ingress_recipient(&list, &"cd".repeat(32)));
    }

    #[test]
    fn counter_example_malformed_var_admits_nothing_and_does_not_panic() {
        for raw in ["not json", "{", "[{\"pubkey\":1}]", "null", "\u{0}", "[[]]"] {
            assert!(ingress_from_var(Some(raw)).is_empty(), "{raw:?}");
        }
    }

    /// An ingress key gains nothing on the author path: `ingress` may be named
    /// only inside the kind-1059 branch of the admission gate, never in the
    /// `else` branch that checks the author against the whitelist.
    #[test]
    fn gate_consults_ingress_only_for_gift_wraps() {
        let src = include_str!("relay_do/nip_handlers.rs");
        let prod = src.split("#[cfg(test)]").next().unwrap();
        let start = prod
            .find("if event.kind == GIFT_WRAP_KIND {")
            .expect("gift-wrap gate present");
        let else_at = start
            + prod[start..]
                .find("} else {")
                .expect("author branch follows the gift-wrap branch");
        let wrap_branch = &prod[start..else_at];
        assert!(wrap_branch.contains("is_ingress_recipient"));
        let uses = prod.matches("is_ingress_recipient").count();
        assert_eq!(
            uses, 1,
            "ingress consulted exactly once, in the wrap branch"
        );
    }
}
