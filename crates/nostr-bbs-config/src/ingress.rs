//! `[[ingress]]` — recipients the relay admits end-to-end-encrypted form traffic for.
//!
//! A static site can take contact enquiries, signups and chat messages with no
//! database by gift-wrapping (NIP-59) each message to a recipient pubkey and
//! publishing the wrap to the relay. The relay admits a kind-1059 wrap only when
//! its recipient is a whitelisted member, and the whitelist is D1 state that an
//! operator reset (`POST /api/admin/reset-db`) silently empties. An ingress
//! recipient is declared in configuration instead, so it survives a reset and is
//! reviewable in the same file as the rest of the deployment.
//!
//! Declaring a recipient **only** lets the relay accept wraps addressed to it. It
//! grants no cohort, no admin right and no zone key, and it does not widen what
//! that key may *author*: its own events still go through the whitelist like
//! anyone else's.
//!
//! The deploy pipeline renders the list with [`ingress_relay_var`] into the relay
//! worker's `INGRESS_RECIPIENTS` binding; the worker reads it back with
//! [`parse_ingress_relay_var`]. Both ends use the types in this module, so the
//! wire format cannot drift between them.
//!
//! # Example
//!
//! ```
//! use nostr_bbs_config::ingress::{
//!     ingress_relay_var, is_ingress_recipient, parse_ingress_relay_var, IngressRecipient,
//!     IngressRole,
//! };
//!
//! let inbox = IngressRecipient {
//!     label: "site-inbox".into(),
//!     pubkey: "ab".repeat(32),
//!     role: IngressRole::Primary,
//!     description: String::new(),
//!     authorised_by: String::new(),
//! };
//! let var = ingress_relay_var(&[inbox]);
//! let parsed = parse_ingress_relay_var(&var);
//! assert!(is_ingress_recipient(&parsed, &"AB".repeat(32)));
//! assert!(!is_ingress_recipient(&parsed, &"cd".repeat(32)));
//! ```

use serde::{Deserialize, Serialize};

/// Longest accepted [`IngressRecipient::label`].
pub const MAX_LABEL_LEN: usize = 64;

/// What an ingress recipient is for. Informational: it does not change how the
/// relay admits wraps, only how the entry is described to operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IngressRole {
    /// The operator's own inbox for enquiries and signups.
    Primary,
    /// A second recipient that gets a copy of the same messages, such as a
    /// monitoring key read by a scheduled job.
    Copy,
    /// An agent identity that answers messages, such as a chat assistant.
    Agent,
}

/// One `[[ingress]]` entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngressRecipient {
    /// Human-readable name, shown in the public agent disclosure. 1 to
    /// [`MAX_LABEL_LEN`] characters once trimmed.
    pub label: String,
    /// Recipient pubkey, 64 hex characters. Compared case-insensitively.
    pub pubkey: String,
    /// What the recipient is for.
    pub role: IngressRole,
    /// Free-text note for operators. Not sent to the relay.
    #[serde(default, skip_serializing)]
    pub description: String,
    /// Pubkey of the principal who authorised this recipient: 64 hex characters,
    /// or empty. When set, the public agent disclosure names it as the
    /// registering principal; when empty the entry is not disclosed.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub authorised_by: String,
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Check a list of `[[ingress]]` entries.
///
/// An empty list is valid. Labels must be non-empty after trimming and at most
/// [`MAX_LABEL_LEN`] characters; pubkeys must be 64 hex characters and unique
/// (ignoring case); `authorised_by` must be empty or 64 hex characters.
///
/// # Errors
///
/// Returns a message naming the offending `ingress` entry.
pub fn validate_ingress(entries: &[IngressRecipient]) -> Result<(), String> {
    let mut seen = std::collections::HashSet::new();
    for (i, e) in entries.iter().enumerate() {
        let label = e.label.trim();
        if label.is_empty() {
            return Err(format!("ingress[{i}].label must not be empty"));
        }
        if label.chars().count() > MAX_LABEL_LEN {
            return Err(format!(
                "ingress[{i}].label must be at most {MAX_LABEL_LEN} characters"
            ));
        }
        if !is_hex64(&e.pubkey) {
            return Err(format!(
                "ingress[{i}].pubkey ({label}) must be 64 hex characters"
            ));
        }
        if !seen.insert(e.pubkey.to_ascii_lowercase()) {
            return Err(format!(
                "ingress[{i}].pubkey ({label}) duplicates an earlier ingress entry"
            ));
        }
        if !e.authorised_by.is_empty() && !is_hex64(&e.authorised_by) {
            return Err(format!(
                "ingress[{i}].authorised_by ({label}) must be empty or 64 hex characters"
            ));
        }
    }
    Ok(())
}

/// Render the list as the JSON the relay worker reads from `INGRESS_RECIPIENTS`.
///
/// Pubkeys are lowercased. An empty list renders as `[]`.
#[must_use]
pub fn ingress_relay_var(entries: &[IngressRecipient]) -> String {
    let normalised: Vec<IngressRecipient> = entries
        .iter()
        .map(|e| IngressRecipient {
            pubkey: e.pubkey.to_ascii_lowercase(),
            authorised_by: e.authorised_by.to_ascii_lowercase(),
            ..e.clone()
        })
        .collect();
    serde_json::to_string(&normalised).unwrap_or_else(|_| "[]".to_string())
}

/// Read the `INGRESS_RECIPIENTS` binding back into entries. **Fails closed.**
///
/// Malformed JSON yields an empty list, and any entry whose pubkey is not 64 hex
/// characters is dropped, so a bad binding admits nothing beyond what the
/// whitelist already admits. Pubkeys come back lowercased. Never panics.
#[must_use]
pub fn parse_ingress_relay_var(raw: &str) -> Vec<IngressRecipient> {
    let Ok(entries) = serde_json::from_str::<Vec<IngressRecipient>>(raw) else {
        return Vec::new();
    };
    entries
        .into_iter()
        .filter(|e| is_hex64(&e.pubkey))
        .map(|mut e| {
            e.pubkey.make_ascii_lowercase();
            if !is_hex64(&e.authorised_by) {
                e.authorised_by.clear();
            } else {
                e.authorised_by.make_ascii_lowercase();
            }
            e
        })
        .collect()
}

/// True when `pubkey` is one of `entries`, ignoring case.
#[must_use]
pub fn is_ingress_recipient(entries: &[IngressRecipient], pubkey: &str) -> bool {
    entries
        .iter()
        .any(|e| e.pubkey.eq_ignore_ascii_case(pubkey))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(label: &str, pubkey: &str, role: IngressRole) -> IngressRecipient {
        IngressRecipient {
            label: label.into(),
            pubkey: pubkey.into(),
            role,
            description: String::new(),
            authorised_by: String::new(),
        }
    }
    fn pk(c: char) -> String {
        c.to_string().repeat(64)
    }

    #[test]
    fn empty_list_is_valid_and_renders_empty() {
        assert!(validate_ingress(&[]).is_ok());
        assert_eq!(ingress_relay_var(&[]), "[]");
    }

    #[test]
    fn valid_entries_pass() {
        let mut e = entry("inbox", &pk('a'), IngressRole::Primary);
        e.authorised_by = pk('b');
        assert!(validate_ingress(&[e, entry("copy", &pk('c'), IngressRole::Copy)]).is_ok());
    }

    #[test]
    fn rejects_empty_or_overlong_label() {
        assert!(validate_ingress(&[entry("  ", &pk('a'), IngressRole::Copy)]).is_err());
        let long = "x".repeat(MAX_LABEL_LEN + 1);
        assert!(validate_ingress(&[entry(&long, &pk('a'), IngressRole::Copy)]).is_err());
    }

    #[test]
    fn rejects_bad_pubkeys() {
        for bad in ["", "abc", &"g".repeat(64), &"a".repeat(65)] {
            let r = validate_ingress(&[entry("x", bad, IngressRole::Copy)]);
            assert!(r.unwrap_err().contains("64 hex"), "{bad:?}");
        }
    }

    #[test]
    fn rejects_duplicate_pubkeys_ignoring_case() {
        let r = validate_ingress(&[
            entry("one", &"ab".repeat(32), IngressRole::Primary),
            entry("two", &"AB".repeat(32), IngressRole::Copy),
        ]);
        assert!(r.unwrap_err().contains("duplicates"));
    }

    #[test]
    fn rejects_malformed_authorised_by() {
        let mut e = entry("x", &pk('a'), IngressRole::Agent);
        e.authorised_by = "nope".into();
        assert!(validate_ingress(&[e])
            .unwrap_err()
            .contains("authorised_by"));
    }

    #[test]
    fn var_round_trips_and_lowercases() {
        let mut e = entry("Site Inbox", &"AB".repeat(32), IngressRole::Primary);
        e.authorised_by = "CD".repeat(32);
        e.description = "operator note".into();
        let parsed = parse_ingress_relay_var(&ingress_relay_var(&[e]));
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].pubkey, "ab".repeat(32));
        assert_eq!(parsed[0].authorised_by, "cd".repeat(32));
        assert_eq!(parsed[0].label, "Site Inbox");
        assert_eq!(parsed[0].role, IngressRole::Primary);
    }

    #[test]
    fn description_is_not_sent_to_the_relay() {
        let mut e = entry("x", &pk('a'), IngressRole::Copy);
        e.description = "private operator note".into();
        assert!(!ingress_relay_var(&[e]).contains("private operator note"));
    }

    #[test]
    fn counter_example_malformed_var_admits_nothing() {
        for raw in ["", "not json", "{}", "[1,2]", r#"[{"pubkey":"x"}]"#, "null"] {
            assert!(parse_ingress_relay_var(raw).is_empty(), "{raw:?}");
        }
    }

    #[test]
    fn counter_example_bad_entries_are_dropped_not_trusted() {
        let raw = format!(
            r#"[{{"label":"bad","pubkey":"zz","role":"copy"}},{{"label":"ok","pubkey":"{}","role":"copy","authorised_by":"junk"}}]"#,
            pk('a')
        );
        let parsed = parse_ingress_relay_var(&raw);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].label, "ok");
        assert!(parsed[0].authorised_by.is_empty(), "junk principal cleared");
    }

    #[test]
    fn recipient_lookup_ignores_case_and_rejects_strangers() {
        let list = [entry("x", &"ab".repeat(32), IngressRole::Copy)];
        assert!(is_ingress_recipient(&list, &"AB".repeat(32)));
        assert!(!is_ingress_recipient(&list, &"cd".repeat(32)));
        assert!(!is_ingress_recipient(&[], &"ab".repeat(32)));
    }

    #[test]
    fn toml_table_array_parses() {
        #[derive(Deserialize)]
        struct Doc {
            ingress: Vec<IngressRecipient>,
        }
        let doc: Doc = toml::from_str(&format!(
            "[[ingress]]\nlabel = \"inbox\"\npubkey = \"{}\"\nrole = \"primary\"\n",
            pk('a')
        ))
        .unwrap();
        assert_eq!(doc.ingress[0].role, IngressRole::Primary);
        assert!(doc.ingress[0].authorised_by.is_empty());
    }
}
