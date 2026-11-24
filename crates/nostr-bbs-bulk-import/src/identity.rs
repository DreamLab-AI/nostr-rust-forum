//! Identity planning: which key signs each source author's history, and
//! which keys the deployment whitelists, makes admin or links by alias.
//!
//! `identities.json`:
//!
//! ```json
//! {
//!   "version": 1,
//!   "default": "fresh",
//!   "authors": {
//!     "alice":   {"decision": "fresh"},
//!     "bob":     {"decision": "existing", "pubkey": "<64-hex live key>", "proof": {…signed event…}},
//!     "carol":   {"decision": "existing", "pubkey": "<64-hex live key>", "trust": "operator"},
//!     "bob2":    {"decision": "merge", "into": "bob"},
//!     "meetbot": {"decision": "drop"},
//!     "jj":      {"decision": "operator", "defer": true}
//!   }
//! }
//! ```
//!
//! | Decision | History signed by | Keystore label | Whitelisted |
//! |---|---|---|---|
//! | `fresh` | a new key | `author:<id>` | yes, zone cohorts |
//! | `existing` | a new per-person **archive key**, aliased to the live key | `archive:<id>` | the live key, zone cohorts, **only with a valid `proof`**; the archive key never |
//! | `merge` | the target author's signer | (target's) | (target's) |
//! | `drop` | nothing; replies to it get a "not migrated" note | — | — |
//! | `operator` | the imported operator key; with `defer`, imported later by `build --deferred-only` | `operator` | yes, admin |
//!
//! The archivist (label `archivist`) signs topic roots, new thread headers
//! and the seals; it is a whitelisted admin with the zone cohorts and never
//! the `agent` cohort.
//!
//! **Proof of a live key.** A typo or a hostile mapping in `identities.json`
//! would otherwise whitelist (and so grant the zone key to) a stranger, and
//! show a real person's history under the stranger's profile. So an
//! `existing` entry carries either a `proof`, an event signed by that key
//! whose content is exactly [`link_statement`] (verified with
//! [`nostr_bbs_core::event::verify_event_strict`]; any kind, never published),
//! or `"trust": "operator"`, the operator's explicit assertion, which writes
//! the alias but does NOT whitelist the key (the person joins through the
//! deployment's normal invite flow).
//!
//! We never hold or ask for another person's live secret: a person who keeps
//! a live key gets an archive key for their history and a profile successor
//! (`pubkey_aliases`, many predecessors to one successor) so every client
//! shows the live identity. See `docs/bulk-import/SECURITY.md`.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::{Deserialize, Serialize};

use crate::error::ImportError;
use crate::format::Archive;

/// Keystore label of the archivist.
pub const ARCHIVIST: &str = "archivist";
/// Keystore label of the operator.
pub const OPERATOR: &str = "operator";

/// One author's decision in `identities.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case", deny_unknown_fields)]
pub enum Decision {
    /// A new forum identity.
    Fresh,
    /// Keeps a live key; history signed by an archive key aliased to it.
    Existing {
        /// The live public key, lowercase hex.
        pubkey: String,
        /// An event signed by `pubkey` whose content is [`link_statement`].
        #[serde(default, skip_serializing_if = "Option::is_none")]
        proof: Option<nostr_bbs_core::NostrEvent>,
        /// `"operator"`: the operator vouches for the mapping without a
        /// proof (alias only; the key is not whitelisted).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        trust: Option<Trust>,
    },
    /// Same person as another author.
    Merge {
        /// The author id whose identity this one shares.
        into: String,
    },
    /// Not imported.
    Drop,
    /// The operator: signs with the imported operator key.
    Operator {
        /// Record the messages and import them later (`build --deferred-only`).
        #[serde(default)]
        defer: bool,
    },
}

/// Who vouches for an unproven live key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Trust {
    /// The operator asserts the mapping (alias only, no whitelist row).
    Operator,
}

/// The exact text a live key signs to prove it belongs to `author` of the
/// archive `provenance` (`<source>:<source_id>`).
pub fn link_statement(provenance: &str, author: &str) -> String {
    format!("nostr-bbs-bulk-import link {provenance} {author}")
}

/// Check a live-key proof (see the module docs).
pub fn check_proof(
    proof: &nostr_bbs_core::NostrEvent,
    pubkey: &str,
    provenance: &str,
    author: &str,
) -> Result<(), String> {
    nostr_bbs_core::event::verify_event_strict(proof)
        .map_err(|e| format!("proof does not verify: {e}"))?;
    if proof.pubkey != pubkey {
        return Err("proof is signed by a different key".into());
    }
    if proof.content != link_statement(provenance, author) {
        return Err(format!(
            "proof content must be exactly {:?}",
            link_statement(provenance, author)
        ));
    }
    Ok(())
}

/// What an author without an entry gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DefaultDecision {
    /// Every author must be listed (refused otherwise).
    #[default]
    Require,
    /// Unlisted authors get a fresh identity.
    Fresh,
}

/// `identities.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityFile {
    /// Always 1.
    pub version: u32,
    /// What unlisted authors get.
    #[serde(default)]
    pub default: DefaultDecision,
    /// Author id → decision.
    #[serde(default)]
    pub authors: BTreeMap<String, Decision>,
}

/// How a resolved author signs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signer {
    /// A key in the keystore under this label.
    Key {
        /// Keystore label.
        label: String,
        /// Operator messages imported later.
        deferred: bool,
    },
    /// Not imported.
    Dropped,
}

/// One author, resolved (merges followed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    /// The canonical author id (after merges).
    pub canonical: String,
    /// The handle shown in profiles.
    pub handle: String,
    /// Display name for the profile.
    pub display_name: Option<String>,
    /// Profile text.
    pub about: Option<String>,
    /// How this author signs.
    pub signer: Signer,
    /// The live key this author keeps (`existing`).
    pub live_pubkey: Option<String>,
    /// The live key is proven by a signature (only then is it whitelisted).
    pub live_proven: bool,
}

/// The whole identity plan.
#[derive(Debug, Clone, Default)]
pub struct IdentityPlan {
    /// Author id → resolution (every author in the archive).
    pub authors: BTreeMap<String, Resolved>,
    /// Keystore labels to generate, with their role.
    pub generate: BTreeMap<String, crate::keystore::Role>,
    /// Whether some author is the operator (needs an imported key).
    pub needs_operator: bool,
    /// Whether every operator message is deferred.
    pub operator_deferred: bool,
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

impl IdentityFile {
    /// Parse `identities.json`.
    pub fn parse(bytes: &[u8]) -> Result<Self, ImportError> {
        let f: IdentityFile = serde_json::from_slice(bytes)
            .map_err(|e| ImportError::Format(format!("identities.json: {e}")))?;
        if f.version != 1 {
            return Err(ImportError::Format(format!(
                "identities.json version {} unsupported",
                f.version
            )));
        }
        Ok(f)
    }

    /// A template listing every author of `archive` as `fresh`, bots as
    /// `drop`, for the operator to edit.
    pub fn template(archive: &Archive) -> Self {
        IdentityFile {
            version: 1,
            default: DefaultDecision::Require,
            authors: archive
                .authors
                .iter()
                .map(|a| {
                    (
                        a.id.clone(),
                        if a.bot {
                            Decision::Drop
                        } else {
                            Decision::Fresh
                        },
                    )
                })
                .collect(),
        }
    }
}

/// Resolve every author of `archive` against `file`. All problems are
/// listed in one error.
pub fn plan(archive: &Archive, file: &IdentityFile) -> Result<IdentityPlan, ImportError> {
    let mut errs = Vec::new();
    let by_id = archive.authors_by_id();
    for id in file.authors.keys() {
        if !by_id.contains_key(id.as_str()) {
            errs.push(format!("identities.json names unknown author {id:?}"));
        }
    }
    let decision = |id: &str| -> Option<Decision> {
        match file.authors.get(id) {
            Some(d) => Some(d.clone()),
            None if file.default == DefaultDecision::Fresh => Some(Decision::Fresh),
            None => None,
        }
    };
    let provenance = format!("{}:{}", archive.manifest.source, archive.manifest.source_id);
    let mut live_owner: HashMap<String, String> = HashMap::new();
    let mut proven: HashMap<String, bool> = HashMap::new();
    let mut operators = Vec::new();
    for a in &archive.authors {
        match decision(&a.id) {
            None => errs.push(format!(
                "author {:?} ({}) has no decision and the default is \"require\"",
                a.id, a.handle
            )),
            Some(Decision::Existing {
                pubkey,
                proof,
                trust,
            }) => {
                if !is_hex64(&pubkey) {
                    errs.push(format!(
                        "author {:?}: pubkey must be 64 lowercase hex",
                        a.id
                    ));
                } else if let Some(other) = live_owner.insert(pubkey.clone(), a.id.clone()) {
                    errs.push(format!("authors {other:?} and {:?} share the live key {}…; merge one into the other", a.id, &pubkey[..8]));
                }
                match (&proof, trust) {
                    (Some(p), _) => match check_proof(p, &pubkey, &provenance, &a.id) {
                        Ok(()) => {
                            proven.insert(a.id.clone(), true);
                        }
                        Err(e) => errs.push(format!("author {:?}: {e}", a.id)),
                    },
                    (None, Some(Trust::Operator)) => {
                        proven.insert(a.id.clone(), false);
                    }
                    (None, None) => errs.push(format!(
                        "author {:?}: an existing live key needs a \"proof\" (an event signed by it with content {:?}) or \"trust\": \"operator\"",
                        a.id,
                        link_statement(&provenance, &a.id)
                    )),
                }
            }
            Some(Decision::Operator { .. }) => operators.push(a.id.clone()),
            _ => {}
        }
    }
    let defers: BTreeSet<bool> = operators
        .iter()
        .filter_map(|id| match decision(id) {
            Some(Decision::Operator { defer }) => Some(defer),
            _ => None,
        })
        .collect();
    if defers.len() > 1 {
        errs.push("operator authors disagree on \"defer\"".into());
    }

    let mut out = IdentityPlan {
        needs_operator: !operators.is_empty(),
        operator_deferred: defers.contains(&true),
        ..Default::default()
    };
    for a in &archive.authors {
        // follow merges, refusing chains, cycles and merges into drops
        let mut cur = a.id.clone();
        let mut d = match decision(&cur) {
            Some(d) => d,
            None => continue,
        };
        if let Decision::Merge { into } = &d {
            if into == &a.id {
                errs.push(format!("author {:?} merges into itself", a.id));
                continue;
            }
            match decision(into) {
                Some(Decision::Merge { .. }) => {
                    errs.push(format!(
                        "author {:?} merges into {into:?}, which merges again (no chains)",
                        a.id
                    ));
                    continue;
                }
                Some(Decision::Drop) => {
                    errs.push(format!("author {:?} merges into dropped {into:?}", a.id));
                    continue;
                }
                None if !by_id.contains_key(into.as_str()) => {
                    errs.push(format!("author {:?} merges into unknown {into:?}", a.id));
                    continue;
                }
                None => continue,
                Some(t) => {
                    cur = into.clone();
                    d = t;
                }
            }
        }
        let target = by_id.get(cur.as_str()).copied().unwrap_or(a);
        let live_proven = proven.get(&cur).copied().unwrap_or(false);
        let (signer, live) = match &d {
            Decision::Fresh => {
                let l = format!("author:{cur}");
                out.generate.insert(l.clone(), crate::keystore::Role::Fresh);
                (
                    Signer::Key {
                        label: l,
                        deferred: false,
                    },
                    None,
                )
            }
            Decision::Existing { pubkey, .. } => {
                let l = format!("archive:{cur}");
                out.generate
                    .insert(l.clone(), crate::keystore::Role::Archive);
                (
                    Signer::Key {
                        label: l,
                        deferred: false,
                    },
                    Some(pubkey.clone()),
                )
            }
            Decision::Operator { defer } => (
                Signer::Key {
                    label: OPERATOR.into(),
                    deferred: *defer,
                },
                None,
            ),
            Decision::Drop => (Signer::Dropped, None),
            Decision::Merge { .. } => unreachable!("merge resolved above"),
        };
        out.authors.insert(
            a.id.clone(),
            Resolved {
                canonical: cur.clone(),
                handle: target.handle.clone(),
                display_name: target.display_name.clone(),
                about: target.about.clone(),
                signer,
                live_pubkey: live,
                live_proven,
            },
        );
    }
    out.generate
        .insert(ARCHIVIST.into(), crate::keystore::Role::Archivist);
    if errs.is_empty() {
        Ok(out)
    } else {
        Err(ImportError::Plan(errs.join("\n")))
    }
}

impl IdentityPlan {
    /// Generate every key the plan needs (existing labels are kept as they
    /// are) and save the store. Returns the labels created.
    pub fn ensure_keys(
        &self,
        ks: &mut crate::keystore::Keystore,
    ) -> Result<Vec<String>, ImportError> {
        let mut created = Vec::new();
        for (label, role) in &self.generate {
            if ks.ensure(label, *role)?.1 {
                created.push(label.clone());
            }
        }
        ks.save()?;
        Ok(created)
    }

    /// Refuse keys that collide: a live key equal to a key in the keystore
    /// (the archivist, the operator, any generated key).
    pub fn check_keys(&self, ks: &crate::keystore::Keystore) -> Result<(), ImportError> {
        let live: BTreeSet<&str> = self
            .authors
            .values()
            .filter_map(|r| r.live_pubkey.as_deref())
            .collect();
        for label in ks.labels() {
            if let Some(e) = ks.get(label) {
                if live.contains(e.pk.as_str()) {
                    return Err(ImportError::Refused(format!(
                        "keystore key {label:?} equals a live key in identities.json"
                    )));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::{ArchiveWriter, Author, Channel, Message};

    fn archive(dir: &std::path::Path) -> Archive {
        let _ = std::fs::remove_dir_all(dir);
        let mut w = ArchiveWriter::new("test", "t");
        w.exported_at(1);
        for (id, bot) in [
            ("a", false),
            ("b", false),
            ("b2", false),
            ("bot", true),
            ("op", false),
        ] {
            w.author(Author {
                id: id.into(),
                handle: id.into(),
                display_name: None,
                about: None,
                bot,
            });
        }
        w.channel(Channel {
            id: "c".into(),
            name: "c".into(),
            topic: None,
            created_at: None,
        });
        w.message(Message {
            id: "m".into(),
            channel: "c".into(),
            author: "a".into(),
            created_at: 1,
            text: "x".into(),
            reply_to: None,
            edited_at: None,
            attachments: vec![],
        });
        w.finish(dir).unwrap()
    }

    #[test]
    fn resolves_merges_and_refuses_bad_plans() {
        let dir = std::env::temp_dir().join(format!("bi-id-{}", std::process::id()));
        let a = archive(&dir);
        let live = "ab".repeat(32);
        let f = IdentityFile::parse(
            format!(
                r#"{{"version":1,"default":"fresh","authors":{{
            "b":{{"decision":"existing","pubkey":"{live}","trust":"operator"}},
            "b2":{{"decision":"merge","into":"b"}},
            "bot":{{"decision":"drop"}},
            "op":{{"decision":"operator","defer":true}}}}}}"#
            )
            .as_bytes(),
        )
        .unwrap();
        let p = plan(&a, &f).unwrap();
        assert_eq!(p.authors["b2"].canonical, "b");
        assert_eq!(
            p.authors["b2"].signer,
            Signer::Key {
                label: "archive:b".into(),
                deferred: false
            }
        );
        assert_eq!(p.authors["b2"].live_pubkey.as_deref(), Some(live.as_str()));
        assert_eq!(p.authors["bot"].signer, Signer::Dropped);
        assert!(p.operator_deferred && p.needs_operator);
        assert!(p.generate.contains_key(ARCHIVIST));
        assert!(!p.generate.contains_key(OPERATOR));

        let chain = IdentityFile::parse(br#"{"version":1,"default":"fresh","authors":{"a":{"decision":"merge","into":"b"},"b":{"decision":"merge","into":"a"}}}"#).unwrap();
        assert!(plan(&a, &chain)
            .unwrap_err()
            .to_string()
            .contains("no chains"));
        let req =
            IdentityFile::parse(br#"{"version":1,"authors":{"a":{"decision":"fresh"}}}"#).unwrap();
        assert!(plan(&a, &req)
            .unwrap_err()
            .to_string()
            .contains("no decision"));
        let shared = IdentityFile::parse(format!(r#"{{"version":1,"default":"fresh","authors":{{"a":{{"decision":"existing","pubkey":"{live}","trust":"operator"}},"b":{{"decision":"existing","pubkey":"{live}","trust":"operator"}}}}}}"#).as_bytes()).unwrap();
        assert!(plan(&a, &shared)
            .unwrap_err()
            .to_string()
            .contains("share the live key"));
        let unknown = IdentityFile::parse(
            br#"{"version":1,"default":"fresh","authors":{"zz":{"decision":"drop"}}}"#,
        )
        .unwrap();
        assert!(plan(&a, &unknown).is_err());
        assert!(!p.authors["b"].live_proven, "operator trust is not a proof");

        // a proof signed by the live key itself
        let kp = nostr_bbs_core::keys::generate_keypair().unwrap();
        let live_pk = kp.public.to_hex();
        let sign = |content: &str| {
            let sk = nostr_bbs_core::keys::signing_key_from_bytes(kp.secret.as_bytes()).unwrap();
            nostr_bbs_core::sign_event(
                nostr_bbs_core::UnsignedEvent {
                    pubkey: live_pk.clone(),
                    created_at: 1,
                    kind: 27235,
                    tags: vec![],
                    content: content.into(),
                },
                &sk,
            )
            .unwrap()
        };
        let good = sign(&link_statement("test:t", "b"));
        let f = IdentityFile {
            version: 1,
            default: DefaultDecision::Fresh,
            authors: [(
                "b".to_string(),
                Decision::Existing {
                    pubkey: live_pk.clone(),
                    proof: Some(good),
                    trust: None,
                },
            )]
            .into(),
        };
        assert!(plan(&a, &f).unwrap().authors["b"].live_proven);
        let wrong = sign(&link_statement("test:t", "a"));
        let f = IdentityFile {
            version: 1,
            default: DefaultDecision::Fresh,
            authors: [(
                "b".to_string(),
                Decision::Existing {
                    pubkey: live_pk.clone(),
                    proof: Some(wrong),
                    trust: None,
                },
            )]
            .into(),
        };
        assert!(plan(&a, &f).is_err());
        let bare = IdentityFile {
            version: 1,
            default: DefaultDecision::Fresh,
            authors: [(
                "b".to_string(),
                Decision::Existing {
                    pubkey: live_pk,
                    proof: None,
                    trust: None,
                },
            )]
            .into(),
        };
        assert!(plan(&a, &bare)
            .unwrap_err()
            .to_string()
            .contains("needs a \"proof\""));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
