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
//!     "bob":     {"decision": "existing", "pubkey": "<64-hex live key>"},
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
//! | `existing` | a new per-person **archive key**, aliased to the live key | `archive:<id>` | the live key, zone cohorts; the archive key never |
//! | `merge` | the target author's signer | (target's) | (target's) |
//! | `drop` | nothing; replies to it get a "not migrated" note | — | — |
//! | `operator` | the imported operator key; with `defer`, imported later by `build --deferred-only` | `operator` | yes, admin |
//!
//! The archivist (label `archivist`) signs topic roots, new thread headers
//! and the seals; it is a whitelisted admin with the zone cohorts and never
//! the `agent` cohort.
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case", deny_unknown_fields)]
pub enum Decision {
    /// A new forum identity.
    Fresh,
    /// Keeps a live key; history signed by an archive key aliased to it.
    Existing {
        /// The live public key, lowercase hex.
        pubkey: String,
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
        let f: IdentityFile =
            serde_json::from_slice(bytes).map_err(|e| ImportError::Format(format!("identities.json: {e}")))?;
        if f.version != 1 {
            return Err(ImportError::Format(format!("identities.json version {} unsupported", f.version)));
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
                .map(|a| (a.id.clone(), if a.bot { Decision::Drop } else { Decision::Fresh }))
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
    let mut live_owner: HashMap<String, String> = HashMap::new();
    let mut operators = Vec::new();
    for a in &archive.authors {
        match decision(&a.id) {
            None => errs.push(format!("author {:?} ({}) has no decision and the default is \"require\"", a.id, a.handle)),
            Some(Decision::Existing { pubkey }) => {
                if !is_hex64(&pubkey) {
                    errs.push(format!("author {:?}: pubkey must be 64 lowercase hex", a.id));
                } else if let Some(other) = live_owner.insert(pubkey.clone(), a.id.clone()) {
                    errs.push(format!("authors {other:?} and {:?} share the live key {}…; merge one into the other", a.id, &pubkey[..8]));
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
                    errs.push(format!("author {:?} merges into {into:?}, which merges again (no chains)", a.id));
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
        let (signer, live) = match &d {
            Decision::Fresh => {
                let l = format!("author:{cur}");
                out.generate.insert(l.clone(), crate::keystore::Role::Fresh);
                (Signer::Key { label: l, deferred: false }, None)
            }
            Decision::Existing { pubkey } => {
                let l = format!("archive:{cur}");
                out.generate.insert(l.clone(), crate::keystore::Role::Archive);
                (Signer::Key { label: l, deferred: false }, Some(pubkey.clone()))
            }
            Decision::Operator { defer } => (Signer::Key { label: OPERATOR.into(), deferred: *defer }, None),
            Decision::Drop => (Signer::Dropped, None),
            Decision::Merge { .. } => unreachable!("merge resolved above"),
        };
        out.authors.insert(a.id.clone(), Resolved {
            canonical: cur.clone(),
            handle: target.handle.clone(),
            display_name: target.display_name.clone(),
            about: target.about.clone(),
            signer,
            live_pubkey: live,
        });
    }
    out.generate.insert(ARCHIVIST.into(), crate::keystore::Role::Archivist);
    if errs.is_empty() {
        Ok(out)
    } else {
        Err(ImportError::Plan(errs.join("\n")))
    }
}

impl IdentityPlan {
    /// Generate every key the plan needs (existing labels are kept as they
    /// are) and save the store. Returns the labels created.
    pub fn ensure_keys(&self, ks: &mut crate::keystore::Keystore) -> Result<Vec<String>, ImportError> {
        let mut created = Vec::new();
        for (label, role) in &self.generate {
            if ks.ensure(label, *role)?.1 {
                created.push(label.clone());
            }
        }
        ks.save()?;
        Ok(created)
    }

    /// Refuse keys that collide: a generated key equal to a live key in the
    /// plan (cannot happen by chance; guards hand-edited stores).
    pub fn check_keys(&self, ks: &crate::keystore::Keystore) -> Result<(), ImportError> {
        let live: BTreeSet<&str> = self.authors.values().filter_map(|r| r.live_pubkey.as_deref()).collect();
        for label in self.generate.keys() {
            if let Some(e) = ks.get(label) {
                if live.contains(e.pk.as_str()) {
                    return Err(ImportError::Refused(format!("keystore key {label:?} equals a live key in identities.json")));
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
        for (id, bot) in [("a", false), ("b", false), ("b2", false), ("bot", true), ("op", false)] {
            w.author(Author { id: id.into(), handle: id.into(), display_name: None, about: None, bot });
        }
        w.channel(Channel { id: "c".into(), name: "c".into(), topic: None, created_at: None });
        w.message(Message { id: "m".into(), channel: "c".into(), author: "a".into(), created_at: 1, text: "x".into(), reply_to: None, edited_at: None, attachments: vec![] });
        w.finish(dir).unwrap()
    }

    #[test]
    fn resolves_merges_and_refuses_bad_plans() {
        let dir = std::env::temp_dir().join(format!("bi-id-{}", std::process::id()));
        let a = archive(&dir);
        let live = "ab".repeat(32);
        let f = IdentityFile::parse(format!(r#"{{"version":1,"default":"fresh","authors":{{
            "b":{{"decision":"existing","pubkey":"{live}"}},
            "b2":{{"decision":"merge","into":"b"}},
            "bot":{{"decision":"drop"}},
            "op":{{"decision":"operator","defer":true}}}}}}"#).as_bytes()).unwrap();
        let p = plan(&a, &f).unwrap();
        assert_eq!(p.authors["b2"].canonical, "b");
        assert_eq!(p.authors["b2"].signer, Signer::Key { label: "archive:b".into(), deferred: false });
        assert_eq!(p.authors["b2"].live_pubkey.as_deref(), Some(live.as_str()));
        assert_eq!(p.authors["bot"].signer, Signer::Dropped);
        assert!(p.operator_deferred && p.needs_operator);
        assert!(p.generate.contains_key(ARCHIVIST));
        assert!(!p.generate.contains_key(OPERATOR));

        let chain = IdentityFile::parse(br#"{"version":1,"default":"fresh","authors":{"a":{"decision":"merge","into":"b"},"b":{"decision":"merge","into":"a"}}}"#).unwrap();
        assert!(plan(&a, &chain).unwrap_err().to_string().contains("no chains"));
        let req = IdentityFile::parse(br#"{"version":1,"authors":{"a":{"decision":"fresh"}}}"#).unwrap();
        assert!(plan(&a, &req).unwrap_err().to_string().contains("no decision"));
        let shared = IdentityFile::parse(format!(r#"{{"version":1,"default":"fresh","authors":{{"a":{{"decision":"existing","pubkey":"{live}"}},"b":{{"decision":"existing","pubkey":"{live}"}}}}}}"#).as_bytes()).unwrap();
        assert!(plan(&a, &shared).unwrap_err().to_string().contains("share the live key"));
        let unknown = IdentityFile::parse(br#"{"version":1,"default":"fresh","authors":{"zz":{"decision":"drop"}}}"#).unwrap();
        assert!(plan(&a, &unknown).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
