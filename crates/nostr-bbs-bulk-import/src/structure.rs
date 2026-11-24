//! Structure mapping: source channel → forum thread (kind-40 channel) in a
//! zone, one topic per source channel.
//!
//! `structure.json`:
//!
//! ```json
//! {
//!   "version": 1,
//!   "zones": [{"id": "zone2", "cohorts": ["zone2", "minimoonoir"], "encrypted": true}],
//!   "threads": {
//!     "rants":  {"zone": "zone2", "section": "zone2-rants", "channel": {"existing": "<kind-40 id>"}},
//!     "photos": {"zone": "zone2", "section": "zone2-photos", "channel": {"new": {"name": "Photos", "about": "Archived photos"}}}
//!   },
//!   "channels": {
//!     "<source channel id>": {"thread": "rants"},
//!     "<another id>":        {"thread": "rants", "topic": "economics"},
//!     "<ignored id>":        {"skip": true}
//!   }
//! }
//! ```
//!
//! Rules checked by [`Structure::validate`]:
//!
//! - every archive channel has an entry (`skip` to leave one out);
//! - a thread's `section` equals its zone id or starts with `<zone id>-`,
//!   and no earlier zone in `zones` (list them in the deployment's config
//!   order) captures it: the forum client routes a kind-40 by that prefix
//!   ([`section_to_zone`]) and silently drops anything else into the FIRST
//!   zone;
//! - zone ids are `[a-z0-9-]`, cohorts are non-empty and never `agent`
//!   (zone-key grants skip agent keys, and the archivist must receive one);
//! - an existing thread id is 64 lowercase hex.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::error::ImportError;
use crate::format::Archive;

/// A zone the import writes into (a subset of the deployment's zone config).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Zone {
    /// Zone id (`zone2`).
    pub id: String,
    /// Cohorts members need: every imported identity receives all of them.
    pub cohorts: Vec<String>,
    /// Whether the zone is encrypted (its history is sealed after the build).
    #[serde(default)]
    pub encrypted: bool,
}

/// Where a thread's kind-40 comes from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ThreadChannel {
    /// A kind-40 already stored in the target D1 (id, 64 hex).
    Existing(String),
    /// A kind-40 the build signs with the archivist key.
    New {
        /// Channel name.
        name: String,
        /// Channel description.
        #[serde(default)]
        about: String,
    },
}

/// A forum thread (kind-40 channel) in a zone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Thread {
    /// [`Zone::id`].
    pub zone: String,
    /// The kind-40 `section` tag value: `<zone id>` or `<zone id>-<slug>`.
    pub section: String,
    /// Existing or new kind-40.
    pub channel: ThreadChannel,
}

/// One source channel's placement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ChannelMap {
    /// Thread key in [`Structure::threads`].
    #[serde(default)]
    pub thread: Option<String>,
    /// Topic title (default: the source channel name).
    #[serde(default)]
    pub topic: Option<String>,
    /// Leave this channel out.
    #[serde(default)]
    pub skip: bool,
}

/// `structure.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Structure {
    /// Always 1.
    pub version: u32,
    /// Zones written into.
    pub zones: Vec<Zone>,
    /// Thread key → thread.
    pub threads: BTreeMap<String, Thread>,
    /// Source channel id → placement.
    pub channels: BTreeMap<String, ChannelMap>,
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_slug(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// The zone the forum client routes a kind-40 `section` to, given the
/// deployment's zones in config order: a mirror of `section_to_zone` in
/// `crates/nostr-bbs-forum-client/src/stores/zones.rs` (case-insensitive
/// exact id, else the FIRST zone whose `<id>-` prefixes the section, else
/// the first zone as a catch-all).
pub fn section_to_zone<'a>(section: &str, zone_ids: &[&'a str]) -> Option<&'a str> {
    let sec = section.to_lowercase();
    if let Some(z) = zone_ids.iter().find(|z| z.to_lowercase() == sec) {
        return Some(z);
    }
    if let Some(z) = zone_ids
        .iter()
        .find(|z| sec.starts_with(&format!("{}-", z.to_lowercase())))
    {
        return Some(z);
    }
    zone_ids.first().copied()
}

/// Whether `section` routes to `zone` by itself (exact id or `<id>-…`),
/// not through the catch-all.
pub fn section_routes_to(section: &str, zone: &str) -> bool {
    let (sec, z) = (section.to_lowercase(), zone.to_lowercase());
    sec == z
        || sec
            .strip_prefix(&z)
            .is_some_and(|rest| rest.starts_with('-') && rest.len() > 1)
}

impl Structure {
    /// Parse `structure.json` (validated separately against an archive).
    pub fn parse(bytes: &[u8]) -> Result<Self, ImportError> {
        let s: Structure = serde_json::from_slice(bytes)
            .map_err(|e| ImportError::Format(format!("structure.json: {e}")))?;
        if s.version != 1 {
            return Err(ImportError::Format(format!(
                "structure.json version {} unsupported",
                s.version
            )));
        }
        Ok(s)
    }

    /// A template mapping every channel of `archive` to one new thread per
    /// channel in `zone`, for the operator to edit.
    pub fn template(archive: &Archive, zone: &str) -> Self {
        let mut threads = BTreeMap::new();
        let mut channels = BTreeMap::new();
        for c in &archive.channels {
            let slug: String = c
                .name
                .to_lowercase()
                .chars()
                .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
                .collect::<String>()
                .split('-')
                .filter(|p| !p.is_empty())
                .collect::<Vec<_>>()
                .join("-");
            let slug = if slug.is_empty() {
                "general".to_string()
            } else {
                slug
            };
            let mut key = slug.clone();
            let mut n = 2;
            while threads.contains_key(&key) {
                key = format!("{slug}-{n}");
                n += 1;
            }
            threads.insert(
                key.clone(),
                Thread {
                    zone: zone.into(),
                    section: format!("{zone}-{key}"),
                    channel: ThreadChannel::New {
                        name: c.name.clone(),
                        about: c.topic.clone().unwrap_or_default(),
                    },
                },
            );
            channels.insert(
                c.id.clone(),
                ChannelMap {
                    thread: Some(key),
                    topic: None,
                    skip: false,
                },
            );
        }
        Structure {
            version: 1,
            zones: vec![Zone {
                id: zone.into(),
                cohorts: vec![zone.into()],
                encrypted: false,
            }],
            threads,
            channels,
        }
    }

    /// Check the structure against `archive` (see the module docs). Every
    /// problem is listed.
    pub fn validate(&self, archive: &Archive) -> Result<(), ImportError> {
        let mut errs = Vec::new();
        let mut zone_ids = BTreeSet::new();
        for z in &self.zones {
            if !is_slug(&z.id) {
                errs.push(format!("zone id {:?} must be [a-z0-9-]+", z.id));
            }
            if !zone_ids.insert(z.id.as_str()) {
                errs.push(format!("zone {:?} listed twice", z.id));
            }
            if z.cohorts.is_empty() {
                errs.push(format!("zone {:?} has no cohorts", z.id));
            }
            if z.cohorts.iter().any(|c| c == "agent") {
                errs.push(format!(
                    "zone {:?}: the agent cohort is never granted (grants skip agent keys)",
                    z.id
                ));
            }
        }
        let mut existing = BTreeSet::new();
        let mut sections = BTreeMap::new();
        for (key, t) in &self.threads {
            if !zone_ids.contains(t.zone.as_str()) {
                errs.push(format!("thread {key:?}: unknown zone {:?}", t.zone));
            }
            let order: Vec<&str> = self.zones.iter().map(|z| z.id.as_str()).collect();
            if section_routes_to(&t.section, &t.zone)
                && section_to_zone(&t.section, &order) != Some(t.zone.as_str())
            {
                errs.push(format!(
                    "thread {key:?}: section {:?} is captured by an earlier zone {:?} in config order",
                    t.section,
                    section_to_zone(&t.section, &order).unwrap_or("")
                ));
            }
            if !section_routes_to(&t.section, &t.zone) {
                errs.push(format!(
                    "thread {key:?}: section {:?} does not route to zone {:?} (must be \"{0}\" or \"{0}-…\"; anything else lands in the first zone)",
                    t.section, t.zone
                ));
            }
            if let Some(other) = sections.insert(t.section.as_str(), key.as_str()) {
                if matches!(t.channel, ThreadChannel::New { .. }) {
                    errs.push(format!(
                        "threads {other:?} and {key:?} both create section {:?}",
                        t.section
                    ));
                }
            }
            match &t.channel {
                ThreadChannel::Existing(id) => {
                    if !is_hex64(id) {
                        errs.push(format!(
                            "thread {key:?}: existing id must be 64 lowercase hex"
                        ));
                    } else if !existing.insert(id.clone()) {
                        errs.push(format!("thread {key:?}: existing id used by two threads"));
                    }
                }
                ThreadChannel::New { name, .. } => {
                    if name.trim().is_empty() {
                        errs.push(format!("thread {key:?}: new channel needs a name"));
                    }
                }
            }
        }
        for c in &archive.channels {
            match self.channels.get(&c.id) {
                None => errs.push(format!(
                    "channel {:?} (#{}) has no entry (map it or set \"skip\": true)",
                    c.id, c.name
                )),
                Some(m) if m.skip => {}
                Some(m) => match &m.thread {
                    None => errs.push(format!("channel {:?} (#{}): no thread", c.id, c.name)),
                    Some(t) if !self.threads.contains_key(t) => errs.push(format!(
                        "channel {:?} (#{}): unknown thread {t:?}",
                        c.id, c.name
                    )),
                    Some(_) => {}
                },
            }
        }
        let ids: BTreeSet<&str> = archive.channels.iter().map(|c| c.id.as_str()).collect();
        for id in self.channels.keys() {
            if !ids.contains(id.as_str()) {
                errs.push(format!("structure.json maps unknown channel {id:?}"));
            }
        }
        if errs.is_empty() {
            Ok(())
        } else {
            Err(ImportError::Plan(errs.join("\n")))
        }
    }

    /// The zone of a thread.
    pub fn zone_of(&self, thread: &str) -> Option<&Zone> {
        let t = self.threads.get(thread)?;
        self.zones.iter().find(|z| z.id == t.zone)
    }

    /// Union of the cohorts of every zone (what imported members receive).
    pub fn member_cohorts(&self) -> Vec<String> {
        let set: BTreeSet<&str> = self
            .zones
            .iter()
            .flat_map(|z| z.cohorts.iter().map(String::as_str))
            .collect();
        set.into_iter().map(str::to_string).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn section_rule() {
        assert!(section_routes_to("zone2", "zone2"));
        assert!(section_routes_to("zone2-rants", "zone2"));
        assert!(!section_routes_to("zone2-", "zone2"));
        assert!(!section_routes_to("zone22-rants", "zone2"));
        assert!(!section_routes_to("minimoonoir-rants", "zone2"));
        assert_eq!(section_to_zone("a-b-c", &["a", "a-b"]), Some("a"));
        assert_eq!(
            section_to_zone("Zone2-X", &["zone1", "zone2"]),
            Some("zone2")
        );
        assert_eq!(section_to_zone("stray", &["zone1", "zone2"]), Some("zone1"));
    }
}
