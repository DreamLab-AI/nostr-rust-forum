//! Topic titles: the reviewable mapping from source channel to the title
//! its topic shows.
//!
//! An imported topic root's content is **exactly** its title and nothing
//! else: no `#`, no "archived from …", no dates or counts. Provenance lives
//! in tags (the root's `["import", "<source>:<source_id>#root:<channel>"]`),
//! never in visible content. The forum client takes a topic's title from the
//! first non-empty line of the root's body, clipped at 90 characters
//! (`first_line` in `pages/thread.rs`, also used by `pages/section.rs`), and
//! there is no subject tag, so the root body is one line of at most
//! [`MAX_TITLE`] characters.
//!
//! `titles.json`, keyed by source channel id like `structure.json`:
//!
//! ```json
//! {"version": 1, "titles": {"<source channel id>": "Kids and shit"}}
//! ```
//!
//! [`ensure`] adds the humanised source name for every imported channel
//! that has no entry and never changes an existing one, so operator edits
//! survive re-runs. Changing a title after a build changes the root's id and
//! with it every reply's `reply` tag: run `reset` first (see
//! `docs/bulk-import/README.md`).
//!
//! ```
//! use nostr_bbs_bulk_import::titles::{check_title, humanise};
//!
//! assert_eq!(humanise("kids_and_shit"), "Kids and shit");
//! assert_eq!(humanise("A-STORM--IS_COMING"), "A STORM IS COMING");
//! assert!(check_title("c1", "Kids and shit").is_ok());
//! assert!(check_title("c1", "#kids").is_ok()); // a title may start with '#' if the operator wants it
//! assert!(check_title("c1", "two\nlines").is_err());
//! ```

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::ImportError;
use crate::format::Archive;
use crate::fsutil;
use crate::structure::Structure;

/// The longest title the client shows without clipping.
pub const MAX_TITLE: usize = 90;

/// `titles.json`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Titles {
    /// Always 1.
    pub version: u32,
    /// Source channel id → title.
    pub titles: BTreeMap<String, String>,
}

/// `kids_and_shit` → `Kids and shit`: underscores and hyphens become
/// spaces, runs of whitespace collapse, the first letter is capitalised,
/// the rest is left as it is.
pub fn humanise(name: &str) -> String {
    let spaced: String = name
        .chars()
        .map(|c| if c == '_' || c == '-' { ' ' } else { c })
        .collect();
    let t = spaced.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut cs = t.chars();
    match cs.next() {
        Some(f) => f.to_uppercase().chain(cs).collect(),
        None => t,
    }
}

/// A title must be one non-empty line, without surrounding whitespace, of
/// at most [`MAX_TITLE`] characters.
pub fn check_title(channel: &str, title: &str) -> Result<(), ImportError> {
    let bad = |why: &str| {
        Err(ImportError::Plan(format!(
            "titles.json: channel {channel:?}: {why}"
        )))
    };
    if title.trim().is_empty() {
        return bad("empty title");
    }
    if title.contains(['\n', '\r']) || title.chars().any(char::is_control) {
        return bad("a title is one line without control characters");
    }
    if title != title.trim() {
        return bad("leading or trailing whitespace");
    }
    if title.chars().count() > MAX_TITLE {
        return bad(&format!(
            "longer than {MAX_TITLE} characters (the client clips it)"
        ));
    }
    Ok(())
}

/// The default title of a channel: its humanised name, cut to
/// [`MAX_TITLE`] characters (never empty).
pub fn default_title(name: &str) -> String {
    let h = humanise(name);
    let h: String = h
        .chars()
        .take(MAX_TITLE)
        .collect::<String>()
        .trim_end()
        .to_string();
    if h.is_empty() {
        "Untitled".into()
    } else {
        h
    }
}

impl Titles {
    /// Load `titles.json`.
    pub fn load(path: &Path) -> Result<Self, ImportError> {
        let bytes = std::fs::read(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                ImportError::Refused(format!("{} does not exist: run `nostr-bbs-import titles` to create it from the source channel names", path.display()))
            } else {
                ImportError::io(path, e)
            }
        })?;
        let t: Titles = serde_json::from_slice(&bytes)
            .map_err(|e| ImportError::Format(format!("{}: {e}", path.display())))?;
        if t.version != 1 {
            return Err(ImportError::Format(format!(
                "{}: version {} unsupported",
                path.display(),
                t.version
            )));
        }
        for (c, v) in &t.titles {
            check_title(c, v)?;
        }
        Ok(t)
    }

    /// Every imported channel has a title, and no title names an unknown
    /// channel.
    pub fn validate(&self, archive: &Archive, structure: &Structure) -> Result<(), ImportError> {
        let mut errs = Vec::new();
        let names = archive.channels_by_id();
        for c in &archive.channels {
            let imported = structure.channels.get(&c.id).is_some_and(|m| !m.skip);
            if imported && !self.titles.contains_key(&c.id) {
                errs.push(format!(
                    "channel {:?} (#{}) has no title: run `nostr-bbs-import titles`",
                    c.id, c.name
                ));
            }
        }
        for id in self.titles.keys() {
            if !names.contains_key(id.as_str()) {
                errs.push(format!("titles.json names unknown channel {id:?}"));
            }
        }
        if errs.is_empty() {
            Ok(())
        } else {
            Err(ImportError::Plan(errs.join("\n")))
        }
    }

    /// The title of a channel.
    pub fn get(&self, channel: &str) -> Option<&str> {
        self.titles.get(channel).map(String::as_str)
    }
}

/// Add a default title for every imported channel without one, never
/// changing an existing entry, and save (0600, atomic) when anything was
/// added. Returns the titles and the channel ids added.
pub fn ensure(
    path: &Path,
    archive: &Archive,
    structure: &Structure,
) -> Result<(Titles, Vec<String>), ImportError> {
    let mut t = if path.exists() {
        Titles::load(path)?
    } else {
        Titles {
            version: 1,
            titles: BTreeMap::new(),
        }
    };
    let mut added = Vec::new();
    for c in &archive.channels {
        let imported = structure.channels.get(&c.id).is_some_and(|m| !m.skip);
        if imported && !t.titles.contains_key(&c.id) {
            t.titles.insert(c.id.clone(), default_title(&c.name));
            added.push(c.id.clone());
        }
    }
    if !added.is_empty() || !path.exists() {
        fsutil::write_private_atomic(
            path,
            &serde_json::to_vec_pretty(&t).expect("titles serialise"),
        )?;
    }
    Ok((t, added))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn humanise_and_check() {
        assert_eq!(humanise("casualty_bench"), "Casualty bench");
        assert_eq!(humanise("2021"), "2021");
        assert_eq!(humanise("ünïcode-name"), "Ünïcode name");
        assert_eq!(humanise("__"), "");
        assert_eq!(default_title("__"), "Untitled");
        assert_eq!(default_title(&"x".repeat(200)).chars().count(), MAX_TITLE);
        assert!(check_title("c", " padded").is_err());
        assert!(check_title("c", &"y".repeat(91)).is_err());
        assert!(check_title("c", "tab\there").is_err());
        assert!(check_title("c", &"é".repeat(90)).is_ok());
    }
}
