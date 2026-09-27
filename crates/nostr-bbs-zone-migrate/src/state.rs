//! The state file (`--state`): the durable record of one migration run.
//!
//! One entry per original (plaintext) event id, with the channel, zone,
//! status and — once sealed — the envelope id, the zone epoch used and the
//! SHA-256 of the original's canonical JSON. The digest lets `verify` prove
//! byte-for-byte equality after `purge` without the state file ever holding
//! plaintext. The file holds no secrets and no message text.
//!
//! ```json
//! {"version": 1, "relay": "wss://relay.example.org", "migrator": "<hex>",
//!  "entries": {"<original id>": {"channel": "<hex>", "zone": "zone3",
//!    "created_at": 1700000000, "status": "sealed", "epoch": 2,
//!    "outer_id": "<hex>", "inner_sha256": "<hex>"}}}
//! ```
//!
//! A failed entry carries `"status": "failed", "step": "seal"|"verify"|"purge",
//! "reason": "…"`.
//!
//! Writes are atomic ([`save_atomic`]): the JSON goes to a sibling temporary
//! file, is flushed to disk, and is renamed over the target, so an
//! interrupted run never leaves a truncated state file.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// The only state-file `version` this build reads and writes.
pub const STATE_VERSION: u32 = 1;

/// The migration step that produced a `failed` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Step {
    /// Building, publishing or reading back the envelope.
    Seal,
    /// Re-fetching and re-opening the envelope.
    Verify,
    /// Deleting the plaintext row.
    Purge,
}

/// Where an original stands. See the runbook's *Entry states* table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum Status {
    /// Plaintext found; no envelope yet.
    Planned,
    /// Envelope accepted, read back, opened, and equal to the original.
    Sealed,
    /// `verify` re-fetched and re-opened the envelope. The only state
    /// `purge` deletes from.
    Verified,
    /// The plaintext row has been deleted from the relay.
    Purged,
    /// A step failed; the plaintext is untouched.
    Failed {
        /// Which step failed.
        step: Step,
        /// Why, in words safe to log.
        reason: String,
    },
}

impl Status {
    /// Short label: `planned`, `sealed`, `verified`, `purged` or `failed`.
    pub fn label(&self) -> &'static str {
        match self {
            Status::Planned => "planned",
            Status::Sealed => "sealed",
            Status::Verified => "verified",
            Status::Purged => "purged",
            Status::Failed { .. } => "failed",
        }
    }
}

/// One original event's record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// Channel id the original belongs to.
    pub channel: String,
    /// Zone from the channels file.
    pub zone: String,
    /// The original's `created_at` (also the envelope's).
    pub created_at: u64,
    /// Current status.
    #[serde(flatten)]
    pub status: Status,
    /// Zone key epoch the envelope was sealed to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u32>,
    /// Envelope (outer event) id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outer_id: Option<String>,
    /// Lowercase hex SHA-256 of the original's canonical JSON (the exact
    /// bytes sealed inside the envelope).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inner_sha256: Option<String>,
}

impl Entry {
    /// A fresh `planned` entry.
    pub fn planned(channel: &str, zone: &str, created_at: u64) -> Self {
        Self {
            channel: channel.to_string(),
            zone: zone.to_string(),
            created_at,
            status: Status::Planned,
            epoch: None,
            outer_id: None,
            inner_sha256: None,
        }
    }
}

/// The whole state file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    /// Format version, [`STATE_VERSION`].
    pub version: u32,
    /// Relay URL the run targets. Every later step must use the same relay.
    pub relay: String,
    /// Migrator pubkey (hex). Every later step must use the same key.
    pub migrator: String,
    /// Entries keyed by original event id.
    pub entries: BTreeMap<String, Entry>,
}

/// Why a state file could not be used.
#[derive(Debug, Error)]
pub enum StateError {
    /// Reading or writing the file failed.
    #[error("state file {path}: {source}")]
    Io {
        /// The file.
        path: PathBuf,
        /// Underlying error.
        source: std::io::Error,
    },
    /// The file is not a valid state file.
    #[error("state file {path} is not valid: {why}")]
    Invalid {
        /// The file.
        path: PathBuf,
        /// What is wrong.
        why: String,
    },
    /// The state file belongs to a different relay or migrator key.
    #[error("state file was written for {field} {recorded}, not {given}; use the same {field} throughout a run")]
    Mismatch {
        /// `relay` or `migrator`.
        field: &'static str,
        /// Value in the file.
        recorded: String,
        /// Value given now.
        given: String,
    },
}

/// Counts by status, for `status` and every step's summary.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Counts {
    /// Entries in total.
    pub total: usize,
    /// `planned` entries.
    pub planned: usize,
    /// `sealed` entries.
    pub sealed: usize,
    /// `verified` entries.
    pub verified: usize,
    /// `purged` entries.
    pub purged: usize,
    /// `failed` entries.
    pub failed: usize,
}

impl State {
    /// An empty state for `relay` and `migrator`.
    pub fn new(relay: &str, migrator: &str) -> Self {
        Self {
            version: STATE_VERSION,
            relay: relay.to_string(),
            migrator: migrator.to_string(),
            entries: BTreeMap::new(),
        }
    }

    /// Refuse to continue a run with a different relay or key.
    pub fn check_matches(&self, relay: &str, migrator: &str) -> Result<(), StateError> {
        if self.relay != relay {
            return Err(StateError::Mismatch {
                field: "relay",
                recorded: self.relay.clone(),
                given: relay.to_string(),
            });
        }
        if !self.migrator.eq_ignore_ascii_case(migrator) {
            return Err(StateError::Mismatch {
                field: "migrator",
                recorded: self.migrator.clone(),
                given: migrator.to_string(),
            });
        }
        Ok(())
    }

    /// Counts by status.
    pub fn counts(&self) -> Counts {
        let mut c = Counts {
            total: self.entries.len(),
            ..Counts::default()
        };
        for e in self.entries.values() {
            match e.status {
                Status::Planned => c.planned += 1,
                Status::Sealed => c.sealed += 1,
                Status::Verified => c.verified += 1,
                Status::Purged => c.purged += 1,
                Status::Failed { .. } => c.failed += 1,
            }
        }
        c
    }

    /// Parse a state file's contents.
    pub fn from_json(json: &str, path: &Path) -> Result<Self, StateError> {
        let state: State = serde_json::from_str(json).map_err(|e| StateError::Invalid {
            path: path.to_path_buf(),
            why: e.to_string(),
        })?;
        if state.version != STATE_VERSION {
            return Err(StateError::Invalid {
                path: path.to_path_buf(),
                why: format!("version {} is not supported", state.version),
            });
        }
        Ok(state)
    }
}

/// Load a state file; `Ok(None)` if it does not exist yet.
pub fn load(path: &Path) -> Result<Option<State>, StateError> {
    match std::fs::read_to_string(path) {
        Ok(json) => State::from_json(&json, path).map(Some),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(StateError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// Write `state` to `path` atomically: write and fsync a sibling temporary
/// file, then rename it over `path`.
pub fn save_atomic(path: &Path, state: &State) -> Result<(), StateError> {
    let io = |source| StateError::Io {
        path: path.to_path_buf(),
        source,
    };
    let json = serde_json::to_vec_pretty(state).map_err(|e| StateError::Invalid {
        path: path.to_path_buf(),
        why: e.to_string(),
    })?;
    let mut tmp_name = path.file_name().unwrap_or_default().to_os_string();
    tmp_name.push(".tmp");
    let tmp = path.with_file_name(tmp_name);
    {
        let mut f = std::fs::File::create(&tmp).map_err(io)?;
        f.write_all(&json).map_err(io)?;
        f.write_all(b"\n").map_err(io)?;
        f.sync_all().map_err(io)?;
    }
    std::fs::rename(&tmp, path).map_err(io)
}

/// Lowercase hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> State {
        let mut s = State::new("wss://relay.example.org", &"a".repeat(64));
        s.entries
            .insert("1".repeat(64), Entry::planned(&"c".repeat(64), "zone3", 10));
        let mut sealed = Entry::planned(&"c".repeat(64), "zone3", 11);
        sealed.status = Status::Sealed;
        sealed.epoch = Some(2);
        sealed.outer_id = Some("9".repeat(64));
        sealed.inner_sha256 = Some(sha256_hex(b"x"));
        s.entries.insert("2".repeat(64), sealed);
        let mut failed = Entry::planned(&"d".repeat(64), "zone4", 12);
        failed.status = Status::Failed {
            step: Step::Seal,
            reason: "blocked: sealed originals are admin-only".into(),
        };
        s.entries.insert("3".repeat(64), failed);
        s
    }

    #[test]
    fn json_round_trip_and_wire_shape() {
        let s = sample();
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains(r#""status":"planned""#));
        assert!(json.contains(r#""status":"failed","step":"seal","reason":"blocked"#));
        assert!(!json.contains("outer_id\":null"));
        let back = State::from_json(&json, Path::new("s.json")).unwrap();
        assert_eq!(back, s);
        assert_eq!(
            back.counts(),
            Counts {
                total: 3,
                planned: 1,
                sealed: 1,
                failed: 1,
                ..Counts::default()
            }
        );
    }

    #[test]
    fn atomic_save_then_load_round_trips_and_leaves_no_temp_file() {
        let dir = std::env::temp_dir().join(format!(
            "zone-migrate-state-{}-{}",
            std::process::id(),
            line!()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json");
        assert!(load(&path).unwrap().is_none());
        let s = sample();
        save_atomic(&path, &s).unwrap();
        save_atomic(&path, &s).unwrap();
        assert_eq!(load(&path).unwrap().unwrap(), s);
        assert!(!dir.join("state.json.tmp").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn refuses_other_versions_and_mismatched_runs() {
        let mut s = sample();
        s.version = 2;
        let json = serde_json::to_string(&s).unwrap();
        assert!(matches!(
            State::from_json(&json, Path::new("s")).unwrap_err(),
            StateError::Invalid { .. }
        ));
        let s = sample();
        assert!(s
            .check_matches("wss://relay.example.org", &"A".repeat(64))
            .is_ok());
        assert!(matches!(
            s.check_matches("wss://other", &"a".repeat(64)).unwrap_err(),
            StateError::Mismatch { field: "relay", .. }
        ));
        assert!(matches!(
            s.check_matches("wss://relay.example.org", &"b".repeat(64))
                .unwrap_err(),
            StateError::Mismatch {
                field: "migrator",
                ..
            }
        ));
    }
}
