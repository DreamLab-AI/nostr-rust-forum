//! The job's state file: how far the relay has been read, what this
//! publisher last published, and its objects waiting out a grace period
//! before deletion. It holds no secret and no plaintext; it is written with
//! mode 0600 through a temporary file and a rename.

use std::path::Path;

use serde::{Deserialize, Serialize};

/// State file format version.
pub const STATE_VERSION: u32 = 1;

/// The state of one zone's index job.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    /// Format version ([`STATE_VERSION`]).
    pub v: u32,
    /// Zone id.
    pub zone: String,
    /// The deployment's relay URL as bound into manifests.
    pub relay_url: String,
    /// Hex pubkey of the publisher running the job.
    pub publisher: String,
    /// Newest `created_at` (seconds) whose posts are all in the index: the
    /// next update reads from here, less an overlap.
    pub high_water: Option<u64>,
    /// Index version this job last published (rollback check: a pod showing
    /// an older newest manifest is refused).
    pub index_version: Option<u64>,
    /// Event id of that manifest.
    pub event_id: Option<String>,
    /// This publisher's objects that its last manifest stopped listing. They
    /// are deleted by the next run, so a browser that read the previous
    /// manifest can still finish loading it.
    pub retired: Vec<String>,
    /// When the state was last written (Unix seconds).
    pub updated_at: u64,
}

impl State {
    /// A fresh state for a zone, relay and publisher.
    pub fn new(zone: &str, relay_url: &str, publisher: &str) -> Self {
        Self {
            v: STATE_VERSION,
            zone: zone.to_string(),
            relay_url: relay_url.to_string(),
            publisher: publisher.to_lowercase(),
            ..Self::default()
        }
    }

    /// Read `path`, or a fresh state when it does not exist.
    ///
    /// # Errors
    ///
    /// When the file exists but cannot be read or parsed, or belongs to
    /// another zone, relay or publisher.
    pub fn load_or_new(
        path: &Path,
        zone: &str,
        relay_url: &str,
        publisher: &str,
    ) -> Result<Self, String> {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::new(zone, relay_url, publisher))
            }
            Err(e) => return Err(format!("state file {}: {e}", path.display())),
        };
        let s: Self = serde_json::from_str(&text)
            .map_err(|e| format!("state file {} is malformed: {e}", path.display()))?;
        if s.v != STATE_VERSION {
            return Err(format!("state file {} has version {}", path.display(), s.v));
        }
        if s.zone != zone
            || s.relay_url != relay_url
            || !s.publisher.eq_ignore_ascii_case(publisher)
        {
            return Err(format!(
                "state file {} belongs to another zone, relay or publisher",
                path.display()
            ));
        }
        Ok(s)
    }

    /// Write the state to `path` (mode 0600, atomically).
    ///
    /// # Errors
    ///
    /// When the file cannot be written.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        let json = serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?;
        let dir = path.parent().unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
        write_private(&tmp, &json)?;
        std::fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))
    }
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    f.write_all(bytes)
        .map_err(|e| format!("{}: {e}", path.display()))
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    std::fs::write(path, bytes).map_err(|e| format!("{}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_roundtrips_and_refuses_another_scope() {
        let dir = std::env::temp_dir().join(format!("nbss-state-{}", std::process::id()));
        let p = dir.join("zone2.json");
        let mut s = State::load_or_new(&p, "zone2", "wss://r", &"ab".repeat(32)).unwrap();
        assert_eq!(s.high_water, None);
        s.high_water = Some(1_700_000_000);
        s.index_version = Some(4);
        s.retired = vec!["b-1-3-v3.age".into()];
        s.save(&p).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&p).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let back = State::load_or_new(&p, "zone2", "wss://r", &"AB".repeat(32)).unwrap();
        assert_eq!(back, s);
        assert!(State::load_or_new(&p, "zone3", "wss://r", &"ab".repeat(32)).is_err());
        assert!(State::load_or_new(&p, "zone2", "wss://x", &"ab".repeat(32)).is_err());
        assert!(State::load_or_new(&p, "zone2", "wss://r", &"cd".repeat(32)).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_leftover_temp_file_cannot_widen_the_state_files_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("nbss-state-tmp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("zone2.json");
        let tmp = p.with_extension(format!("tmp-{}", std::process::id()));
        std::fs::write(&tmp, "stale").unwrap();
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644)).unwrap();
        State::new("zone2", "wss://r", &"ab".repeat(32))
            .save(&p)
            .unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
