//! The publisher (indexer) key: from [`IDENTITY_ENV`] or from a file only
//! its owner can read. Never from a command-line argument (argv lands in
//! shell history and `ps` output), and no error message echoes it.

use std::path::Path;

use nostr_bbs_core::keys::SecretKey;
pub use nostr_bbs_zone_migrate::identity::IDENTITY_ENV;
use nostr_bbs_zone_migrate::identity::{identity_from_env, parse_identity};
use zeroize::Zeroizing;

/// Why the key could not be loaded. Messages never contain the key.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KeyLoadError {
    /// Neither a key file nor [`IDENTITY_ENV`] was given.
    #[error("set {IDENTITY_ENV} or pass --key-file (a 0600 file holding the hex or nsec key)")]
    Missing,
    /// The key file is readable by its group or by others.
    #[error("key file {0} must not be readable by group or others (chmod 600)")]
    Permissions(String),
    /// The key file could not be read.
    #[error("cannot read key file {0}")]
    Unreadable(String),
    /// The key is not a valid hex or nsec secret.
    #[error("the key is not a valid 64-hex or nsec secret key")]
    Malformed,
}

/// Load the key from `file` when given (mode 0600 or stricter), else from
/// [`IDENTITY_ENV`].
///
/// # Errors
///
/// [`KeyLoadError`] when neither source yields a valid key, or the file's
/// permissions let anyone but its owner read it.
pub fn load_identity(file: Option<&Path>) -> Result<SecretKey, KeyLoadError> {
    let Some(path) = file else {
        return identity_from_env().map_err(|e| match e {
            nostr_bbs_zone_migrate::identity::IdentityError::Missing => KeyLoadError::Missing,
            _ => KeyLoadError::Malformed,
        });
    };
    let shown = path.display().to_string();
    check_owner_only(path).map_err(|()| KeyLoadError::Permissions(shown.clone()))?;
    let raw =
        Zeroizing::new(std::fs::read_to_string(path).map_err(|_| KeyLoadError::Unreadable(shown))?);
    parse_identity(&raw).map_err(|_| KeyLoadError::Malformed)
}

/// Refuse a file holding secrets (a zone-key file, say) that anyone but its
/// owner could read. `what` names it in the message.
///
/// # Errors
///
/// When the file cannot be inspected or its mode lets group or others read it.
pub fn ensure_owner_only(path: &Path, what: &str) -> Result<(), String> {
    check_owner_only(path).map_err(|()| {
        format!(
            "{what} {} must exist and not be readable by group or others (chmod 600)",
            path.display()
        )
    })
}

/// Write `bytes` to a fresh file at `path` with mode 0600 (any existing file
/// is replaced, never reused with its old mode).
///
/// # Errors
///
/// When the file cannot be written.
pub fn write_owner_only(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            return Err(format!("{}: {e}", path.display()))
        }
        _ => {}
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
        .and_then(|mut f| f.write_all(bytes))
        .map_err(|e| format!("{}: {e}", path.display()))
}

#[cfg(unix)]
fn check_owner_only(path: &Path) -> Result<(), ()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path)
        .map_err(|_| ())?
        .permissions()
        .mode();
    if mode & 0o077 == 0 {
        Ok(())
    } else {
        Err(())
    }
}

#[cfg(not(unix))]
fn check_owner_only(_path: &Path) -> Result<(), ()> {
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn a_key_file_must_be_owner_only() {
        let dir = std::env::temp_dir().join(format!("nbss-key-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("indexer.key");
        std::fs::write(&p, "7f".repeat(32)).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = load_identity(Some(&p)).err().expect("refused");
        assert!(matches!(err, KeyLoadError::Permissions(_)));
        assert!(!err.to_string().contains("7f7f"));
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(load_identity(Some(&p)).unwrap().as_bytes(), &[0x7f; 32]);
        std::fs::write(&p, "not a key").unwrap();
        assert_eq!(load_identity(Some(&p)).err(), Some(KeyLoadError::Malformed));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
