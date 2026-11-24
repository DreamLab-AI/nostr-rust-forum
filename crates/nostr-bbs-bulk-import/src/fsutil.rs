//! Private, atomic file writes and digests.
//!
//! Everything the tool writes lands in a work directory created 0700 with
//! files 0600: archives hold private chat, `keys.json` holds secrets.

use std::io::{Read, Write};
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::error::ImportError;

/// Unix seconds now.
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Lowercase hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Lowercase hex SHA-256 of a file, streamed.
pub fn sha256_file(path: &Path) -> Result<String, ImportError> {
    let mut f = std::fs::File::open(path).map_err(|e| ImportError::io(path, e))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = f.read(&mut buf).map_err(|e| ImportError::io(path, e))?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}

/// Create `dir` (and parents) with mode 0700 for the leaf.
pub fn create_private_dir(dir: &Path) -> Result<(), ImportError> {
    std::fs::create_dir_all(dir).map_err(|e| ImportError::io(dir, e))?;
    set_mode(dir, 0o700)
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), ImportError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|e| ImportError::io(path, e))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<(), ImportError> {
    Ok(())
}

fn open_new_private(path: &Path) -> std::io::Result<std::fs::File> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)
}

fn fsync_dir(dir: &Path) {
    #[cfg(unix)]
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    #[cfg(not(unix))]
    let _ = dir;
}

/// Write `bytes` to `path` atomically: a new 0600 temp file in the same
/// directory (`O_EXCL`), fsync, rename over `path`, fsync the directory.
pub fn write_private_atomic(path: &Path, bytes: &[u8]) -> Result<(), ImportError> {
    let dir = path.parent().unwrap_or(Path::new("."));
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    // Unique per process and call; O_EXCL refuses any collision anyway.
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp = dir.join(format!(".{name}.{}.{seq}.tmp", std::process::id()));
    let mut f = open_new_private(&tmp).map_err(|e| ImportError::io(&tmp, e))?;
    let res = f.write_all(bytes).and_then(|_| f.sync_all());
    drop(f);
    if let Err(e) = res {
        let _ = std::fs::remove_file(&tmp);
        return Err(ImportError::io(&tmp, e));
    }
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        ImportError::io(path, e)
    })?;
    fsync_dir(dir);
    Ok(())
}

/// Append `bytes` to `path` (created 0600) and fsync.
pub fn append_private(path: &Path, bytes: &[u8]) -> Result<(), ImportError> {
    let mut o = std::fs::OpenOptions::new();
    o.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o.open(path).map_err(|e| ImportError::io(path, e))?;
    f.write_all(bytes)
        .and_then(|_| f.sync_all())
        .map_err(|e| ImportError::io(path, e))
}

/// Copy `src` to a new 0600 file `dst` (refuses to overwrite), fsynced.
pub fn copy_private(src: &Path, dst: &Path) -> Result<(), ImportError> {
    let mut input = std::fs::File::open(src).map_err(|e| ImportError::io(src, e))?;
    let mut out = open_new_private(dst).map_err(|e| ImportError::io(dst, e))?;
    std::io::copy(&mut input, &mut out)
        .and_then(|_| out.sync_all())
        .map_err(|e| ImportError::io(dst, e))
}

/// Refuse a secret file readable by group or others.
pub fn require_private_file(path: &Path) -> Result<(), ImportError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let m = std::fs::metadata(path).map_err(|e| ImportError::io(path, e))?;
        if m.permissions().mode() & 0o077 != 0 {
            return Err(ImportError::Refused(format!(
                "{} must be mode 0600 (is {:o})",
                path.display(),
                m.permissions().mode() & 0o777
            )));
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}
