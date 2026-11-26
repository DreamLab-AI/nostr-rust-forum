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

/// Longest line accepted from any JSONL input (a hostile file cannot make
/// the reader allocate without bound).
pub const MAX_LINE: usize = 16 * 1024 * 1024;

/// Call `f(line_number, line)` for every line of `path`, refusing any line
/// longer than [`MAX_LINE`] bytes. Lines are passed without the newline;
/// invalid UTF-8 is an error.
pub fn for_each_line(
    path: &Path,
    mut f: impl FnMut(usize, &str) -> Result<(), ImportError>,
) -> Result<(), ImportError> {
    use std::io::BufRead;
    let file = std::fs::File::open(path).map_err(|e| ImportError::io(path, e))?;
    let mut r = std::io::BufReader::new(file);
    let mut buf = Vec::new();
    let mut n = 0usize;
    loop {
        buf.clear();
        let got = (&mut r)
            .take(MAX_LINE as u64 + 1)
            .read_until(b'\n', &mut buf)
            .map_err(|e| ImportError::io(path, e))?;
        if got == 0 {
            return Ok(());
        }
        n += 1;
        if buf.len() > MAX_LINE {
            return Err(ImportError::Format(format!(
                "{}:{n}: line longer than {MAX_LINE} bytes",
                path.display()
            )));
        }
        while buf.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
            buf.pop();
        }
        let line = std::str::from_utf8(&buf)
            .map_err(|_| ImportError::Format(format!("{}:{n}: not UTF-8", path.display())))?;
        f(n, line)?;
    }
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

/// Write `bytes` to a NEW 0600 file (`O_EXCL`: refuses to overwrite), fsynced.
pub fn write_new_private(path: &Path, bytes: &[u8]) -> Result<(), ImportError> {
    let mut f = open_new_private(path).map_err(|e| ImportError::io(path, e))?;
    f.write_all(bytes)
        .and_then(|_| f.sync_all())
        .map_err(|e| ImportError::io(path, e))
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

/// Read a secret file safely: opened without following a symlink, it must
/// be a regular file owned by the current user with no group or other
/// permission bits, and it is read from the same descriptor that was
/// checked. The bytes are zeroized on drop.
pub fn read_private_file(path: &Path) -> Result<zeroize::Zeroizing<Vec<u8>>, ImportError> {
    let mut o = std::fs::OpenOptions::new();
    o.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.custom_flags(libc::O_NOFOLLOW);
    }
    let mut f = o.open(path).map_err(|e| ImportError::io(path, e))?;
    let meta = f.metadata().map_err(|e| ImportError::io(path, e))?;
    if !meta.is_file() {
        return Err(ImportError::Refused(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid has no preconditions and cannot fail.
        let me = unsafe { libc::geteuid() };
        if meta.uid() != me {
            return Err(ImportError::Refused(format!(
                "{} is not owned by the current user",
                path.display()
            )));
        }
        if meta.mode() & 0o077 != 0 {
            return Err(ImportError::Refused(format!(
                "{} must be mode 0600 (is {:o})",
                path.display(),
                meta.mode() & 0o777
            )));
        }
    }
    let mut buf = zeroize::Zeroizing::new(Vec::with_capacity(meta.len() as usize));
    f.read_to_end(&mut buf)
        .map_err(|e| ImportError::io(path, e))?;
    Ok(buf)
}

/// Refuse a secret file readable by group or others (see
/// [`read_private_file`] for reading one).
pub fn require_private_file(path: &Path) -> Result<(), ImportError> {
    read_private_file(path).map(|_| ())
}

/// An exclusive lock file (`O_EXCL`), removed on drop. A stale lock after a
/// crash names itself in the error.
#[derive(Debug)]
pub struct LockFile(std::path::PathBuf);

impl LockFile {
    /// Take the lock at `path`.
    pub fn take(path: &Path) -> Result<Self, ImportError> {
        match open_new_private(path) {
            Ok(_) => Ok(LockFile(path.to_path_buf())),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                Err(ImportError::Refused(format!(
                    "{} exists: another run holds the lock (remove it only if no run is active)",
                    path.display()
                )))
            }
            Err(e) => Err(ImportError::io(path, e)),
        }
    }
}

impl Drop for LockFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
