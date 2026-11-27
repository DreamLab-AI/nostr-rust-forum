//! Where sealed objects and manifests live: a publisher's pod folder
//! `pods/<pubkey>/media/zones/<zone>/search/<name>` (sealed-search design
//! §5), reached over NIP-98 HTTP ([`HttpPod`]), a directory laid out the same
//! way for local runs ([`DirPod`]), or a dry run that reads through and
//! writes to a local folder instead ([`DryRun`]).
//!
//! Reads may name any publisher's pod (an update lists objects another
//! trusted publisher holds); writes and deletes only ever go to this
//! publisher's own pod, as the pod gate requires.

use std::path::{Path, PathBuf};

use nostr_bbs_core::keys::SecretKey;
use nostr_bbs_sealed_search::manifest::valid_object_name;
use nostr_bbs_sealed_search::search::sha256_hex;

/// Media type of a sealed object.
pub const OCTET: &str = "application/octet-stream";
/// Media type of `m.json`.
pub const JSON: &str = "application/json";

/// A publisher's view of the zone's search folders.
// Futures are awaited on a single-threaded runtime; no Send bound needed.
#[allow(async_fn_in_trait)]
pub trait Pod {
    /// GET `name` from `owner`'s search folder: `Ok(None)` when it is not
    /// there (404).
    async fn get(&mut self, owner: &str, name: &str) -> Result<Option<Vec<u8>>, String>;
    /// PUT `name` into this publisher's own search folder.
    async fn put(&mut self, name: &str, bytes: &[u8], content_type: &str) -> Result<(), String>;
    /// DELETE `name` from this publisher's own search folder.
    async fn delete(&mut self, name: &str) -> Result<(), String>;
}

fn check_name(owner: &str, name: &str) -> Result<(), String> {
    let hex64 = owner.len() == 64 && owner.bytes().all(|b| b.is_ascii_hexdigit());
    if hex64 && valid_object_name(name) {
        Ok(())
    } else {
        Err(format!(
            "refusing an unexpected search object path {owner}/{name}"
        ))
    }
}

/// The pod over HTTP, every request NIP-98 signed by the publisher.
pub struct HttpPod {
    base: String,
    zone: String,
    sk: SecretKey,
    me: String,
    http: reqwest::Client,
}

impl HttpPod {
    /// A pod at `base` (such as `https://pods.example.org`) for `zone`,
    /// acting as `sk`.
    pub fn new(base: &str, zone: &str, sk: &SecretKey) -> Result<Self, String> {
        Ok(Self {
            base: base.trim_end_matches('/').to_string(),
            zone: zone.to_string(),
            sk: SecretKey::from_bytes(*sk.as_bytes()).map_err(|_| "invalid key".to_string())?,
            me: sk.public_key().to_hex(),
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(120))
                .build()
                .map_err(|e| e.to_string())?,
        })
    }

    fn url(&self, owner: &str, name: &str) -> String {
        format!(
            "{}/pods/{owner}/media/zones/{}/search/{name}",
            self.base, self.zone
        )
    }

    async fn send(
        &self,
        method: reqwest::Method,
        url: &str,
        body: Option<(&[u8], &str)>,
    ) -> Result<reqwest::Response, String> {
        let token = nostr_bbs_core::nip98::create_token(
            self.sk.as_bytes(),
            url,
            method.as_str(),
            body.map(|(b, _)| b),
        )
        .map_err(|e| format!("NIP-98 token: {e}"))?;
        let mut r = self
            .http
            .request(method, url)
            .header("Authorization", format!("Nostr {token}"));
        if let Some((b, ct)) = body {
            r = r.header("Content-Type", ct).body(b.to_vec());
        }
        r.send()
            .await
            .map_err(|e| format!("pod request failed: {e}"))
    }
}

impl Pod for HttpPod {
    async fn get(&mut self, owner: &str, name: &str) -> Result<Option<Vec<u8>>, String> {
        check_name(owner, name)?;
        let url = self.url(owner, name);
        let r = self.send(reqwest::Method::GET, &url, None).await?;
        match r.status().as_u16() {
            200..=299 => Ok(Some(
                r.bytes()
                    .await
                    .map_err(|e| format!("GET {name}: {e}"))?
                    .to_vec(),
            )),
            404 => Ok(None),
            s => Err(format!("GET {name} from {}: HTTP {s}", &owner[..8])),
        }
    }

    async fn put(&mut self, name: &str, bytes: &[u8], content_type: &str) -> Result<(), String> {
        check_name(&self.me, name)?;
        let url = self.url(&self.me, name);
        let r = self
            .send(reqwest::Method::PUT, &url, Some((bytes, content_type)))
            .await?;
        if r.status().is_success() {
            Ok(())
        } else {
            Err(format!("PUT {name}: HTTP {}", r.status()))
        }
    }

    async fn delete(&mut self, name: &str) -> Result<(), String> {
        check_name(&self.me, name)?;
        let url = self.url(&self.me, name);
        let r = self.send(reqwest::Method::DELETE, &url, None).await?;
        match r.status().as_u16() {
            200..=299 | 404 => Ok(()),
            s => Err(format!("DELETE {name}: HTTP {s}")),
        }
    }
}

/// Write `bytes` to `path` through a temporary file and a rename, so a
/// reader never sees half a file.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let dir = path.parent().ok_or("path has no parent")?;
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    std::fs::write(&tmp, bytes).map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))
}

/// A directory laid out as the pods are
/// (`<root>/pods/<owner>/media/zones/<zone>/search/<name>`), for local runs
/// and tests. Writes go to this publisher's folder only.
pub struct DirPod {
    root: PathBuf,
    zone: String,
    me: String,
}

impl DirPod {
    /// A directory pod at `root` for `zone`, acting as `me` (hex pubkey).
    pub fn new(root: &Path, zone: &str, me: &str) -> Self {
        Self {
            root: root.to_path_buf(),
            zone: zone.to_string(),
            me: me.to_lowercase(),
        }
    }

    /// Path of `name` in `owner`'s folder.
    pub fn path(&self, owner: &str, name: &str) -> PathBuf {
        self.root
            .join("pods")
            .join(owner)
            .join("media/zones")
            .join(&self.zone)
            .join("search")
            .join(name)
    }
}

impl Pod for DirPod {
    async fn get(&mut self, owner: &str, name: &str) -> Result<Option<Vec<u8>>, String> {
        check_name(owner, name)?;
        match std::fs::read(self.path(owner, name)) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("{name}: {e}")),
        }
    }

    async fn put(&mut self, name: &str, bytes: &[u8], _content_type: &str) -> Result<(), String> {
        check_name(&self.me, name)?;
        write_atomic(&self.path(&self.me, name), bytes)
    }

    async fn delete(&mut self, name: &str) -> Result<(), String> {
        check_name(&self.me, name)?;
        match std::fs::remove_file(self.path(&self.me, name)) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(format!("{name}: {e}")),
            _ => Ok(()),
        }
    }
}

/// A dry run: reads go to the real pod; writes land in `out` (flat, by
/// name) and deletes are only counted.
pub struct DryRun<P> {
    inner: P,
    out: PathBuf,
    /// Names a real run would have deleted.
    pub would_delete: Vec<String>,
}

impl<P> DryRun<P> {
    /// Read through `inner`, write to `out`.
    pub fn new(inner: P, out: &Path) -> Self {
        Self {
            inner,
            out: out.to_path_buf(),
            would_delete: Vec::new(),
        }
    }
}

impl<P: Pod> Pod for DryRun<P> {
    async fn get(&mut self, owner: &str, name: &str) -> Result<Option<Vec<u8>>, String> {
        self.inner.get(owner, name).await
    }

    async fn put(&mut self, name: &str, bytes: &[u8], _content_type: &str) -> Result<(), String> {
        if !valid_object_name(name) {
            return Err(format!("refusing an unexpected object name {name}"));
        }
        write_atomic(&self.out.join(name), bytes)
    }

    async fn delete(&mut self, name: &str) -> Result<(), String> {
        self.would_delete.push(name.to_string());
        Ok(())
    }
}

/// Sealed objects already downloaded, keyed by the SHA-256 of their bytes
/// (ciphertext only: the same bytes the pod serves).
pub struct ObjectCache {
    dir: PathBuf,
}

impl ObjectCache {
    /// A cache in `dir` (created on first write).
    pub fn new(dir: &Path) -> Self {
        Self {
            dir: dir.to_path_buf(),
        }
    }

    fn path(&self, sha256: &str) -> Option<PathBuf> {
        (sha256.len() == 64 && sha256.bytes().all(|b| b.is_ascii_hexdigit()))
            .then(|| self.dir.join(sha256.to_lowercase()))
    }

    /// The cached bytes whose hash is `sha256`, if held and intact.
    pub fn get(&self, sha256: &str) -> Option<Vec<u8>> {
        let b = std::fs::read(self.path(sha256)?).ok()?;
        (sha256_hex(&b) == sha256.to_lowercase()).then_some(b)
    }

    /// Keep `bytes` (whose hash the caller checked is `sha256`).
    pub fn put(&self, sha256: &str, bytes: &[u8]) -> Result<(), String> {
        let p = self.path(sha256).ok_or("bad sha256")?;
        write_atomic(&p, bytes)
    }

    /// Drop every entry not named in `keep`.
    pub fn retain(&self, keep: &std::collections::HashSet<String>) {
        let Ok(rd) = std::fs::read_dir(&self.dir) else {
            return;
        };
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if name.len() == 64 && !keep.contains(&name) {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
}
