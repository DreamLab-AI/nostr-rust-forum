//! The keystore: `keys.json`, the only file holding secrets.
//!
//! ```json
//! {"version":1,"keys":{"author:alice":{"pk":"<hex>","sk":"<hex>","role":"fresh","created_at":1700000000}}}
//! ```
//!
//! Rules (all enforced by [`Keystore::save`]):
//!
//! - written atomically (temp file `O_EXCL` 0600 in the same directory,
//!   fsync, rename, fsync of the directory), directory 0700;
//! - **refuse-to-change**: a save that would remove a label or change any
//!   label's `pk` or `sk` writes nothing and fails, so a re-run can never
//!   replace a key someone already holds a recovery sheet for;
//! - keys come from [`nostr_bbs_core::keys::generate_keypair`] (OS RNG) or
//!   from [`Keystore::import`] (a 0600 file); secrets live in
//!   [`Zeroizing`] buffers and are never formatted into logs or errors.
//!
//! The format is private to this kit (not a reusable key format).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use nostr_bbs_core::keys::SecretKey;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::ImportError;
use crate::fsutil;

/// What a key is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// A new forum identity for a source author (gets a recovery sheet).
    Fresh,
    /// Signs the imported history of a person who keeps a live key; linked
    /// to it by a profile successor. Never whitelisted.
    Archive,
    /// Signs topic roots, new thread headers and the seals; admin.
    Archivist,
    /// The operator's key, imported (never generated here).
    Operator,
}

/// One key. `sk` is zeroized on drop.
#[derive(Clone)]
pub struct KeyEntry {
    /// Public key, lowercase hex.
    pub pk: String,
    sk: Zeroizing<String>,
    /// What the key is for.
    pub role: Role,
    /// Unix seconds the key entered the store.
    pub created_at: u64,
}

impl std::fmt::Debug for KeyEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyEntry")
            .field("pk", &self.pk)
            .field("sk", &"<redacted>")
            .field("role", &self.role)
            .finish()
    }
}

impl KeyEntry {
    /// The signing key.
    pub fn secret(&self) -> Result<SecretKey, ImportError> {
        parse_secret(&self.sk)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EntryFile {
    pk: String,
    sk: String,
    role: Role,
    created_at: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoreFile {
    version: u32,
    keys: BTreeMap<String, EntryFile>,
}

/// Parse a secret key given as 64 hex or `nsec1…`.
pub fn parse_secret(text: &str) -> Result<SecretKey, ImportError> {
    let t = text.trim();
    let hexsk: Zeroizing<String> = if t.starts_with("nsec1") {
        Zeroizing::new(
            nostr_bbs_core::nip19::decode_nsec(t).map_err(|_| ImportError::Key("not a valid nsec".into()))?,
        )
    } else {
        Zeroizing::new(t.to_string())
    };
    let v = Zeroizing::new(hex::decode(hexsk.as_str()).map_err(|_| ImportError::Key("secret is not hex or nsec".into()))?);
    let bytes: Zeroizing<[u8; 32]> = Zeroizing::new(
        v.as_slice().try_into().map_err(|_| ImportError::Key("secret must be 32 bytes".into()))?,
    );
    SecretKey::from_bytes(*bytes).map_err(|_| ImportError::Key("secret is not a valid secp256k1 scalar".into()))
}

/// The key store (see the module docs).
#[derive(Debug, Clone, Default)]
pub struct Keystore {
    path: PathBuf,
    keys: BTreeMap<String, KeyEntry>,
    /// What was on disk when loaded: the refuse-to-change baseline.
    baseline: BTreeMap<String, (String, Zeroizing<String>)>,
}

impl Keystore {
    /// Load `path` (missing file: empty store). Refuses a file readable by
    /// group or others.
    pub fn load(path: &Path) -> Result<Self, ImportError> {
        let mut ks = Keystore { path: path.to_path_buf(), ..Default::default() };
        let bytes = match std::fs::read(path) {
            Ok(b) => Zeroizing::new(b),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(ks),
            Err(e) => return Err(ImportError::io(path, e)),
        };
        fsutil::require_private_file(path)?;
        let f: StoreFile = serde_json::from_slice(&bytes)
            .map_err(|_| ImportError::Format(format!("{} is not a keystore", path.display())))?;
        if f.version != 1 {
            return Err(ImportError::Format(format!("{}: keystore version {} unsupported", path.display(), f.version)));
        }
        for (label, e) in f.keys {
            let sk = Zeroizing::new(e.sk);
            let derived = parse_secret(&sk)?.public_key().to_hex();
            if derived != e.pk {
                return Err(ImportError::Key(format!("keystore entry {label:?}: pk does not match its secret")));
            }
            ks.baseline.insert(label.clone(), (e.pk.clone(), sk.clone()));
            ks.keys.insert(label, KeyEntry { pk: e.pk, sk, role: e.role, created_at: e.created_at });
        }
        Ok(ks)
    }

    /// The file this store saves to.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// A key by label.
    pub fn get(&self, label: &str) -> Option<&KeyEntry> {
        self.keys.get(label)
    }

    /// Every label, sorted.
    pub fn labels(&self) -> impl Iterator<Item = &str> {
        self.keys.keys().map(String::as_str)
    }

    /// Generate a key for `label` unless one exists (then it is returned
    /// unchanged with its role checked). Returns `(entry, created)`.
    pub fn ensure(&mut self, label: &str, role: Role) -> Result<(&KeyEntry, bool), ImportError> {
        if role == Role::Operator {
            return Err(ImportError::Refused("the operator key is imported, never generated".into()));
        }
        let created = if let Some(e) = self.keys.get(label) {
            if e.role != role {
                return Err(ImportError::Refused(format!("keystore label {label:?} exists with role {:?}, not {role:?}", e.role)));
            }
            false
        } else {
            let kp = nostr_bbs_core::keys::generate_keypair().map_err(|e| ImportError::Key(e.to_string()))?;
            let sk = Zeroizing::new(hex::encode(kp.secret.as_bytes()));
            self.keys.insert(label.to_string(), KeyEntry { pk: kp.public.to_hex(), sk, role, created_at: fsutil::now() });
            true
        };
        Ok((&self.keys[label], created))
    }

    /// Import an external secret from a 0600 file (hex or nsec) under
    /// `label`. Refused if `label` exists with a different key; a no-op if
    /// it exists with the same key.
    pub fn import(&mut self, label: &str, role: Role, file: &Path) -> Result<&KeyEntry, ImportError> {
        fsutil::require_private_file(file)?;
        let text = Zeroizing::new(std::fs::read_to_string(file).map_err(|e| ImportError::io(file, e))?);
        let sk = parse_secret(&text)?;
        let pk = sk.public_key().to_hex();
        if let Some(e) = self.keys.get(label) {
            if e.pk != pk {
                return Err(ImportError::Refused(format!("keystore label {label:?} already holds a different key")));
            }
            return Ok(&self.keys[label]);
        }
        let hexsk = Zeroizing::new(hex::encode(sk.as_bytes()));
        self.keys.insert(label.to_string(), KeyEntry { pk, sk: hexsk, role, created_at: fsutil::now() });
        Ok(&self.keys[label])
    }

    /// Save atomically, refusing any removal or key change against what was
    /// loaded AND against what is on disk now (another process may have
    /// written since).
    pub fn save(&mut self) -> Result<(), ImportError> {
        let on_disk = Keystore::load(&self.path)?;
        for base in [&self.baseline, &on_disk.baseline] {
            for (label, (pk, sk)) in base {
                match self.keys.get(label) {
                    None => return Err(ImportError::Refused(format!("keystore: label {label:?} would be removed"))),
                    Some(e) if &e.pk != pk || *e.sk != **sk => {
                        return Err(ImportError::Refused(format!("keystore: the key of {label:?} would change")))
                    }
                    Some(_) => {}
                }
            }
        }
        if let Some(dir) = self.path.parent() {
            if !dir.as_os_str().is_empty() {
                fsutil::create_private_dir(dir)?;
            }
        }
        let file = StoreFile {
            version: 1,
            keys: self
                .keys
                .iter()
                .map(|(l, e)| (l.clone(), EntryFile { pk: e.pk.clone(), sk: (*e.sk).clone(), role: e.role, created_at: e.created_at }))
                .collect(),
        };
        let bytes = Zeroizing::new(serde_json::to_vec_pretty(&file).expect("keystore serialises"));
        // The plaintext copies in `file` are dropped right after the write.
        drop(file);
        fsutil::write_private_atomic(&self.path, &bytes)?;
        self.baseline = self.keys.iter().map(|(l, e)| (l.clone(), (e.pk.clone(), e.sk.clone()))).collect();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("bi-ks-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn ensure_is_stable_and_save_refuses_changes() {
        let d = tmp("stable");
        let p = d.join("keys.json");
        let mut ks = Keystore::load(&p).unwrap();
        let pk = ks.ensure("author:a", Role::Fresh).unwrap().0.pk.clone();
        ks.save().unwrap();
        let mut again = Keystore::load(&p).unwrap();
        let (e, created) = again.ensure("author:a", Role::Fresh).unwrap();
        assert!(!created);
        assert_eq!(e.pk, pk);
        assert!(again.ensure("author:a", Role::Archive).is_err());
        // Another writer replaced the file behind our back: refuse.
        let mut other = Keystore::load(&p).unwrap();
        other.keys.remove("author:a");
        other.baseline.clear();
        assert!(other.save().is_err(), "on-disk baseline must still protect the label");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
            assert_eq!(std::fs::metadata(&d).unwrap().permissions().mode() & 0o777, 0o700);
        }
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn import_requires_private_file_and_refuses_a_different_key() {
        let d = tmp("import");
        fsutil::create_private_dir(&d).unwrap();
        let f = d.join("op.key");
        let kp = nostr_bbs_core::keys::generate_keypair().unwrap();
        std::fs::write(&f, hex::encode(kp.secret.as_bytes())).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
            let mut ks = Keystore::load(&d.join("keys.json")).unwrap();
            assert!(ks.import("operator", Role::Operator, &f).is_err());
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let mut ks = Keystore::load(&d.join("keys.json")).unwrap();
        assert_eq!(ks.import("operator", Role::Operator, &f).unwrap().pk, kp.public.to_hex());
        let kp2 = nostr_bbs_core::keys::generate_keypair().unwrap();
        std::fs::write(&f, hex::encode(kp2.secret.as_bytes())).unwrap();
        assert!(ks.import("operator", Role::Operator, &f).is_err());
        assert!(ks.ensure("operator", Role::Operator).is_err());
        assert!(!format!("{:?}", ks.get("operator").unwrap()).contains(&hex::encode(kp.secret.as_bytes())));
        std::fs::remove_dir_all(&d).unwrap();
    }
}
