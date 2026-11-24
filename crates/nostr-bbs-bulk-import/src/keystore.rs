//! The keystore: `keys.json`, the only file holding secrets.
//!
//! ```json
//! {"version":1,"keys":{
//!   "author:alice": {"pk":"<hex>","sk":"<hex>","role":"fresh","created_at":1700000000},
//!   "archive:bob":  {"pk":"<hex>","role":"archive","created_at":1700000000,"retired_at":1700100000},
//!   "operator":     {"pk":"<hex>","role":"operator","created_at":1700000000}
//! }}
//! ```
//!
//! Rules (all enforced by [`Keystore::save`]):
//!
//! - written atomically (temp file `O_EXCL` 0600 in the same directory,
//!   fsync, rename, fsync of the directory), directory 0700, under an
//!   exclusive lock file for the whole read-check-write;
//! - **refuse-to-change**: a save that would remove a label, change any
//!   label's `pk`, or give a retired label a secret again writes nothing and
//!   fails, so a re-run can never replace a key someone holds a recovery
//!   sheet for;
//! - **retirement** ([`Keystore::retire`]) is the one permitted change: the
//!   secret is dropped and the public key kept (archive keys after the final
//!   build, fresh keys once their sheets are delivered, the archivist after
//!   sealing);
//! - the **operator key is never stored**: `keys import` records its public
//!   key only, and each run that signs as the operator reads the secret from
//!   its 0600 file ([`Keystore::unlock`]) for that run alone;
//! - keys come from [`nostr_bbs_core::keys::generate_keypair`] (OS RNG);
//!   secrets live in [`Zeroizing`] buffers, are never formatted into logs,
//!   errors or `Debug` output, and are read only from files that pass
//!   [`fsutil::read_private_file`].
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
    /// The operator: public key only on disk, secret read per run.
    Operator,
}

/// One key. The secret (if held) is zeroized on drop and never printed.
#[derive(Clone)]
pub struct KeyEntry {
    /// Public key, lowercase hex.
    pub pk: String,
    sk: Option<Zeroizing<String>>,
    /// The secret came from [`Keystore::unlock`] and is never saved.
    ephemeral: bool,
    /// What the key is for.
    pub role: Role,
    /// Unix seconds the key entered the store.
    pub created_at: u64,
    /// Unix seconds the secret was dropped.
    pub retired_at: Option<u64>,
}

impl std::fmt::Debug for KeyEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyEntry")
            .field("pk", &self.pk)
            .field("role", &self.role)
            .field("has_secret", &self.sk.is_some())
            .field("retired_at", &self.retired_at)
            .finish()
    }
}

impl KeyEntry {
    /// The signing key; refused for a retired key or a locked operator key.
    pub fn secret(&self) -> Result<SecretKey, ImportError> {
        match &self.sk {
            Some(sk) => parse_secret(sk),
            None if self.role == Role::Operator => Err(ImportError::Refused(
                "the operator key is not unlocked: pass --operator-key FILE (0600)".into(),
            )),
            None => Err(ImportError::Refused(format!(
                "key {}… is retired (no secret held)",
                &self.pk[..8]
            ))),
        }
    }

    /// Whether a secret is held (stored or unlocked).
    pub fn has_secret(&self) -> bool {
        self.sk.is_some()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EntryFile {
    pk: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sk: Option<Zeroizing<String>>,
    role: Role,
    created_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    retired_at: Option<u64>,
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
            nostr_bbs_core::nip19::decode_nsec(t)
                .map_err(|_| ImportError::Key("not a valid nsec".into()))?,
        )
    } else {
        Zeroizing::new(t.to_string())
    };
    let v = Zeroizing::new(
        hex::decode(hexsk.as_str())
            .map_err(|_| ImportError::Key("secret is not hex or nsec".into()))?,
    );
    let bytes: Zeroizing<[u8; 32]> = Zeroizing::new(
        v.as_slice()
            .try_into()
            .map_err(|_| ImportError::Key("secret must be 32 bytes".into()))?,
    );
    SecretKey::from_bytes(*bytes)
        .map_err(|_| ImportError::Key("secret is not a valid secp256k1 scalar".into()))
}

/// Read a secret key from a 0600 file (see [`fsutil::read_private_file`]).
pub fn read_secret_file(path: &Path) -> Result<SecretKey, ImportError> {
    let bytes = fsutil::read_private_file(path)?;
    let text = Zeroizing::new(
        String::from_utf8(bytes.to_vec())
            .map_err(|_| ImportError::Key("key file is not UTF-8".into()))?,
    );
    parse_secret(&text)
}

/// Public facts the refuse-to-change rule compares (never a secret).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Baseline {
    pk: String,
    retired: bool,
}

/// The key store (see the module docs).
#[derive(Default)]
pub struct Keystore {
    path: PathBuf,
    keys: BTreeMap<String, KeyEntry>,
    baseline: BTreeMap<String, Baseline>,
}

impl std::fmt::Debug for Keystore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keystore")
            .field("path", &self.path)
            .field("keys", &self.keys)
            .finish()
    }
}

fn baseline_of(keys: &BTreeMap<String, KeyEntry>) -> BTreeMap<String, Baseline> {
    keys.iter()
        .map(|(l, e)| {
            (
                l.clone(),
                Baseline {
                    pk: e.pk.clone(),
                    retired: e.retired_at.is_some(),
                },
            )
        })
        .collect()
}

impl Keystore {
    /// Load `path` (missing file: empty store). The file must pass
    /// [`fsutil::read_private_file`]; every stored secret must match its
    /// public key.
    pub fn load(path: &Path) -> Result<Self, ImportError> {
        let mut ks = Keystore {
            path: path.to_path_buf(),
            ..Default::default()
        };
        if !path.exists() && path.symlink_metadata().is_err() {
            return Ok(ks);
        }
        let bytes = fsutil::read_private_file(path)?;
        let f: StoreFile = serde_json::from_slice(&bytes)
            .map_err(|_| ImportError::Format(format!("{} is not a keystore", path.display())))?;
        if f.version != 1 {
            return Err(ImportError::Format(format!(
                "{}: keystore version {} unsupported",
                path.display(),
                f.version
            )));
        }
        for (label, e) in f.keys {
            match (&e.sk, e.role, e.retired_at) {
                (Some(_), Role::Operator, _) => {
                    return Err(ImportError::Refused(format!(
                        "keystore entry {label:?}: an operator secret must never be stored"
                    )))
                }
                (Some(_), _, Some(_)) => {
                    return Err(ImportError::Format(format!(
                        "keystore entry {label:?}: retired but holds a secret"
                    )))
                }
                (None, r, None) if r != Role::Operator => {
                    return Err(ImportError::Format(format!(
                        "keystore entry {label:?}: no secret and not retired"
                    )))
                }
                _ => {}
            }
            if let Some(sk) = &e.sk {
                if parse_secret(sk)?.public_key().to_hex() != e.pk {
                    return Err(ImportError::Key(format!(
                        "keystore entry {label:?}: pk does not match its secret"
                    )));
                }
            }
            ks.keys.insert(
                label,
                KeyEntry {
                    pk: e.pk,
                    sk: e.sk,
                    ephemeral: false,
                    role: e.role,
                    created_at: e.created_at,
                    retired_at: e.retired_at,
                },
            );
        }
        ks.baseline = baseline_of(&ks.keys);
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
            return Err(ImportError::Refused(
                "the operator key is imported, never generated".into(),
            ));
        }
        let created = if let Some(e) = self.keys.get(label) {
            if e.role != role {
                return Err(ImportError::Refused(format!(
                    "keystore label {label:?} exists with role {:?}, not {role:?}",
                    e.role
                )));
            }
            false
        } else {
            let kp = nostr_bbs_core::keys::generate_keypair()
                .map_err(|e| ImportError::Key(e.to_string()))?;
            let sk = Zeroizing::new(hex::encode(kp.secret.as_bytes()));
            self.keys.insert(
                label.to_string(),
                KeyEntry {
                    pk: kp.public.to_hex(),
                    sk: Some(sk),
                    ephemeral: false,
                    role,
                    created_at: fsutil::now(),
                    retired_at: None,
                },
            );
            true
        };
        Ok((&self.keys[label], created))
    }

    /// Record the operator's PUBLIC key from its 0600 key file (the secret
    /// is not stored). Refused if an operator with a different key exists.
    pub fn import_operator(&mut self, label: &str, file: &Path) -> Result<&KeyEntry, ImportError> {
        let pk = read_secret_file(file)?.public_key().to_hex();
        if let Some(e) = self.keys.get(label) {
            if e.pk != pk || e.role != Role::Operator {
                return Err(ImportError::Refused(format!(
                    "keystore label {label:?} already holds a different key"
                )));
            }
            return Ok(&self.keys[label]);
        }
        self.keys.insert(
            label.to_string(),
            KeyEntry {
                pk,
                sk: None,
                ephemeral: false,
                role: Role::Operator,
                created_at: fsutil::now(),
                retired_at: None,
            },
        );
        Ok(&self.keys[label])
    }

    /// Hold the operator's secret for this run only, from its 0600 file;
    /// its public key must equal the recorded one. Never saved.
    pub fn unlock(&mut self, label: &str, file: &Path) -> Result<(), ImportError> {
        let sk = read_secret_file(file)?;
        let e = self.keys.get_mut(label).ok_or_else(|| {
            ImportError::Refused(format!("no {label:?} in the keystore: `keys import` first"))
        })?;
        if e.role != Role::Operator {
            return Err(ImportError::Refused(format!(
                "{label:?} is not an operator key"
            )));
        }
        if sk.public_key().to_hex() != e.pk {
            return Err(ImportError::Refused(format!(
                "{} is not the recorded {label:?} key",
                file.display()
            )));
        }
        e.sk = Some(Zeroizing::new(hex::encode(sk.as_bytes())));
        e.ephemeral = true;
        Ok(())
    }

    /// Drop the secret of `label`, keeping its public key (irreversible).
    pub fn retire(&mut self, label: &str) -> Result<(), ImportError> {
        let e = self
            .keys
            .get_mut(label)
            .ok_or_else(|| ImportError::Refused(format!("no {label:?} in the keystore")))?;
        if e.role == Role::Operator {
            return Err(ImportError::Refused(
                "the operator key is never stored; nothing to retire".into(),
            ));
        }
        if e.retired_at.is_none() {
            e.sk = None;
            e.retired_at = Some(fsutil::now());
        }
        Ok(())
    }

    /// Write the secret of `label` to a NEW 0600 file `out` (refuses to
    /// overwrite), for `NOSTR_BBS_MIGRATE_KEY="$(cat out)"`.
    pub fn export(&self, label: &str, out: &Path) -> Result<(), ImportError> {
        let e = self
            .keys
            .get(label)
            .ok_or_else(|| ImportError::Refused(format!("no {label:?} in the keystore")))?;
        let sk = e.secret()?;
        let hexsk = Zeroizing::new(hex::encode(sk.as_bytes()));
        fsutil::write_new_private(out, hexsk.as_bytes())
    }

    /// Save atomically under the lock, refusing removals, key changes and
    /// un-retirement against both what was loaded and what is on disk now.
    pub fn save(&mut self) -> Result<(), ImportError> {
        if let Some(dir) = self.path.parent() {
            if !dir.as_os_str().is_empty() {
                fsutil::create_private_dir(dir)?;
            }
        }
        let _lock = fsutil::LockFile::take(&self.path.with_extension("json.lock"))?;
        let on_disk = Keystore::load(&self.path)?;
        for base in [&self.baseline, &on_disk.baseline] {
            for (label, b) in base {
                match self.keys.get(label) {
                    None => {
                        return Err(ImportError::Refused(format!(
                            "keystore: label {label:?} would be removed"
                        )))
                    }
                    Some(e) if e.pk != b.pk => {
                        return Err(ImportError::Refused(format!(
                            "keystore: the key of {label:?} would change"
                        )))
                    }
                    Some(e) if b.retired && e.retired_at.is_none() => {
                        return Err(ImportError::Refused(format!(
                            "keystore: retired {label:?} cannot hold a secret again"
                        )))
                    }
                    Some(_) => {}
                }
            }
        }
        let file = StoreFile {
            version: 1,
            keys: self
                .keys
                .iter()
                .map(|(l, e)| {
                    let sk = if e.ephemeral || e.role == Role::Operator {
                        None
                    } else {
                        e.sk.clone()
                    };
                    (
                        l.clone(),
                        EntryFile {
                            pk: e.pk.clone(),
                            sk,
                            role: e.role,
                            created_at: e.created_at,
                            retired_at: e.retired_at,
                        },
                    )
                })
                .collect(),
        };
        let bytes = Zeroizing::new(serde_json::to_vec_pretty(&file).expect("keystore serialises"));
        drop(file); // the secret copies are Zeroizing and scrubbed here
        fsutil::write_private_atomic(&self.path, &bytes)?;
        self.baseline = baseline_of(&self.keys);
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

    fn key_file(dir: &Path, name: &str) -> (PathBuf, SecretKey) {
        fsutil::create_private_dir(dir).unwrap();
        let kp = nostr_bbs_core::keys::generate_keypair().unwrap();
        let f = dir.join(name);
        fsutil::write_private_atomic(&f, hex::encode(kp.secret.as_bytes()).as_bytes()).unwrap();
        (f, kp.secret)
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
        // another writer dropped the label behind our back: refused by the on-disk baseline
        let mut other = Keystore::load(&p).unwrap();
        other.keys.remove("author:a");
        other.baseline.clear();
        assert!(other.save().is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                std::fs::metadata(&d).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn debug_never_prints_secrets() {
        let d = tmp("debug");
        let mut ks = Keystore::load(&d.join("keys.json")).unwrap();
        ks.ensure("author:a", Role::Fresh).unwrap();
        ks.save().unwrap();
        let ks = Keystore::load(&d.join("keys.json")).unwrap();
        let sk = hex::encode(ks.get("author:a").unwrap().secret().unwrap().as_bytes());
        assert!(!format!("{ks:?}").contains(&sk));
        assert!(!format!("{:?}", ks.get("author:a").unwrap()).contains(&sk));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn retire_is_one_way_and_operator_secret_is_never_stored() {
        let d = tmp("retire");
        let p = d.join("keys.json");
        let (opf, opsk) = key_file(&d, "op.key");
        let mut ks = Keystore::load(&p).unwrap();
        ks.ensure("archive:b", Role::Archive).unwrap();
        ks.import_operator("operator", &opf).unwrap();
        ks.unlock("operator", &opf).unwrap();
        assert_eq!(
            ks.get("operator")
                .unwrap()
                .secret()
                .unwrap()
                .public_key()
                .to_hex(),
            opsk.public_key().to_hex()
        );
        ks.save().unwrap();
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(
            !text.contains(&hex::encode(opsk.as_bytes())),
            "operator secret written to disk"
        );
        let mut ks = Keystore::load(&p).unwrap();
        assert!(
            ks.get("operator").unwrap().secret().is_err(),
            "locked again after reload"
        );
        ks.retire("archive:b").unwrap();
        ks.save().unwrap();
        let ks = Keystore::load(&p).unwrap();
        assert!(ks.get("archive:b").unwrap().secret().is_err());
        let (other, _) = key_file(&d, "other.key");
        let mut ks2 = Keystore::load(&p).unwrap();
        assert!(ks2.import_operator("operator", &other).is_err());
        assert!(ks2.unlock("operator", &other).is_err());
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn secret_files_must_be_private_and_not_symlinks() {
        let d = tmp("private");
        let (f, _) = key_file(&d, "k.key");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(read_secret_file(&f).is_err());
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
            std::os::unix::fs::symlink(&f, d.join("link.key")).unwrap();
            assert!(read_secret_file(&d.join("link.key")).is_err());
        }
        assert!(read_secret_file(&f).is_ok());
        std::fs::remove_dir_all(&d).unwrap();
    }
}
