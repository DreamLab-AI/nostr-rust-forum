//! NIP-171 key plane for zones (ADR-2028 decisions 1, 3).
//!
//! A zone's group identity and epoch keys are derived from a 12-word recovery
//! master, and the descriptors needed to re-derive used epochs are kept in
//! group-signed, NIP-44 self-encrypted kind 30078 records chained by parent.
//! This module follows the NIP-171 draft ("Recovery Master and Key
//! Derivation", "Recovery Records", "Ownership and Secret Backup").
//!
//! It composes only `bip39`, `hkdf`, `sha2`, `k256` and the NIP-44 wrapper in
//! `nostr_bbs_core`. Nothing here is hand-rolled cryptography, and nothing of
//! the draft record format enters the published `nostr-bbs-core`.
//!
//! The imported-epoch record (ADR-2028 decision 3) is project-private and sits
//! in its own `d` namespace outside the recovery chain; the recovery parser
//! refuses it by name.

#![allow(
    dead_code,
    reason = "the owner flows (create, rotate, restore, import) that consume this land after the ticket work; tests cover every item now"
)]

use std::collections::{BTreeSet, HashMap, HashSet};

use hkdf::Hkdf;
use nostr_bbs_core::event::sign_event;
use nostr_bbs_core::keys::{signing_key_from_bytes, SecretKey as CoreSecret};
use nostr_bbs_core::{verify_event_strict, NostrEvent, UnsignedEvent};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

/// NIP-78 application-data kind carrying every record in this module.
pub const KIND_APP_DATA: u64 = 30078;
/// HKDF salt, UTF-8.
pub const HKDF_SALT: &[u8] = b"nip171/group-recovery/v1";
/// `d` prefix of a recovery record; the management revision follows.
pub const RECOVERY_D_PREFIX: &str = "nip171-group-recovery-v1:";
/// `t` tag value of a recovery record.
pub const RECOVERY_T: &str = "nip171-group-recovery-v1";
/// `t` tag value of an owner backup.
pub const BACKUP_T: &str = "group";
/// `d` prefix of the project-private imported-epoch record (decision 3);
/// the group pubkey follows. Deliberately not under the NIP-171 prefix.
pub const IMPORTED_D_PREFIX: &str = "nostr-bbs/imported-epochs/v1:";
/// Revision of epoch 0 and of the genesis management record: 64 zeroes.
pub const ZERO_REVISION: &str = "0000000000000000000000000000000000000000000000000000000000000000";
/// Largest epoch number the draft allows (`2^53 - 1`).
pub const MAX_EPOCH: u64 = (1 << 53) - 1;
/// Counter ceiling: a rejection loop that long means a broken expander, not
/// bad luck (each draw fails with probability about 2^-128).
const MAX_COUNTER: u32 = 255;

/// Why an NIP-171 operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Nip171Error {
    /// Mnemonic is not a valid 12-word English BIP-39 phrase.
    BadMnemonic(String),
    /// Epoch number above `2^53 - 1`.
    EpochOutOfRange,
    /// A revision is not 64 lowercase hex characters.
    BadRevision,
    /// The derivation counter ran past its ceiling.
    CounterExhausted,
    /// OS entropy was unavailable.
    Entropy(String),
    /// Wrong event kind.
    WrongKind,
    /// The event is not in this record's `d` namespace.
    WrongNamespace,
    /// The `d` or `t` tag does not match the payload or the expected key.
    TagMismatch,
    /// The event was not authored by the expected key.
    WrongAuthor,
    /// Id or signature failed verification.
    BadSignature,
    /// NIP-44 encryption or decryption failed.
    Crypto(String),
    /// The payload is not well-formed.
    BadPayload(String),
    /// Payload version is not the one this record type carries.
    BadVersion,
    /// A master in a backup does not derive the group pubkey in its `d` tag.
    MasterMismatch,
}

impl std::fmt::Display for Nip171Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadMnemonic(e) => write!(f, "invalid recovery mnemonic: {e}"),
            Self::EpochOutOfRange => f.write_str("epoch number out of range"),
            Self::BadRevision => f.write_str("revision is not 64 lowercase hex characters"),
            Self::CounterExhausted => f.write_str("key derivation counter exhausted"),
            Self::Entropy(e) => write!(f, "entropy unavailable: {e}"),
            Self::WrongKind => f.write_str("wrong event kind"),
            Self::WrongNamespace => f.write_str("event is in a different d namespace"),
            Self::TagMismatch => f.write_str("d/t tags do not match the record"),
            Self::WrongAuthor => f.write_str("record not authored by the expected key"),
            Self::BadSignature => f.write_str("event id or signature invalid"),
            Self::Crypto(e) => write!(f, "NIP-44 failure: {e}"),
            Self::BadPayload(e) => write!(f, "malformed payload: {e}"),
            Self::BadVersion => f.write_str("unsupported payload version"),
            Self::MasterMismatch => f.write_str("master does not derive the stated group"),
        }
    }
}

impl std::error::Error for Nip171Error {}

// ---------------------------------------------------------------------------
// Derivation
// ---------------------------------------------------------------------------

fn is_revision(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_hex64(s: &str) -> bool {
    is_revision(s)
}

/// Draw 32 bytes of HKDF output for `info` under `seed` (the production
/// expander).
fn hkdf_expand(seed: &[u8], info: &str) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), seed);
    let mut out = [0u8; 32];
    // 32 bytes is far below the 255 * 32 limit, so expand cannot fail.
    hk.expand(info.as_bytes(), &mut out)
        .expect("32-byte HKDF-SHA256 output is always in range");
    out
}

/// The rejection loop: counter starts at 0 and is incremented only when the
/// output is zero or not below the curve order. Never reduces modulo n.
/// `k256::SecretKey::from_slice` is exactly that test.
fn derive_scalar(
    info_for: impl Fn(u32) -> String,
    mut expand: impl FnMut(&str) -> [u8; 32],
) -> Result<([u8; 32], u32), Nip171Error> {
    for counter in 0..=MAX_COUNTER {
        let out = Zeroizing::new(expand(&info_for(counter)));
        if k256::SecretKey::from_slice(out.as_slice()).is_ok() {
            return Ok((*out, counter));
        }
    }
    Err(Nip171Error::CounterExhausted)
}

fn epoch_info(epoch: u64, revision: &str, counter: u32) -> String {
    format!("epoch/{epoch}/{revision}/{counter}")
}

/// Normalise a user-typed mnemonic: NFKD, lowercase, single spaces.
pub fn normalise_mnemonic(input: &str) -> String {
    use unicode_normalization::UnicodeNormalization;
    let nfkd: String = input.nfkd().collect();
    nfkd.to_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// A group's 128-bit recovery master. Zeroised on drop.
pub struct RecoveryMaster {
    entropy: Zeroizing<[u8; 16]>,
}

impl RecoveryMaster {
    /// Fresh master from the OS random generator.
    pub fn generate() -> Result<Self, Nip171Error> {
        let mut e = [0u8; 16];
        getrandom::getrandom(&mut e).map_err(|e| Nip171Error::Entropy(e.to_string()))?;
        Ok(Self::from_entropy(e))
    }

    /// Master from known entropy (restore, tests).
    pub fn from_entropy(entropy: [u8; 16]) -> Self {
        Self {
            entropy: Zeroizing::new(entropy),
        }
    }

    /// Restore from a typed mnemonic: normalised, exactly 12 words, checksum
    /// verified.
    pub fn from_mnemonic(input: &str) -> Result<Self, Nip171Error> {
        let norm = Zeroizing::new(normalise_mnemonic(input));
        let m = bip39::Mnemonic::parse_normalized(&norm)
            .map_err(|e| Nip171Error::BadMnemonic(e.to_string()))?;
        if m.word_count() != 12 {
            return Err(Nip171Error::BadMnemonic(format!(
                "expected 12 words, got {}",
                m.word_count()
            )));
        }
        let ent = Zeroizing::new(m.to_entropy());
        let arr: [u8; 16] = ent
            .as_slice()
            .try_into()
            .map_err(|_| Nip171Error::BadMnemonic("entropy is not 128 bits".into()))?;
        Ok(Self::from_entropy(arr))
    }

    /// Restore from lowercase hex entropy (owner backup payload).
    pub fn from_entropy_hex(h: &str) -> Result<Self, Nip171Error> {
        let b = hex::decode(h).map_err(|_| Nip171Error::BadPayload("entropy not hex".into()))?;
        let arr: [u8; 16] = b
            .try_into()
            .map_err(|_| Nip171Error::BadPayload("entropy is not 16 bytes".into()))?;
        Ok(Self::from_entropy(arr))
    }

    /// The 12-word phrase to show the owner once.
    pub fn mnemonic(&self) -> Zeroizing<String> {
        let m = bip39::Mnemonic::from_entropy(self.entropy.as_slice())
            .expect("16 bytes is a valid BIP-39 entropy length");
        Zeroizing::new(m.to_string())
    }

    /// Entropy as lowercase hex, for the owner backup payload.
    pub fn entropy_hex(&self) -> Zeroizing<String> {
        Zeroizing::new(hex::encode(self.entropy.as_slice()))
    }

    fn seed(&self) -> Zeroizing<[u8; 64]> {
        let m = bip39::Mnemonic::from_entropy(self.entropy.as_slice())
            .expect("16 bytes is a valid BIP-39 entropy length");
        Zeroizing::new(m.to_seed(""))
    }

    /// Group identity secret (`identity/<counter>`).
    pub fn identity_secret(&self) -> Result<Zeroizing<[u8; 32]>, Nip171Error> {
        let seed = self.seed();
        let (sk, _) = derive_scalar(
            |c| format!("identity/{c}"),
            |info| hkdf_expand(seed.as_slice(), info),
        )?;
        Ok(Zeroizing::new(sk))
    }

    /// Hex x-only pubkey of the group identity.
    pub fn group_pubkey(&self) -> Result<String, Nip171Error> {
        pubkey_of(&*self.identity_secret()?)
    }

    /// Epoch secret for `(epoch, revision)`. Epoch 0 takes [`ZERO_REVISION`].
    pub fn epoch_secret(
        &self,
        epoch: u64,
        revision: &str,
    ) -> Result<Zeroizing<[u8; 32]>, Nip171Error> {
        let seed = self.seed();
        self.epoch_secret_with(epoch, revision, |info| hkdf_expand(seed.as_slice(), info))
            .map(|(sk, _)| Zeroizing::new(sk))
    }

    fn epoch_secret_with(
        &self,
        epoch: u64,
        revision: &str,
        expand: impl FnMut(&str) -> [u8; 32],
    ) -> Result<([u8; 32], u32), Nip171Error> {
        if epoch > MAX_EPOCH {
            return Err(Nip171Error::EpochOutOfRange);
        }
        if !is_revision(revision) {
            return Err(Nip171Error::BadRevision);
        }
        derive_scalar(|c| epoch_info(epoch, revision, c), expand)
    }
}

/// A fresh random 32-byte revision as lowercase hex (rotations and
/// management records).
pub fn random_revision() -> Result<String, Nip171Error> {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).map_err(|e| Nip171Error::Entropy(e.to_string()))?;
    Ok(hex::encode(b))
}

fn pubkey_of(sk: &[u8; 32]) -> Result<String, Nip171Error> {
    let s = CoreSecret::from_bytes(*sk).map_err(|e| Nip171Error::Crypto(e.to_string()))?;
    Ok(s.public_key().to_hex())
}

fn pk_bytes(hex_pk: &str) -> Result<[u8; 32], Nip171Error> {
    hex::decode(hex_pk)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| Nip171Error::BadPayload("pubkey is not 32-byte hex".into()))
}

// ---------------------------------------------------------------------------
// Shared event plumbing
// ---------------------------------------------------------------------------

fn sign_self_encrypted(
    sk: &[u8; 32],
    tags: Vec<Vec<String>>,
    payload: &str,
    created_at: u64,
) -> Result<NostrEvent, Nip171Error> {
    let pk = pubkey_of(sk)?;
    let content = nostr_bbs_core::nip44::encrypt(sk, &pk_bytes(&pk)?, payload)
        .map_err(|e| Nip171Error::Crypto(e.to_string()))?;
    let key = signing_key_from_bytes(sk).map_err(|e| Nip171Error::Crypto(e.to_string()))?;
    sign_event(
        UnsignedEvent {
            pubkey: pk,
            created_at,
            kind: KIND_APP_DATA,
            tags,
            content,
        },
        &key,
    )
    .map_err(|e| Nip171Error::Crypto(e.to_string()))
}

fn tag_value<'a>(ev: &'a NostrEvent, name: &str) -> Option<&'a str> {
    ev.tags
        .iter()
        .find(|t| t.len() >= 2 && t[0] == name)
        .map(|t| t[1].as_str())
}

/// Kind, `d` namespace, author, signature, then decrypt (self-encrypted to
/// `author_sk`'s own key by the *reader* holding the secret). Returns the
/// `d` value and plaintext.
fn open_self_encrypted(
    ev: &NostrEvent,
    d_prefix: &str,
    author_pubkey: &str,
    reader_sk: &[u8; 32],
) -> Result<(String, Zeroizing<String>), Nip171Error> {
    if ev.kind != KIND_APP_DATA {
        return Err(Nip171Error::WrongKind);
    }
    let d = tag_value(ev, "d").ok_or(Nip171Error::TagMismatch)?;
    if !d.starts_with(d_prefix) {
        return Err(Nip171Error::WrongNamespace);
    }
    if !ev.pubkey.eq_ignore_ascii_case(author_pubkey) {
        return Err(Nip171Error::WrongAuthor);
    }
    verify_event_strict(ev).map_err(|_| Nip171Error::BadSignature)?;
    let pt = nostr_bbs_core::nip44::decrypt(reader_sk, &pk_bytes(author_pubkey)?, &ev.content)
        .map_err(|e| Nip171Error::Crypto(e.to_string()))?;
    Ok((d.to_string(), Zeroizing::new(pt)))
}

// ---------------------------------------------------------------------------
// Recovery records
// ---------------------------------------------------------------------------

/// Decrypted payload of a recovery record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryPayload {
    /// Always 1.
    pub version: u32,
    /// Management revision (matches the `d` tag).
    pub revision: String,
    /// Event ids of the preceding records; empty only for genesis.
    pub parents: Vec<String>,
    /// Current epoch number.
    pub epoch: u64,
    /// Revision of the current epoch.
    pub epoch_revision: String,
    /// Current member pubkeys.
    pub members: Vec<String>,
    /// Known master-holder account pubkeys.
    pub owners: Vec<String>,
    /// Recovery relays.
    pub relays: Vec<String>,
}

impl RecoveryPayload {
    /// The genesis payload: no parents, epoch 0, both revisions zero.
    pub fn genesis(members: Vec<String>, owners: Vec<String>, relays: Vec<String>) -> Self {
        Self {
            version: 1,
            revision: ZERO_REVISION.into(),
            parents: vec![],
            epoch: 0,
            epoch_revision: ZERO_REVISION.into(),
            members,
            owners,
            relays,
        }
    }

    fn validate(&self) -> Result<(), Nip171Error> {
        if self.version != 1 {
            return Err(Nip171Error::BadVersion);
        }
        if self.epoch > MAX_EPOCH {
            return Err(Nip171Error::EpochOutOfRange);
        }
        if !is_revision(&self.revision) || !is_revision(&self.epoch_revision) {
            return Err(Nip171Error::BadRevision);
        }
        let all_hex = self
            .parents
            .iter()
            .chain(&self.members)
            .chain(&self.owners)
            .all(|s| is_hex64(s));
        if !all_hex {
            return Err(Nip171Error::BadPayload(
                "parents, members and owners must be 32-byte lowercase hex".into(),
            ));
        }
        let genesis_shape = self.parents.is_empty()
            && self.epoch == 0
            && self.revision == ZERO_REVISION
            && self.epoch_revision == ZERO_REVISION;
        if self.parents.is_empty() != genesis_shape {
            return Err(Nip171Error::BadPayload(
                "genesis has no parents, epoch 0 and zero revisions; nothing else may".into(),
            ));
        }
        if !self.parents.is_empty() && self.revision == ZERO_REVISION {
            return Err(Nip171Error::BadPayload(
                "a non-genesis record needs a fresh management revision".into(),
            ));
        }
        Ok(())
    }

    fn is_genesis(&self) -> bool {
        self.parents.is_empty()
    }
}

/// A verified recovery record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryRecord {
    /// Event id.
    pub id: String,
    /// Event `created_at` (informational: never used to pick a winner).
    pub created_at: u64,
    /// Decrypted, validated payload.
    pub payload: RecoveryPayload,
}

/// Build and sign a recovery record with the group identity secret.
pub fn build_recovery_record(
    group_sk: &[u8; 32],
    payload: &RecoveryPayload,
    created_at: u64,
) -> Result<NostrEvent, Nip171Error> {
    payload.validate()?;
    let json =
        serde_json::to_string(payload).map_err(|e| Nip171Error::BadPayload(e.to_string()))?;
    sign_self_encrypted(
        group_sk,
        vec![
            vec![
                "d".into(),
                format!("{RECOVERY_D_PREFIX}{}", payload.revision),
            ],
            vec!["t".into(), RECOVERY_T.into()],
        ],
        &json,
        created_at,
    )
}

/// Verify and decrypt a recovery record for `group_sk`'s group. Checks kind,
/// namespace, authorship, signature, payload version and the `d` binding.
pub fn parse_recovery_record(
    ev: &NostrEvent,
    group_sk: &[u8; 32],
) -> Result<RecoveryRecord, Nip171Error> {
    let group_pk = pubkey_of(group_sk)?;
    let (d, pt) = open_self_encrypted(ev, RECOVERY_D_PREFIX, &group_pk, group_sk)?;
    if tag_value(ev, "t") != Some(RECOVERY_T) {
        return Err(Nip171Error::TagMismatch);
    }
    let payload: RecoveryPayload =
        serde_json::from_str(&pt).map_err(|e| Nip171Error::BadPayload(e.to_string()))?;
    payload.validate()?;
    if d != format!("{RECOVERY_D_PREFIX}{}", payload.revision) {
        return Err(Nip171Error::TagMismatch);
    }
    Ok(RecoveryRecord {
        id: ev.id.clone(),
        created_at: ev.created_at,
        payload,
    })
}

/// Why a recovery chain is not usable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainError {
    /// No records given.
    Empty,
    /// No genesis record present.
    NoGenesis,
    /// More than one genesis record.
    MultipleGenesis,
    /// A record names a parent that is not in the set.
    MissingParent {
        /// The record naming it.
        record: String,
        /// The absent parent id.
        parent: String,
    },
    /// Epoch decreases along a parent edge.
    EpochDecreases {
        /// The child record.
        record: String,
    },
    /// Epoch unchanged but its revision differs.
    RevisionChanged {
        /// The child record.
        record: String,
    },
    /// Epoch rose but the revision was reused.
    RevisionNotFresh {
        /// The child record.
        record: String,
    },
    /// Two records share a management revision.
    DuplicateRevision(String),
    /// A record is not reachable back to genesis (cycle).
    Unreachable(String),
    /// More than one head: concurrent changes. Never pick a winner by
    /// timestamp; the owner must reconcile.
    Inconsistent {
        /// Head record ids, sorted.
        heads: Vec<String>,
    },
}

/// The verified head of a consistent chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainHead {
    /// The single head record.
    pub head: RecoveryRecord,
    /// Every `(epoch, epoch_revision)` seen, ascending: what restore derives.
    pub epochs: Vec<(u64, String)>,
}

/// Validate `records` back to genesis and find the single head.
pub fn validate_chain(records: &[RecoveryRecord]) -> Result<ChainHead, ChainError> {
    if records.is_empty() {
        return Err(ChainError::Empty);
    }
    let mut by_id: HashMap<&str, &RecoveryRecord> = HashMap::new();
    let mut revisions: HashSet<&str> = HashSet::new();
    for r in records {
        if by_id.insert(r.id.as_str(), r).is_none()
            && !revisions.insert(r.payload.revision.as_str())
        {
            return Err(ChainError::DuplicateRevision(r.payload.revision.clone()));
        }
    }
    let genesis: Vec<&&RecoveryRecord> =
        by_id.values().filter(|r| r.payload.is_genesis()).collect();
    match genesis.len() {
        0 => return Err(ChainError::NoGenesis),
        1 => {}
        _ => return Err(ChainError::MultipleGenesis),
    }
    let mut referenced: HashSet<&str> = HashSet::new();
    for r in by_id.values() {
        for p in &r.payload.parents {
            let parent = by_id
                .get(p.as_str())
                .ok_or_else(|| ChainError::MissingParent {
                    record: r.id.clone(),
                    parent: p.clone(),
                })?;
            referenced.insert(p.as_str());
            let (c, pp) = (&r.payload, &parent.payload);
            if c.epoch < pp.epoch {
                return Err(ChainError::EpochDecreases {
                    record: r.id.clone(),
                });
            }
            if c.epoch == pp.epoch && c.epoch_revision != pp.epoch_revision {
                return Err(ChainError::RevisionChanged {
                    record: r.id.clone(),
                });
            }
            if c.epoch > pp.epoch && c.epoch_revision == pp.epoch_revision {
                return Err(ChainError::RevisionNotFresh {
                    record: r.id.clone(),
                });
            }
        }
    }
    // Every record must reach genesis (rules out cycles among ids).
    let mut reach: HashSet<&str> = genesis.iter().map(|r| r.id.as_str()).collect();
    loop {
        let before = reach.len();
        for r in by_id.values() {
            if !reach.contains(r.id.as_str())
                && r.payload.parents.iter().all(|p| reach.contains(p.as_str()))
            {
                reach.insert(r.id.as_str());
            }
        }
        if reach.len() == before {
            break;
        }
    }
    if let Some(r) = by_id.values().find(|r| !reach.contains(r.id.as_str())) {
        return Err(ChainError::Unreachable(r.id.clone()));
    }
    let mut heads: Vec<&str> = by_id
        .keys()
        .copied()
        .filter(|id| !referenced.contains(id))
        .collect();
    heads.sort_unstable();
    if heads.len() != 1 {
        return Err(ChainError::Inconsistent {
            heads: heads.into_iter().map(String::from).collect(),
        });
    }
    let epochs: BTreeSet<(u64, String)> = by_id
        .values()
        .map(|r| (r.payload.epoch, r.payload.epoch_revision.clone()))
        .collect();
    Ok(ChainHead {
        head: (*by_id[heads[0]]).clone(),
        epochs: epochs.into_iter().collect(),
    })
}

// ---------------------------------------------------------------------------
// Owner backup
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct BackupPayload {
    version: u32,
    recovery_entropy: String,
    relays: Vec<String>,
}

/// A verified owner backup.
pub struct OwnerBackup {
    /// The group pubkey the master derives.
    pub group_pubkey: String,
    /// The restored master.
    pub master: RecoveryMaster,
    /// Recovery relay hints.
    pub relays: Vec<String>,
}

/// Build the owner's backup: kind 30078, `d` = group pubkey, `t` = group,
/// NIP-44 to the owner's own key, signed by the owner account.
pub fn build_owner_backup(
    owner_sk: &[u8; 32],
    master: &RecoveryMaster,
    relays: Vec<String>,
    created_at: u64,
) -> Result<NostrEvent, Nip171Error> {
    let payload = Zeroizing::new(
        serde_json::to_string(&BackupPayload {
            version: 2,
            recovery_entropy: master.entropy_hex().to_string(),
            relays,
        })
        .map_err(|e| Nip171Error::BadPayload(e.to_string()))?,
    );
    sign_self_encrypted(
        owner_sk,
        vec![
            vec!["d".into(), master.group_pubkey()?],
            vec!["t".into(), BACKUP_T.into()],
        ],
        &payload,
        created_at,
    )
}

/// Restore from an owner backup. The master must derive the `d` tag's group
/// pubkey; otherwise the backup is invalid and must be ignored.
pub fn parse_owner_backup(
    ev: &NostrEvent,
    owner_sk: &[u8; 32],
) -> Result<OwnerBackup, Nip171Error> {
    let owner_pk = pubkey_of(owner_sk)?;
    // `d` is a bare group pubkey: no prefix namespace to test.
    let (d, pt) = open_self_encrypted(ev, "", &owner_pk, owner_sk)?;
    if tag_value(ev, "t") != Some(BACKUP_T) {
        return Err(Nip171Error::TagMismatch);
    }
    let p: BackupPayload =
        serde_json::from_str(&pt).map_err(|e| Nip171Error::BadPayload(e.to_string()))?;
    if p.version != 2 {
        return Err(Nip171Error::BadVersion);
    }
    let master = RecoveryMaster::from_entropy_hex(&p.recovery_entropy)?;
    if master.group_pubkey()? != d {
        return Err(Nip171Error::MasterMismatch);
    }
    Ok(OwnerBackup {
        group_pubkey: d,
        master,
        relays: p.relays,
    })
}

// ---------------------------------------------------------------------------
// Imported-epoch record (ADR-2028 decision 3; project-private)
// ---------------------------------------------------------------------------

/// One legacy random epoch key.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportedEpoch {
    /// Legacy epoch number (from 1).
    pub epoch: u32,
    /// 64-hex secret.
    pub sk_hex: String,
    /// 64-hex x-only pubkey the secret derives.
    pub pubkey: String,
}

impl std::fmt::Debug for ImportedEpoch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportedEpoch")
            .field("epoch", &self.epoch)
            .field("pubkey", &self.pubkey)
            .finish_non_exhaustive()
    }
}

#[derive(Serialize, Deserialize)]
struct ImportedPayload {
    version: u32,
    group: String,
    epochs: Vec<ImportedEpoch>,
}

fn validate_imported(p: &ImportedPayload) -> Result<(), Nip171Error> {
    if p.version != 1 {
        return Err(Nip171Error::BadVersion);
    }
    let mut seen = HashSet::new();
    for e in &p.epochs {
        if e.epoch == 0 || !seen.insert(e.epoch) {
            return Err(Nip171Error::BadPayload(
                "legacy epochs are unique and start at 1".into(),
            ));
        }
        let sk: [u8; 32] = hex::decode(&e.sk_hex)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| Nip171Error::BadPayload("epoch secret is not 32-byte hex".into()))?;
        if pubkey_of(&sk)? != e.pubkey {
            return Err(Nip171Error::BadPayload(
                "epoch secret does not derive its pubkey".into(),
            ));
        }
    }
    Ok(())
}

/// Build the imported-epoch record: group-signed, NIP-44 self-encrypted,
/// `d` = [`IMPORTED_D_PREFIX`] + group pubkey. Outside the recovery chain.
pub fn build_imported_epochs(
    group_sk: &[u8; 32],
    epochs: Vec<ImportedEpoch>,
    created_at: u64,
) -> Result<NostrEvent, Nip171Error> {
    let group = pubkey_of(group_sk)?;
    let payload = ImportedPayload {
        version: 1,
        group: group.clone(),
        epochs,
    };
    validate_imported(&payload)?;
    let json = Zeroizing::new(
        serde_json::to_string(&payload).map_err(|e| Nip171Error::BadPayload(e.to_string()))?,
    );
    sign_self_encrypted(
        group_sk,
        vec![vec!["d".into(), format!("{IMPORTED_D_PREFIX}{group}")]],
        &json,
        created_at,
    )
}

/// Verify and decrypt an imported-epoch record for `group_sk`'s group.
pub fn parse_imported_epochs(
    ev: &NostrEvent,
    group_sk: &[u8; 32],
) -> Result<Vec<ImportedEpoch>, Nip171Error> {
    let group = pubkey_of(group_sk)?;
    let (d, pt) = open_self_encrypted(ev, IMPORTED_D_PREFIX, &group, group_sk)?;
    let p: ImportedPayload =
        serde_json::from_str(&pt).map_err(|e| Nip171Error::BadPayload(e.to_string()))?;
    validate_imported(&p)?;
    if p.group != group || d != format!("{IMPORTED_D_PREFIX}{group}") {
        return Err(Nip171Error::TagMismatch);
    }
    Ok(p.epochs)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID_VEC: &str = "13d184e4bcb80ec9e3e9e474783e5c33708154e48c3e75fca524a79966211111";
    const E0_VEC: &str = "15bb3fbeafd0839896fe006fee52cc18e69fbc9054fa7c29e3c8033f1cda3b34";
    const E1_VEC: &str = "72c9245b9ab372a58354804295a5b6b5a5ab366ba37787de056294f468902a29";

    fn zero_master() -> RecoveryMaster {
        RecoveryMaster::from_entropy([0u8; 16])
    }

    /// The draft's test vector: entropy 00..00, empty passphrase, counter 0.
    #[test]
    fn nip171_test_vector_identity_epoch0_epoch1() {
        let m = zero_master();
        assert_eq!(hex::encode(*m.identity_secret().unwrap()), ID_VEC);
        assert_eq!(
            hex::encode(*m.epoch_secret(0, ZERO_REVISION).unwrap()),
            E0_VEC
        );
        assert_eq!(
            hex::encode(*m.epoch_secret(1, &"b".repeat(64)).unwrap()),
            E1_VEC
        );
    }

    #[test]
    fn mnemonic_for_zero_entropy_is_abandon_about() {
        let expect = format!("{} about", ["abandon"; 11].join(" "));
        assert_eq!(zero_master().mnemonic().as_str(), expect);
    }

    #[test]
    fn counter_increments_only_on_out_of_range_output() {
        let m = zero_master();
        let mut calls = Vec::new();
        let (sk, counter) = m
            .epoch_secret_with(3, ZERO_REVISION, |info| {
                calls.push(info.to_string());
                match calls.len() {
                    1 => [0xff; 32], // >= curve order
                    2 => [0x00; 32], // zero
                    _ => [0x11; 32],
                }
            })
            .unwrap();
        assert_eq!(counter, 2);
        assert_eq!(sk, [0x11; 32]);
        assert_eq!(
            calls,
            (0..3)
                .map(|c| format!("epoch/3/{ZERO_REVISION}/{c}"))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn in_range_output_is_never_reduced_or_recounted() {
        let (sk, counter) = derive_scalar(|c| c.to_string(), |_| [0x22; 32]).unwrap();
        assert_eq!((sk, counter), ([0x22; 32], 0));
    }

    #[test]
    fn epoch_and_revision_bounds() {
        let m = zero_master();
        assert_eq!(
            m.epoch_secret(MAX_EPOCH + 1, ZERO_REVISION).unwrap_err(),
            Nip171Error::EpochOutOfRange
        );
        assert!(m.epoch_secret(MAX_EPOCH, ZERO_REVISION).is_ok());
        assert_eq!(
            m.epoch_secret(1, &"B".repeat(64)).unwrap_err(),
            Nip171Error::BadRevision
        );
        assert_eq!(
            m.epoch_secret(1, "abc").unwrap_err(),
            Nip171Error::BadRevision
        );
    }

    #[test]
    fn mnemonic_input_is_normalised() {
        let canon = zero_master().mnemonic().to_string();
        let messy = format!("  {}\n", canon.to_uppercase().replace(' ', "  \t"));
        let m = RecoveryMaster::from_mnemonic(&messy).unwrap();
        assert_eq!(hex::encode(*m.identity_secret().unwrap()), ID_VEC);
        // Full-width letters fold under NFKD.
        let wide: String = canon
            .chars()
            .map(|c| {
                if c.is_ascii_lowercase() {
                    char::from_u32(c as u32 - 'a' as u32 + 0xFF41).unwrap()
                } else {
                    c
                }
            })
            .collect();
        assert!(RecoveryMaster::from_mnemonic(&wide).is_ok());
    }

    #[test]
    fn mnemonic_rejects_bad_checksum_and_wrong_length() {
        let bad = format!("{} abandon", ["abandon"; 11].join(" "));
        assert!(matches!(
            RecoveryMaster::from_mnemonic(&bad),
            Err(Nip171Error::BadMnemonic(_))
        ));
        let twenty_four = format!("{} art", ["abandon"; 23].join(" "));
        assert!(matches!(
            RecoveryMaster::from_mnemonic(&twenty_four),
            Err(Nip171Error::BadMnemonic(_))
        ));
    }

    #[test]
    fn generated_masters_differ_and_round_trip_their_mnemonic() {
        let (a, b) = (
            RecoveryMaster::generate().unwrap(),
            RecoveryMaster::generate().unwrap(),
        );
        assert_ne!(a.entropy_hex().as_str(), b.entropy_hex().as_str());
        let back = RecoveryMaster::from_mnemonic(&a.mnemonic()).unwrap();
        assert_eq!(back.group_pubkey().unwrap(), a.group_pubkey().unwrap());
        assert_ne!(random_revision().unwrap(), random_revision().unwrap());
    }

    // -- records ----------------------------------------------------------

    fn sk() -> [u8; 32] {
        *zero_master().identity_secret().unwrap()
    }

    fn hexid(c: char) -> String {
        c.to_string().repeat(64)
    }

    fn payload(
        revision: &str,
        parents: &[&str],
        epoch: u64,
        epoch_revision: &str,
    ) -> RecoveryPayload {
        RecoveryPayload {
            version: 1,
            revision: revision.into(),
            parents: parents.iter().map(|s| s.to_string()).collect(),
            epoch,
            epoch_revision: epoch_revision.into(),
            members: vec![hexid('a')],
            owners: vec![hexid('b')],
            relays: vec!["wss://r.example/".into()],
        }
    }

    fn record(p: RecoveryPayload) -> RecoveryRecord {
        let ev = build_recovery_record(&sk(), &p, 1_700_000_000).unwrap();
        parse_recovery_record(&ev, &sk()).unwrap()
    }

    fn genesis() -> RecoveryRecord {
        record(RecoveryPayload::genesis(
            vec![hexid('a')],
            vec![hexid('b')],
            vec![],
        ))
    }

    #[test]
    fn recovery_record_round_trips_and_carries_the_spec_tags() {
        let p =
            RecoveryPayload::genesis(vec![hexid('a')], vec![hexid('b')], vec!["wss://x/".into()]);
        let ev = build_recovery_record(&sk(), &p, 5).unwrap();
        assert_eq!(ev.kind, 30078);
        assert_eq!(ev.pubkey, zero_master().group_pubkey().unwrap());
        assert_eq!(
            tag_value(&ev, "d"),
            Some(format!("nip171-group-recovery-v1:{ZERO_REVISION}").as_str())
        );
        assert_eq!(tag_value(&ev, "t"), Some("nip171-group-recovery-v1"));
        assert!(!ev.content.contains("members"));
        let r = parse_recovery_record(&ev, &sk()).unwrap();
        assert_eq!(r.payload, p);
        assert_eq!(r.id, ev.id);
    }

    #[test]
    fn recovery_record_refuses_other_author_tampering_and_d_mismatch() {
        let p = RecoveryPayload::genesis(vec![], vec![], vec![]);
        let ev = build_recovery_record(&sk(), &p, 5).unwrap();
        let other = *RecoveryMaster::from_entropy([1; 16])
            .identity_secret()
            .unwrap();
        assert!(parse_recovery_record(&ev, &other).is_err());
        let mut t = ev.clone();
        t.created_at += 1;
        assert_eq!(
            parse_recovery_record(&t, &sk()).unwrap_err(),
            Nip171Error::BadSignature
        );
        // d tag naming a different revision than the payload.
        let rev = hexid('c');
        let child = payload(&rev, &[&hexid('1')], 0, ZERO_REVISION);
        let json = serde_json::to_string(&child).unwrap();
        let wrong_d = sign_self_encrypted(
            &sk(),
            vec![
                vec!["d".into(), format!("{RECOVERY_D_PREFIX}{}", hexid('d'))],
                vec!["t".into(), RECOVERY_T.into()],
            ],
            &json,
            5,
        )
        .unwrap();
        assert_eq!(
            parse_recovery_record(&wrong_d, &sk()).unwrap_err(),
            Nip171Error::TagMismatch
        );
    }

    #[test]
    fn genesis_shape_is_enforced() {
        // No parents but epoch 1: not a genesis, not a child.
        let bad = payload(&hexid('c'), &[], 1, &hexid('d'));
        assert!(build_recovery_record(&sk(), &bad, 1).is_err());
        // Parents but zero management revision.
        let bad = payload(ZERO_REVISION, &[&hexid('1')], 0, ZERO_REVISION);
        assert!(build_recovery_record(&sk(), &bad, 1).is_err());
    }

    #[test]
    fn chain_valid_to_single_head() {
        let g = genesis();
        let c1 = record(payload(&hexid('1'), &[&g.id], 0, ZERO_REVISION));
        let c2 = record(payload(&hexid('2'), &[&c1.id], 1, &hexid('e')));
        let c3 = record(payload(&hexid('3'), &[&c2.id], 1, &hexid('e')));
        let head = validate_chain(&[c3.clone(), g, c2, c1]).unwrap();
        assert_eq!(head.head.id, c3.id);
        assert_eq!(
            head.epochs,
            vec![(0, ZERO_REVISION.to_string()), (1, hexid('e'))]
        );
    }

    #[test]
    fn chain_parent_missing() {
        let g = genesis();
        let ghost = hexid('9');
        let c1 = record(payload(&hexid('1'), &[&g.id, &ghost], 0, ZERO_REVISION));
        assert_eq!(
            validate_chain(&[g, c1.clone()]).unwrap_err(),
            ChainError::MissingParent {
                record: c1.id,
                parent: ghost
            }
        );
    }

    #[test]
    fn chain_epoch_decreases() {
        let g = genesis();
        let up = record(payload(&hexid('1'), &[&g.id], 2, &hexid('e')));
        let down = record(payload(&hexid('2'), &[&up.id], 1, &hexid('f')));
        assert_eq!(
            validate_chain(&[g, up, down.clone()]).unwrap_err(),
            ChainError::EpochDecreases { record: down.id }
        );
    }

    #[test]
    fn chain_epoch_revision_rules() {
        let g = genesis();
        let same_epoch_new_rev = record(payload(&hexid('1'), &[&g.id], 0, &hexid('e')));
        assert_eq!(
            validate_chain(&[g.clone(), same_epoch_new_rev.clone()]).unwrap_err(),
            ChainError::RevisionChanged {
                record: same_epoch_new_rev.id
            }
        );
        let higher_old_rev = record(payload(&hexid('2'), &[&g.id], 1, ZERO_REVISION));
        assert_eq!(
            validate_chain(&[g, higher_old_rev.clone()]).unwrap_err(),
            ChainError::RevisionNotFresh {
                record: higher_old_rev.id
            }
        );
    }

    #[test]
    fn chain_two_heads_is_inconsistent() {
        let g = genesis();
        let a = record(payload(&hexid('1'), &[&g.id], 1, &hexid('e')));
        let b = record(payload(&hexid('2'), &[&g.id], 1, &hexid('f')));
        let mut heads = vec![a.id.clone(), b.id.clone()];
        heads.sort();
        assert_eq!(
            validate_chain(&[g, a, b]).unwrap_err(),
            ChainError::Inconsistent { heads }
        );
    }

    #[test]
    fn chain_without_genesis_or_empty() {
        assert_eq!(validate_chain(&[]).unwrap_err(), ChainError::Empty);
        let c = record(payload(&hexid('1'), &[&hexid('9')], 0, ZERO_REVISION));
        assert_eq!(validate_chain(&[c]).unwrap_err(), ChainError::NoGenesis);
    }

    // -- owner backup -----------------------------------------------------

    fn owner() -> [u8; 32] {
        *RecoveryMaster::from_entropy([7; 16])
            .identity_secret()
            .unwrap()
    }

    #[test]
    fn owner_backup_round_trip() {
        let m = RecoveryMaster::from_entropy([3; 16]);
        let ev = build_owner_backup(&owner(), &m, vec!["wss://r/".into()], 9).unwrap();
        assert_eq!(
            tag_value(&ev, "d"),
            Some(m.group_pubkey().unwrap().as_str())
        );
        assert_eq!(tag_value(&ev, "t"), Some("group"));
        assert!(!ev.content.contains(m.entropy_hex().as_str()));
        let back = parse_owner_backup(&ev, &owner()).unwrap();
        assert_eq!(back.group_pubkey, m.group_pubkey().unwrap());
        assert_eq!(back.master.entropy_hex().as_str(), m.entropy_hex().as_str());
        assert_eq!(back.relays, vec!["wss://r/".to_string()]);
        // Someone else cannot open it.
        assert!(parse_owner_backup(&ev, &sk()).is_err());
    }

    #[test]
    fn owner_backup_with_wrong_group_in_d_is_rejected() {
        let m = RecoveryMaster::from_entropy([3; 16]);
        let other_group = RecoveryMaster::from_entropy([4; 16])
            .group_pubkey()
            .unwrap();
        let json = serde_json::to_string(&BackupPayload {
            version: 2,
            recovery_entropy: m.entropy_hex().to_string(),
            relays: vec![],
        })
        .unwrap();
        let ev = sign_self_encrypted(
            &owner(),
            vec![
                vec!["d".into(), other_group],
                vec!["t".into(), "group".into()],
            ],
            &json,
            9,
        )
        .unwrap();
        assert_eq!(
            parse_owner_backup(&ev, &owner()).err(),
            Some(Nip171Error::MasterMismatch)
        );
    }

    // -- imported epochs --------------------------------------------------

    fn legacy(epoch: u32, fill: u8) -> ImportedEpoch {
        let secret = [fill; 32];
        ImportedEpoch {
            epoch,
            sk_hex: hex::encode(secret),
            pubkey: pubkey_of(&secret).unwrap(),
        }
    }

    #[test]
    fn imported_epochs_round_trip() {
        let epochs = vec![legacy(1, 0x11), legacy(2, 0x22)];
        let ev = build_imported_epochs(&sk(), epochs.clone(), 3).unwrap();
        let group = zero_master().group_pubkey().unwrap();
        assert_eq!(
            tag_value(&ev, "d"),
            Some(format!("nostr-bbs/imported-epochs/v1:{group}").as_str())
        );
        assert!(!ev.content.contains(&epochs[0].sk_hex));
        assert_eq!(parse_imported_epochs(&ev, &sk()).unwrap(), epochs);
    }

    #[test]
    fn imported_epochs_refuse_inconsistent_content() {
        let mut bad = legacy(1, 0x11);
        bad.pubkey = hexid('a');
        assert!(build_imported_epochs(&sk(), vec![bad], 3).is_err());
        assert!(build_imported_epochs(&sk(), vec![legacy(1, 0x11), legacy(1, 0x22)], 3).is_err());
        assert!(build_imported_epochs(&sk(), vec![legacy(0, 0x11)], 3).is_err());
    }

    /// The two record types live in disjoint `d` namespaces: each parser
    /// refuses the other's event by namespace, before any payload is read.
    #[test]
    fn imported_record_is_outside_the_recovery_chain() {
        let imported = build_imported_epochs(&sk(), vec![legacy(1, 0x11)], 3).unwrap();
        assert_eq!(
            parse_recovery_record(&imported, &sk()).unwrap_err(),
            Nip171Error::WrongNamespace
        );
        let rec =
            build_recovery_record(&sk(), &RecoveryPayload::genesis(vec![], vec![], vec![]), 3)
                .unwrap();
        assert_eq!(
            parse_imported_epochs(&rec, &sk()).unwrap_err(),
            Nip171Error::WrongNamespace
        );
        assert!(!IMPORTED_D_PREFIX.starts_with("nip171"));
    }
}
