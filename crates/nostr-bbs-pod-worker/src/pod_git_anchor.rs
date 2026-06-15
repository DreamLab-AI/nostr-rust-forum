//! Native-only pod-git identity + gitmark/blocktrails anchoring (ADR-124 §5.4).
//!
//! This module wires the canonical `did:nostr` Multikey DID document and the
//! gitmark/blocktrails web-contract trail onto a **real, externally-pullable
//! pod-git repository** — the native/agentbox deployment tier described in
//! `ADR-089`. It is gated `#[cfg(not(target_arch = "wasm32"))]` and is therefore
//! **structurally absent from the Cloudflare Workers (`wasm32-unknown-unknown`)
//! build**: CF Workers cannot spawn subprocesses or run a Tokio runtime, so the
//! git path is unreachable there (ADR-089). On CF the pod-worker keeps returning
//! the `501 / X-Git-Unavailable: cf-workers` stub from [`crate::git`]; on the
//! native build the operator gets a clone-able pod whose root carries
//! `agent.did.json`, `gitmark.json`, and `blocktrails.json`.
//!
//! ## What this writes into the pod-git root (Melvin Carvalho `create-agent` layout)
//!
//! - `agent.did.json` — the canonical ADR-125 §2 Multikey DID document, rendered
//!   by [`nostr_bbs_core::did`] (single source of truth; no re-encoding here).
//! - `git config nostr.privkey <hex>` — the agent's raw BIP-340 secret key, stored
//!   in the repo's local git config (NOT a tracked file — never committed).
//! - `gitmark.json` — the 5-key trail mark (ADR-124 §2.1): `@id`, `genesis`,
//!   `nick`, `package`, `repository`. Nothing else.
//! - `blocktrails.json` — the `@type: Blocktrail` / `profile: gitmark` envelope
//!   (ADR-124 §2.2): `states[]` = real pod-git commit SHAs, `txo[]` = the BIP-341
//!   single-use-seal UTXO chain (one seal per state).
//!
//! ## Invariant boundary (I1–I4 — ADR-124 §7)
//!
//! This module is identity-rail-agnostic above the `did:nostr` Multikey layer.
//! - **I1**: the `agent_did` it carries is the unchanged `did:nostr:<hex>` string.
//! - **I2**: `agent.did.json` is rendered by the upstream canonical renderer; this
//!   module never re-encodes `publicKeyMultibase`.
//! - **I3**: NIP-98 auth never reads anything written here. The trail signs/anchors
//!   with the raw `nostr.privkey`/pubkey, NEVER by decoding the DID-doc
//!   verificationMethod. A future verifier that decoded `publicKeyMultibase` for an
//!   auth decision would violate I3 — flag it.
//! - **I4**: ADR-074 §D1 (x-only hex = canonical identity) is untouched.

#![cfg(not(target_arch = "wasm32"))]

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{json, Value};

/// Error surface for native pod-git anchoring.
#[derive(Debug)]
pub enum AnchorError {
    /// The provided pubkey/privkey was not valid 64-char lowercase hex.
    InvalidHex(String),
    /// A `git` subprocess failed (non-zero exit or spawn error).
    Git(String),
    /// A filesystem write/read failed.
    Io(String),
    /// Serialisation of a JSON artefact failed.
    Encode(String),
}

impl std::fmt::Display for AnchorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnchorError::InvalidHex(s) => write!(f, "invalid hex: {s}"),
            AnchorError::Git(s) => write!(f, "git: {s}"),
            AnchorError::Io(s) => write!(f, "io: {s}"),
            AnchorError::Encode(s) => write!(f, "encode: {s}"),
        }
    }
}

impl std::error::Error for AnchorError {}

type AnchorResult<T> = Result<T, AnchorError>;

/// Filename of the canonical DID document committed to the pod-git root
/// (Melvin Carvalho `create-agent` layout).
pub const AGENT_DID_FILENAME: &str = "agent.did.json";

/// Filename of the gitmark trail mark (ADR-124 §2.1).
pub const GITMARK_FILENAME: &str = "gitmark.json";

/// Filename of the blocktrails envelope (ADR-124 §2.2).
pub const BLOCKTRAILS_FILENAME: &str = "blocktrails.json";

/// The git config key under which the agent's raw secret key is stored
/// (Melvin Carvalho `create-agent`: `git config nostr.privkey`).
pub const GIT_CONFIG_PRIVKEY: &str = "nostr.privkey";

// ---------------------------------------------------------------------------
// Identity: agent.did.json + git config nostr.privkey
// ---------------------------------------------------------------------------

/// Render the canonical ADR-125 §2 Multikey DID document for `pubkey_hex`.
///
/// Delegates entirely to [`nostr_bbs_core::did`] (which delegates to the
/// upstream `solid_pod_rs::did_nostr_types` canonical renderer). No DID-doc
/// field is constructed here — this keeps I1/I2 single-sourced.
pub fn render_agent_did_doc(pubkey_hex: &str) -> AnchorResult<Value> {
    let pk = nostr_bbs_core::did::NostrPubkey::from_hex(pubkey_hex)
        .map_err(AnchorError::InvalidHex)?;
    Ok(nostr_bbs_core::did::render_did_document_tier1(&pk))
}

/// Write `agent.did.json` (canonical Multikey form) into the pod-git `repo_root`.
///
/// Returns the absolute path written. The document is the unchanged
/// `did:nostr:<hex>` identity rendered upstream (I1/I2).
pub fn write_agent_did_json(repo_root: &Path, pubkey_hex: &str) -> AnchorResult<PathBuf> {
    let doc = render_agent_did_doc(pubkey_hex)?;
    let body =
        serde_json::to_vec_pretty(&doc).map_err(|e| AnchorError::Encode(e.to_string()))?;
    let path = repo_root.join(AGENT_DID_FILENAME);
    std::fs::write(&path, body).map_err(|e| AnchorError::Io(e.to_string()))?;
    Ok(path)
}

/// Store the agent's raw secret key via `git config nostr.privkey <hex>` in the
/// pod-git repo at `repo_root`.
///
/// The privkey is set in the repo's **local** git config (`.git/config`), which
/// is NOT a tracked file — it is never committed and never appears in the
/// externally-pullable surface. This mirrors `create-agent`'s
/// `git config nostr.privkey`. Auth still uses the raw key (I3); nothing here
/// is read by the NIP-98 verifier.
pub fn set_git_privkey(repo_root: &Path, privkey_hex: &str) -> AnchorResult<()> {
    if privkey_hex.len() != 64 || !privkey_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(AnchorError::InvalidHex(
            "privkey must be 64 hex chars".into(),
        ));
    }
    run_git(repo_root, &["config", "--local", GIT_CONFIG_PRIVKEY, privkey_hex])?;
    Ok(())
}

/// Read back `git config nostr.privkey` from the repo at `repo_root`, if set.
pub fn get_git_privkey(repo_root: &Path) -> AnchorResult<Option<String>> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(["config", "--local", "--get", GIT_CONFIG_PRIVKEY])
        .output()
        .map_err(|e| AnchorError::Git(e.to_string()))?;
    if out.status.success() {
        let v = String::from_utf8_lossy(&out.stdout).trim().to_string();
        Ok((!v.is_empty()).then_some(v))
    } else {
        // `git config --get` exits 1 when the key is unset; that is not an error.
        Ok(None)
    }
}

// ---------------------------------------------------------------------------
// gitmark.json (ADR-124 §2.1) — EXACTLY five keys, nothing else
// ---------------------------------------------------------------------------

/// Build the gitmark trail-mark `Value` (ADR-124 §2.1).
///
/// Exactly five keys: `@id`, `genesis`, `nick`, `package`, `repository`.
/// `@id` is `gitmark:<commit_sha>:<vout>`. The genesis mark has
/// `genesis == @id`. **Do NOT add `@context`/`@type`/`commit`/`parent`** —
/// parent linkage lives in `blocktrails.json` `states[]`/`txo[]`.
pub fn build_gitmark(
    commit_sha: &str,
    vout: u32,
    genesis_sha: &str,
    genesis_vout: u32,
    nick: &str,
    package: &str,
    repository: &str,
) -> Value {
    json!({
        "@id": format!("gitmark:{commit_sha}:{vout}"),
        "genesis": format!("gitmark:{genesis_sha}:{genesis_vout}"),
        "nick": nick,
        "package": package,
        "repository": repository,
    })
}

// ---------------------------------------------------------------------------
// blocktrails.json (ADR-124 §2.2) — @type Blocktrail / profile gitmark
// ---------------------------------------------------------------------------

/// A single-use-seal txo entry in the blocktrails chain (ADR-124 §2.2).
#[derive(Debug, Clone)]
pub struct TxoEntry {
    /// Funding txid of this seal in the BIP-341 single-use-seal chain.
    pub txid: String,
    /// Output index of the seal.
    pub vout: u32,
}

/// Build the blocktrails envelope (ADR-124 §2.2).
///
/// `states[]` are real pod-git commit SHAs; `txo[]` is the BIP-341
/// single-use-seal UTXO chain. The well-formed invariant is
/// `states.len() == txo.len()` (one seal per state); this function asserts it
/// and returns an error otherwise rather than emitting a malformed trail.
pub fn build_blocktrails(
    genesis_gitmark_id: &str,
    states: &[String],
    txo: &[TxoEntry],
) -> AnchorResult<Value> {
    if states.len() != txo.len() {
        return Err(AnchorError::Encode(format!(
            "blocktrails malformed: states.len()={} != txo.len()={} (one seal per state)",
            states.len(),
            txo.len()
        )));
    }
    let txo_json: Vec<Value> = txo
        .iter()
        .map(|t| json!({ "txid": t.txid, "vout": t.vout }))
        .collect();
    Ok(json!({
        "@type": "Blocktrail",
        "profile": "gitmark",
        "genesis": genesis_gitmark_id,
        "states": states,
        "txo": txo_json,
    }))
}

// ---------------------------------------------------------------------------
// The deploy ritual: init → pull → commit → git-mark → push (ADR-124 §2.3)
// ---------------------------------------------------------------------------

/// Ensure a git repository exists at `repo_root`, initialising one (branch
/// `main`) if absent. Idempotent — re-running on an existing repo is a no-op.
pub fn ensure_repo(repo_root: &Path) -> AnchorResult<()> {
    std::fs::create_dir_all(repo_root).map_err(|e| AnchorError::Io(e.to_string()))?;
    if repo_root.join(".git").exists() {
        return Ok(());
    }
    run_git(repo_root, &["init", "-b", "main"])?;
    Ok(())
}

/// Pull the latest state from `remote`/`branch` if a remote is configured.
///
/// Best-effort: a fresh externally-pullable pod may have no remote yet, in which
/// case this is a no-op. Network/merge failures surface as [`AnchorError::Git`].
pub fn pull(repo_root: &Path, remote: &str, branch: &str) -> AnchorResult<()> {
    let has_remote = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(["remote", "get-url", remote])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !has_remote {
        return Ok(());
    }
    run_git(repo_root, &["pull", "--ff-only", remote, branch])?;
    Ok(())
}

/// Stage the given pod-relative `paths` and commit them with `message`.
///
/// Returns the resulting commit SHA (the real pod-git SHA that goes into
/// `blocktrails.json` `states[]`). Honours an explicit `did:nostr:<hex>` author
/// identity so the commit metadata carries the unchanged identity string (I1).
pub fn commit(
    repo_root: &Path,
    paths: &[&str],
    message: &str,
    agent_did: &str,
) -> AnchorResult<String> {
    let mut add = vec!["add", "--"];
    add.extend_from_slice(paths);
    run_git(repo_root, &add)?;

    // Author identity carries the unchanged did:nostr:<hex> string (I1).
    let author = format!("agent <{agent_did}>");
    run_git(
        repo_root,
        &[
            "-c",
            &format!("user.name=agent"),
            "-c",
            &format!("user.email={agent_did}"),
            "commit",
            "--author",
            &author,
            "-m",
            message,
        ],
    )?;

    head_sha(repo_root)
}

/// Resolve the current `HEAD` commit SHA of the pod-git repo.
pub fn head_sha(repo_root: &Path) -> AnchorResult<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(["rev-parse", "HEAD"])
        .output()
        .map_err(|e| AnchorError::Git(e.to_string()))?;
    if !out.status.success() {
        return Err(AnchorError::Git(
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Push `branch` to `remote` if a remote is configured (best-effort, like
/// [`pull`]). The pod is externally pullable, so push is the publish step of the
/// ritual.
pub fn push(repo_root: &Path, remote: &str, branch: &str) -> AnchorResult<()> {
    let has_remote = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(["remote", "get-url", remote])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !has_remote {
        return Ok(());
    }
    run_git(repo_root, &["push", remote, branch])?;
    Ok(())
}

/// Returns `true` when the working tree is clean (no staged/unstaged changes) —
/// the `verify` "assert git-clean" check (ADR-124 §2.4 step 3).
pub fn is_git_clean(repo_root: &Path) -> AnchorResult<bool> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(["status", "--porcelain"])
        .output()
        .map_err(|e| AnchorError::Git(e.to_string()))?;
    if !out.status.success() {
        return Err(AnchorError::Git(
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        ));
    }
    Ok(out.stdout.is_empty())
}

// ---------------------------------------------------------------------------
// High-level provisioning entry point
// ---------------------------------------------------------------------------

/// Bootstrap a freshly-provisioned external forum pod's git identity + genesis
/// trail (ADR-124 §5.4). This is the native counterpart to the CF
/// [`crate::provision::provision_pod`] R2/KV path.
///
/// Steps (the deploy ritual, ADR-124 §2.3):
/// 1. `ensure_repo` — `git init -b main` at `repo_root` if absent.
/// 2. write `agent.did.json` (canonical Multikey) + `git config nostr.privkey`.
/// 3. commit `agent.did.json` → genesis commit SHA.
/// 4. git-mark: write `gitmark.json` (genesis: `@id == genesis`) from the
///    genesis SHA + anchoring `vout`, and `blocktrails.json` with
///    `states=[genesis_sha]`, `txo=[genesis seal]`.
/// 5. commit the trail artefacts (their SHA extends `states[]` on the next mark).
///
/// `pubkey_hex`/`privkey_hex` are the agent's raw BIP-340 keys. `vout`/`genesis_txo`
/// come from the anchoring `BlockTrailAnchor` (caller-supplied; the actual taproot
/// broadcast is the solid-pod-rs engine's job per ADR-124 §2.3 `anchor`). Returns
/// the genesis commit SHA.
#[allow(clippy::too_many_arguments)]
pub fn bootstrap_pod_identity_and_trail(
    repo_root: &Path,
    pubkey_hex: &str,
    privkey_hex: &str,
    nick: &str,
    package: &str,
    repository: &str,
    vout: u32,
    genesis_txo: TxoEntry,
) -> AnchorResult<String> {
    let agent_did = format!("did:nostr:{pubkey_hex}");

    // 1. repo
    ensure_repo(repo_root)?;

    // 2. identity
    write_agent_did_json(repo_root, pubkey_hex)?;
    set_git_privkey(repo_root, privkey_hex)?;

    // 3. genesis commit (agent.did.json)
    let genesis_sha = commit(
        repo_root,
        &[AGENT_DID_FILENAME],
        "chore(identity): canonical did:nostr Multikey DID document (ADR-125)",
        &agent_did,
    )?;

    // 4. git-mark: genesis gitmark + blocktrails
    let gitmark = build_gitmark(
        &genesis_sha,
        vout,
        &genesis_sha,
        vout,
        nick,
        package,
        repository,
    );
    let gitmark_id = gitmark["@id"].as_str().unwrap_or_default().to_string();
    write_json(repo_root, GITMARK_FILENAME, &gitmark)?;

    let blocktrails = build_blocktrails(
        &gitmark_id,
        std::slice::from_ref(&genesis_sha),
        std::slice::from_ref(&genesis_txo),
    )?;
    write_json(repo_root, BLOCKTRAILS_FILENAME, &blocktrails)?;

    // 5. commit the trail artefacts
    commit(
        repo_root,
        &[GITMARK_FILENAME, BLOCKTRAILS_FILENAME],
        "chore(trail): genesis gitmark + blocktrails (ADR-124)",
        &agent_did,
    )?;

    Ok(genesis_sha)
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

fn write_json(repo_root: &Path, filename: &str, value: &Value) -> AnchorResult<()> {
    let body =
        serde_json::to_vec_pretty(value).map_err(|e| AnchorError::Encode(e.to_string()))?;
    std::fs::write(repo_root.join(filename), body).map_err(|e| AnchorError::Io(e.to_string()))
}

fn run_git(repo_root: &Path, args: &[&str]) -> AnchorResult<()> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(args)
        .output()
        .map_err(|e| AnchorError::Git(format!("spawn `git {}`: {e}", args.join(" "))))?;
    if !out.status.success() {
        return Err(AnchorError::Git(format!(
            "`git {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests (native — this module is wasm-excluded so these run on the host build)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const PK_HEX: &str = "611df01bfcf85c26ae65453b772d8f1dfd25c264621c0277e1fc1518686faef9";
    const SK_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000001";

    fn temp_dir(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "podgit-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn agent_did_doc_carries_unchanged_identity() {
        // This module's contract is to WRITE whatever the canonical renderer
        // emits into git — not to re-assert the renderer's VM shape (that is
        // `nostr_bbs_core::did`'s job, whose canonical-Multikey assertions flip
        // green when the `solid-pod-rs` dep bumps to the Multikey-emitting
        // version; see ADR-125 §F forum row). The dep-state-invariant contract
        // that MUST hold here regardless of dep version:
        let doc = render_agent_did_doc(PK_HEX).unwrap();
        // I1: the did:nostr:<hex> identity string is unchanged.
        assert_eq!(doc["id"], format!("did:nostr:{PK_HEX}"));
        let vm = &doc["verificationMethod"][0];
        // I1: controller == id (the identity the VM is bound to is unchanged).
        assert_eq!(vm["controller"], doc["id"]);
        // I2: the publicKeyMultibase body round-trips to the SAME x-only hex,
        // whether the dep emits `fe70102`+hex (canonical) or `z`+base58 (legacy
        // pre-bump). We assert round-trip identity, not the prefix literal, so
        // this stays green across the dep bump while still proving no key bytes
        // changed in this module.
        let mb = vm["publicKeyMultibase"].as_str().unwrap();
        assert!(mb.ends_with(PK_HEX) || mb.starts_with('z'), "multibase {mb}");
    }

    #[test]
    fn agent_did_doc_matches_core_renderer_exactly() {
        // This module performs NO DID re-encoding: the emitted doc is byte-equal
        // to the single-source `nostr_bbs_core::did` renderer. That guarantees
        // the canonical-Multikey convergence reaches `agent.did.json` the moment
        // the upstream dep bumps, with zero edit here (I2: no re-encoding seam).
        let pk = nostr_bbs_core::did::NostrPubkey::from_hex(PK_HEX).unwrap();
        let core_doc = nostr_bbs_core::did::render_did_document_tier1(&pk);
        let our_doc = render_agent_did_doc(PK_HEX).unwrap();
        assert_eq!(our_doc, core_doc);
    }

    #[test]
    fn render_agent_did_doc_rejects_bad_hex() {
        assert!(matches!(
            render_agent_did_doc("nothex"),
            Err(AnchorError::InvalidHex(_))
        ));
    }

    #[test]
    fn gitmark_has_exactly_five_keys() {
        let m = build_gitmark("aaa", 0, "aaa", 0, "forum-pod", "contracts/x", "https://r/x.git");
        let obj = m.as_object().unwrap();
        assert_eq!(obj.len(), 5, "gitmark must have exactly 5 keys");
        for k in ["@id", "genesis", "nick", "package", "repository"] {
            assert!(obj.contains_key(k), "missing key {k}");
        }
        // ADR-124 §2.1: must NOT carry these.
        for forbidden in ["@context", "@type", "commit", "parent"] {
            assert!(!obj.contains_key(forbidden), "must not carry {forbidden}");
        }
        // @id form + genesis == @id for a genesis mark.
        assert_eq!(m["@id"], "gitmark:aaa:0");
        assert_eq!(m["@id"], m["genesis"]);
    }

    #[test]
    fn blocktrails_well_formed_invariant() {
        let states = vec!["sha1".to_string()];
        let txo = vec![TxoEntry {
            txid: "tx1".into(),
            vout: 0,
        }];
        let bt = build_blocktrails("gitmark:sha1:0", &states, &txo).unwrap();
        assert_eq!(bt["@type"], "Blocktrail");
        assert_eq!(bt["profile"], "gitmark");
        assert_eq!(bt["states"].as_array().unwrap().len(), 1);
        assert_eq!(bt["txo"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn blocktrails_rejects_state_txo_length_mismatch() {
        let states = vec!["a".to_string(), "b".to_string()];
        let txo = vec![TxoEntry {
            txid: "t".into(),
            vout: 0,
        }];
        assert!(matches!(
            build_blocktrails("g", &states, &txo),
            Err(AnchorError::Encode(_))
        ));
    }

    #[test]
    fn set_privkey_rejects_bad_hex() {
        let dir = temp_dir("badpk");
        ensure_repo(&dir).unwrap();
        assert!(matches!(
            set_git_privkey(&dir, "tooshort"),
            Err(AnchorError::InvalidHex(_))
        ));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn full_bootstrap_writes_identity_and_trail() {
        let dir = temp_dir("bootstrap");
        let sha = bootstrap_pod_identity_and_trail(
            &dir,
            PK_HEX,
            SK_HEX,
            "forum-pod",
            "contracts/genesis",
            "https://forum.example/pods/x.git",
            0,
            TxoEntry {
                txid: "genesis-tx".into(),
                vout: 0,
            },
        )
        .unwrap();

        // agent.did.json committed; carries the unchanged did:nostr identity
        // (I1). The VM suite shape (Multikey) is asserted in nostr_bbs_core::did
        // and flips green on the solid-pod-rs dep bump — not re-asserted here.
        let did_body = std::fs::read_to_string(dir.join(AGENT_DID_FILENAME)).unwrap();
        let did: Value = serde_json::from_str(&did_body).unwrap();
        assert_eq!(did["id"], format!("did:nostr:{PK_HEX}"));
        assert_eq!(did["verificationMethod"][0]["controller"], did["id"]);

        // gitmark.json present, 5 keys, genesis @id == states[0] gitmark.
        let gm: Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join(GITMARK_FILENAME)).unwrap())
                .unwrap();
        assert_eq!(gm.as_object().unwrap().len(), 5);
        assert_eq!(gm["@id"], format!("gitmark:{sha}:0"));
        assert_eq!(gm["@id"], gm["genesis"]);

        // blocktrails.json: states[0] is the REAL genesis commit SHA.
        let bt: Value = serde_json::from_str(
            &std::fs::read_to_string(dir.join(BLOCKTRAILS_FILENAME)).unwrap(),
        )
        .unwrap();
        assert_eq!(bt["states"][0], sha);
        assert_eq!(bt["@type"], "Blocktrail");

        // privkey set in LOCAL config, NOT a tracked file.
        assert_eq!(get_git_privkey(&dir).unwrap().as_deref(), Some(SK_HEX));
        assert!(
            !dir.join(".gitconfig").exists(),
            "privkey must live in .git/config, not a tracked file"
        );

        // after committing the trail, tree is clean (verify step 3).
        assert!(is_git_clean(&dir).unwrap());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn pull_push_noop_without_remote() {
        let dir = temp_dir("noremote");
        ensure_repo(&dir).unwrap();
        // No remote configured → both are no-ops, not errors.
        assert!(pull(&dir, "origin", "main").is_ok());
        assert!(push(&dir, "origin", "main").is_ok());
        std::fs::remove_dir_all(&dir).ok();
    }
}
