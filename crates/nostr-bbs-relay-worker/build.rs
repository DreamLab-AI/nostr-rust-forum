//! Schema fingerprint for the once-per-deploy schema gate (`schema_gate` in
//! `src/lib.rs`).
//!
//! Hashes every source file of this crate, its migrations and the replay
//! schema it also bootstraps. Any change yields a new fingerprint, so the first
//! request after a deploy that changed the code re-runs the idempotent schema
//! pass once; every other new isolate only reads the stored fingerprint.

use std::fs;
use std::path::{Path, PathBuf};

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(&path, out);
        } else if matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("rs") | Some("sql")
        ) {
            out.push(path);
        }
    }
}

/// FNV-1a, 64-bit: a change detector, not a security boundary.
fn fnv1a(hash: &mut u64, bytes: &[u8]) {
    for b in bytes {
        *hash ^= u64::from(*b);
        *hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
}

fn main() {
    let root = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let replay = root.join("../nostr-bbs-rate-limit/src/replay.rs");
    let mut files = Vec::new();
    collect(&root.join("src"), &mut files);
    collect(&root.join("migrations"), &mut files);
    if replay.exists() {
        files.push(replay.clone());
    }
    files.sort();
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for f in &files {
        let rel = f.strip_prefix(&root).unwrap_or(f);
        fnv1a(&mut hash, rel.to_string_lossy().as_bytes());
        if let Ok(bytes) = fs::read(f) {
            fnv1a(&mut hash, &bytes);
        }
    }
    println!("cargo:rustc-env=RELAY_SCHEMA_FINGERPRINT={hash:016x}");
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=migrations");
    println!("cargo:rerun-if-changed={}", replay.display());
}
