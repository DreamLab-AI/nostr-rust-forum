//! The binary's refusals that happen before any network or model access.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;

fn dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("nbss-cli-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn write(path: &PathBuf, text: &str, mode: u32) {
    std::fs::write(path, text).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn run(args: &[&str]) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_nostr-bbs-search-build"))
        .args(args)
        .env("NOSTR_BBS_MIGRATE_KEY", "7f".repeat(32))
        .output()
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

#[test]
fn a_zone_key_file_readable_by_others_is_refused() {
    let d = dir("keys");
    let keys = d.join("keys.json");
    write(&keys, r#"{"version":1,"owner":"","keys":[]}"#, 0o644);
    let (code, err) = run(&[
        "update",
        "--zone",
        "zone2",
        "--relay-url",
        "wss://r",
        "--pod-dir",
        d.to_str().unwrap(),
        "--keys-file",
        keys.to_str().unwrap(),
        "--from-events",
        d.join("none.jsonl").to_str().unwrap(),
        "--state",
        d.join("s.json").to_str().unwrap(),
    ]);
    assert_eq!(code, 2, "{err}");
    assert!(err.contains("keys file") && err.contains("600"), "{err}");
    std::fs::remove_dir_all(&d).unwrap();
}

#[test]
fn dump_vectors_is_refused_for_rows_read_from_a_relay_or_export() {
    let d = dir("dump");
    let (code, err) = run(&[
        "--zone",
        "zone2",
        "--relay-url",
        "wss://r",
        "--from-events",
        d.join("none.jsonl").to_str().unwrap(),
        "--dry-run",
        "--out",
        d.join("out").to_str().unwrap(),
        "--dump-vectors",
        d.join("v.bin").to_str().unwrap(),
    ]);
    assert_eq!(code, 2, "{err}");
    assert!(err.contains("--dump-vectors"), "{err}");
    std::fs::remove_dir_all(&d).unwrap();
}
