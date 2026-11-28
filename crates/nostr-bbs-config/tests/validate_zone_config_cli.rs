//! The `validate-zone-config` command (ADR-2037): exit codes and messages.

use std::process::Command;

const PIN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn run(json: &str) -> (i32, String) {
    let dir = std::env::temp_dir().join(format!("vzc-{}-{}", std::process::id(), json.len()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("zone-config.json");
    std::fs::write(&path, json).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_validate-zone-config"))
        .arg(&path)
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr),
    )
}

#[test]
fn well_formed_pins_pass() {
    let (code, out) = run(&format!(
        r#"[{{"id":"open"}},{{"id":"staff","channels":["{PIN}"]}}]"#
    ));
    assert_eq!(code, 0, "{out}");
}

#[test]
fn bad_pins_fail_with_a_message() {
    for (json, want) in [
        (
            format!(r#"[{{"id":"staff","channel":["{PIN}"]}}]"#),
            "did you mean",
        ),
        (
            r#"[{"id":"staff","channels":["abc"]}]"#.to_string(),
            "64-char",
        ),
        (
            format!(r#"[{{"id":"staff","channels":"{PIN}"}}]"#),
            "ZONE_CONFIG zone",
        ),
        (
            format!(r#"[{{"id":"a","channels":["{PIN}"]}},{{"id":"b","channels":["{PIN}"]}}]"#),
            "pinned by both",
        ),
        ("not json".to_string(), "not valid JSON"),
    ] {
        let (code, out) = run(&json);
        assert_eq!(code, 1, "{json}: {out}");
        assert!(out.contains(want), "{json}: {out}");
    }
}

#[test]
fn a_missing_file_is_exit_2() {
    let out = Command::new(env!("CARGO_BIN_EXE_validate-zone-config"))
        .arg("/nonexistent/zone-config.json")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
}
