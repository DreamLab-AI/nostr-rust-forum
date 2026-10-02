//! Guard: a `/pay/` balance can only rise through the evidence journal.
//!
//! ADR-2012 D6 (b72dbe6) removed `POST /pay/.deposit {"amount_sats": n}`,
//! which credited `n` on the caller's word. The behavioural tests in
//! `src/pay_ledger/tests.rs` prove today's routes refuse a forged amount;
//! this test stops the pattern coming back by another door. It scans every
//! source file in the workspace (Rust, SQL, TypeScript, JavaScript) that can
//! reach the shared D1 and asserts:
//!
//! 1. exactly one statement inserts into `webledger_accounts`, and it is
//!    `SQL_APPLY_CREDIT` in `pay_ledger.rs`, which takes the account and the
//!    amount from a `pay_credits` row (whose CHECK demands an outpoint or a
//!    signed-request id) rather than from a parameter;
//! 2. exactly one statement raises `balance_sats`, the same one;
//! 3. nothing assigns `balance_sats` from a bound parameter.
//!
//! Test fixtures (`tests.rs`, `tests/`) are skipped: they build pre-journal
//! databases on purpose.

use std::fs;
use std::path::{Path, PathBuf};

/// The ledger module, the only file allowed to write a balance.
const LEDGER: &str = "crates/nostr-bbs-pod-worker/src/pay_ledger.rs";

/// The journal clause `SQL_APPLY_CREDIT` must read its amount from.
const FROM_JOURNAL: &str = "frompay_creditswherecredit_ref=?1andapplied=0";

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate sits at <root>/crates/<name>")
        .to_path_buf()
}

fn is_fixture(path: &Path) -> bool {
    path.file_name().is_some_and(|n| n == "tests.rs")
        || path.components().any(|c| c.as_os_str() == "tests")
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if !matches!(name.as_ref(), "target" | "node_modules" | "pkg" | "dist") {
                collect(&path, out);
            }
        } else if matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("rs" | "sql" | "ts" | "js" | "mjs")
        ) && !is_fixture(&path)
        {
            out.push(path);
        }
    }
}

/// Lower-cased with whitespace, Rust line-continuation backslashes and
/// string quotes removed, so SQL split across literals still matches.
fn squash(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_whitespace() && *c != '\\' && *c != '"')
        .flat_map(char::to_lowercase)
        .collect()
}

fn occurrences<'a>(files: &'a [(String, String)], needle: &str) -> Vec<(&'a str, usize)> {
    files
        .iter()
        .flat_map(|(rel, text)| {
            text.match_indices(needle)
                .map(move |(at, _)| (rel.as_str(), at))
        })
        .collect()
}

fn sources() -> Vec<(String, String)> {
    let root = workspace_root();
    let mut paths = Vec::new();
    collect(&root.join("crates"), &mut paths);
    assert!(
        paths.iter().any(|p| p.ends_with(LEDGER)),
        "scan did not reach {LEDGER}; the guard is looking in the wrong place"
    );
    paths
        .into_iter()
        .filter_map(|p| {
            let text = fs::read_to_string(&p).ok()?;
            let rel = p
                .strip_prefix(&root)
                .unwrap_or(&p)
                .to_string_lossy()
                .replace('\\', "/");
            Some((rel, squash(&text)))
        })
        .collect()
}

#[test]
fn only_the_journal_inserts_an_account_balance() {
    let files = sources();
    let hits = occurrences(&files, "insertintowebledger_accounts");
    assert_eq!(
        hits.iter().map(|(f, _)| *f).collect::<Vec<_>>(),
        vec![LEDGER],
        "a balance row may be created only by SQL_APPLY_CREDIT in {LEDGER}"
    );
    let (_, at) = hits[0];
    let ledger = &files.iter().find(|(f, _)| f == LEDGER).expect("ledger").1;
    let stmt_end = ledger[at..].find(';').map_or(ledger.len(), |e| at + e);
    assert!(
        ledger[at..stmt_end].contains(FROM_JOURNAL),
        "the balance insert must read did and amount from an unapplied pay_credits row"
    );
}

#[test]
fn only_the_journal_raises_a_balance() {
    let files = sources();
    let raises = occurrences(&files, "balance_sats=balance_sats+");
    assert_eq!(
        raises.iter().map(|(f, _)| *f).collect::<Vec<_>>(),
        vec![LEDGER],
        "a balance may rise only through SQL_APPLY_CREDIT in {LEDGER}"
    );
    let ledger = &files.iter().find(|(f, _)| f == LEDGER).expect("ledger").1;
    let (_, at) = raises[0];
    assert!(
        ledger[at..].starts_with("balance_sats=balance_sats+excluded.balance_sats"),
        "the one raise must add the journalled amount (excluded.balance_sats), not a parameter"
    );
}

#[test]
fn no_balance_is_assigned_from_a_parameter() {
    let files = sources();
    for needle in [
        "balance_sats=?",
        "balance_sats+?",
        "balance_sats=:",
        "balance_sats=$",
    ] {
        let hits = occurrences(&files, needle);
        assert!(
            hits.is_empty(),
            "`{needle}` sets a balance from caller-supplied input: {hits:?}"
        );
    }
}
