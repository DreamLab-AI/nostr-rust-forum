//! ADR-2014 phase 1 guards over the `whitelist` table.
//!
//! The cohort semantics themselves (a grant merges, a revoke removes only what
//! it names) are tested against a real SQLite in `nostr-bbs-core`'s
//! `whitelist_sql` module. These tests hold the rest of the tree to them:
//!
//! - no writer in any crate carries its own cohort-replacing upsert, so the
//!   shared statements are the only way cohorts get written;
//! - the checked-in migration and the DDL `ensure_schema()` runs are the same.

use std::fs;
use std::path::{Path, PathBuf};

use nostr_bbs_core::whitelist_sql::WHITELIST_CREATE_SQL;

fn crates_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/")
        .to_path_buf()
}

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("read_dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Every `.rs` file under `crates/*/src`.
fn all_sources() -> Vec<PathBuf> {
    let mut out = Vec::new();
    for krate in fs::read_dir(crates_dir()).expect("crates/") {
        let src = krate.expect("crate entry").path().join("src");
        if src.is_dir() {
            rust_sources(&src, &mut out);
        }
    }
    assert!(
        out.len() > 50,
        "source walk found too little: {}",
        out.len()
    );
    out
}

/// Collapse whitespace and drop SQL `--` comments, a trailing `;` and the
/// spaces SQLite ignores beside punctuation, so formatting differences between
/// a `.sql` file and a Rust string literal do not matter.
fn normalise_sql(sql: &str) -> String {
    let stripped: String = sql
        .lines()
        .map(|l| l.split("--").next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join(" ");
    let collapsed = stripped.split_whitespace().collect::<Vec<_>>().join(" ");
    collapsed
        .trim_end_matches(';')
        .replace("( ", "(")
        .replace(" )", ")")
        .replace(" ,", ",")
}

#[test]
fn no_writer_replaces_a_members_cohorts() {
    let shared = Path::new("nostr-bbs-core/src/whitelist_sql.rs");
    let mut offenders = Vec::new();
    for path in all_sources() {
        if path.ends_with(shared) {
            continue;
        }
        let text = fs::read_to_string(&path).expect("read source");
        for (i, line) in text.lines().enumerate() {
            let code = line.trim_start();
            if code.starts_with("//") {
                continue;
            }
            // The replace idiom every pre-ADR-2014 writer used.
            if code.contains("cohorts = excluded.cohorts") {
                offenders.push(format!("{}:{}", path.display(), i + 1));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "cohort-replacing upsert outside nostr_bbs_core::whitelist_sql \
         (use WHITELIST_GRANT_COHORTS_SQL): {offenders:?}"
    );
}

#[test]
fn every_set_cohorts_update_is_accounted_for() {
    // A bare `UPDATE whitelist SET cohorts = ?` writes whatever the worker
    // computed. The only one allowed outside the shared module is the invite
    // zone grant, which binds a Rust-side merge of the stored set.
    let allowed = [
        Path::new("nostr-bbs-core/src/whitelist_sql.rs"),
        Path::new("nostr-bbs-auth-worker/src/invites.rs"),
    ];
    let mut offenders = Vec::new();
    for path in all_sources() {
        if allowed.iter().any(|a| path.ends_with(a)) {
            continue;
        }
        let text = fs::read_to_string(&path).expect("read source");
        if text.contains("UPDATE whitelist SET cohorts") {
            offenders.push(path.display().to_string());
        }
    }
    assert!(
        offenders.is_empty(),
        "unreviewed cohort writer: {offenders:?}"
    );
}

#[test]
fn migration_0008_matches_the_ddl_ensure_schema_runs() {
    let migration = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations/0008_whitelist.sql"),
    )
    .expect("migrations/0008_whitelist.sql");
    assert_eq!(
        normalise_sql(&migration),
        normalise_sql(WHITELIST_CREATE_SQL)
    );
}

#[test]
fn ensure_schema_creates_the_table_before_altering_it() {
    let lib = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs"))
        .expect("src/lib.rs");
    let create = lib
        .find("db.prepare(WHITELIST_CREATE_SQL)")
        .expect("ensure_schema runs WHITELIST_CREATE_SQL");
    let first_alter = lib
        .find("ALTER TABLE whitelist ADD COLUMN")
        .expect("whitelist ALTER list");
    assert!(create < first_alter, "CREATE must precede the ALTERs");
    assert!(
        lib.contains("\"ALTER TABLE whitelist ADD COLUMN expires_at INTEGER\""),
        "an existing table must gain expires_at"
    );
}
