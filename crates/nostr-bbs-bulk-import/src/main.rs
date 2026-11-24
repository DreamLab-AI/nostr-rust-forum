//! `nostr-bbs-import`: the bulk-import CLI. See the library docs and
//! `docs/bulk-import/README.md`.
//!
//! The binary is native-only; on wasm32 it compiles to an empty `main` so
//! the workspace-wide wasm32 check still covers the library.

#[cfg(not(target_arch = "wasm32"))]
mod cli {
    use std::path::{Path, PathBuf};
    use std::process::ExitCode;

    use clap::{Parser, Subcommand, ValueEnum};
    use nostr_bbs_bulk_import::adapter::{
        self, generic::GenericAdapter, keybase::KeybaseAdapter, SourceAdapter,
    };
    use nostr_bbs_bulk_import::events::Emit;
    use nostr_bbs_bulk_import::identity::{link_statement, OPERATOR};
    use nostr_bbs_bulk_import::keystore::{Keystore, Role};
    use nostr_bbs_bulk_import::media::{self, Magick};
    use nostr_bbs_bulk_import::pipeline::{self, BuildOptions, Phase, Work};
    use nostr_bbs_bulk_import::ImportError;
    use serde_json::json;

    #[derive(Parser)]
    #[command(
        name = "nostr-bbs-import",
        version,
        about = "Offline bulk import of an external chat archive into a nostr-bbs forum deployment.",
        after_help = "Runbook: docs/bulk-import/README.md. Nothing here makes a network call; remote steps are written as plans."
    )]
    struct Cli {
        #[command(subcommand)]
        cmd: Cmd,
    }

    #[derive(Clone, Copy, ValueEnum)]
    enum Source {
        /// The intermediate format itself (validate and normalise).
        Generic,
        /// A Keybase team archive (keybase-port archiver layout).
        Keybase,
    }

    #[derive(Clone, Copy, ValueEnum)]
    enum PhaseArg {
        Built,
        Sealed,
        Purged,
    }

    #[derive(Clone, Copy, ValueEnum)]
    enum RetireRole {
        Archive,
        Fresh,
        Archivist,
    }

    #[derive(Subcommand)]
    enum KeysCmd {
        /// Generate the keys the plan needs (existing keys are never changed).
        Ensure,
        /// Record the operator's PUBLIC key from its 0600 key file (the secret is never stored).
        Import {
            /// The operator's key file (64 hex or nsec, mode 0600).
            #[arg(long)]
            from: PathBuf,
        },
        /// Drop secrets, keeping public keys (irreversible).
        Retire {
            /// One label.
            #[arg(long, conflicts_with = "role")]
            label: Option<String>,
            /// Every key of a role.
            #[arg(long, value_enum)]
            role: Option<RetireRole>,
        },
        /// Write one secret to a NEW 0600 file (for NOSTR_BBS_MIGRATE_KEY="$(cat FILE)").
        Export {
            /// Keystore label (normally `archivist`).
            #[arg(long)]
            label: String,
            /// Output file (must not exist).
            #[arg(long)]
            out: PathBuf,
        },
        /// List labels, roles and public keys (never secrets).
        List,
    }

    #[derive(Subcommand)]
    enum Cmd {
        /// Convert a source export into the intermediate format at WORK/archive.
        Adapt {
            /// Source type.
            #[arg(value_enum)]
            source: Source,
            /// The export to read.
            #[arg(long = "in")]
            input: PathBuf,
            /// The work directory.
            #[arg(long)]
            work: PathBuf,
            /// Export name recorded in the manifest (team, guild); default: the input directory name.
            #[arg(long)]
            source_id: Option<String>,
        },
        /// Write identities.json / structure.json templates if absent, else validate and print the plan.
        Plan {
            #[arg(long)]
            work: PathBuf,
            /// Zone id for the structure template.
            #[arg(long, default_value = "zone1")]
            zone: String,
        },
        /// Key management.
        Keys {
            #[arg(long, global = true)]
            work: Option<PathBuf>,
            #[command(subcommand)]
            cmd: KeysCmd,
        },
        /// Print the text a live key signs to prove it belongs to an author.
        LinkStatement {
            #[arg(long)]
            work: PathBuf,
            /// Source author id.
            #[arg(long)]
            author: String,
        },
        /// Optimise every image attachment into WORK/media (ImageMagick).
        Media {
            #[arg(long)]
            work: PathBuf,
            /// The magick binary.
            #[arg(long, default_value = "magick")]
            magick: PathBuf,
        },
        /// Sign and write the plan into the local D1 (stack DOWN).
        Build {
            #[arg(long)]
            work: PathBuf,
            /// The relay's D1 SQLite file.
            #[arg(long)]
            d1: PathBuf,
            /// Import only the deferred operator messages.
            #[arg(long)]
            deferred_only: bool,
            /// Write placeholders for images without processed media.
            #[arg(long)]
            allow_missing_media: bool,
            /// The operator's 0600 key file (runs that sign operator messages).
            #[arg(long)]
            operator_key: Option<PathBuf>,
            /// LABEL=FILE: unlock a retired key for this run only (repeatable).
            #[arg(long = "key", value_name = "LABEL=FILE", value_parser = parse_unlock)]
            unlock: Vec<(String, PathBuf)>,
        },
        /// Copy and re-wrap DMs into the local D1 (stack DOWN).
        Dm {
            #[arg(long)]
            work: PathBuf,
            #[arg(long)]
            d1: PathBuf,
            /// Accept that zone-key grants among the wraps travel too.
            #[arg(long)]
            allow_stale_grants: bool,
            /// The operator's OLD key file (0600): re-wrap the DMs it sent to the current operator key.
            #[arg(long)]
            rewrap_old_key: Option<PathBuf>,
        },
        /// Write seal/channels.json and seal/RUNBOOK.md and check the sealing preconditions.
        SealPrep {
            #[arg(long)]
            work: PathBuf,
            #[arg(long)]
            d1: PathBuf,
            /// The LOCAL relay's ws URL (loopback only).
            #[arg(long)]
            relay: String,
        },
        /// Write search/docs.jsonl for nostr-bbs-search-build (after seal commit, BEFORE purge).
        SearchInput {
            #[arg(long)]
            work: PathBuf,
            #[arg(long)]
            d1: PathBuf,
        },
        /// Check the parity invariants for a phase.
        VerifyParity {
            #[arg(long)]
            work: PathBuf,
            #[arg(long)]
            d1: PathBuf,
            #[arg(long, value_enum)]
            phase: PhaseArg,
        },
        /// Rewrite the D1 file so purged plaintext does not linger (stack DOWN).
        Scrub {
            #[arg(long)]
            d1: PathBuf,
        },
        /// Write WORK/upload: allowlisted dump, object list, quota SQL, runbook (never run).
        UploadPlan {
            #[arg(long)]
            work: PathBuf,
            #[arg(long)]
            d1: PathBuf,
            /// nostr-bbs-search-build --dry-run --out directory to include.
            #[arg(long)]
            search_out: Option<PathBuf>,
            /// The deployment's POD_QUOTA_MB (warns above it).
            #[arg(long, default_value_t = 50)]
            pod_quota_mb: u64,
        },
        /// Apply WORK/upload's dump twice to a fresh booted D1 and compare with the source.
        UploadRehearse {
            #[arg(long)]
            work: PathBuf,
            /// The built (source) D1.
            #[arg(long)]
            d1: PathBuf,
            /// A fresh D1 with the relay migrations applied and the relay booted once.
            #[arg(long)]
            fresh_d1: PathBuf,
        },
    }

    fn parse_unlock(s: &str) -> Result<(String, PathBuf), String> {
        let (l, f) = s.split_once('=').ok_or("expected LABEL=FILE")?;
        if l.is_empty() || f.is_empty() {
            return Err("expected LABEL=FILE".into());
        }
        Ok((l.to_string(), PathBuf::from(f)))
    }

    fn need(work: &Option<PathBuf>) -> Result<Work, ImportError> {
        work.as_deref()
            .map(Work::new)
            .ok_or_else(|| ImportError::Plan("--work is required".into()))
    }

    fn run(cli: Cli) -> Result<(serde_json::Value, bool), ImportError> {
        Ok(match cli.cmd {
            Cmd::Adapt {
                source,
                input,
                work,
                source_id,
            } => {
                let w = Work::new(&work);
                nostr_bbs_bulk_import::fsutil::create_private_dir(&w.dir)?;
                let id = source_id.unwrap_or_else(|| {
                    input
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("archive")
                        .to_string()
                });
                let a: &dyn SourceAdapter = match source {
                    Source::Generic => &GenericAdapter,
                    Source::Keybase => &KeybaseAdapter,
                };
                let (archive, report) = adapter::run(a, &input, &id, &w.archive())?;
                (
                    json!({"manifest": archive.manifest, "report": report}),
                    true,
                )
            }
            Cmd::Plan { work, zone } => {
                let w = Work::new(&work);
                if !w.identities().exists() || !w.structure().exists() {
                    if w.identities().exists() || w.structure().exists() {
                        return Err(ImportError::Refused("only one of identities.json / structure.json exists; remove it or write the other".into()));
                    }
                    pipeline::write_templates(&w, &zone)?;
                    (
                        json!({"templates": [w.identities(), w.structure()], "next": "edit both, add target.json, then run plan again"}),
                        true,
                    )
                } else {
                    let l = pipeline::load(&w)?;
                    let labels: Vec<String> = pipeline::needed_labels(&l).into_keys().collect();
                    (
                        json!({"stats": l.plan.stats, "keys_needed": labels, "operator_deferred": l.ids.operator_deferred}),
                        true,
                    )
                }
            }
            Cmd::Keys { work, cmd } => {
                let w = need(&work)?;
                match cmd {
                    KeysCmd::Ensure => {
                        let l = pipeline::load(&w)?;
                        let created = pipeline::ensure_keys(&w, &l)?;
                        (json!({"created": created}), true)
                    }
                    KeysCmd::Import { from } => {
                        let mut ks = Keystore::load(&w.keys())?;
                        let pk = ks.import_operator(OPERATOR, &from)?.pk.clone();
                        ks.save()?;
                        (json!({"operator": pk, "stored": "public key only"}), true)
                    }
                    KeysCmd::Retire { label, role } => {
                        let mut ks = Keystore::load(&w.keys())?;
                        let labels: Vec<String> = match (label, role) {
                            (Some(l), _) => vec![l],
                            (None, Some(r)) => {
                                let want = match r {
                                    RetireRole::Archive => Role::Archive,
                                    RetireRole::Fresh => Role::Fresh,
                                    RetireRole::Archivist => Role::Archivist,
                                };
                                ks.labels()
                                    .filter(|l| ks.get(l).is_some_and(|e| e.role == want))
                                    .map(str::to_string)
                                    .collect()
                            }
                            (None, None) => {
                                return Err(ImportError::Plan("pass --label or --role".into()))
                            }
                        };
                        for l in &labels {
                            ks.retire(l)?;
                        }
                        ks.save()?;
                        (json!({"retired": labels}), true)
                    }
                    KeysCmd::Export { label, out } => {
                        Keystore::load(&w.keys())?.export(&label, &out)?;
                        (
                            json!({"written": out, "mode": "0600", "next": "NOSTR_BBS_MIGRATE_KEY=\"$(cat FILE)\" <command>; then shred -u FILE"}),
                            true,
                        )
                    }
                    KeysCmd::List => {
                        let ks = Keystore::load(&w.keys())?;
                        let rows: Vec<_> = ks
                            .labels()
                            .filter_map(|l| ks.get(l).map(|e| json!({"label": l, "role": e.role, "pk": e.pk, "has_secret": e.has_secret(), "retired_at": e.retired_at})))
                            .collect();
                        (json!({"keys": rows}), true)
                    }
                }
            }
            Cmd::LinkStatement { work, author } => {
                let a = nostr_bbs_bulk_import::format::Archive::open(&Work::new(&work).archive())?;
                if !a.authors.iter().any(|x| x.id == author) {
                    return Err(ImportError::Plan(format!("unknown author {author:?}")));
                }
                let prov = format!("{}:{}", a.manifest.source, a.manifest.source_id);
                (
                    json!({"sign_this_content": link_statement(&prov, &author)}),
                    true,
                )
            }
            Cmd::Media { work, magick } => {
                let w = Work::new(&work);
                let a = nostr_bbs_bulk_import::format::Archive::open(&w.archive())?;
                let m = Magick::new(&magick, &w.dir)?;
                let (_, report) = media::process_archive(&a, &m, &w.media())?;
                let ok = report.failed == 0;
                (json!({"report": report}), ok)
            }
            Cmd::Build {
                work,
                d1,
                deferred_only,
                allow_missing_media,
                operator_key,
                unlock,
            } => {
                let r = pipeline::build(
                    &Work::new(&work),
                    &BuildOptions {
                        d1,
                        emit: if deferred_only {
                            Emit::DeferredOnly
                        } else {
                            Emit::Normal
                        },
                        require_media: !allow_missing_media,
                        operator_key,
                        unlock,
                    },
                )?;
                (json!({"report": r}), true)
            }
            Cmd::Dm {
                work,
                d1,
                allow_stale_grants,
                rewrap_old_key,
            } => (
                pipeline::import_dms(
                    &Work::new(&work),
                    &d1,
                    allow_stale_grants,
                    rewrap_old_key.as_deref(),
                )?,
                true,
            ),
            Cmd::SealPrep { work, d1, relay } => {
                let p = pipeline::seal_prep(&Work::new(&work), &d1, &relay)?;
                let ok = p.missing.is_empty();
                (
                    json!({"channels": p.channels, "missing": p.missing, "runbook": Work::new(&work).seal().join("RUNBOOK.md")}),
                    ok,
                )
            }
            Cmd::SearchInput { work, d1 } => {
                let n = pipeline::search_input(&Work::new(&work), &d1)?;
                (
                    json!({"rows": n, "file": Work::new(&work).search().join("docs.jsonl"), "next": "nostr-bbs-search-build --dry-run --out DIR --relay-url <NEW relay ws URL> …; then delete docs.jsonl"}),
                    true,
                )
            }
            Cmd::VerifyParity { work, d1, phase } => {
                let ph = match phase {
                    PhaseArg::Built => Phase::Built,
                    PhaseArg::Sealed => Phase::Sealed,
                    PhaseArg::Purged => Phase::Purged,
                };
                let r = pipeline::verify_parity(&Work::new(&work), &d1, ph)?;
                let ok = r.problems.is_empty();
                (json!({"report": r}), ok)
            }
            Cmd::Scrub { d1 } => {
                pipeline::scrub(&d1)?;
                (json!({"scrubbed": d1}), true)
            }
            Cmd::UploadPlan {
                work,
                d1,
                search_out,
                pod_quota_mb,
            } => {
                let r = pipeline::upload_plan(
                    &Work::new(&work),
                    &d1,
                    search_out.as_deref(),
                    pod_quota_mb,
                )?;
                (json!({"report": r, "dir": Work::new(&work).upload()}), true)
            }
            Cmd::UploadRehearse { work, d1, fresh_d1 } => {
                rehearse(&Work::new(&work), &d1, &fresh_d1)?
            }
        })
    }

    fn rehearse(
        w: &Work,
        src: &Path,
        fresh: &Path,
    ) -> Result<(serde_json::Value, bool), ImportError> {
        let mut chunks: Vec<PathBuf> = std::fs::read_dir(w.upload())
            .map_err(|e| ImportError::io(&w.upload(), e))?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("data-") && n.ends_with(".sql"))
            })
            .collect();
        chunks.sort();
        let c = nostr_bbs_bulk_import::d1::open_rw(fresh)?;
        nostr_bbs_bulk_import::d1::check_schema(&c)?;
        let before: i64 = c.query_row("SELECT count(*) FROM events", [], |r| r.get(0))?;
        if before != 0 {
            return Err(ImportError::Refused(format!(
                "{} is not fresh ({before} events)",
                fresh.display()
            )));
        }
        pipeline::apply_dump(&c, &chunks)?;
        pipeline::apply_dump(&c, &chunks)?; // twice: every chunk must be idempotent
        let want = pipeline::table_counts(&nostr_bbs_bulk_import::d1::open_ro(src)?)?;
        let got = pipeline::table_counts(&c)?;
        let diff: Vec<String> = want
            .iter()
            .filter(|(k, v)| got.get(*k) != Some(v))
            .map(|(k, v)| {
                format!(
                    "{k}: source {v}, rehearsal {}",
                    got.get(k).copied().unwrap_or(-1)
                )
            })
            .collect();
        let ok = diff.is_empty();
        Ok((
            json!({"source": want, "rehearsal": got, "differences": diff}),
            ok,
        ))
    }

    pub fn main() -> ExitCode {
        let cli = Cli::parse();
        match run(cli) {
            Ok((out, ok)) => {
                println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
                if ok {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::from(2)
                }
            }
            Err(e) => {
                eprintln!("nostr-bbs-import: {e}");
                ExitCode::from(match e {
                    ImportError::Refused(_) => 3,
                    _ => 1,
                })
            }
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn main() -> std::process::ExitCode {
    cli::main()
}

#[cfg(target_arch = "wasm32")]
fn main() {}
