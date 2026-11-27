//! `nostr-bbs-search-build`: build, update, compact and upload a zone's
//! sealed search index (sealed-search design §8 and Phase 2).
//!
//! ```text
//! # Full build (a new base): rows from a file, or read from the relay.
//! nostr-bbs-search-build --zone zone2 --input docs.jsonl | --from-relay wss://… \
//!     --keys-file keys.json | --fetch-grants [--relay wss://…] \
//!     --model-dir work/models/bge-small-en-v1.5 --model-q8 stack/models/bge-small-en-v1.5-q8_0.gguf \
//!     --relay-url wss://… --publishers "<archivist>,<admin>,<indexer>" \
//!     --pod https://… | --pod-dir DIR  [--state zone2.json] [--dry-run --out DIR]
//! # Incremental update: new posts since the state's high-water mark.
//! nostr-bbs-search-build update  --zone zone2 --from-relay wss://… --state zone2.json [--cache-dir DIR] …
//! # Fold update shards (or everything, --all) into fresh shards.
//! nostr-bbs-search-build compact --zone zone2 --from-relay wss://… --state zone2.json [--all] …
//! # The newest index on the pods, or one field of it.
//! nostr-bbs-search-build status  --zone zone2 [--field partial_pairs] …
//! # Browser model (GGUF Q8_0) + vocab.
//! nostr-bbs-search-build model-q8 --model-dir … --out DIR
//! ```
//!
//! Input rows (JSONL, `--input`): `{"id": <event id hex>, "text": <plaintext>,
//! "epoch": u32, "zone_pk": <hex>}`; ids in `--exclude` are skipped. With
//! `--from-relay` (or `--from-events`, a NIP-01 JSONL export of the zone's
//! events) the rows are read and opened in memory, never written.
//!
//! The publisher key comes from `NOSTR_BBS_MIGRATE_KEY` or `--key-file` (a
//! file only its owner can read), never from argv. Zone keys come from
//! zone-migrate's key file or the publisher's own grants. Embeddings are
//! computed locally (FP32 candle).
//!
//! Exit codes: 0 done (published, or nothing new); 1 error; 2 usage; 3
//! published, but posts under an epoch whose key is not held were held back;
//! 4 the relay session is not NIP-42 authenticated; 5 a compaction found too
//! many rows missing from the relay; 6 the pods show an older index than the
//! state recorded (rollback or withholding); 7 the relay serves none of the
//! zone's indexed posts to this identity (not admitted to the zone).
//!
//! A `--dry-run` needs no pod: without `--pod` or `--pod-dir` it builds as if
//! no index existed yet (version 1), as the import hand-off does.

#[cfg(target_arch = "wasm32")]
fn main() {}

#[cfg(not(target_arch = "wasm32"))]
fn main() -> std::process::ExitCode {
    native::main()
}

#[cfg(not(target_arch = "wasm32"))]
mod native {
    use std::collections::HashSet;
    use std::path::{Path, PathBuf};
    use std::process::ExitCode;

    use clap::{Parser, Subcommand};
    use nostr_bbs_core::keys::SecretKey;
    use nostr_bbs_core::NostrEvent;
    use nostr_bbs_sealed_search::model::{to_gguf_q8, DIM};
    use nostr_bbs_sealed_search::search::sha256_hex;
    use nostr_bbs_search_build::embed::{BgeEmbedder, Embedder};
    use nostr_bbs_search_build::harvest::{harvest, ZoneRow};
    use nostr_bbs_search_build::memrelay::MemRelay;
    use nostr_bbs_search_build::pipeline::{
        run_compact, run_full, run_update, status, Fold, Format, Job, JobError, Pins,
        DEFAULT_OVERLAP_SECS,
    };
    use nostr_bbs_search_build::pod::{DirPod, DryRun, HttpPod, ObjectCache, Pod};
    use nostr_bbs_search_build::secrets::load_identity;
    use nostr_bbs_search_build::state::State;
    use nostr_bbs_zone_migrate::keys::{parse_key_file, KeyRing};
    use nostr_bbs_zone_migrate::net::NetRelay;
    use nostr_bbs_zone_migrate::relay::{DeleteOutcome, Filter, PublishOutcome, Relay, RelayError};
    use zeroize::Zeroizing;

    #[derive(Parser)]
    #[command(about = "Build, update, compact and upload a zone's sealed search index")]
    struct Cli {
        #[command(subcommand)]
        cmd: Option<Cmd>,
        /// Zone id (e.g. zone2).
        #[arg(long, global = true)]
        zone: Option<String>,
        /// Full build: JSONL rows {"id","text","epoch","zone_pk"}.
        #[arg(long, global = true)]
        input: Option<PathBuf>,
        /// Full build from --input: ids to leave out, one hex id per line.
        #[arg(long, global = true)]
        exclude: Option<PathBuf>,
        /// Read the zone's posts from this relay (NIP-42 as the publisher).
        #[arg(long, global = true)]
        from_relay: Option<String>,
        /// Read the zone's posts from a NIP-01 JSONL export instead of a relay.
        #[arg(long, global = true)]
        from_events: Option<PathBuf>,
        /// zone-migrate key file.
        #[arg(long, global = true)]
        keys_file: Option<PathBuf>,
        /// Fetch zone-key grants addressed to the publisher.
        #[arg(long, global = true)]
        fetch_grants: bool,
        /// Relay WebSocket URL for --fetch-grants (default: --from-relay).
        #[arg(long, global = true)]
        relay: Option<String>,
        /// Origin header for relay connections.
        #[arg(long, global = true, default_value = "http://localhost")]
        origin: String,
        /// The deployment's relay URL as clients use it (bound into the manifest).
        #[arg(long, global = true)]
        relay_url: Option<String>,
        /// bge-small-en-v1.5 checkpoint directory (pytorch_model.bin, vocab.txt).
        #[arg(long, global = true)]
        model_dir: Option<PathBuf>,
        /// Browser model file (GGUF Q8_0) whose SHA-256 the manifest pins.
        #[arg(long, global = true)]
        model_q8: Option<PathBuf>,
        /// Pod base URL (e.g. https://pods.example.org).
        #[arg(long, global = true)]
        pod: Option<String>,
        /// A directory laid out as the pods are, instead of --pod (local runs).
        #[arg(long, global = true)]
        pod_dir: Option<PathBuf>,
        /// Comma-separated trusted publishers (clients' SEARCH_PUBLISHERS);
        /// this key must be one of them. Default: this key alone.
        #[arg(long, global = true)]
        publishers: Option<String>,
        /// Publisher key file (mode 0600); else NOSTR_BBS_MIGRATE_KEY.
        #[arg(long, global = true)]
        key_file: Option<PathBuf>,
        /// State file (high-water mark, last version, objects to delete).
        #[arg(long, global = true)]
        state: Option<PathBuf>,
        /// Cache of downloaded sealed objects (ciphertext, by SHA-256).
        #[arg(long, global = true)]
        cache_dir: Option<PathBuf>,
        /// Update: read posts from this created_at instead of the state's
        /// high-water mark (0 reads the whole zone: a reconcile).
        #[arg(long, global = true)]
        since: Option<u64>,
        /// Update: seconds re-read before the high-water mark.
        #[arg(long, global = true, default_value_t = DEFAULT_OVERLAP_SECS)]
        overlap_secs: u64,
        /// Full build: manifest content version. `auto` signs v1 while no
        /// trusted publisher holds a v2 manifest for the zone, v2 once one does.
        #[arg(long, global = true, value_enum, default_value_t = ManifestFormat::Auto)]
        manifest_format: ManifestFormat,
        /// Rows per shard.
        #[arg(long, global = true, default_value_t = 32768)]
        shard_rows: usize,
        /// Embedding batch size.
        #[arg(long, global = true, default_value_t = 16)]
        batch: usize,
        /// Concurrent embedding workers (default: half the CPUs).
        #[arg(long, global = true)]
        workers: Option<usize>,
        /// Write new objects and m.json to --out and change nothing.
        #[arg(long, global = true)]
        dry_run: bool,
        /// Output directory (dry run, or model-q8).
        #[arg(long, global = true)]
        out: Option<PathBuf>,
        /// Measurement only, full build with --dry-run: also write the FP32
        /// embeddings (row order) here. Embeddings are plaintext-equivalent.
        #[arg(long, global = true)]
        dump_vectors: Option<PathBuf>,
        /// Comma-separated hex pubkeys whose kind-5 deletes any post (admins
        /// and moderators); anyone else deletes only their own posts.
        #[arg(long, global = true)]
        moderators: Option<String>,
        /// Seconds an object a manifest stopped listing stays in the pod
        /// before deletion (browsers may still be loading it).
        #[arg(long, global = true, default_value_t = nostr_bbs_search_build::pipeline::DEFAULT_RETIRE_AFTER_SECS)]
        retire_after_secs: u64,
    }

    #[derive(Clone, Copy, clap::ValueEnum)]
    enum ManifestFormat {
        Auto,
        V1,
        V2,
    }

    impl From<ManifestFormat> for Format {
        fn from(f: ManifestFormat) -> Self {
            match f {
                ManifestFormat::Auto => Format::Auto,
                ManifestFormat::V1 => Format::V1,
                ManifestFormat::V2 => Format::V2,
            }
        }
    }

    #[derive(Subcommand)]
    enum Cmd {
        /// Index posts written since the last run into additional shards.
        Update,
        /// Fold update shards into fresh shards (--all: every shard).
        Compact {
            /// Fold every shard pair, re-homing the whole index in this pod.
            #[arg(long)]
            all: bool,
        },
        /// Show the newest index on the pods.
        Status {
            /// Print only this field (e.g. partial_pairs, excluded, index_version).
            #[arg(long)]
            field: Option<String>,
        },
        /// Write the browser model (GGUF Q8_0) and vocab.txt to --out.
        ModelQ8,
        /// Build the author book from the zone's events (--from-relay, or
        /// --from-events with an export taken at import), before the first update.
        SeedBook,
        /// Exclude posts from the next manifest (operator takedown).
        Takedown {
            /// File of post ids (hex, one per line) to take down.
            #[arg(long)]
            ids: PathBuf,
            /// Why (recorded in the report and the job log).
            #[arg(long)]
            reason: String,
        },
    }

    struct Fail(String, u8);

    impl From<String> for Fail {
        fn from(e: String) -> Self {
            Fail(e, 1)
        }
    }

    impl From<JobError> for Fail {
        fn from(e: JobError) -> Self {
            let code = e.exit_code();
            Fail(e.to_string(), code)
        }
    }

    fn req<T: Clone>(v: &Option<T>, name: &str) -> Result<T, Fail> {
        v.clone()
            .ok_or_else(|| Fail(format!("--{name} is required"), 2))
    }

    fn io<T, E: std::fmt::Display>(r: Result<T, E>) -> Result<T, Fail> {
        r.map_err(|e| Fail(e.to_string(), 1))
    }

    pub fn main() -> ExitCode {
        let cli = Cli::parse();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime builds");
        match rt.block_on(run(cli)) {
            Ok(code) => ExitCode::from(code),
            Err(Fail(m, code)) => {
                eprintln!("error: {m}");
                ExitCode::from(code)
            }
        }
    }

    /// Either pod implementation (the pipeline is generic; `Pod` has async
    /// methods, so no trait object).
    enum AnyPod {
        Http(HttpPod),
        Dir(DirPod),
        /// No pod at all (a dry run without one): holds nothing.
        None,
    }

    impl Pod for AnyPod {
        async fn get(&mut self, owner: &str, name: &str) -> Result<Option<Vec<u8>>, String> {
            match self {
                Self::Http(p) => p.get(owner, name).await,
                Self::Dir(p) => p.get(owner, name).await,
                Self::None => Ok(None),
            }
        }
        async fn put(&mut self, name: &str, bytes: &[u8], ct: &str) -> Result<(), String> {
            match self {
                Self::Http(p) => p.put(name, bytes, ct).await,
                Self::Dir(p) => p.put(name, bytes, ct).await,
                Self::None => Err("no pod to write to".into()),
            }
        }
        async fn delete(&mut self, name: &str) -> Result<(), String> {
            match self {
                Self::Http(p) => p.delete(name).await,
                Self::Dir(p) => p.delete(name).await,
                Self::None => Err("no pod to delete from".into()),
            }
        }
    }

    enum AnyRelay {
        Net(Box<NetRelay>),
        Mem(MemRelay),
    }

    impl Relay for AnyRelay {
        fn session_authenticated(&self) -> bool {
            match self {
                Self::Net(r) => r.authenticated(),
                Self::Mem(r) => r.session_authenticated(),
            }
        }
        async fn query(&mut self, f: &Filter) -> Result<Vec<NostrEvent>, RelayError> {
            match self {
                Self::Net(r) => r.query(f).await,
                Self::Mem(r) => r.query(f).await,
            }
        }
        async fn publish(&mut self, e: &NostrEvent) -> Result<PublishOutcome, RelayError> {
            match self {
                Self::Net(r) => r.publish(e).await,
                Self::Mem(r) => r.publish(e).await,
            }
        }
        async fn is_admin(&mut self, pk: &str) -> Result<bool, RelayError> {
            match self {
                Self::Net(r) => r.is_admin(pk).await,
                Self::Mem(r) => r.is_admin(pk).await,
            }
        }
        async fn delete_events(
            &mut self,
            ids: &[String],
            reason: &str,
        ) -> Result<DeleteOutcome, RelayError> {
            match self {
                Self::Net(r) => r.delete_events(ids, reason).await,
                Self::Mem(r) => r.delete_events(ids, reason).await,
            }
        }
    }

    /// Records every vector it returns (the measurement-only --dump-vectors).
    struct Dumping<E> {
        inner: E,
        vecs: Vec<[f32; DIM]>,
    }

    impl<E: Embedder> Embedder for Dumping<E> {
        fn embed(&mut self, texts: &[&str]) -> Result<Vec<[f32; DIM]>, String> {
            let v = self.inner.embed(texts)?;
            self.vecs.extend_from_slice(&v);
            Ok(v)
        }
    }

    #[derive(serde::Deserialize)]
    struct InRow {
        id: String,
        text: String,
        epoch: u32,
        zone_pk: String,
    }

    async fn connect(cli: &Cli, url: &str, me: &SecretKey) -> Result<NetRelay, Fail> {
        NetRelay::connect(url, &cli.origin, me)
            .await
            .map_err(|e| Fail(e.to_string(), 1))
    }

    async fn load_keys(cli: &Cli, me: &SecretKey) -> Result<KeyRing, Fail> {
        let mut ring = KeyRing::new();
        if let Some(path) = &cli.keys_file {
            nostr_bbs_search_build::secrets::ensure_owner_only(path, "keys file")
                .map_err(|e| Fail(e, 2))?;
            let text = Zeroizing::new(io(std::fs::read_to_string(path))?);
            for key in io(parse_key_file(&text))?.keys {
                io(ring.insert(key))?;
            }
        }
        if cli.fetch_grants {
            let url = cli
                .relay
                .clone()
                .or_else(|| cli.from_relay.clone())
                .ok_or_else(|| Fail("--fetch-grants needs --relay or --from-relay".into(), 2))?;
            let mut relay = connect(cli, &url, me).await?;
            let harvest =
                io(nostr_bbs_zone_migrate::grants::fetch_grants(&mut relay, me, None).await)?;
            for r in &harvest.rejected {
                eprintln!("refused grant {}: {}", r.wrap_id, r.reason);
            }
            for key in harvest.keys {
                io(ring.insert(key))?;
            }
        }
        if ring.is_empty() {
            return Err(Fail(
                "no zone keys (use --keys-file or --fetch-grants)".into(),
                2,
            ));
        }
        Ok(ring)
    }

    async fn open_relay(cli: &Cli, me: &SecretKey) -> Result<Option<AnyRelay>, Fail> {
        if let Some(url) = &cli.from_relay {
            return Ok(Some(AnyRelay::Net(Box::new(connect(cli, url, me).await?))));
        }
        if let Some(path) = &cli.from_events {
            return Ok(Some(AnyRelay::Mem(MemRelay::from_jsonl(path)?)));
        }
        Ok(None)
    }

    fn pins(cli: &Cli) -> Result<Option<Pins>, Fail> {
        let (Some(dir), Some(q8)) = (&cli.model_dir, &cli.model_q8) else {
            return Ok(None);
        };
        Ok(Some(Pins {
            model: "bge-small-en-v1.5".into(),
            model_sha256: sha256_hex(&io(std::fs::read(q8))?),
            vocab_sha256: sha256_hex(&io(std::fs::read(dir.join("vocab.txt")))?),
        }))
    }

    fn print_json<T: serde::Serialize>(v: &T) -> Result<(), Fail> {
        println!("{}", io(serde_json::to_string(v))?);
        Ok(())
    }

    async fn run(cli: Cli) -> Result<u8, Fail> {
        if let Some(Cmd::ModelQ8) = cli.cmd {
            let dir = req(&cli.model_dir, "model-dir")?;
            let out = req(&cli.out, "out")?;
            io(std::fs::create_dir_all(&out))?;
            let g = to_gguf_q8(&dir)?;
            io(std::fs::write(out.join("bge-small-en-v1.5-q8_0.gguf"), &g))?;
            io(std::fs::copy(dir.join("vocab.txt"), out.join("vocab.txt")))?;
            println!(
                "{{\"model_q8_mb\":{:.1},\"model_sha256\":\"{}\"}}",
                g.len() as f64 / 1048576.0,
                sha256_hex(&g)
            );
            return Ok(0);
        }
        let zone = req(&cli.zone, "zone")?;
        let relay_url = req(&cli.relay_url, "relay-url")?;
        let me = load_identity(cli.key_file.as_deref()).map_err(|e| Fail(e.to_string(), 2))?;
        let publisher = me.public_key().to_hex();
        let publishers = match &cli.publishers {
            Some(l) => nostr_bbs_sealed_search::manifest::parse_publishers(l),
            None => vec![publisher.clone()],
        };
        if !publishers.contains(&publisher) {
            return Err(Fail(
                "this key is not in --publishers; clients would refuse its manifest".into(),
                2,
            ));
        }
        if cli.dump_vectors.is_some() && !cli.dry_run {
            return Err(Fail("--dump-vectors requires --dry-run".into(), 2));
        }
        if cli.dump_vectors.is_some() && (cli.input.is_none() || cli.cmd.is_some()) {
            return Err(Fail(
                "--dump-vectors is only for a full build from --input: rows read from a relay or an export are never written"
                    .into(),
                2,
            ));
        }
        let inner = match (&cli.pod_dir, &cli.pod) {
            (Some(dir), _) => AnyPod::Dir(DirPod::new(dir, &zone, &publisher)),
            (None, Some(url)) => AnyPod::Http(HttpPod::new(url, &zone, &me)?),
            (None, None) if cli.dry_run => AnyPod::None,
            (None, None) => return Err(Fail("--pod or --pod-dir is required".into(), 2)),
        };
        if cli.dry_run {
            let out = req(&cli.out, "out")?;
            let mut pod = DryRun::new(inner, &out);
            let code = execute(&cli, &mut pod, &zone, &relay_url, &publishers, &me).await?;
            if !pod.would_delete.is_empty() {
                eprintln!("dry run: would delete {}", pod.would_delete.join(", "));
            }
            Ok(code)
        } else {
            let mut pod = inner;
            execute(&cli, &mut pod, &zone, &relay_url, &publishers, &me).await
        }
    }

    async fn execute<P: Pod>(
        cli: &Cli,
        pod: &mut P,
        zone: &str,
        relay_url: &str,
        publishers: &[String],
        me: &SecretKey,
    ) -> Result<u8, Fail> {
        let publisher = me.public_key().to_hex();
        let pins = pins(cli)?;
        let cache = cli.cache_dir.as_deref().map(ObjectCache::new);
        let now = io(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH))?.as_secs();
        let state_path: Option<&Path> = cli.state.as_deref();
        let book_path = state_path.map(|p| p.with_extension("authors.json"));
        let mut book = match &book_path {
            Some(p) => nostr_bbs_search_build::harvest::AuthorBook::load(p)?,
            None => Default::default(),
        };
        let mut state = match state_path {
            Some(p) => Some(State::load_or_new(p, zone, relay_url, &publisher)?),
            None => None,
        };
        let needs_keys = !matches!(cli.cmd, Some(Cmd::Status { .. }));
        let ring = if needs_keys {
            load_keys(cli, me).await?
        } else {
            KeyRing::new()
        };
        let moderators = cli
            .moderators
            .as_deref()
            .map(nostr_bbs_sealed_search::manifest::parse_publishers)
            .unwrap_or_default();
        let mut job = Job {
            zone,
            relay_url,
            publishers,
            me,
            ring: &ring,
            pod,
            cache: cache.as_ref(),
            pins: pins.as_ref(),
            shard_rows: cli.shard_rows,
            now,
            warnings: Vec::new(),
            moderators: &moderators,
            max_excluded: nostr_bbs_sealed_search::manifest::MAX_EXCLUDED,
            retire_after_secs: cli.retire_after_secs,
        };
        let workers = cli.workers.unwrap_or_else(|| {
            std::thread::available_parallelism().map_or(4, |n| (n.get() / 2).max(1))
        });
        let model_dir = || req(&cli.model_dir, "model-dir");

        let mut report = match &cli.cmd {
            Some(Cmd::Status { field }) => {
                let s = status(&mut job).await?;
                match field {
                    Some(f) => println!(
                        "{}",
                        s.field(f)
                            .ok_or_else(|| Fail(format!("unknown field {f}"), 2))?
                    ),
                    None => print_json(&s)?,
                }
                return Ok(0);
            }
            Some(Cmd::Update) => {
                let mut relay = open_relay(cli, me)
                    .await?
                    .ok_or_else(|| Fail("update needs --from-relay or --from-events".into(), 2))?;
                let st = state
                    .as_mut()
                    .ok_or_else(|| Fail("update needs --state".into(), 2))?;
                let mut emb = BgeEmbedder::new(&model_dir()?, cli.batch, workers);
                run_update(
                    &mut job,
                    &mut relay,
                    st,
                    &mut book,
                    &mut emb,
                    cli.since,
                    cli.overlap_secs,
                )
                .await?
            }
            Some(Cmd::Compact { all }) => {
                let mut relay = open_relay(cli, me)
                    .await?
                    .ok_or_else(|| Fail("compact needs --from-relay or --from-events".into(), 2))?;
                let st = state
                    .as_mut()
                    .ok_or_else(|| Fail("compact needs --state".into(), 2))?;
                let fold = if *all { Fold::All } else { Fold::Partial };
                run_compact(&mut job, &mut relay, st, &mut book, fold).await?
            }
            Some(Cmd::ModelQ8) => unreachable!("handled before the job is set up"),
            Some(Cmd::SeedBook) => {
                let mut relay = open_relay(cli, me).await?.ok_or_else(|| {
                    Fail("seed-book needs --from-relay or --from-events".into(), 2)
                })?;
                if book_path.is_none() {
                    return Err(Fail(
                        "seed-book needs --state (the book is kept beside it)".into(),
                        2,
                    ));
                }
                let r =
                    nostr_bbs_search_build::harvest::seed_book(&mut relay, zone, &ring, &mut book)
                        .await
                        .map_err(JobError::from)?;
                if !cli.dry_run {
                    if let Some(p) = &book_path {
                        book.save(p)?;
                    }
                }
                print_json(&r)?;
                return Ok(0);
            }
            Some(Cmd::Takedown { ids, reason }) => {
                let st = state
                    .as_mut()
                    .ok_or_else(|| Fail("takedown needs --state".into(), 2))?;
                let list: Vec<String> = io(std::fs::read_to_string(ids))?
                    .lines()
                    .map(|l| l.trim().to_lowercase())
                    .filter(|l| !l.is_empty())
                    .collect();
                nostr_bbs_search_build::pipeline::run_takedown(&mut job, st, &list, reason).await?
            }
            None => {
                let base = BgeEmbedder::new(&model_dir()?, cli.batch, workers);
                let mut emb = Dumping {
                    inner: base,
                    vecs: Vec::new(),
                };
                let report = if let Some(input) = &cli.input {
                    let exclude: HashSet<String> = match &cli.exclude {
                        Some(p) => io(std::fs::read_to_string(p))?
                            .lines()
                            .map(|l| l.trim().to_lowercase())
                            .filter(|l| !l.is_empty())
                            .collect(),
                        None => HashSet::new(),
                    };
                    let text = Zeroizing::new(io(std::fs::read_to_string(input))?);
                    let mut rows = Vec::new();
                    for (i, line) in text
                        .lines()
                        .enumerate()
                        .filter(|(_, l)| !l.trim().is_empty())
                    {
                        let r: InRow = serde_json::from_str(line)
                            .map_err(|_| Fail(format!("input line {} is malformed", i + 1), 1))?;
                        rows.push(ZoneRow {
                            id: r.id.to_lowercase(),
                            text: Zeroizing::new(r.text),
                            epoch: r.epoch,
                            zone_pk: r.zone_pk.to_lowercase(),
                            created_at: 0,
                        });
                    }
                    run_full(
                        &mut job,
                        state.as_mut(),
                        rows,
                        &exclude,
                        None,
                        &mut emb,
                        cli.manifest_format.into(),
                    )
                    .await?
                } else {
                    let mut relay = open_relay(cli, me).await?.ok_or_else(|| {
                        Fail(
                            "a full build needs --input, --from-relay or --from-events".into(),
                            2,
                        )
                    })?;
                    let rules = nostr_bbs_search_build::harvest::Rules {
                        now,
                        moderators: &moderators,
                    };
                    let mut h = harvest(
                        &mut relay,
                        zone,
                        &ring,
                        None,
                        &HashSet::new(),
                        &rules,
                        &mut book,
                    )
                    .await
                    .map_err(JobError::from)?;
                    let rows = std::mem::take(&mut h.rows);
                    run_full(
                        &mut job,
                        state.as_mut(),
                        rows,
                        &HashSet::new(),
                        Some(&h),
                        &mut emb,
                        cli.manifest_format.into(),
                    )
                    .await?
                };
                if let Some(p) = &cli.dump_vectors {
                    let bytes: Vec<u8> = emb
                        .vecs
                        .iter()
                        .flat_map(|v| v.iter().flat_map(|x| x.to_le_bytes()))
                        .collect();
                    nostr_bbs_search_build::secrets::write_owner_only(p, &bytes)?;
                }
                report
            }
        };
        report.dry_run = cli.dry_run;
        if !cli.dry_run {
            if let Some(s) = state.as_mut() {
                s.updated_at = now;
            }
            nostr_bbs_search_build::pipeline::persist(
                state_path.zip(state.as_ref()).map(|(p, s)| (s, p)),
                book_path.as_deref().map(|p| (&book, p)),
            )?;
        }
        print_json(&report)?;
        Ok(if report.missing_key > 0 { 3 } else { 0 })
    }
}
