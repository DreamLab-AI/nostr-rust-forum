//! `nostr-bbs-search-build`: build, seal and upload a zone's sealed search
//! index (keybase-port/analysis/SEALED-SEARCH-DESIGN.md §8).
//!
//! ```text
//! NOSTR_BBS_MIGRATE_KEY=<publisher hex|nsec, from a 0600 file>  \
//! nostr-bbs-search-build --zone zone2 --input docs.jsonl \
//!     --keys-file keys.json | --fetch-grants --relay ws://… \
//!     --model-dir work/models/bge-small-en-v1.5 \
//!     --relay-url ws://… --pod http://…:8789 [--version N] [--exclude ids.txt] [--dry-run --out dir]
//! nostr-bbs-search-build model-q8 --model-dir … --out dir    # browser model (GGUF Q8_0) + vocab
//! ```
//!
//! Input rows (JSONL): `{"id": <event id hex>, "text": <plaintext>, "epoch": u32, "zone_pk": <hex>}`.
//! Each row is sealed under its own epoch's key, and the key's pubkey must
//! equal `zone_pk` (review M3/M4). Ids in `--exclude` (deleted / superseded,
//! review M5) are skipped.
//!
//! Embeddings are computed **locally** with candle (FP32 bge-small-en-v1.5);
//! there is no remote-embedding option (review M6: the LAN embedder logs
//! request bodies). Zone keys come only from zone-migrate's key file or its
//! `--fetch-grants`; the publisher key only from the environment.

#[cfg(target_arch = "wasm32")]
fn main() {}

#[cfg(not(target_arch = "wasm32"))]
fn main() -> std::process::ExitCode {
    native::main()
}

#[cfg(not(target_arch = "wasm32"))]
mod native {
    use std::collections::{HashMap, HashSet};
    use std::path::PathBuf;
    use std::process::ExitCode;
    use std::time::Instant;

    use clap::{Parser, Subcommand};
    use nostr_bbs_core::keys::SecretKey;
    use nostr_bbs_core::{sign_event, UnsignedEvent};
    use nostr_bbs_sealed_search::build::{build, BuildSpec, DocRow, KeyMap};
    use nostr_bbs_sealed_search::manifest::{Content, Manifest, KIND};
    use nostr_bbs_sealed_search::model::{to_gguf_q8, Bge, DIM};
    use nostr_bbs_sealed_search::search::sha256_hex;
    use nostr_bbs_sealed_search::seal::SearchKey;
    use nostr_bbs_zone_migrate::identity::{identity_from_env, IDENTITY_ENV};
    use nostr_bbs_zone_migrate::keys::{parse_key_file, KeyRing};
    use zeroize::Zeroizing;

    #[derive(Parser)]
    #[command(about = "Build, seal and upload a zone's sealed search index")]
    struct Cli {
        #[command(subcommand)]
        cmd: Option<Cmd>,
        /// Zone id (e.g. zone2).
        #[arg(long)]
        zone: Option<String>,
        /// JSONL rows: {"id","text","epoch","zone_pk"}.
        #[arg(long)]
        input: Option<PathBuf>,
        /// Ids to leave out (deleted or superseded), one hex id per line.
        #[arg(long)]
        exclude: Option<PathBuf>,
        /// zone-migrate key file.
        #[arg(long)]
        keys_file: Option<PathBuf>,
        /// Fetch zone-key grants addressed to the publisher (zone-migrate --fetch-grants).
        #[arg(long)]
        fetch_grants: bool,
        /// Relay WebSocket URL for --fetch-grants.
        #[arg(long)]
        relay: Option<String>,
        /// Origin header for the relay connection.
        #[arg(long, default_value = "http://localhost")]
        origin: String,
        /// The deployment's relay URL as clients use it (bound into the manifest).
        #[arg(long)]
        relay_url: Option<String>,
        /// bge-small-en-v1.5 checkpoint directory (pytorch_model.bin, vocab.txt).
        #[arg(long)]
        model_dir: Option<PathBuf>,
        /// Browser model file (GGUF Q8_0) whose SHA-256 the manifest pins.
        #[arg(long)]
        model_q8: Option<PathBuf>,
        /// Pod base URL (e.g. http://172.20.0.10:8789).
        #[arg(long)]
        pod: Option<String>,
        /// Comma-separated publisher pubkeys clients accept (e.g.
        /// "<archivist>,<admin>"); this key must be one of them. Defaults to
        /// this key alone. Used to verify the previously published manifest.
        #[arg(long)]
        publishers: Option<String>,
        /// Index version (default: current pod version + 1, or 1).
        #[arg(long)]
        version: Option<u64>,
        /// Rows per shard.
        #[arg(long, default_value_t = 32768)]
        shard_rows: usize,
        /// Embedding batch size.
        #[arg(long, default_value_t = 16)]
        batch: usize,
        /// Concurrent embedding workers (default: half the CPUs).
        #[arg(long)]
        workers: Option<usize>,
        /// Write sealed objects + m.json here and do not upload.
        #[arg(long)]
        dry_run: bool,
        /// Output directory (dry run, or model-q8).
        #[arg(long)]
        out: Option<PathBuf>,
        /// Measurement only, with --dry-run: also write the FP32 embeddings
        /// (row order of the input) here. Embeddings are plaintext-equivalent,
        /// so this is refused without --dry-run.
        #[arg(long)]
        dump_vectors: Option<PathBuf>,
    }

    #[derive(Subcommand)]
    enum Cmd {
        /// Write the browser model (GGUF Q8_0) and vocab.txt to --out.
        ModelQ8,
    }

    struct Fail(String);
    impl<E: std::fmt::Display> From<E> for Fail {
        fn from(e: E) -> Self {
            Fail(e.to_string())
        }
    }

    fn req<T: Clone>(v: &Option<T>, name: &str) -> Result<T, Fail> {
        v.clone().ok_or_else(|| Fail(format!("--{name} is required")))
    }

    pub fn main() -> ExitCode {
        let cli = Cli::parse();
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime");
        match rt.block_on(run(cli)) {
            Ok(()) => ExitCode::SUCCESS,
            Err(Fail(m)) => {
                eprintln!("error: {m}");
                ExitCode::FAILURE
            }
        }
    }

    #[derive(serde::Deserialize)]
    struct InRow {
        id: String,
        text: String,
        epoch: u32,
        zone_pk: String,
    }

    fn hex32(s: &str, what: &str) -> Result<[u8; 32], Fail> {
        let v = hex::decode(s).map_err(|_| Fail(format!("{what} is not hex")))?;
        v.try_into().map_err(|_| Fail(format!("{what} is not 32 bytes")))
    }

    async fn load_keys(cli: &Cli, me: &SecretKey) -> Result<KeyRing, Fail> {
        let mut ring = KeyRing::new();
        if let Some(path) = &cli.keys_file {
            let text = Zeroizing::new(std::fs::read_to_string(path)?);
            for key in parse_key_file(&text)?.keys {
                ring.insert(key)?;
            }
        }
        if cli.fetch_grants {
            let url = req(&cli.relay, "relay")?;
            let mut relay = nostr_bbs_zone_migrate::net::NetRelay::connect(&url, &cli.origin, me).await?;
            let harvest = nostr_bbs_zone_migrate::grants::fetch_grants(&mut relay, me, None).await?;
            for r in &harvest.rejected {
                eprintln!("refused grant {}: {}", r.wrap_id, r.reason);
            }
            for key in harvest.keys {
                ring.insert(key)?;
            }
        }
        if ring.is_empty() {
            return Err(Fail("no zone keys (use --keys-file or --fetch-grants)".into()));
        }
        Ok(ring)
    }

    fn pod_url(pod: &str, publisher: &str, zone: &str, name: &str) -> String {
        format!("{}/pods/{publisher}/media/zones/{zone}/search/{name}", pod.trim_end_matches('/'))
    }

    async fn pod_request(
        http: &reqwest::Client,
        sk: &SecretKey,
        method: reqwest::Method,
        url: &str,
        body: Option<(Vec<u8>, &str)>,
    ) -> Result<reqwest::Response, Fail> {
        let token = nostr_bbs_core::nip98::create_token(
            sk.as_bytes(),
            url,
            method.as_str(),
            body.as_ref().map(|(b, _)| b.as_slice()),
        )?;
        let mut r = http.request(method, url).header("Authorization", format!("Nostr {token}"));
        if let Some((b, ct)) = body {
            r = r.header("Content-Type", ct).body(b);
        }
        Ok(r.send().await?)
    }

    async fn run(cli: Cli) -> Result<(), Fail> {
        if let Some(Cmd::ModelQ8) = cli.cmd {
            let dir = req(&cli.model_dir, "model-dir")?;
            let out = req(&cli.out, "out")?;
            std::fs::create_dir_all(&out)?;
            let g = to_gguf_q8(&dir).map_err(Fail)?;
            std::fs::write(out.join("bge-small-en-v1.5-q8_0.gguf"), &g)?;
            std::fs::copy(dir.join("vocab.txt"), out.join("vocab.txt"))?;
            println!("{{\"model_q8_mb\":{:.1},\"model_sha256\":\"{}\"}}", g.len() as f64 / 1048576.0, sha256_hex(&g));
            return Ok(());
        }
        let zone = req(&cli.zone, "zone")?;
        let relay_url = req(&cli.relay_url, "relay-url")?;
        let model_dir = req(&cli.model_dir, "model-dir")?;
        let model_q8 = req(&cli.model_q8, "model-q8")?;
        let me = identity_from_env().map_err(|_| Fail(format!("set {IDENTITY_ENV} to the publisher key (hex or nsec)")))?;
        let publisher = me.public_key().to_hex();
        let publishers = match &cli.publishers {
            Some(l) => nostr_bbs_sealed_search::manifest::parse_publishers(l),
            None => vec![publisher.clone()],
        };
        if !publishers.contains(&publisher) {
            return Err(Fail("this key is not in --publishers; clients would refuse its manifest".into()));
        }

        // Rows.
        let exclude: HashSet<String> = match &cli.exclude {
            Some(p) => std::fs::read_to_string(p)?.lines().map(|l| l.trim().to_lowercase()).filter(|l| !l.is_empty()).collect(),
            None => HashSet::new(),
        };
        let text = std::fs::read_to_string(req(&cli.input, "input")?)?;
        let mut rows_in: Vec<InRow> = Vec::new();
        let mut skipped = 0usize;
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            let r: InRow = serde_json::from_str(line)?;
            if exclude.contains(&r.id.to_lowercase()) {
                skipped += 1;
                continue;
            }
            rows_in.push(r);
        }

        // Keys: each row's (epoch, zone_pk) must be a held key for this zone.
        let ring = load_keys(&cli, &me).await?;
        let mut keys: KeyMap = HashMap::new();
        for r in &rows_in {
            let pk = hex32(&r.zone_pk, "zone_pk")?;
            if keys.contains_key(&(r.epoch, pk)) {
                continue;
            }
            let k = ring.get(&zone, r.epoch).ok_or_else(|| Fail(format!("no key for {zone} epoch {}", r.epoch)))?;
            if !k.pubkey().eq_ignore_ascii_case(&r.zone_pk) {
                return Err(Fail(format!("row zone_pk does not match the held key for epoch {}", r.epoch)));
            }
            keys.insert((r.epoch, pk), SearchKey::derive(k.secret(), &zone, r.epoch, &pk));
        }

        // Embed locally (FP32), batched by length.
        let model = Bge::load_fp32_dir(&model_dir).map_err(Fail)?;
        let t0 = Instant::now();
        let mut order: Vec<(usize, Vec<u32>)> = rows_in.iter().enumerate().map(|(i, r)| (i, model.encode(&r.text))).collect();
        order.sort_by_key(|x| x.1.len());
        // Length-sorted batches, processed by several workers at once: the
        // per-op overhead of small GEMMs and single-threaded elementwise ops
        // dominates one forward pass, so concurrency is what scales.
        let batches: Vec<&[(usize, Vec<u32>)]> = order.chunks(cli.batch.max(1)).collect();
        let workers = cli
            .workers
            .unwrap_or_else(|| std::thread::available_parallelism().map_or(4, |n| (n.get() / 2).max(1)));
        let next = std::sync::atomic::AtomicUsize::new(0);
        let results: std::sync::Mutex<Vec<(usize, [f32; DIM])>> = std::sync::Mutex::new(Vec::with_capacity(rows_in.len()));
        let failure: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);
        std::thread::scope(|sc| {
            for _ in 0..workers {
                sc.spawn(|| loop {
                    let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let Some(chunk) = batches.get(i) else { break };
                    let ids: Vec<Vec<u32>> = chunk.iter().map(|x| x.1.clone()).collect();
                    match model.embed_ids(&ids) {
                        Ok(vs) => {
                            let mut r = results.lock().expect("results lock");
                            for (j, v) in vs.into_iter().enumerate() {
                                r.push((chunk[j].0, v));
                            }
                        }
                        Err(e) => {
                            *failure.lock().expect("failure lock") = Some(e);
                            break;
                        }
                    }
                });
            }
        });
        if let Some(e) = failure.into_inner().expect("failure lock") {
            return Err(Fail(e));
        }
        let mut vecs = vec![[0f32; DIM]; rows_in.len()];
        for (i, v) in results.into_inner().expect("results lock") {
            vecs[i] = v;
        }
        let embed_s = t0.elapsed().as_secs_f64();
        if let Some(p) = &cli.dump_vectors {
            if !cli.dry_run {
                return Err(Fail("--dump-vectors requires --dry-run".into()));
            }
            let bytes: Vec<u8> = vecs.iter().flat_map(|v| v.iter().flat_map(|x| x.to_le_bytes())).collect();
            std::fs::write(p, bytes)?;
        }
        let rows: Vec<DocRow> = rows_in
            .iter()
            .zip(vecs)
            .map(|(r, vec)| Ok(DocRow { id: hex32(&r.id, "id")?, epoch: r.epoch, zone_pk: hex32(&r.zone_pk, "zone_pk")?, vec }))
            .collect::<Result<_, Fail>>()?;
        drop(rows_in);

        // Version: explicit, else the pod's current + 1.
        let http = reqwest::Client::new();
        let mut previous: Option<Content> = None;
        if let Some(pod) = &cli.pod {
            let url = pod_url(pod, &publisher, &zone, "m.json");
            let resp = pod_request(&http, &me, reqwest::Method::GET, &url, None).await?;
            if resp.status().is_success() {
                let ev: nostr_bbs_core::NostrEvent = serde_json::from_slice(&resp.bytes().await?)?;
                let m = Manifest::verify(ev, &zone, &relay_url, &publishers, None).map_err(Fail)?;
                previous = Some(m.content);
            }
        }
        let version = cli.version.unwrap_or_else(|| previous.as_ref().map_or(1, |p| p.index_version + 1));
        if previous.as_ref().is_some_and(|p| version <= p.index_version) {
            return Err(Fail(format!("version {version} is not above the published one")));
        }

        // Build + sign.
        let q8 = std::fs::read(&model_q8)?;
        let vocab = std::fs::read(model_dir.join("vocab.txt"))?;
        let t1 = Instant::now();
        let built = build(
            &BuildSpec { zone: &zone, version, model: "bge-small-en-v1.5", model_sha256: &sha256_hex(&q8), vocab_sha256: &sha256_hex(&vocab), shard_rows: cli.shard_rows },
            &rows,
            &keys,
        )
        .map_err(Fail)?;
        let seal_s = t1.elapsed().as_secs_f64();
        let sk = nostr_bbs_core::keys::signing_key_from_bytes(me.as_bytes())?;
        let unsigned = UnsignedEvent {
            pubkey: publisher.clone(),
            created_at: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs(),
            kind: KIND,
            tags: Manifest::tags(&built.content, &relay_url),
            content: serde_json::to_string(&built.content)?,
        };
        let event = sign_event(unsigned, &sk).map_err(|e| Fail(format!("{e:?}")))?;
        let manifest_json = serde_json::to_vec(&event)?;
        let sealed_bytes: usize = built.objects.iter().map(|(_, b)| b.len()).sum();

        if cli.dry_run {
            let out = req(&cli.out, "out")?;
            std::fs::create_dir_all(&out)?;
            for (name, b) in &built.objects {
                std::fs::write(out.join(name), b)?;
            }
            std::fs::write(out.join("m.json"), &manifest_json)?;
        } else {
            let pod = req(&cli.pod, "pod")?;
            for (name, b) in &built.objects {
                let url = pod_url(&pod, &publisher, &zone, name);
                let r = pod_request(&http, &me, reqwest::Method::PUT, &url, Some((b.clone(), "application/octet-stream"))).await?;
                if !r.status().is_success() {
                    return Err(Fail(format!("PUT {name}: HTTP {}", r.status())));
                }
            }
            let url = pod_url(&pod, &publisher, &zone, "m.json");
            let r = pod_request(&http, &me, reqwest::Method::PUT, &url, Some((manifest_json.clone(), "application/json"))).await?;
            if !r.status().is_success() {
                return Err(Fail(format!("PUT m.json: HTTP {}", r.status())));
            }
            // Superseded objects go (review M5).
            if let Some(prev) = previous {
                let keep: HashSet<&str> = built.content.objects.iter().map(|o| o.name.as_str()).collect();
                for o in prev.objects.iter().filter(|o| !keep.contains(o.name.as_str())) {
                    let url = pod_url(&pod, &publisher, &zone, &o.name);
                    let _ = pod_request(&http, &me, reqwest::Method::DELETE, &url, None).await?;
                }
            }
        }
        println!(
            "{{\"zone\":\"{zone}\",\"version\":{version},\"rows\":{},\"skipped\":{skipped},\"objects\":{},\"sealed_mb\":{:.1},\"embed_s\":{embed_s:.1},\"embed_rows_per_s\":{:.0},\"seal_s\":{seal_s:.1},\"uploaded\":{}}}",
            rows.len(),
            built.objects.len(),
            sealed_bytes as f64 / 1048576.0,
            rows.len() as f64 / embed_s.max(1e-9),
            !cli.dry_run
        );
        Ok(())
    }
}
