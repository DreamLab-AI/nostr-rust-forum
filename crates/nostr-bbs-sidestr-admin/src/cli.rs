//! The command line: flags, the producer round trip, and what is printed.

mod faucet_run;

use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use nostr_bbs_poker_citizen::chain::Replayed;
use nostr_bbs_sidestr_admin::{
    build_asset_transfer, build_issue, build_send, check_document, holdings, parse_key,
    parse_recipient, pin, replay, resolve_asset, PINS,
};
use sidestr_agent::AgentKey;
use sidestr_wallet::spend::Spend;
use zeroize::Zeroizing;

/// Holdings, asset issue and sends on a pinned sidestr chain, replayed under
/// the parent's header family (stock or BLAKE2b).
#[derive(Debug, Parser)]
#[command(
    name = "nostr-bbs-sidestr-admin",
    version,
    after_help = "The key is read from --key-file (64 hex or nsec1…), never from a flag's value, and never printed. Without --post nothing is sent: the default prints the signed transaction's hex and txid; --dry-run builds and checks in memory and prints neither hex nor anything to post. Testnet only: coins on these chains carry no value."
)]
pub struct Cli {
    /// The chain's producer (`/chain.json`, `/blocks.dat`, `POST /tx`).
    #[arg(long, global = true, default_value = "http://127.0.0.1:3450")]
    pub url: String,
    /// The pinned chain the producer must serve, exactly.
    #[arg(long, global = true, default_value = "sidestr:dreamlab")]
    pub chain_id: String,
    /// The key file (64 hex characters or an nsec1…).
    #[arg(long, global = true)]
    pub key_file: Option<PathBuf>,
    /// What to do.
    #[command(subcommand)]
    pub command: Command,
}

/// The subcommands.
#[derive(Debug, Subcommand, PartialEq, Eq)]
pub enum Command {
    /// The key's holdings: plain sats and every asset (id, ticker, held).
    Assets,
    /// Issue an asset: the whole supply on one carrier to the issuer (SPEC 12).
    Issue {
        /// 1 to 8 of A-Z0-9.
        ticker: String,
        /// Units created.
        supply: u64,
        /// Display decimals, 0 to 8.
        #[arg(long, default_value_t = 0)]
        decimals: u8,
        #[command(flatten)]
        mode: Mode,
    },
    /// Send units of an asset, named by id or ticker.
    SendAsset {
        /// The asset's id (64 hex) or its ticker.
        asset: String,
        /// A hex pubkey or an npub1….
        recipient: String,
        /// Units to send.
        units: u64,
        /// A memo record kept beside the tally.
        #[arg(long)]
        memo: Option<String>,
        #[command(flatten)]
        mode: Mode,
    },
    /// Send plain sats.
    Send {
        /// A hex pubkey or an npub1….
        recipient: String,
        /// Sats to send.
        sats: u64,
        #[command(flatten)]
        mode: Mode,
    },
    /// Answer kind-23501 faucet requests on the relays with plain sats and,
    /// optionally, units of an asset; one grant per script per window. Runs
    /// until stopped; grants are posted, never only printed.
    Faucet {
        /// Plain sats per grant.
        #[arg(long, default_value_t = 2_000)]
        sats: u64,
        /// An asset to grant too (id or ticker).
        #[arg(long)]
        asset: Option<String>,
        /// Units of the asset per grant.
        #[arg(long, default_value_t = 100, requires = "asset")]
        units: u64,
        /// Hours before one script may be paid again.
        #[arg(long, default_value_t = 24)]
        per_address_hours: u64,
        /// Grants per hour, all scripts together.
        #[arg(long, default_value_t = 20)]
        per_hour: usize,
        /// Where grants are remembered across restarts (sidestr-agent faucet's format).
        #[arg(long)]
        state: PathBuf,
        /// Relays to follow and publish to, comma-separated.
        #[arg(
            long,
            value_delimiter = ',',
            default_value = "wss://nos.lol,wss://relay.damus.io,wss://relay.primal.net,wss://nostr.mom,wss://nostr.oxtr.dev"
        )]
        relays: Vec<String>,
    },
}

/// What happens to a built transaction.
#[derive(Debug, Args, Clone, Copy, PartialEq, Eq, Default)]
pub struct Mode {
    /// Build and check only: print no hex, post nothing.
    #[arg(long, conflicts_with = "post")]
    pub dry_run: bool,
    /// Post the signed transaction to the producer (`POST /tx`).
    #[arg(long)]
    pub post: bool,
}

/// Run the CLI; the exit code says whether it worked.
pub fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("runtime: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    match rt.block_on(run(cli)) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("nostr-bbs-sidestr-admin: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// The key from its file. The text is held in zeroizing memory and never
/// appears in an error.
fn read_key(path: &Path) -> Result<AgentKey, String> {
    let text = Zeroizing::new(
        std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?,
    );
    parse_key(&text).map_err(|e| format!("{}: {e}", path.display()))
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

struct Producer {
    base: String,
    http: reqwest::Client,
}

impl Producer {
    fn new(url: &str) -> Result<Self, String> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(120))
            .user_agent(concat!(
                "nostr-bbs-sidestr-admin/",
                env!("CARGO_PKG_VERSION")
            ))
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self {
            base: url.trim_end_matches('/').to_string(),
            http,
        })
    }

    async fn get(&self, path: &str) -> Result<reqwest::Response, String> {
        let r = self
            .http
            .get(format!("{}{path}", self.base))
            .send()
            .await
            .map_err(|e| format!("producer {path}: {e}"))?;
        if !r.status().is_success() {
            return Err(format!("producer {path}: HTTP {}", r.status()));
        }
        Ok(r)
    }

    /// The pinned chain, replayed: the producer's document must be the
    /// sealed one, and its blocks must validate against it.
    async fn replayed(&self, chain_id: &str) -> Result<Replayed, String> {
        let p = pin(chain_id.trim()).ok_or_else(|| {
            format!(
                "--chain-id {chain_id:?} is not a pinned chain (one of {})",
                PINS.map(|p| p.id).join(", ")
            )
        })?;
        let json = self
            .get("/chain.json")
            .await?
            .text()
            .await
            .map_err(|e| e.to_string())?;
        let doc = check_document(p, &json)?;
        let dat = self
            .get("/blocks.dat")
            .await?
            .bytes()
            .await
            .map_err(|e| e.to_string())?;
        let now = u32::try_from(now_secs()).ok();
        replay(doc, &dat, now)
    }

    /// `POST /tx`; the producer's txid must be the one built.
    async fn post(&self, spend: &Spend) -> Result<String, String> {
        let r = self
            .http
            .post(format!("{}/tx", self.base))
            .body(spend.hex.clone())
            .send()
            .await
            .map_err(|e| format!("producer /tx: {e}"))?;
        let status = r.status();
        let text = r.text().await.unwrap_or_default();
        let accepted = sidestr_wallet::deliver::parse_tx_response(&text)
            .map_err(|e| format!("the producer refused (HTTP {status}): {e}"))?;
        if accepted.txid != spend.txid.to_string() {
            return Err(format!(
                "the producer accepted {} but {} was built",
                accepted.txid, spend.txid
            ));
        }
        Ok(accepted.txid)
    }
}

async fn run(cli: Cli) -> Result<(), String> {
    let key_file = cli
        .key_file
        .as_deref()
        .ok_or("--key-file is required (64 hex or nsec1…)")?;
    let key = read_key(key_file)?;
    let producer = Producer::new(&cli.url)?;
    if let Command::Faucet {
        sats,
        asset,
        units,
        per_address_hours,
        per_hour,
        state,
        relays,
    } = cli.command
    {
        return faucet_run::run(
            &producer,
            &key,
            faucet_run::Settings {
                chain_id: cli.chain_id,
                asset: asset.map(|a| (a, units)),
                sats,
                per_address_hours,
                per_hour,
                state,
                relays,
            },
        )
        .await;
    }
    let r = producer.replayed(&cli.chain_id).await?;
    let me = key.pubkey().to_string();
    let doc = r.state.document();
    println!(
        "chain     {} beside {} · height {}",
        doc.id,
        doc.parent,
        r.state.height()
    );
    println!("producer  {}", producer.base);
    println!("key       {me}");
    let coins = r.state.coins(&key.script());
    match cli.command {
        Command::Assets => {
            let h = holdings(&r, &key.script());
            println!(
                "plain     {} sats on {} coins{}",
                h.plain_sats,
                h.plain_coins,
                if h.immature_sats > 0 {
                    format!(" (+{} immature)", h.immature_sats)
                } else {
                    String::new()
                }
            );
            if h.assets.is_empty() {
                println!("assets    none");
            } else {
                println!("assets    {} sats on carriers", h.carrier_sats);
                for a in &h.assets {
                    println!(
                        "  {}  {:<8}  {} (decimals {})",
                        a.id, a.ticker, a.held, a.decimals
                    );
                }
            }
            Ok(())
        }
        Command::Issue {
            ticker,
            supply,
            decimals,
            mode,
        } => {
            let spend = build_issue(&key, &r, &coins, &ticker, supply, decimals)?;
            println!(
                "issue     {ticker} · supply {supply} · decimals {decimals} · output 0 to the issuer"
            );
            println!("asset id  {}", spend.txid);
            finish(&producer, &spend, mode).await
        }
        Command::SendAsset {
            asset,
            recipient,
            units,
            memo,
            mode,
        } => {
            let id = resolve_asset(&r, &asset)?;
            let to = parse_recipient(&recipient)?;
            let t = build_asset_transfer(&key, &r, &coins, id, &to, units, memo.as_deref())?;
            let ticker = r
                .assets
                .issued()
                .get(&id)
                .map_or("?", |i| i.ticker.as_str());
            println!("send      {units} {ticker} ({id}) to {to}");
            println!("change    {} {ticker} back to the key", t.asset_change);
            if let Some(m) = &memo {
                println!("memo      {m}");
            }
            finish(&producer, &t.spend, mode).await
        }
        Command::Send {
            recipient,
            sats,
            mode,
        } => {
            let to = parse_recipient(&recipient)?;
            let spend = build_send(&key, &r, &coins, &to, sats)?;
            println!("send      {sats} sats to {to}");
            finish(&producer, &spend, mode).await
        }
        Command::Faucet { .. } => unreachable!("answered above"),
    }
}

/// Print the built spend, then post it, print its hex, or neither.
async fn finish(producer: &Producer, spend: &Spend, mode: Mode) -> Result<(), String> {
    println!("txid      {}", spend.txid);
    println!(
        "spend     {} inputs · fee {} sats · vsize {} vB · change {} sats",
        spend.inputs, spend.fee, spend.vsize, spend.change
    );
    if let Some(n) = &spend.note {
        println!("note      {n}");
    }
    if mode.dry_run {
        println!("dry run   built and checked in memory; no hex printed, nothing posted");
        return Ok(());
    }
    if mode.post {
        let txid = producer.post(spend).await?;
        println!("posted    {txid}");
    } else {
        println!("hex       {}", spend.hex);
        println!("not posted: re-run with --post to send it");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("nostr-bbs-sidestr-admin").chain(args.iter().copied()))
    }

    #[test]
    fn defaults_and_global_flags() {
        let c = parse(&["--key-file", "k", "assets"]).unwrap();
        assert_eq!(c.url, "http://127.0.0.1:3450");
        assert_eq!(c.chain_id, "sidestr:dreamlab");
        assert_eq!(c.key_file.as_deref(), Some(Path::new("k")));
        assert_eq!(c.command, Command::Assets);
        // the shared flags may follow the subcommand too
        let c = parse(&[
            "assets",
            "--url",
            "http://127.0.0.1:3451",
            "--chain-id",
            "sidestr:dreamlab-txbt4",
            "--key-file",
            "k",
        ])
        .unwrap();
        assert_eq!(
            (c.url.as_str(), c.chain_id.as_str()),
            ("http://127.0.0.1:3451", "sidestr:dreamlab-txbt4")
        );
    }

    #[test]
    fn issue_parses_with_its_modes() {
        let c = parse(&[
            "--key-file",
            "k",
            "issue",
            "BLAKES7",
            "10000000",
            "--dry-run",
        ])
        .unwrap();
        assert_eq!(
            c.command,
            Command::Issue {
                ticker: "BLAKES7".into(),
                supply: 10_000_000,
                decimals: 0,
                mode: Mode {
                    dry_run: true,
                    post: false
                },
            }
        );
        let c = parse(&["issue", "X", "5", "--decimals", "2", "--post"]).unwrap();
        assert!(matches!(
            c.command,
            Command::Issue {
                decimals: 2,
                mode: Mode {
                    post: true,
                    dry_run: false
                },
                ..
            }
        ));
        // the default neither posts nor dry-runs
        let c = parse(&["issue", "X", "5"]).unwrap();
        assert!(matches!(c.command, Command::Issue { mode, .. } if mode == Mode::default()));
        // --dry-run and --post together are refused
        assert!(parse(&["issue", "X", "5", "--dry-run", "--post"]).is_err());
        // supply is a whole number
        assert!(parse(&["issue", "X", "-5"]).is_err());
        assert!(parse(&["issue", "X", "1.5"]).is_err());
        assert!(parse(&["issue", "X", "5", "--decimals", "256"]).is_err());
    }

    #[test]
    fn sends_parse() {
        let c = parse(&[
            "send-asset",
            "DREAM",
            "npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg",
            "250",
            "--memo",
            "grant:hello",
        ])
        .unwrap();
        assert_eq!(
            c.command,
            Command::SendAsset {
                asset: "DREAM".into(),
                recipient: "npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg".into(),
                units: 250,
                memo: Some("grant:hello".into()),
                mode: Mode::default(),
            }
        );
        let c = parse(&["send", &"ab".repeat(32), "1000", "--post"]).unwrap();
        assert!(matches!(
            c.command,
            Command::Send {
                sats: 1000,
                mode: Mode { post: true, .. },
                ..
            }
        ));
        assert!(parse(&["send", "x"]).is_err());
        assert!(parse(&["send-asset", "DREAM", "x"]).is_err());
        // there is no flag that takes a key's value
        assert!(parse(&["--key", "abc", "assets"]).is_err());
        assert!(parse(&["--nsec", "abc", "assets"]).is_err());
    }

    #[test]
    fn faucet_parses_with_defaults_and_an_asset() {
        let c = parse(&["--key-file", "k", "faucet", "--state", "f.json"]).unwrap();
        match c.command {
            Command::Faucet {
                sats,
                asset,
                units,
                per_address_hours,
                per_hour,
                state,
                relays,
            } => {
                assert_eq!(
                    (sats, units, per_address_hours, per_hour),
                    (2_000, 100, 24, 20)
                );
                assert_eq!(asset, None);
                assert_eq!(state, PathBuf::from("f.json"));
                assert_eq!(relays.len(), 5);
            }
            other => panic!("{other:?}"),
        }
        let c = parse(&[
            "faucet",
            "--state",
            "f.json",
            "--asset",
            "BLAKES7",
            "--units",
            "50",
            "--sats",
            "1000",
            "--relays",
            "wss://a,wss://b",
        ])
        .unwrap();
        assert!(matches!(
            c.command,
            Command::Faucet { sats: 1_000, units: 50, ref asset, ref relays, .. }
                if asset.as_deref() == Some("BLAKES7") && relays.len() == 2
        ));
        // the ledger is required; units without an asset is refused
        assert!(parse(&["faucet"]).is_err());
        assert!(parse(&["faucet", "--state", "f", "--units", "5"]).is_err());
    }

    #[test]
    fn a_key_file_is_read_and_never_echoed() {
        let dir = std::env::temp_dir().join(format!("sidestr-admin-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let good = dir.join("good.key");
        std::fs::write(&good, format!("{}\n", "11".repeat(32))).unwrap();
        assert!(read_key(&good).is_ok());
        let bad = dir.join("bad.key");
        std::fs::write(&bad, "secretish-but-wrong").unwrap();
        let e = read_key(&bad).unwrap_err();
        assert!(!e.contains("secretish"), "{e}");
        assert!(read_key(&dir.join("missing.key")).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
