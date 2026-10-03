//! The coach service: one key, one relay inbox, one model. Each `[poker-coach]`
//! DM becomes one chat-completions call; the answer goes back as a `[coach]`
//! DM to whoever asked. Nothing is kept between requests but a window of
//! seen ids.

use std::collections::{HashSet, VecDeque};
use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use nostr_bbs_core::gift_wrap::{gift_wrap, unwrap_gift};
use nostr_bbs_core::keys::SecretKey;
use nostr_bbs_core::NostrEvent;
use serde_json::Value;
use tokio::sync::mpsc;
use tokio::time::{sleep, Instant};
use zeroize::Zeroizing;

use nostr_bbs_poker_citizen::coach;
use nostr_bbs_poker_citizen::net::{now_secs, Frame, Relay};

#[derive(Parser, Debug)]
#[command(
    name = "nostr-bbs-poker-coach",
    version,
    about = "The practice table's coach: answers each decision the table DMs it, from an OpenAI-compatible model, on its own key.",
    after_help = "The coach key is read from --key-file (64 hex or nsec1…), never from a flag's value. A bearer token for the model, when one is needed, is read from POKER_COACH_LLM_KEY only. The coach holds no funds and deals nothing."
)]
pub struct Cli {
    /// The coach's key file.
    #[arg(long, env = "POKER_COACH_KEY_FILE", value_name = "PATH")]
    key_file: PathBuf,
    /// The forum relay (wss://…).
    #[arg(long, env = "POKER_COACH_RELAY", value_name = "URL")]
    relay: String,
    /// The model's OpenAI-compatible base URL, up to and excluding
    /// `/chat/completions`.
    #[arg(long, env = "POKER_COACH_LLM_URL", value_name = "URL")]
    llm_url: String,
    /// The model name the endpoint expects.
    #[arg(long, env = "POKER_COACH_MODEL", value_name = "NAME")]
    model: String,
    /// Extra fields merged into every request, as a JSON object (a thinking
    /// switch, a façade's options). Overrides --llm-extra-file.
    #[arg(long, env = "POKER_COACH_LLM_EXTRA", value_name = "JSON")]
    llm_extra: Option<String>,
    /// A file holding the same JSON object.
    #[arg(long, env = "POKER_COACH_LLM_EXTRA_FILE", value_name = "PATH")]
    llm_extra_file: Option<PathBuf>,
    /// A file holding the system prompt, in place of the built-in one.
    #[arg(long, env = "POKER_COACH_SYSTEM_FILE", value_name = "PATH")]
    system_prompt_file: Option<PathBuf>,
    /// The most tokens the model may spend on one answer.
    #[arg(long, env = "POKER_COACH_MAX_TOKENS", default_value_t = 400)]
    max_tokens: u32,
    /// How long the model has before the table is told to play on. The table
    /// itself gives up at 30 s, so this stays under it.
    #[arg(long, env = "POKER_COACH_REPLY_SECS", default_value_t = 25)]
    reply_secs: u64,
    /// Requests older than this, by their rumor's clock, are left unanswered:
    /// the decision has passed.
    #[arg(long, default_value_t = 90)]
    max_age_secs: u64,
}

/// How many seen ids are kept before the oldest are forgotten.
const SEEN_CAP: usize = 4_096;
/// How far back the inbox REQ reaches. A gift wrap's outer timestamp is
/// randomised up to two days into the past (NIP-59), so a short window
/// would miss most of them; the rumor's own clock decides freshness.
const INBOX_LOOKBACK: u64 = 2 * 24 * 60 * 60 + 3_600;

/// An answer ready to send.
struct Reply {
    asker: String,
    content: String,
}

fn read_key(path: &PathBuf) -> Result<(Zeroizing<[u8; 32]>, String), String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let t = text.trim();
    let hex_text = if t.get(..5).is_some_and(|p| p.eq_ignore_ascii_case("nsec1")) {
        nostr_bbs_core::nip19::decode_nsec(t).map_err(|e| e.to_string())?
    } else {
        t.to_string()
    };
    let bytes = hex::decode(hex_text).map_err(|_| "the key file is not hex".to_string())?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "the key is not 32 bytes".to_string())?;
    let pubkey = SecretKey::from_bytes(arr)
        .map_err(|e| e.to_string())?
        .public_key()
        .to_hex();
    Ok((Zeroizing::new(arr), pubkey))
}

fn read_extra(cli: &Cli) -> Result<Option<Value>, String> {
    let text = match (&cli.llm_extra, &cli.llm_extra_file) {
        (Some(s), _) => s.clone(),
        (None, Some(p)) => {
            std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?
        }
        (None, None) => return Ok(None),
    };
    let v: Value = serde_json::from_str(&text).map_err(|e| format!("--llm-extra: {e}"))?;
    if !v.is_object() {
        return Err("--llm-extra must be a JSON object".into());
    }
    Ok(Some(v))
}

/// Run the coach until the process is stopped.
pub async fn main() -> Result<(), String> {
    let cli = Cli::parse();
    let (sk, pubkey) = read_key(&cli.key_file)?;
    let system = match &cli.system_prompt_file {
        Some(p) => std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?,
        None => coach::DEFAULT_SYSTEM_PROMPT.to_string(),
    };
    let extra = read_extra(&cli)?;
    let llm_key = std::env::var("POKER_COACH_LLM_KEY")
        .ok()
        .filter(|k| !k.trim().is_empty());
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(cli.reply_secs))
        .user_agent(concat!("nostr-bbs-poker-coach/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| e.to_string())?;
    eprintln!(
        "coach {pubkey} on {} · model {} at {} · {} s to answer",
        cli.relay, cli.model, cli.llm_url, cli.reply_secs
    );
    let (tx, mut rx) = mpsc::channel::<Reply>(64);
    let mut runner = Runner {
        cli,
        sk,
        pubkey,
        system,
        extra,
        llm_key,
        http,
        tx,
        started: now_secs(),
        seen: HashSet::new(),
        seen_order: VecDeque::new(),
        thinking_for: HashSet::new(),
    };
    let mut backoff = 2u64;
    loop {
        match Relay::connect(&runner.cli.relay, &runner.sk, &runner.pubkey).await {
            Ok(mut relay) => {
                backoff = 2;
                if !relay.authenticated() {
                    eprintln!("relay did not challenge for AUTH; the inbox may be refused");
                }
                if let Err(e) = relay
                    .subscribe_inbox(now_secs().saturating_sub(INBOX_LOOKBACK))
                    .await
                {
                    eprintln!("relay: REQ failed: {e}");
                    sleep(Duration::from_secs(backoff)).await;
                    continue;
                }
                eprintln!("relay: inbox open");
                runner.serve(&mut relay, &mut rx).await;
                eprintln!("relay: connection lost; reconnecting in {backoff}s");
            }
            Err(e) => eprintln!("relay: {e}; retrying in {backoff}s"),
        }
        sleep(Duration::from_secs(backoff)).await;
        backoff = (backoff * 2).min(60);
    }
}

struct Runner {
    cli: Cli,
    sk: Zeroizing<[u8; 32]>,
    pubkey: String,
    system: String,
    extra: Option<Value>,
    llm_key: Option<String>,
    http: reqwest::Client,
    tx: mpsc::Sender<Reply>,
    started: u64,
    seen: HashSet<String>,
    seen_order: VecDeque<String>,
    thinking_for: HashSet<String>,
}

impl Runner {
    fn remember(&mut self, id: &str) -> bool {
        if !self.seen.insert(id.to_string()) {
            return false;
        }
        self.seen_order.push_back(id.to_string());
        while self.seen_order.len() > SEEN_CAP {
            if let Some(old) = self.seen_order.pop_front() {
                self.seen.remove(&old);
            }
        }
        true
    }

    async fn serve(&mut self, relay: &mut Relay, rx: &mut mpsc::Receiver<Reply>) {
        loop {
            tokio::select! {
                frame = relay.next() => match frame {
                    Frame::Event(ev) => self.on_event(ev),
                    Frame::Ok { accepted: false, id, message } => {
                        eprintln!("relay refused {}…: {message}", &id[..8.min(id.len())]);
                    }
                    Frame::Notice(n) => eprintln!("relay notice: {n}"),
                    Frame::Closed(why) => {
                        eprintln!("relay closed the inbox: {why}");
                        return;
                    }
                    Frame::Disconnected => return,
                    _ => {}
                },
                Some(reply) = rx.recv() => {
                    self.thinking_for.remove(&reply.asker);
                    match gift_wrap(&self.sk, &self.pubkey, &reply.asker, &reply.content) {
                        Ok(wrap) => {
                            if let Err(e) = relay.publish(&wrap).await {
                                eprintln!("reply to {}…: {e}", &reply.asker[..8]);
                            }
                        }
                        Err(e) => eprintln!("wrap to {}…: {e}", &reply.asker[..8]),
                    }
                }
            }
        }
    }

    fn on_event(&mut self, ev: NostrEvent) {
        let unwrapped = match unwrap_gift(&ev, &self.sk) {
            Ok(u) => u,
            Err(_) => return, // not a DM, or not ours
        };
        let asker = unwrapped.sender_pubkey;
        let rumor = unwrapped.rumor;
        if !coach::is_request(&rumor.content) || asker == self.pubkey {
            return;
        }
        let id = rumor_id(&rumor).unwrap_or_else(|| ev.id.clone());
        if !self.remember(&id) {
            return;
        }
        let now = now_secs();
        let floor = self.started.saturating_sub(self.cli.max_age_secs);
        if rumor.created_at < floor || now.saturating_sub(rumor.created_at) > self.cli.max_age_secs
        {
            return; // the decision has passed
        }
        if !self.thinking_for.insert(asker.clone()) {
            eprintln!(
                "coach: still thinking for {}…; this request is dropped",
                &asker[..8]
            );
            return;
        }
        let body = coach::chat_request(
            &self.cli.model,
            &self.system,
            &rumor.content,
            self.cli.max_tokens,
            self.extra.as_ref(),
        );
        let mut req = self
            .http
            .post(format!(
                "{}/chat/completions",
                self.cli.llm_url.trim_end_matches('/')
            ))
            .header("content-type", "application/json");
        if let Some(k) = &self.llm_key {
            req = req.bearer_auth(k);
        }
        let tx = self.tx.clone();
        tokio::spawn(async move {
            let t0 = Instant::now();
            let answer = match req.body(body.to_string()).send().await {
                Ok(r) => {
                    let status = r.status();
                    match r.text().await {
                        Ok(text) if status.is_success() => coach::answer_from(&text),
                        Ok(text) => {
                            let head: String = text.chars().take(160).collect();
                            eprintln!("model: HTTP {status}: {head}");
                            None
                        }
                        Err(e) => {
                            eprintln!("model: {e}");
                            None
                        }
                    }
                }
                Err(e) => {
                    eprintln!("model: {e}");
                    None
                }
            };
            let content = match answer {
                Some(a) => coach::reply_content(&a),
                None => coach::FALLBACK_REPLY.to_string(),
            };
            eprintln!(
                "coach: answered {}… in {:.1}s ({} chars)",
                &asker[..8],
                t0.elapsed().as_secs_f32(),
                content.chars().count()
            );
            let _ = tx.send(Reply { asker, content }).await;
        });
    }
}

/// The rumor's NIP-01 id, computed here: the relay re-serves the same wrap
/// on every re-REQ, and a sender may wrap one rumor more than once, so the
/// rumor, not the wrap, is what was asked.
fn rumor_id(rumor: &nostr_bbs_core::UnsignedEvent) -> Option<String> {
    Some(hex::encode(nostr_bbs_core::event::compute_event_id(rumor)))
}
