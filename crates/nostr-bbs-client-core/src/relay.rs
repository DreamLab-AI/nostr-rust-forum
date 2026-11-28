//! WebSocket relay connection manager for NIP-01 Nostr protocol.
//!
//! Manages a single WebSocket connection to the nostr-bbs relay, handling
//! subscriptions, event parsing, publishing, auto-reconnect with exponential
//! backoff, and connection state as a reactive Leptos signal.
//!
//! Uses `SendWrapper` to satisfy `Send + Sync` bounds required by Leptos
//! context in CSR mode. All access is single-threaded on the WASM main
//! thread, so this is safe.

use leptos::prelude::*;
use nostr_bbs_core::{NostrEvent, UnsignedEvent};
use send_wrapper::SendWrapper;
use serde_json::Value;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::rc::Rc;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::JsCast;
use web_sys::WebSocket;

pub mod info;
mod receipt;
mod verified;
use receipt::{
    classify_auth_ok, explain_write_refusal, logical_id, release_held_writes, req_watch_delay,
    req_wire_id, route, watch_due, wire_id, AuthReply, HandshakeView, ReqLedger, Route, Watch,
    WatchDue, AUTH_ANSWER_TIMEOUT_MS, AUTH_SIGN_TIMEOUT_MS,
};

/// Default relay URL when VITE_RELAY_URL is not set.
const DEFAULT_RELAY_URL: &str = "wss://relay.example.com";

/// Maximum reconnect delay in milliseconds.
const MAX_RECONNECT_DELAY_MS: u32 = 30_000;

/// Base reconnect delay in milliseconds.
const BASE_RECONNECT_DELAY_MS: u32 = 1_000;

/// Client-side send pacing: at most this many REQ/EVENT/CLOSE frames per
/// rolling second. The relay-worker drops frames beyond a per-IP cap
/// (`MAX_EVENTS_PER_SECOND = 10` in `relay_do/broadcast.rs`) with only a
/// NOTICE — at boot the client's burst (initial REQs + kind-0/10002
/// publishes + the post-AUTH replay) exceeded it, silently losing the
/// message subscriptions ("0 messages" everywhere). Pacing below the cap
/// leaves headroom for the AUTH frame and clock skew; overflow is delayed
/// into the next window, never dropped.
const MAX_SENDS_PER_SECOND: usize = 8;

/// Rolling window for [`MAX_SENDS_PER_SECOND`], in milliseconds.
const SEND_WINDOW_MS: f64 = 1_000.0;

/// The `left_total` that means every frame queued so far has left: those
/// already pushed onto the paced queue, plus `held` frames (held for AUTH or
/// a reconnect) that will be pushed onto it ahead of anything queued later.
fn send_mark(queued_total: u64, held: usize) -> u64 {
    queued_total.saturating_add(held as u64)
}

/// How often [`RelayConnection::wait_until_sent`] re-checks the queue.
const QUEUE_POLL_MS: i32 = 200;

/// The time `frames` queued frames take to leave this client under its send
/// pacing (`MAX_SENDS_PER_SECOND` per `SEND_WINDOW_MS`), assuming an open
/// socket. A timer for a request queued behind them must allow at least this
/// much before its own round trip begins.
pub fn drain_time_ms(frames: usize) -> u32 {
    let windows = u32::try_from(frames.div_ceil(MAX_SENDS_PER_SECOND)).unwrap_or(u32::MAX);
    windows.saturating_mul(SEND_WINDOW_MS as u32)
}

/// Connection state for the relay WebSocket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Reconnecting,
    Error,
}

/// A NIP-01 subscription filter.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct Filter {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authors: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kinds: Option<Vec<u64>>,
    #[serde(rename = "#e", skip_serializing_if = "Option::is_none")]
    pub e_tags: Option<Vec<String>>,
    #[serde(rename = "#p", skip_serializing_if = "Option::is_none")]
    pub p_tags: Option<Vec<String>>,
    /// `#t` topic-tag filter. Colloquy knowledge units carry one `t` per domain
    /// tag so a subscription can follow a subject rather than an author.
    #[serde(rename = "#t", skip_serializing_if = "Option::is_none")]
    pub t_tags: Option<Vec<String>>,
    /// `#d` filter, for addressable events such as kind-30078 app data.
    #[serde(rename = "#d", skip_serializing_if = "Option::is_none")]
    pub d_tags: Option<Vec<String>>,
    /// `#sealed` filter: a sealed original by its INNER (original) id, which
    /// the envelope names in its `["sealed", <inner id>, "1"]` tag.
    #[serde(rename = "#sealed", skip_serializing_if = "Option::is_none")]
    pub sealed_tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub until: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,
    /// NIP-50 full-text query. The relay-worker matches it as a
    /// case-insensitive substring of `content` (`relay_do/filter.rs`), so a
    /// member can find their own post by a word in it without that post ever
    /// having reached the vector index.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search: Option<String>,
}

/// Callback type for received events on a subscription.
pub type EventCallback = Rc<dyn Fn(NostrEvent)>;

/// Callback type for EOSE (End of Stored Events) on a subscription.
pub type EoseCallback = Rc<dyn Fn()>;

/// Callback for an EOSE that also says whether it is an *authenticated*
/// "that is everything": `true` only once every REQ sent for the
/// subscription has been answered and the latest went out after the relay
/// accepted our NIP-42 AUTH (see `receipt::ReqLedger`). Pages that must not
/// call a members-only thing "absent" on an anonymous answer use this.
pub type ReceiptCallback = Rc<dyn Fn(bool)>;

/// Called with the CLOSED reason (see `subscribe_with_receipt_or_closed`).
pub type ClosedCallback = Rc<dyn Fn(String)>;

/// Callback for a NIP-45 COUNT answer: the number of events matching the
/// filters, as the relay counts them for this session.
pub type CountCallback = Rc<dyn Fn(u64)>;

/// Callback type for publish acknowledgement (accepted: bool, message: String).
pub type PublishCallback = Rc<dyn Fn(bool, String)>;

/// Called once with a `SECTION-STATS` answer's payload, or the reason it was
/// refused (`CLOSED`) or is unsupported (ADR-2038).
pub type SectionStatsCallback = Rc<dyn Fn(Result<Value, String>)>;

/// Tracks a pending publish awaiting relay OK response.
struct PendingPublish {
    on_ok: Option<PublishCallback>,
}

/// Internal subscription tracking.
struct Subscription {
    filters: Vec<Filter>,
    on_event: EventCallback,
    on_eose: Option<EoseCallback>,
    on_receipt: Option<ReceiptCallback>,
    /// Called with the reason when the relay refuses or ends this
    /// subscription with CLOSED (one-shot history pages take it as their
    /// answer: an over-cap REQ is refused with CLOSED, not EOSE).
    on_closed: Option<ClosedCallback>,
    /// REQs sent for this subscription on the current socket and not yet
    /// answered, and whether the latest went out after AUTH was accepted.
    ledger: ReqLedger,
    /// The id this subscription currently uses on the wire. Starts as the
    /// logical id; a re-send after an unanswered REQ retires it for a fresh
    /// one (see [`receipt::wire_id`]) so late answers to the abandoned REQ
    /// can be told apart and discarded.
    wire_id: String,
    wire_gen: u32,
}

/// Our kind-22242 AUTH event, sent and awaiting the relay's `OK`.
struct PendingAuth {
    event_id: String,
    frame: String,
    attempts: u32,
    /// When the frame (or its latest re-send) went out, epoch ms.
    sent_at: f64,
}

/// A NIP-45 COUNT awaiting its answer. Kept (not removed on the first
/// answer) because the frame is re-sent after NIP-42 AUTH like a REQ is: the
/// relay answers an unauthenticated COUNT on protected kinds with 0, so the
/// later, authenticated answer must still find its callback.
struct PendingCount {
    filters: Vec<Filter>,
    on_count: CountCallback,
}

/// Synchronous signer for NIP-42 AUTH (nsec / passkey logins).
pub type AuthSignCallback = Rc<dyn Fn(UnsignedEvent) -> Option<NostrEvent>>;

/// Async signer for NIP-42 AUTH (NIP-07 browser extension logins).
pub type AuthSignAsyncCallback = Rc<
    dyn Fn(
        UnsignedEvent,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<NostrEvent>>>>,
>;

/// Internal mutable state for the relay connection.
struct RelayInner {
    ws: Option<WebSocket>,
    subscriptions: HashMap<String, Subscription>,
    counts: HashMap<String, PendingCount>,
    /// `SECTION-STATS` requests awaiting their answer (ADR-2038), by id.
    /// Removed on the answer, a `CLOSED`, or the caller's timeout.
    section_stats: HashMap<String, SectionStatsCallback>,
    pending_publishes: HashMap<String, PendingPublish>,
    sub_counter: u32,
    reconnect_attempts: u32,
    pending_messages: Vec<String>,
    /// Timestamps (ms) of frames sent in the current [`SEND_WINDOW_MS`]
    /// window — the client half of the relay's per-IP rate limit.
    send_times: Vec<f64>,
    /// Frames awaiting a send slot. Drained FIFO by [`drain_send_queue`].
    send_queue: VecDeque<String>,
    /// Frames ever pushed onto `send_queue`, and frames that have left it
    /// (sent, or dropped by a reconnect or disconnect). Their difference is
    /// `send_queue.len()`; [`RelayConnection::wait_until_sent`] waits on
    /// `left_total` to reach a mark taken when it was called.
    queued_total: u64,
    left_total: u64,
    /// Whether a delayed drain is already scheduled (avoids timer pile-up).
    drain_scheduled: bool,
    relay_url: String,
    /// A one-shot connection to a foreign relay (see [`RelayConnection::to_url`]):
    /// writes go out as soon as the socket is open instead of waiting for a
    /// NIP-42 AUTH that a foreign relay may never ask for.
    immediate_writes: bool,
    /// Per-subscription dedup of delivered events, keyed `"{sub_id}:{event_id}"`.
    ///
    /// The relay sends one EVENT frame per MATCHING SUBSCRIPTION, so the same
    /// event legitimately arrives once per overlapping sub. Deduping on the
    /// bare event id let whichever subscription's frame arrived first STARVE
    /// every other subscription of that event (e.g. an app-level governance
    /// subscription swallowing kind-31403 decisions a page-level board
    /// subscription also needs). Scoping the key to the subscription keeps the
    /// replay/reconnect dedup while delivering each event to every sub once.
    seen_events: HashSet<String>,
    /// Events whose signature has been verified this session (see
    /// [`verified`]); a re-delivery skips only the Schnorr check.
    verified: verified::VerifiedIds,
    /// PRD-010 G4: EVENT (write) frames deferred because the socket is connected
    /// but has not yet completed NIP-42 AUTH. In `nip42` mode the relay rejects
    /// unauthenticated writes with `["OK", id, false, "auth-required: …"]`, so
    /// rather than fire-and-lose them we hold writes here and flush them the
    /// instant the relay accepts AUTH (see `replay_after_auth`). Public
    /// READ subscriptions are never deferred — they stay non-blocking.
    deferred_writes: Vec<String>,
    auth_signer: Option<AuthSignCallback>,
    auth_signer_async: Option<AuthSignAsyncCallback>,
    /// Reactive sink for relay NOTICE messages (cloned from the outer
    /// `RelayConnection::notice` signal so `handle_relay_message` can publish).
    notice_sink: Option<RwSignal<Option<RelayNotice>>>,
    /// Reactive sink for the NIP-42 authenticated flag (cloned from the outer
    /// `RelayConnection::authenticated` signal so the AUTH handler can flip it
    /// once the auth response has been signed + sent and subscriptions replayed).
    authed_sink: Option<RwSignal<bool>>,
    /// Rate-limit state for NOTICE dedup: last surfaced text + epoch-ms time.
    last_notice: Option<(String, f64)>,
    /// Monotonic counter so each surfaced notice has a distinct `seq`.
    notice_seq: u64,
    /// The relay answered our AUTH with `OK true` on the current socket.
    /// Distinct from the public `authenticated` signal's old meaning ("AUTH
    /// frame sent"): a REQ the relay began before it accepted AUTH is
    /// answered anonymously, so only REQs sent after this flips may produce an
    /// authenticated receipt.
    auth_accepted: bool,
    pending_auth: Option<PendingAuth>,
    /// The relay refused our AUTH on the current socket. Writes stop being
    /// deferred, so the relay's refusal reaches each publish callback.
    auth_refused: bool,
    /// When the current socket's NIP-42 challenge arrived (epoch ms), while
    /// the handshake is unresolved. Drives the stall bound.
    auth_challenge_at: Option<f64>,
    /// Why this socket's sign-in did not complete, once it has been given up
    /// on. Turns the relay's bare `auth-required:` refusal of a post into an
    /// explanation (see [`receipt::explain_write_refusal`]).
    auth_note: Option<String>,
    /// When each wire subscription id's latest REQ actually left the paced
    /// send queue on the current socket (epoch ms). A REQ's answer timeout
    /// runs from this, not from when it was queued.
    req_sent_at: HashMap<String, f64>,
    /// Bumped on every new socket, so a timer armed for the old one (AUTH
    /// retry, stall check, REQ answer timeout) can tell it is stale.
    conn_gen: u64,
    _on_open: Option<Closure<dyn FnMut()>>,
    _on_message: Option<Closure<dyn FnMut(web_sys::MessageEvent)>>,
    _on_error: Option<Closure<dyn FnMut(web_sys::ErrorEvent)>>,
    _on_close: Option<Closure<dyn FnMut(web_sys::CloseEvent)>>,
}

/// Thread-safe wrapper around the relay inner state.
/// `SendWrapper` asserts single-thread access at runtime, which is
/// guaranteed in WASM.
type SharedInner = SendWrapper<Rc<RefCell<RelayInner>>>;

/// A relay NOTICE message surfaced to the UI. Carries a monotonically
/// increasing `seq` so consumers can react to *every* notice (even a repeat of
/// the same text) without missing one, while the relay layer still suppresses
/// rapid duplicates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayNotice {
    /// The human-readable notice text from the relay.
    pub message: String,
    /// Monotonic sequence — changes on every surfaced notice.
    pub seq: u64,
}

/// Relay connection manager. Provided as Leptos context so any component
/// can subscribe to events or publish.
#[derive(Clone)]
pub struct RelayConnection {
    inner: SharedInner,
    state: RwSignal<ConnectionState>,
    /// Whether the current socket has completed NIP-42 AUTH. Flips `true` once
    /// the relay ACCEPTS the AUTH response (its `OK true`) and subscriptions
    /// have been replayed, and back
    /// to `false` whenever the socket (re)connects or disconnects. AUTH-gated
    /// REQs (kind-1059 DMs, gated zones) must wait for this to avoid racing the
    /// handshake — critical for slow NIP-07 extensions where signing the AUTH
    /// challenge round-trips through `window.nostr` (and may prompt the user),
    /// which can easily exceed a fixed re-subscribe timer.
    authenticated: RwSignal<bool>,
}

// SAFETY: In WASM, there is only one thread. SendWrapper enforces this
// at runtime. These impls allow RelayConnection to be used with
// provide_context.
#[cfg(target_arch = "wasm32")]
unsafe impl Send for RelayConnection {}
#[cfg(target_arch = "wasm32")]
unsafe impl Sync for RelayConnection {}

/// Queue a frame for paced sending and kick the drain. See
/// [`MAX_SENDS_PER_SECOND`] for why the client self-limits.
fn queue_paced(inner_rc: &Rc<RefCell<RelayInner>>, msg: String) {
    {
        let mut inner = inner_rc.borrow_mut();
        inner.send_queue.push_back(msg);
        inner.queued_total += 1;
    }
    drain_send_queue(inner_rc.clone());
}

/// Send queued frames while the rolling window has budget; when the budget
/// is exhausted, schedule a one-shot drain for when the oldest send ages out
/// of the window. Frames are only dequeued while the socket is OPEN — on a
/// closed socket they wait for the reconnect flush in `on_open`.
fn drain_send_queue(inner_rc: Rc<RefCell<RelayInner>>) {
    let (batch, ws, retry_in) = {
        let mut inner = inner_rc.borrow_mut();
        let now = js_sys::Date::now();
        inner.send_times.retain(|&ts| ts >= now - SEND_WINDOW_MS);

        let ws = match &inner.ws {
            Some(ws) if ws.ready_state() == WebSocket::OPEN => ws.clone(),
            _ => return,
        };

        let budget = MAX_SENDS_PER_SECOND.saturating_sub(inner.send_times.len());
        let mut batch = Vec::new();
        for _ in 0..budget {
            match inner.send_queue.pop_front() {
                Some(m) => {
                    inner.left_total += 1;
                    inner.send_times.push(now);
                    if let Some(wire) = req_wire_id(&m) {
                        let wire = wire.to_string();
                        inner.req_sent_at.insert(wire, now);
                    }
                    batch.push(m);
                }
                None => break,
            }
        }

        let retry_in = if inner.send_queue.is_empty() || inner.drain_scheduled {
            None
        } else {
            inner.drain_scheduled = true;
            // Wake just after the oldest timestamp leaves the window.
            let oldest = inner.send_times.first().copied().unwrap_or(now);
            Some(((oldest + SEND_WINDOW_MS - now).max(0.0) as i32) + 15)
        };
        (batch, ws, retry_in)
    };

    for msg in batch {
        let _ = ws.send_with_str(&msg);
    }
    if let Some(delay_ms) = retry_in {
        let rc = inner_rc.clone();
        crate::utils::set_timeout_once(
            move || {
                rc.borrow_mut().drain_scheduled = false;
                drain_send_queue(rc.clone());
            },
            delay_ms,
        );
    }
}

impl Default for RelayConnection {
    fn default() -> Self {
        Self::new()
    }
}

impl RelayConnection {
    /// Create a new relay connection manager. Does not connect immediately.
    pub fn new() -> Self {
        Self::build(get_relay_url(), false)
    }

    /// A short-lived connection to a relay that is not ours (a recipient's
    /// NIP-17 inbox relay). Writes are never held back for NIP-42 AUTH: a
    /// foreign relay that never issues a challenge would otherwise leave the
    /// session "unauthenticated" for ever and the frame unsent. Does not connect
    /// immediately; the caller must [`disconnect`](Self::disconnect) it, which
    /// also ends the reconnect loop.
    pub fn to_url(url: &str) -> Self {
        Self::build(url.to_string(), true)
    }

    fn build(relay_url: String, immediate_writes: bool) -> Self {
        let inner = Rc::new(RefCell::new(RelayInner {
            ws: None,
            subscriptions: HashMap::new(),
            counts: HashMap::new(),
            section_stats: HashMap::new(),
            pending_publishes: HashMap::new(),
            sub_counter: 0,
            reconnect_attempts: 0,
            pending_messages: Vec::new(),
            send_times: Vec::new(),
            send_queue: VecDeque::new(),
            queued_total: 0,
            left_total: 0,
            drain_scheduled: false,
            relay_url,
            immediate_writes,
            seen_events: HashSet::new(),
            verified: verified::VerifiedIds::default(),
            deferred_writes: Vec::new(),
            auth_signer: None,
            auth_signer_async: None,
            notice_sink: None,
            authed_sink: None,
            last_notice: None,
            notice_seq: 0,
            auth_accepted: false,
            pending_auth: None,
            auth_refused: false,
            auth_challenge_at: None,
            auth_note: None,
            req_sent_at: HashMap::new(),
            conn_gen: 0,
            _on_open: None,
            _on_message: None,
            _on_error: None,
            _on_close: None,
        }));
        let notice = RwSignal::new(None);
        let authenticated = RwSignal::new(false);
        {
            let mut b = inner.borrow_mut();
            b.notice_sink = Some(notice);
            b.authed_sink = Some(authenticated);
        }
        Self {
            inner: SendWrapper::new(inner),
            state: RwSignal::new(ConnectionState::Disconnected),
            authenticated,
        }
    }

    /// Reactive signal: `true` once the current socket has completed NIP-42 AUTH.
    ///
    /// AUTH-gated subscriptions (kind-1059 DMs, gated zones) should wait for this
    /// rather than firing on `ConnectionState::Connected`, which races the AUTH
    /// handshake. Resets to `false` on every (re)connect and on disconnect.
    pub fn authenticated(&self) -> RwSignal<bool> {
        self.authenticated
    }

    /// Get the reactive connection state signal.
    pub fn connection_state(&self) -> RwSignal<ConnectionState> {
        self.state
    }

    /// Register a synchronous signer for NIP-42 AUTH challenges (nsec / passkey).
    pub fn set_auth_signer(&self, signer: AuthSignCallback) {
        self.with_inner(|rc| {
            rc.borrow_mut().auth_signer = Some(signer);
        });
    }

    /// Register an async signer for NIP-42 AUTH challenges (NIP-07 extension).
    pub fn set_auth_signer_async(&self, signer: AuthSignAsyncCallback) {
        self.with_inner(|rc| {
            rc.borrow_mut().auth_signer_async = Some(signer);
        });
    }

    /// Access the inner Rc.
    fn with_inner<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&Rc<RefCell<RelayInner>>) -> R,
    {
        f(&self.inner)
    }

    /// Connect to the relay WebSocket.
    pub fn connect(&self) {
        let url = self.with_inner(|rc| rc.borrow().relay_url.clone());
        self.connect_to(&url);
    }

    /// Connect to a specific relay URL.
    fn connect_to(&self, url: &str) {
        // Close existing connection. Detach the JS event handlers BEFORE the
        // closures are dropped below — otherwise the closing socket fires
        // onclose/onmessage on a later tick and invokes a freed Closure
        // ("closure invoked recursively or after being dropped", thrown from
        // WebSocket.real), and that stale onclose also re-triggers
        // schedule_reconnect() (state is not Disconnected here) → reconnect storm.
        self.with_inner(|rc| {
            let mut inner = rc.borrow_mut();
            if let Some(ws) = inner.ws.take() {
                ws.set_onopen(None);
                ws.set_onmessage(None);
                ws.set_onerror(None);
                ws.set_onclose(None);
                let _ = ws.close();
            }
            inner._on_open = None;
            inner._on_message = None;
            inner._on_error = None;
            inner._on_close = None;
        });

        self.state.set(ConnectionState::Connecting);

        let ws = match WebSocket::new(url) {
            Ok(ws) => ws,
            Err(e) => {
                web_sys::console::error_1(
                    &format!("[Relay] Failed to create WebSocket: {:?}", e).into(),
                );
                self.state.set(ConnectionState::Error);
                self.schedule_reconnect();
                return;
            }
        };

        ws.set_binary_type(web_sys::BinaryType::Arraybuffer);

        // --- onopen ---
        let inner_rc = (*self.inner).clone();
        let state = self.state;
        let on_open = Closure::wrap(Box::new(move || {
            web_sys::console::log_1(&"[Relay] WebSocket connected".into());
            let (frames, watches, authed_sink) = {
                let mut inner = inner_rc.borrow_mut();
                inner.reconnect_attempts = 0;
                inner.seen_events.clear();
                inner.conn_gen += 1;
                // A fresh socket starts anonymous until the relay accepts AUTH.
                inner.auth_accepted = false;
                inner.pending_auth = None;
                inner.auth_refused = false;
                inner.auth_note = None;
                // Send times belong to the old socket's frames.
                inner.req_sent_at.clear();
                // The handshake clock starts at connect, so a relay that never
                // sends a challenge cannot hold writes forever either; the
                // challenge, when it arrives, restarts the clock.
                inner.auth_challenge_at = Some(js_sys::Date::now());
                // Flush pending frames queued while the socket was down —
                // EXCEPT REQs: every live subscription is replayed below, so
                // flushing a queued REQ too double-sends it (observed at boot,
                // where the duplicate burned rate-limit budget).
                let mut frames: Vec<String> = inner
                    .pending_messages
                    .drain(..)
                    .filter(|m| !m.starts_with("[\"REQ\""))
                    .collect();
                // Same for REQs still in the paced queue from the previous
                // socket (a reconnect without `disconnect` keeps the queue):
                // the replay below re-sends them, and an uncounted extra REQ
                // would let the ledger call an anonymous answer authenticated.
                let before = inner.send_queue.len();
                inner.send_queue.retain(|m| !m.starts_with("[\"REQ\""));
                inner.left_total += (before - inner.send_queue.len()) as u64;
                // Replay subscriptions on (re)connect. Answers owed on the old
                // socket will never arrive, so each ledger restarts here.
                let mut watches = Vec::new();
                for (sub_id, sub) in inner.subscriptions.iter_mut() {
                    sub.ledger.reset();
                    let seq = sub.ledger.sent(false);
                    if let Some(msg) = req_frame(&sub.wire_id, &sub.filters) {
                        frames.push(msg);
                    }
                    watches.push((sub_id.clone(), seq, 0));
                }
                (frames, watches, inner.authed_sink)
            };
            // Borrow released — the paced queue re-borrows per frame.
            for msg in frames {
                queue_paced(&inner_rc, msg);
            }
            for (sub_id, seq, resends) in watches {
                arm_req_watch(&inner_rc, sub_id, seq, resends);
            }
            arm_auth_stall_check(&inner_rc, AUTH_SIGN_TIMEOUT_MS);
            // A fresh socket is not yet NIP-42 authenticated. Cleared BEFORE
            // Connected is announced, so an effect fired by Connected never
            // sees the previous socket's `true` and writes before AUTH. Set
            // after the borrow ends so a reactive effect reading
            // `authenticated` cannot re-enter this RefCell.
            if let Some(sig) = authed_sink {
                sig.set(false);
            }
            // Announce Connected only now: an effect that subscribes on it
            // then sends (and counts) its own REQ after the replay above has
            // reset and counted every ledger, so no REQ goes uncounted.
            state.set(ConnectionState::Connected);
        }) as Box<dyn FnMut()>);
        ws.set_onopen(Some(on_open.as_ref().unchecked_ref()));

        // --- onmessage ---
        let inner_rc_msg = (*self.inner).clone();
        let on_message = Closure::wrap(Box::new(move |e: web_sys::MessageEvent| {
            if let Some(text) = e.data().as_string() {
                handle_relay_message(&inner_rc_msg, &text);
            }
        }) as Box<dyn FnMut(web_sys::MessageEvent)>);
        ws.set_onmessage(Some(on_message.as_ref().unchecked_ref()));

        // --- onerror ---
        let state_err = self.state;
        let on_error = Closure::wrap(Box::new(move |_e: web_sys::ErrorEvent| {
            web_sys::console::error_1(&"[Relay] WebSocket error".into());
            state_err.set(ConnectionState::Error);
        }) as Box<dyn FnMut(web_sys::ErrorEvent)>);
        ws.set_onerror(Some(on_error.as_ref().unchecked_ref()));

        // --- onclose ---
        let self_clone = self.clone();
        let on_close = Closure::wrap(Box::new(move |_e: web_sys::CloseEvent| {
            web_sys::console::log_1(&"[Relay] WebSocket closed".into());
            // Invalidate every timer armed for this socket (AUTH retry, stall
            // check, REQ timeouts) now, not at the next open: a stall check
            // firing during the reconnect backoff would otherwise release held
            // writes into a queue that the next socket flushes before its AUTH.
            self_clone.with_inner(|rc| rc.borrow_mut().conn_gen += 1);
            let current = self_clone.state.get_untracked();
            if current != ConnectionState::Disconnected {
                self_clone.state.set(ConnectionState::Reconnecting);
                self_clone.schedule_reconnect();
            }
        }) as Box<dyn FnMut(web_sys::CloseEvent)>);
        ws.set_onclose(Some(on_close.as_ref().unchecked_ref()));

        // Store everything
        self.with_inner(|rc| {
            let mut inner = rc.borrow_mut();
            inner.ws = Some(ws);
            inner._on_open = Some(on_open);
            inner._on_message = Some(on_message);
            inner._on_error = Some(on_error);
            inner._on_close = Some(on_close);
        });
    }

    /// Disconnect from the relay and stop reconnecting.
    pub fn disconnect(&self) {
        self.state.set(ConnectionState::Disconnected);
        self.authenticated.set(false);
        self.with_inner(|rc| {
            let mut inner = rc.borrow_mut();
            if let Some(ws) = inner.ws.take() {
                // Detach handlers before dropping the closures so the closing
                // socket cannot invoke a freed Closure on a later tick.
                ws.set_onopen(None);
                ws.set_onmessage(None);
                ws.set_onerror(None);
                ws.set_onclose(None);
                let _ = ws.close();
            }
            inner._on_open = None;
            inner._on_message = None;
            inner._on_error = None;
            inner._on_close = None;
            inner.auth_accepted = false;
            inner.pending_auth = None;
            inner.auth_refused = false;
            inner.auth_challenge_at = None;
            inner.auth_note = None;
            inner.conn_gen += 1;
            // NOTE: subscriptions are preserved so they can be replayed on reconnect.
            inner.pending_publishes.clear();
            inner.pending_messages.clear();
            // Writes held for AUTH belong to the session being closed. Their
            // ack callbacks are gone with `pending_publishes`, and the next
            // session may be another account: they must not go out after its
            // AUTH is accepted.
            inner.deferred_writes.clear();
            // Stale queued frames must not double-send after a reconnect —
            // the on_open flush + replay rebuilds everything still relevant.
            inner.left_total += inner.send_queue.len() as u64;
            inner.send_queue.clear();
            inner.send_times.clear();
        });
    }

    /// Subscribe to events matching the given filters.
    /// Returns a subscription ID that can be used to unsubscribe.
    pub fn subscribe(
        &self,
        filters: Vec<Filter>,
        on_event: EventCallback,
        on_eose: Option<EoseCallback>,
    ) -> String {
        self.subscribe_inner(filters, on_event, on_eose, None, None)
    }

    /// Like [`subscribe`](Self::subscribe), but the EOSE callback is told
    /// whether the answer is authenticated — see [`ReceiptCallback`]. It may
    /// fire more than once (the post-AUTH replay re-answers the same id).
    pub fn subscribe_with_receipt(
        &self,
        filters: Vec<Filter>,
        on_event: EventCallback,
        on_receipt: ReceiptCallback,
    ) -> String {
        self.subscribe_inner(filters, on_event, None, Some(on_receipt), None)
    }

    /// [`Self::subscribe_with_receipt`], plus `on_closed` with the reason if
    /// the relay answers CLOSED instead (it refused the REQ, e.g. too many
    /// subscriptions on this connection, or ended it).
    pub fn subscribe_with_receipt_or_closed(
        &self,
        filters: Vec<Filter>,
        on_event: EventCallback,
        on_receipt: ReceiptCallback,
        on_closed: ClosedCallback,
    ) -> String {
        self.subscribe_inner(filters, on_event, None, Some(on_receipt), Some(on_closed))
    }

    fn subscribe_inner(
        &self,
        filters: Vec<Filter>,
        on_event: EventCallback,
        on_eose: Option<EoseCallback>,
        on_receipt: Option<ReceiptCallback>,
        on_closed: Option<ClosedCallback>,
    ) -> String {
        let (sub_id, watch) = self.with_inner(|rc| {
            let mut inner = rc.borrow_mut();
            inner.sub_counter += 1;
            let sub_id = format!("sub_{}", inner.sub_counter);
            // Mirrors `send_raw`: a REQ only reaches this socket when it is
            // open; otherwise it is dropped from the pending flush and the
            // on_open replay sends (and counts) it instead.
            let is_open = matches!(&inner.ws, Some(ws) if ws.ready_state() == WebSocket::OPEN);
            let mut ledger = ReqLedger::default();
            let watch = is_open.then(|| ledger.sent(inner.auth_accepted));
            inner.subscriptions.insert(
                sub_id.clone(),
                Subscription {
                    filters: filters.clone(),
                    on_event,
                    on_eose,
                    on_receipt,
                    on_closed,
                    ledger,
                    wire_id: wire_id(&sub_id, 0),
                    wire_gen: 0,
                },
            );
            (sub_id, watch)
        });
        if let Some(seq) = watch {
            self.with_inner(|rc| arm_req_watch(rc, sub_id.clone(), seq, 0));
        }

        // Build REQ message: ["REQ", sub_id, filter1, filter2, ...]
        let mut req = vec![Value::String("REQ".into()), Value::String(sub_id.clone())];
        for filter in &filters {
            if let Ok(v) = serde_json::to_value(filter) {
                req.push(v);
            }
        }

        let msg = serde_json::to_string(&req).unwrap_or_default();
        self.send_raw(&msg);

        sub_id
    }

    /// Unsubscribe from a subscription by ID.
    /// Ask the relay how many events match `filters` (NIP-45 COUNT) and hand
    /// the number to `on_count`. The count is made on the relay, so it is not
    /// bounded by the row cap a REQ without a `limit` is given (500). The
    /// callback may run more than once: the frame is replayed after NIP-42
    /// AUTH, and the authenticated answer is the complete one.
    pub fn count(&self, filters: Vec<Filter>, on_count: CountCallback) -> String {
        let id = self.with_inner(|rc| {
            let mut inner = rc.borrow_mut();
            inner.sub_counter += 1;
            let id = format!("count_{}", inner.sub_counter);
            inner.counts.insert(
                id.clone(),
                PendingCount {
                    filters: filters.clone(),
                    on_count,
                },
            );
            id
        });
        self.send_raw(&count_frame(&id, &filters));
        id
    }

    /// Ask for one section's topic stats (ADR-2038): `["SECTION-STATS", id,
    /// {"channel": channel}]`. `on_answer` runs once, with the payload or the
    /// refusal; the caller owns the timeout ([`Self::cancel_section_stats`]).
    /// Send only to a relay whose NIP-11 document advertises it
    /// ([`crate::topics::section_stats::advertised`]). Holds no subscription,
    /// so it does not count against the relay's subscription cap.
    pub fn section_stats(&self, channel: &str, on_answer: SectionStatsCallback) -> String {
        let id = self.with_inner(|rc| {
            let mut inner = rc.borrow_mut();
            inner.sub_counter += 1;
            let id = format!("stats_{}", inner.sub_counter);
            inner.section_stats.insert(id.clone(), on_answer);
            id
        });
        self.send_raw(&crate::topics::section_stats::section_stats_frame(
            &id, channel,
        ));
        id
    }

    /// Forget a `SECTION-STATS` request (timed out): a late answer is dropped.
    pub fn cancel_section_stats(&self, id: &str) {
        self.with_inner(|rc| {
            rc.borrow_mut().section_stats.remove(id);
        });
    }

    /// Forget every verified event id (see `relay/verified.rs`), so the next
    /// identity's deliveries are all verified afresh and the cache's hit
    /// pattern says nothing about what the previous identity fetched.
    /// Called on every identity switch (`ZoneKeyStore::switch_owner`).
    pub fn clear_verified(&self) {
        // `switch_owner` runs from an Effect, never inside the socket
        // handler, so the borrow is free; if it ever is not, say so rather
        // than panic in the middle of a sign-out.
        match self.inner.try_borrow_mut() {
            Ok(mut inner) => inner.verified = verified::VerifiedIds::default(),
            Err(_) => web_sys::console::warn_1(
                &"[Relay] verified-id cache busy at identity switch; not cleared".into(),
            ),
        }
    }

    /// Sizes of the per-id collections (`alloc-stats` diagnostics).
    #[cfg(feature = "alloc-stats")]
    pub fn debug_sizes(&self) -> Vec<(&'static str, usize)> {
        let inner = self.inner.borrow();
        vec![
            ("relay.subscriptions", inner.subscriptions.len()),
            ("relay.seen_events", inner.seen_events.len()),
            ("relay.verified", inner.verified.len()),
            ("relay.verified_queue", inner.verified.queue_len()),
            ("relay.req_sent_at", inner.req_sent_at.len()),
            ("relay.counts", inner.counts.len()),
            ("relay.section_stats", inner.section_stats.len()),
            ("relay.pending_publishes", inner.pending_publishes.len()),
        ]
    }

    pub fn unsubscribe(&self, sub_id: &str) {
        // Close the id the subscription is using on the wire now, which
        // differs from the logical id after an unanswered-REQ re-send.
        let wire = self.with_inner(|rc| {
            let mut inner = rc.borrow_mut();
            let wire = inner
                .subscriptions
                .remove(sub_id)
                .map(|s| s.wire_id)
                .unwrap_or_else(|| sub_id.to_string());
            // Its send time is no longer needed (the map would otherwise
            // grow by one entry per REQ until the next socket).
            inner.req_sent_at.remove(&wire);
            wire
        });

        let close_msg = close_frame(&wire);
        self.send_raw(&close_msg);
    }

    /// Publish a signed event to the relay.
    pub fn publish(&self, event: &NostrEvent) {
        let msg = serde_json::json!(["EVENT", event]);
        let serialized = serde_json::to_string(&msg).unwrap_or_default();
        self.send_or_defer_write(&serialized);
    }

    /// Send an EVENT (write) frame, or DEFER it until NIP-42 AUTH completes.
    ///
    /// PRD-010 G4: while the socket is OPEN but not yet authenticated the relay
    /// rejects writes `auth-required`, so rather than fire-and-lose them we
    /// buffer the frame and flush it the instant AUTH completes (the AUTH
    /// `replay_after_auth`). When already authenticated it goes out
    /// immediately; when disconnected `send_raw` buffers it in
    /// `pending_messages` and flushes on (re)connect. READ subscriptions never
    /// route through here, so public reads stay non-blocking.
    fn send_or_defer_write(&self, msg: &str) {
        let deferred = self.with_inner(|rc| {
            let mut inner = rc.borrow_mut();
            let is_open = matches!(&inner.ws, Some(ws) if ws.ready_state() == WebSocket::OPEN);
            let is_authed = inner.immediate_writes
                || inner.auth_refused
                || inner
                    .authed_sink
                    .map(|s| s.get_untracked())
                    .unwrap_or(false);
            if is_open && !is_authed {
                inner.deferred_writes.push(msg.to_string());
                true
            } else {
                false
            }
        });
        if !deferred {
            self.send_raw(msg);
        }
    }

    /// Publish a signed event and invoke `on_ok` when the relay responds with OK.
    ///
    /// The callback receives `(accepted: bool, message: String)` matching the
    /// NIP-01 `["OK", event_id, accepted, message]` response.
    pub fn publish_with_ack(
        &self,
        event: &NostrEvent,
        on_ok: Option<PublishCallback>,
    ) -> Result<(), String> {
        let event_id = event.id.clone();
        self.with_inner(|rc| {
            rc.borrow_mut()
                .pending_publishes
                .insert(event_id, PendingPublish { on_ok });
        });
        let msg = serde_json::json!(["EVENT", event]);
        let serialized =
            serde_json::to_string(&msg).map_err(|e| format!("serialize error: {}", e))?;
        self.send_or_defer_write(&serialized);
        Ok(())
    }

    /// Frames this connection has accepted but not yet put on the wire: the
    /// paced send queue, writes held until NIP-42 AUTH completes, and frames
    /// waiting for a (re)connect.
    pub fn queued_frames(&self) -> usize {
        self.with_inner(|rc| {
            let inner = rc.borrow();
            inner.send_queue.len() + inner.deferred_writes.len() + inner.pending_messages.len()
        })
    }

    /// Wait until every frame queued before this call has left this client,
    /// or `cap_ms` passes. Returns whether they all left. A caller about to
    /// start a timed request waits here first, so its timer measures the
    /// relay's answer and not the frames ahead of it. Frames queued after the
    /// call are not waited for, so a busy page cannot starve the wait.
    pub async fn wait_until_sent(&self, cap_ms: u32) -> bool {
        let start = js_sys::Date::now();
        let mark = self.with_inner(|rc| {
            let inner = rc.borrow();
            send_mark(
                inner.queued_total,
                inner.deferred_writes.len() + inner.pending_messages.len(),
            )
        });
        loop {
            if self.with_inner(|rc| rc.borrow().left_total) >= mark {
                return true;
            }
            if js_sys::Date::now() - start >= f64::from(cap_ms) {
                return false;
            }
            let promise = js_sys::Promise::new(&mut |resolve, _| {
                if let Some(win) = web_sys::window() {
                    let _ = win.set_timeout_with_callback_and_timeout_and_arguments_0(
                        &resolve,
                        QUEUE_POLL_MS,
                    );
                }
            });
            let _ = wasm_bindgen_futures::JsFuture::from(promise).await;
        }
    }

    /// Send a raw string message to the WebSocket, paced under the relay's
    /// per-IP rate limit. Queued in `pending_messages` while disconnected.
    fn send_raw(&self, msg: &str) {
        self.with_inner(|rc| {
            let is_open = {
                let inner = rc.borrow();
                matches!(&inner.ws, Some(ws) if ws.ready_state() == WebSocket::OPEN)
            };
            if is_open {
                queue_paced(rc, msg.to_string());
            } else {
                rc.borrow_mut().pending_messages.push(msg.to_string());
            }
        });
    }

    /// Schedule a reconnect with exponential backoff.
    ///
    /// Uses `set_timeout_once` which properly drops the closure after execution,
    /// preventing memory leaks on repeated reconnect cycles (e.g. spotty mobile).
    fn schedule_reconnect(&self) {
        let attempts = self.with_inner(|rc| rc.borrow().reconnect_attempts);

        let delay = std::cmp::min(
            BASE_RECONNECT_DELAY_MS * 2u32.saturating_pow(attempts),
            MAX_RECONNECT_DELAY_MS,
        );

        self.with_inner(|rc| {
            rc.borrow_mut().reconnect_attempts = attempts + 1;
        });

        web_sys::console::log_1(
            &format!(
                "[Relay] Reconnecting in {}ms (attempt {})",
                delay,
                attempts + 1
            )
            .into(),
        );

        let self_clone = self.clone();
        crate::utils::set_timeout_once(
            move || {
                let current = self_clone.state.get_untracked();
                if current != ConnectionState::Disconnected && current != ConnectionState::Connected
                {
                    self_clone.connect();
                }
            },
            delay as i32,
        );
    }
}

/// A value that one callback supplies and one task awaits. First writer wins.
///
/// The relay API is callback-shaped (`subscribe`, `publish_with_ack`); the DM
/// send path is a task that wants to `await` an answer. Single-threaded, so
/// `Rc`/`RefCell` rather than a channel.
pub struct OneShot<T> {
    value: RefCell<Option<T>>,
    waker: RefCell<Option<std::task::Waker>>,
}

impl<T> OneShot<T> {
    /// An empty slot.
    pub fn new() -> Rc<Self> {
        Rc::new(Self {
            value: RefCell::new(None),
            waker: RefCell::new(None),
        })
    }

    /// Store `v` unless the slot is already full, and wake the waiter.
    pub fn fill(&self, v: T) {
        if self.value.borrow().is_none() {
            *self.value.borrow_mut() = Some(v);
            if let Some(w) = self.waker.borrow_mut().take() {
                w.wake();
            }
        }
    }

    /// Resolve once [`fill`](Self::fill) has run.
    pub async fn wait(self: &Rc<Self>) -> T {
        std::future::poll_fn(|cx| {
            if let Some(v) = self.value.borrow_mut().take() {
                return std::task::Poll::Ready(v);
            }
            *self.waker.borrow_mut() = Some(cx.waker().clone());
            std::task::Poll::Pending
        })
        .await
    }
}

/// Publish one event to a relay that is not ours and report what it said.
///
/// Opens a short-lived [`RelayConnection::to_url`] socket, sends the event,
/// waits up to `timeout_ms` for the relay's `OK`, then closes the socket (which
/// also stops its reconnect loop). `Ok(())` means the relay accepted the event;
/// `Err(reason)` carries the relay's refusal text, `"timeout"` when it never
/// answered, or the local failure. Silence is a failure, never a success.
pub async fn publish_to(url: &str, event: &NostrEvent, timeout_ms: i32) -> Result<(), String> {
    let conn = RelayConnection::to_url(url);
    let slot: Rc<OneShot<Result<(), String>>> = OneShot::new();
    let on_ok_slot = slot.clone();
    let on_ok: PublishCallback = Rc::new(move |accepted, message| {
        on_ok_slot.fill(if accepted { Ok(()) } else { Err(message) });
    });
    conn.connect();
    if let Err(e) = conn.publish_with_ack(event, Some(on_ok)) {
        conn.disconnect();
        return Err(e);
    }
    let timeout_slot = slot.clone();
    crate::utils::set_timeout_once(
        move || timeout_slot.fill(Err("timeout".to_string())),
        timeout_ms,
    );
    let outcome = slot.wait().await;
    conn.disconnect();
    outcome
}

/// Parse and route incoming relay messages to the appropriate subscription callbacks.
/// The wire frame of a NIP-45 COUNT request.
fn count_frame(id: &str, filters: &[Filter]) -> String {
    let mut req = vec![Value::String("COUNT".into()), Value::String(id.into())];
    for filter in filters {
        if let Ok(v) = serde_json::to_value(filter) {
            req.push(v);
        }
    }
    serde_json::to_string(&req).unwrap_or_default()
}

/// The relay answered our AUTH event. On acceptance, replay every
/// subscription (each REQ now counts as authenticated in its ledger), flush
/// writes held back for AUTH, and only then flip the public `authenticated`
/// signal. A rate-limited refusal re-sends the same frame a bounded number of
/// times; any other refusal leaves the socket anonymous.
fn on_auth_ok(inner_rc: &Rc<RefCell<RelayInner>>, accepted: bool, message: &str) {
    let (attempts, gen) = {
        let inner = inner_rc.borrow();
        let attempts = inner.pending_auth.as_ref().map(|p| p.attempts).unwrap_or(0);
        (attempts, inner.conn_gen)
    };
    match classify_auth_ok(accepted, message, attempts) {
        AuthReply::Accepted => {
            {
                let mut inner = inner_rc.borrow_mut();
                inner.pending_auth = None;
                inner.auth_challenge_at = None;
                // A late acceptance after a stall un-refuses the socket.
                inner.auth_refused = false;
                inner.auth_note = None;
            }
            replay_after_auth(inner_rc);
        }
        AuthReply::Retry => {
            let rc = inner_rc.clone();
            crate::utils::set_timeout_once(
                move || {
                    let frame = {
                        let mut inner = rc.borrow_mut();
                        // Tied to the socket that was refused: after a
                        // reconnect `pending_auth` belongs to a new challenge.
                        let ws_open =
                            matches!(&inner.ws, Some(ws) if ws.ready_state() == WebSocket::OPEN);
                        let same_socket = inner.conn_gen == gen;
                        match inner.pending_auth.as_mut() {
                            Some(p) if ws_open && same_socket => {
                                p.attempts += 1;
                                p.sent_at = js_sys::Date::now();
                                Some(p.frame.clone())
                            }
                            _ => None,
                        }
                    };
                    if let Some(frame) = frame {
                        queue_paced(&rc, frame);
                        arm_auth_stall_check(&rc, AUTH_ANSWER_TIMEOUT_MS);
                    }
                },
                1_000 * attempts as i32,
            );
        }
        AuthReply::Rejected => {
            refuse_auth(inner_rc, &format!("the relay rejected it: {message}"));
        }
    }
}

/// Give up on NIP-42 for this socket: the relay rejected AUTH, the signer
/// failed or is missing, or the handshake stalled. Writes held back for AUTH
/// are released and no longer deferred, so the relay's own
/// `OK false "auth-required…"` reaches each publish callback and the user sees
/// an error instead of a post that waits forever. Subscriptions are not
/// replayed and `authenticated` stays false. A late `OK true` still wins.
fn refuse_auth(inner_rc: &Rc<RefCell<RelayInner>>, reason: &str) {
    let deferred = {
        let mut inner = inner_rc.borrow_mut();
        // Only on a live socket. Released writes go to the send queue, and a
        // closed socket's queue is flushed on reconnect BEFORE the next AUTH,
        // where the relay refuses them; held, they go out once that AUTH is
        // accepted instead.
        let open = matches!(&inner.ws, Some(ws) if ws.ready_state() == WebSocket::OPEN);
        if !open {
            return;
        }
        inner.auth_note = Some(reason.to_string());
        // `pending_auth` is deliberately kept: if this was a stall and the
        // relay's `OK true` arrives late, it must still match our AUTH event
        // and take the Accepted path. A new socket resets it.
        inner.auth_challenge_at = None;
        inner.auth_refused = true;
        std::mem::take(&mut inner.deferred_writes)
    };
    for msg in deferred {
        queue_paced(inner_rc, msg);
    }
    web_sys::console::warn_1(&format!("[Relay] NIP-42 AUTH not completed: {reason}").into());
}

/// Check, `delay_ms` from now, whether this socket's handshake has stalled
/// (see [`receipt::auth_stalled`]). Stale checks are harmless: the verdict is
/// computed from the current timestamps, and a different socket is ignored.
fn arm_auth_stall_check(inner_rc: &Rc<RefCell<RelayInner>>, delay_ms: i32) {
    let gen = inner_rc.borrow().conn_gen;
    let rc = inner_rc.clone();
    crate::utils::set_timeout_once(
        move || {
            let stalled = {
                let inner = rc.borrow();
                release_held_writes(
                    HandshakeView {
                        same_socket: inner.conn_gen == gen,
                        socket_open: matches!(
                            &inner.ws,
                            Some(ws) if ws.ready_state() == WebSocket::OPEN
                        ),
                        immediate_writes: inner.immediate_writes,
                        accepted: inner.auth_accepted,
                        refused: inner.auth_refused,
                        challenge_at: inner.auth_challenge_at,
                        sent_at: inner.pending_auth.as_ref().map(|p| p.sent_at),
                    },
                    js_sys::Date::now(),
                )
            };
            if stalled {
                refuse_auth(&rc, "the relay did not answer in time");
            }
        },
        delay_ms,
    );
}

/// The `["CLOSE", wire_id]` frame.
fn close_frame(wire: &str) -> String {
    serde_json::to_string(&[Value::String("CLOSE".into()), Value::String(wire.into())])
        .unwrap_or_default()
}

/// The `["REQ", wire_id, filter…]` frame for a subscription.
fn req_frame(sub_id: &str, filters: &[Filter]) -> Option<String> {
    let mut req = vec![
        serde_json::Value::String("REQ".into()),
        serde_json::Value::String(sub_id.to_string()),
    ];
    for filter in filters {
        if let Ok(v) = serde_json::to_value(filter) {
            req.push(v);
        }
    }
    serde_json::to_string(&req).ok()
}

/// Arm the answer timeout for REQ `seq` of `sub_id` (see
/// [`receipt::ReqLedger::on_watch`]). The relay drops some REQs with only a
/// NOTICE, which names no subscription; without this the ledger would wait
/// for that answer until the next reconnect.
fn arm_req_watch(inner_rc: &Rc<RefCell<RelayInner>>, sub_id: String, seq: u64, resends: u32) {
    arm_req_watch_in(inner_rc, sub_id, seq, resends, req_watch_delay(resends));
}

/// [`arm_req_watch`] with an explicit first delay. When it fires before the
/// REQ has been on the wire for the whole timeout (it may still be in the
/// paced queue), it re-arms for the remainder instead of judging it
/// (see [`receipt::watch_due`]).
fn arm_req_watch_in(
    inner_rc: &Rc<RefCell<RelayInner>>,
    sub_id: String,
    seq: u64,
    resends: u32,
    delay_ms: i32,
) {
    enum Next {
        Nothing,
        Recheck(i32),
        Resend(String, String, u64, u32),
    }
    let gen = inner_rc.borrow().conn_gen;
    let rc = inner_rc.clone();
    crate::utils::set_timeout_once(
        move || {
            let next = {
                let mut inner = rc.borrow_mut();
                if inner.conn_gen != gen {
                    return; // the new socket re-sent and re-armed everything
                }
                let ws_open = matches!(&inner.ws, Some(ws) if ws.ready_state() == WebSocket::OPEN);
                let accepted = inner.auth_accepted;
                let now = js_sys::Date::now();
                let RelayInner {
                    subscriptions,
                    req_sent_at,
                    ..
                } = &mut *inner;
                let Some(sub) = subscriptions.get_mut(&sub_id) else {
                    return; // unsubscribed meanwhile
                };
                if !sub.ledger.is_waiting_on(seq) {
                    Next::Nothing
                } else if let WatchDue::RecheckIn(ms) = watch_due(
                    req_sent_at.get(&sub.wire_id).copied(),
                    now,
                    req_watch_delay(resends),
                ) {
                    Next::Recheck(ms)
                } else {
                    match sub.ledger.on_watch(seq) {
                        Watch::Settled => Next::Nothing,
                        Watch::GiveUp => {
                            web_sys::console::warn_1(
                                &format!("[Relay] {sub_id} unanswered after re-sends; not waiting")
                                    .into(),
                            );
                            Next::Nothing
                        }
                        // A closed socket's on_open replays (and re-arms) it.
                        Watch::Resend if !ws_open => Next::Nothing,
                        // Retire the old wire id (CLOSE it) and re-send under a
                        // fresh one, so a late answer to the abandoned REQ is
                        // recognisably not this one's.
                        Watch::Resend => {
                            let old = sub.wire_id.clone();
                            // The retired id's send time is dead weight now.
                            req_sent_at.remove(&old);
                            sub.wire_gen += 1;
                            sub.wire_id = wire_id(&sub_id, sub.wire_gen);
                            let seq = sub.ledger.sent(accepted);
                            web_sys::console::log_1(
                                &format!("[Relay] {old} unanswered; re-sending as {}", sub.wire_id)
                                    .into(),
                            );
                            match req_frame(&sub.wire_id, &sub.filters) {
                                Some(frame) => Next::Resend(
                                    close_frame(&old),
                                    frame,
                                    seq,
                                    sub.ledger.resends(),
                                ),
                                None => Next::Nothing,
                            }
                        }
                    }
                }
            };
            match next {
                Next::Nothing => {}
                Next::Recheck(ms) => arm_req_watch_in(&rc, sub_id, seq, resends, ms),
                Next::Resend(close, frame, seq, resends) => {
                    // FIFO: the relay frees the old slot before the new REQ.
                    queue_paced(&rc, close);
                    queue_paced(&rc, frame);
                    arm_req_watch(&rc, sub_id, seq, resends);
                }
            }
        },
        delay_ms,
    );
}

/// Re-send every subscription (and pending COUNT) now that the relay has
/// accepted AUTH, so it re-evaluates them for the authenticated session.
fn replay_after_auth(inner_rc: &Rc<RefCell<RelayInner>>) {
    // Extract the authed signal, then drop the borrow BEFORE flipping it:
    // `sig.set(true)` synchronously runs the DM Effect, which calls
    // `relay.subscribe()` -> `inner.borrow_mut()`. Holding this borrow across
    // the set would re-enter the same RefCell and panic ("already borrowed").
    let (frames, watches, deferred_writes, authed_sink) = {
        let mut inner = inner_rc.borrow_mut();
        let ws_live = inner.ws.is_some();
        inner.auth_accepted = true;
        let mut frames = Vec::new();
        let mut watches = Vec::new();
        if ws_live {
            for (sub_id, sub) in inner.subscriptions.iter_mut() {
                let seq = sub.ledger.sent(true);
                if let Some(msg) = req_frame(&sub.wire_id, &sub.filters) {
                    frames.push(msg);
                }
                watches.push((sub_id.clone(), seq, sub.ledger.resends()));
            }
            // The replay reuses each wire id, whose send time still belongs to
            // the pre-AUTH REQ. Forget it, so the replay's timeout waits until
            // the replay itself leaves the paced queue (it may sit behind the
            // whole burst) instead of judging it by the older send.
            let RelayInner {
                subscriptions,
                req_sent_at,
                ..
            } = &mut *inner;
            for sub in subscriptions.values() {
                req_sent_at.remove(&sub.wire_id);
            }
            // Pending COUNTs go again too: before AUTH the relay answered them
            // with 0 for protected kinds.
            for (id, pending) in inner.counts.iter() {
                frames.push(count_frame(id, &pending.filters));
            }
        }
        // PRD-010 G4: drain writes deferred while this socket was
        // unauthenticated. Only when the socket is live.
        let deferred_writes = if ws_live {
            std::mem::take(&mut inner.deferred_writes)
        } else {
            Vec::new()
        };
        (frames, watches, deferred_writes, inner.authed_sink)
    };
    // Paced: the boot replay is exactly the burst that tripped the relay's
    // per-IP limit and dropped the message REQs ("0 messages" symptom).
    if !frames.is_empty() {
        for msg in frames {
            queue_paced(inner_rc, msg);
        }
        web_sys::console::log_1(&"[Relay] replayed subscriptions post-AUTH (paced)".into());
    }
    for (sub_id, seq, resends) in watches {
        arm_req_watch(inner_rc, sub_id, seq, resends);
    }
    let deferred_count = deferred_writes.len();
    for msg in deferred_writes {
        queue_paced(inner_rc, msg);
    }
    if deferred_count > 0 {
        web_sys::console::log_1(
            &format!("[Relay] flushed {deferred_count} deferred write(s) post-AUTH").into(),
        );
    }
    // Mark the session authenticated so AUTH-gated consumers (DM store) can
    // now safely (re-)issue their kind-1059 REQs.
    if let Some(sig) = authed_sink {
        sig.set(true);
    }
}

fn handle_relay_message(inner_rc: &Rc<RefCell<RelayInner>>, text: &str) {
    let parsed: Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(e) => {
            web_sys::console::warn_1(&format!("[Relay] Failed to parse message: {}", e).into());
            return;
        }
    };

    let arr = match parsed.as_array() {
        Some(a) => a,
        None => return,
    };

    if arr.is_empty() {
        return;
    }

    let msg_type = match arr[0].as_str() {
        Some(s) => s,
        None => return,
    };

    match msg_type {
        "EVENT" => {
            if arr.len() < 3 {
                return;
            }
            // The frame carries the WIRE id; dispatch by the logical id it
            // encodes. Events under a retired id are still delivered: the
            // dedup below is keyed by the logical id, so the re-sent REQ
            // cannot deliver an event twice.
            let sub_id = match arr[1].as_str() {
                Some(s) => logical_id(s).to_string(),
                None => return,
            };
            let event: NostrEvent = match serde_json::from_value(arr[2].clone()) {
                Ok(e) => e,
                Err(e) => {
                    web_sys::console::warn_1(
                        &format!("[Relay] Failed to parse event: {}", e).into(),
                    );
                    return;
                }
            };

            // Verify event-id integrity and Schnorr signature before dedup or
            // dispatch. Never hand forged authorship to callbacks — drop it.
            // An event already verified this session (same id and signature,
            // id recomputed from its fields) skips only the Schnorr check: see
            // `relay/verified.rs` for why that is safe. Every new event, and
            // any re-delivery that differs in a single field, is verified in
            // full.
            let known = inner_rc.borrow_mut().verified.already_verified(&event);
            if !known {
                if let Err(e) = nostr_bbs_core::verify_event_strict(&event) {
                    web_sys::console::warn_1(
                        &format!("[Relay] Dropping event failing verification: {:?}", e).into(),
                    );
                    return;
                }
                inner_rc.borrow_mut().verified.insert(&event);
            }

            {
                let mut inner = inner_rc.borrow_mut();
                if !inner.seen_events.insert(format!("{sub_id}:{}", event.id)) {
                    return;
                }
                if inner.seen_events.len() > 10_000 {
                    inner.seen_events.clear();
                }
            }

            let callback = {
                let inner = inner_rc.borrow();
                inner
                    .subscriptions
                    .get(&sub_id)
                    .map(|s| Rc::clone(&s.on_event))
            };
            if let Some(cb) = callback {
                cb(event);
            }
        }
        "EOSE" => {
            if arr.len() < 2 {
                return;
            }
            let Some(wire) = arr[1].as_str() else { return };

            // An EOSE under a retired wire id answers an abandoned REQ: it is
            // never credited to the ledger and fires no callback.
            let callbacks = {
                let mut inner = inner_rc.borrow_mut();
                inner
                    .subscriptions
                    .get_mut(logical_id(wire))
                    .filter(|s| route(wire, &s.wire_id) == Route::Current)
                    .map(|s| {
                        let authed = s.ledger.answered();
                        (s.on_eose.clone(), s.on_receipt.clone(), authed)
                    })
            };
            // Borrow released: callbacks may subscribe re-entrantly.
            if let Some((on_eose, on_receipt, authed)) = callbacks {
                if let Some(cb) = on_eose {
                    cb();
                }
                if let Some(cb) = on_receipt {
                    cb(authed);
                }
            }
        }
        "CLOSED" => {
            // A refused SECTION-STATS request (ADR-2038) is answered by id.
            if let Some(id) = arr.get(1).and_then(Value::as_str) {
                let pending = inner_rc.borrow_mut().section_stats.remove(id);
                if let Some(cb) = pending {
                    let reason = arr.get(2).and_then(Value::as_str).unwrap_or("").to_string();
                    cb(Err(reason));
                    return;
                }
            }
            // A refused REQ is still an answer to one REQ: count it so the
            // ledger is not left waiting forever. It is not a completeness
            // receipt, so no callback fires.
            // Under a retired wire id it answers an abandoned REQ: ignored.
            if let Some(wire) = arr.get(1).and_then(Value::as_str) {
                let on_closed = inner_rc
                    .borrow_mut()
                    .subscriptions
                    .get_mut(logical_id(wire))
                    .filter(|s| route(wire, &s.wire_id) == Route::Current)
                    .and_then(|s| {
                        s.ledger.answered();
                        s.on_closed.clone()
                    });
                if let Some(cb) = on_closed {
                    let reason = arr.get(2).and_then(Value::as_str).unwrap_or("").to_string();
                    cb(reason);
                }
            }
        }
        "COUNT" => {
            // ["COUNT", <id>, {"count": n}]
            if arr.len() < 3 {
                return;
            }
            let Some(id) = arr[1].as_str() else { return };
            let Some(n) = arr[2].get("count").and_then(|c| c.as_u64()) else {
                return;
            };
            let callback = {
                let inner = inner_rc.borrow();
                inner.counts.get(id).map(|c| Rc::clone(&c.on_count))
            };
            if let Some(cb) = callback {
                cb(n);
            }
        }
        crate::topics::section_stats::SECTION_STATS_VERB => {
            // ["SECTION-STATS", <id>, {payload}] (ADR-2038).
            let Some(id) = arr.get(1).and_then(Value::as_str) else {
                return;
            };
            let pending = inner_rc.borrow_mut().section_stats.remove(id);
            if let (Some(cb), Some(payload)) = (pending, arr.get(2)) {
                cb(Ok(payload.clone()));
            }
        }
        "NOTICE" => {
            if arr.len() >= 2 {
                if let Some(notice) = arr[1].as_str() {
                    // An old relay sent the verb anyway (a stale NIP-11
                    // answer): fail every pending request, quietly.
                    if notice == crate::topics::section_stats::SECTION_STATS_UNKNOWN_NOTICE {
                        let pending: Vec<SectionStatsCallback> = inner_rc
                            .borrow_mut()
                            .section_stats
                            .drain()
                            .map(|(_, cb)| cb)
                            .collect();
                        for cb in pending {
                            cb(Err("unsupported: relay does not know SECTION-STATS".into()));
                        }
                        return;
                    }
                    web_sys::console::warn_1(&format!("[Relay] NOTICE: {}", notice).into());

                    // Surface to the UI as a warn toast, rate-limiting rapid
                    // duplicates: the same notice text within 5s is dropped so a
                    // chatty relay cannot spam the user.
                    const NOTICE_DEDUP_WINDOW_MS: f64 = 5_000.0;
                    let now = js_sys::Date::now();
                    let mut inner = inner_rc.borrow_mut();
                    let is_dup = inner
                        .last_notice
                        .as_ref()
                        .map(|(prev, ts)| prev == notice && (now - *ts) < NOTICE_DEDUP_WINDOW_MS)
                        .unwrap_or(false);
                    if !is_dup {
                        inner.last_notice = Some((notice.to_string(), now));
                        inner.notice_seq = inner.notice_seq.wrapping_add(1);
                        let seq = inner.notice_seq;
                        let sink = inner.notice_sink;
                        drop(inner);
                        if let Some(sink) = sink {
                            sink.set(Some(RelayNotice {
                                message: notice.to_string(),
                                seq,
                            }));
                        }
                    }
                }
            }
        }
        "OK" => {
            if arr.len() >= 4 {
                let event_id = arr[1].as_str().unwrap_or("unknown");
                let accepted = arr[2].as_bool().unwrap_or(false);
                let message = arr[3].as_str().unwrap_or("");
                let is_auth_reply = inner_rc
                    .borrow()
                    .pending_auth
                    .as_ref()
                    .is_some_and(|p| p.event_id == event_id);
                if is_auth_reply {
                    on_auth_ok(inner_rc, accepted, message);
                    return;
                }
                if !accepted {
                    web_sys::console::warn_1(
                        &format!("[Relay] Event {} rejected: {}", event_id, message).into(),
                    );
                }
                // Dispatch to pending publish callback if registered. A
                // refusal that follows a sign-in which did not complete on
                // this socket is explained rather than shown bare.
                let (callback, note) = {
                    let mut inner = inner_rc.borrow_mut();
                    let cb = inner
                        .pending_publishes
                        .remove(event_id)
                        .and_then(|p| p.on_ok);
                    (cb, inner.auth_note.clone())
                };
                if let Some(cb) = callback {
                    let shown = if accepted {
                        message.to_string()
                    } else {
                        explain_write_refusal(message, note.as_deref())
                    };
                    cb(accepted, shown);
                }
            }
        }
        "AUTH" => {
            if arr.len() >= 2 {
                if let Some(challenge) = arr[1].as_str() {
                    let inner = inner_rc.borrow();
                    let relay_url = inner.relay_url.clone();
                    let sync_signer = inner.auth_signer.clone();
                    let async_signer = inner.auth_signer_async.clone();
                    let ws = inner.ws.clone();
                    drop(inner);

                    let now = (js_sys::Date::now() / 1000.0) as u64;
                    let make_unsigned = |url: String, ch: &str| UnsignedEvent {
                        pubkey: String::new(),
                        created_at: now,
                        kind: 22242,
                        tags: vec![
                            vec!["relay".into(), url],
                            vec!["challenge".into(), ch.to_string()],
                        ],
                        content: String::new(),
                    };

                    // Send the AUTH response and remember it: subscriptions are
                    // replayed only when the relay ACCEPTS it (its `OK true`,
                    // see `on_auth_ok`). Replaying on send let the anonymous
                    // answer to a REQ the relay began before AUTH be taken for
                    // an authenticated one.
                    let send_auth =
                        |signed: &NostrEvent,
                         ws: &Option<WebSocket>,
                         rc: &Rc<RefCell<RelayInner>>| {
                            if let Ok(msg) =
                                serde_json::to_string(&serde_json::json!(["AUTH", signed]))
                            {
                                if let Some(ws) = ws {
                                    rc.borrow_mut().pending_auth = Some(PendingAuth {
                                        event_id: signed.id.clone(),
                                        frame: msg.clone(),
                                        attempts: 1,
                                        sent_at: js_sys::Date::now(),
                                    });
                                    let _ = ws.send_with_str(&msg);
                                    web_sys::console::log_1(
                                        &"[Relay] NIP-42 AUTH response sent".into(),
                                    );
                                    // An OK that is lost or never sent must
                                    // not hold writes forever.
                                    arm_auth_stall_check(rc, AUTH_ANSWER_TIMEOUT_MS);
                                }
                            }
                        };

                    // Start the handshake clock: a challenge left unsigned
                    // (e.g. a NIP-07 prompt never answered) releases held
                    // writes after AUTH_SIGN_TIMEOUT_MS.
                    {
                        let mut inner = inner_rc.borrow_mut();
                        inner.auth_challenge_at = Some(js_sys::Date::now());
                        // A new challenge supersedes any AUTH still pending:
                        // that one answered the old challenge, and its
                        // `sent_at` must not drive this handshake's clock.
                        inner.pending_auth = None;
                    }
                    arm_auth_stall_check(inner_rc, AUTH_SIGN_TIMEOUT_MS);

                    if let Some(sign_fn) = sync_signer {
                        let unsigned = make_unsigned(relay_url, challenge);
                        if let Some(signed) = sign_fn(unsigned) {
                            send_auth(&signed, &ws, inner_rc);
                        } else {
                            refuse_auth(inner_rc, "signing failed");
                        }
                    } else if let Some(async_sign) = async_signer {
                        let unsigned = make_unsigned(relay_url, challenge);
                        let rc = inner_rc.clone();
                        wasm_bindgen_futures::spawn_local(async move {
                            if let Some(signed) = async_sign(unsigned).await {
                                // The socket may have been replaced while the
                                // extension was signing; answer only the one
                                // that issued this challenge.
                                let current = rc.borrow().ws.clone();
                                let same = match (&ws, &current) {
                                    (Some(a), Some(b)) => a == b,
                                    _ => false,
                                };
                                if same {
                                    send_auth(&signed, &ws, &rc);
                                }
                            } else {
                                // A denied extension prompt lands here.
                                let current = rc.borrow().ws.clone();
                                if ws.is_some() && ws == current {
                                    refuse_auth(&rc, "signing was denied or failed");
                                }
                            }
                        });
                    } else {
                        refuse_auth(inner_rc, "no signing key was available");
                    }
                }
            }
        }
        _ => {
            web_sys::console::log_1(
                &format!("[Relay] Unhandled message type: {}", msg_type).into(),
            );
        }
    }
}

/// The relay URL connections use (see `get_relay_url`); browser data is
/// scoped to it (`stores::relay_scope`).
pub fn configured_relay_url() -> String {
    get_relay_url()
}

/// Read the relay URL from the environment or fall back to the default.
fn get_relay_url() -> String {
    if let Some(window) = web_sys::window() {
        if let Ok(val) = js_sys::Reflect::get(&window, &"__ENV__".into()) {
            if !val.is_undefined() && !val.is_null() {
                if let Ok(url) = js_sys::Reflect::get(&val, &"VITE_RELAY_URL".into()) {
                    if let Some(s) = url.as_string() {
                        if !s.is_empty() {
                            return s;
                        }
                    }
                }
            }
        }
    }

    option_env!("VITE_RELAY_URL")
        .unwrap_or(DEFAULT_RELAY_URL)
        .to_string()
}

#[cfg(test)]
mod pacing_tests {
    use super::{drain_time_ms, send_mark};

    #[test]
    fn the_send_mark_covers_held_frames_but_not_later_ones() {
        // 130 pushed, 3 held for AUTH: all 133 must leave first.
        assert_eq!(send_mark(130, 3), 133);
        assert_eq!(send_mark(0, 0), 0);
        assert_eq!(send_mark(u64::MAX, 5), u64::MAX);
    }

    #[test]
    fn drain_time_counts_whole_send_windows() {
        assert_eq!(drain_time_ms(0), 0);
        assert_eq!(drain_time_ms(1), 1_000);
        assert_eq!(drain_time_ms(8), 1_000);
        assert_eq!(drain_time_ms(9), 2_000);
        // The 2026-11-26 sweep: ~127 zone2 + ~25 zone4 wraps.
        assert_eq!(drain_time_ms(152), 19_000);
        assert_eq!(drain_time_ms(usize::MAX), u32::MAX);
    }
}

#[cfg(test)]
mod section_stats_tests {
    //! ADR-2038: the `SECTION-STATS` request on the client socket: its frame,
    //! its answer, a refusal, an old relay's NOTICE and a cancelled request.
    use super::*;
    use std::cell::RefCell;

    fn conn() -> RelayConnection {
        RelayConnection::build("ws://relay.test".into(), false)
    }

    type Seen = Rc<RefCell<Vec<Result<Value, String>>>>;

    fn ask(c: &RelayConnection, channel: &str) -> (String, Seen) {
        let seen: Seen = Rc::new(RefCell::new(Vec::new()));
        let sink = seen.clone();
        let id = c.section_stats(channel, Rc::new(move |r| sink.borrow_mut().push(r)));
        (id, seen)
    }

    fn feed(c: &RelayConnection, frame: Value) {
        handle_relay_message(&c.inner, &frame.to_string());
    }

    #[test]
    fn the_request_goes_out_as_one_frame_and_its_answer_comes_back_once() {
        let c = conn();
        let (id, seen) = ask(&c, "ab");
        let queued = c.inner.borrow().pending_messages.clone();
        assert_eq!(
            queued,
            vec![format!(r#"["SECTION-STATS","{id}",{{"channel":"ab"}}]"#)]
        );
        feed(&c, serde_json::json!(["SECTION-STATS", id, {"topics": []}]));
        feed(
            &c,
            serde_json::json!(["SECTION-STATS", id, {"topics": [1]}]),
        );
        assert_eq!(seen.borrow().len(), 1, "answered once");
        assert_eq!(seen.borrow()[0], Ok(serde_json::json!({"topics": []})));
        assert!(c.inner.borrow().section_stats.is_empty());
        assert!(
            c.inner.borrow().subscriptions.is_empty(),
            "no subscription held"
        );
    }

    #[test]
    fn a_closed_refusal_is_the_answer() {
        let c = conn();
        let (id, seen) = ask(&c, "ab");
        feed(
            &c,
            serde_json::json!(["CLOSED", id, "restricted: section not readable"]),
        );
        assert_eq!(
            seen.borrow().as_slice(),
            &[Err("restricted: section not readable".to_string())]
        );
    }

    #[test]
    fn an_old_relay_s_unknown_verb_notice_fails_quietly() {
        let c = conn();
        let (_, a) = ask(&c, "ab");
        let (_, b) = ask(&c, "cd");
        let notices = c.inner.borrow().notice_sink.unwrap();
        feed(
            &c,
            serde_json::json!(["NOTICE", "Unknown message type: SECTION-STATS"]),
        );
        assert!(a.borrow()[0].is_err() && b.borrow()[0].is_err());
        assert_eq!(notices.get_untracked(), None, "no toast for it");
    }

    #[test]
    fn a_cancelled_request_ignores_a_late_answer() {
        let c = conn();
        let (id, seen) = ask(&c, "ab");
        c.cancel_section_stats(&id);
        feed(&c, serde_json::json!(["SECTION-STATS", id, {"topics": []}]));
        feed(&c, serde_json::json!(["CLOSED", id, "error: late"]));
        assert!(seen.borrow().is_empty());
    }
}
