//! Direct Message state store with NIP-59 Gift Wrap + NIP-44 encryption.
//!
//! Manages DM conversations using NIP-59 (Gift Wrap) for outgoing messages and
//! backward-compatible NIP-44 kind-4 decryption for incoming events. Subscribes
//! to both kind 4 and kind 1059 events for real-time DM delivery via the relay.

pub mod encrypted_media;

use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use leptos::prelude::*;
use nostr_bbs_core::gift_wrap::{unwrap_gift_with_signer, KIND_ENCRYPTED_DM, KIND_GIFT_WRAP};
use nostr_bbs_core::signer::Signer;
use nostr_bbs_core::{gift_wrap_with_signer, NostrEvent};

use crate::components::user_display::use_display_name;
use crate::relay::{EoseCallback, EventCallback, Filter, RelayConnection};

/// A single decrypted direct message.
#[derive(Clone, Debug, PartialEq)]
pub struct DMMessage {
    pub id: String,
    pub sender_pubkey: String,
    pub recipient_pubkey: String,
    pub content: String,
    pub timestamp: u64,
    pub is_sent: bool,
    pub is_read: bool,
}

/// Summary of a DM conversation with a single counterparty.
#[derive(Clone, Debug, PartialEq)]
pub struct DMConversation {
    pub pubkey: String,
    pub name: String,
    pub last_message: String,
    pub last_timestamp: u64,
    pub unread_count: u32,
}

/// Internal reactive state for the DM system.
#[derive(Clone, Debug, Default)]
struct DMStateInner {
    conversations: HashMap<String, DMConversation>,
    current_conversation: Option<String>,
    messages: Vec<DMMessage>,
    /// O(1) dedup index for message IDs (avoids O(n) linear scan).
    seen_ids: HashSet<String>,
    is_loading: bool,
    error: Option<String>,
}

/// Reactive DM store provided as Leptos context.
#[derive(Clone, Copy)]
pub struct DMStore {
    state: RwSignal<DMStateInner>,
    sub_ids: RwSignal<Vec<String>>,
    /// Bumped by `cleanup()`; pending auth-retry timers from a previous
    /// page abort when the epoch they captured no longer matches.
    sub_epoch: RwSignal<u32>,
}

#[cfg(target_arch = "wasm32")]
unsafe impl Send for DMStore {}
#[cfg(target_arch = "wasm32")]
unsafe impl Sync for DMStore {}

impl DMStore {
    fn new() -> Self {
        Self {
            state: RwSignal::new(DMStateInner::default()),
            sub_ids: RwSignal::new(Vec::new()),
            sub_epoch: RwSignal::new(0),
        }
    }

    /// Sorted conversation list (most recent first).
    pub fn conversations(&self) -> Memo<Vec<DMConversation>> {
        let state = self.state;
        Memo::new(move |_| {
            let inner = state.get();
            let mut convos: Vec<DMConversation> = inner.conversations.values().cloned().collect();
            convos.sort_by_key(|x| std::cmp::Reverse(x.last_timestamp));
            convos
        })
    }

    /// Messages for the currently selected conversation (chronological).
    pub fn messages(&self) -> Memo<Vec<DMMessage>> {
        let state = self.state;
        Memo::new(move |_| {
            let mut msgs = state.get().messages.clone();
            msgs.sort_by_key(|m| m.timestamp);
            msgs
        })
    }

    #[allow(dead_code)]
    pub fn current_conversation(&self) -> Memo<Option<String>> {
        let state = self.state;
        Memo::new(move |_| state.get().current_conversation)
    }

    pub fn is_loading(&self) -> Memo<bool> {
        let state = self.state;
        Memo::new(move |_| state.get().is_loading)
    }

    pub fn error(&self) -> Memo<Option<String>> {
        let state = self.state;
        Memo::new(move |_| state.get().error.clone())
    }

    #[allow(dead_code)]
    pub fn total_unread(&self) -> Memo<u32> {
        let state = self.state;
        Memo::new(move |_| {
            state
                .get()
                .conversations
                .values()
                .map(|c| c.unread_count)
                .sum()
        })
    }

    pub fn clear_error(&self) {
        self.state.update(|s| s.error = None);
    }

    /// Fetch existing DM conversations by subscribing to kind 4 (legacy) and
    /// kind 1059 (NIP-59 Gift Wrap) events where the user is either sender
    /// (author) or recipient (#p tag).
    ///
    /// Accepts a [`Signer`]. Decryption runs through the async `Signer` trait
    /// methods (`nip44_decrypt`), so it works for both an in-memory local key
    /// (`PrfSigner`) and a NIP-07 extension (`Nip07Signer`) — the signing key
    /// has full authority to decrypt and no raw secret-key bytes are required.
    pub fn fetch_conversations(
        &self,
        relay: &RelayConnection,
        signer: Rc<dyn Signer>,
        my_pubkey: &str,
    ) {
        self.state.update(|s| {
            s.is_loading = true;
            s.error = None;
        });

        let my_pk = my_pubkey.to_string();
        let state = self.state;

        let sent_filter = Filter {
            kinds: Some(vec![4, 1059]),
            authors: Some(vec![my_pk.clone()]),
            ..Default::default()
        };
        let recv_filter = Filter {
            kinds: Some(vec![4, 1059]),
            p_tags: Some(vec![my_pk.clone()]),
            ..Default::default()
        };

        let my_pk_cb = my_pk.clone();
        let on_event: EventCallback = Rc::new(move |event: NostrEvent| {
            spawn_process_dm_event(event, signer.clone(), my_pk_cb.clone(), state);
        });
        let on_eose: EoseCallback = Rc::new(move || {
            state.update(|s| s.is_loading = false);
        });

        subscribe_dm_with_auth_retry(
            *self,
            relay.clone(),
            vec![sent_filter, recv_filter],
            on_event,
            Some(on_eose),
            "fetch_conversations",
            0,
        );

        // Timeout guard so the UI never gets stuck (auto-drops closure)
        crate::utils::set_timeout_once(
            move || {
                if state.get_untracked().is_loading {
                    state.update(|s| s.is_loading = false);
                }
            },
            8000,
        );
    }

    /// Subscribe to incoming DMs in real-time.
    /// Listens for both kind 4 (legacy) and kind 1059 (NIP-59 Gift Wrap).
    ///
    /// Decryption is performed via the async [`Signer`] trait, so both local-key
    /// and NIP-07 sessions receive and decrypt live DMs.
    ///
    /// Root cause (DM-not-received bug): NIP-59 gift-wraps (kind-1059)
    /// deliberately RANDOMISE their outer `created_at` into the PAST (up to ~2
    /// days per the spec, to obscure timing metadata). A DM sent *right now* is
    /// therefore stamped earlier than `now`, so a realtime subscription with
    /// `since = now` SKIPS it and the recipient never sees the message without a
    /// full reload. The fix widens the `since` window for the gift-wrap (and
    /// kind-14) subscription to cover the randomisation window, and relies on
    /// the existing event-id dedup (`seen_ids`) so re-streamed history is not
    /// re-rendered. The legacy kind-4 path keeps a real `created_at`, but is
    /// folded into the same widened filter for simplicity — dedup makes the
    /// wider window harmless.
    pub fn subscribe_incoming(
        &self,
        relay: &RelayConnection,
        signer: Rc<dyn Signer>,
        my_pubkey: &str,
    ) {
        let my_pk = my_pubkey.to_string();
        let state = self.state;
        let now = (js_sys::Date::now() / 1000.0) as u64;
        // Cover the NIP-59 gift-wrap timestamp-randomisation window (~2 days).
        // A live gift-wrap addressed to us can be stamped up to this far in the
        // past, so anchoring `since` here is what makes realtime delivery work.
        // De-duplication by event id (`seen_ids`) prevents re-processing of any
        // history this widened window also re-streams.
        let since = now.saturating_sub(GIFT_WRAP_LOOKBACK_SECS);

        let filter = Filter {
            kinds: Some(vec![4, 1059]),
            p_tags: Some(vec![my_pk.clone()]),
            since: Some(since),
            ..Default::default()
        };
        let on_event: EventCallback = Rc::new(move |event: NostrEvent| {
            spawn_process_dm_event(event, signer.clone(), my_pk.clone(), state);
        });

        subscribe_dm_with_auth_retry(
            *self,
            relay.clone(),
            vec![filter],
            on_event,
            None,
            "subscribe_incoming",
            0,
        );
    }

    /// Select a conversation and mark it as read.
    pub fn select_conversation(&self, pubkey: &str) {
        let pk = pubkey.to_string();
        self.state.update(|s| {
            s.current_conversation = Some(pk.clone());
            if let Some(convo) = s.conversations.get_mut(&pk) {
                convo.unread_count = 0;
            }
            for msg in &mut s.messages {
                let cp = if msg.is_sent {
                    &msg.recipient_pubkey
                } else {
                    &msg.sender_pubkey
                };
                if cp == &pk {
                    msg.is_read = true;
                }
            }
        });
    }

    /// Subscribe to historical + live messages for a specific conversation partner.
    /// Subscribes to both kind 4 (legacy) and kind 1059 (NIP-59 Gift Wrap).
    ///
    /// Decryption is performed via the async [`Signer`] trait, so both local-key
    /// and NIP-07 sessions can read the conversation.
    pub fn load_conversation_messages(
        &self,
        relay: &RelayConnection,
        signer: Rc<dyn Signer>,
        my_pubkey: &str,
        partner_pubkey: &str,
    ) {
        let my_pk = my_pubkey.to_string();
        let partner_pk = partner_pubkey.to_string();
        let state = self.state;

        state.update(|s| {
            s.messages.retain(|m| {
                let cp = if m.is_sent {
                    &m.recipient_pubkey
                } else {
                    &m.sender_pubkey
                };
                if cp == &partner_pk {
                    s.seen_ids.remove(&m.id);
                    false
                } else {
                    true
                }
            });
            s.is_loading = true;
        });

        let sent_filter = Filter {
            kinds: Some(vec![4, 1059]),
            authors: Some(vec![my_pk.clone()]),
            p_tags: Some(vec![partner_pk.clone()]),
            ..Default::default()
        };
        let recv_filter = Filter {
            kinds: Some(vec![4, 1059]),
            authors: Some(vec![partner_pk]),
            p_tags: Some(vec![my_pk.clone()]),
            ..Default::default()
        };

        let my_pk_cb = my_pk.clone();
        let on_event: EventCallback = Rc::new(move |event: NostrEvent| {
            spawn_process_dm_event(event, signer.clone(), my_pk_cb.clone(), state);
        });
        let on_eose: EoseCallback = Rc::new(move || {
            state.update(|s| s.is_loading = false);
        });

        subscribe_dm_with_auth_retry(
            *self,
            relay.clone(),
            vec![sent_filter, recv_filter],
            on_event,
            Some(on_eose),
            "load_conversation_messages",
            0,
        );
    }

    /// Encrypt and send a DM using NIP-59 Gift Wrap (kind 1059).
    ///
    /// The gift-wrap pipeline produces all three layers:
    ///   1. Rumor (unsigned kind 14 with plaintext)
    ///   2. Seal (kind 13, sender signs + NIP-44 encrypts the rumor)
    ///   3. Wrap (kind 1059, throwaway key signs + NIP-44 encrypts the seal)
    ///
    /// Encryption and the sender's seal signature go through the async [`Signer`]
    /// trait (`gift_wrap_with_signer`), so this works for both a local key
    /// (`PrfSigner`) and a NIP-07 extension (`Nip07Signer`). The signing key has
    /// full authority — no raw secret-key bytes are required.
    ///
    /// The optimistic UI update is applied synchronously; the encrypted publish
    /// happens on a spawned task because the signer is async.
    ///
    /// Also publishes kind-10050 (preferred DM relay) on first send if not already done.
    pub fn send_message(
        &self,
        relay: &RelayConnection,
        recipient_pk_hex: &str,
        content: &str,
        signer: Rc<dyn Signer>,
        my_pubkey: &str,
    ) -> Result<(), String> {
        if content.trim().is_empty() {
            return Err("Message cannot be empty".into());
        }

        // Validate recipient pubkey before doing any crypto.
        if hex::decode(recipient_pk_hex)
            .ok()
            .filter(|b| b.len() == 32)
            .is_none()
        {
            return Err("Invalid recipient pubkey hex".into());
        }

        let now = (js_sys::Date::now() / 1000.0) as u64;

        // Optimistic local update — keyed by a temporary local ID. When the real
        // gift-wrap event ID is known we re-key the dedup entry so the inbound
        // echo (if any) does not duplicate the bubble.
        let local_id = format!("local-{}-{}", now, content.len());
        let msg = DMMessage {
            id: local_id.clone(),
            sender_pubkey: my_pubkey.to_string(),
            recipient_pubkey: recipient_pk_hex.to_string(),
            content: content.to_string(),
            timestamp: now,
            is_sent: true,
            is_read: true,
        };

        self.state.update(|s| {
            if s.current_conversation.as_deref() == Some(recipient_pk_hex)
                && s.seen_ids.insert(msg.id.clone())
            {
                s.messages.push(msg.clone());
            }
            let convo = s
                .conversations
                .entry(recipient_pk_hex.to_string())
                .or_insert_with(|| DMConversation {
                    pubkey: recipient_pk_hex.to_string(),
                    name: use_display_name(recipient_pk_hex),
                    last_message: String::new(),
                    last_timestamp: 0,
                    unread_count: 0,
                });
            convo.last_message = truncate_message(content, 80);
            convo.last_timestamp = now;
        });

        // Encrypt + sign + publish on a spawned task (the signer is async, and a
        // NIP-07 extension performs the seal signature off the main flow).
        let relay = relay.clone();
        let recipient = recipient_pk_hex.to_string();
        let content_owned = content.to_string();
        let my_pk = my_pubkey.to_string();
        let state = self.state;
        wasm_bindgen_futures::spawn_local(async move {
            // Publish kind-10050 (preferred DM relay) once per pubkey per session.
            ensure_dm_relay_published(&relay, signer.as_ref(), &my_pk).await;

            match gift_wrap_with_signer(signer.as_ref(), &recipient, &content_owned).await {
                Ok(wrapped) => {
                    // Re-key the optimistic message to the real wrap event ID so
                    // the relay echo dedups against it instead of duplicating.
                    state.update(|s| {
                        if s.seen_ids.remove(&local_id) {
                            s.seen_ids.insert(wrapped.id.clone());
                        }
                        if let Some(m) = s.messages.iter_mut().find(|m| m.id == local_id) {
                            m.id = wrapped.id.clone();
                        }
                    });
                    relay.publish(&wrapped);
                }
                Err(e) => {
                    web_sys::console::error_1(&format!("[DM] Gift wrap failed: {e}").into());
                    // Roll the optimistic bubble back and surface the error.
                    state.update(|s| {
                        s.seen_ids.remove(&local_id);
                        s.messages.retain(|m| m.id != local_id);
                        s.error = Some(format!("Could not send message: {e}"));
                    });
                }
            }
        });

        Ok(())
    }

    /// Unsubscribe from all active DM subscriptions.
    pub fn cleanup(&self, relay: &RelayConnection) {
        // Invalidate any pending auth-retry timers from this page.
        self.sub_epoch.update(|e| *e = e.wrapping_add(1));
        for id in &self.sub_ids.get_untracked() {
            relay.unsubscribe(id);
        }
        self.sub_ids.set(Vec::new());
    }
}

// -- Authenticated subscription with retry -------------------------------------

/// How long to wait for the relay's EOSE before treating the REQ as dropped.
const DM_SUB_CONFIRM_MS: i32 = 3_000;
/// Maximum REQ attempts before surfacing an error.
const DM_SUB_MAX_ATTEMPTS: u32 = 4;

/// How far back to anchor the realtime incoming-DM subscription's `since`
/// filter. NIP-59 gift-wraps randomise their outer `created_at` up to ~2 days
/// into the past, so the live subscription must look back at least that far or
/// it silently drops freshly-sent DMs. Two days plus a small margin.
const GIFT_WRAP_LOOKBACK_SECS: u64 = 2 * 24 * 60 * 60 + 3600;

/// Subscribe to DM filters, re-issuing the REQ if the relay never confirms it.
///
/// Root cause (QA HIGH bug #3): kind-1059 REQs are AUTH-gated server-side.
/// The DM pages subscribe as soon as the WebSocket reports `Connected`, which
/// races the NIP-42 AUTH handshake — the relay answers a pre-AUTH REQ with
/// `NOTICE auth-required: must authenticate to receive kind-1059 DMs` and
/// drops it *without* an EOSE, so the subscription is never established on
/// the authenticated session (live kind-1059 broadcast also requires
/// `authed_pubkey == recipient`). The relay sends EOSE on every accepted REQ,
/// so a missing EOSE within `DM_SUB_CONFIRM_MS` reliably identifies a dropped
/// subscription: close it and re-REQ on the (by now) authenticated session.
/// This also self-heals reconnect/replay races where the post-AUTH replay in
/// the relay client did not take effect.
#[allow(clippy::too_many_arguments)]
fn subscribe_dm_with_auth_retry(
    store: DMStore,
    relay: RelayConnection,
    filters: Vec<Filter>,
    on_event: EventCallback,
    on_eose: Option<EoseCallback>,
    label: &'static str,
    attempt: u32,
) {
    let epoch = store.sub_epoch.get_untracked();
    let confirmed = Rc::new(std::cell::Cell::new(false));

    let confirmed_for_eose = confirmed.clone();
    let caller_eose = on_eose.clone();
    let eose_wrapper: EoseCallback = Rc::new(move || {
        confirmed_for_eose.set(true);
        if let Some(cb) = &caller_eose {
            cb();
        }
    });

    let sub_id = relay.subscribe(filters.clone(), on_event.clone(), Some(eose_wrapper));
    store.sub_ids.update(|ids| ids.push(sub_id.clone()));

    crate::utils::set_timeout_once(
        move || {
            if confirmed.get() {
                return;
            }
            // The page that owned this subscription was cleaned up.
            if store.sub_epoch.get_untracked() != epoch {
                return;
            }
            store.sub_ids.update(|ids| ids.retain(|id| id != &sub_id));
            relay.unsubscribe(&sub_id);

            if attempt + 1 >= DM_SUB_MAX_ATTEMPTS {
                web_sys::console::error_1(
                    &format!(
                        "[DM] {label}: subscription never confirmed after {DM_SUB_MAX_ATTEMPTS} \
                         attempts — relay session is not authenticated"
                    )
                    .into(),
                );
                store.state.update(|s| {
                    s.is_loading = false;
                    s.error = Some(
                        "Could not establish an authenticated connection for DMs. \
                         Please reload the page to retry."
                            .into(),
                    );
                });
                return;
            }

            web_sys::console::warn_1(
                &format!(
                    "[DM] {label}: no EOSE within {DM_SUB_CONFIRM_MS}ms (likely raced NIP-42 \
                     AUTH) — re-subscribing (attempt {})",
                    attempt + 2
                )
                .into(),
            );
            subscribe_dm_with_auth_retry(
                store,
                relay,
                filters,
                on_event,
                on_eose,
                label,
                attempt + 1,
            );
        },
        DM_SUB_CONFIRM_MS,
    );
}

// -- Event processing ---------------------------------------------------------

/// Spawn an async decrypt of a single inbound DM event.
///
/// The relay event callback is synchronous, but [`Signer`] decryption is async
/// (a NIP-07 extension bridges through `window.nostr`). Each event is processed
/// on its own spawned task so callbacks never block and both signer backends
/// work uniformly.
fn spawn_process_dm_event(
    event: NostrEvent,
    signer: Rc<dyn Signer>,
    my_pubkey: String,
    state: RwSignal<DMStateInner>,
) {
    wasm_bindgen_futures::spawn_local(async move {
        process_dm_event(&event, signer.as_ref(), &my_pubkey, state).await;
    });
}

/// Process an incoming DM event — either kind 1059 (NIP-59 Gift Wrap) or
/// kind 4 (legacy). Deduplicates and updates reactive state. Decryption runs
/// through the async [`Signer`] trait, so the in-memory (or extension-held)
/// signing key has authority for both backends.
async fn process_dm_event(
    event: &NostrEvent,
    signer: &dyn Signer,
    my_pubkey: &str,
    state: RwSignal<DMStateInner>,
) {
    if event.kind == KIND_GIFT_WRAP {
        process_gift_wrap_event(event, signer, my_pubkey, state).await;
    } else if event.kind == KIND_ENCRYPTED_DM {
        process_kind4_event(event, signer, my_pubkey, state).await;
    }
    // Ignore other kinds silently
}

/// Unwrap a NIP-59 Gift Wrap (kind 1059) event and insert into state.
///
/// `unwrap_gift_with_signer` peels the three layers through the signer:
///   Wrap (kind 1059) -> Seal (kind 13) -> Rumor (kind 14)
/// returning the sender's real pubkey, the plaintext rumor, and the seal.
async fn process_gift_wrap_event(
    event: &NostrEvent,
    signer: &dyn Signer,
    my_pubkey: &str,
    state: RwSignal<DMStateInner>,
) {
    let unwrapped = match unwrap_gift_with_signer(event, signer).await {
        Ok(u) => u,
        Err(e) => {
            web_sys::console::warn_1(
                &format!("[DM] Gift unwrap failed for {}: {}", &event.id, e).into(),
            );
            return;
        }
    };

    let sender_pubkey = unwrapped.sender_pubkey.clone();
    let is_sent = sender_pubkey == my_pubkey;

    // The rumor's "p" tag identifies the recipient
    let recipient_pubkey = unwrapped
        .rumor
        .tags
        .iter()
        .find(|t| t.len() >= 2 && t[0] == "p")
        .map(|t| t[1].clone())
        .unwrap_or_else(|| {
            if is_sent {
                String::new()
            } else {
                my_pubkey.to_string()
            }
        });

    let counterparty_pk = if is_sent {
        recipient_pubkey.clone()
    } else {
        sender_pubkey.clone()
    };

    if counterparty_pk.len() != 64 {
        return;
    }

    let plaintext = unwrapped.rumor.content.clone();
    // Use the rumor's created_at as the real timestamp (wrap timestamp is randomized)
    let timestamp = unwrapped.rumor.created_at;

    // Use the outer wrap event ID for deduplication
    let msg = DMMessage {
        id: event.id.clone(),
        sender_pubkey,
        recipient_pubkey,
        content: plaintext.clone(),
        timestamp,
        is_sent,
        is_read: is_sent,
    };

    insert_dm_message(msg, &counterparty_pk, &plaintext, timestamp, is_sent, state);
}

/// Decrypt a legacy kind 4 DM event and insert into state.
///
/// Decryption goes through the signer's `nip44_decrypt`, preserving the existing
/// kind-4 decryption semantics while working for local-key and NIP-07 sessions.
async fn process_kind4_event(
    event: &NostrEvent,
    signer: &dyn Signer,
    my_pubkey: &str,
    state: RwSignal<DMStateInner>,
) {
    let is_sent = event.pubkey == my_pubkey;
    let counterparty_pk = if is_sent {
        event
            .tags
            .iter()
            .find(|t| t.len() >= 2 && t[0] == "p")
            .map(|t| t[1].clone())
    } else {
        Some(event.pubkey.clone())
    };

    let counterparty_pk = match counterparty_pk {
        Some(pk) if pk.len() == 64 => pk,
        _ => return,
    };

    // NIP-44 conversation key is symmetric: decrypt with our key against the
    // counterparty pubkey, via the signer.
    let plaintext = match signer.nip44_decrypt(&counterparty_pk, &event.content).await {
        Ok(pt) => pt,
        Err(e) => {
            web_sys::console::warn_1(
                &format!("[DM] Decrypt failed for {}: {}", &event.id, e).into(),
            );
            return;
        }
    };

    let msg = DMMessage {
        id: event.id.clone(),
        sender_pubkey: event.pubkey.clone(),
        recipient_pubkey: if is_sent {
            counterparty_pk.clone()
        } else {
            my_pubkey.to_string()
        },
        content: plaintext.clone(),
        timestamp: event.created_at,
        is_sent,
        is_read: is_sent,
    };

    insert_dm_message(
        msg,
        &counterparty_pk,
        &plaintext,
        event.created_at,
        is_sent,
        state,
    );
}

/// Shared helper: deduplicate and insert a DM message into the reactive state,
/// updating the conversation summary.
fn insert_dm_message(
    msg: DMMessage,
    counterparty_pk: &str,
    plaintext: &str,
    timestamp: u64,
    is_sent: bool,
    state: RwSignal<DMStateInner>,
) {
    state.update(|s| {
        if s.seen_ids.insert(msg.id.clone()) {
            s.messages.push(msg.clone());
        }

        let convo = s
            .conversations
            .entry(counterparty_pk.to_string())
            .or_insert_with(|| DMConversation {
                pubkey: counterparty_pk.to_string(),
                name: use_display_name(counterparty_pk),
                last_message: String::new(),
                last_timestamp: 0,
                unread_count: 0,
            });
        if timestamp >= convo.last_timestamp {
            convo.last_message = truncate_message(plaintext, 80);
            convo.last_timestamp = timestamp;
        }
        if !is_sent && s.current_conversation.as_deref() != Some(counterparty_pk) {
            convo.unread_count += 1;
        }
    });
}

// -- Helpers ------------------------------------------------------------------

fn truncate_message(content: &str, max_chars: usize) -> String {
    let t = content.trim();
    if t.chars().count() <= max_chars {
        t.to_string()
    } else {
        let truncated: String = t.chars().take(max_chars).collect();
        format!("{truncated}...")
    }
}

// -- kind-10050 auto-publish --------------------------------------------------

/// localStorage key tracking whether kind-10050 has been published for a pubkey.
const KIND_10050_KEY_PREFIX: &str = "nostr_bbs_dm_relay_published_";

/// Publish kind-10050 (preferred DM relay) once per pubkey.
///
/// Uses localStorage to avoid publishing on every DM send. The event is signed
/// through the [`Signer`] (so local-key and NIP-07 sessions both work) and
/// published fire-and-forget — failures are logged but don't block the DM send.
async fn ensure_dm_relay_published(relay: &RelayConnection, signer: &dyn Signer, my_pubkey: &str) {
    let storage_key = format!(
        "{}{}",
        KIND_10050_KEY_PREFIX,
        &my_pubkey[..8.min(my_pubkey.len())]
    );

    // Check localStorage flag first to avoid re-publishing
    let already_published = web_sys::window()
        .and_then(|w| w.local_storage().ok())
        .flatten()
        .and_then(|s| s.get_item(&storage_key).ok())
        .flatten()
        .map(|v| v == "1")
        .unwrap_or(false);

    if already_published {
        return;
    }

    let relay_url = crate::utils::relay_url::relay_url();
    let now = (js_sys::Date::now() / 1000.0) as u64;

    let unsigned = nostr_bbs_core::UnsignedEvent {
        pubkey: my_pubkey.to_string(),
        created_at: now,
        kind: 10050,
        tags: vec![vec!["r".to_string(), relay_url]],
        content: String::new(),
    };

    match signer.sign_event(unsigned).await {
        Ok(signed) => {
            relay.publish(&signed);
            // Mark as published in localStorage
            if let Some(storage) = web_sys::window()
                .and_then(|w| w.local_storage().ok())
                .flatten()
            {
                let _ = storage.set_item(&storage_key, "1");
            }
            web_sys::console::log_1(
                &format!(
                    "[DM] Published kind-10050 DM relay for: {}",
                    &my_pubkey[..8.min(my_pubkey.len())]
                )
                .into(),
            );
        }
        Err(e) => {
            web_sys::console::warn_1(&format!("[DM] Failed to publish kind-10050: {e}").into());
        }
    }
}

// -- Context providers --------------------------------------------------------

/// Create and provide the DM store context.
pub fn provide_dm_store() {
    provide_context(DMStore::new());
}

/// Get the DM store from context. Panics if `provide_dm_store()` was not called.
pub fn use_dm_store() -> DMStore {
    expect_context::<DMStore>()
}
