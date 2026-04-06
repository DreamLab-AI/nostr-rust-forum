//! Direct Message state store with NIP-59 Gift Wrap + NIP-44 encryption.
//!
//! Manages DM conversations using NIP-59 (Gift Wrap) for outgoing messages and
//! backward-compatible NIP-44 kind-4 decryption for incoming events. Subscribes
//! to both kind 4 and kind 1059 events for real-time DM delivery via the relay.

pub mod encrypted_media;

use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use leptos::prelude::*;
use nostr_core::gift_wrap::{gift_wrap, unwrap_gift};
use nostr_core::{nip44_decrypt, NostrEvent};

use crate::components::user_display::use_display_name;
use crate::relay::{Filter, RelayConnection};

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
        }
    }

    /// Sorted conversation list (most recent first).
    pub fn conversations(&self) -> Memo<Vec<DMConversation>> {
        let state = self.state;
        Memo::new(move |_| {
            let inner = state.get();
            let mut convos: Vec<DMConversation> = inner.conversations.values().cloned().collect();
            convos.sort_by(|a, b| b.last_timestamp.cmp(&a.last_timestamp));
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
    pub fn fetch_conversations(
        &self,
        relay: &RelayConnection,
        privkey_bytes: &[u8; 32],
        my_pubkey: &str,
    ) {
        self.state.update(|s| {
            s.is_loading = true;
            s.error = None;
        });

        let sk = *privkey_bytes;
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
        let on_event = Rc::new(move |event: NostrEvent| {
            process_dm_event(&event, &sk, &my_pk_cb, state);
        });
        let on_eose = Rc::new(move || {
            state.update(|s| s.is_loading = false);
        });

        let id = relay.subscribe(vec![sent_filter, recv_filter], on_event, Some(on_eose));
        self.sub_ids.update(|ids| ids.push(id));

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

    /// Subscribe to incoming DMs in real-time (new events only, since=now).
    /// Listens for both kind 4 (legacy) and kind 1059 (NIP-59 Gift Wrap).
    pub fn subscribe_incoming(
        &self,
        relay: &RelayConnection,
        privkey_bytes: &[u8; 32],
        my_pubkey: &str,
    ) {
        let sk = *privkey_bytes;
        let my_pk = my_pubkey.to_string();
        let state = self.state;
        let now = (js_sys::Date::now() / 1000.0) as u64;

        let filter = Filter {
            kinds: Some(vec![4, 1059]),
            p_tags: Some(vec![my_pk.clone()]),
            since: Some(now),
            ..Default::default()
        };
        let on_event = Rc::new(move |event: NostrEvent| {
            process_dm_event(&event, &sk, &my_pk, state);
        });

        let id = relay.subscribe(vec![filter], on_event, None);
        self.sub_ids.update(|ids| ids.push(id));
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
    pub fn load_conversation_messages(
        &self,
        relay: &RelayConnection,
        privkey_bytes: &[u8; 32],
        my_pubkey: &str,
        partner_pubkey: &str,
    ) {
        let sk = *privkey_bytes;
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
        let on_event = Rc::new(move |event: NostrEvent| {
            process_dm_event(&event, &sk, &my_pk_cb, state);
        });
        let on_eose = Rc::new(move || {
            state.update(|s| s.is_loading = false);
        });

        let id = relay.subscribe(vec![sent_filter, recv_filter], on_event, Some(on_eose));
        self.sub_ids.update(|ids| ids.push(id));
    }

    /// Encrypt and send a DM using NIP-59 Gift Wrap (kind 1059).
    ///
    /// The gift_wrap function handles all three layers internally:
    ///   1. Rumor (unsigned kind 14 with plaintext)
    ///   2. Seal (kind 13, sender signs + NIP-44 encrypts the rumor)
    ///   3. Wrap (kind 1059, throwaway key signs + NIP-44 encrypts the seal)
    ///
    /// The privkey bytes are passed directly to `gift_wrap()` which creates the
    /// Seal signature internally. No separate `auth.sign_event()` call is needed.
    pub fn send_message(
        &self,
        relay: &RelayConnection,
        recipient_pk_hex: &str,
        content: &str,
        privkey_bytes: &[u8; 32],
        my_pubkey: &str,
    ) -> Result<(), String> {
        if content.trim().is_empty() {
            return Err("Message cannot be empty".into());
        }

        // Validate recipient pubkey before calling gift_wrap
        if hex::decode(recipient_pk_hex)
            .ok()
            .filter(|b| b.len() == 32)
            .is_none()
        {
            return Err("Invalid recipient pubkey hex".into());
        }

        let wrapped = gift_wrap(privkey_bytes, my_pubkey, recipient_pk_hex, content)
            .map_err(|e| format!("Gift wrap failed: {e}"))?;

        let now = (js_sys::Date::now() / 1000.0) as u64;

        // Optimistic local update — use the outer wrap event ID for dedup.
        // The UI does not need to know about the wire format.
        let msg = DMMessage {
            id: wrapped.id.clone(),
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

        // gift_wrap returns a fully signed kind 1059 event — publish directly
        relay.publish(&wrapped);
        Ok(())
    }

    /// Unsubscribe from all active DM subscriptions.
    pub fn cleanup(&self, relay: &RelayConnection) {
        for id in &self.sub_ids.get_untracked() {
            relay.unsubscribe(id);
        }
        self.sub_ids.set(Vec::new());
    }
}

// -- Event processing ---------------------------------------------------------

/// Process an incoming DM event — either kind 1059 (NIP-59 Gift Wrap) or
/// kind 4 (legacy NIP-44). Deduplicates and updates reactive state.
fn process_dm_event(
    event: &NostrEvent,
    my_sk: &[u8; 32],
    my_pubkey: &str,
    state: RwSignal<DMStateInner>,
) {
    if event.kind == 1059 {
        process_gift_wrap_event(event, my_sk, my_pubkey, state);
    } else if event.kind == 4 {
        process_kind4_event(event, my_sk, my_pubkey, state);
    }
    // Ignore other kinds silently
}

/// Unwrap a NIP-59 Gift Wrap (kind 1059) event and insert into state.
///
/// The unwrap_gift function peels the three layers:
///   Wrap (kind 1059) -> Seal (kind 13) -> Rumor (kind 14)
/// and returns the sender's real pubkey, the plaintext rumor, and the seal.
fn process_gift_wrap_event(
    event: &NostrEvent,
    my_sk: &[u8; 32],
    my_pubkey: &str,
    state: RwSignal<DMStateInner>,
) {
    let unwrapped = match unwrap_gift(event, my_sk) {
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

/// Decrypt a legacy kind 4 DM event (NIP-44) and insert into state.
fn process_kind4_event(
    event: &NostrEvent,
    my_sk: &[u8; 32],
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
    let cp_bytes: [u8; 32] = match hex::decode(&counterparty_pk) {
        Ok(b) if b.len() == 32 => b.try_into().unwrap(),
        _ => return,
    };

    // NIP-44 conversation key is symmetric: decrypt with my SK + counterparty PK
    let plaintext = match nip44_decrypt(my_sk, &cp_bytes, &event.content) {
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

// -- Context providers --------------------------------------------------------

/// Create and provide the DM store context.
pub fn provide_dm_store() {
    provide_context(DMStore::new());
}

/// Get the DM store from context. Panics if `provide_dm_store()` was not called.
pub fn use_dm_store() -> DMStore {
    expect_context::<DMStore>()
}
