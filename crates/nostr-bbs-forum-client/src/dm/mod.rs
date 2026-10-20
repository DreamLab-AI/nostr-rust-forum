//! Direct Message state store with NIP-59 Gift Wrap + NIP-44 encryption.
//!
//! Manages DM conversations using NIP-59 (Gift Wrap) for outgoing messages and
//! backward-compatible NIP-44 kind-4 decryption for incoming events. Subscribes
//! to both kind 4 and kind 1059 events for real-time DM delivery via the relay.

use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use leptos::prelude::*;
use nostr_bbs_core::gift_wrap::{unwrap_gift_with_signer, KIND_ENCRYPTED_DM, KIND_GIFT_WRAP};
use nostr_bbs_core::signer::Signer;
use nostr_bbs_core::{
    gift_wrap_pair_with_signer, gift_wrap_rumor_pair_with_signer, gift_wrap_with_signer, NostrEvent,
};

use crate::components::user_display::try_display_name;
use crate::poker::coach::is_coach_content;
use crate::relay::{
    EoseCallback, EventCallback, Filter, OneShot, PublishCallback, RelayConnection,
};

pub mod consent;
pub mod delivery;
pub mod requests;
pub mod routing;
pub mod rumors;

pub use delivery::{Attempt, Delivery};
pub use rumors::Attachment;

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
    /// The counterparty's profile name when one was known as the conversation
    /// opened; empty otherwise (the list then shows the live name or the
    /// copyable abridged key).
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
    /// Rumor id -> message id. A reaction or deletion names the RUMOR (both wraps
    /// of a message share it); `DMMessage.id` is the outer wrap's.
    rumor_index: HashMap<String, String>,
    /// Message id -> rumor id, the inverse, for the UI to address a message.
    msg_rumor: HashMap<String, String>,
    /// Reactions by target rumor id. Kept even when the target has not arrived
    /// yet (relays do not order a reaction after its message).
    reactions: HashMap<String, Vec<Reaction>>,
    /// `(target rumor id, deleter)` pairs. A deletion that arrives before its
    /// target still applies; keyed by deleter so a stranger cannot cancel or
    /// forge someone else's.
    tombstones: HashSet<(String, String)>,
    /// File-message attachments by message id.
    attachments: HashMap<String, Attachment>,
    /// Outcome of each message we sent, by message id (extended path only).
    deliveries: HashMap<String, DeliveryReport>,
    /// A question waiting for the member: may we connect to a stranger's relays?
    consent: Option<consent::ConsentRequest>,
}

/// A reaction to a message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reaction {
    /// Lowercase hex of whoever reacted.
    pub sender: String,
    /// `+`, `-` or an emoji.
    pub emoji: String,
    /// The reaction's own rumor id (so it can itself be deleted).
    pub rumor_id: String,
}

/// What happened to a message we sent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeliveryReport {
    /// The single outcome to show: sent, partial or failed.
    pub outcome: Delivery,
    /// One entry per relay the recipient's copy was addressed to.
    pub to_recipient: Vec<Attempt>,
    /// Our own copy's attempt.
    pub own_copy: Vec<Attempt>,
}

/// Per-message extras for the DM screen, keyed by `DMMessage.id`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct DMExtras {
    /// Reactions on each message.
    pub reactions: HashMap<String, Vec<Reaction>>,
    /// File-message attachments (render as a link; nothing is fetched).
    pub attachments: HashMap<String, Attachment>,
    /// Delivery outcome of messages we sent.
    pub deliveries: HashMap<String, DeliveryReport>,
    /// Rumor id of each message, for reacting to or deleting it.
    pub rumor_ids: HashMap<String, String>,
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
        Memo::new(move |_| state.with(visible_conversations))
    }

    /// Messages for the currently selected conversation (chronological).
    ///
    /// The conversation filter is applied HERE rather than in the relay query,
    /// and that is forced by NIP-59, not laziness: a gift wrap reveals nothing
    /// about which conversation it belongs to until it has been unwrapped
    /// locally, so the subscription necessarily pulls the whole wrap inbox
    /// (see `gift_wrap_filters`).
    ///
    /// It previously returned `state.messages` wholesale. Because the realtime
    /// subscription is inbox-wide, a DM arriving from a THIRD party while you
    /// were reading a conversation was appended straight into it — someone
    /// else's message rendered inside an unrelated thread. Scoping the memo to
    /// `current_conversation` is what keeps the two concerns separate.
    pub fn messages(&self) -> Memo<Vec<DMMessage>> {
        let state = self.state;
        Memo::new(move |_| {
            let inner = state.get();
            let Some(current) = inner.current_conversation.as_deref() else {
                // No conversation open: render nothing rather than the whole
                // inbox flattened into one stream.
                return Vec::new();
            };
            thread_of(
                &inner.messages,
                current,
                crate::poker::PokerConfig::load().coach().as_deref(),
            )
        })
    }

    /// Every message received from `pubkey`, coach exchanges included, in
    /// arrival order. The practice table's coach reads its replies here; the
    /// DM pages use [`messages`](Self::messages), which leaves them out.
    pub fn received_from(&self, pubkey: String) -> Memo<Vec<DMMessage>> {
        let state = self.state;
        let pubkey = pubkey.to_ascii_lowercase();
        Memo::new(move |_| {
            state.with(|inner| {
                inner
                    .messages
                    .iter()
                    .filter(|m| !m.is_sent && m.sender_pubkey == pubkey)
                    .cloned()
                    .collect()
            })
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
        // Requests and blocked conversations stay out of the badge.
        let requests = use_context::<requests::RequestsStore>();
        let mutes = use_context::<crate::stores::mute::MuteStore>();
        Memo::new(move |_| {
            state.with(|s| {
                requests::unread_total(s.conversations.values().map(|c| {
                    let lane = requests.map_or(requests::Lane::Main, |r| {
                        r.lane_of(&c.pubkey, mutes.is_some_and(|m| m.is_user_muted(&c.pubkey)))
                    });
                    (c.unread_count, lane)
                }))
            })
        })
    }

    /// Reactions, attachments, delivery outcomes and rumor ids for the DM
    /// screen, keyed by `DMMessage.id`. Empty with `RECIPIENT_KEYS_ENABLED` off.
    // Consumed by the DM page; no page renders these yet.
    #[allow(dead_code)]
    pub fn extras(&self) -> Memo<DMExtras> {
        let state = self.state;
        Memo::new(move |_| state.with(extras_of))
    }

    /// The confirmation waiting for the member, if any (see [`consent`]).
    pub fn pending_consent(&self) -> Memo<Option<consent::ConsentRequest>> {
        let state = self.state;
        Memo::new(move |_| state.with(|s| s.consent.clone()))
    }

    /// Answer the pending confirmation: `true` is "Send anyway".
    pub fn answer_consent(&self, accept: bool) {
        self.state.update(|s| s.consent = None);
        consent::answer(accept);
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

        let filters = inbox_filters(&my_pk);

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
            filters,
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

        let filters = incoming_filters(&my_pk, since);
        let on_event: EventCallback = Rc::new(move |event: NostrEvent| {
            spawn_process_dm_event(event, signer.clone(), my_pk.clone(), state);
        });

        subscribe_dm_with_auth_retry(
            *self,
            relay.clone(),
            filters,
            on_event,
            None,
            "subscribe_incoming",
            0,
        );
    }

    /// Select a conversation and mark it as read.
    pub fn select_conversation(&self, pubkey: &str) {
        let pk = canonical_or_lower(pubkey);
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
        let partner_pk = canonical_or_lower(partner_pubkey);
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

        let filters = conversation_filters(&my_pk, &partner_pk);

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
            filters,
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
    /// The recipient may be given as hex (any case) or `npub`; it is normalised
    /// to lowercase hex before anything is keyed, tagged or wrapped.
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
        self.send_message_to(relay, recipient_pk_hex, content, None, signer, my_pubkey)
    }

    /// [`send_message`](Self::send_message), optionally as a reply to the
    /// message whose rumor id is `reply_to` (see [`DMExtras::rumor_ids`]).
    ///
    /// With `RECIPIENT_KEYS_ENABLED` on, the rumor also carries the
    /// `["e", id, "", "reply"]` tag and `imeta` for media URLs, and the
    /// recipient's copy goes to the relays they named. With it off this is
    /// today's single-relay send and `reply_to` is ignored.
    pub fn send_message_to(
        &self,
        relay: &RelayConnection,
        recipient_pk_hex: &str,
        content: &str,
        reply_to: Option<&str>,
        signer: Rc<dyn Signer>,
        my_pubkey: &str,
    ) -> Result<(), String> {
        if content.trim().is_empty() {
            return Err("Message cannot be empty".into());
        }

        // Validate and normalise the recipient before doing any crypto: hex in
        // any case or an npub all become the same lowercase hex, which is what
        // the `p` tag, the conversation key and the ledger then use.
        let recipient = canonical_pubkey(recipient_pk_hex)?;
        let recipient = recipient.as_str();
        let my_pubkey = my_pubkey.to_ascii_lowercase();
        let my_pubkey = my_pubkey.as_str();

        let now = (js_sys::Date::now() / 1000.0) as u64;

        // Optimistic local update — keyed by a temporary local ID. When the real
        // gift-wrap event ID is known we re-key the dedup entry so the inbound
        // echo (if any) does not duplicate the bubble.
        // Collision-resistant optimistic key.
        //
        // This was `format!("local-{}-{}", now, content.len())`, with `now` in
        // whole seconds — so two messages of equal byte length sent in the same
        // second ("hey" and "yo!") produced the SAME key. The second one's
        // `seen_ids.insert` then returned false, its bubble was never pushed,
        // and the later re-key step operated on a shared key, corrupting the
        // dedup index for both. Both messages still reached the relay; the
        // sender just could not see one of them, which reads as a lost message.
        let local_id = format!(
            "local-{}-{}-{:08x}",
            now,
            content.len(),
            (js_sys::Math::random() * (u32::MAX as f64)) as u32
        );
        let msg = DMMessage {
            id: local_id.clone(),
            sender_pubkey: my_pubkey.to_string(),
            recipient_pubkey: recipient.to_string(),
            content: content.to_string(),
            timestamp: now,
            is_sent: true,
            is_read: true,
        };

        let coach = is_coach_exchange(content, recipient);

        // The rumor, with the optional reply and imeta tags, only on the
        // extended path; the plain path keeps core's own DM rumor. Checked
        // BEFORE the bubble appears, so a refused send leaves no trace.
        let extended = extras_enabled() && !coach;
        let rumor = if extended {
            let rumor = rumors::chat_rumor(signer.public_key(), recipient, content, reply_to);
            self.state.with_untracked(|s| {
                rumors::validate_outgoing(&rumor, recipient, signer.public_key(), &|id| {
                    known_in_conversation(s, id, signer.public_key(), recipient)
                })
            })?;
            Some(rumor)
        } else {
            None
        };

        self.state.update(|s| {
            if s.current_conversation.as_deref() == Some(recipient)
                && s.seen_ids.insert(msg.id.clone())
            {
                s.messages.push(msg.clone());
            }
            if coach {
                return;
            }
            let convo = s
                .conversations
                .entry(recipient.to_string())
                .or_insert_with(|| DMConversation {
                    pubkey: recipient.to_string(),
                    name: try_display_name(recipient).unwrap_or_default(),
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
        let recipient = recipient.to_string();
        let content_owned = content.to_string();
        let my_pk = my_pubkey.to_string();
        let state = self.state;
        wasm_bindgen_futures::spawn_local(async move {
            // Publish kind-10050 (preferred DM relay) once per pubkey per session.
            ensure_dm_relay_published(&relay, signer.as_ref(), &my_pk).await;

            // The public-inbox top-up (indexer sockets, up to 8 s each) runs as
            // its own task: a send never waits on it. A no-op with the flag or
            // the opt-in off.
            {
                let topup_signer = signer.clone();
                wasm_bindgen_futures::spawn_local(async move {
                    crate::zone_crypto::public_inbox::top_up_if_opted_in(topup_signer.as_ref())
                        .await;
                });
            }

            // NIP-17 requires TWO wraps: one encrypted to the recipient, one
            // encrypted back to us. Without the self-copy a sent message is
            // write-only for its author — the wrap is encrypted to the
            // recipient's key and authored by a throwaway key, so we can
            // neither decrypt nor even *find* it afterwards. The optimistic
            // bubble below would then be the only copy in existence and would
            // die with the page, which is why sent history kept vanishing.
            // A coach request is table traffic, not mail: the table keeps its
            // own ledger of what it asked, so no self-copy is made. One matters
            // beyond tidiness: every wrap to our own key is read by whatever
            // else holds it (a phone client, an operator's control gateway),
            // which would otherwise see each request as a message we typed.
            if coach {
                match gift_wrap_with_signer(signer.as_ref(), &recipient, &content_owned).await {
                    Ok(to_recipient) => relay.publish(&to_recipient),
                    Err(e) => {
                        web_sys::console::error_1(
                            &format!("[DM] Coach wrap failed: {}", send_failure_text(&e)).into(),
                        );
                        state.update(|s| {
                            s.seen_ids.remove(&local_id);
                            s.messages.retain(|m| m.id != local_id);
                        });
                    }
                }
                return;
            }

            let wrapped = match &rumor {
                Some(r) => gift_wrap_rumor_pair_with_signer(signer.as_ref(), &recipient, r).await,
                None => {
                    gift_wrap_pair_with_signer(signer.as_ref(), &recipient, &content_owned).await
                }
            };
            match wrapped {
                Ok((to_recipient, to_self)) => {
                    // Re-key the optimistic message to the real wrap event ID so
                    // the relay echo dedups against it instead of duplicating.
                    //
                    // We key on the SELF copy: that is the one that comes back
                    // to us through our own `#p` subscription, so it is the one
                    // that would otherwise render a second bubble. The
                    // recipient copy is never delivered to us at all.
                    let rumor_id = rumor.as_ref().map(rumor_id_of);
                    state.update(|s| {
                        if s.seen_ids.remove(&local_id) {
                            s.seen_ids.insert(to_self.id.clone());
                        }
                        if let Some(m) = s.messages.iter_mut().find(|m| m.id == local_id) {
                            m.id = to_self.id.clone();
                        }
                        if let Some(rid) = &rumor_id {
                            index_rumor(s, rid, &to_self.id);
                        }
                    });
                    if extended {
                        let report = publish_extended(
                            state,
                            &relay,
                            &my_pk,
                            &recipient,
                            &to_recipient,
                            &to_self,
                        )
                        .await;
                        record_delivery(state, &to_self.id, report);
                    } else {
                        // Own copy first, so the sent message is recoverable
                        // after a reload even if the recipient's publish fails.
                        for copy in delivery::plain_order() {
                            match copy {
                                delivery::Copy::Own => relay.publish(&to_self),
                                delivery::Copy::Recipient => relay.publish(&to_recipient),
                            }
                        }
                    }
                }
                Err(e) => {
                    let why = send_failure_text(&e);
                    web_sys::console::error_1(&format!("[DM] Gift wrap failed: {why}").into());
                    // Roll the optimistic bubble back and surface the error.
                    state.update(|s| {
                        s.seen_ids.remove(&local_id);
                        s.messages.retain(|m| m.id != local_id);
                        s.error = Some(format!("Could not send message: {why}"));
                    });
                }
            }
        });

        Ok(())
    }

    /// React to the message whose rumor id is `target_rumor_id` (see
    /// [`DMExtras::rumor_ids`]) with `emoji`. A kind 7 rumor through the same
    /// wrap and publish path as a message. Needs `RECIPIENT_KEYS_ENABLED`.
    // Consumed by the DM page; no page offers a reaction button yet.
    #[allow(dead_code)]
    pub fn send_reaction(
        &self,
        relay: &RelayConnection,
        recipient_pk_hex: &str,
        target_rumor_id: &str,
        emoji: &str,
        signer: Rc<dyn Signer>,
    ) -> Result<(), String> {
        if !extras_enabled() {
            return Err("Reactions are not enabled".into());
        }
        let emoji = emoji.trim();
        if emoji.is_empty() || emoji.chars().count() > 16 {
            return Err("Invalid reaction".into());
        }
        if !rumors::is_rumor_id(target_rumor_id) {
            return Err("Invalid message reference".into());
        }
        let recipient = canonical_pubkey(recipient_pk_hex)?;
        let me = signer.public_key().to_string();
        let rumor = rumors::reaction_rumor(
            &me,
            &recipient,
            &target_rumor_id.to_ascii_lowercase(),
            emoji,
        );
        self.state.with_untracked(|s| {
            rumors::validate_outgoing(&rumor, &recipient, &me, &|id| {
                known_in_conversation(s, id, &me, &recipient)
            })
        })?;
        self.send_control_rumor(relay, recipient, rumor, signer, me);
        Ok(())
    }

    /// Delete our own messages (rumor ids from [`DMExtras::rumor_ids`]): removed
    /// here at once, and a kind 5 rumor tells the other side. Refuses ids that
    /// are not messages we sent. Needs `RECIPIENT_KEYS_ENABLED`.
    // Consumed by the DM page; no page offers a delete action yet.
    #[allow(dead_code)]
    pub fn send_deletion(
        &self,
        relay: &RelayConnection,
        recipient_pk_hex: &str,
        target_rumor_ids: &[String],
        signer: Rc<dyn Signer>,
    ) -> Result<(), String> {
        if !extras_enabled() {
            return Err("Deletion is not enabled".into());
        }
        let recipient = canonical_pubkey(recipient_pk_hex)?;
        let me = signer.public_key().to_string();
        let targets: Vec<String> = target_rumor_ids
            .iter()
            .map(|t| t.to_ascii_lowercase())
            .collect();
        let all_mine = !targets.is_empty()
            && self
                .state
                .with_untracked(|s| targets.iter().all(|t| owns_rumor(s, t, &me)));
        if !all_mine {
            return Err("You can only delete your own messages".into());
        }
        let rumor = rumors::deletion_rumor(&me, &recipient, &targets);
        self.state.with_untracked(|s| {
            rumors::validate_outgoing(&rumor, &recipient, &me, &|id| {
                known_in_conversation(s, id, &me, &recipient)
            })
        })?;
        self.send_control_rumor(relay, recipient, rumor, signer, me);
        Ok(())
    }

    /// Wrap and publish a reaction or deletion rumor, then apply it locally
    /// under the self-copy's wrap id (so the relay echo dedups against it).
    fn send_control_rumor(
        &self,
        relay: &RelayConnection,
        recipient: String,
        rumor: nostr_bbs_core::UnsignedEvent,
        signer: Rc<dyn Signer>,
        me: String,
    ) {
        let relay = relay.clone();
        let state = self.state;
        wasm_bindgen_futures::spawn_local(async move {
            match gift_wrap_rumor_pair_with_signer(signer.as_ref(), &recipient, &rumor).await {
                Ok((to_recipient, to_self)) => {
                    let rumor_id = rumor_id_of(&rumor);
                    state.update(|s| apply_control_rumor(s, &to_self.id, &me, &rumor_id, &rumor));
                    let report =
                        publish_extended(state, &relay, &me, &recipient, &to_recipient, &to_self)
                            .await;
                    if report.outcome == Delivery::Failed {
                        state.update(|s| {
                            s.error = Some("Could not deliver that to any relay".into());
                        });
                    }
                }
                Err(e) => {
                    let why = send_failure_text(&e);
                    web_sys::console::error_1(&format!("[DM] Gift wrap failed: {why}").into());
                    state.update(|s| s.error = Some(format!("Could not send: {why}")));
                }
            }
        });
    }

    /// Inject a message directly into the store (dev-auth echo bot only).
    #[cfg(feature = "dev-auth")]
    pub fn inject_dev_message(&self, msg: DMMessage) {
        self.state.update(|s| {
            if s.seen_ids.insert(msg.id.clone()) {
                // Update conversation summary
                let convo = s
                    .conversations
                    .entry(msg.sender_pubkey.clone())
                    .or_insert_with(|| DMConversation {
                        pubkey: msg.sender_pubkey.clone(),
                        name: try_display_name(&msg.sender_pubkey).unwrap_or_default(),
                        last_message: String::new(),
                        last_timestamp: 0,
                        unread_count: 0,
                    });
                convo.last_message = truncate_message(&msg.content, 80);
                convo.last_timestamp = msg.timestamp;
                convo.unread_count += 1;

                // Only push to visible messages if this conversation is selected
                if s.current_conversation.as_deref() == Some(&msg.sender_pubkey) {
                    s.messages.push(msg);
                }
            }
        });
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

// -- DM subscription filters (pure; unit-tested on the host target) -----------
//
// # Why these are separate functions
//
// Two independent relay-side facts make naive DM filters silently return
// nothing, and both were live bugs:
//
// 1. **A gift wrap's `authors` is a throwaway key, never a person.** NIP-59
//    signs the kind-1059 outer layer with a fresh keypair minted per message
//    (`nostr_bbs_core::gift_wrap::wrap_seal`) precisely so an observer cannot
//    tell who sent it. The relay translates `authors` to `pubkey IN (...)`, so
//    ANY `authors` constraint on a kind-1059 filter matches zero rows — for
//    both parties, forever. A conversation's history is therefore *not*
//    selectable relay-side at all: the only usable handle is the `#p` tag, and
//    which conversation a wrap belongs to is knowable only AFTER unwrapping it
//    locally.
//
// 2. **The relay rewrites `#p` on any filter mentioning kind 1059.** The DM
//    privacy gate (`relay_do/nip_handlers.rs::gate_kind_1059_filters`) forces
//    `#p = <authenticated pubkey>` on every filter whose `kinds` contains 1059,
//    so that nobody can fish for someone else's wraps. Correct — but the client
//    used to bundle kinds 4 and 1059 into ONE filter, so the rewrite also
//    clobbered the legacy kind-4 half of the query and destroyed outbound
//    kind-4 history as collateral damage.
//
// Hence: gift wraps and legacy kind-4 DMs get **separate filters**, and the
// gift-wrap filter carries `#p` only.
//
// These are free functions taking plain strings so they can be asserted
// directly in host-target unit tests — the bug lived in filter *shape*, which
// no amount of crypto testing would have caught.

/// Filters for the gift-wrap (kind-1059) half of any DM query.
///
/// `#p` is the sole constraint by necessity (see the module note above).
/// `since` is optional: `None` asks for all history, `Some(t)` narrows a
/// realtime subscription.
fn gift_wrap_filters(my_pubkey: &str, since: Option<u64>) -> Vec<Filter> {
    vec![Filter {
        kinds: Some(vec![KIND_GIFT_WRAP]),
        p_tags: Some(vec![my_pubkey.to_string()]),
        since,
        ..Default::default()
    }]
}

/// Filters for the legacy NIP-04 (kind-4) half of a *conversation* query.
///
/// Kind 4 predates gift-wrapping: its author IS the real sender and the `p` tag
/// IS the real recipient, so both directions are precisely selectable — which
/// is exactly why it must not share a filter with kind 1059 and inherit the
/// relay's `#p` rewrite.
fn legacy_dm_filters(my_pubkey: &str, partner_pubkey: Option<&str>) -> Vec<Filter> {
    match partner_pubkey {
        // One conversation: both directions, each precisely constrained.
        Some(partner) => vec![
            Filter {
                kinds: Some(vec![KIND_ENCRYPTED_DM]),
                authors: Some(vec![my_pubkey.to_string()]),
                p_tags: Some(vec![partner.to_string()]),
                ..Default::default()
            },
            Filter {
                kinds: Some(vec![KIND_ENCRYPTED_DM]),
                authors: Some(vec![partner.to_string()]),
                p_tags: Some(vec![my_pubkey.to_string()]),
                ..Default::default()
            },
        ],
        // The whole inbox: everything we sent, plus everything addressed to us.
        None => vec![
            Filter {
                kinds: Some(vec![KIND_ENCRYPTED_DM]),
                authors: Some(vec![my_pubkey.to_string()]),
                ..Default::default()
            },
            Filter {
                kinds: Some(vec![KIND_ENCRYPTED_DM]),
                p_tags: Some(vec![my_pubkey.to_string()]),
                ..Default::default()
            },
        ],
    }
}

/// Every filter needed to rebuild the DM inbox (all conversations).
fn inbox_filters(my_pubkey: &str) -> Vec<Filter> {
    let mut f = gift_wrap_filters(my_pubkey, None);
    f.extend(legacy_dm_filters(my_pubkey, None));
    f
}

/// Every filter needed to rebuild one conversation's history.
///
/// Note the asymmetry, and that it is deliberate: the gift-wrap half CANNOT be
/// narrowed to `partner` relay-side, so it fetches the whole wrap inbox and the
/// conversation is selected locally after unwrapping. That is more data over
/// the wire than one would like, and it is the price NIP-59's sender anonymity
/// charges. The alternative — an `authors` constraint — simply returns nothing.
fn conversation_filters(my_pubkey: &str, partner_pubkey: &str) -> Vec<Filter> {
    let mut f = gift_wrap_filters(my_pubkey, None);
    f.extend(legacy_dm_filters(my_pubkey, Some(partner_pubkey)));
    f
}

/// Every filter for the realtime inbound subscription.
///
/// The gift-wrap half is windowed by `since` because NIP-59 randomises the
/// outer `created_at` up to ~2 days into the past; a `since = now` subscription
/// would skip a message sent this second. Legacy kind-4 keeps a real timestamp
/// but is left unwindowed — event-id dedup makes the overlap free.
fn incoming_filters(my_pubkey: &str, since: u64) -> Vec<Filter> {
    let mut f = gift_wrap_filters(my_pubkey, Some(since));
    f.extend(legacy_dm_filters(my_pubkey, None));
    f
}

/// How long to wait for the relay's EOSE before treating the REQ as dropped.
const DM_SUB_CONFIRM_MS: i32 = 3_000;
/// Maximum REQ attempts before surfacing an error.
const DM_SUB_MAX_ATTEMPTS: u32 = 4;

/// How far back to anchor the realtime incoming-DM subscription's `since`
/// filter. NIP-59 gift-wraps randomise their outer `created_at` up to ~2 days
/// into the past, so the live subscription must look back at least that far or
/// it silently drops freshly-sent DMs. Two days plus a small margin.
const GIFT_WRAP_LOOKBACK_SECS: u64 = 2 * 24 * 60 * 60 + 3600;

/// NIP-59 backdates a gift wrap's outer `created_at` by up to two days, so a
/// narrower lookback silently drops messages that were sent seconds ago. The
/// bound is a property of the constant alone, so it is asserted at compile time
/// rather than in a test that only the host target ever runs.
const _: () = assert!(
    GIFT_WRAP_LOOKBACK_SECS >= 2 * 24 * 60 * 60,
    "lookback must cover the full 2-day backdating window"
);

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

// -- App-wide incoming-DM watcher (Tier 0, ADR-2023) ---------------------------

/// Most stored wraps the watcher asks the relay for on connect.
const WATCHER_HISTORY_LIMIT: u64 = 100;

/// Subscribe to gift wraps addressed to `my_pubkey` for the whole app session
/// and raise a notification for each fresh DM.
///
/// The [`DMStore`] is provided per page (the DM list, a chat, the poker table),
/// so its subscription only exists while one of those is open; a DM arriving
/// anywhere else would never notify. This watcher lives in the layout instead.
/// It keeps no message state: it opens each wrap not yet announced, hands the
/// sender and rumor timestamp to the notification store (which applies the
/// baseline and de-duplication rules), and forgets the plaintext.
///
/// Returns the subscription id so the caller can close it on sign-out or a
/// dropped session. Call only once the relay session is NIP-42 authenticated.
pub fn start_incoming_watcher(
    relay: &RelayConnection,
    signer: Rc<dyn Signer>,
    my_pubkey: &str,
) -> String {
    let my_pk = my_pubkey.to_string();
    let since = ((js_sys::Date::now() / 1000.0) as u64).saturating_sub(GIFT_WRAP_LOOKBACK_SECS);
    let mut filters = gift_wrap_filters(&my_pk, Some(since));
    // Bound the history this always-on watcher decrypts: anyone can send a wrap,
    // so an unbounded window is a decrypt flood on every page load. Live wraps
    // are not subject to the limit.
    for f in &mut filters {
        f.limit = Some(WATCHER_HISTORY_LIMIT);
    }
    let on_event: EventCallback = Rc::new(move |event: NostrEvent| {
        if event.kind != KIND_GIFT_WRAP {
            return;
        }
        let signer = signer.clone();
        let me = my_pk.clone();
        wasm_bindgen_futures::spawn_local(async move {
            watch_one(&event, signer.as_ref(), &me).await;
        });
    });
    relay.subscribe(filters, on_event, None)
}

/// Open one wrap and notify if it is a fresh DM from someone else.
async fn watch_one(event: &NostrEvent, signer: &dyn Signer, me: &str) {
    let Some(store) = crate::stores::notifications::global_notification_store() else {
        return;
    };
    // Already announced (or settled as backlog) on an earlier load: skip the
    // decryption entirely.
    if store.dm_settled(&event.id) {
        return;
    }
    // Zone-key grants and poker traffic ride the same transport and fail here;
    // that is expected, not an error.
    let Ok(unwrapped) = unwrap_gift_with_signer(event, signer).await else {
        return;
    };
    // Reactions, deletions and file messages now unwrap too (ADR-2027); this
    // inbox renders chat only until it grows UI for them.
    if unwrapped.rumor_kind() != Some(nostr_bbs_core::gift_wrap::RumorKind::Chat) {
        return;
    }
    let is_sent = unwrapped.sender_pubkey == me;
    // Only the other party can be the coach: a wrap we sent is our own copy.
    if !is_sent && is_coach_exchange(&unwrapped.rumor.content, &unwrapped.sender_pubkey) {
        return;
    }
    // A request from a non-member waits in Requests without a notification
    // (ADR-2027); a no-op with the flag off.
    if !is_sent && !requests::notifies_for(&unwrapped.sender_pubkey, me).await {
        return;
    }
    store.notify_dm(
        &event.id,
        &unwrapped.sender_pubkey,
        unwrapped.rumor.created_at,
        is_sent,
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
        // A zone-key grant (ADR-2016) rides the same gift-wrap transport but
        // is not a DM: core refuses its rumor kind, and the zone-key store
        // picks it up instead. Not an error, so nothing to log.
        // The poker table's messages (ADR-2020) ride the same transport too;
        // the table's own subscription reads them.
        Err(nostr_bbs_core::gift_wrap::SignerGiftWrapError::InvalidKind { actual, .. })
            if actual == crate::zone_crypto::KIND_ZONE_KEY_GRANT
                || actual == nostr_bbs_poker::protocol::RUMOR_KIND =>
        {
            return;
        }
        Err(e) => {
            // Core's own errors are fixed strings (never decrypted bytes); a
            // signer error carries the backend's text, which names the
            // extension's capability, not message content.
            web_sys::console::warn_1(
                &format!("[DM] Gift unwrap failed for {}: {e}", event.id).into(),
            );
            // A NIP-07 extension that implements only NIP-04 (no `window.nostr
            // .nip44`) cannot decrypt gift wraps at all — every unwrap fails the
            // same way and the list would otherwise stay silently empty. Surface
            // a clear, actionable message instead of leaving the user guessing.
            if signer_lacks_nip44(&e) {
                state.update(|s| {
                    if s.error.is_none() {
                        s.error = Some(
                            "Your Nostr extension doesn't support NIP-44 encryption, which is \
                             required to read these messages. Update your extension (or use a \
                             local key) to view DMs."
                                .into(),
                        );
                    }
                });
            }
            return;
        }
    };
    // Reactions, deletions and file messages unwrap too (ADR-2027). Today's
    // behaviour, chat only, stands unless the interop flag is on.
    let incoming = if unwrapped.rumor_kind() == Some(nostr_bbs_core::gift_wrap::RumorKind::Chat) {
        rumors::Incoming::Chat
    } else if extras_enabled() {
        match rumors::classify(&unwrapped.rumor) {
            Some(other) => other,
            None => return,
        }
    } else {
        return;
    };

    let my_pubkey = my_pubkey.to_ascii_lowercase();
    let sender_pubkey = unwrapped.sender_pubkey.to_ascii_lowercase();
    let is_sent = sender_pubkey == my_pubkey;

    // The rumor's "p" tag identifies the recipient
    let recipient_pubkey = unwrapped
        .rumor
        .tags
        .iter()
        .find(|t| t.len() >= 2 && t[0] == "p")
        .map(|t| t[1].to_ascii_lowercase())
        .unwrap_or_else(|| {
            if is_sent {
                String::new()
            } else {
                my_pubkey.clone()
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

    let rumor_id = rumor_id_of(&unwrapped.rumor);

    // What the message says. A file message shows its URL as the text and keeps
    // the attachment alongside; a reaction or deletion is not a message at all.
    let (plaintext, attachment, preview) = match incoming {
        rumors::Incoming::Chat => {
            let text = unwrapped.rumor.content.clone();
            (text.clone(), None, text)
        }
        rumors::Incoming::File(att) => (att.url.clone(), Some(att), "[file]".to_string()),
        rumors::Incoming::Reaction { .. } | rumors::Incoming::Deletion { .. } => {
            state.update(|s| {
                apply_control_rumor(s, &event.id, &sender_pubkey, &rumor_id, &unwrapped.rumor)
            });
            return;
        }
    };

    // Use the rumor's created_at as the real timestamp (wrap timestamp is randomized)
    // (sender-controlled, so clamp it to now).
    let timestamp = clamp_to_now(unwrapped.rumor.created_at, now_secs());

    // Use the outer wrap event ID for deduplication
    let msg = DMMessage {
        id: event.id.clone(),
        sender_pubkey,
        recipient_pubkey,
        content: plaintext,
        timestamp,
        is_sent,
        is_read: is_sent,
    };

    if extras_enabled() {
        // Index even a wrap already seen (our own echo), so a reaction to a
        // message we sent can find it; skip a message its sender has deleted.
        let skip = state.with_untracked(|s| is_tombstoned(s, &rumor_id, &msg.sender_pubkey));
        state.update(|s| index_rumor(s, &rumor_id, &msg.id));
        if skip {
            state.update(|s| {
                s.seen_ids.insert(msg.id.clone());
            });
            return;
        }
        if let Some(att) = attachment {
            state.update(|s| {
                s.attachments.insert(msg.id.clone(), att);
            });
        }
    }

    insert_dm_message(msg, &counterparty_pk, &preview, timestamp, is_sent, state);
}

/// Decrypt a legacy kind 4 DM event and insert into state.
///
/// Decryption goes through the signer's `nip04_decrypt`, which works for
/// local-key and NIP-07 sessions alike.
///
/// This previously called `nip44_decrypt`. Kind 4 is NIP-04 (AES-256-CBC);
/// NIP-44 is ChaCha20-Poly1305 and a different key schedule, so the call could
/// only ever fail. Every legacy DM was therefore dropped with a console warning
/// and the conversation rendered empty — one of the several independent causes
/// of "DM history isn't viewable".
async fn process_kind4_event(
    event: &NostrEvent,
    signer: &dyn Signer,
    my_pubkey: &str,
    state: RwSignal<DMStateInner>,
) {
    let my_pubkey = my_pubkey.to_ascii_lowercase();
    let sender_pubkey = event.pubkey.to_ascii_lowercase();
    let is_sent = sender_pubkey == my_pubkey;
    let counterparty_pk = if is_sent {
        event
            .tags
            .iter()
            .find(|t| t.len() >= 2 && t[0] == "p")
            .map(|t| t[1].to_ascii_lowercase())
    } else {
        Some(sender_pubkey.clone())
    };

    let counterparty_pk = match counterparty_pk {
        Some(pk) if pk.len() == 64 => pk,
        _ => return,
    };

    // NIP-44 conversation key is symmetric: decrypt with our key against the
    // counterparty pubkey, via the signer.
    let plaintext = match signer.nip04_decrypt(&counterparty_pk, &event.content).await {
        Ok(pt) => pt,
        Err(e) => {
            web_sys::console::warn_1(
                &format!("[DM] Decrypt failed for {}: {}", event.id, e).into(),
            );
            return;
        }
    };

    let timestamp = clamp_to_now(event.created_at, now_secs());
    let msg = DMMessage {
        id: event.id.clone(),
        sender_pubkey,
        recipient_pubkey: if is_sent {
            counterparty_pk.clone()
        } else {
            my_pubkey
        },
        content: plaintext.clone(),
        timestamp,
        is_sent,
        is_read: is_sent,
    };

    insert_dm_message(msg, &counterparty_pk, &plaintext, timestamp, is_sent, state);
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
    let coach = crate::poker::PokerConfig::load().coach();
    state.update(|s| {
        apply_message(
            s,
            msg,
            counterparty_pk,
            plaintext,
            timestamp,
            is_sent,
            coach.as_deref(),
        )
    });
}

/// Whether `content` exchanged with `counterparty` is poker-table plumbing:
/// tagged like a coach request or reply AND the other party is the configured
/// coach agent. The tag alone proves nothing, since anyone can start a message
/// with `[coach]`; classifying on text alone hid such a message from the
/// recipient's inbox and notifications, and made the sender skip their own
/// NIP-17 copy, so it vanished from their history for good.
fn is_coach_exchange_with(content: &str, counterparty: &str, coach: Option<&str>) -> bool {
    is_coach_content(content) && coach.is_some_and(|c| c.eq_ignore_ascii_case(counterparty))
}

/// [`is_coach_exchange_with`] against the operator's configured coach.
fn is_coach_exchange(content: &str, counterparty: &str) -> bool {
    is_coach_exchange_with(
        content,
        counterparty,
        crate::poker::PokerConfig::load().coach().as_deref(),
    )
}

/// Store a message (once, by id) and fold it into its conversation's summary:
/// preview, time and unread count.
///
/// A coach exchange (the practice table's `[poker-coach]` requests and
/// `[coach]` replies, [`is_coach_content`]) is stored like any message, so
/// the table can read the reply, but never touches the summary: it opens no
/// conversation, sets no preview and counts toward no unread total.
fn apply_message(
    s: &mut DMStateInner,
    msg: DMMessage,
    counterparty_pk: &str,
    plaintext: &str,
    timestamp: u64,
    is_sent: bool,
    coach: Option<&str>,
) {
    // A re-streamed event (relay reconnect, overlapping subscriptions) must not
    // touch the summary a second time, or the unread badge inflates.
    if !s.seen_ids.insert(msg.id.clone()) {
        return;
    }
    s.messages.push(msg);
    if is_coach_exchange_with(plaintext, counterparty_pk, coach) {
        return;
    }

    let convo = s
        .conversations
        .entry(counterparty_pk.to_string())
        .or_insert_with(|| DMConversation {
            pubkey: counterparty_pk.to_string(),
            name: try_display_name(counterparty_pk).unwrap_or_default(),
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
}

/// One conversation's messages, oldest first, coach exchanges left out.
///
/// The "other party" of a message is the recipient when we sent it and the
/// sender when we received it.
fn thread_of(messages: &[DMMessage], counterparty: &str, coach: Option<&str>) -> Vec<DMMessage> {
    // Pubkeys are lowercased at ingestion, so the only normalisation left is
    // the caller's argument (a UI route value or config string).
    let counterparty = canonical_or_lower(counterparty);
    let mut msgs: Vec<DMMessage> = messages
        .iter()
        .filter(|m| !is_coach_exchange_with(&m.content, &counterparty, coach))
        .filter(|m| {
            let other = if m.is_sent {
                &m.recipient_pubkey
            } else {
                &m.sender_pubkey
            };
            *other == counterparty
        })
        .cloned()
        .collect();
    msgs.sort_by_key(|m| m.timestamp);
    msgs
}

/// The conversation list, most recent first. Coach exchanges never open a
/// conversation ([`apply_message`]), so a partner met only through the coach
/// is not listed.
fn visible_conversations(inner: &DMStateInner) -> Vec<DMConversation> {
    let mut convos: Vec<DMConversation> = inner.conversations.values().cloned().collect();
    convos.sort_by_key(|x| std::cmp::Reverse(x.last_timestamp));
    convos
}

// -- Recipient identity -------------------------------------------------------

/// A recipient pubkey as lowercase hex, from hex in any case or an `npub`.
///
/// Parsed through `nostr::PublicKey`, so a malformed key, or a 64-character
/// string that is not a point on the curve, is refused before any crypto runs.
/// Everything downstream (the `p` tag, the conversation key, the ledger) then
/// agrees on one spelling: a mixed-case key used to make a second conversation
/// and a wrap whose `p` tag the relay's recipient gate did not match.
fn canonical_pubkey(input: &str) -> Result<String, String> {
    nostr::PublicKey::parse(input.trim())
        .map(|k| k.to_hex())
        .map_err(|_| "Invalid recipient pubkey".to_string())
}

/// [`canonical_pubkey`], or the plain lowercase when it does not parse (a
/// conversation key from a route is looked up, not trusted).
fn canonical_or_lower(input: &str) -> String {
    canonical_pubkey(input).unwrap_or_else(|_| input.trim().to_ascii_lowercase())
}

// -- Extended NIP-17 behaviour (ADR-2027), behind RECIPIENT_KEYS_ENABLED -------

/// Whether the interoperable NIP-17 behaviour is switched on: multi-relay
/// delivery, reactions, deletions and file messages. Off leaves the DM path as
/// it was.
fn extras_enabled() -> bool {
    crate::zone_crypto::inbox_key::recipient_keys_enabled()
}

/// A rumor's NIP-01 id as hex: what a reaction or deletion refers to.
fn rumor_id_of(rumor: &nostr_bbs_core::UnsignedEvent) -> String {
    hex::encode(nostr_bbs_core::compute_event_id(rumor))
}

fn index_rumor(s: &mut DMStateInner, rumor_id: &str, msg_id: &str) {
    s.rumor_index
        .insert(rumor_id.to_string(), msg_id.to_string());
    s.msg_rumor.insert(msg_id.to_string(), rumor_id.to_string());
}

/// Whether `rumor_id` is a message we know that `sender` sent.
fn owns_rumor(s: &DMStateInner, rumor_id: &str, sender: &str) -> bool {
    s.rumor_index
        .get(rumor_id)
        .and_then(|mid| s.messages.iter().find(|m| &m.id == mid))
        .is_some_and(|m| m.sender_pubkey == sender)
}

/// Whether `rumor_id` is a message already in the conversation between `me`
/// and `recipient` (either direction) in the local store.
fn known_in_conversation(s: &DMStateInner, rumor_id: &str, me: &str, recipient: &str) -> bool {
    s.rumor_index
        .get(rumor_id)
        .and_then(|mid| s.messages.iter().find(|m| &m.id == mid))
        .is_some_and(|m| {
            (m.sender_pubkey == me && m.recipient_pubkey == recipient)
                || (m.sender_pubkey == recipient && m.recipient_pubkey == me)
        })
}

fn is_tombstoned(s: &DMStateInner, rumor_id: &str, sender: &str) -> bool {
    s.tombstones
        .contains(&(rumor_id.to_string(), sender.to_string()))
}

/// Attach a reaction to its target rumor. Idempotent per wrap id and per
/// `(sender, emoji)`; ignored if the sender already deleted it.
fn apply_reaction(
    s: &mut DMStateInner,
    wrap_id: &str,
    sender: &str,
    rumor_id: &str,
    target: &str,
    emoji: &str,
) {
    if !s.seen_ids.insert(wrap_id.to_string()) || is_tombstoned(s, rumor_id, sender) {
        return;
    }
    let list = s.reactions.entry(target.to_string()).or_default();
    if list.iter().any(|r| r.sender == sender && r.emoji == emoji) {
        return;
    }
    list.push(Reaction {
        sender: sender.to_string(),
        emoji: emoji.to_string(),
        rumor_id: rumor_id.to_string(),
    });
}

/// Apply a deletion request from `deleter`: it removes that sender's OWN
/// messages and reactions, and nothing else. The request is remembered either
/// way, so one that arrives before its target still takes effect.
fn apply_deletion(s: &mut DMStateInner, wrap_id: &str, deleter: &str, targets: &[String]) {
    if !s.seen_ids.insert(wrap_id.to_string()) {
        return;
    }
    for target in targets {
        s.tombstones.insert((target.clone(), deleter.to_string()));
        if owns_rumor(s, target, deleter) {
            if let Some(mid) = s.rumor_index.get(target).cloned() {
                // `seen_ids` keeps the wrap id, so a re-streamed copy is not
                // resurrected.
                s.messages.retain(|m| m.id != mid);
                s.attachments.remove(&mid);
                s.deliveries.remove(&mid);
            }
            s.reactions.remove(target);
        }
        for list in s.reactions.values_mut() {
            list.retain(|r| !(r.rumor_id == *target && r.sender == deleter));
        }
    }
}

/// Apply a reaction or deletion rumor sent by `sender` (us, or the other side).
fn apply_control_rumor(
    s: &mut DMStateInner,
    wrap_id: &str,
    sender: &str,
    rumor_id: &str,
    rumor: &nostr_bbs_core::UnsignedEvent,
) {
    match rumors::classify(rumor) {
        Some(rumors::Incoming::Reaction { target, emoji }) => {
            apply_reaction(s, wrap_id, sender, rumor_id, &target, &emoji)
        }
        Some(rumors::Incoming::Deletion { targets }) => {
            apply_deletion(s, wrap_id, sender, &targets)
        }
        _ => {}
    }
}

/// The per-message extras, with reactions re-keyed from rumor id to message id.
fn extras_of(s: &DMStateInner) -> DMExtras {
    let reactions = s
        .reactions
        .iter()
        .filter_map(|(target, list)| {
            let mid = s.rumor_index.get(target)?;
            (!list.is_empty()).then(|| (mid.clone(), list.clone()))
        })
        .collect();
    DMExtras {
        reactions,
        attachments: s.attachments.clone(),
        deliveries: s.deliveries.clone(),
        rumor_ids: s.msg_rumor.clone(),
    }
}

fn record_delivery(state: RwSignal<DMStateInner>, msg_id: &str, report: DeliveryReport) {
    if report.outcome != Delivery::Sent {
        web_sys::console::warn_1(
            &format!(
                "[DM] delivery {:?}: {:?}",
                report.outcome, report.to_recipient
            )
            .into(),
        );
    }
    state.update(|s| {
        if report.outcome == Delivery::Failed {
            s.error = Some("Message not delivered: no relay accepted it".into());
        }
        s.deliveries.insert(msg_id.to_string(), report);
    });
}

// -- Multi-relay publish --------------------------------------------------------

/// How long our own relay has to acknowledge a publish.
const OWN_ACK_TIMEOUT_MS: i32 = 8_000;
/// How long a foreign relay has to acknowledge a publish.
const FOREIGN_ACK_TIMEOUT_MS: i32 = 8_000;

/// Answers still outstanding for one send, and where they land.
struct Tally {
    to_recipient: std::cell::RefCell<Vec<Attempt>>,
    own_copy: std::cell::RefCell<Vec<Attempt>>,
    outstanding: std::cell::Cell<usize>,
    done: Rc<OneShot<()>>,
}

impl Tally {
    fn record(&self, for_recipient: bool, attempt: Attempt) {
        let list = if for_recipient {
            &self.to_recipient
        } else {
            &self.own_copy
        };
        list.borrow_mut().push(attempt);
        self.settle();
    }

    /// One outstanding item is accounted for; wake the waiter when none remain.
    fn settle(&self) {
        self.outstanding
            .set(self.outstanding.get().saturating_sub(1));
        if self.outstanding.get() == 0 {
            self.done.fill(());
        }
    }
}

/// Publish to our own relay and wait for its `OK` (or the timeout).
async fn publish_ours(relay: &RelayConnection, event: &NostrEvent) -> Attempt {
    let url = crate::utils::relay_url::relay_url();
    let slot: Rc<OneShot<(bool, String)>> = OneShot::new();
    let on_ok_slot = slot.clone();
    let on_ok: PublishCallback = Rc::new(move |accepted, msg| on_ok_slot.fill((accepted, msg)));
    if let Err(e) = relay.publish_with_ack(event, Some(on_ok)) {
        return Attempt::failed(&url, &e);
    }
    let timeout = slot.clone();
    crate::utils::set_timeout_once(
        move || timeout.fill((false, "timeout".to_string())),
        OWN_ACK_TIMEOUT_MS,
    );
    let (accepted, reason) = slot.wait().await;
    Attempt {
        relay: url,
        accepted,
        reason,
    }
}

/// A report for a send that stopped early, with `why` as the only recipient
/// attempt so the cause is on the message.
fn stopped(why: &str, own_copy: Vec<Attempt>) -> DeliveryReport {
    let to_recipient = vec![Attempt::failed("", why)];
    DeliveryReport {
        outcome: delivery::fold(&to_recipient, &own_copy),
        to_recipient,
        own_copy,
    }
}

/// Ask the member to confirm connecting to a stranger's relays; no answer in
/// [`consent::ANSWER_TIMEOUT_MS`] counts as "Cancel".
async fn ask_consent(
    state: RwSignal<DMStateInner>,
    recipient: &str,
    foreign: &[nostr::RelayUrl],
) -> bool {
    let answer = consent::begin();
    state.update(|s| {
        s.consent = Some(consent::ConsentRequest {
            recipient: recipient.to_string(),
            hosts: delivery::hosts(foreign),
        });
    });
    let timeout = answer.clone();
    crate::utils::set_timeout_once(move || timeout.fill(false), consent::ANSWER_TIMEOUT_MS);
    let accepted = answer.wait().await;
    state.update(|s| s.consent = None);
    accepted
}

/// Publish both copies of a wrapped rumor and report what each relay said.
///
/// 1. Our own copy goes first, alone, and the send waits for our relay to
///    acknowledge it. If that fails nothing is sent to the recipient: a message
///    that arrived but cannot be recovered by its author is worse than one that
///    visibly failed.
/// 2. Only then the route and membership are resolved. A plan with no recipient
///    target at all ([`delivery::NO_ROUTE`]) is `Failed` before anything else
///    is published.
/// 3. For a non-member with foreign relays the member must confirm once per
///    recipient; no foreign socket opens before that
///    ([`delivery::release_steps`]).
/// 4. The recipient's copy goes to the relays they named, and to ours only when
///    they are a member (our relay refuses a wrap for a non-member). Nothing is
///    called "sent" unless the recipient's copy was acknowledged somewhere.
async fn publish_extended(
    state: RwSignal<DMStateInner>,
    relay: &RelayConnection,
    me: &str,
    recipient: &str,
    to_recipient: &NostrEvent,
    to_self: &NostrEvent,
) -> DeliveryReport {
    let own = publish_ours(relay, to_self).await;
    if !delivery::own_copy_stored(&own) {
        return stopped(
            "your own copy could not be stored, so nothing was sent",
            vec![own],
        );
    }

    let route = routing::route_for(relay, recipient).await;
    let member = recipient_is_member(recipient).await;
    let plan = delivery::plan(&route, member);
    if plan.is_empty() {
        return stopped(delivery::NO_ROUTE, vec![own]);
    }

    let accepted = consent::is_accepted(me, recipient).await;
    let required = delivery::consent_needed(member, &plan.foreign, accepted);
    let mut given = false;
    if required {
        given = ask_consent(state, recipient, &plan.foreign).await;
        if !given {
            return stopped("cancelled: foreign relays were not approved", vec![own]);
        }
        consent::remember(me, recipient).await;
    }
    let steps = delivery::release_steps(&delivery::send_order(&plan), required, given);
    // The first step, our own copy, has already been published and acknowledged.
    let rest = &steps[1..];

    let tally = Rc::new(Tally {
        to_recipient: Default::default(),
        own_copy: std::cell::RefCell::new(vec![own]),
        outstanding: std::cell::Cell::new(rest.len()),
        done: OneShot::new(),
    });
    for (_, target) in rest {
        let (relay, ev, tally) = (relay.clone(), to_recipient.clone(), tally.clone());
        match target {
            delivery::Target::Ours => wasm_bindgen_futures::spawn_local(async move {
                let attempt = publish_ours(&relay, &ev).await;
                tally.record(true, attempt);
            }),
            delivery::Target::Foreign(url) => {
                let url = url.to_string();
                wasm_bindgen_futures::spawn_local(async move {
                    let attempt =
                        match crate::relay::publish_to(&url, &ev, FOREIGN_ACK_TIMEOUT_MS).await {
                            Ok(()) => Attempt::ok(&url),
                            Err(reason) => Attempt::failed(&url, &reason),
                        };
                    tally.record(true, attempt);
                });
            }
        }
    }
    tally.done.wait().await;

    let recipient_attempts = tally.to_recipient.borrow().clone();
    let own_copy = tally.own_copy.borrow().clone();
    DeliveryReport {
        outcome: delivery::fold(&recipient_attempts, &own_copy),
        to_recipient: recipient_attempts,
        own_copy,
    }
}

/// Whether `recipient` is a member of this board, from the one membership cache
/// in the DM module ([`requests::reaches_our_relay_cached`]).
///
/// A lookup that fails counts as "member": sending to our relay as well costs
/// one refused `OK` the send path already treats as expected, while wrongly
/// skipping our relay would strand a member's message.
async fn recipient_is_member(recipient: &str) -> bool {
    requests::reaches_our_relay_cached(recipient)
        .await
        .unwrap_or(true)
}

// -- Helpers ------------------------------------------------------------------

/// Tags of the kind-10050 DM-relay list (NIP-17): one `["relay", url]` per
/// relay. (`"r"` is the NIP-65 relay-list tag and is not read for 10050.)
fn dm_relay_tags(relay_url: &str) -> Vec<Vec<String>> {
    vec![vec!["relay".to_string(), relay_url.to_string()]]
}

/// Clamp a sender-controlled timestamp to `now`. A rumor's `created_at` is
/// chosen by the sender, so a far-future value would otherwise pin its message
/// to the top of the thread and win the conversation preview forever.
fn clamp_to_now(timestamp: u64, now: u64) -> u64 {
    timestamp.min(now)
}

/// Current Unix time in seconds, from the browser clock.
fn now_secs() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}

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
        tags: dm_relay_tags(&relay_url),
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

/// Whether an unwrap failure means the NIP-07 extension has no NIP-44 at all.
///
/// Matched on the signer variant, never on core's own error text: core's
/// messages are fixed strings about layers, and only the signer backend
/// reports the extension's capabilities.
fn signer_lacks_nip44(e: &nostr_bbs_core::gift_wrap::SignerGiftWrapError) -> bool {
    match e {
        nostr_bbs_core::gift_wrap::SignerGiftWrapError::Signer(se) => {
            let msg = se.to_string();
            msg.contains("nip44 not supported") || msg.contains("window.nostr.nip44")
        }
        _ => false,
    }
}

/// What to tell the user (and the console) when a DM could not be wrapped.
///
/// One fixed sentence per category. The signer's own text is passed through
/// because it names a capability or a refusal the user can act on; nothing
/// on the wrap path carries message content in an error.
fn send_failure_text(e: &nostr_bbs_core::gift_wrap::SignerGiftWrapError) -> String {
    use nostr_bbs_core::gift_wrap::SignerGiftWrapError as E;
    if signer_lacks_nip44(e) {
        return "your Nostr extension does not support NIP-44 encryption".to_string();
    }
    match e {
        E::Signer(se) => format!("your signer refused: {se}"),
        E::Serialization(_) | E::InvalidKind { .. } => {
            "the message could not be encoded".to_string()
        }
        E::KeyError(_) => "a key on the envelope was malformed".to_string(),
        E::SealVerification(_) | E::WrapVerification(_) | E::AuthorMismatch { .. } => {
            "the encrypted envelope failed its own check".to_string()
        }
    }
}

// -- Tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const ME: &str = "11111111111111111111111111111111111111111111111111111111111111aa";
    const PARTNER: &str = "22222222222222222222222222222222222222222222222222222222222222bb";

    /// Every filter in `filters` that targets gift wraps.
    fn wrap_filters(filters: &[Filter]) -> Vec<&Filter> {
        filters
            .iter()
            .filter(|f| {
                f.kinds
                    .as_ref()
                    .map(|k| k.contains(&KIND_GIFT_WRAP))
                    .unwrap_or(false)
            })
            .collect()
    }

    /// Every filter in `filters` that targets legacy kind-4 DMs.
    fn legacy_filters(filters: &[Filter]) -> Vec<&Filter> {
        filters
            .iter()
            .filter(|f| {
                f.kinds
                    .as_ref()
                    .map(|k| k.contains(&KIND_ENCRYPTED_DM))
                    .unwrap_or(false)
            })
            .collect()
    }

    // ── The regression that made DM history unviewable ──────────────────────

    #[test]
    fn no_gift_wrap_filter_constrains_authors() {
        // THE bug. A kind-1059 event is signed by a per-message throwaway key,
        // so `authors: [anyone_real]` matches zero rows at the relay. A history
        // query built that way returns nothing — for both parties, always.
        for filters in [
            inbox_filters(ME),
            conversation_filters(ME, PARTNER),
            incoming_filters(ME, 1_700_000_000),
        ] {
            for f in wrap_filters(&filters) {
                assert!(
                    f.authors.is_none(),
                    "gift-wrap filter must not constrain authors \
                     (wraps are signed by throwaway keys): {f:?}"
                );
            }
        }
    }

    #[test]
    fn gift_wrap_and_legacy_kinds_never_share_a_filter() {
        // The relay's DM privacy gate rewrites `#p` to the authenticated pubkey
        // on ANY filter mentioning kind 1059. Bundling kind 4 into that filter
        // let the rewrite clobber the legacy query too, which is what destroyed
        // outbound kind-4 history.
        for filters in [
            inbox_filters(ME),
            conversation_filters(ME, PARTNER),
            incoming_filters(ME, 1_700_000_000),
        ] {
            for f in &filters {
                let kinds = f.kinds.as_ref().expect("every DM filter pins its kinds");
                let has_wrap = kinds.contains(&KIND_GIFT_WRAP);
                let has_legacy = kinds.contains(&KIND_ENCRYPTED_DM);
                assert!(
                    !(has_wrap && has_legacy),
                    "kinds 1059 and 4 must be queried separately: {f:?}"
                );
            }
        }
    }

    #[test]
    fn gift_wrap_filter_is_addressed_to_me() {
        // `#p` is the only handle a wrap exposes, so it must be present and it
        // must be us — anything else is either empty or someone else's mail.
        for filters in [
            inbox_filters(ME),
            conversation_filters(ME, PARTNER),
            incoming_filters(ME, 1_700_000_000),
        ] {
            let wraps = wrap_filters(&filters);
            assert!(!wraps.is_empty(), "a DM query must ask for gift wraps");
            for f in wraps {
                assert_eq!(f.p_tags.as_deref(), Some(&[ME.to_string()][..]));
            }
        }
    }

    #[test]
    fn conversation_gift_wrap_filter_is_not_narrowed_to_the_partner() {
        // Deliberate and worth pinning: a wrap carries no relay-visible hint of
        // which conversation it belongs to, so the partner cannot be part of
        // the query. Selection happens locally, after unwrapping. A future
        // "optimisation" that adds the partner here would silently empty the
        // page again.
        let filters = conversation_filters(ME, PARTNER);
        for f in wrap_filters(&filters) {
            assert!(f.authors.is_none());
            assert_eq!(f.p_tags.as_deref(), Some(&[ME.to_string()][..]));
        }
    }

    // ── Legacy kind-4 halves ────────────────────────────────────────────────

    #[test]
    fn conversation_legacy_filters_cover_both_directions() {
        let filters = conversation_filters(ME, PARTNER);
        let legacy = legacy_filters(&filters);
        assert_eq!(legacy.len(), 2, "sent and received");

        let sent = legacy
            .iter()
            .find(|f| f.authors.as_deref() == Some(&[ME.to_string()][..]))
            .expect("outbound kind-4 filter");
        assert_eq!(sent.p_tags.as_deref(), Some(&[PARTNER.to_string()][..]));

        let recv = legacy
            .iter()
            .find(|f| f.authors.as_deref() == Some(&[PARTNER.to_string()][..]))
            .expect("inbound kind-4 filter");
        assert_eq!(recv.p_tags.as_deref(), Some(&[ME.to_string()][..]));
    }

    #[test]
    fn inbox_legacy_filters_cover_sent_and_received() {
        let filters = inbox_filters(ME);
        let legacy = legacy_filters(&filters);
        assert_eq!(legacy.len(), 2);
        assert!(legacy
            .iter()
            .any(|f| f.authors.as_deref() == Some(&[ME.to_string()][..]) && f.p_tags.is_none()));
        assert!(legacy
            .iter()
            .any(|f| f.p_tags.as_deref() == Some(&[ME.to_string()][..]) && f.authors.is_none()));
    }

    // ── since-windowing ─────────────────────────────────────────────────────

    #[test]
    fn only_the_realtime_wrap_filter_is_windowed() {
        // History queries must be unwindowed or they are not history.
        for filters in [inbox_filters(ME), conversation_filters(ME, PARTNER)] {
            for f in &filters {
                assert!(
                    f.since.is_none(),
                    "history filter must not set since: {f:?}"
                );
            }
        }

        // The realtime wrap sub IS windowed, to cover NIP-59's backdating.
        let since = 1_700_000_000;
        let live = incoming_filters(ME, since);
        for f in wrap_filters(&live) {
            assert_eq!(f.since, Some(since));
        }
    }

    // -- coach exchanges: stored, but out of the inbox ----------------------

    const MEMBER: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const COACH: &str = "2de44d5622eef79519ac078f6e227a85aecbaefd561e4e50c5f51dfadbf916e9";

    fn received(id: &str, text: &str, ts: u64) -> DMMessage {
        DMMessage {
            id: id.into(),
            sender_pubkey: COACH.into(),
            recipient_pubkey: MEMBER.into(),
            content: text.into(),
            timestamp: ts,
            is_sent: false,
            is_read: false,
        }
    }

    fn sent(id: &str, text: &str, ts: u64) -> DMMessage {
        DMMessage {
            id: id.into(),
            sender_pubkey: MEMBER.into(),
            recipient_pubkey: COACH.into(),
            content: text.into(),
            timestamp: ts,
            is_sent: true,
            is_read: true,
        }
    }

    fn apply(s: &mut DMStateInner, m: DMMessage) {
        let text = m.content.clone();
        let (ts, out) = (m.timestamp, m.is_sent);
        apply_message(s, m, COACH, &text, ts, out, Some(COACH));
    }

    #[test]
    fn dm_relay_list_uses_the_nip17_relay_tag() {
        assert_eq!(
            dm_relay_tags("wss://relay.example"),
            vec![vec!["relay".to_string(), "wss://relay.example".to_string()]]
        );
    }

    #[test]
    fn clamp_to_now_pins_future_timestamps() {
        assert_eq!(clamp_to_now(5_000, 1_000), 1_000);
        assert_eq!(clamp_to_now(900, 1_000), 900);
        assert_eq!(clamp_to_now(1_000, 1_000), 1_000);
    }

    #[test]
    fn restreamed_message_does_not_inflate_unread_or_preview() {
        let mut s = DMStateInner::default();
        let m = received("dup", "hello", 10);
        apply_message(&mut s, m.clone(), COACH, "hello", 10, false, None);
        apply_message(&mut s, m, COACH, "hello", 10, false, None);
        assert_eq!(s.messages.len(), 1);
        assert_eq!(s.conversations[COACH].unread_count, 1);
        // a replay must not rewrite the preview either
        let mut again = received("dup", "tampered", 99);
        again.id = "dup".into();
        apply_message(&mut s, again, COACH, "tampered", 99, false, None);
        assert_eq!(s.conversations[COACH].last_message, "hello");
        assert_eq!(s.conversations[COACH].last_timestamp, 10);
    }

    #[test]
    fn thread_matching_is_exact_on_lowercased_keys() {
        let mut m = received("a", "hi", 1);
        m.sender_pubkey = "ab".repeat(32);
        let thread = thread_of(std::slice::from_ref(&m), &"AB".repeat(32), None);
        assert_eq!(thread.len(), 1);
        assert!(thread_of(&[m], &"cd".repeat(32), None).is_empty());
    }

    #[test]
    fn coach_exchange_is_stored_but_opens_no_conversation() {
        let mut s = DMStateInner::default();
        apply(&mut s, sent("q", "[poker-coach]\nI am a beginner…", 10));
        apply(&mut s, received("r", "[coach] Call: top pair.", 12));
        // kept in storage, so the table can read the reply
        assert_eq!(s.messages.len(), 2);
        // but no conversation, no unread
        assert!(visible_conversations(&s).is_empty());
        assert_eq!(
            s.conversations
                .values()
                .map(|c| c.unread_count)
                .sum::<u32>(),
            0
        );
        assert!(thread_of(&s.messages, COACH, Some(COACH)).is_empty());
    }

    #[test]
    fn coach_exchange_leaves_a_real_conversation_untouched() {
        let mut s = DMStateInner::default();
        apply(&mut s, received("hi", "Hello from Jarvis", 5));
        apply(&mut s, sent("q", "[poker-coach]\nI am a beginner…", 10));
        apply(&mut s, received("r", "  [coach] Fold.", 12));

        let list = visible_conversations(&s);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].last_message, "Hello from Jarvis");
        assert_eq!(list[0].last_timestamp, 5);
        assert_eq!(
            list[0].unread_count, 1,
            "the coach reply is not unread mail"
        );

        let thread = thread_of(&s.messages, COACH, Some(COACH));
        assert_eq!(thread.len(), 1);
        assert_eq!(thread[0].id, "hi");
        // all three are still stored
        assert_eq!(s.messages.len(), 3);
    }

    #[test]
    fn a_message_merely_mentioning_the_tag_is_ordinary_mail() {
        let mut s = DMStateInner::default();
        apply(&mut s, received("m", "what does [coach] mean?", 7));
        assert_eq!(visible_conversations(&s)[0].unread_count, 1);
        assert_eq!(thread_of(&s.messages, COACH, Some(COACH)).len(), 1);
    }

    #[test]
    fn the_tag_only_counts_from_the_configured_coach() {
        let stranger = "3333333333333333333333333333333333333333333333333333333333333333";
        // Same text, different counterparty: ordinary mail.
        let mut s = DMStateInner::default();
        let mut m = received("x", "[coach] hello, are you free tonight?", 7);
        m.sender_pubkey = stranger.into();
        let text = m.content.clone();
        apply_message(&mut s, m, stranger, &text, 7, false, Some(COACH));
        let list = visible_conversations(&s);
        assert_eq!(
            list.len(),
            1,
            "a stranger's tagged message opens a conversation"
        );
        assert_eq!(list[0].unread_count, 1, "and counts as unread");
        assert_eq!(
            thread_of(&s.messages, stranger, Some(COACH)).len(),
            1,
            "and shows in the thread"
        );
    }

    #[test]
    fn with_no_coach_configured_nothing_is_table_traffic() {
        assert!(!is_coach_exchange_with("[coach] Fold.", COACH, None));
        assert!(!is_coach_exchange_with("[poker-coach] hi", COACH, None));
        assert!(is_coach_exchange_with("[coach] Fold.", COACH, Some(COACH)));
        assert!(
            is_coach_exchange_with("[coach] Fold.", &COACH.to_uppercase(), Some(COACH)),
            "hex case is not significant"
        );
        assert!(
            !is_coach_exchange_with("plain text", COACH, Some(COACH)),
            "the coach's ordinary mail is mail"
        );
    }
}

#[cfg(test)]
mod extended_tests {
    //! Recipient normalisation, reactions, deletions and file messages.
    use super::*;
    use nostr_bbs_core::UnsignedEvent;

    const ME: &str = "a41654017f6850b13857d19d8ae0e3f88f1365600cab0321e8101c9e92682f7a";
    const YOU: &str = "b41654017f6850b13857d19d8ae0e3f88f1365600cab0321e8101c9e92682f7a";
    const OTHER: &str = "c41654017f6850b13857d19d8ae0e3f88f1365600cab0321e8101c9e92682f7a";
    const TARGET: &str = "d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0";

    fn npub_of(hex: &str) -> String {
        use nostr::ToBech32;
        nostr::PublicKey::parse(hex).unwrap().to_bech32().unwrap()
    }

    fn message(id: &str, from: &str, to: &str) -> DMMessage {
        DMMessage {
            id: id.into(),
            sender_pubkey: from.into(),
            recipient_pubkey: to.into(),
            content: "hello".into(),
            timestamp: 5,
            is_sent: from == ME,
            is_read: true,
        }
    }

    /// State holding one message from YOU, indexed under rumor id TARGET.
    fn state_with_target() -> DMStateInner {
        let mut s = DMStateInner::default();
        s.seen_ids.insert("wrap-1".into());
        s.messages.push(message("wrap-1", YOU, ME));
        index_rumor(&mut s, TARGET, "wrap-1");
        s
    }

    fn rumor(kind: u64, sender: &str, tags: Vec<Vec<&str>>, content: &str) -> UnsignedEvent {
        UnsignedEvent {
            pubkey: sender.into(),
            created_at: 1,
            kind,
            tags: tags
                .into_iter()
                .map(|t| t.into_iter().map(String::from).collect())
                .collect(),
            content: content.into(),
        }
    }

    #[test]
    fn mixed_case_hex_and_npub_recipients_normalise_to_the_same_lowercase_hex() {
        let upper = YOU.to_ascii_uppercase();
        assert_eq!(canonical_pubkey(&upper).unwrap(), YOU);
        assert_eq!(canonical_pubkey(YOU).unwrap(), YOU);
        assert_eq!(canonical_pubkey(&npub_of(YOU)).unwrap(), YOU);
        assert_eq!(canonical_pubkey(&format!("  {YOU}\n")).unwrap(), YOU);
    }

    #[test]
    fn the_p_tag_a_recipient_is_wrapped_with_is_the_lowercase_hex() {
        for spelling in [YOU.to_ascii_uppercase(), npub_of(YOU), YOU.to_string()] {
            let hex = canonical_pubkey(&spelling).unwrap();
            let r = rumors::chat_rumor(ME, &hex, "hi", None);
            assert!(r.tags.contains(&vec!["p".to_string(), YOU.to_string()]));
        }
    }

    #[test]
    fn a_malformed_recipient_is_refused() {
        for bad in ["", "zz", &"g".repeat(64), &"a".repeat(63), "npub1notvalid"] {
            assert!(canonical_pubkey(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_conversation_opened_by_npub_or_upper_case_finds_the_lowercase_thread() {
        let mut s = DMStateInner::default();
        s.messages.push(message("w", ME, YOU));
        for key in [npub_of(YOU), YOU.to_ascii_uppercase()] {
            assert_eq!(thread_of(&s.messages, &key, None).len(), 1);
            assert_eq!(canonical_or_lower(&key), YOU);
        }
    }

    #[test]
    fn a_reaction_attaches_to_the_message_it_names() {
        let mut s = state_with_target();
        let r = rumor(7, ME, vec![vec!["e", TARGET], vec!["p", YOU]], "🔥");
        apply_control_rumor(&mut s, "wrap-r", ME, "r1", &r);
        let extras = extras_of(&s);
        let on_msg = &extras.reactions["wrap-1"];
        assert_eq!(on_msg.len(), 1);
        assert_eq!(
            (on_msg[0].emoji.as_str(), on_msg[0].sender.as_str()),
            ("🔥", ME)
        );
        assert!(
            s.conversations.is_empty(),
            "a reaction opens no conversation"
        );
        assert_eq!(s.messages.len(), 1, "and is not a message");
    }

    #[test]
    fn a_restreamed_or_repeated_reaction_counts_once() {
        let mut s = state_with_target();
        let r = rumor(7, ME, vec![vec!["e", TARGET]], "+");
        apply_control_rumor(&mut s, "wrap-r", ME, "r1", &r);
        apply_control_rumor(&mut s, "wrap-r", ME, "r1", &r);
        apply_control_rumor(&mut s, "wrap-r2", ME, "r2", &r);
        assert_eq!(extras_of(&s).reactions["wrap-1"].len(), 1);
    }

    #[test]
    fn a_reaction_that_arrives_before_its_message_is_kept() {
        let mut s = DMStateInner::default();
        let r = rumor(7, YOU, vec![vec!["e", TARGET]], "+");
        apply_control_rumor(&mut s, "wrap-r", YOU, "r1", &r);
        assert!(
            extras_of(&s).reactions.is_empty(),
            "no message to show it on yet"
        );
        s.messages.push(message("wrap-1", YOU, ME));
        index_rumor(&mut s, TARGET, "wrap-1");
        assert_eq!(extras_of(&s).reactions["wrap-1"].len(), 1);
    }

    #[test]
    fn a_deletion_from_the_sender_removes_that_senders_own_message() {
        let mut s = state_with_target();
        let d = rumor(5, YOU, vec![vec!["e", TARGET]], "");
        apply_control_rumor(&mut s, "wrap-d", YOU, "d1", &d);
        assert!(s.messages.is_empty());
        assert!(
            s.seen_ids.contains("wrap-1"),
            "the wrap stays seen so a re-stream cannot resurrect it"
        );
    }

    #[test]
    fn a_deletion_from_anyone_else_removes_nothing() {
        let mut s = state_with_target();
        let d = rumor(5, OTHER, vec![vec!["e", TARGET]], "");
        apply_control_rumor(&mut s, "wrap-d", OTHER, "d1", &d);
        assert_eq!(s.messages.len(), 1);
        // ...and the stranger's tombstone does not hide YOU's message later.
        assert!(!is_tombstoned(&s, TARGET, YOU));
    }

    #[test]
    fn a_deletion_that_arrives_first_still_applies_to_a_later_message() {
        let mut s = DMStateInner::default();
        let d = rumor(5, YOU, vec![vec!["e", TARGET]], "");
        apply_control_rumor(&mut s, "wrap-d", YOU, "d1", &d);
        assert!(is_tombstoned(&s, TARGET, YOU));
        assert!(!is_tombstoned(&s, TARGET, OTHER));
    }

    #[test]
    fn deleting_a_message_drops_its_reactions_and_attachment() {
        let mut s = state_with_target();
        s.attachments.insert(
            "wrap-1".into(),
            Attachment {
                url: "https://f.example.com/a.png".into(),
                file_type: "image/png".into(),
            },
        );
        apply_control_rumor(
            &mut s,
            "wrap-r",
            ME,
            "r1",
            &rumor(7, ME, vec![vec!["e", TARGET]], "+"),
        );
        apply_control_rumor(
            &mut s,
            "wrap-d",
            YOU,
            "d1",
            &rumor(5, YOU, vec![vec!["e", TARGET]], ""),
        );
        let extras = extras_of(&s);
        assert!(extras.reactions.is_empty() && extras.attachments.is_empty());
    }

    #[test]
    fn a_senders_deletion_can_retract_their_own_reaction() {
        let mut s = state_with_target();
        apply_control_rumor(
            &mut s,
            "wrap-r",
            ME,
            "react-1",
            &rumor(7, ME, vec![vec!["e", TARGET]], "+"),
        );
        apply_deletion(&mut s, "wrap-d", ME, &["react-1".to_string()]);
        assert!(extras_of(&s).reactions.is_empty());
    }

    #[test]
    fn only_messages_we_sent_can_be_deleted_by_us() {
        let s = state_with_target();
        assert!(owns_rumor(&s, TARGET, YOU));
        assert!(!owns_rumor(&s, TARGET, ME));
        assert!(!owns_rumor(&s, "unknown", YOU));
    }

    #[test]
    fn nothing_extra_is_recorded_for_a_plain_chat_state() {
        let s = DMStateInner::default();
        assert_eq!(extras_of(&s), DMExtras::default());
    }

    #[test]
    fn a_file_message_renders_its_url_as_an_attachment_without_fetching() {
        let r = rumor(
            15,
            YOU,
            vec![vec!["file-type", "image/png"]],
            "https://f.example.com/a.png",
        );
        let Some(rumors::Incoming::File(att)) = rumors::classify(&r) else {
            panic!("expected a file message");
        };
        let mut s = DMStateInner::default();
        let mut m = message("wrap-f", YOU, ME);
        m.content = att.url.clone();
        s.attachments.insert(m.id.clone(), att);
        apply_message(&mut s, m, YOU, "[file]", 5, false, None);
        assert_eq!(s.conversations[YOU].last_message, "[file]");
        assert_eq!(extras_of(&s).attachments["wrap-f"].file_type, "image/png");
    }

    #[test]
    fn mixed_case_and_npub_recipients_wrap_to_the_same_lowercase_p_tag() {
        use nostr_bbs_core::gift_wrap::unwrap_gift_with_signer;
        use nostr_bbs_core::keys::generate_keypair;
        use nostr_bbs_core::signer::PrfSigner;

        let me = PrfSigner::new(generate_keypair().unwrap());
        let you = PrfSigner::new(generate_keypair().unwrap());
        let you_hex = you.public_key().to_string();
        let spellings = [
            you_hex.to_ascii_uppercase(),
            npub_of(&you_hex),
            you_hex.clone(),
        ];
        for spelling in spellings {
            let recipient = canonical_pubkey(&spelling).unwrap();
            let (to_you, to_me) =
                futures::executor::block_on(gift_wrap_pair_with_signer(&me, &recipient, "hello"))
                    .unwrap();
            for (wrap, reader) in [(&to_you, &you), (&to_me, &me)] {
                let got =
                    futures::executor::block_on(unwrap_gift_with_signer(wrap, reader)).unwrap();
                let p = got.rumor.tags.iter().find(|t| t[0] == "p").unwrap();
                assert_eq!(p[1], you_hex, "spelling {spelling}");
            }
        }
    }
}
