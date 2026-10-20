//! NIP-171 epoch tickets for zone keys (ADR-2028 decision 2).
//!
//! A `kind:1014` ticket is a **regular signed event**, signed by the zone's
//! group identity key, with exactly one `p` tag (the member), exactly one
//! `epoch` tag (a non-negative decimal) and the 32-byte lowercase-hex epoch
//! private key as content. It reaches the member inside a NIP-59 gift wrap
//! whose seal the group identity also signs, so the rumor's author is the
//! seal's signer.
//!
//! ## Why this does not use core's rumor wrap
//!
//! Core's `gift_wrap_rumor_with_signer` / `unwrap_gift_kind` carry an
//! `UnsignedEvent` and never a `sig`. A ticket's signature is what Phase 5
//! messages quote as `invitation_proof`, so it must survive the trip.
//! [`wrap_ticket`] and [`open_ticket`] therefore compose the same core
//! primitives (`Signer::nip44_encrypt`, a signed kind-13 seal,
//! `gift_wrap::wrap_seal`, `verify_event_strict`) around the whole signed
//! event, in the order `unwrap_any` uses. Nothing is hand-rolled and
//! `nostr-bbs-core` is unchanged.
//!
//! ## Trust
//!
//! A ticket is accepted only when its signer equals the group pubkey the
//! relay binds to exactly one zone ([`ZoneGroupBindings`]). No binding, or a
//! signer other than the bound one, is a refusal: the `zk` tag hint is never
//! enough on its own. The whole feature sits behind `ZONE_GROUPS_ENABLED`
//! ([`zone_groups_enabled`]).

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use nostr_bbs_core::signer::Signer;
use nostr_bbs_core::{verify_event_strict, NostrEvent, UnsignedEvent};

use super::ZoneKey;

/// Kind of an NIP-171 epoch ticket.
pub const KIND_EPOCH_TICKET: u64 = 1014;
/// `window.__ENV__` key of the zone-group switch. Absent means off.
#[cfg_attr(
    not(target_arch = "wasm32"),
    allow(dead_code, reason = "read by the wasm flag lookup")
)]
pub const ZONE_GROUPS_ENV: &str = "ZONE_GROUPS_ENABLED";

const SEAL_KIND: u64 = 13;

/// Whether `ZONE_GROUPS_ENABLED` is `"true"` in `window.__ENV__`.
#[cfg(target_arch = "wasm32")]
pub fn zone_groups_enabled() -> bool {
    let raw = web_sys::window()
        .and_then(|w| js_sys::Reflect::get(&w, &"__ENV__".into()).ok())
        .filter(|env| !env.is_undefined() && !env.is_null())
        .and_then(|env| js_sys::Reflect::get(&env, &ZONE_GROUPS_ENV.into()).ok())
        .and_then(|v| v.as_string());
    super::gate_value_enabled(raw.as_deref())
}

/// Native builds (the unit tests) have no `window`: the switch is off.
#[cfg(not(target_arch = "wasm32"))]
pub fn zone_groups_enabled() -> bool {
    false
}

/// Why a ticket was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TicketError {
    /// The event is not kind 1014.
    WrongKind(u64),
    /// The event id or signature does not verify.
    BadSignature,
    /// Not exactly one `p` tag with a 64-hex pubkey.
    BadMemberTag,
    /// Not exactly one `epoch` tag holding a plain non-negative decimal.
    BadEpochTag,
    /// The epoch does not fit the store's `u32`, or is the record-only epoch 0.
    EpochOutOfRange,
    /// Content is not 64 lowercase hex characters.
    BadContent,
    /// Content is hex but not a valid secp256k1 secret scalar.
    BadScalar,
    /// The ticket is addressed to someone else.
    NotForMe,
    /// The relay has not told us the zone-group bindings yet. Retry later.
    BindingsUnavailable,
    /// The signer is not bound to exactly one zone (none, or ambiguous).
    NoBinding,
    /// The signer differs from the zone's bound group pubkey.
    WrongSigner,
}

impl std::fmt::Display for TicketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::WrongKind(k) => return write!(f, "not an epoch ticket (kind {k})"),
            Self::BadSignature => "ticket id or signature does not verify",
            Self::BadMemberTag => "ticket needs exactly one valid p tag",
            Self::BadEpochTag => "ticket needs exactly one valid epoch tag",
            Self::EpochOutOfRange => "ticket epoch is outside the usable range",
            Self::BadContent => "ticket content is not 64 lowercase hex",
            Self::BadScalar => "ticket content is not a valid secret key",
            Self::NotForMe => "ticket is addressed to another member",
            Self::BindingsUnavailable => "zone-group bindings are not loaded yet",
            Self::NoBinding => "ticket signer is not bound to exactly one zone",
            Self::WrongSigner => "ticket signer is not the zone's bound group identity",
        };
        f.write_str(s)
    }
}

/// A validated epoch ticket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ticket {
    /// Group identity pubkey that signed it (hex).
    pub group: String,
    /// Member the ticket is addressed to (hex).
    pub member: String,
    /// Epoch number.
    pub epoch: u32,
    /// Epoch private key (64 lowercase hex).
    pub epoch_sk: String,
    /// The ticket's `created_at` (Phase 5 `invited_at`).
    pub created_at: u64,
    /// The ticket's event id.
    pub id: String,
    /// The ticket's signature (Phase 5 `invitation_proof`).
    pub sig: String,
}

fn is_lower_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Parse a plain decimal: digits only, no sign, no leading zeros.
fn parse_epoch(s: &str) -> Result<u32, TicketError> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0'))
    {
        return Err(TicketError::BadEpochTag);
    }
    s.parse::<u32>().map_err(|_| TicketError::EpochOutOfRange)
}

/// Build and sign a ticket with the group identity `group_signer`.
pub async fn build_ticket(
    group_signer: &dyn Signer,
    member: &str,
    epoch: u32,
    epoch_sk: &str,
    created_at: u64,
) -> Result<NostrEvent, String> {
    group_signer
        .sign_event(UnsignedEvent {
            pubkey: group_signer.public_key().to_string(),
            created_at,
            kind: KIND_EPOCH_TICKET,
            tags: vec![
                vec!["p".to_string(), member.to_string()],
                vec!["epoch".to_string(), epoch.to_string()],
            ],
            content: epoch_sk.to_string(),
        })
        .await
        .map_err(|e| e.to_string())
}

/// Validate a signed ticket event. Binding to a zone is a separate step
/// ([`accept_ticket`]).
pub fn parse_ticket(ev: &NostrEvent) -> Result<Ticket, TicketError> {
    if ev.kind != KIND_EPOCH_TICKET {
        return Err(TicketError::WrongKind(ev.kind));
    }
    verify_event_strict(ev).map_err(|_| TicketError::BadSignature)?;
    let mut p = ev
        .tags
        .iter()
        .filter(|t| t.first().is_some_and(|n| n == "p"));
    let member = match (p.next(), p.next()) {
        (Some(t), None) if t.len() == 2 && is_lower_hex64(&t[1]) => t[1].clone(),
        _ => return Err(TicketError::BadMemberTag),
    };
    let mut e = ev
        .tags
        .iter()
        .filter(|t| t.first().is_some_and(|n| n == "epoch"));
    let epoch = match (e.next(), e.next()) {
        (Some(t), None) if t.len() == 2 => parse_epoch(&t[1])?,
        _ => return Err(TicketError::BadEpochTag),
    };
    if !is_lower_hex64(&ev.content) {
        return Err(TicketError::BadContent);
    }
    let raw = hex::decode(&ev.content).map_err(|_| TicketError::BadContent)?;
    k256::SecretKey::from_slice(&raw).map_err(|_| TicketError::BadScalar)?;
    Ok(Ticket {
        group: ev.pubkey.clone(),
        member,
        epoch,
        epoch_sk: ev.content.clone(),
        created_at: ev.created_at,
        id: ev.id.clone(),
        sig: ev.sig.clone(),
    })
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "read by the Phase 5 sender and the key-plane owner flow"
    )
)]
/// Which ticket a member sends and reads with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selection {
    /// No ticket for this group.
    None,
    /// The current ticket.
    Current(Ticket),
    /// Two tickets at the top epoch carry different keys: do not send.
    Inconsistent {
        /// The disputed epoch.
        epoch: u32,
    },
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "read by the Phase 5 sender and the key-plane owner flow"
    )
)]
/// Pick the current ticket for `group`: highest epoch, then greatest
/// `created_at`, then lowest id. Different keys at the top epoch make it
/// [`Selection::Inconsistent`].
pub fn select_current(tickets: &[Ticket], group: &str) -> Selection {
    let mine = || tickets.iter().filter(|t| t.group == group);
    let Some(top) = mine().map(|t| t.epoch).max() else {
        return Selection::None;
    };
    let at_top: Vec<&Ticket> = mine().filter(|t| t.epoch == top).collect();
    if at_top.iter().any(|t| t.epoch_sk != at_top[0].epoch_sk) {
        return Selection::Inconsistent { epoch: top };
    }
    let best = at_top
        .into_iter()
        .max_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| b.id.cmp(&a.id))
        })
        .expect("top epoch has a ticket");
    Selection::Current(best.clone())
}

// -- Binding ------------------------------------------------------------------

/// The zone to group-identity bindings the relay serves in its NIP-11
/// `nostr_bbs.zone_groups` block (an object of zone id to group pubkey).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ZoneGroupBindings(HashMap<String, String>);

impl ZoneGroupBindings {
    #[cfg_attr(
        not(any(test, target_arch = "wasm32")),
        allow(dead_code, reason = "used by the wasm NIP-11 loader")
    )]
    /// Build from explicit `(zone, group)` pairs; malformed pubkeys are dropped.
    pub fn new<I: IntoIterator<Item = (String, String)>>(pairs: I) -> Self {
        Self(
            pairs
                .into_iter()
                .filter(|(z, g)| !z.is_empty() && is_lower_hex64(g))
                .collect(),
        )
    }

    #[cfg_attr(
        not(any(test, target_arch = "wasm32")),
        allow(dead_code, reason = "used by the wasm NIP-11 loader")
    )]
    /// Read the block out of a NIP-11 document. A missing block is empty.
    pub fn from_nip11(doc: &serde_json::Value) -> Self {
        let pairs = doc["nostr_bbs"]["zone_groups"]
            .as_object()
            .into_iter()
            .flatten()
            .filter_map(|(z, g)| Some((z.clone(), g.as_str()?.to_ascii_lowercase())));
        Self::new(pairs)
    }

    /// Group pubkey bound to `zone`.
    pub fn group_for_zone(&self, zone: &str) -> Option<&str> {
        self.0.get(zone).map(String::as_str)
    }

    /// Zone bound to `group`, `None` when none or more than one claims it.
    pub fn zone_for_group(&self, group: &str) -> Option<&str> {
        let mut it = self.0.iter().filter(|(_, g)| g.as_str() == group);
        match (it.next(), it.next()) {
            (Some((z, _)), None) => Some(z.as_str()),
            _ => None,
        }
    }
}

thread_local! {
    static BINDINGS: RefCell<Option<ZoneGroupBindings>> = const { RefCell::new(None) };
}

#[cfg_attr(
    not(any(test, target_arch = "wasm32")),
    allow(dead_code, reason = "used by the wasm NIP-11 loader")
)]
/// Store the bindings read from the relay's NIP-11 document.
pub fn set_zone_group_bindings(b: ZoneGroupBindings) {
    BINDINGS.with(|c| *c.borrow_mut() = Some(b));
}

/// The loaded bindings, or `None` before the relay has been asked.
pub fn loaded_bindings() -> Option<ZoneGroupBindings> {
    BINDINGS.with(|c| c.borrow().clone())
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "single-zone lookup for the Phase 5 sender; the reader uses the reverse lookup"
    )
)]
/// The group pubkey the relay binds to `zone`; `None` means "no binding"
/// (and every ticket for it is refused).
pub fn zone_group_binding(zone: &str) -> Option<String> {
    loaded_bindings()?.group_for_zone(zone).map(str::to_string)
}

/// Fetch the relay's NIP-11 document once and cache its bindings. Safe to call
/// repeatedly; later calls return at once when the cache is filled.
#[cfg(target_arch = "wasm32")]
pub async fn ensure_bindings_loaded() -> Result<(), String> {
    use wasm_bindgen::JsCast;
    use wasm_bindgen_futures::JsFuture;
    if loaded_bindings().is_some() {
        return Ok(());
    }
    let url = crate::utils::relay_url::relay_api_base();
    let headers = web_sys::Headers::new().map_err(|_| "headers")?;
    headers
        .set("Accept", "application/nostr+json")
        .map_err(|_| "headers")?;
    let init = web_sys::RequestInit::new();
    init.set_headers(&headers);
    let req = web_sys::Request::new_with_str_and_init(&url, &init).map_err(|_| "request")?;
    let win = web_sys::window().ok_or("no window")?;
    let resp: web_sys::Response = JsFuture::from(win.fetch_with_request(&req))
        .await
        .map_err(|_| "NIP-11 fetch failed")?
        .dyn_into()
        .map_err(|_| "NIP-11 response")?;
    if !resp.ok() {
        return Err(format!("NIP-11 HTTP {}", resp.status()));
    }
    let text = JsFuture::from(resp.text().map_err(|_| "NIP-11 body")?)
        .await
        .map_err(|_| "NIP-11 body")?
        .as_string()
        .ok_or("NIP-11 body")?;
    let doc: serde_json::Value = serde_json::from_str(&text).map_err(|_| "NIP-11 JSON")?;
    set_zone_group_bindings(ZoneGroupBindings::from_nip11(&doc));
    Ok(())
}

/// Native builds have no relay to ask; the bindings stay as set.
#[cfg(not(target_arch = "wasm32"))]
pub async fn ensure_bindings_loaded() -> Result<(), String> {
    Ok(())
}

/// Reader: validate a ticket and turn it into the store's [`ZoneKey`].
///
/// `bindings` is `None` while the relay document has not loaded, which is not
/// a refusal ([`TicketError::BindingsUnavailable`]: the caller leaves the wrap
/// unmarked and retries).
pub fn accept_ticket(
    ev: &NostrEvent,
    me: &str,
    bindings: Option<&ZoneGroupBindings>,
    now: u64,
) -> Result<ZoneKey, TicketError> {
    let t = parse_ticket(ev)?;
    if t.member != me {
        return Err(TicketError::NotForMe);
    }
    let bindings = bindings.ok_or(TicketError::BindingsUnavailable)?;
    let zone = bindings
        .zone_for_group(&t.group)
        .ok_or(TicketError::NoBinding)?;
    if bindings.group_for_zone(zone) != Some(t.group.as_str()) {
        return Err(TicketError::WrongSigner);
    }
    if t.epoch == 0 {
        // Genesis epoch 0 is record-only (ADR-2028 decision 6).
        return Err(TicketError::EpochOutOfRange);
    }
    let raw = hex::decode(&t.epoch_sk).map_err(|_| TicketError::BadContent)?;
    let raw: [u8; 32] = raw.try_into().map_err(|_| TicketError::BadContent)?;
    let pubkey = nostr_bbs_core::keys::pubkey_hex(&raw).map_err(|_| TicketError::BadScalar)?;
    Ok(ZoneKey {
        zone: zone.to_string(),
        epoch: t.epoch,
        secret: t.epoch_sk,
        pubkey,
        group: Some(t.group.clone()),
        granted_by: t.group,
        received_at: now,
    })
}

// -- Wire ---------------------------------------------------------------------

/// Gift-wrap a signed ticket to `recipient_key` (the member's identity or
/// inbox key). The seal is signed by `group_signer`, which must be the
/// ticket's signer.
pub async fn wrap_ticket(
    group_signer: &dyn Signer,
    recipient_key: &str,
    ticket: &NostrEvent,
    now: u64,
) -> Result<NostrEvent, String> {
    if ticket.kind != KIND_EPOCH_TICKET || ticket.pubkey != group_signer.public_key() {
        return Err("ticket is not signed by this group identity".into());
    }
    let json = serde_json::to_string(ticket).map_err(|e| e.to_string())?;
    let sealed = group_signer
        .nip44_encrypt(recipient_key, &json)
        .await
        .map_err(|e| e.to_string())?;
    let seal = group_signer
        .sign_event(UnsignedEvent {
            pubkey: group_signer.public_key().to_string(),
            created_at: super::seal_timestamp(now),
            kind: SEAL_KIND,
            tags: vec![],
            content: sealed,
        })
        .await
        .map_err(|e| e.to_string())?;
    nostr_bbs_core::gift_wrap::wrap_seal(&seal, recipient_key).map_err(|e| e.to_string())
}

async fn open_with(wrap: &NostrEvent, signer: &dyn Signer) -> Result<NostrEvent, String> {
    if wrap.kind != nostr_bbs_core::gift_wrap::KIND_GIFT_WRAP {
        return Err("not a gift wrap".into());
    }
    verify_event_strict(wrap).map_err(|_| "gift wrap id or signature does not verify")?;
    let seal_json = signer
        .nip44_decrypt(&wrap.pubkey, &wrap.content)
        .await
        .map_err(|_| "gift wrap layer does not decrypt")?;
    let seal: NostrEvent = serde_json::from_str(&seal_json).map_err(|_| "seal JSON malformed")?;
    if seal.kind != SEAL_KIND {
        return Err("not a seal".into());
    }
    verify_event_strict(&seal).map_err(|_| "seal id or signature does not verify")?;
    let inner = signer
        .nip44_decrypt(&seal.pubkey, &seal.content)
        .await
        .map_err(|_| "seal layer does not decrypt")?;
    let ticket: NostrEvent =
        serde_json::from_str(&inner).map_err(|_| "ticket is not a signed event")?;
    if ticket.kind != KIND_EPOCH_TICKET {
        return Err(format!("not an epoch ticket (kind {})", ticket.kind));
    }
    if ticket.pubkey != seal.pubkey {
        return Err("ticket author does not match seal author".into());
    }
    verify_event_strict(&ticket).map_err(|_| "ticket id or signature does not verify")?;
    Ok(ticket)
}

/// Open a gift wrap that carries a signed ticket, with the inbox key first
/// (when held) and then the identity. Errors are fixed strings.
pub async fn open_ticket(
    wrap: &NostrEvent,
    inbox: Option<&dyn Signer>,
    identity: &dyn Signer,
) -> Result<NostrEvent, String> {
    if let Some(inbox) = inbox {
        if let Ok(t) = open_with(wrap, inbox).await {
            return Ok(t);
        }
    }
    open_with(wrap, identity).await
}

/// What the wrap reader does with a rumor of a given kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// A 21453 zone-key grant: the existing admin-sealed path.
    Grant,
    /// A 1014 epoch ticket: [`open_ticket`] and [`accept_ticket`].
    Ticket,
    /// Anything else, or a 1014 with `ZONE_GROUPS_ENABLED` off: mark the wrap
    /// processed and move on, exactly as before tickets existed.
    Ignore,
}

/// Decide the path for a rumor `kind`. A 21453 grant is read whatever the flag
/// says; a 1014 is read only with `groups_enabled`.
pub fn route(kind: u64, groups_enabled: bool) -> Route {
    if kind == super::KIND_ZONE_KEY_GRANT {
        Route::Grant
    } else if kind == KIND_EPOCH_TICKET && groups_enabled {
        Route::Ticket
    } else {
        Route::Ignore
    }
}

/// What to do with a wrap that carried a ticket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TicketVerdict {
    /// Store this key.
    Accept(Box<ZoneKey>),
    /// Not decidable yet (bindings not loaded): leave the wrap unmarked.
    Retry,
    /// Final refusal, with the reason: mark the wrap processed.
    Refuse(String),
}

/// Turn the result of [`open_ticket`] into a verdict.
pub fn ticket_verdict(
    opened: Result<NostrEvent, String>,
    me: &str,
    bindings: Option<&ZoneGroupBindings>,
    now: u64,
) -> TicketVerdict {
    match opened {
        Err(e) => TicketVerdict::Refuse(e),
        Ok(ev) => match accept_ticket(&ev, me, bindings, now) {
            Ok(k) => TicketVerdict::Accept(Box::new(k)),
            // Transient: the binding set may be incomplete (not yet loaded, a
            // stale NIP-11 cache, or a Hidden zone the relay omits from NIP-11
            // and delivers a binding for only through owner tooling). Leave the
            // wrap unmarked so it is re-examined rather than lost forever
            // (ADR-2028, Phase 4 review finding 4).
            Err(TicketError::BindingsUnavailable | TicketError::NoBinding) => TicketVerdict::Retry,
            Err(e) => TicketVerdict::Refuse(e.to_string()),
        },
    }
}

/// The group identity signers this browser holds, registered by the code that
/// loads a zone's recovery master. A zone with none registered is issued
/// 21453 grants as before.
#[derive(Debug, Clone, Copy, Default)]
pub struct HeldGroupIdentities;

thread_local! {
    static HELD: RefCell<HashMap<String, Rc<dyn Signer>>> = RefCell::new(HashMap::new());
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "hook awaiting the owner flow that loads a zone's recovery master (no caller yet)"
    )
)]
/// Register (or replace) the group identity signer held for `zone`.
pub fn register_group_identity(zone: &str, signer: Rc<dyn Signer>) {
    HELD.with(|h| h.borrow_mut().insert(zone.to_string(), signer));
}

impl GroupIdentities for HeldGroupIdentities {
    fn group_identity_for(&self, zone: &str) -> Option<Rc<dyn Signer>> {
        HELD.with(|h| h.borrow().get(zone).cloned())
    }
}

// -- Issuer -------------------------------------------------------------------

/// Where the issuer finds the group identity signers this browser holds.
pub trait GroupIdentities {
    /// The group identity signer for `zone`, when this browser holds it.
    fn group_identity_for(&self, zone: &str) -> Option<Rc<dyn Signer>>;
}

/// Build the ticket wrap for one grant, or `None` when the zone has no group
/// binding or this browser does not hold that identity (the caller then sends
/// the 21453 grant as before).
///
/// `member` is the ticket's `p` tag; `target` is where the wrap goes (the
/// member's inbox key or identity).
pub async fn issue_ticket_wrap(
    ids: &dyn GroupIdentities,
    bindings: Option<&ZoneGroupBindings>,
    key: &ZoneKey,
    member: &str,
    target: &str,
    now: u64,
) -> Option<Result<NostrEvent, String>> {
    let group = bindings?.group_for_zone(&key.zone)?;
    let signer = ids.group_identity_for(&key.zone)?;
    if signer.public_key() != group {
        return None;
    }
    let ticket = match build_ticket(&*signer, member, key.epoch, &key.secret, now).await {
        Ok(t) => t,
        Err(e) => return Some(Err(e)),
    };
    Some(wrap_ticket(&*signer, target, &ticket, now).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr_bbs_core::keys::generate_keypair;
    use nostr_bbs_core::signer::PrfSigner;

    fn signer() -> PrfSigner {
        PrfSigner::new(generate_keypair().unwrap())
    }

    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        let mut f = std::pin::pin!(f);
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        loop {
            if let std::task::Poll::Ready(v) = f.as_mut().poll(&mut cx) {
                return v;
            }
        }
    }

    fn epoch_key() -> (String, String) {
        let kp = generate_keypair().unwrap();
        let sk = hex::encode(kp.secret.as_bytes());
        let pk = nostr_bbs_core::keys::pubkey_hex(kp.secret.as_bytes()).unwrap();
        (sk, pk)
    }

    fn signed(g: &PrfSigner, tags: Vec<Vec<String>>, content: &str, at: u64) -> NostrEvent {
        block_on(g.sign_event(UnsignedEvent {
            pubkey: g.public_key().to_string(),
            created_at: at,
            kind: KIND_EPOCH_TICKET,
            tags,
            content: content.to_string(),
        }))
        .unwrap()
    }

    fn tag(n: &str, v: &str) -> Vec<String> {
        vec![n.to_string(), v.to_string()]
    }

    fn bindings(zone: &str, group: &str) -> ZoneGroupBindings {
        ZoneGroupBindings::new([(zone.to_string(), group.to_string())])
    }

    #[test]
    fn build_and_parse_round_trip_keeps_sig_and_created_at() {
        let (g, m) = (signer(), signer());
        let (sk, _) = epoch_key();
        let ev = block_on(build_ticket(&g, m.public_key(), 3, &sk, 1234)).unwrap();
        let t = parse_ticket(&ev).unwrap();
        assert_eq!(t.group, g.public_key());
        assert_eq!(t.member, m.public_key());
        assert_eq!((t.epoch, t.created_at), (3, 1234));
        assert_eq!(t.epoch_sk, sk);
        assert_eq!(
            (t.id.as_str(), t.sig.as_str()),
            (ev.id.as_str(), ev.sig.as_str())
        );
    }

    #[test]
    fn every_must_violation_is_refused() {
        let (g, m) = (signer(), signer());
        let mk = m.public_key();
        let (sk, _) = epoch_key();
        let p = || tag("p", mk);
        let e = || tag("epoch", "2");
        let bad = |tags: Vec<Vec<String>>, content: &str| {
            parse_ticket(&signed(&g, tags, content, 1)).unwrap_err()
        };
        assert_eq!(bad(vec![p(), p(), e()], &sk), TicketError::BadMemberTag);
        assert_eq!(bad(vec![e()], &sk), TicketError::BadMemberTag);
        assert_eq!(bad(vec![p()], &sk), TicketError::BadEpochTag);
        assert_eq!(bad(vec![p(), e(), e()], &sk), TicketError::BadEpochTag);
        for v in ["-1", "+1", "01", "1.0", "", "0x1", " 1"] {
            assert_eq!(
                bad(vec![p(), tag("epoch", v)], &sk),
                TicketError::BadEpochTag,
                "{v}"
            );
        }
        assert_eq!(
            bad(vec![p(), tag("epoch", "4294967296")], &sk),
            TicketError::EpochOutOfRange
        );
        assert_eq!(bad(vec![p(), e()], "zz"), TicketError::BadContent);
        assert_eq!(
            bad(vec![p(), e()], &sk.to_uppercase()),
            TicketError::BadContent
        );
        assert_eq!(bad(vec![p(), e()], &sk[..62]), TicketError::BadContent);
        // Zero and the group order are not valid scalars.
        assert_eq!(bad(vec![p(), e()], &"0".repeat(64)), TicketError::BadScalar);
        assert_eq!(bad(vec![p(), e()], &"f".repeat(64)), TicketError::BadScalar);
        // Wrong kind and a broken signature.
        let mut ev = signed(&g, vec![p(), e()], &sk, 1);
        ev.kind = 1;
        assert_eq!(parse_ticket(&ev).unwrap_err(), TicketError::WrongKind(1));
        let mut ev = signed(&g, vec![p(), e()], &sk, 1);
        ev.content = epoch_key().0;
        assert_eq!(parse_ticket(&ev).unwrap_err(), TicketError::BadSignature);
    }

    fn tk(group: &str, epoch: u32, sk: &str, at: u64, id: &str) -> Ticket {
        Ticket {
            group: group.into(),
            member: "m".into(),
            epoch,
            epoch_sk: sk.into(),
            created_at: at,
            id: id.into(),
            sig: String::new(),
        }
    }

    #[test]
    fn select_current_orders_by_epoch_then_created_at_then_lowest_id() {
        assert_eq!(select_current(&[], "g"), Selection::None);
        assert_eq!(
            select_current(&[tk("h", 9, "a", 1, "x")], "g"),
            Selection::None
        );
        let v = [
            tk("g", 1, "a", 99, "a1"),
            tk("g", 2, "b", 5, "b9"),
            tk("g", 2, "b", 7, "b8"),
            tk("g", 2, "b", 7, "b3"),
            tk("h", 8, "z", 1, "zz"),
        ];
        assert_eq!(select_current(&v, "g"), Selection::Current(v[3].clone()));
        let v = [tk("g", 1, "a", 99, "a1"), tk("g", 2, "b", 5, "b9")];
        assert_eq!(select_current(&v, "g"), Selection::Current(v[1].clone()));
    }

    #[test]
    fn different_keys_at_the_top_epoch_are_inconsistent() {
        let v = [
            tk("g", 2, "b", 5, "i1"),
            tk("g", 2, "c", 6, "i2"),
            tk("g", 1, "a", 1, "i0"),
        ];
        assert_eq!(
            select_current(&v, "g"),
            Selection::Inconsistent { epoch: 2 }
        );
        // A disagreement below the top epoch does not block sending.
        let v = [
            tk("g", 2, "b", 5, "i1"),
            tk("g", 1, "a", 1, "i0"),
            tk("g", 1, "z", 1, "i9"),
        ];
        assert!(matches!(select_current(&v, "g"), Selection::Current(_)));
    }

    #[test]
    fn accept_requires_the_bound_signer_and_never_a_hint() {
        let (g, m, other) = (signer(), signer(), signer());
        let (sk, pk) = epoch_key();
        let ev = block_on(build_ticket(&g, m.public_key(), 4, &sk, 10)).unwrap();
        let me = m.public_key();
        let good = bindings("zone-a", g.public_key());
        let key = accept_ticket(&ev, me, Some(&good), 77).unwrap();
        assert_eq!(
            (key.zone.as_str(), key.epoch, key.secret.as_str()),
            ("zone-a", 4, sk.as_str())
        );
        assert_eq!(
            (key.pubkey.as_str(), key.granted_by.as_str()),
            (pk.as_str(), g.public_key())
        );
        assert_eq!(key.received_at, 77);
        // Bound to another group: the signer is unbound.
        let wrong = bindings("zone-a", other.public_key());
        assert_eq!(
            accept_ticket(&ev, me, Some(&wrong), 1).unwrap_err(),
            TicketError::NoBinding
        );
        // No binding at all.
        let none = ZoneGroupBindings::default();
        assert_eq!(
            accept_ticket(&ev, me, Some(&none), 1).unwrap_err(),
            TicketError::NoBinding
        );
        // Not loaded yet is retryable, not a verdict.
        assert_eq!(
            accept_ticket(&ev, me, None, 1).unwrap_err(),
            TicketError::BindingsUnavailable
        );
        // Someone else's ticket.
        assert_eq!(
            accept_ticket(&ev, other.public_key(), Some(&good), 1).unwrap_err(),
            TicketError::NotForMe
        );
        // Group bound to two zones is ambiguous: refuse, do not pick.
        let two = ZoneGroupBindings::new([
            ("zone-a".to_string(), g.public_key().to_string()),
            ("zone-b".to_string(), g.public_key().to_string()),
        ]);
        assert_eq!(
            accept_ticket(&ev, me, Some(&two), 1).unwrap_err(),
            TicketError::NoBinding
        );
        // Epoch 0 is record-only.
        let zero = block_on(build_ticket(&g, m.public_key(), 0, &sk, 10)).unwrap();
        assert_eq!(
            accept_ticket(&zero, me, Some(&good), 1).unwrap_err(),
            TicketError::EpochOutOfRange
        );
    }

    #[test]
    fn bindings_read_from_nip11_and_lookup_both_ways() {
        let g = "ab".repeat(32);
        let doc = serde_json::json!({"nostr_bbs": {"zone_groups": {"z1": g.to_uppercase(), "z2": "bad"}}});
        let b = ZoneGroupBindings::from_nip11(&doc);
        assert_eq!(b.group_for_zone("z1"), Some(g.as_str()));
        assert_eq!(b.group_for_zone("z2"), None);
        assert_eq!(b.zone_for_group(&g), Some("z1"));
        assert_eq!(
            ZoneGroupBindings::from_nip11(&serde_json::json!({})),
            ZoneGroupBindings::default()
        );
    }

    #[test]
    fn binding_cache_is_none_until_set() {
        assert_eq!(zone_group_binding("zq"), None);
        let g = "cd".repeat(32);
        set_zone_group_bindings(bindings("zq", &g));
        assert_eq!(zone_group_binding("zq"), Some(g));
        assert_eq!(zone_group_binding("other"), None);
    }

    #[test]
    fn wrap_open_round_trip_through_inbox_then_identity() {
        let (g, member, inbox) = (signer(), signer(), signer());
        let (sk, _) = epoch_key();
        let ev = block_on(build_ticket(&g, member.public_key(), 2, &sk, 50)).unwrap();
        let to_inbox = block_on(wrap_ticket(&g, inbox.public_key(), &ev, 50)).unwrap();
        let to_id = block_on(wrap_ticket(&g, member.public_key(), &ev, 50)).unwrap();
        for w in [&to_inbox, &to_id] {
            let got = block_on(open_ticket(w, Some(&inbox), &member)).unwrap();
            assert_eq!(
                (got.sig.as_str(), got.id.as_str()),
                (ev.sig.as_str(), ev.id.as_str())
            );
            assert!(parse_ticket(&got).is_ok());
        }
        assert!(block_on(open_ticket(&to_inbox, None, &member)).is_err());
        // The group cannot wrap someone else's ticket.
        let foreign = block_on(build_ticket(&signer(), member.public_key(), 2, &sk, 1)).unwrap();
        assert!(block_on(wrap_ticket(&g, member.public_key(), &foreign, 1)).is_err());
    }

    #[test]
    fn open_refuses_a_ticket_sealed_by_another_key() {
        // Ticket signed by the group, but the seal is signed by an impostor.
        let (g, imp, member) = (signer(), signer(), signer());
        let (sk, _) = epoch_key();
        let ev = block_on(build_ticket(&g, member.public_key(), 2, &sk, 50)).unwrap();
        let json = serde_json::to_string(&ev).unwrap();
        let sealed = block_on(imp.nip44_encrypt(member.public_key(), &json)).unwrap();
        let seal = block_on(imp.sign_event(UnsignedEvent {
            pubkey: imp.public_key().to_string(),
            created_at: 1,
            kind: SEAL_KIND,
            tags: vec![],
            content: sealed,
        }))
        .unwrap();
        let wrap = nostr_bbs_core::gift_wrap::wrap_seal(&seal, member.public_key()).unwrap();
        assert_eq!(
            block_on(open_ticket(&wrap, None, &member)).unwrap_err(),
            "ticket author does not match seal author"
        );
    }

    struct Ids(Vec<(String, Rc<PrfSigner>)>);
    impl GroupIdentities for Ids {
        fn group_identity_for(&self, zone: &str) -> Option<Rc<dyn Signer>> {
            self.0
                .iter()
                .find(|(z, _)| z == zone)
                .map(|(_, s)| s.clone() as Rc<dyn Signer>)
        }
    }

    fn zone_key(zone: &str) -> ZoneKey {
        let (sk, pk) = epoch_key();
        ZoneKey {
            zone: zone.into(),
            epoch: 5,
            secret: sk,
            pubkey: pk,
            granted_by: "adm".into(),
            received_at: 1,
            group: None,
        }
    }

    #[test]
    fn issuer_emits_a_ticket_only_with_binding_and_identity() {
        let (g, member) = (Rc::new(signer()), signer());
        let ids = Ids(vec![("z".into(), g.clone())]);
        let key = zone_key("z");
        let b = bindings("z", g.public_key());
        let go = |ids: &Ids, b: Option<&ZoneGroupBindings>, key: &ZoneKey| {
            block_on(issue_ticket_wrap(
                ids,
                b,
                key,
                member.public_key(),
                member.public_key(),
                9,
            ))
        };
        let wrap = go(&ids, Some(&b), &key).unwrap().unwrap();
        let ev = block_on(open_ticket(&wrap, None, &member)).unwrap();
        let got = accept_ticket(&ev, member.public_key(), Some(&b), 1).unwrap();
        assert_eq!(
            (got.zone.as_str(), got.epoch, got.secret.as_str()),
            ("z", 5, key.secret.as_str())
        );
        // No binding, no binding loaded, no identity held, identity not the bound one: fall back.
        assert!(go(&ids, Some(&ZoneGroupBindings::default()), &key).is_none());
        assert!(go(&ids, None, &key).is_none());
        assert!(go(&Ids(vec![]), Some(&b), &key).is_none());
        let moved = bindings("z", &"ee".repeat(32));
        assert!(go(&ids, Some(&moved), &key).is_none());
        assert!(go(&ids, Some(&b), &zone_key("other")).is_none());
    }

    #[test]
    fn flag_is_off_natively() {
        assert!(!zone_groups_enabled());
    }

    #[test]
    fn routing_keeps_21453_and_gates_1014_on_the_flag() {
        assert_eq!(route(21453, false), Route::Grant);
        assert_eq!(route(21453, true), Route::Grant);
        assert_eq!(route(1014, true), Route::Ticket);
        assert_eq!(route(1014, false), Route::Ignore);
        assert_eq!(route(14, true), Route::Ignore);
    }

    #[test]
    fn wrap_reader_accepts_a_1014_and_still_opens_a_21453() {
        let (g, admin, member) = (signer(), signer(), signer());
        let (sk, _) = epoch_key();
        let b = bindings("z", g.public_key());
        // 1014: rumor-kind peek (the existing unwrap) routes it, open + verdict accept it.
        let ev = block_on(build_ticket(&g, member.public_key(), 2, &sk, 5)).unwrap();
        let wrap = block_on(wrap_ticket(&g, member.public_key(), &ev, 5)).unwrap();
        let (sealer, rumor) = block_on(super::super::inbox_key::unwrap_inbox_then_identity(
            &wrap, None, &member,
        ))
        .unwrap();
        assert_eq!(
            (sealer.as_str(), route(rumor.kind, true)),
            (g.public_key(), Route::Ticket)
        );
        let opened = block_on(open_ticket(&wrap, None, &member));
        match ticket_verdict(opened.clone(), member.public_key(), Some(&b), 9) {
            TicketVerdict::Accept(k) => assert_eq!((k.zone.as_str(), k.epoch), ("z", 2)),
            other => panic!("{other:?}"),
        }
        assert_eq!(
            ticket_verdict(opened.clone(), member.public_key(), None, 9),
            TicketVerdict::Retry
        );
        // An empty (or stale) binding set is transient, not final: the zone's
        // binding may simply not be loaded yet, or be a Hidden zone the relay
        // omits from NIP-11. Retry, so the ticket is not lost (finding 4).
        assert_eq!(
            ticket_verdict(
                opened,
                member.public_key(),
                Some(&ZoneGroupBindings::default()),
                9
            ),
            TicketVerdict::Retry
        );
        // 21453 still unwraps and routes to the grant path.
        let key = zone_key("z");
        let grant = block_on(super::super::build_grant_wrap(
            &admin,
            member.public_key(),
            &key,
            5,
        ))
        .unwrap();
        let (_, rumor) = block_on(super::super::inbox_key::unwrap_inbox_then_identity(
            &grant, None, &member,
        ))
        .unwrap();
        assert_eq!(route(rumor.kind, false), Route::Grant);
        assert!(super::super::validate_grant(&rumor, admin.public_key(), true, 1).is_ok());
    }

    #[test]
    fn held_identities_feed_the_issuer() {
        let g = Rc::new(signer());
        let pk = g.public_key().to_string();
        assert!(HeldGroupIdentities.group_identity_for("held-z").is_none());
        register_group_identity("held-z", g);
        assert_eq!(
            HeldGroupIdentities
                .group_identity_for("held-z")
                .unwrap()
                .public_key(),
            pk
        );
    }
}
