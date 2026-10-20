//! Where a recipient's gift wrap should be delivered (ADR-2027 decision 1).
//!
//! NIP-17 says a DM belongs on the relays the recipient named for it: kind
//! 10050 first, and failing that their NIP-65 kind 10002 list. This module
//! resolves that list. It is the only place that reads those events, and it
//! does it through the `nostr` crate's own extractors rather than parsing tags.
//!
//! [`resolve`] is pure (events in, [`Route`] out) so the precedence, the cap and
//! the URL hygiene are unit-tested on the host target. [`route_for`] is the
//! browser half: it asks OUR relay for the two events and caches the answer for
//! the session.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use nostr::nips::nip65::RelayMetadata;
use nostr::nips::{nip17, nip65};
use nostr::RelayUrl;
use nostr_bbs_core::NostrEvent;

use crate::relay::{EoseCallback, EventCallback, Filter, OneShot, RelayConnection};
use crate::zone_crypto::public_inbox::{live_fetch, INDEXERS};

/// Most foreign relays one wrap is sent to. A recipient (or an attacker who
/// wants our client to open sockets) controls the list, so it is bounded.
pub const MAX_FOREIGN_RELAYS: usize = 4;

/// NIP-17 "preferred DM relays" list.
pub const KIND_DM_RELAYS: u64 = 10050;

/// NIP-65 relay list metadata.
pub const KIND_RELAY_LIST: u64 = 10002;

/// How long to wait for our relay to answer a list lookup.
const LOOKUP_TIMEOUT_MS: i32 = 4_000;

/// Which list the route came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteSource {
    /// The recipient's kind 10050.
    DmRelays,
    /// The recipient's kind 10002 (read / inbox relays).
    RelayList,
    /// Neither exists: our relay only.
    Default,
}

/// The resolved delivery targets for one recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    /// Which list produced [`foreign`](Self::foreign).
    pub source: RouteSource,
    /// Relays other than ours, normalised, de-duplicated, at most
    /// [`MAX_FOREIGN_RELAYS`]. Empty means "our relay only".
    pub foreign: Vec<RelayUrl>,
}

impl Route {
    fn default_route() -> Self {
        Self {
            source: RouteSource::Default,
            foreign: Vec::new(),
        }
    }
}

/// The newest event of `kind` that `author` actually signed.
///
/// A relay answers a filter, but the filter is not a guarantee: only the
/// author's own list may steer where their mail goes.
pub fn newest_authored<'a>(
    events: &'a [NostrEvent],
    kind: u64,
    author: &str,
) -> Option<&'a NostrEvent> {
    events
        .iter()
        .filter(|e| {
            e.kind == kind
                && e.pubkey.eq_ignore_ascii_case(author)
                // The signature is what makes the list the author's: an
                // unsigned or forged one is not allowed to steer their mail.
                && nostr_bbs_core::verify_event_strict(e).is_ok()
        })
        .max_by_key(|e| e.created_at)
}

/// Relays named by a kind 10050, via `nostr`'s NIP-17 extractor.
fn dm_relays(event: &NostrEvent) -> Vec<RelayUrl> {
    match event.to_upstream() {
        Ok(ev) => nip17::extract_relay_list(&ev).cloned().collect(),
        Err(_) => Vec::new(),
    }
}

/// Inbox relays named by a kind 10002, via `nostr`'s NIP-65 extractor.
///
/// Mail for a user goes to where they READ, so an entry marked `write` is not a
/// delivery target; an unmarked entry counts for both directions.
fn inbox_relays(event: &NostrEvent) -> Vec<RelayUrl> {
    match event.to_upstream() {
        Ok(ev) => nip65::extract_relay_list(&ev)
            .filter(|(_, marker)| !matches!(marker, Some(RelayMetadata::Write)))
            .map(|(url, _)| url.clone())
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Whether `host` is a name or address that only means something on the
/// reader's own machine or network.
///
/// `RelayUrl::is_local_addr` is not enough: it passes `localhost`, `::1`,
/// link-local addresses (the cloud metadata endpoint, 169.254.169.254) and
/// `.local` names.
fn internal_host(host: &str) -> bool {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    let v4 = |a: Ipv4Addr| {
        let o = a.octets();
        a.is_private()
            || a.is_loopback()
            || a.is_link_local()
            || a.is_unspecified()
            || a.is_broadcast()
            || (o[0] == 100 && (64..128).contains(&o[1])) // CGNAT 100.64.0.0/10
    };
    let v6 = |a: Ipv6Addr| {
        let first = a.segments()[0];
        a.is_loopback()
            || a.is_unspecified()
            || (first & 0xfe00) == 0xfc00 // unique local fc00::/7
            || (first & 0xffc0) == 0xfe80 // link local fe80::/10
            || a.to_ipv4_mapped().is_some_and(v4)
    };
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    match bare.parse::<IpAddr>() {
        Ok(IpAddr::V4(a)) => v4(a),
        Ok(IpAddr::V6(a)) => v6(a),
        Err(_) => {
            let d = bare.trim_end_matches('.').to_ascii_lowercase();
            !d.contains('.')
                || ["localhost", "local", "internal", "lan", "home", "onion"]
                    .iter()
                    .any(|tld| d == *tld || d.ends_with(&format!(".{tld}")))
        }
    }
}

/// Whether we will open a socket to this URL from a browser page.
///
/// TLS only (a plain `ws://` socket is blocked from an https page anyway), and
/// never an internal address, a single-label name or an onion service: the list
/// is attacker-supplied, and a page that dials `wss://localhost` for a stranger
/// is a request-forgery primitive.
fn dialable(url: &RelayUrl) -> bool {
    url.as_str().starts_with("wss://")
        && !url.is_local_addr()
        && !url.is_onion()
        && url.host().is_some_and(|h| !internal_host(&h.to_string()))
}

/// Normalise, drop ours and unusable ones, de-duplicate, then cap.
///
/// Our own relay is removed BEFORE the cap so it cannot use up one of the four
/// slots.
fn finish(urls: Vec<RelayUrl>, own: Option<&RelayUrl>) -> Vec<RelayUrl> {
    let mut out: Vec<RelayUrl> = Vec::new();
    for url in urls {
        if Some(&url) == own || !dialable(&url) || out.contains(&url) {
            continue;
        }
        out.push(url);
        if out.len() == MAX_FOREIGN_RELAYS {
            break;
        }
    }
    out
}

/// Resolve the delivery route from whatever lists the relay returned.
///
/// Precedence: the recipient's newest kind 10050, else their newest kind 10002
/// inbox relays, else our relay alone. A list that exists but names no usable
/// relay counts as absent, so it falls through rather than stranding the
/// message. `own_url` is our relay, as configured.
pub fn resolve(own_url: &str, recipient: &str, events: &[NostrEvent]) -> Route {
    let own = RelayUrl::parse(own_url).ok();
    if let Some(list) = newest_authored(events, KIND_DM_RELAYS, recipient) {
        let foreign = finish(dm_relays(list), own.as_ref());
        if !foreign.is_empty() {
            return Route {
                source: RouteSource::DmRelays,
                foreign,
            };
        }
    }
    if let Some(list) = newest_authored(events, KIND_RELAY_LIST, recipient) {
        let foreign = finish(inbox_relays(list), own.as_ref());
        if !foreign.is_empty() {
            return Route {
                source: RouteSource::RelayList,
                foreign,
            };
        }
    }
    Route::default_route()
}

thread_local! {
    /// Resolved routes for this page session, keyed by lowercase recipient hex.
    static ROUTES: RefCell<HashMap<String, Route>> = RefCell::new(HashMap::new());
}

/// The cached route for `recipient`, if one was resolved this session.
fn cached(recipient: &str) -> Option<Route> {
    ROUTES.with(|c| c.borrow().get(recipient).cloned())
}

/// Resolve (and cache for the session) where `recipient`'s wraps should go.
///
/// Asks, concurrently and within [`LOOKUP_TIMEOUT_MS`]: the public indexers
/// (where an outsider, whom our relay refuses to hold any non-wrap event from,
/// publishes their lists) and OUR relay (a member's lists). Every candidate is
/// verified in [`resolve`]: signed, and authored by the recipient. If some
/// source does not finish in time nothing is cached and the best route found so
/// far is used, so a slow lookup is retried on the next send.
pub async fn route_for(relay: &RelayConnection, recipient: &str) -> Route {
    if let Some(hit) = cached(recipient) {
        return hit;
    }
    let events: Rc<RefCell<Vec<NostrEvent>>> = Rc::default();
    let done: Rc<OneShot<bool>> = OneShot::new();
    let outstanding = Rc::new(std::cell::Cell::new(1 + INDEXERS.len()));
    let finish = {
        let (done, outstanding) = (done.clone(), outstanding.clone());
        Rc::new(move || {
            outstanding.set(outstanding.get().saturating_sub(1));
            if outstanding.get() == 0 {
                done.fill(true);
            }
        })
    };

    // Our relay.
    let sink = events.clone();
    let on_event: EventCallback = Rc::new(move |ev: NostrEvent| sink.borrow_mut().push(ev));
    let fin = finish.clone();
    let on_eose: EoseCallback = Rc::new(move || fin());
    let filter = Filter {
        kinds: Some(vec![KIND_DM_RELAYS, KIND_RELAY_LIST]),
        authors: Some(vec![recipient.to_string()]),
        limit: Some(8),
        ..Default::default()
    };
    let sub_id = relay.subscribe(vec![filter], on_event, Some(on_eose));

    // The public indexers.
    for url in INDEXERS {
        let (sink, fin, author) = (events.clone(), finish.clone(), recipient.to_string());
        wasm_bindgen_futures::spawn_local(async move {
            if let Some(found) = live_fetch(url, &author).await {
                sink.borrow_mut().extend(found);
            }
            fin();
        });
    }

    let timeout = done.clone();
    crate::utils::set_timeout_once(move || timeout.fill(false), LOOKUP_TIMEOUT_MS);
    let complete = done.wait().await;
    relay.unsubscribe(&sub_id);

    let route = resolve(
        &crate::utils::relay_url::relay_url(),
        recipient,
        &events.borrow(),
    );
    if complete {
        ROUTES.with(|c| c.borrow_mut().insert(recipient.to_string(), route.clone()));
    }
    route
}

/// Public key (hex) of the deterministic test identity `seed`.
#[cfg(test)]
pub(crate) fn test_pubkey(seed: u8) -> String {
    let key = k256::schnorr::SigningKey::from_bytes(&[seed; 32]).unwrap();
    hex::encode(key.verifying_key().to_bytes())
}

/// An event of `kind` signed by test identity `seed`.
#[cfg(test)]
pub(crate) fn signed(kind: u64, seed: u8, at: u64, tags: Vec<Vec<String>>) -> NostrEvent {
    let key = k256::schnorr::SigningKey::from_bytes(&[seed; 32]).unwrap();
    nostr_bbs_core::sign_event_deterministic(
        nostr_bbs_core::UnsignedEvent {
            pubkey: test_pubkey(seed),
            created_at: at,
            kind,
            tags,
            content: String::new(),
        },
        &key,
    )
    .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dm::routing::{signed, test_pubkey};

    const OWN: &str = "wss://members-nostr-relay.solitary-paper-764d.workers.dev";
    const BOB: u8 = 7;
    const EVE: u8 = 9;

    fn list(kind: u64, author: u8, at: u64, tags: Vec<Vec<&str>>) -> NostrEvent {
        signed(
            kind,
            author,
            at,
            tags.into_iter()
                .map(|t| t.into_iter().map(String::from).collect())
                .collect(),
        )
    }

    fn dm(author: u8, at: u64, relays: &[&str]) -> NostrEvent {
        list(
            KIND_DM_RELAYS,
            author,
            at,
            relays.iter().map(|r| vec!["relay", *r]).collect(),
        )
    }

    fn urls(route: &Route) -> Vec<&str> {
        route.foreign.iter().map(|u| u.as_str()).collect()
    }

    #[test]
    fn dm_relays_beat_the_nip65_list_which_beats_the_default() {
        let nip65 = list(
            KIND_RELAY_LIST,
            BOB,
            10,
            vec![vec!["r", "wss://r65.example.com"]],
        );
        let both = [nip65.clone(), dm(BOB, 5, &["wss://r1050.example.com"])];
        let route = resolve(OWN, &test_pubkey(BOB), &both);
        assert_eq!(route.source, RouteSource::DmRelays);
        assert_eq!(urls(&route), ["wss://r1050.example.com"]);

        let route = resolve(OWN, &test_pubkey(BOB), &[nip65]);
        assert_eq!(route.source, RouteSource::RelayList);
        assert_eq!(urls(&route), ["wss://r65.example.com"]);

        let route = resolve(OWN, &test_pubkey(BOB), &[]);
        assert_eq!(route.source, RouteSource::Default);
        assert!(route.foreign.is_empty());
    }

    #[test]
    fn the_newest_list_wins_and_only_the_recipients_own_counts() {
        let events = [
            dm(BOB, 1, &["wss://old.example.com"]),
            dm(BOB, 9, &["wss://new.example.com"]),
            dm(EVE, 99, &["wss://evil.example.com"]),
        ];
        assert_eq!(
            urls(&resolve(OWN, &test_pubkey(BOB), &events)),
            ["wss://new.example.com"]
        );
    }

    #[test]
    fn foreign_relays_are_capped_at_four() {
        let many: Vec<String> = (0..9).map(|i| format!("wss://r{i}.example.com")).collect();
        let refs: Vec<&str> = many.iter().map(String::as_str).collect();
        let route = resolve(OWN, &test_pubkey(BOB), &[dm(BOB, 1, &refs)]);
        assert_eq!(route.foreign.len(), MAX_FOREIGN_RELAYS);
        assert_eq!(route.foreign[0].as_str(), "wss://r0.example.com");
    }

    #[test]
    fn our_own_relay_does_not_take_one_of_the_four_slots() {
        let mut relays = vec![OWN];
        let rest: Vec<String> = (0..4).map(|i| format!("wss://r{i}.example.com")).collect();
        relays.extend(rest.iter().map(String::as_str));
        let route = resolve(OWN, &test_pubkey(BOB), &[dm(BOB, 1, &relays)]);
        assert_eq!(route.foreign.len(), 4);
        assert!(urls(&route).iter().all(|u| !u.contains("workers.dev")));
    }

    #[test]
    fn urls_are_normalised_and_deduplicated() {
        let route = resolve(
            OWN,
            &test_pubkey(BOB),
            &[dm(
                BOB,
                1,
                &[
                    "wss://Relay.Example.com",
                    "wss://relay.example.com/",
                    "wss://relay.example.com",
                ],
            )],
        );
        assert_eq!(route.foreign.len(), 1);
    }

    #[test]
    fn our_relay_is_recognised_whatever_its_spelling() {
        let route = resolve(
            "wss://relay.example.com",
            &test_pubkey(BOB),
            &[dm(BOB, 1, &["wss://RELAY.example.com/"])],
        );
        assert_eq!(route.source, RouteSource::Default);
    }

    #[test]
    fn unsafe_or_unparseable_relays_are_dropped_and_the_list_falls_through() {
        let hostile = dm(
            BOB,
            1,
            &[
                "ws://plain.example.com",
                "wss://localhost",
                "wss://127.0.0.1:8080",
                "wss://192.168.1.5",
                "wss://abcdefghijklmnop.onion",
                "wss://[::1]",
                "wss://169.254.169.254",
                "wss://100.64.1.1",
                "wss://printer.local",
                "wss://intranet",
                "wss://[::ffff:10.0.0.1]",
                "not a url",
            ],
        );
        let nip65 = list(
            KIND_RELAY_LIST,
            BOB,
            1,
            vec![vec!["r", "wss://ok.example.com"]],
        );
        let route = resolve(OWN, &test_pubkey(BOB), &[hostile, nip65]);
        assert_eq!(route.source, RouteSource::RelayList);
        assert_eq!(urls(&route), ["wss://ok.example.com"]);
    }

    #[test]
    fn nip65_delivery_uses_read_and_unmarked_relays_not_write_only_ones() {
        let nip65 = list(
            KIND_RELAY_LIST,
            BOB,
            1,
            vec![
                vec!["r", "wss://write-only.example.com", "write"],
                vec!["r", "wss://reads.example.com", "read"],
                vec!["r", "wss://both.example.com"],
            ],
        );
        let route = resolve(OWN, &test_pubkey(BOB), &[nip65]);
        assert_eq!(
            urls(&route),
            ["wss://reads.example.com", "wss://both.example.com"]
        );
    }

    #[test]
    fn the_r_tag_is_not_read_for_a_10050() {
        let wrong = list(
            KIND_DM_RELAYS,
            BOB,
            1,
            vec![vec!["r", "wss://nip65-style.example.com"]],
        );
        assert_eq!(
            resolve(OWN, &test_pubkey(BOB), &[wrong]).source,
            RouteSource::Default
        );
    }

    #[test]
    fn an_unsigned_forged_or_foreign_authored_list_is_ignored() {
        let mut forged = dm(BOB, 5, &["wss://forged.example.com"]);
        forged.sig = "00".repeat(64);
        assert_eq!(
            resolve(OWN, &test_pubkey(BOB), &[forged]).source,
            RouteSource::Default
        );
        // Signed by EVE, claiming BOB's pubkey: the signature does not verify.
        let mut spoof = dm(EVE, 5, &["wss://spoof.example.com"]);
        spoof.pubkey = test_pubkey(BOB);
        assert_eq!(
            resolve(OWN, &test_pubkey(BOB), &[spoof]).source,
            RouteSource::Default
        );
        // Validly signed, but by someone else: not the recipient's list.
        let theirs = dm(EVE, 5, &["wss://eve.example.com"]);
        assert_eq!(
            resolve(OWN, &test_pubkey(BOB), &[theirs]).source,
            RouteSource::Default
        );
    }

    #[test]
    fn plain_ws_relays_are_never_dialled() {
        let ev = dm(BOB, 1, &["ws://plain.example.com"]);
        assert_eq!(
            resolve(OWN, &test_pubkey(BOB), &[ev]).source,
            RouteSource::Default
        );
    }

    #[test]
    fn an_outsider_with_lists_only_on_an_indexer_resolves_to_those_relays() {
        // Our relay holds nothing of theirs; the indexer returns both lists.
        let from_our_relay: Vec<NostrEvent> = Vec::new();
        let from_indexer = vec![
            list(
                KIND_RELAY_LIST,
                BOB,
                3,
                vec![vec!["r", "wss://r65.example.com"]],
            ),
            dm(BOB, 4, &["wss://inbox.example.com"]),
        ];
        let merged: Vec<NostrEvent> = from_our_relay.into_iter().chain(from_indexer).collect();
        let route = resolve(OWN, &test_pubkey(BOB), &merged);
        assert_eq!(route.source, RouteSource::DmRelays);
        assert_eq!(urls(&route), ["wss://inbox.example.com"]);
    }
}
