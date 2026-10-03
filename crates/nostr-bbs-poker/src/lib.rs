//! Heads-up poker for the nostr-bbs forum: the engine, the house bots, the
//! fair deal, the settlement rules, the hand record, the table protocol and
//! replay verification — pure Rust, no I/O, built for `wasm32` and native
//! alike.
//!
//! # What is here
//!
//! | Module | Does | Port of |
//! |---|---|---|
//! | [`engine`] | Cards, the seeded shuffle, the evaluator, the hold'em hand state machine, seat views | Libre Poker `poker.js` |
//! | [`bots`] | The house characters and their decisions | Libre Poker `bots.js` |
//! | [`fair`] | Two-party committed shuffle seed and the bot's per-step seed | — |
//! | [`rules`] | Stakes, settlement, the `hand:<root>` memo, RFC 8785 roots, the HAND.md record types | forum client `wallet::poker` |
//! | [`record`] | An engine hand → a HAND.md record | — |
//! | [`protocol`] | The member ↔ house messages | — |
//! | [`verify`] | Replay a finished hand from its seed and check the house played by the book | — |
//!
//! # The table, in one paragraph
//!
//! The house seat (the *citizen*, a service holding its own Nostr key)
//! commits to a secret; the member (the *hero*, in the forum client) answers
//! with a nonce; the seed is the hash of both ([`fair::seed_of`]). The
//! citizen deals and keeps the whole hand; the hero only ever receives their
//! own [`engine::SeatView`], so the house's hole cards never reach the
//! browser. Each hero turn travels as an [`engine::Action`]; the house seat
//! decides with [`bots::decide`] under [`fair::bot_seed`]. When the hand
//! ends the citizen reveals the secret and sends the [`rules::HandRecord`];
//! the hero replays it ([`verify::verify`]) and the loser pays the winner
//! one transfer of the hero's stack delta ([`rules::settlement`]) with the
//! memo [`rules::hand_memo`]. The chain is the ledger.
//!
//! # Fidelity
//!
//! The engine and the bots are ports of AGPL-3.0 JavaScript by the Libre
//! Poker project (<https://github.com/libre-poker/engine>, commit
//! `564d4c3f1ab069589b4c5d82f4e5db35a699f41c`). `tests/differential.rs`
//! replays 160 recorded hands (378 decisions, limit and no-limit, all-ins,
//! side pots) and 400 evaluations and requires the same JSON the JavaScript
//! produced, so a browser running the original and a service running this
//! crate agree on every state.
//!
//! # Example
//!
//! ```
//! use nostr_bbs_poker::engine::{act, legal, new_hand, seat_view, Action, HandConfig, SeatConfig};
//!
//! let cfg = HandConfig {
//!     seats: vec![
//!         SeatConfig { name: "You".into(), stack: 2000 },
//!         SeatConfig { name: "House".into(), stack: 2000 },
//!     ],
//!     button: 0,
//!     sb: 10,
//!     bb: 20,
//!     ante: 0,
//!     seed_hex: "ab".repeat(32),
//!     limit: true,
//! };
//! let h = new_hand(&cfg).unwrap();
//! let l = legal(&h).unwrap();
//! assert_eq!(l.seat, 0); // heads-up: the button posts the small blind and acts first
//! let h = act(&h, &Action { seat: 0, action: "fold".into(), amount: None }).unwrap();
//! assert!(!h.in_play());
//! assert!(seat_view(&h, 0).seats[1].hole.is_none()); // no showdown: the house's cards stay hidden
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod bots;
pub mod engine;
pub mod fair;
pub mod protocol;
pub mod record;
pub mod rules;
pub mod verify;
