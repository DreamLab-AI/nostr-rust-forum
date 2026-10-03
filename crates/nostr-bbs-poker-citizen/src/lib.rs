//! `nostr-bbs-poker-citizen` — the house seat of the forum's poker table.
//!
//! A member's browser never sees the house's cards: the house holds the
//! whole hand and sends the member only their own seat view, over NIP-59
//! gift wraps of kind 20779 on the forum's relay. The deal is committed by
//! both sides ([`nostr_bbs_poker::fair`]); the house plays
//! [`nostr_bbs_poker::bots::decide`] under the derived per-step seed, so
//! the member can replay the revealed hand and check every house action.
//! Each finished hand owes one transfer of the hero's stack delta,
//! settled in the house seat's chain asset — DREAM on `sidestr:dreamlab`,
//! BLAKES7 on `sidestr:dreamlab-txbt4`, one chain per instance
//! ([`chain::select`]) — with the memo `hand:<root>`
//! ([`nostr_bbs_poker::rules`]): the member signs theirs in the browser;
//! the house signs its own with the key it holds. The chain is the ledger;
//! the house keeps a small book ([`ledger`]) of what is not yet on it.
//!
//! | Module | Does |
//! |---|---|
//! | [`table`] | The state machine: messages in, messages and effects out; every money rule |
//! | [`ledger`] | What members owe, what the house owes, what it paid today; saved as JSON |
//! | [`chain`] | The two chain locks; replay the producer's blocks, read asset balances and `hand:` payments, build payouts |
//! | [`coach`] | The practice table's coach: the request, the question to the model, the reply (binary `nostr-bbs-poker-coach`) |
//! | [`net`] | One authenticated connection to the forum relay (native only), shared by both binaries |
//!
//! The binary (native only) joins them to a relay, a producer and a clock.
//! Run it with `--help`; the key file is never a flag's value. A second
//! binary, `nostr-bbs-poker-coach`, serves the practice table's coach from
//! its own key: it holds no funds and deals nothing.
//!
//! The house refuses to deal while the member owes for a hand the chain has
//! not shown paid (a member's own report of a transfer buys a grace
//! period), pays what it owes as soon as its coins allow, and stops paying
//! out at a daily cap. Coins on these chains carry no value.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod chain;
pub mod coach;
pub mod ledger;
#[cfg(not(target_arch = "wasm32"))]
pub mod net;
pub mod table;
