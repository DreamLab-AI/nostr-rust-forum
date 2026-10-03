//! The table protocol between a member (the hero) and the house seat (the
//! citizen): what each sends the other, carried as the content of a NIP-59
//! gift-wrapped rumor of kind [`RUMOR_KIND`] on the forum's relay.
//!
//! One hand, in order:
//!
//! 1. the hero sends [`Hello`](ToCitizen::Hello);
//! 2. the citizen answers [`Offer`](ToHero::Offer): the tables it deals, its
//!    pubkey and script, a fresh shuffle commitment, and what it knows of the
//!    hero's standing (debts outstanding);
//! 3. the hero sends [`Sit`](ToCitizen::Sit) naming a stake and a nonce;
//! 4. the citizen deals and sends [`State`](ToHero::State) with the hero's
//!    seat view and the hand log; after every action by either seat it sends
//!    another;
//! 5. the hero sends [`Act`](ToCitizen::Act) for each of its turns;
//! 6. when the hand ends the citizen sends [`Done`](ToHero::Done): the final
//!    view, the revealed secret, the hand record, its root and the
//!    settlement; then a new [`Offer`](ToHero::Offer) for the next hand;
//! 7. the loser pays: the hero signs a transfer and sends
//!    [`Paid`](ToCitizen::Paid); the citizen pays and sends
//!    [`Paid`](ToHero::Paid).
//!
//! Two members may also play each other, the citizen dealing but holding no
//! seat: a member sends [`Challenge`](ToCitizen::Challenge) naming an
//! opponent the offer listed as present; the opponent receives
//! [`Challenged`](ToHero::Challenged) and answers
//! [`Accept`](ToCitizen::Accept) with a nonce of their own (or
//! [`Decline`](ToCitizen::Decline)); the seed is the citizen's secret with
//! both nonces, and the hand runs as above with each member receiving their
//! own seat's view. The loser pays the winner directly.
//!
//! Every message names the hand it belongs to by the citizen's shuffle
//! commitment, which is unique per hand. A message the other side cannot act
//! on is answered with [`Error`](ToHero::Error) or ignored. The protocol is
//! versioned by [`VERSION`]; a peer refuses another version.
//!
//! The views and logs travel in the engine's JSON shape so a client written
//! against `poker.js` reads them unchanged.

use serde::{Deserialize, Serialize};

use crate::engine::{Action, LogEntry, SeatView};
use crate::rules::{HandRecord, Settlement};

/// The kind of the rumor inside the gift wrap. Libre Poker's browsers use
/// this ephemeral kind for table claims; it is not a DM (kind 14), so a DM
/// inbox never shows a hand.
pub const RUMOR_KIND: u64 = 20779;

/// The protocol version both sides must speak.
pub const VERSION: u32 = 1;

/// The asset a table settles in.
///
/// A house seat serves one chain, so the asset is always that chain's issued
/// asset, and protocol 1 names it with the one tag it shipped with: `dream`
/// is DREAM to the `sidestr:dreamlab` house seat and BLAKES7 to the
/// `sidestr:dreamlab-txbt4` one (kit ADR-2021). The member's browser sends
/// it to the house seat of the table it sat at, so the two never meet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Asset {
    /// The house seat's chain asset: DREAM on `sidestr:dreamlab`, BLAKES7 on
    /// `sidestr:dreamlab-txbt4` (wire tag `dream`).
    Dream,
}

/// One table on offer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TableOffer {
    /// Big blind, in the asset's base units.
    pub bb: u64,
    /// Small blind.
    pub sb: u64,
    /// The buy-in each seat covers for every hand.
    pub buyin: u64,
    /// The label the picker shows, `"<sb>/<bb>"`.
    pub label: String,
}

/// A debt one side owes the other for a settled hand.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Debt {
    /// The hand's root.
    pub root: String,
    /// Base units owed.
    pub amount: u64,
    /// When the hand ended, unix seconds.
    pub since: u64,
}

/// What the hero sends the citizen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum ToCitizen {
    /// Ask for an offer.
    Hello {
        /// Protocol version.
        v: u32,
    },
    /// Sit at a table for one hand.
    Sit {
        /// Protocol version.
        v: u32,
        /// The commitment the offer carried: names the hand.
        commit: String,
        /// The asset to settle in.
        asset: Asset,
        /// The big blind chosen, one of the offer's.
        bb: u64,
        /// The hero's 32-byte nonce as 64 hex characters.
        nonce: String,
    },
    /// Act on the hero's turn.
    Act {
        /// The hand.
        commit: String,
        /// The action, seat 0.
        action: Action,
    },
    /// The hero paid a settlement it owed.
    Paid {
        /// The hand's root.
        root: String,
        /// The transfer's id.
        txid: String,
    },
    /// Leave the table (an unfinished hand is folded).
    Leave {
        /// The hand, if one is in play.
        commit: Option<String>,
    },
    /// Challenge another member, present at the table, to one hand the
    /// citizen deals.
    Challenge {
        /// Protocol version.
        v: u32,
        /// The opponent's pubkey, 64 hex.
        opponent: String,
        /// The big blind, one of the offer's.
        bb: u64,
        /// The challenger's 32-byte nonce as 64 hex characters.
        nonce: String,
    },
    /// Accept a challenge.
    Accept {
        /// The challenge's commitment.
        commit: String,
        /// The accepter's nonce, 64 hex.
        nonce: String,
    },
    /// Decline a challenge.
    Decline {
        /// The challenge's commitment.
        commit: String,
    },
}

/// What the citizen sends the hero.
// `Done` carries a whole record and view; messages are transient, so the
// size spread is not worth boxing.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum ToHero {
    /// The tables on offer and a fresh shuffle commitment for the next hand.
    Offer {
        /// Protocol version.
        v: u32,
        /// The citizen's pubkey, 64 hex.
        citizen: String,
        /// The citizen's receive script, hex (`5120‖pubkey`).
        script: String,
        /// The house character's name.
        name: String,
        /// The house character's profile.
        profile: String,
        /// Assets the citizen settles in.
        assets: Vec<Asset>,
        /// Tables, in lobby order.
        tables: Vec<TableOffer>,
        /// Commitment to the citizen's secret for the next hand.
        commit: String,
        /// Hands the hero still owes for; the citizen deals no new hand
        /// while any is outstanding.
        owed: Vec<Debt>,
        /// Hands the citizen still owes the hero for (paid as soon as the
        /// chain allows).
        owing: Vec<Debt>,
        /// The largest amount the citizen will pay out today, in base units.
        daily_cap_left: u64,
        /// Other members at the table now (said hello recently and are not
        /// in a hand), who may be challenged.
        present: Vec<String>,
    },
    /// Someone challenged the recipient to a hand.
    Challenged {
        /// The challenge's commitment: names the hand if accepted.
        commit: String,
        /// The challenger's pubkey.
        from: String,
        /// The big blind.
        bb: u64,
        /// The buy-in each seat covers.
        buyin: u64,
        /// When the challenge lapses, unix seconds.
        expires: u64,
    },
    /// The recipient's challenge is waiting for the opponent.
    Waiting {
        /// The challenge's commitment.
        commit: String,
        /// The opponent.
        opponent: String,
        /// When it lapses, unix seconds.
        expires: u64,
    },
    /// A challenge was declined or lapsed.
    Declined {
        /// The challenge's commitment.
        commit: String,
        /// Who declined, or the citizen for a lapse.
        by: String,
    },
    /// The hand as the recipient may see it, after the deal and after every
    /// action.
    State {
        /// The hand.
        commit: String,
        /// The recipient's seat.
        seat: u32,
        /// The opponent's pubkey (the citizen's for a house hand).
        opponent: String,
        /// Whether the opponent is the house bot.
        house: bool,
        /// The recipient's seat view.
        view: SeatView,
        /// The hand log so far.
        log: Vec<LogEntry>,
    },
    /// The hand is over.
    Done {
        /// The hand.
        commit: String,
        /// The recipient's seat.
        seat: u32,
        /// The opponent's pubkey (the citizen's for a house hand).
        opponent: String,
        /// Whether the opponent is the house bot.
        house: bool,
        /// The final view (hole cards shown at a showdown).
        view: SeatView,
        /// The hand log.
        log: Vec<LogEntry>,
        /// The citizen's revealed secret, 64 hex.
        secret: String,
        /// The players' nonces as the citizen received them, in seat order.
        nonces: Vec<String>,
        /// The seed the hand was dealt from, `sha256(secret ‖ nonces…)`.
        seed: String,
        /// The hand record.
        record: HandRecord,
        /// The record's root.
        root: String,
        /// The buy-in the hand was played for.
        buyin: u64,
        /// What the hand owes from the recipient's side: `Hero` is the
        /// recipient, `Citizen` the opponent; `None` for a split pot.
        settlement: Option<Settlement>,
    },
    /// The citizen paid a settlement it owed.
    Paid {
        /// The hand's root.
        root: String,
        /// The transfer's id.
        txid: String,
    },
    /// Something the citizen could not do, in words.
    Error {
        /// The hand, when the error concerns one.
        commit: Option<String>,
        /// The reason.
        message: String,
    },
}

impl ToCitizen {
    /// Parse a message from its JSON.
    pub fn parse(json: &str) -> Result<Self, String> {
        serde_json::from_str(json).map_err(|e| format!("unreadable message: {e}"))
    }

    /// The message as JSON.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("protocol messages serialise")
    }
}

impl ToHero {
    /// Parse a message from its JSON.
    pub fn parse(json: &str) -> Result<Self, String> {
        serde_json::from_str(json).map_err(|e| format!("unreadable message: {e}"))
    }

    /// The message as JSON.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("protocol messages serialise")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_are_tagged_and_round_trip() {
        let m = ToCitizen::Sit {
            v: VERSION,
            commit: "ab".repeat(32),
            asset: Asset::Dream,
            bb: 20,
            nonce: "cd".repeat(32),
        };
        let json = m.to_json();
        assert!(json.starts_with(r#"{"t":"sit","v":1,"#), "{json}");
        assert!(json.contains(r#""asset":"dream""#));
        assert_eq!(ToCitizen::parse(&json).unwrap(), m);

        let e = ToHero::Error {
            commit: None,
            message: "no".into(),
        };
        assert_eq!(e.to_json(), r#"{"t":"error","commit":null,"message":"no"}"#);
        assert_eq!(ToHero::parse(&e.to_json()).unwrap(), e);
        assert!(ToHero::parse(r#"{"t":"nope"}"#).is_err());
    }
}
