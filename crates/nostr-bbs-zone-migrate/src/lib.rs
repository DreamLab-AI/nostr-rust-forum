//! `nostr-bbs-zone-migrate` — seal the plaintext history of an encrypted
//! zone into *sealed originals*, verify them, then purge the plaintext
//! (ADR-2017).
//!
//! ADR-2016 encrypts new posts in encrypted zones; older kind-42 messages
//! stay on the relay as plaintext. This tool re-publishes each of them as a
//! zone-encrypted envelope, signed by an admin, that carries the **full
//! original signed event** ([`nostr_bbs_core::sealed`]). Ids, authorship,
//! timestamps and the reply graph survive, and the author's own signature
//! still proves the text. Once every envelope has been read back and checked,
//! the plaintext rows are deleted through the relay's silent admin endpoint.
//! No kind-5 is published, because clients tombstone kind-5 targets and would
//! hide the restored copy.
//!
//! The operator runbook is `docs/security/encrypted-zone-history-migration.md`.
//!
//! # Commands
//!
//! ```text
//! nostr-bbs-zone-migrate --relay wss://relay.example.org \
//!     --channels channels.json [--keys-file keys.json] [--fetch-grants] \
//!     --state migrate-state.json [--json] <COMMAND>
//! ```
//!
//! | Command | Does | Writes |
//! |---|---|---|
//! | `plan` (default) | Per listed channel: plaintext count, already-sealed count, ids that would be sealed, originals whose signature does not verify. | nothing |
//! | `seal [--limit N]` | Publishes an envelope per planned original, waits for `OK true`, fetches it back by id, opens it with the zone key and requires the inner event to equal the original byte for byte. Resumable. | relay: envelopes; state |
//! | `verify` | Re-fetches and re-opens every recorded envelope; the inner event must still hash to what was sealed. | state |
//! | `purge --yes` | Refuses unless every entry is `verified`. Deletes the originals via `POST /api/admin/events/delete` (NIP-98, ≤ 200 ids per call), re-checking each chunk's envelopes just before deleting it. | relay: deletions; state |
//! | `status` | Counts by state from the state file. | nothing |
//! | `--print-channels` | Lists the relay's kind-40 channels with name and `section` tag, to help write `channels.json`. | nothing |
//!
//! Identity: the admin secret key is read **only** from the environment
//! variable [`identity::IDENTITY_ENV`] (`NOSTR_BBS_MIGRATE_KEY`, hex or
//! `nsec`), never from a flag, and is never printed. The CLI checks
//! `GET /api/check-whitelist` first and stops if the key is not an admin.
//!
//! Zone keys come from `--keys-file` ([`keys`]) and/or `--fetch-grants`
//! ([`grants`]); they are merged and the highest epoch per zone seals.
//! Channels are mapped to zones explicitly ([`channels`]); nothing is
//! inferred from section tags.
//!
//! Progress goes to stderr; `--json` prints a machine-readable summary on
//! stdout. The state file ([`state`]) holds ids, zones, epochs and digests
//! only: no secrets and no message text.
//!
//! # Library layout
//!
//! The library is pure and compiles to `wasm32-unknown-unknown`; the binary's
//! WebSocket/HTTP client is native-only and implements [`relay::Relay`].
//!
//! - [`identity`]: the migrator key from the environment.
//! - [`keys`]: zone keys, the key-file schema, the merged [`keys::KeyRing`].
//! - [`grants`]: opening and validating zone-key grants.
//! - [`channels`]: the channels file and `--print-channels`.
//! - [`plan`]: classifying a channel's events.
//! - [`state`]: the state file and atomic writes.
//! - [`relay`]: the [`relay::Relay`] trait, filters, paging.
//! - [`engine`]: the `seal`, `verify` and `purge` steps.
//!
//! # Example
//!
//! Planning is pure: classify a channel's events without a relay.
//!
//! ```
//! use nostr_bbs_core::{sign_event, UnsignedEvent};
//! use nostr_bbs_zone_migrate::channels::ChannelSpec;
//! use nostr_bbs_zone_migrate::keys::KeyRing;
//! use nostr_bbs_zone_migrate::plan::scan_channel;
//!
//! let channel = "c".repeat(64);
//! let author = nostr_bbs_core::keys::signing_key_from_bytes(&[0x11; 32]).unwrap();
//! let original = sign_event(
//!     UnsignedEvent {
//!         pubkey: hex::encode(author.verifying_key().to_bytes()),
//!         created_at: 1_700_000_000,
//!         kind: 42,
//!         tags: vec![vec!["e".into(), channel.clone(), "".into(), "root".into()]],
//!         content: "from before encryption".into(),
//!     },
//!     &author,
//! )
//! .unwrap();
//!
//! let spec = ChannelSpec { id: channel, zone: "zone3".into() };
//! let scan = scan_channel(&spec, &[original.clone()], &KeyRing::new());
//! assert_eq!(scan.plan.would_seal, vec![original.id]);
//! assert_eq!(scan.plan.seal_epoch, None); // no zone key held yet
//! ```

#![warn(missing_docs)]

pub mod channels;
pub mod engine;
pub mod grants;
pub mod identity;
pub mod keys;
pub mod plan;
pub mod relay;
pub mod state;
