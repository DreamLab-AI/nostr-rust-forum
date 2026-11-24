//! DMs: already-signed kind-1059 gift wraps (NIP-59) only. Source-platform
//! DMs are never imported (they would need forged signatures).
//!
//! - **Verbatim copy** ([`copy_plan`]): a wrap whose id and signature verify,
//!   with exactly one `p` recipient, is copied byte for byte when that
//!   recipient is whitelisted in the new deployment (the relay accepts wraps
//!   only to whitelisted recipients). Nothing is decrypted. Zone-key grants
//!   (rumor 21453) cannot be told apart without decrypting, so copying needs
//!   an explicit acknowledgement that stale grants travel too.
//! - **Re-wrap** ([`rewrap_operator_sent`]): only DMs the operator SENT from
//!   an old key. Each wrap addressed to the old key is opened in memory with
//!   [`nostr_bbs_core::gift_wrap::unwrap_gift`] (which enforces
//!   rumor author = seal signer and NIP-17 kinds); a rumor by anyone else is
//!   skipped and counted (a seal must be signed by the rumor's author, and we
//!   never forge a sender). The operator's own rumors are re-sealed with the
//!   old key and wrapped to the new key, rumor untouched.

use std::collections::BTreeSet;

use nostr_bbs_core::gift_wrap::{seal_rumor, unwrap_gift, wrap_seal};
use nostr_bbs_core::keys::SecretKey;
use nostr_bbs_core::{verify_event, NostrEvent};
use serde::Serialize;

use crate::error::ImportError;

/// Gift wrap kind.
pub const KIND_WRAP: u64 = 1059;

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The single `p` recipient of a wrap, if it has exactly one.
pub fn recipient_of(w: &NostrEvent) -> Option<&str> {
    let ps: Vec<&str> = w
        .tags
        .iter()
        .filter(|t| t.first().map(String::as_str) == Some("p"))
        .filter_map(|t| t.get(1).map(String::as_str))
        .collect();
    match ps.as_slice() {
        [one] if is_hex64(one) => Some(one),
        _ => None,
    }
}

/// Counts from [`copy_plan`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct CopyReport {
    /// Wraps to copy.
    pub copied: usize,
    /// Not kind 1059, bad id/signature, or not exactly one recipient.
    pub invalid: usize,
    /// Recipient not whitelisted in the new deployment.
    pub not_whitelisted: usize,
}

/// Select the wraps that may be copied verbatim. Refused outright unless
/// `allow_stale_grants` (see the module docs).
pub fn copy_plan(
    wraps: &[NostrEvent],
    whitelisted: &BTreeSet<String>,
    allow_stale_grants: bool,
) -> Result<(Vec<NostrEvent>, CopyReport), ImportError> {
    if !wraps.is_empty() && !allow_stale_grants {
        return Err(ImportError::Refused(
            "copying gift wraps also copies any zone-key grants among them (indistinguishable without decrypting); pass --allow-stale-grants to accept".into(),
        ));
    }
    let mut out = Vec::new();
    let mut r = CopyReport::default();
    for w in wraps {
        if w.kind != KIND_WRAP || !verify_event(w) {
            r.invalid += 1;
            continue;
        }
        match recipient_of(w) {
            None => r.invalid += 1,
            Some(p) if !whitelisted.contains(p) => r.not_whitelisted += 1,
            Some(_) => {
                out.push(w.clone());
                r.copied += 1;
            }
        }
    }
    Ok((out, r))
}

/// Counts from [`rewrap_operator_sent`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct RewrapReport {
    /// Wraps addressed to the old key.
    pub addressed: usize,
    /// Re-wrapped to the new key.
    pub rewrapped: usize,
    /// Rumors written by someone else (never re-sealed).
    pub third_party: usize,
    /// Not openable, or not a NIP-17 rumor (grants, application kinds).
    pub skipped: usize,
    /// Wraps to other recipients.
    pub other_recipient: usize,
}

/// Re-wrap the DMs the operator sent from `old` to `new_pk` (see the module
/// docs). Returns `(original wrap id, new wrap)` pairs.
pub fn rewrap_operator_sent(
    wraps: &[NostrEvent],
    old: &SecretKey,
    new_pk: &str,
) -> Result<(Vec<(String, NostrEvent)>, RewrapReport), ImportError> {
    let old_pk = old.public_key().to_hex();
    if old_pk == new_pk {
        return Err(ImportError::Refused("old and new operator keys are the same".into()));
    }
    let new_bytes: [u8; 32] = hex::decode(new_pk)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| ImportError::Key("new operator pubkey must be 64 hex".into()))?;
    let mut out = Vec::new();
    let mut r = RewrapReport::default();
    for w in wraps {
        if w.kind != KIND_WRAP || !verify_event(w) || recipient_of(w) != Some(old_pk.as_str()) {
            r.other_recipient += 1;
            continue;
        }
        r.addressed += 1;
        let Ok(g) = unwrap_gift(w, old.as_bytes()) else {
            r.skipped += 1;
            continue;
        };
        if g.rumor.pubkey != old_pk || g.sender_pubkey != old_pk {
            r.third_party += 1;
            continue;
        }
        let seal = seal_rumor(&g.rumor, old.as_bytes(), &new_bytes).map_err(|e| ImportError::Key(e.to_string()))?;
        let wrap = wrap_seal(&seal, new_pk).map_err(|e| ImportError::Key(e.to_string()))?;
        out.push((w.id.clone(), wrap));
        r.rewrapped += 1;
    }
    Ok((out, r))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr_bbs_core::gift_wrap::gift_wrap;

    fn kp() -> SecretKey {
        nostr_bbs_core::keys::generate_keypair().unwrap().secret
    }

    #[test]
    fn rewrap_only_operator_sent() {
        let old = kp();
        let new = kp();
        let friend = kp();
        let (old_pk, new_pk, friend_pk) = (old.public_key().to_hex(), new.public_key().to_hex(), friend.public_key().to_hex());
        // the operator's self-copy of a DM it sent (addressed to the old key)
        let mine = gift_wrap(old.as_bytes(), &old_pk, &old_pk, "sent by me").unwrap();
        // a DM the friend sent to the operator
        let theirs = gift_wrap(friend.as_bytes(), &friend_pk, &old_pk, "from a friend").unwrap();
        let (out, r) = rewrap_operator_sent(&[mine, theirs], &old, &new_pk).unwrap();
        assert_eq!((r.addressed, r.rewrapped, r.third_party), (2, 1, 1));
        let g = unwrap_gift(&out[0].1, new.as_bytes()).unwrap();
        assert_eq!(g.rumor.content, "sent by me");
        assert_eq!(g.rumor.pubkey, old_pk, "the author stays the old key: never re-authored");
    }

    #[test]
    fn copy_needs_ack_and_whitelisted_recipient() {
        let a = kp();
        let b = kp();
        let w = gift_wrap(a.as_bytes(), &a.public_key().to_hex(), &b.public_key().to_hex(), "x").unwrap();
        assert!(copy_plan(&[w.clone()], &BTreeSet::new(), false).is_err());
        let (none, r) = copy_plan(&[w.clone()], &BTreeSet::new(), true).unwrap();
        assert!(none.is_empty() && r.not_whitelisted == 1);
        let wl: BTreeSet<String> = [b.public_key().to_hex()].into();
        let (one, _) = copy_plan(&[w.clone()], &wl, true).unwrap();
        assert_eq!((one[0].id.as_str(), one[0].sig.as_str()), (w.id.as_str(), w.sig.as_str()));
        let mut forged = w;
        forged.content.push('x');
        assert_eq!(copy_plan(&[forged], &wl, true).unwrap().1.invalid, 1);
    }
}
