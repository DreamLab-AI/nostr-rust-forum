//! Privacy-preserving URL slug hashing for forum sections and topics (#9).
//!
//! Section and topic identifiers in the URL must NOT leak the underlying
//! channel/thread titles. Zone ids stay readable (they are public config:
//! `public`/`friends`/`family`/`business`). Sections and topics are carried as
//! short, stable hashes; the real names are resolved for breadcrumbs/titles
//! from the shared `ChannelStore` via the resolver helpers in `section.rs` /
//! `thread.rs`.
//!
//! Scheme (mirrored in ruflo memory `forum-kit-slug-scheme`):
//! - **Section slug** = `'s'` + first 12 lowercase-hex chars of
//!   `sha256(channel_id)`. The channel id is the kind-40 event id (64 hex). The
//!   `'s'` prefix marks it as a section hash and guarantees a non-numeric lead.
//! - **Topic slug** = `'t'` + first 16 lowercase-hex chars of the kind-42
//!   *root* event id. The event id is already a sha256, so a prefix is itself a
//!   stable, collision-resistant handle — no extra hashing needed.
//!
//! Resolution accepts the hashed form first, then falls back to legacy
//! plaintext forms (slugified names, raw section tags, full hex ids) so old
//! seeded links and breadcrumb back-links keep working through the transition.

use sha2::{Digest, Sha256};

/// Number of hex chars retained from `sha256(channel_id)` for a section slug.
const SECTION_HEX_LEN: usize = 12;
/// Number of hex chars retained from the root event id for a topic slug.
const TOPIC_HEX_LEN: usize = 16;

const SECTION_PREFIX: char = 's';
const TOPIC_PREFIX: char = 't';

/// Lowercase hex sha256 of an arbitrary string.
fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

/// Build the URL slug for a section from its channel id (kind-40 event id).
///
/// `s<12 hex of sha256(channel_id)>`. Stable for a given channel id and never
/// reveals the channel name.
pub fn section_slug(channel_id: &str) -> String {
    let digest = sha256_hex(channel_id);
    format!("{SECTION_PREFIX}{}", &digest[..SECTION_HEX_LEN])
}

/// Build the URL slug for a topic from its root kind-42 event id.
///
/// `t<16 hex prefix of the event id>`. The event id is already a sha256, so a
/// prefix is collision-resistant; no re-hashing is performed.
pub fn topic_slug(root_event_id: &str) -> String {
    let id = root_event_id.to_lowercase();
    let take = TOPIC_HEX_LEN.min(id.len());
    format!("{TOPIC_PREFIX}{}", &id[..take])
}

/// True when `slug` has the shape of a section hash (`s` + 12 hex chars).
pub fn is_section_slug(slug: &str) -> bool {
    let mut chars = slug.chars();
    match chars.next() {
        Some(c) if c == SECTION_PREFIX => {}
        _ => return false,
    }
    let rest = &slug[SECTION_PREFIX.len_utf8()..];
    rest.len() == SECTION_HEX_LEN && rest.chars().all(|c| c.is_ascii_hexdigit())
}

/// True when `slug` has the shape of a topic hash (`t` + 16 hex chars).
pub fn is_topic_slug(slug: &str) -> bool {
    let mut chars = slug.chars();
    match chars.next() {
        Some(c) if c == TOPIC_PREFIX => {}
        _ => return false,
    }
    let rest = &slug[TOPIC_PREFIX.len_utf8()..];
    rest.len() == TOPIC_HEX_LEN && rest.chars().all(|c| c.is_ascii_hexdigit())
}

/// True when the given channel id hashes to `slug` (case-insensitive).
pub fn matches_section_slug(channel_id: &str, slug: &str) -> bool {
    section_slug(channel_id).eq_ignore_ascii_case(slug)
}

/// True when the given root event id maps to `slug`.
///
/// Accepts both the short `t…` slug AND a full 64-hex event id (deep-link /
/// legacy URLs that carried the raw id).
pub fn matches_topic_slug(event_id: &str, slug: &str) -> bool {
    if event_id.eq_ignore_ascii_case(slug) {
        return true;
    }
    topic_slug(event_id).eq_ignore_ascii_case(slug)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CID: &str = "a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff00";
    const ROOT: &str = "00ffeeddccbbaa998877665544332211090f8e7d6c5b4a39281706f5e4d3c2b1";

    #[test]
    fn section_slug_is_stable_and_prefixed() {
        let a = section_slug(CID);
        let b = section_slug(CID);
        assert_eq!(a, b, "section slug must be deterministic");
        assert!(a.starts_with('s'));
        assert_eq!(a.len(), 1 + SECTION_HEX_LEN);
        assert!(is_section_slug(&a));
        assert!(matches_section_slug(CID, &a));
        // Does not leak the input.
        assert!(!a.contains(&CID[..SECTION_HEX_LEN]));
    }

    #[test]
    fn topic_slug_is_event_id_prefix() {
        let t = topic_slug(ROOT);
        assert!(t.starts_with('t'));
        assert_eq!(t.len(), 1 + TOPIC_HEX_LEN);
        assert!(is_topic_slug(&t));
        assert!(matches_topic_slug(ROOT, &t));
        // Full id still resolves (deep-link compatibility).
        assert!(matches_topic_slug(ROOT, ROOT));
        // Case-insensitive.
        assert!(matches_topic_slug(&ROOT.to_uppercase(), &t));
    }

    #[test]
    fn distinct_inputs_distinct_slugs() {
        assert_ne!(section_slug(CID), section_slug(ROOT));
        assert_ne!(topic_slug(CID), topic_slug(ROOT));
    }

    #[test]
    fn shape_guards_reject_plaintext() {
        assert!(!is_section_slug("home-lobby"));
        assert!(!is_section_slug("sgggggggggggg")); // non-hex
        assert!(!is_topic_slug("welcome"));
        assert!(!is_topic_slug("s1234567890ab")); // wrong prefix/len
                                                  // A topic slug is not a section slug and vice-versa.
        assert!(!is_section_slug(&topic_slug(ROOT)));
        assert!(!is_topic_slug(&section_slug(CID)));
    }
}
