//! Canonical section and topic URLs.
//!
//! A section is one kind-40 channel, and its URL id is the hash of the channel
//! id ([`section_slug`]). The section-tag hash (`section_slug("zone2-rants")`)
//! that the Forums index used to emit names a *group* of channels, so it is
//! only ever accepted as an old link: [`find_by_section_slug`] resolves it and
//! the page replaces the address with the canonical one
//! ([`canonical_replacement`]).
//!
//! Canonical shapes, inside the router base:
//! - section: `/<zone-slug>/s<12 hex of sha256(channel id)>`
//! - topic: `/<zone-slug>/s<…>/t<16 hex of the root event id>`
//!
//! Also accepted, and replaced: the `/forums/…` prefix, the zone's immutable
//! id in place of its slug, the section-tag hash, and a full 64-hex topic id.
//!
//! The derivation lives here so the forum and the BBS (whose links point
//! into the forum) emit the same URLs. The forum's address-bar replacement
//! is in the forum crate (`components::canonical_address`).

use crate::stores::channels::ChannelMeta;
use crate::stores::zones::{section_routes_to_zone, section_to_zone, zone_slug, Zone};
use crate::utils::back_nav::ForumRoute;
use crate::utils::slug_hash::{is_topic_slug, matches_section_slug, section_slug, topic_slug};

/// The section tag a channel is grouped under: its `section` tag, or the first
/// zone's id when the tag is empty (the Forums index's rule).
pub fn effective_section_tag<'a>(channel: &'a ChannelMeta, zones: &'a [Zone]) -> &'a str {
    if channel.section.is_empty() {
        zones.first().map(|z| z.id.as_str()).unwrap_or_default()
    } else {
        &channel.section
    }
}

/// The URL segment of the zone that owns `channel`, or `None` without zones.
pub fn channel_zone_slug(channel: &ChannelMeta, zones: &[Zone]) -> Option<String> {
    let zone_id = section_to_zone(effective_section_tag(channel, zones), zones)?;
    zones
        .iter()
        .find(|z| z.id == zone_id)
        .map(|z| zone_slug(z).to_string())
}

/// `/<zone_slug>/<section id>` for the channel `channel_id`.
pub fn section_path(zone_slug: &str, channel_id: &str) -> String {
    format!("/{zone_slug}/{}", section_slug(channel_id))
}

/// `/<zone_slug>/<section id>/<topic id>` for the topic rooted at
/// `root_event_id` in channel `channel_id`.
pub fn topic_path(zone_slug: &str, channel_id: &str, root_event_id: &str) -> String {
    format!(
        "{}/{}",
        section_path(zone_slug, channel_id),
        topic_slug(root_event_id)
    )
}

/// The canonical section path of `channel`, or `None` without zones.
pub fn canonical_section_path(channel: &ChannelMeta, zones: &[Zone]) -> Option<String> {
    channel_zone_slug(channel, zones).map(|z| section_path(&z, &channel.id))
}

/// The canonical topic path for the topic URL segment `topic_param` in
/// `channel`: from the root event id once it is known, else from the
/// parameter itself when it already has the short `t…` shape. `None` while
/// neither is available (a full-id link waits for its root) or without zones.
pub fn canonical_topic_path(
    channel: &ChannelMeta,
    topic_param: &str,
    root_event_id: Option<&str>,
    zones: &[Zone],
) -> Option<String> {
    let topic = match root_event_id {
        Some(root) => topic_slug(root),
        None if is_topic_slug(topic_param) => topic_param.to_lowercase(),
        None => return None,
    };
    canonical_section_path(channel, zones).map(|s| format!("{s}/{topic}"))
}

/// The channel a group of channels sharing one section tag stands for: the
/// first by lowercased name, then id (the zone page's order), so a group link
/// always opens the same channel whatever order the store holds them in.
pub fn representative_channel<'a, I>(channels: I) -> Option<&'a ChannelMeta>
where
    I: IntoIterator<Item = &'a ChannelMeta>,
{
    channels
        .into_iter()
        .min_by(|a, b| (a.name.to_lowercase(), &a.id).cmp(&(b.name.to_lowercase(), &b.id)))
}

/// The channel a hashed section id names within zone `category` (slug or id,
/// empty for any zone): the channel whose id hashes to `slug` (canonical), or
/// else the representative of the channels whose section tag hashes to it
/// (old Forums index links). `None` when neither matches; callers then try the
/// plaintext forms.
pub fn find_by_section_slug<'a>(
    channels: &'a [ChannelMeta],
    category: &str,
    slug: &str,
    zones: &[Zone],
) -> Option<&'a ChannelMeta> {
    let in_zone = |c: &&ChannelMeta| section_routes_to_zone(&c.section, category, zones);
    channels
        .iter()
        .filter(in_zone)
        .find(|c| matches_section_slug(&c.id, slug))
        .or_else(|| {
            representative_channel(
                channels
                    .iter()
                    .filter(in_zone)
                    .filter(|c| matches_section_slug(effective_section_tag(c, zones), slug)),
            )
        })
}

/// The address to replace the current one with, or `None` when it is
/// already canonical. `current_path` is the base-relative path; `search` and
/// `hash` (each with its leading `?`/`#`, or empty) are carried over.
///
/// Only a page of the same kind is replaced (a section by a section, a topic
/// by a topic): a section page still mounted while the router moves on to one
/// of its topics must not pull the address back to itself.
pub fn canonical_replacement(
    current_path: &str,
    canonical_path: &str,
    search: &str,
    hash: &str,
) -> Option<String> {
    let same_kind = matches!(
        (
            ForumRoute::parse(current_path),
            ForumRoute::parse(canonical_path)
        ),
        (ForumRoute::Section { .. }, ForumRoute::Section { .. })
            | (ForumRoute::Topic { .. }, ForumRoute::Topic { .. })
    );
    (same_kind && current_path != canonical_path).then(|| format!("{canonical_path}{search}{hash}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The live deployment's zone 2 entry, in `ZONE_CONFIG` shape.
    fn zones() -> Vec<Zone> {
        serde_json::from_str(
            r#"[
                {"id":"zone1","slug":"welcome","display_name":"Welcome"},
                {"id":"zone2","slug":"minimoonoir","display_name":"Minimoonoir",
                 "section_order":["zone2-rants"]}
            ]"#,
        )
        .expect("zone config parses")
    }

    fn channel(id: &str, name: &str, section: &str) -> ChannelMeta {
        ChannelMeta {
            id: id.to_string(),
            name: name.to_string(),
            description: String::new(),
            section: section.to_string(),
            picture: String::new(),
            created_at: 0,
        }
    }

    /// The four Minimoonoir sections as published on the live relay:
    /// (kind-40 id, name, section tag, canonical id, old Forums index id).
    const LIVE: [(&str, &str, &str, &str, &str); 4] = [
        (
            "62e1c0f409f0e35bacefb701e49ba85a8b6168ee48cc4a55eb70df8b8638e1bd",
            "Rants",
            "zone2-rants",
            "s00405652f2bf",
            "s6d38b5f106d8",
        ),
        (
            "5f8f6a6d7792c9c3d11f43067979b3a71aa6ee128b284438f011508bf20f4212",
            "Events",
            "zone2-events",
            "s2e0e14f07842",
            "sc5674e790f6d",
        ),
        (
            "86a2ad0cd878f0fa913330bbdce8c4fe43ba6904a890930c827813c824ed7b8b",
            "Music",
            "zone2-music",
            "sa8bdf1e4a343",
            "saf751274212e",
        ),
        (
            "7f6a48ee36ff0ed0a9d410a0e94c1178f9431c3f5662c8ace882bea04b2efe0a",
            "Photos",
            "zone2-photos",
            "sac368b8573a2",
            "sc461a5fe80cd",
        ),
    ];

    fn live_channels() -> Vec<ChannelMeta> {
        LIVE.iter()
            .map(|(id, name, tag, _, _)| channel(id, name, tag))
            .collect()
    }

    #[test]
    fn live_ids_derive_from_channel_id_and_section_tag() {
        for (id, _, tag, canonical, old) in LIVE {
            assert_eq!(section_slug(id), canonical);
            assert_eq!(section_slug(tag), old);
        }
    }

    #[test]
    fn canonical_section_path_uses_zone_slug_and_channel_hash() {
        let zs = zones();
        for (ch, (_, _, _, canonical, _)) in live_channels().iter().zip(LIVE) {
            assert_eq!(
                canonical_section_path(ch, &zs).as_deref(),
                Some(format!("/minimoonoir/{canonical}").as_str())
            );
        }
    }

    #[test]
    fn both_live_forms_resolve_to_the_same_channel() {
        let zs = zones();
        let chans = live_channels();
        for (id, _, _, canonical, old) in LIVE {
            for category in ["minimoonoir", "zone2", "MiniMoonoir", ""] {
                for slug in [canonical, old, &canonical.to_uppercase()] {
                    let found = find_by_section_slug(&chans, category, slug, &zs);
                    assert_eq!(found.map(|c| c.id.as_str()), Some(id), "{category}/{slug}");
                }
            }
            // Never across zones.
            assert!(find_by_section_slug(&chans, "welcome", canonical, &zs).is_none());
        }
    }

    #[test]
    fn old_forms_are_replaced_and_the_canonical_form_is_left_alone() {
        let zs = zones();
        for (ch, (_, _, _, canonical, old)) in live_channels().iter().zip(LIVE) {
            let target = canonical_section_path(ch, &zs).unwrap();
            for current in [
                format!("/minimoonoir/{old}"),
                format!("/forums/minimoonoir/{old}"),
                format!("/forums/minimoonoir/{canonical}"),
                format!("/zone2/{canonical}"),
                format!("/minimoonoir/{canonical}/"),
            ] {
                assert_eq!(
                    canonical_replacement(&current, &target, "", "").as_deref(),
                    Some(target.as_str()),
                    "{current}"
                );
            }
            assert_eq!(canonical_replacement(&target, &target, "", ""), None);
        }
    }

    #[test]
    fn a_page_never_replaces_another_kind_of_page() {
        // The section page, still mounted as its topic opens, sees the topic
        // path: that is not its own old form.
        let section = "/minimoonoir/s00405652f2bf";
        let topic = "/minimoonoir/s00405652f2bf/teddb1228c6efe63d";
        assert_eq!(canonical_replacement(topic, section, "", ""), None);
        assert_eq!(canonical_replacement(section, topic, "", ""), None);
        assert_eq!(canonical_replacement("/minimoonoir", section, "", ""), None);
        assert_eq!(canonical_replacement("/settings", section, "", ""), None);
    }

    #[test]
    fn replacement_keeps_query_and_hash() {
        assert_eq!(
            canonical_replacement("/forums/z/s1/t1", "/z/s1/t1", "?focus=ab", "#r").as_deref(),
            Some("/z/s1/t1?focus=ab#r")
        );
    }

    #[test]
    fn topic_paths_are_short_and_accept_full_ids() {
        let zs = zones();
        let rants = &live_channels()[0];
        let root = "eddb1228c6efe63d00112233445566778899aabbccddeeff0011223344556677";
        let want = "/minimoonoir/s00405652f2bf/teddb1228c6efe63d";
        assert_eq!(topic_path("minimoonoir", &rants.id, root), want);
        // Root known: whatever the parameter was.
        assert_eq!(
            canonical_topic_path(rants, root, Some(root), &zs).as_deref(),
            Some(want)
        );
        // Root not yet loaded: a short parameter is already canonical...
        assert_eq!(
            canonical_topic_path(rants, "tEDDB1228C6EFE63D", None, &zs).as_deref(),
            Some(want)
        );
        // ...a full id waits for the root.
        assert_eq!(canonical_topic_path(rants, root, None, &zs), None);
    }

    #[test]
    fn group_links_open_one_channel_whatever_the_store_order() {
        let zs = zones();
        let a = channel(&"a".repeat(64), "Beta", "zone2-shared");
        let b = channel(&"b".repeat(64), "alpha", "zone2-shared");
        let slug = section_slug("zone2-shared");
        for chans in [vec![a.clone(), b.clone()], vec![b.clone(), a.clone()]] {
            let found = find_by_section_slug(&chans, "minimoonoir", &slug, &zs);
            assert_eq!(found.map(|c| c.name.as_str()), Some("alpha"));
        }
    }

    #[test]
    fn untagged_channels_group_under_the_first_zone_and_still_resolve() {
        // The Forums index keys an untagged channel by the first zone's id, so
        // its old link is the hash of "zone1"; that used to match nothing.
        let zs = zones();
        let lobby = channel(&"c".repeat(64), "Lobby", "");
        let chans = vec![lobby.clone()];
        let old = section_slug("zone1");
        let found = find_by_section_slug(&chans, "welcome", &old, &zs);
        assert_eq!(found.map(|c| c.id.as_str()), Some(lobby.id.as_str()));
        assert_eq!(
            canonical_section_path(&lobby, &zs),
            Some(section_path("welcome", &lobby.id))
        );
    }

    #[test]
    fn no_zones_means_no_canonical_path() {
        let ch = channel(&"d".repeat(64), "x", "");
        assert_eq!(canonical_section_path(&ch, &[]), None);
    }
}
