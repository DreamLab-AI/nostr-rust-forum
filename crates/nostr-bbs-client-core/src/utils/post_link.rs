//! Deep links to a post (`/go/<id>?c=<channel>`), shared by the forum's jump
//! page and the notification store.

use nostr_bbs_core::NostrEvent;

/// Query parameter carrying the post's channel id: `/go/<id>?c=<channel>`.
pub const CHANNEL_HINT_PARAM: &str = "c";

/// The deep link to post `event_id`, carrying its channel as a hint when
/// known. In an encrypted zone the relay holds only the sealed envelope,
/// whose id is not the post's id, so the jump page resolves from the
/// channel's own (decrypted) history.
///
/// A hint that is not URL-safe as it stands (a legacy slug-style channel
/// tag) is left off rather than escaped: the page still resolves without it.
pub fn jump_link(event_id: &str, channel_id: Option<&str>) -> String {
    let url_safe = |c: &str| {
        !c.is_empty()
            && c.chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
    };
    match channel_id.filter(|c| url_safe(c)) {
        Some(c) => format!("/go/{event_id}?{CHANNEL_HINT_PARAM}={c}"),
        None => format!("/go/{event_id}"),
    }
}

/// The deep link for a post held in store list `list_key`. The hint is the
/// post's own channel tag: the store's list keys include `topic:<root>` and
/// `roots:<channel>`, which are not channels. A bare list key stands in only
/// for a post with no channel tag.
pub fn post_link(ev: &NostrEvent, list_key: &str) -> String {
    let channel =
        channel_of(ev).or_else(|| (!list_key.contains(':')).then(|| list_key.to_string()));
    jump_link(&ev.id, channel.as_deref())
}

/// Channel id of a kind-42: the `root`-marked `e` tag, else the first `e`
/// (an owned [`nostr_bbs_core::sealed::channel_of`]).
pub fn channel_of(ev: &NostrEvent) -> Option<String> {
    nostr_bbs_core::sealed::channel_of(ev).map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(id: &str, tags: Vec<Vec<&str>>) -> NostrEvent {
        NostrEvent {
            id: id.into(),
            pubkey: "pk".into(),
            created_at: 0,
            kind: 42,
            tags: tags
                .into_iter()
                .map(|t| t.into_iter().map(String::from).collect())
                .collect(),
            content: String::new(),
            sig: String::new(),
        }
    }

    #[test]
    fn jump_link_carries_the_channel_hint() {
        assert_eq!(jump_link("abc", Some("chan")), "/go/abc?c=chan");
        assert_eq!(jump_link("abc", None), "/go/abc");
        assert_eq!(jump_link("abc", Some("")), "/go/abc");
        // Old persisted links stay recognisable as post links.
        assert!(jump_link("abc", Some("chan")).starts_with("/go/"));
    }

    #[test]
    fn post_link_hints_the_posts_own_channel() {
        let reply = ev(
            "r1",
            vec![
                vec!["e", "root", "", "reply"],
                vec!["e", "chan", "", "root"],
            ],
        );
        // Held in its topic's list: the hint is still the channel.
        assert_eq!(post_link(&reply, "topic:root"), "/go/r1?c=chan");
        assert_eq!(post_link(&reply, "chan"), "/go/r1?c=chan");
        let untagged = ev("u", vec![]);
        assert_eq!(post_link(&untagged, "chan"), "/go/u?c=chan");
        assert_eq!(post_link(&untagged, "topic:root"), "/go/u");
    }

    #[test]
    fn channel_of_prefers_the_root_marker() {
        let reply = ev(
            "e",
            vec![vec!["e", "orig", "", "edit"], vec!["e", "chan", "", "root"]],
        );
        assert_eq!(channel_of(&reply), Some("chan".into()));
        let legacy = ev("l", vec![vec!["e", "first"], vec!["e", "second"]]);
        assert_eq!(channel_of(&legacy), Some("first".into()));
        assert_eq!(channel_of(&ev("n", vec![])), None);
    }
}
