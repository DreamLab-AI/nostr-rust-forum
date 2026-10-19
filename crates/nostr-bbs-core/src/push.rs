//! Web Push preference types shared by the relay and the forum client (ADR-2023).
//!
//! These are the wire contract of `GET`/`POST /api/push/prefs`: the relay stores
//! and enforces them, the client edits them. Keeping one definition here means
//! the two sides cannot drift.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

/// Most channels a member may mute.
pub const MAX_MUTED_CHANNELS: usize = 100;

/// What an alert is about. Fixed vocabulary: it is also the whole of what the
/// drain endpoint can tell a device.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Category {
    /// A gift-wrapped direct message (kind 1059) addressed to the member.
    Dm,
    /// A channel post that `p`-tags the member (a reply or an @-mention).
    Reply,
    /// A newly created topic/channel (kind 40).
    Topic,
    /// Any new channel post (kind 42) in a zone the member can read.
    Post,
}

impl Category {
    /// Stable lowercase name; used as the `Topic` header (push-service
    /// coalescing) and in logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Category::Dm => "dm",
            Category::Reply => "reply",
            Category::Topic => "topic",
            Category::Post => "post",
        }
    }

    /// RFC 8030 `Urgency`: DMs and replies are addressed to a person, the rest
    /// is background chatter.
    pub fn urgency(self) -> &'static str {
        match self {
            Category::Dm | Category::Reply => "normal",
            Category::Topic | Category::Post => "low",
        }
    }

    /// RFC 8030 `TTL`: how long the push service holds an undelivered push.
    pub fn ttl_secs(self) -> u64 {
        match self {
            Category::Dm | Category::Reply => 24 * 60 * 60,
            Category::Topic | Category::Post => 60 * 60,
        }
    }

    /// Minimum seconds between pushes to one device. Counters still accumulate
    /// while throttled; the cron trailing flush (and the next push or app open)
    /// delivers them. Even addressed alerts are throttled: gift-wrap admission
    /// only requires a whitelisted *recipient*, so any throwaway key can send a
    /// wrap, and an unthrottled push would let a stranger buzz a member's phone.
    pub fn min_interval_secs(self) -> u64 {
        match self {
            Category::Dm | Category::Reply => 5,
            Category::Topic | Category::Post => 60,
        }
    }

    /// Whether the category carries a deep link column (DMs open `/dm`).
    pub fn has_link(self) -> bool {
        !matches!(self, Category::Dm)
    }
}

/// Daily quiet window, in the member's local time.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuietHours {
    /// Start, minutes after local midnight (0..1440).
    pub start_min: u16,
    /// End (exclusive), minutes after local midnight (0..1440). The window may
    /// wrap midnight (`start_min > end_min`).
    pub end_min: u16,
    /// Minutes the member's local time is ahead of UTC (JS
    /// `-getTimezoneOffset()`), -840..=840.
    pub tz_offset_min: i16,
}

impl QuietHours {
    /// Whether `now_secs` (UNIX) falls inside the window. An empty window
    /// (`start == end`) never suppresses.
    pub fn contains(&self, now_secs: u64) -> bool {
        if self.start_min == self.end_min {
            return false;
        }
        let local = ((now_secs / 60) as i64 + i64::from(self.tz_offset_min)).rem_euclid(1440);
        let (start, end) = (i64::from(self.start_min), i64::from(self.end_min));
        if start < end {
            local >= start && local < end
        } else {
            local >= start || local < end
        }
    }
}

/// A member's alert preferences.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushPrefs {
    /// Replies and @-mentions.
    pub replies: bool,
    /// Direct messages.
    pub dms: bool,
    /// New topics (kind 40) in zones the member can read.
    pub new_topics: bool,
    /// Every new post (kind 42) in zones the member can read.
    #[serde(default)]
    pub new_posts: bool,
    /// Channel ids (64 hex) that never alert for posts/topics. Replies that
    /// `p`-tag the member still alert: being addressed beats a mute.
    #[serde(default)]
    pub muted_channels: Vec<String>,
    /// Optional quiet window; suppresses every category.
    #[serde(default)]
    pub quiet: Option<QuietHours>,
}

impl Default for PushPrefs {
    fn default() -> Self {
        Self {
            replies: true,
            dms: true,
            new_topics: false,
            new_posts: false,
            muted_channels: Vec::new(),
            quiet: None,
        }
    }
}

impl PushPrefs {
    /// Whether an alert of `category` (in `channel`, if any) should be sent at
    /// `now_secs`.
    pub fn wants(&self, category: Category, channel: Option<&str>, now_secs: u64) -> bool {
        if self.quiet.is_some_and(|q| q.contains(now_secs)) {
            return false;
        }
        match category {
            Category::Dm => self.dms,
            Category::Reply => self.replies,
            Category::Topic | Category::Post => {
                let enabled = if category == Category::Topic {
                    self.new_topics
                } else {
                    self.new_posts
                };
                enabled && !channel.is_some_and(|c| self.muted_channels.iter().any(|m| m == c))
            }
        }
    }

    /// Normalise and validate member-supplied preferences in place.
    pub fn sanitize(&mut self) -> std::result::Result<(), &'static str> {
        let mut seen = HashSet::new();
        let mut cleaned = Vec::new();
        for c in self.muted_channels.drain(..) {
            let c = c.to_ascii_lowercase();
            if !is_hex64(&c) {
                return Err("muted_channels entries must be 64-char hex channel ids");
            }
            if seen.insert(c.clone()) {
                cleaned.push(c);
            }
        }
        if cleaned.len() > MAX_MUTED_CHANNELS {
            return Err("too many muted channels");
        }
        self.muted_channels = cleaned;
        if let Some(q) = self.quiet {
            if q.start_min >= 1440 || q.end_min >= 1440 {
                return Err("quiet hours must be minutes after midnight (0..1439)");
            }
            if !(-840..=840).contains(&q.tz_offset_min) {
                return Err("quiet hours tz_offset_min out of range");
            }
        }
        Ok(())
    }
}

pub fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PK_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const CHAN: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    // -- preferences ---------------------------------------------------------

    #[test]
    fn defaults_alert_for_replies_and_dms_only() {
        let p = PushPrefs::default();
        assert!(p.wants(Category::Dm, None, 0));
        assert!(p.wants(Category::Reply, Some(CHAN), 0));
        assert!(!p.wants(Category::Topic, Some(CHAN), 0));
        assert!(!p.wants(Category::Post, Some(CHAN), 0));
    }

    #[test]
    fn opt_in_categories_respect_channel_mutes_but_replies_do_not() {
        let p = PushPrefs {
            new_posts: true,
            new_topics: true,
            muted_channels: vec![CHAN.into()],
            ..PushPrefs::default()
        };
        assert!(!p.wants(Category::Post, Some(CHAN), 0), "muted channel");
        assert!(!p.wants(Category::Topic, Some(CHAN), 0), "muted channel");
        assert!(p.wants(Category::Post, Some(PK_A), 0));
        assert!(
            p.wants(Category::Reply, Some(CHAN), 0),
            "being addressed beats a mute"
        );
    }

    #[test]
    fn quiet_hours_suppress_every_category_including_across_midnight() {
        // 22:00-07:00 local, UTC+1. 23:30 UTC is 00:30 local -> quiet.
        let q = QuietHours {
            start_min: 22 * 60,
            end_min: 7 * 60,
            tz_offset_min: 60,
        };
        let p = PushPrefs {
            quiet: Some(q),
            ..PushPrefs::default()
        };
        let day = 86_400 * 100;
        assert!(!p.wants(Category::Dm, None, day + 23 * 3600 + 30 * 60));
        assert!(
            p.wants(Category::Dm, None, day + 12 * 3600),
            "13:00 local is awake"
        );
        assert!(q.contains(day + 5 * 3600), "06:00 local");
    }

    #[test]
    fn quiet_window_edges_and_negative_offsets() {
        let q = QuietHours {
            start_min: 60,
            end_min: 120,
            tz_offset_min: -300,
        };
        // 06:00 UTC = 01:00 local (UTC-5): start is inclusive, end exclusive.
        let day = 86_400 * 100;
        assert!(q.contains(day + 6 * 3600));
        assert!(q.contains(day + 6 * 3600 + 59 * 60));
        assert!(!q.contains(day + 7 * 3600));
        let empty = QuietHours {
            start_min: 600,
            end_min: 600,
            tz_offset_min: 0,
        };
        assert!(
            !empty.contains(day + 600 * 60),
            "empty window never suppresses"
        );
    }

    #[test]
    fn sanitize_normalises_and_rejects() {
        let mut p = PushPrefs {
            muted_channels: vec![CHAN.to_uppercase(), CHAN.into()],
            ..PushPrefs::default()
        };
        p.sanitize().unwrap();
        assert_eq!(
            p.muted_channels,
            vec![CHAN.to_string()],
            "lower-cased and de-duplicated"
        );

        let mut bad = PushPrefs {
            muted_channels: vec!["nope".into()],
            ..PushPrefs::default()
        };
        assert!(bad.sanitize().is_err());
        let mut many = PushPrefs {
            muted_channels: (0..=MAX_MUTED_CHANNELS)
                .map(|i| format!("{i:064x}"))
                .collect(),
            ..PushPrefs::default()
        };
        assert!(many.sanitize().is_err());
        let mut q = PushPrefs {
            quiet: Some(QuietHours {
                start_min: 1440,
                end_min: 0,
                tz_offset_min: 0,
            }),
            ..PushPrefs::default()
        };
        assert!(q.sanitize().is_err());
        let mut tz = PushPrefs {
            quiet: Some(QuietHours {
                start_min: 0,
                end_min: 60,
                tz_offset_min: 900,
            }),
            ..PushPrefs::default()
        };
        assert!(tz.sanitize().is_err());
    }

    #[test]
    fn prefs_json_round_trips_and_new_posts_defaults_off() {
        let p: PushPrefs =
            serde_json::from_str(r#"{"replies":true,"dms":false,"new_topics":true}"#).unwrap();
        assert!(!p.new_posts && p.muted_channels.is_empty() && p.quiet.is_none());
        assert_eq!(
            serde_json::from_str::<PushPrefs>(&serde_json::to_string(&p).unwrap()).unwrap(),
            p
        );
    }

    #[test]
    fn category_wire_names_are_stable() {
        let names: Vec<_> = [
            Category::Dm,
            Category::Reply,
            Category::Topic,
            Category::Post,
        ]
        .iter()
        .map(|c| c.as_str())
        .collect();
        assert_eq!(names, ["dm", "reply", "topic", "post"]);
        assert!(
            names.iter().all(|n| n.len() <= 32),
            "RFC 8030 Topic header limit"
        );
    }
}
