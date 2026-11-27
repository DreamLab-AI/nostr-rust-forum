//! Shared freshness vocabulary for cached, fetched-once-and-shown data.
//!
//! Anything the client fetches and then renders for a while — the agent
//! register, a user's badge awards — has an age, and that age is part of what
//! the rendering means. A badge derived from a five-minute-old snapshot is a
//! different claim from one derived from a snapshot taken now, and a view that
//! cannot say which is showing the reader something it does not know.
//!
//! Two primitives, both pure and both used by every surface that caches:
//! [`is_stale`] draws the bounded window, [`relative_age`] says the age in
//! words. Keeping them here means one definition of "stale" and one phrasing
//! across the app rather than a per-component reinvention.

/// Whether a snapshot taken at `as_of` has passed its freshness window.
///
/// A clock-skewed future timestamp counts as fresh rather than wrapping into a
/// nonsensical age.
pub fn is_stale(as_of: f64, now: f64, ttl_secs: f64) -> bool {
    now - as_of > ttl_secs
}

/// Age of a snapshot in plain words: "just now", "4 minutes ago", "2 days ago".
///
/// `None` means no snapshot has ever been taken, which is phrased as "never
/// checked" rather than an age — the difference matters, because "never" is
/// what a total fetch failure looks like.
pub fn relative_age(as_of: Option<f64>, now: f64) -> String {
    let Some(t) = as_of else {
        return "never checked".to_string();
    };
    // Clamped: a clock skew must never render as a negative age.
    let secs = (now - t).max(0.0);
    if secs < 45.0 {
        return "just now".to_string();
    }
    let mins = (secs / 60.0).round() as i64;
    if mins < 60 {
        return format!("{mins} minute{} ago", plural(mins));
    }
    let hours = (secs / 3600.0).round() as i64;
    if hours < 24 {
        return format!("{hours} hour{} ago", plural(hours));
    }
    let days = (secs / 86_400.0).round() as i64;
    format!("{days} day{} ago", plural(days))
}

fn plural(n: i64) -> &'static str {
    if n == 1 {
        ""
    } else {
        "s"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: f64 = 1_000_000.0;

    #[test]
    fn within_the_window_is_fresh() {
        assert!(!is_stale(NOW - 10.0, NOW, 300.0));
        assert!(!is_stale(NOW - 300.0, NOW, 300.0), "boundary must be fresh");
    }

    #[test]
    fn past_the_window_is_stale() {
        assert!(is_stale(NOW - 301.0, NOW, 300.0));
    }

    #[test]
    fn a_future_timestamp_is_fresh_not_stale() {
        assert!(!is_stale(NOW + 500.0, NOW, 300.0));
    }

    #[test]
    fn no_snapshot_reads_as_never_checked() {
        assert_eq!(relative_age(None, NOW), "never checked");
    }

    #[test]
    fn ages_read_as_plain_words() {
        assert_eq!(relative_age(Some(NOW), NOW), "just now");
        assert_eq!(relative_age(Some(NOW - 44.0), NOW), "just now");
        assert_eq!(relative_age(Some(NOW - 60.0), NOW), "1 minute ago");
        assert_eq!(relative_age(Some(NOW - 600.0), NOW), "10 minutes ago");
        assert_eq!(relative_age(Some(NOW - 3600.0), NOW), "1 hour ago");
        assert_eq!(relative_age(Some(NOW - 7200.0), NOW), "2 hours ago");
        assert_eq!(relative_age(Some(NOW - 86_400.0), NOW), "1 day ago");
        assert_eq!(relative_age(Some(NOW - 259_200.0), NOW), "3 days ago");
    }

    #[test]
    fn a_future_timestamp_does_not_produce_a_negative_age() {
        assert_eq!(relative_age(Some(NOW + 500.0), NOW), "just now");
    }
}
