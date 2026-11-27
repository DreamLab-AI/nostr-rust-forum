//! Base-path helper shared across client modules.
//!
//! Compile-time `FORUM_BASE` (e.g. `"/community"` in production, `""` in local
//! development) prefixes app-relative paths for redirects, service-worker
//! assets, and sealed-search worker scripts.

/// Compile-time base URL prefix.
pub const FORUM_BASE: &str = match option_env!("FORUM_BASE") {
    Some(b) => b,
    None => "",
};

/// Build a full href by prepending `FORUM_BASE` to `path`.
pub fn base_href(path: &str) -> String {
    if FORUM_BASE.is_empty() {
        path.to_string()
    } else {
        format!("{}{}", FORUM_BASE, path)
    }
}
