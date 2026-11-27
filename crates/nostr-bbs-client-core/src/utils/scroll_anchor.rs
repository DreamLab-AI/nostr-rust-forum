//! Keep the reader's place while history pages are added and evicted.
//!
//! A history page lands at one end of a list and the window evicts at the
//! other; either can change the height ABOVE what the reader is looking at
//! (a prepended page in a chat, evicted newest topics at the top of a topic
//! list). Rather than predict height deltas, [`capture`] notes one row on
//! screen (any element carrying `data-anchor-id`) and its position, and
//! [`restore`] scrolls by however far that row moved once the DOM has
//! updated. That is correct for any mix of insertions and removals, and it
//! composes with the browser's own scroll anchoring: if the browser already
//! kept the row in place, the measured move is zero.

use wasm_bindgen::JsCast;

/// One on-screen row and its top edge, in viewport pixels.
#[derive(Clone, Debug, PartialEq)]
pub struct Anchor {
    id: String,
    top: f64,
}

/// The first `[data-anchor-id]` row visible in `container` (or in the
/// window when `None`), with its current position.
pub fn capture(container: Option<&web_sys::Element>) -> Option<Anchor> {
    let window = web_sys::window()?;
    let document = window.document()?;
    let (view_top, view_bottom) = match container {
        Some(c) => {
            let r = c.get_bounding_client_rect();
            (r.top(), r.bottom())
        }
        None => (0.0, window.inner_height().ok()?.as_f64()?),
    };
    let nodes = match container {
        Some(c) => c.query_selector_all("[data-anchor-id]").ok()?,
        None => document.query_selector_all("[data-anchor-id]").ok()?,
    };
    for i in 0..nodes.length() {
        let Some(el) = nodes
            .item(i)
            .and_then(|n| n.dyn_into::<web_sys::Element>().ok())
        else {
            continue;
        };
        let r = el.get_bounding_client_rect();
        if r.bottom() > view_top && r.top() < view_bottom {
            let id = el.get_attribute("data-anchor-id")?;
            return Some(Anchor { id, top: r.top() });
        }
    }
    None
}

/// After the pending DOM update (a zero-delay timeout runs after Leptos's
/// render effects), scroll `container` (or the window) so the anchored row
/// is back where it was. A row that is gone (it should never be: eviction
/// happens far from the reader) leaves the scroll as it is.
pub fn restore(anchor: Anchor, container: Option<web_sys::HtmlElement>) {
    crate::utils::set_timeout_once(
        move || {
            let Some(document) = web_sys::window().and_then(|w| w.document()) else {
                return;
            };
            let selector = format!("[data-anchor-id=\"{}\"]", css_escape(&anchor.id));
            let Some(el) = document.query_selector(&selector).ok().flatten() else {
                return;
            };
            let moved = el.get_bounding_client_rect().top() - anchor.top;
            if moved.abs() < 0.5 {
                return;
            }
            match container {
                Some(c) => c.set_scroll_top(c.scroll_top() + moved.round() as i32),
                None => {
                    if let Some(w) = web_sys::window() {
                        w.scroll_by_with_x_and_y(0.0, moved);
                    }
                }
            }
        },
        0,
    );
}

/// Anchor ids are event ids (hex); anything else is reduced to the
/// characters an attribute selector can carry unquoted-safe.
fn css_escape(id: &str) -> String {
    id.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect()
}
