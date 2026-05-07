//! Breadcrumb trail for hierarchical navigation.
//!
//! Renders a horizontal sequence of links separated by `">"` chevrons, using
//! the `.breadcrumb-nav` and `.breadcrumb-separator` CSS classes from `style.css`.
//! The last item is rendered as plain text (current page), while preceding items
//! are links. The first item optionally displays a home icon when its href is "/".

use leptos::prelude::*;
use leptos_router::components::A;

use crate::app::base_href;

/// A single breadcrumb segment.
#[derive(Clone, Debug)]
pub struct BreadcrumbItem {
    /// Display label for this segment.
    pub label: String,
    /// If `Some`, this segment is a navigable link. `None` means current page.
    pub href: Option<String>,
}

impl BreadcrumbItem {
    /// Create a linked breadcrumb item.
    pub fn link(label: impl Into<String>, href: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            href: Some(href.into()),
        }
    }

    /// Create a terminal (current-page) breadcrumb item.
    pub fn current(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            href: None,
        }
    }
}

fn home_icon() -> impl IntoView {
    view! {
        <svg class="w-3.5 h-3.5 inline-block mr-0.5" viewBox="0 0 24 24" fill="none"
             stroke="currentColor" stroke-width="2">
            <path d="M3 9.5L12 3l9 6.5V20a1 1 0 01-1 1H4a1 1 0 01-1-1V9.5z"
                stroke-linecap="round" stroke-linejoin="round"/>
            <polyline points="9 22 9 12 15 12 15 22"
                stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
    }
}

/// Breadcrumb navigation trail.
///
/// Renders items in a horizontally-scrollable row. The last item is styled as
/// the current page (white text, no link). Earlier items are gray links that
/// highlight amber on hover. A home icon is prepended when the first item
/// points to `"/"`.
#[component]
pub(crate) fn Breadcrumb(
    /// Ordered breadcrumb segments, from root to current page.
    items: Vec<BreadcrumbItem>,
) -> impl IntoView {
    let total = items.len();

    let entries: Vec<_> = items
        .into_iter()
        .enumerate()
        .map(|(idx, item)| {
            let is_last = idx == total - 1;
            let is_home = idx == 0 && item.href.as_deref() == Some("/");
            let label = item.label.clone();

            let segment = if is_last {
                // Current page — plain text, white
                view! {
                    <span class="text-white font-medium">{label}</span>
                }
                .into_any()
            } else if let Some(ref href) = item.href {
                let full_href = base_href(href);
                let show_home = is_home;
                view! {
                    <A href=full_href attr:class="text-gray-400 hover:text-amber-400 transition-colors">
                        {show_home.then(home_icon)}
                        {label}
                    </A>
                }
                .into_any()
            } else {
                view! {
                    <span class="text-gray-400">{label}</span>
                }
                .into_any()
            };

            let separator = if !is_last {
                Some(view! {
                    <span class="breadcrumb-separator">{"\u{203A}"}</span>
                })
            } else {
                None
            };

            view! {
                {segment}
                {separator}
            }
        })
        .collect();

    view! {
        <nav class="breadcrumb-nav scrollbar-none">
            {entries}
        </nav>
    }
}
