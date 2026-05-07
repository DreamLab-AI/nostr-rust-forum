//! Virtual scrolling list for efficient rendering of large datasets.
//!
//! Only renders the visible items plus a configurable overscan buffer,
//! using spacer divs to maintain correct scrollbar height. Uses the
//! `.virtual-scroll` CSS class from `style.css`.

use leptos::prelude::*;

/// Default number of extra items rendered above and below the visible range.
const DEFAULT_OVERSCAN: usize = 5;

/// Virtual scrolling list that efficiently renders only visible items.
///
/// Given a total item count and a render callback, this component calculates
/// the visible range from `scrollTop` and only instantiates items within
/// that window (plus an overscan buffer). Spacer `div`s above and below
/// maintain the correct total scroll height.
///
/// # Props
///
/// - `total_items` - Total number of items in the list.
/// - `item_height` - Estimated height in pixels for each item.
/// - `container_height` - Height of the scrollable viewport in pixels.
/// - `render_item` - Callback `(index) -> View` for rendering each item.
/// - `overscan` - Number of extra items to render outside the visible area.
/// - `scroll_to` - Optional signal: set to an index to programmatically scroll.
#[allow(dead_code)]
#[component]
pub(crate) fn VirtualList(
    /// Total number of items in the list.
    total_items: Signal<usize>,
    /// Estimated height per item in pixels.
    #[prop(default = 48.0)]
    item_height: f64,
    /// Visible container height in pixels.
    #[prop(default = 600.0)]
    container_height: f64,
    /// Render callback: receives item index, returns view.
    render_item: Callback<usize, AnyView>,
    /// Number of extra items rendered outside visible area (above and below).
    #[prop(default = DEFAULT_OVERSCAN)]
    overscan: usize,
    /// Set this signal to scroll to a specific item index.
    #[prop(optional)]
    scroll_to: Option<RwSignal<Option<usize>>>,
) -> impl IntoView {
    let scroll_top = RwSignal::new(0.0f64);
    let container_ref = NodeRef::<leptos::html::Div>::new();

    // Calculate visible range from scroll position
    let visible_count = (container_height / item_height).ceil() as usize + 1;

    let start_idx = Memo::new(move |_| {
        let st = scroll_top.get();
        let total = total_items.get();
        let raw = (st / item_height).floor() as usize;
        let start = raw.saturating_sub(overscan);
        start.min(total)
    });

    let end_idx = Memo::new(move |_| {
        let total = total_items.get();
        let start_raw = (scroll_top.get() / item_height).floor() as usize;

        (start_raw + visible_count + overscan).min(total)
    });

    // Total scrollable height
    let total_height = Memo::new(move |_| {
        let total = total_items.get();
        (total as f64) * item_height
    });

    // Spacer height above visible items
    let top_spacer = Memo::new(move |_| (start_idx.get() as f64) * item_height);

    // Spacer height below visible items
    let bottom_spacer = Memo::new(move |_| {
        let total = total_items.get();
        let end = end_idx.get();
        ((total - end) as f64) * item_height
    });

    // Scroll event handler
    let on_scroll = move |_: leptos::ev::Event| {
        if let Some(el) = container_ref.get() {
            let html_el: web_sys::HtmlElement = el.into();
            let st = html_el.scroll_top() as f64;
            scroll_top.set(st);
        }
    };

    // Programmatic scroll-to-index
    if let Some(scroll_to_sig) = scroll_to {
        Effect::new(move |_| {
            if let Some(idx) = scroll_to_sig.get() {
                if let Some(el) = container_ref.get() {
                    let target_top = (idx as f64) * item_height;
                    let html_el: &web_sys::Element = &el;
                    let opts = web_sys::ScrollToOptions::new();
                    opts.set_top(target_top);
                    opts.set_behavior(web_sys::ScrollBehavior::Smooth);
                    html_el.scroll_to_with_scroll_to_options(&opts);
                }
                // Reset after scrolling
                scroll_to_sig.set(None);
            }
        });
    }

    let container_style = format!(
        "height: {}px; overflow-y: auto; position: relative;",
        container_height
    );

    view! {
        <div
            node_ref=container_ref
            class="virtual-scroll"
            style=container_style
            on:scroll=on_scroll
        >
            // Inner container with total height for scrollbar
            <div style=move || format!("height: {}px; position: relative;", total_height.get())>
                // Top spacer
                <div style=move || format!("height: {}px;", top_spacer.get()) />

                // Visible items
                {move || {
                    let s = start_idx.get();
                    let e = end_idx.get();
                    (s..e).map(|idx| {
                        let item_style = format!(
                            "height: {}px; box-sizing: border-box;",
                            item_height
                        );
                        view! {
                            <div style=item_style>
                                {render_item.run(idx)}
                            </div>
                        }
                    }).collect_view()
                }}

                // Bottom spacer
                <div style=move || format!("height: {}px;", bottom_spacer.get()) />
            </div>
        </div>
    }
}
