//! Reaction burst effect: spawns emoji particles that burst outward on trigger.
//!
//! Pure CSS animations (transform + opacity) — works on all render tiers.
//! Each emoji gets a random angle and distance, animates for 800ms, then is
//! removed from the DOM.

use leptos::prelude::*;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::JsCast;

/// Burst of emoji particles triggered by a reactive signal.
///
/// When `trigger` transitions to `true`, spawns `particle_count` copies of
/// `emoji` that explode outward from the element's position and fade out.
#[component]
pub fn ReactionBurst(
    /// Signal that triggers the burst when it becomes `true`.
    #[prop(into)]
    trigger: Signal<bool>,
    /// Number of emoji particles to spawn (default 16).
    #[prop(default = 16)]
    particle_count: u32,
    /// The emoji character to burst.
    #[prop(into)]
    emoji: String,
) -> impl IntoView {
    let container_ref = NodeRef::<leptos::html::Div>::new();
    let emoji_stored = StoredValue::new(emoji);

    Effect::new(move |prev: Option<bool>| {
        let current = trigger.get();
        let was_false = prev.map(|p| !p).unwrap_or(true);

        // Fire only on false -> true transition
        if current && was_false {
            let Some(container) = container_ref.get() else {
                return current;
            };
            let container_el: web_sys::HtmlElement = container.into();

            let document = web_sys::window()
                .and_then(|w| w.document())
                .expect("document");

            let emoji_str = emoji_stored.get_value();

            for i in 0..particle_count {
                // Random angle evenly distributed + jitter
                let base_angle = (i as f64 / particle_count as f64) * std::f64::consts::TAU;
                let jitter = (js_sys::Math::random() - 0.5) * 0.4;
                let angle = base_angle + jitter;

                // Random distance 40-100px
                let dist = 40.0 + js_sys::Math::random() * 60.0;

                let tx = angle.cos() * dist;
                let ty = angle.sin() * dist;

                // Random rotation
                let rot = (js_sys::Math::random() - 0.5) * 360.0;

                // Create the emoji element
                let el = document.create_element("span").expect("create span");
                el.set_text_content(Some(&emoji_str));

                let style = format!(
                    "position:absolute;left:50%;top:50%;pointer-events:none;\
                     font-size:{}px;z-index:100;will-change:transform,opacity;\
                     animation:reaction-burst-anim 800ms ease-out forwards;\
                     --burst-tx:{}px;--burst-ty:{}px;--burst-rot:{}deg;",
                    12 + (js_sys::Math::random() * 8.0) as u32,
                    tx,
                    ty,
                    rot,
                );
                el.set_attribute("style", &style).ok();
                el.set_attribute("aria-hidden", "true").ok();

                container_el.append_child(&el).ok();

                // Remove element after animation completes (850ms for safety margin)
                let el_clone = el.clone();
                let cb = Closure::once(move || {
                    el_clone.remove();
                });
                web_sys::window()
                    .expect("window")
                    .set_timeout_with_callback_and_timeout_and_arguments_0(
                        cb.as_ref().unchecked_ref(),
                        850,
                    )
                    .ok();
                cb.forget(); // One-shot closure, small and bounded
            }
        }

        current
    });

    view! {
        <div
            node_ref=container_ref
            class="relative inline-block"
            style="position:relative;"
        />
    }
}
