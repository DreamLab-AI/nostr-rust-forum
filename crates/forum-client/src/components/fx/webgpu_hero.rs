//! WebGPU hero background with automatic fallback to Canvas2D or CSS-only.
//!
//! The WebGPU path delegates to a JS module (`js/webgpu-particles.js`) for the
//! GPU pipeline. The Rust side handles lifecycle (init, resize, cleanup) via
//! wasm-bindgen JS interop.

use std::cell::Cell;
use std::rc::Rc;

use leptos::prelude::*;
use send_wrapper::SendWrapper;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::spawn_local;

use super::css_hero::CSSFallbackHero;
use super::{use_render_tier, RenderTier};
use crate::components::particle_canvas::ParticleCanvas;

// -- JS interop with the WebGPU particle module --------------------------------

#[wasm_bindgen(module = "/js/webgpu-particles.js")]
extern "C" {
    #[wasm_bindgen(js_name = initWebGPUParticles, catch)]
    async fn init_webgpu_particles(
        canvas: &web_sys::HtmlCanvasElement,
        particle_count: u32,
    ) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(js_name = destroyWebGPUParticles)]
    fn destroy_webgpu_particles(handle: &JsValue);
}

// -- Public component ----------------------------------------------------------

/// Hero background that auto-selects WebGPU, Canvas2D, or CSS-only rendering.
#[component]
pub fn WebGPUHero() -> impl IntoView {
    let tier = use_render_tier();

    view! {
        {move || match tier.get() {
            RenderTier::WebGPU => view! { <WebGPUCanvas /> }.into_any(),
            RenderTier::Canvas2D => view! { <ParticleCanvas /> }.into_any(),
            RenderTier::CSSOnly => view! { <CSSFallbackHero /> }.into_any(),
        }}
    }
}

// -- WebGPU canvas (internal) --------------------------------------------------

/// GPU-accelerated particle field via WebGPU compute + render.
#[component]
fn WebGPUCanvas() -> impl IntoView {
    let canvas_ref = NodeRef::<leptos::html::Canvas>::new();
    let started = Rc::new(Cell::new(false));
    // Store the JS handle for cleanup. Wrapped in SendWrapper for on_cleanup bounds.
    let handle: Rc<Cell<Option<JsValue>>> = Rc::new(Cell::new(None));
    let handle_cleanup = SendWrapper::new(handle.clone());

    Effect::new(move |_| {
        if started.get() {
            return;
        }
        let Some(el) = canvas_ref.get() else {
            return;
        };
        started.set(true);

        let canvas: web_sys::HtmlCanvasElement = el;
        let rect = canvas.get_bounding_client_rect();
        let w = rect.width();
        let h = rect.height();
        if w < 200.0 || h < 100.0 {
            return;
        }

        // Set canvas resolution (device pixel ratio)
        let dpr = web_sys::window()
            .map(|win| win.device_pixel_ratio())
            .unwrap_or(1.0);
        canvas.set_width((w * dpr) as u32);
        canvas.set_height((h * dpr) as u32);

        // Mobile-first particle budget
        let count: u32 = if w < 480.0 {
            32
        } else if w < 768.0 {
            56
        } else if w < 1280.0 {
            90
        } else {
            120
        };

        let handle_inner = handle.clone();
        spawn_local(async move {
            match init_webgpu_particles(&canvas, count).await {
                Ok(h) => {
                    if !h.is_null() && !h.is_undefined() {
                        handle_inner.set(Some(h));
                    } else {
                        web_sys::console::warn_1(
                            &"[WebGPUHero] WebGPU adapter unavailable, falling back".into(),
                        );
                    }
                }
                Err(e) => {
                    web_sys::console::warn_1(
                        &format!("[WebGPUHero] WebGPU init error: {:?}", e).into(),
                    );
                }
            }
        });
    });

    // Cleanup: destroy the WebGPU particle system
    on_cleanup(move || {
        let rc = &*handle_cleanup;
        if let Some(h) = rc.take() {
            destroy_webgpu_particles(&h);
        }
    });

    view! {
        <canvas
            node_ref=canvas_ref
            class="absolute inset-0 w-full h-full"
            style="z-index: 0;"
            aria-hidden="true"
        />
    }
}
