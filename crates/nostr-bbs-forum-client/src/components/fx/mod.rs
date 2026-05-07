//! Visual effects module with tiered rendering: WebGPU > Canvas2D > CSS-only.
//!
//! ADR-020: WebGPU fallback rendering. Detects hardware capabilities at startup
//! and provides the appropriate renderer via Leptos context.

pub mod css_hero;
pub mod reaction_burst;
pub mod webgpu_activity;
pub mod webgpu_hero;

use leptos::prelude::*;

/// Rendering tier, ordered by capability (highest first).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenderTier {
    /// Full GPU compute + render via WebGPU API.
    WebGPU,
    /// Canvas 2D software rasterisation (existing particle_canvas).
    Canvas2D,
    /// CSS-only ambient effects (prefers-reduced-motion or no canvas).
    CSSOnly,
}

/// Detect the best rendering tier for the current browser/device.
pub fn detect_render_tier() -> RenderTier {
    if prefers_reduced_motion() {
        return RenderTier::CSSOnly;
    }
    if has_webgpu() {
        return RenderTier::WebGPU;
    }
    RenderTier::Canvas2D
}

/// Check `prefers-reduced-motion: reduce` media query.
fn prefers_reduced_motion() -> bool {
    web_sys::window()
        .and_then(|w| {
            w.match_media("(prefers-reduced-motion: reduce)")
                .ok()
                .flatten()
        })
        .map(|mq| mq.matches())
        .unwrap_or(false)
}

/// Check whether `navigator.gpu` exists (WebGPU support).
fn has_webgpu() -> bool {
    web_sys::window()
        .map(|w| {
            js_sys::Reflect::get(&w, &"gpu".into())
                .map(|v| !v.is_undefined() && !v.is_null())
                .unwrap_or(false)
        })
        .unwrap_or(false)
}

/// Provide the render tier as Leptos context. Call once in App.
pub fn provide_render_tier() {
    let tier = RwSignal::new(detect_render_tier());
    provide_context(tier);
}

/// Consume the render tier from Leptos context.
pub fn use_render_tier() -> RwSignal<RenderTier> {
    expect_context()
}
