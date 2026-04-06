//! Activity visualization: network graph of channels with activity levels.
//!
//! P2 priority — simpler than the hero. Three render tiers:
//! - WebGPU: animated force-directed graph (future enhancement)
//! - Canvas2D: circle layout with pulsing nodes
//! - CSS-only: static grid of colored circles

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use leptos::prelude::*;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::JsCast;
use web_sys::CanvasRenderingContext2d;

use super::{use_render_tier, RenderTier};

/// Channel activity data point.
#[derive(Clone, Debug)]
pub struct ChannelActivity {
    pub name: String,
    pub level: f32, // 0.0 - 1.0
}

/// Activity visualization component with tiered rendering.
#[allow(dead_code)]
#[component]
pub fn WebGPUActivity(
    /// Reactive channel activity data: (name, activity_level 0..1).
    #[prop(into)]
    data: Signal<Vec<ChannelActivity>>,
) -> impl IntoView {
    let tier = use_render_tier();

    view! {
        {move || match tier.get() {
            RenderTier::WebGPU | RenderTier::Canvas2D => {
                view! { <CanvasActivityGraph data=data /> }.into_any()
            }
            RenderTier::CSSOnly => {
                view! { <CSSActivityGrid data=data /> }.into_any()
            }
        }}
    }
}

// -- Canvas2D circle-layout activity graph ------------------------------------

type AnimSlot = Rc<RefCell<Option<Closure<dyn FnMut(f64)>>>>;

#[component]
fn CanvasActivityGraph(
    #[prop(into)] data: Signal<Vec<ChannelActivity>>,
) -> impl IntoView {
    let canvas_ref = NodeRef::<leptos::html::Canvas>::new();
    let running = Arc::new(AtomicBool::new(true));
    let running_cleanup = running.clone();
    let started = Rc::new(Cell::new(false));

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
        if w < 100.0 || h < 100.0 {
            return;
        }

        let dpr = web_sys::window()
            .map(|win| win.device_pixel_ratio())
            .unwrap_or(1.0);
        canvas.set_width((w * dpr) as u32);
        canvas.set_height((h * dpr) as u32);

        let ctx = match canvas.get_context("2d") {
            Ok(Some(c)) => match c.dyn_into::<CanvasRenderingContext2d>() {
                Ok(c) => c,
                Err(_) => return,
            },
            _ => return,
        };
        let _ = ctx.scale(dpr, dpr);

        let ctx = Rc::new(ctx);
        let running_loop = running.clone();
        let anim_slot: AnimSlot = Rc::new(RefCell::new(None));
        let slot = anim_slot.clone();
        let last_t = Rc::new(Cell::new(0.0f64));

        let closure = Closure::wrap(Box::new(move |timestamp: f64| {
            if !running_loop.load(Ordering::Relaxed) {
                slot.borrow_mut().take();
                return;
            }

            let lt = last_t.get();
            let _dt = if lt > 0.0 {
                ((timestamp - lt) / 1000.0).min(0.05)
            } else {
                0.016
            };
            last_t.set(timestamp);

            let time = timestamp / 1000.0;
            let channels = data.get_untracked();

            // Clear
            ctx.clear_rect(0.0, 0.0, w, h);

            if channels.is_empty() {
                if let Some(ref cb) = *slot.borrow() {
                    if let Some(window) = web_sys::window() {
                        let _ =
                            window.request_animation_frame(cb.as_ref().unchecked_ref());
                    }
                }
                return;
            }

            let cx = w / 2.0;
            let cy = h / 2.0;
            let radius = w.min(h) * 0.35;
            let n = channels.len();

            // Draw connections first (lighter)
            for i in 0..n {
                let angle_i = (i as f64 / n as f64) * std::f64::consts::TAU - std::f64::consts::FRAC_PI_2;
                let xi = cx + angle_i.cos() * radius;
                let yi = cy + angle_i.sin() * radius;

                for j in (i + 1)..n {
                    let angle_j = (j as f64 / n as f64) * std::f64::consts::TAU
                        - std::f64::consts::FRAC_PI_2;
                    let xj = cx + angle_j.cos() * radius;
                    let yj = cy + angle_j.sin() * radius;

                    let avg_level =
                        (channels[i].level as f64 + channels[j].level as f64) / 2.0;
                    let alpha = avg_level * 0.15;

                    ctx.set_stroke_style_str(&format!("rgba(251,191,36,{})", alpha));
                    ctx.set_line_width(0.5);
                    ctx.begin_path();
                    ctx.move_to(xi, yi);
                    ctx.line_to(xj, yj);
                    ctx.stroke();
                }
            }

            // Draw nodes
            for (i, ch) in channels.iter().enumerate() {
                let angle =
                    (i as f64 / n as f64) * std::f64::consts::TAU - std::f64::consts::FRAC_PI_2;
                let x = cx + angle.cos() * radius;
                let y = cy + angle.sin() * radius;

                let level = ch.level as f64;
                let pulse = 0.8 + 0.2 * (time * 2.0 + i as f64 * 0.5).sin();
                let node_r = 4.0 + level * 12.0;

                // Glow
                let glow_alpha = level * 0.15 * pulse;
                ctx.set_fill_style_str(&format!("rgba(251,191,36,{})", glow_alpha));
                ctx.begin_path();
                let _ = ctx.arc(x, y, node_r * 3.0, 0.0, std::f64::consts::TAU);
                ctx.fill();

                // Core
                let core_alpha = 0.4 + level * 0.5 * pulse;
                ctx.set_fill_style_str(&format!("rgba(251,191,36,{})", core_alpha));
                ctx.begin_path();
                let _ = ctx.arc(x, y, node_r, 0.0, std::f64::consts::TAU);
                ctx.fill();

                // Label
                ctx.set_fill_style_str(&format!("rgba(209,213,219,{})", 0.6 + level * 0.3));
                ctx.set_font("10px Inter, system-ui, sans-serif");
                ctx.set_text_align("center");
                let _ = ctx.fill_text(&ch.name, x, y + node_r + 14.0);
            }

            // Schedule next
            if let Some(ref cb) = *slot.borrow() {
                if let Some(window) = web_sys::window() {
                    let _ = window.request_animation_frame(cb.as_ref().unchecked_ref());
                }
            }
        }) as Box<dyn FnMut(f64)>);

        if let Some(window) = web_sys::window() {
            let _ = window.request_animation_frame(closure.as_ref().unchecked_ref());
        }
        anim_slot.borrow_mut().replace(closure);
    });

    on_cleanup(move || {
        running_cleanup.store(false, Ordering::Relaxed);
    });

    view! {
        <canvas
            node_ref=canvas_ref
            class="w-full h-full"
            style="min-height: 200px;"
            aria-hidden="true"
        />
    }
}

// -- CSS-only grid fallback ---------------------------------------------------

#[component]
fn CSSActivityGrid(
    #[prop(into)] data: Signal<Vec<ChannelActivity>>,
) -> impl IntoView {
    view! {
        <div class="grid grid-cols-3 sm:grid-cols-4 gap-3 p-4">
            <For
                each=move || data.get()
                key=|ch| ch.name.clone()
                let:channel
            >
                {
                    let level = channel.level;
                    let opacity = 0.3 + level * 0.7;
                    let size = 24.0 + level * 24.0;
                    view! {
                        <div class="flex flex-col items-center gap-1">
                            <div
                                class="rounded-full bg-amber-500 animate-pulse"
                                style=format!(
                                    "width: {}px; height: {}px; opacity: {};",
                                    size, size, opacity,
                                )
                            />
                            <span class="text-xs text-gray-400 truncate max-w-[80px]">
                                {channel.name.clone()}
                            </span>
                        </div>
                    }
                }
            </For>
        </div>
    }
}
