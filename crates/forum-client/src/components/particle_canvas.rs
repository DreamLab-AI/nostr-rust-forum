//! Constellation particle field — WASM Canvas2D.
//!
//! Design DNA drawn (subtly) from:
//! - **Private** hero: concentric rings, ice-blue glow on deep navy
//! - **Nostr BBS** hero: node-edge constellation, ethereal sparkle
//! - **Main site Voronoi**: golden-angle math, slow deliberate motion
//!
//! Wired as a tech demo with graceful fallback:
//! - **Tier 1**: Canvas2D particle field (this module)
//! - **Tier 2**: CSS ambient effects (style.css `.ambient-*` classes)
//! - **Tier 3**: Static background (existing gray-900)
//!
//! The animation loop uses self-dropping `Closure` via `Rc<RefCell<Option<...>>>`
//! — NO `.forget()` calls. On cleanup, the running flag is set to false and the
//! next rAF callback breaks the Rc cycle by clearing its own slot.

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use leptos::prelude::*;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::JsCast;
use web_sys::CanvasRenderingContext2d;

/// Slot type for a self-dropping rAF animation closure.
type AnimSlot = Rc<RefCell<Option<Closure<dyn FnMut(f64)>>>>;

// -- Constants ----------------------------------------------------------------

/// Golden angle in radians: 360 * (1 - 1/phi) where phi = (1+sqrt5)/2.
const GOLDEN_ANGLE_RAD: f64 = 2.399_963_229_728_653;

/// phi itself — used for phase offsets so particles feel non-repeating.
const PHI: f64 = 1.618_033_988_749_895;

const TAU: f64 = std::f64::consts::TAU;

// -- Palette (from brand images, not too literal) -----------------------------

/// Amber-400: primary particle colour.
const AMBER: (f64, f64, f64) = (251.0, 191.0, 36.0);

/// Blue-300: cool accent (~15 % of particles). Nods to private ice-blue
/// and cool cyan without overwhelming the amber theme.
const ICE_BLUE: (f64, f64, f64) = (147.0, 197.0, 253.0);

// -- Data structures ----------------------------------------------------------

struct Particle {
    x: f64,
    y: f64,
    base_x: f64,
    base_y: f64,
    radius: f64,
    alpha: f64,
    phase: f64,
    accent: bool,
}

struct ParticleField {
    particles: Vec<Particle>,
    w: f64,
    h: f64,
    time: f64,
    conn_dist: f64,
    // Concentric ring pulse (vinyl-groove nod)
    ring_r: f64,
    ring_alpha: f64,
}

impl ParticleField {
    fn new(w: f64, h: f64, count: usize) -> Self {
        let cx = w / 2.0;
        let cy = h / 2.0;
        let max_r = w.min(h) * 0.44;

        let mut particles = Vec::with_capacity(count);
        for i in 0..count {
            let n = i as f64;
            let angle = n * GOLDEN_ANGLE_RAD;
            let r = max_r * (n / count as f64).sqrt(); // Fermat's spiral density

            let x = cx + r * angle.cos();
            let y = cy + r * angle.sin();

            particles.push(Particle {
                x,
                y,
                base_x: x,
                base_y: y,
                radius: 1.0 + (i % 3) as f64 * 0.6,
                alpha: 0.25 + (n / count as f64) * 0.55,
                phase: n * PHI,
                accent: (i % 7) == 3, // ~14 % get ice-blue accent
            });
        }

        Self {
            particles,
            w,
            h,
            time: 0.0,
            conn_dist: if w < 600.0 { 70.0 } else { 110.0 },
            ring_r: 0.0,
            ring_alpha: 0.5,
        }
    }

    fn update(&mut self, dt: f64) {
        self.time += dt;

        // Expand ring pulse (fades out over ~3 s)
        if self.ring_alpha > 0.0 {
            self.ring_r += dt * 180.0;
            self.ring_alpha -= dt * 0.17;
            if self.ring_alpha < 0.0 {
                self.ring_alpha = 0.0;
            }
        }

        // Global breathing: slow alpha oscillation
        let _breath = 0.85 + 0.15 * (self.time * 0.4).sin();

        for p in &mut self.particles {
            // Layered sinusoidal drift — mimics simplex noise cheaply.
            // Two octaves with phi-scaled frequencies give a non-repeating feel.
            let nx = (self.time * 0.25 + p.phase).sin() * 0.7
                + (self.time * 0.13 + p.phase * PHI).cos() * 0.35;
            let ny = (self.time * 0.21 + p.phase * 1.3).cos() * 0.7
                + (self.time * 0.17 + p.phase * 0.6).sin() * 0.35;

            let tx = p.base_x + nx * 18.0;
            let ty = p.base_y + ny * 18.0;

            // Ease toward target (spring)
            p.x += (tx - p.x) * 0.04;
            p.y += (ty - p.y) * 0.04;
        }
    }

    fn draw(&self, ctx: &CanvasRenderingContext2d) {
        ctx.clear_rect(0.0, 0.0, self.w, self.h);

        let breath = 0.85 + 0.15 * (self.time * 0.4).sin();
        let cd2 = self.conn_dist * self.conn_dist;

        // -- Connections (constellation lines) --------------------------------
        // Checking all pairs: O(n^2) but n <= 120 so ~7 K checks @ 60 fps.
        let particles = &self.particles;
        for i in 0..particles.len() {
            let pi = &particles[i];
            for pj in &particles[(i + 1)..] {
                let dx = pi.x - pj.x;
                let dy = pi.y - pj.y;
                let d2 = dx * dx + dy * dy;
                if d2 < cd2 {
                    let d = d2.sqrt();
                    let a = (1.0 - d / self.conn_dist) * 0.12 * breath;
                    // Mix colour: if either end is accent, line gets a blue tinge
                    let (r, g, b) = if pi.accent || pj.accent {
                        lerp_rgb(AMBER, ICE_BLUE, 0.35)
                    } else {
                        AMBER
                    };
                    set_stroke(ctx, r, g, b, a);
                    ctx.set_line_width(0.5);
                    ctx.begin_path();
                    ctx.move_to(pi.x, pi.y);
                    ctx.line_to(pj.x, pj.y);
                    ctx.stroke();
                }
            }
        }

        // -- Ring pulse -------------------------------------------------------
        if self.ring_alpha > 0.005 {
            let cx = self.w / 2.0;
            let cy = self.h / 2.0;

            // Primary ring: amber
            set_stroke(ctx, AMBER.0, AMBER.1, AMBER.2, self.ring_alpha * 0.25);
            ctx.set_line_width(1.5);
            ctx.begin_path();
            let _ = ctx.arc(cx, cy, self.ring_r, 0.0, TAU);
            ctx.stroke();

            // Secondary ring: ice-blue, trails behind
            if self.ring_r > 50.0 {
                let a2 = self.ring_alpha * 0.15;
                set_stroke(ctx, ICE_BLUE.0, ICE_BLUE.1, ICE_BLUE.2, a2);
                ctx.set_line_width(1.0);
                ctx.begin_path();
                let _ = ctx.arc(cx, cy, self.ring_r - 50.0, 0.0, TAU);
                ctx.stroke();
            }
        }

        // -- Particles --------------------------------------------------------
        for p in particles {
            let (r, g, b) = if p.accent { ICE_BLUE } else { AMBER };

            // Twinkle: oscillate alpha per particle
            let twinkle = 0.65 + 0.35 * (self.time * 1.3 + p.phase).sin();
            let a = p.alpha * twinkle * breath;

            // Soft outer glow (larger particles only)
            if p.radius > 1.2 {
                set_fill(ctx, r, g, b, a * 0.12);
                ctx.begin_path();
                let _ = ctx.arc(p.x, p.y, p.radius * 3.5, 0.0, TAU);
                ctx.fill();
            }

            // Core dot
            set_fill(ctx, r, g, b, a);
            ctx.begin_path();
            let _ = ctx.arc(p.x, p.y, p.radius, 0.0, TAU);
            ctx.fill();
        }
    }
}

// -- Helpers ------------------------------------------------------------------

#[inline]
fn set_fill(ctx: &CanvasRenderingContext2d, r: f64, g: f64, b: f64, a: f64) {
    ctx.set_fill_style_str(&format!("rgba({},{},{},{})", r as u8, g as u8, b as u8, a));
}

#[inline]
fn set_stroke(ctx: &CanvasRenderingContext2d, r: f64, g: f64, b: f64, a: f64) {
    ctx.set_stroke_style_str(&format!("rgba({},{},{},{})", r as u8, g as u8, b as u8, a));
}

#[inline]
fn lerp_rgb(a: (f64, f64, f64), b: (f64, f64, f64), t: f64) -> (f64, f64, f64) {
    (
        a.0 + (b.0 - a.0) * t,
        a.1 + (b.1 - a.1) * t,
        a.2 + (b.2 - a.2) * t,
    )
}

// -- Leptos Component ---------------------------------------------------------

/// Constellation particle canvas that sits behind hero content.
///
/// Falls back gracefully:
/// - Canvas2D unavailable → renders an empty `<div>`, CSS ambient takes over
/// - `prefers-reduced-motion` → draws a single static frame, no animation loop
/// - Very small viewport (< 200 px) → skips entirely
#[component]
pub fn ParticleCanvas() -> impl IntoView {
    let canvas_ref = NodeRef::<leptos::html::Canvas>::new();

    // Arc<AtomicBool> for the running flag — the ONLY thing shared with
    // on_cleanup. All Rc types stay inside the Effect where they compile fine.
    let running = Arc::new(AtomicBool::new(true));
    let running_for_cleanup = running.clone();

    // Guard against Effect re-firing (NodeRef resolves twice: None then Some).
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
        if w < 200.0 || h < 100.0 {
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

        // Mobile-first particle budget
        let count = if w < 480.0 {
            28
        } else if w < 768.0 {
            50
        } else if w < 1280.0 {
            80
        } else {
            110
        };

        let reduced_motion = web_sys::window()
            .and_then(|w| {
                w.match_media("(prefers-reduced-motion: reduce)")
                    .ok()
                    .flatten()
            })
            .map(|m: web_sys::MediaQueryList| m.matches())
            .unwrap_or(false);

        let field = Rc::new(RefCell::new(ParticleField::new(w, h, count)));

        if reduced_motion {
            // Static constellation — one frame, no loop
            field.borrow().draw(&ctx);
            return;
        }

        // -- Animation loop (no .forget()) ------------------------------------
        //
        // The Closure is stored in `anim_slot` (an Rc<RefCell>) and the closure
        // itself captures a clone of `anim_slot`. This creates an Rc cycle that
        // is broken when `running` becomes false: the next rAF callback calls
        // `slot.borrow_mut().take()`, dropping the closure and breaking the
        // cycle. If no rAF fires after on_cleanup (tab hidden), the browser
        // will resume it when the tab is re-foregrounded.
        let ctx = Rc::new(ctx);
        let running_loop = running.clone();
        let anim_slot: AnimSlot = Rc::new(RefCell::new(None));
        let slot = anim_slot.clone();
        let last_t = Rc::new(Cell::new(0.0f64));

        let closure = Closure::wrap(Box::new(move |timestamp: f64| {
            if !running_loop.load(Ordering::Relaxed) {
                // Break the Rc cycle: drop ourselves
                slot.borrow_mut().take();
                return;
            }

            let lt = last_t.get();
            let dt = if lt > 0.0 {
                ((timestamp - lt) / 1000.0).min(0.05)
            } else {
                0.016
            };
            last_t.set(timestamp);

            field.borrow_mut().update(dt);
            field.borrow().draw(&ctx);

            // Schedule next frame
            if let Some(ref cb) = *slot.borrow() {
                if let Some(window) = web_sys::window() {
                    let _ = window.request_animation_frame(cb.as_ref().unchecked_ref());
                }
            }
        }) as Box<dyn FnMut(f64)>);

        // Kick first frame
        if let Some(window) = web_sys::window() {
            let _ = window.request_animation_frame(closure.as_ref().unchecked_ref());
        }
        anim_slot.borrow_mut().replace(closure);
    });

    // Cleanup: signal stop. The next rAF callback will self-drop.
    on_cleanup(move || {
        running_for_cleanup.store(false, Ordering::Relaxed);
    });

    view! {
        <canvas
            node_ref=canvas_ref
            class="absolute inset-0 w-full h-full pointer-events-none"
            style="z-index: 0;"
            aria-hidden="true"
        />
    }
}
