//! The 3D poker table: a Three.js scene of the same seat view and log the DOM
//! table renders, for members who switch it on (Settings is not involved: the
//! table page carries the toggle, stored as `poker_table_3d`).
//!
//! The scene lives in `js/table3d/` and three.js in `assets/vendor/`; neither
//! is loaded until this component mounts. The seam is the wasm-bindgen
//! snippet `js/table3d.js`, which dynamic-imports the scene and passes JSON
//! strings both ways, as `js/poker-table.js` does for the engine: Rust holds
//! one opaque handle and never a JavaScript object graph.
//!
//! The view stays authoritative. The scene animates the log entries it has
//! not yet shown and reports `busy` while it does, so the page can hold the
//! action buttons until the river has landed. Anything the scene cannot do —
//! no GPU backend, a failed start, a lost device — reports back as
//! [`Table3dStatus::Failed`], and the page shows the DOM table, which is
//! always rendered anyway as the accessible text layer.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use leptos::prelude::*;
use send_wrapper::SendWrapper;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::components::fx::RenderTier;
use crate::poker::{LogEntry, SeatView};

// -- JS interop with the scene -------------------------------------------------

#[wasm_bindgen(module = "/js/table3d.js")]
extern "C" {
    #[wasm_bindgen(js_name = table3dInit, catch)]
    async fn table3d_init(
        canvas: &web_sys::HtmlCanvasElement,
        opts_json: &str,
    ) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(js_name = table3dUpdate)]
    fn table3d_update(handle: &JsValue, frame_json: &str) -> String;

    #[wasm_bindgen(js_name = table3dSetOptions)]
    fn table3d_set_options(handle: &JsValue, opts_json: &str) -> String;

    #[wasm_bindgen(js_name = table3dOnEvent)]
    fn table3d_on_event(handle: &JsValue, cb: &Closure<dyn FnMut(String)>);

    #[wasm_bindgen(js_name = table3dDispose)]
    fn table3d_dispose(handle: &JsValue);
}

/// The closure the scene calls with each event, kept alive beside the handle.
type EventListener = Closure<dyn FnMut(String)>;

// -- Pure helpers ----------------------------------------------------------------

/// The GPU API the scene starts on. three's `WebGPURenderer` drives both; the
/// WebGL 2 backend is its `forceWebGL` mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Backend {
    /// WebGPU.
    #[serde(rename = "webgpu")]
    WebGpu,
    /// WebGL 2.
    #[serde(rename = "webgl")]
    WebGl,
}

impl Backend {
    /// The backend's name as the scene reports it: `webgpu` or `webgl`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WebGpu => "webgpu",
            Self::WebGl => "webgl",
        }
    }

    /// Read a backend name from the scene; `None` for anything else.
    pub fn parse(s: &str) -> Option<Self> {
        [Self::WebGpu, Self::WebGl]
            .into_iter()
            .find(|b| b.as_str() == s)
    }

    /// A label for people: `WebGPU`, `WebGL 2`.
    pub fn label(self) -> &'static str {
        match self {
            Self::WebGpu => "WebGPU",
            Self::WebGl => "WebGL 2",
        }
    }
}

/// The backend for the app's render tier: WebGPU where the hero probed it,
/// WebGL 2 on the canvas tier when the browser has it, and nothing on the
/// CSS-only tier (reduced motion, or no canvas worth driving), where the DOM
/// table stays.
pub fn choose_backend(tier: RenderTier, webgl2: bool) -> Option<Backend> {
    match tier {
        RenderTier::WebGPU => Some(Backend::WebGpu),
        RenderTier::Canvas2D if webgl2 => Some(Backend::WebGl),
        RenderTier::Canvas2D | RenderTier::CSSOnly => None,
    }
}

/// Whether the browser exposes WebGL 2 at all. A cheap global check, not a
/// context: a blocklisted GPU still fails at init, and init failure falls
/// back to the DOM table.
pub fn has_webgl2() -> bool {
    web_sys::window()
        .and_then(|w| js_sys::Reflect::get(&w, &"WebGL2RenderingContext".into()).ok())
        .is_some_and(|v| !v.is_undefined() && !v.is_null())
}

/// The backend this browser offers the 3D table, if any.
pub fn available_backend(tier: RenderTier) -> Option<Backend> {
    choose_backend(tier, has_webgl2())
}

/// One frame for the scene: what the table shows now and how it got there.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Frame<'a> {
    /// Changes from one hand to the next (the shuffle's seed or commitment):
    /// two hands can show identical views, so the view alone cannot say a new
    /// hand began.
    pub hand_key: &'a str,
    /// The seat view, exactly as the engine serialises it.
    pub view: &'a SeatView,
    /// The hand's whole log so far.
    pub log: &'a [LogEntry],
}

/// The JSON frame the scene's `update` takes.
pub fn frame_json(hand_key: &str, view: &SeatView, log: &[LogEntry]) -> String {
    serde_json::to_string(&Frame {
        hand_key,
        view,
        log,
    })
    .unwrap_or_else(|_| "null".to_string())
}

/// What the scene starts with.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InitOptions {
    /// The GPU API to start on.
    pub backend: Backend,
    /// `auto`, `low` or `high`: real-time shadows and bumped felt, or not.
    pub quality: &'static str,
    /// Animate with short crossfades instead of motion.
    pub reduced_motion: bool,
    /// The four-colour deck (green clubs, blue diamonds).
    pub four_colour: bool,
    /// Let touch drag the camera (the page then stops scrolling under it).
    pub free_look: bool,
}

/// The options that change while the table is up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LiveOptions {
    /// As [`InitOptions::reduced_motion`].
    pub reduced_motion: bool,
    /// As [`InitOptions::four_colour`].
    pub four_colour: bool,
    /// As [`InitOptions::free_look`].
    pub free_look: bool,
}

/// What a tap on the table landed on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PickTarget {
    /// The hero's own hole cards.
    HeroCards,
    /// The pot in the middle.
    Pot,
    /// The hero's stack.
    Stack,
    /// The other seat: its cards, its stack, or the rail in front of it.
    Seat,
}

/// A tap on the table: what, and whose (`None` for the pot).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pick {
    /// The thing tapped.
    pub target: PickTarget,
    /// The engine seat it belongs to.
    pub seat: Option<u32>,
}

/// An event from the scene.
#[derive(Debug, Clone, PartialEq)]
pub enum Table3dEvent {
    /// Started; the backend actually in use (WebGPU can fall back on its own).
    Ready(Backend),
    /// Animating log entries the member has not seen yet (true), or settled.
    Busy(bool),
    /// A tap on something worth a tap.
    Pick(Pick),
    /// The adaptive pixel ratio moved to this value.
    Quality(f64),
    /// The GPU device or context was lost; the scene has stopped.
    Lost(String),
    /// Something failed inside the scene.
    Error(String),
}

#[derive(Deserialize)]
struct RawEvent {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    backend: Option<String>,
    #[serde(default)]
    value: Option<bool>,
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    seat: Option<u32>,
    #[serde(default)]
    dpr: Option<f64>,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

/// Read one event the scene sent; `None` for anything unrecognised.
pub fn parse_event(json: &str) -> Option<Table3dEvent> {
    let raw: RawEvent = serde_json::from_str(json).ok()?;
    Some(match raw.kind.as_str() {
        "ready" => Table3dEvent::Ready(Backend::parse(raw.backend.as_deref()?)?),
        "busy" => Table3dEvent::Busy(raw.value?),
        "pick" => Table3dEvent::Pick(Pick {
            target: match raw.target.as_deref()? {
                "heroCards" => PickTarget::HeroCards,
                "pot" => PickTarget::Pot,
                "stack" => PickTarget::Stack,
                "seat" => PickTarget::Seat,
                _ => return None,
            },
            seat: raw.seat,
        }),
        "quality" => Table3dEvent::Quality(raw.dpr?),
        "lost" => Table3dEvent::Lost(raw.reason.unwrap_or_default()),
        "error" => Table3dEvent::Error(raw.error.unwrap_or_default()),
        _ => return None,
    })
}

/// Read the `{"error": …}` a seam call returned, if it was one.
pub fn seam_error(reply: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(reply).ok()?;
    v.get("error")?.as_str().map(str::to_string)
}

/// Where the scene stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Table3dStatus {
    /// Loading three.js and compiling the scene.
    Loading,
    /// Drawing, on this backend.
    Ready(Backend),
    /// It could not start, or stopped: the DOM table shows instead.
    Failed(String),
}

impl Table3dStatus {
    /// Whether the 3D table is drawing.
    pub fn is_ready(&self) -> bool {
        matches!(self, Self::Ready(_))
    }

    /// Whether the 3D table gave up.
    pub fn is_failed(&self) -> bool {
        matches!(self, Self::Failed(_))
    }
}

/// Whether the OS asks for reduced motion.
fn os_reduced_motion() -> bool {
    web_sys::window()
        .and_then(|w| {
            w.match_media("(prefers-reduced-motion: reduce)")
                .ok()
                .flatten()
        })
        .is_some_and(|mq| mq.matches())
}

// -- The component ---------------------------------------------------------------

/// The 3D table over a canvas, with its DOM labels pinned to the scene.
///
/// `frame` is the JSON from [`frame_json`] (or `None` for an empty table);
/// `busy` and `status` are written by the component for the page to read.
/// `four_colour` and `free_look` may change while the table is up.
#[component]
pub fn Table3d(
    /// The frame to show.
    #[prop(into)]
    frame: Signal<Option<String>>,
    /// The backend to start on (from [`available_backend`]).
    backend: Backend,
    /// Set while the scene animates entries the member has not seen.
    busy: RwSignal<bool>,
    /// Where the scene stands.
    status: RwSignal<Table3dStatus>,
    /// The hero's label.
    #[prop(into)]
    near_name: Signal<String>,
    /// The other seat's label.
    #[prop(into)]
    far_name: Signal<String>,
    /// The chip unit printed after amounts: `chips`, `DREAM`.
    unit: &'static str,
    /// The four-colour deck.
    #[prop(into)]
    four_colour: Signal<bool>,
    /// Touch may orbit the camera.
    #[prop(into)]
    free_look: Signal<bool>,
    /// Called when the member taps something on the table.
    #[prop(optional)]
    on_pick: Option<Callback<Pick>>,
) -> impl IntoView {
    let prefs = crate::stores::preferences::use_preferences();
    let reduced = Memo::new(move |_| prefs.with(|p| p.reduced_motion) || os_reduced_motion());

    let canvas_ref = NodeRef::<leptos::html::Canvas>::new();
    let handle: Rc<RefCell<Option<JsValue>>> = Rc::new(RefCell::new(None));
    let listener: Rc<RefCell<Option<EventListener>>> = Rc::new(RefCell::new(None));
    let disposed = Rc::new(Cell::new(false));
    let started = Rc::new(Cell::new(false));
    status.set(Table3dStatus::Loading);

    // Start once the canvas is in the document.
    {
        let handle = handle.clone();
        let listener = listener.clone();
        let disposed = disposed.clone();
        Effect::new(move |_| {
            if started.get() {
                return;
            }
            let Some(canvas) = canvas_ref.get() else {
                return;
            };
            started.set(true);
            let opts = InitOptions {
                backend,
                quality: "auto",
                reduced_motion: reduced.get_untracked(),
                four_colour: four_colour.get_untracked(),
                free_look: free_look.get_untracked(),
            };
            let opts = serde_json::to_string(&opts).unwrap_or_else(|_| "{}".into());
            let handle = handle.clone();
            let listener = listener.clone();
            let disposed = disposed.clone();
            spawn_local(async move {
                match table3d_init(&canvas, &opts).await {
                    Ok(h) if disposed.get() => table3d_dispose(&h),
                    Ok(h) => {
                        let cb =
                            Closure::<dyn FnMut(String)>::new(
                                move |json: String| match parse_event(&json) {
                                    Some(Table3dEvent::Ready(b)) => {
                                        status.try_set(Table3dStatus::Ready(b));
                                    }
                                    Some(Table3dEvent::Busy(v)) => {
                                        busy.try_set(v);
                                    }
                                    Some(Table3dEvent::Pick(p)) => {
                                        if let Some(f) = on_pick {
                                            f.run(p);
                                        }
                                    }
                                    Some(Table3dEvent::Lost(reason)) => {
                                        busy.try_set(false);
                                        status.try_set(Table3dStatus::Failed(
                                            if reason.is_empty() {
                                                "the GPU device was lost".into()
                                            } else {
                                                format!("the GPU device was lost ({reason})")
                                            },
                                        ));
                                    }
                                    Some(Table3dEvent::Error(e)) => {
                                        web_sys::console::warn_1(&format!("[Table3d] {e}").into());
                                    }
                                    Some(Table3dEvent::Quality(_)) | None => {}
                                },
                            );
                        table3d_on_event(&h, &cb);
                        *listener.borrow_mut() = Some(cb);
                        // `null` too: an empty table is a frame, so the
                        // first hand dealt is animated rather than snapped to
                        let json = frame.get_untracked().unwrap_or_else(|| "null".into());
                        report(&table3d_update(&h, &json));
                        *handle.borrow_mut() = Some(h);
                    }
                    Err(e) => {
                        let msg = e
                            .as_string()
                            .map(|s| seam_error(&s).unwrap_or(s))
                            .unwrap_or_else(|| "the 3D table could not start".into());
                        web_sys::console::warn_1(&format!("[Table3d] init failed: {msg}").into());
                        busy.try_set(false);
                        status.try_set(Table3dStatus::Failed(msg));
                    }
                }
            });
        });
    }

    // Every new frame goes to the scene once it is up.
    {
        let handle = handle.clone();
        Effect::new(move |_| {
            let json = frame.get().unwrap_or_else(|| "null".into());
            if let Some(h) = handle.borrow().as_ref() {
                report(&table3d_update(h, &json));
            }
        });
    }

    // Live options.
    {
        let handle = handle.clone();
        Effect::new(move |_| {
            let live = LiveOptions {
                reduced_motion: reduced.get(),
                four_colour: four_colour.get(),
                free_look: free_look.get(),
            };
            if let Some(h) = handle.borrow().as_ref() {
                if let Ok(json) = serde_json::to_string(&live) {
                    report(&table3d_set_options(h, &json));
                }
            }
        });
    }

    let cleanup = SendWrapper::new((handle, listener, disposed));
    on_cleanup(move || {
        let (handle, listener, disposed) = &*cleanup;
        disposed.set(true);
        if let Some(h) = handle.borrow_mut().take() {
            table3d_dispose(&h);
        }
        // after dispose: the scene has dropped its listeners, so nothing can
        // call the closure once it is freed
        listener.borrow_mut().take();
        busy.try_set(false);
    });

    let loading = move || matches!(status.get(), Table3dStatus::Loading);

    view! {
        <div class="t3d-stage">
            <canvas node_ref=canvas_ref class="t3d-canvas" aria-hidden="true"></canvas>
            <div data-t3d-overlay="" class="t3d-overlay" aria-hidden="true">
                <div data-t3d-anchor="far-seat" class="t3d-tag">
                    <span class="t3d-name">{move || far_name.get()}</span>
                    <span class="t3d-num"><span data-t3d-field="far-stack"></span>" "{unit}</span>
                </div>
                <div data-t3d-anchor="near-seat" class="t3d-tag">
                    <span class="t3d-name">{move || near_name.get()}</span>
                    <span class="t3d-num"><span data-t3d-field="near-stack"></span>" "{unit}</span>
                </div>
                <div data-t3d-anchor="far-bet" class="t3d-amount"><span data-t3d-field="far-bet"></span></div>
                <div data-t3d-anchor="near-bet" class="t3d-amount"><span data-t3d-field="near-bet"></span></div>
                <div data-t3d-anchor="pot" class="t3d-amount t3d-pot">"Pot "<span data-t3d-field="pot"></span></div>
            </div>
            <Show when=loading>
                <div class="t3d-veil">
                    <span class="loading-ring"></span>
                    <span class="text-xs text-gray-400">"Setting the table…"</span>
                </div>
            </Show>
        </div>
    }
}

/// Log a seam call's `{"error": …}` reply; the table carries on.
fn report(reply: &str) {
    if let Some(e) = seam_error(reply) {
        web_sys::console::warn_1(&format!("[Table3d] {e}").into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VIEW_SHOWDOWN: &str = include_str!("../poker/testdata/view_showdown.json");
    const HAND_SHOWDOWN: &str = include_str!("../poker/testdata/hand_showdown.json");

    #[test]
    fn backend_follows_the_render_tier() {
        assert_eq!(
            choose_backend(RenderTier::WebGPU, false),
            Some(Backend::WebGpu)
        );
        assert_eq!(
            choose_backend(RenderTier::WebGPU, true),
            Some(Backend::WebGpu)
        );
        assert_eq!(
            choose_backend(RenderTier::Canvas2D, true),
            Some(Backend::WebGl)
        );
        assert_eq!(choose_backend(RenderTier::Canvas2D, false), None);
        assert_eq!(choose_backend(RenderTier::CSSOnly, true), None);
        for b in [Backend::WebGpu, Backend::WebGl] {
            assert_eq!(Backend::parse(b.as_str()), Some(b));
            assert_eq!(
                serde_json::to_string(&b).unwrap(),
                format!("\"{}\"", b.as_str())
            );
        }
        assert_eq!(Backend::parse("vulkan"), None);
        assert_eq!(Backend::WebGl.label(), "WebGL 2");
    }

    #[test]
    fn frame_carries_the_engine_shapes_verbatim() {
        let view: SeatView = serde_json::from_str(VIEW_SHOWDOWN).unwrap();
        let hand: serde_json::Value = serde_json::from_str(HAND_SHOWDOWN).unwrap();
        let log: Vec<LogEntry> = serde_json::from_value(hand["log"].clone()).unwrap();
        let json = frame_json("k1", &view, &log);
        let back: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(back["handKey"], "k1");
        // the scene reads the view exactly as the engine wrote it
        let orig: serde_json::Value = serde_json::from_str(VIEW_SHOWDOWN).unwrap();
        assert_eq!(back["view"], orig);
        assert_eq!(back["log"], hand["log"]);
        assert_eq!(back["view"]["toAct"], -1);
        assert_eq!(back["log"][0]["ev"], "sb");
    }

    #[test]
    fn options_serialise_for_the_scene() {
        let o = InitOptions {
            backend: Backend::WebGl,
            quality: "auto",
            reduced_motion: true,
            four_colour: false,
            free_look: true,
        };
        let v: serde_json::Value = serde_json::to_value(&o).unwrap();
        assert_eq!(v["backend"], "webgl");
        assert_eq!(v["reducedMotion"], true);
        assert_eq!(v["fourColour"], false);
        assert_eq!(v["freeLook"], true);
        let l = LiveOptions {
            reduced_motion: false,
            four_colour: true,
            free_look: false,
        };
        assert_eq!(
            serde_json::to_string(&l).unwrap(),
            r#"{"reducedMotion":false,"fourColour":true,"freeLook":false}"#
        );
    }

    #[test]
    fn events_parse_and_junk_does_not() {
        assert_eq!(
            parse_event(r#"{"type":"ready","backend":"webgpu","tier":"high"}"#),
            Some(Table3dEvent::Ready(Backend::WebGpu))
        );
        assert_eq!(
            parse_event(r#"{"type":"busy","value":true}"#),
            Some(Table3dEvent::Busy(true))
        );
        assert_eq!(
            parse_event(r#"{"type":"pick","target":"pot","seat":null}"#),
            Some(Table3dEvent::Pick(Pick {
                target: PickTarget::Pot,
                seat: None
            }))
        );
        assert_eq!(
            parse_event(r#"{"type":"pick","target":"seat","seat":1}"#),
            Some(Table3dEvent::Pick(Pick {
                target: PickTarget::Seat,
                seat: Some(1)
            }))
        );
        assert_eq!(
            parse_event(r#"{"type":"quality","dpr":1.25}"#),
            Some(Table3dEvent::Quality(1.25))
        );
        assert_eq!(
            parse_event(r#"{"type":"lost","reason":"destroyed"}"#),
            Some(Table3dEvent::Lost("destroyed".into()))
        );
        assert_eq!(
            parse_event(r#"{"type":"error","error":"x"}"#),
            Some(Table3dEvent::Error("x".into()))
        );
        for junk in [
            "",
            "null",
            r#"{"type":"ready","backend":"metal"}"#,
            r#"{"type":"busy"}"#,
            r#"{"type":"pick","target":"felt"}"#,
            r#"{"type":"teleport"}"#,
        ] {
            assert_eq!(parse_event(junk), None, "{junk}");
        }
        assert_eq!(
            seam_error(r#"{"error":"bad frame"}"#).as_deref(),
            Some("bad frame")
        );
        assert_eq!(seam_error("null"), None);
        assert!(Table3dStatus::Ready(Backend::WebGl).is_ready());
        assert!(Table3dStatus::Failed(String::new()).is_failed());
        assert!(!Table3dStatus::Loading.is_ready());
    }
}
