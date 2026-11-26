//! "Scan your sheet": sign in by pointing the camera at a sign-in sheet's QR
//! code, or by choosing a photo or screenshot of it.
//!
//! This exists for the iOS storage split. A home-screen app on iPhone/iPad
//! keeps storage separate from Safari (webkit.org/tracking-prevention), so a
//! key imported in Safari is absent in the installed app. Inside the app, the
//! member scans the same sheet once more. It works on every platform, and the
//! photo path covers members who received the sheet on the phone itself.
//!
//! Pipeline: `getUserMedia` (rear camera) → `<video playsinline muted>` →
//! every 200 ms one frame drawn to a canvas scaled to at most
//! [`MAX_DECODE_SIDE`] px → RGBA → [`qr_scan::decode_rgba`] (rqrr, in WASM).
//! A decoded payload must pass [`connect_link::parse_sheet_payload`] (this
//! forum's origin and base only, or a bare nsec). The key is then parked in
//! the one-shot slot and the member is sent to `/connect`, which asks before
//! replacing any other account on the device.
//!
//! Hygiene: camera tracks are stopped on success, cancel, unmount,
//! `visibilitychange` (hidden) and `pagehide`; `srcObject` is cleared and the
//! canvas wiped. Decoded payloads and frames are never logged.

use std::cell::RefCell;
use std::rc::Rc;

use gloo::events::EventListener;
use gloo::timers::callback::Interval;
use leptos::prelude::*;
use leptos_router::hooks::use_navigate;
use leptos_router::NavigateOptions;
use send_wrapper::SendWrapper;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;

use crate::app::base_href;
use crate::utils::connect_link::{self, PayloadError};
use crate::utils::qr_scan::{self, Decoded, MAX_DECODE_SIDE};

/// Largest photo accepted (bytes).
const MAX_FILE_BYTES: f64 = 20.0 * 1024.0 * 1024.0;
/// Largest decoded photo accepted (pixels), before scaling for the decoder.
const MAX_FILE_PIXELS: u64 = 60_000_000;
/// Longest side a chosen photo is scaled to for decoding.
const MAX_PHOTO_SIDE: u32 = 1280;
/// Frame interval while the camera is open.
const FRAME_MS: u32 = 200;

/// Live camera resources. Dropping it stops everything.
struct CameraSession {
    stream: web_sys::MediaStream,
    video: web_sys::HtmlVideoElement,
    _ticker: Interval,
    _hidden: EventListener,
    _pagehide: EventListener,
}

impl Drop for CameraSession {
    fn drop(&mut self) {
        stop_stream(&self.stream);
        self.video.set_src_object(None);
    }
}

fn stop_stream(stream: &web_sys::MediaStream) {
    for t in stream.get_tracks().iter() {
        if let Ok(track) = t.dyn_into::<web_sys::MediaStreamTrack>() {
            track.stop();
        }
    }
}

/// Shared, non-Send slot for the session (lives on the UI thread only).
type SessionSlot = Rc<RefCell<Option<CameraSession>>>;

fn scan_canvas() -> Option<(
    web_sys::HtmlCanvasElement,
    web_sys::CanvasRenderingContext2d,
)> {
    let canvas: web_sys::HtmlCanvasElement = web_sys::window()?
        .document()?
        .create_element("canvas")
        .ok()?
        .dyn_into()
        .ok()?;
    let opts = js_sys::Object::new();
    let _ = js_sys::Reflect::set(&opts, &"willReadFrequently".into(), &JsValue::TRUE);
    let ctx = canvas
        .get_context_with_context_options("2d", &opts)
        .ok()??
        .dyn_into::<web_sys::CanvasRenderingContext2d>()
        .ok()?;
    Some((canvas, ctx))
}

/// Read back the canvas and decode; wipes the canvas afterwards.
fn decode_canvas(
    canvas: &web_sys::HtmlCanvasElement,
    ctx: &web_sys::CanvasRenderingContext2d,
) -> Decoded {
    let (w, h) = (canvas.width(), canvas.height());
    if w == 0 || h == 0 {
        return Decoded::Nothing;
    }
    let out = match ctx.get_image_data(0.0, 0.0, f64::from(w), f64::from(h)) {
        Ok(img) => {
            let data = zeroize::Zeroizing::new(img.data().0);
            qr_scan::decode_rgba(&data, w as usize, h as usize)
        }
        Err(_) => Decoded::Nothing,
    };
    ctx.clear_rect(0.0, 0.0, f64::from(w), f64::from(h));
    out
}

/// User-facing scanner message for a refused or ambiguous code.
fn refusal_text(e: &PayloadError) -> String {
    e.to_string()
}

/// The scanner UI: an entry button that opens the camera on tap (never on
/// load, so no permission prompt appears unasked), plus the photo picker.
#[component]
pub fn SheetScanner() -> impl IntoView {
    let navigate = StoredValue::new(use_navigate());
    let open = RwSignal::new(false);
    let status = RwSignal::new(String::new());
    let video_ref = NodeRef::<leptos::html::Video>::new();
    let file_ref = NodeRef::<leptos::html::Input>::new();
    let session: StoredValue<SendWrapper<SessionSlot>> =
        StoredValue::new(SendWrapper::new(Rc::new(RefCell::new(None))));

    // Stop the camera at once, and drop the session (ticker and listeners)
    // on the next turn: `stop` can run inside the ticker's or a listener's
    // own callback, and a wasm-bindgen closure must not be freed while it
    // is executing.
    let stop = move || {
        let _ = open.try_set(false);
        let Some(slot) = session.try_with_value(|s| Rc::clone(s)) else {
            return;
        };
        if let Some(sess) = slot.borrow().as_ref() {
            stop_stream(&sess.stream);
            sess.video.set_src_object(None);
        }
        gloo::timers::callback::Timeout::new(0, move || {
            slot.borrow_mut().take();
        })
        .forget();
    };

    // A payload decoded from either path.
    let handle = move |decoded: Decoded| -> bool {
        match decoded {
            Decoded::Nothing => false,
            Decoded::Several => {
                status.set("Two different codes are in view. Show only the large code on your sign-in sheet.".into());
                false
            }
            Decoded::One(payload) => {
                let origin = web_sys::window()
                    .and_then(|w| w.location().origin().ok())
                    .unwrap_or_default();
                match connect_link::parse_sheet_payload(&payload, &origin, &base_href("")) {
                    Ok(key) => {
                        stop();
                        connect_link::stash(key);
                        navigate.with_value(|n| n("/connect", NavigateOptions::default()));
                        true
                    }
                    Err(e) => {
                        status.set(refusal_text(&e));
                        false
                    }
                }
            }
        }
    };

    let start_camera = move || {
        status.set("Starting the camera…".into());
        open.set(true);
        leptos::task::spawn_local(async move {
            let Some(media) = web_sys::window().and_then(|w| w.navigator().media_devices().ok())
            else {
                status.set("This browser can\u{2019}t use the camera here. Choose a photo of the code instead.".into());
                return;
            };
            let constraints = js_sys::Object::new();
            let video_c = js_sys::Object::new();
            let facing = js_sys::Object::new();
            let _ = js_sys::Reflect::set(&facing, &"ideal".into(), &"environment".into());
            let _ = js_sys::Reflect::set(&video_c, &"facingMode".into(), &facing);
            let _ = js_sys::Reflect::set(&constraints, &"video".into(), &video_c);
            let _ = js_sys::Reflect::set(&constraints, &"audio".into(), &JsValue::FALSE);
            let Ok(promise) = media.get_user_media_with_constraints(constraints.unchecked_ref())
            else {
                status.set(
                    "The camera isn\u{2019}t available. Choose a photo of the code instead.".into(),
                );
                return;
            };
            let stream: web_sys::MediaStream = match JsFuture::from(promise)
                .await
                .and_then(|s| s.dyn_into())
            {
                Ok(s) => s,
                Err(_) => {
                    status.set("Camera permission was refused. Allow the camera, or choose a photo of the code.".into());
                    open.set(false);
                    return;
                }
            };
            // The scanner may have been closed while permission was pending.
            let Some(video) = video_ref.get_untracked() else {
                stop_stream(&stream);
                return;
            };
            if !open.get_untracked() {
                stop_stream(&stream);
                return;
            }
            video.set_muted(true);
            let _ = video.set_attribute("playsinline", "");
            video.set_src_object(Some(&stream));
            let _ = video.play();
            status.set("Point the camera at the large code on your sheet.".into());

            let Some((canvas, ctx)) = scan_canvas() else {
                stop_stream(&stream);
                status.set("Scanning isn\u{2019}t supported in this browser.".into());
                return;
            };
            let v = video.clone();
            let ticker = Interval::new(FRAME_MS, move || {
                if v.ready_state() < 2 {
                    return;
                }
                let (w, h) =
                    qr_scan::scaled_dims(v.video_width(), v.video_height(), MAX_DECODE_SIDE);
                if w == 0 || h == 0 {
                    return;
                }
                canvas.set_width(w);
                canvas.set_height(h);
                if ctx
                    .draw_image_with_html_video_element_and_dw_and_dh(
                        &v,
                        0.0,
                        0.0,
                        f64::from(w),
                        f64::from(h),
                    )
                    .is_err()
                {
                    return;
                }
                handle(decode_canvas(&canvas, &ctx));
            });
            let doc = gloo::utils::document();
            let hidden = EventListener::new(&doc, "visibilitychange", move |_| {
                if gloo::utils::document().hidden() {
                    stop();
                    status.set(
                        "Camera paused. Tap \u{201c}Scan your sheet\u{201d} to try again.".into(),
                    );
                }
            });
            let pagehide = EventListener::new(&gloo::utils::window(), "pagehide", move |_| stop());
            session.with_value(|s| {
                *s.borrow_mut() = Some(CameraSession {
                    stream,
                    video,
                    _ticker: ticker,
                    _hidden: hidden,
                    _pagehide: pagehide,
                });
            });
        });
    };

    let on_file = move |_| {
        let Some(input) = file_ref.get_untracked() else {
            return;
        };
        let Some(file) = input.files().and_then(|f| f.get(0)) else {
            return;
        };
        // Clear the input so the same file can be chosen again, and so the
        // File object is not kept by the element.
        input.set_value("");
        if file.size() > MAX_FILE_BYTES {
            status.set("That picture is too large. Use a screenshot of the code instead.".into());
            return;
        }
        status.set("Reading the picture…".into());
        leptos::task::spawn_local(async move {
            let Some(window) = web_sys::window() else {
                return;
            };
            let Ok(promise) = window.create_image_bitmap_with_blob(&file) else {
                status.set("That file isn\u{2019}t a picture this browser can read.".into());
                return;
            };
            let Ok(bitmap) = JsFuture::from(promise)
                .await
                .and_then(|b| b.dyn_into::<web_sys::ImageBitmap>())
            else {
                status.set("That file isn\u{2019}t a picture this browser can read.".into());
                return;
            };
            let (bw, bh) = (bitmap.width(), bitmap.height());
            if u64::from(bw) * u64::from(bh) > MAX_FILE_PIXELS {
                bitmap.close();
                status
                    .set("That picture is too large. Use a screenshot of the code instead.".into());
                return;
            }
            let Some((canvas, ctx)) = scan_canvas() else {
                bitmap.close();
                return;
            };
            // Try a decoder-friendly size first, then the larger photo size
            // (a small code in a big photo needs the extra pixels).
            let mut result = Decoded::Nothing;
            for max in [MAX_DECODE_SIDE, MAX_PHOTO_SIDE] {
                let (w, h) = qr_scan::scaled_dims(bw, bh, max);
                canvas.set_width(w);
                canvas.set_height(h);
                if ctx
                    .draw_image_with_image_bitmap_and_dw_and_dh(
                        &bitmap,
                        0.0,
                        0.0,
                        f64::from(w),
                        f64::from(h),
                    )
                    .is_err()
                {
                    break;
                }
                result = decode_canvas(&canvas, &ctx);
                if result != Decoded::Nothing {
                    break;
                }
            }
            bitmap.close();
            if result == Decoded::Nothing {
                status.set("No code found in that picture. Try a clearer photo or screenshot of the large code.".into());
            } else {
                handle(result);
            }
        });
    };

    on_cleanup(stop);

    view! {
        <div class="space-y-3" data-testid="sheet-scanner">
            <Show
                when=move || open.get()
                fallback=move || view! {
                    <button
                        on:click=move |_| start_camera()
                        class="w-full flex items-center justify-center gap-2 bg-amber-500 hover:bg-amber-400 text-gray-900 font-semibold py-3 rounded-xl text-sm"
                        data-testid="scan-open"
                    >
                        <span aria-hidden="true">"📷"</span>
                        "Scan your sheet"
                    </button>
                }
            >
                <div class="relative rounded-xl overflow-hidden bg-black aspect-square">
                    <video node_ref=video_ref class="w-full h-full object-cover" playsinline=true muted=true data-testid="scan-video"></video>
                    // Aiming frame.
                    <div class="absolute inset-[12%] border-4 border-amber-400/80 rounded-xl pointer-events-none"></div>
                </div>
                <button
                    on:click=move |_| stop()
                    class="w-full border border-gray-600 text-gray-200 hover:bg-gray-700/50 py-2.5 rounded-xl text-sm"
                    data-testid="scan-cancel"
                >"Cancel"</button>
            </Show>
            <label class="block text-center text-xs text-gray-400">
                <span class="underline cursor-pointer hover:text-gray-200">"Or choose a photo or screenshot of the code"</span>
                <input
                    node_ref=file_ref
                    type="file"
                    accept="image/*"
                    class="sr-only"
                    on:change=on_file
                    data-testid="scan-file"
                />
            </label>
            <Show when=move || !status.get().is_empty()>
                <p class="text-sm text-gray-300 text-center" role="status" data-testid="scan-status">{move || status.get()}</p>
            </Show>
        </div>
    }
}
