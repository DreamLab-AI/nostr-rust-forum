//! Client-side image compression and thumbnail generation using Canvas API.
//!
//! Uses `createImageBitmap` + offscreen `<canvas>` to resize and re-encode
//! images as JPEG blobs entirely in the browser, avoiding any server round-trip
//! for compression.

use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Blob, HtmlCanvasElement};

/// Default maximum dimension for compressed images (px).
const DEFAULT_MAX_DIM: u32 = 1920;

/// Default JPEG quality for compressed images (0.0 - 1.0).
const DEFAULT_QUALITY: f64 = 0.85;

/// Thumbnail dimension (px).
const THUMB_SIZE: u32 = 200;

/// Thumbnail JPEG quality.
const THUMB_QUALITY: f64 = 0.7;

/// Compress an image file by resizing to `max_dimension` and encoding as JPEG.
///
/// Maintains aspect ratio. If the image is already smaller than `max_dimension`,
/// it is still re-encoded at the target quality to reduce file size.
pub async fn compress_image(
    file: &web_sys::File,
    max_dimension: u32,
    quality: f64,
) -> Result<Blob, String> {
    resize_to_blob(file, max_dimension, quality).await
}

/// Compress with default settings (1920px max, 0.85 quality).
pub async fn compress_image_default(file: &web_sys::File) -> Result<Blob, String> {
    compress_image(file, DEFAULT_MAX_DIM, DEFAULT_QUALITY).await
}

/// Generate a small thumbnail (200px, 0.7 quality).
pub async fn generate_thumbnail(file: &web_sys::File) -> Result<Blob, String> {
    resize_to_blob(file, THUMB_SIZE, THUMB_QUALITY).await
}

/// Core resize logic: decode image -> scale on canvas -> export as JPEG blob.
async fn resize_to_blob(
    file: &web_sys::File,
    max_dim: u32,
    quality: f64,
) -> Result<Blob, String> {
    let window = web_sys::window().ok_or("No window")?;

    // 1. Decode File -> ImageBitmap via createImageBitmap
    let blob: &Blob = file.as_ref();
    let promise = window
        .create_image_bitmap_with_blob(blob)
        .map_err(|e| format!("createImageBitmap failed: {e:?}"))?;
    let bitmap_val = JsFuture::from(promise)
        .await
        .map_err(|e| format!("ImageBitmap await: {e:?}"))?;
    let bitmap: web_sys::ImageBitmap = bitmap_val
        .dyn_into()
        .map_err(|_| "Not an ImageBitmap".to_string())?;

    let orig_w = bitmap.width();
    let orig_h = bitmap.height();

    // 2. Calculate scaled dimensions maintaining aspect ratio
    let (target_w, target_h) = scale_dimensions(orig_w, orig_h, max_dim);

    // 3. Create offscreen canvas and draw scaled image
    let document = window.document().ok_or("No document")?;
    let canvas: HtmlCanvasElement = document
        .create_element("canvas")
        .map_err(|e| format!("createElement: {e:?}"))?
        .dyn_into()
        .map_err(|_| "Not a canvas".to_string())?;
    canvas.set_width(target_w);
    canvas.set_height(target_h);

    let ctx = canvas
        .get_context("2d")
        .map_err(|e| format!("getContext: {e:?}"))?
        .ok_or("No 2d context")?;
    let ctx: web_sys::CanvasRenderingContext2d = ctx
        .dyn_into()
        .map_err(|_| "Not CanvasRenderingContext2d".to_string())?;

    ctx.draw_image_with_image_bitmap_and_dw_and_dh(
        &bitmap,
        0.0,
        0.0,
        target_w as f64,
        target_h as f64,
    )
    .map_err(|e| format!("drawImage: {e:?}"))?;

    // 4. Export as JPEG blob via toBlob callback
    canvas_to_blob(&canvas, "image/jpeg", quality).await
}

/// Convert a canvas to a Blob via `toBlob()`, wrapped in a JS Promise for async.
async fn canvas_to_blob(
    canvas: &HtmlCanvasElement,
    mime_type: &str,
    quality: f64,
) -> Result<Blob, String> {
    let mime = mime_type.to_string();
    let canvas_ref = canvas.clone();

    let promise = js_sys::Promise::new(&mut move |resolve, reject| {
        let reject_clone = reject.clone();
        let callback = wasm_bindgen::closure::Closure::once(Box::new(move |blob: JsValue| {
            if blob.is_null() || blob.is_undefined() {
                let _ = reject_clone.call1(
                    &JsValue::NULL,
                    &JsValue::from_str("toBlob returned null"),
                );
            } else {
                let _ = resolve.call1(&JsValue::NULL, &blob);
            }
        }) as Box<dyn FnOnce(JsValue)>);

        if let Err(e) = canvas_ref.to_blob_with_type_and_encoder_options(
            callback.as_ref().unchecked_ref(),
            &mime,
            &JsValue::from_f64(quality),
        ) {
            let _ = reject.call1(&JsValue::NULL, &e);
        }

        callback.forget();
    });

    let result = JsFuture::from(promise)
        .await
        .map_err(|e| format!("toBlob: {e:?}"))?;

    result
        .dyn_into::<Blob>()
        .map_err(|_| "toBlob result not a Blob".to_string())
}

/// Scale dimensions to fit within `max_dim` while preserving aspect ratio.
/// If both dimensions are already within bounds, returns original dimensions.
fn scale_dimensions(width: u32, height: u32, max_dim: u32) -> (u32, u32) {
    if width <= max_dim && height <= max_dim {
        return (width, height);
    }
    let ratio = if width > height {
        max_dim as f64 / width as f64
    } else {
        max_dim as f64 / height as f64
    };
    let new_w = (width as f64 * ratio).round().max(1.0) as u32;
    let new_h = (height as f64 * ratio).round().max(1.0) as u32;
    (new_w, new_h)
}

/// Check if a file's MIME type is an accepted image format.
pub fn is_accepted_image(file: &web_sys::File) -> bool {
    let t = file.type_();
    matches!(
        t.as_str(),
        "image/jpeg" | "image/png" | "image/webp" | "image/gif"
    )
}

/// Maximum pre-compression file size in bytes (5 MB).
pub const MAX_FILE_SIZE: u64 = 5 * 1024 * 1024;
