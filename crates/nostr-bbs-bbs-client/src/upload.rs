//! Composer image upload (F10): client-side compression + validation, then a
//! NIP-98-authenticated `PUT` to the viewer's Solid pod.
//!
//! The compression/validation half is **copied** from the forum client
//! (`nostr-bbs-forum-client/src/utils/image_compress.rs`) and the pod upload is
//! **adapted** from that crate's `utils/pod_client.rs::upload_to_pod_signer` —
//! copied here rather than taking a path dependency on the whole Leptos forum
//! client, so the BBS keeps its small dependency surface (spec §5.2 gives this
//! choice; the workspace layout makes copying the cleaner option). The NIP-98
//! token is built through the shared `nostr_bbs_core::signer::Signer` trait, so
//! the BBS `BbsSigner` (in-memory `PrfSigner` or a NIP-07 extension) plugs
//! straight in with no new auth code.
//!
//! **`PUT` is load-bearing.** The pod-api Worker treats PUT as the primary
//! resource write and `solid-pod-rs` accepts *only* PUT for direct file URLs
//! (its POST is container-only, which previously 404'd) — see the forum client's
//! `pod_client.rs` header.

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::JsCast;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_futures::JsFuture;
#[cfg(target_arch = "wasm32")]
use web_sys::{Blob, HtmlCanvasElement};

/// Default maximum dimension for compressed images (px).
#[cfg(target_arch = "wasm32")]
const DEFAULT_MAX_DIM: u32 = 1920;
/// Default JPEG quality for compressed images (0.0–1.0).
#[cfg(target_arch = "wasm32")]
const DEFAULT_QUALITY: f64 = 0.85;
/// Thumbnail dimension (px).
#[cfg(target_arch = "wasm32")]
const THUMB_SIZE: u32 = 200;
/// Thumbnail JPEG quality.
#[cfg(target_arch = "wasm32")]
const THUMB_QUALITY: f64 = 0.7;

/// Maximum pre-compression file size in bytes (5 MB). Mirrors the forum client.
pub const MAX_FILE_SIZE: u64 = 5 * 1024 * 1024;

/// Whether a file's MIME type is an accepted image format (jpeg/png/webp/gif).
#[cfg(target_arch = "wasm32")]
pub fn is_accepted_image(file: &web_sys::File) -> bool {
    matches!(
        file.type_().as_str(),
        "image/jpeg" | "image/png" | "image/webp" | "image/gif"
    )
}

/// Compress + upload one image and return its public pod URL. Compresses to a
/// ≤1920 px JPEG (and a thumbnail, uploaded best-effort), then PUTs both to
/// `{pod_api}/pods/{pubkey}/media/public/…` with NIP-98 auth. wasm-only.
#[cfg(target_arch = "wasm32")]
pub async fn compress_and_upload(
    file: &web_sys::File,
    pubkey: &str,
    signer: &dyn nostr_bbs_core::signer::Signer,
    pod_api: &str,
) -> Result<String, String> {
    let blob = compress_image_default(file).await?;
    let now = js_sys::Date::now() as u64;
    let filename = format!("bbs-{now}.jpg");
    let url = upload_to_pod_signer(&blob, &filename, pubkey, signer, pod_api).await?;
    // Thumbnail is best-effort — the BBS renders the full image as ASCII, so a
    // failed thumbnail must not fail the post.
    if let Ok(thumb) = generate_thumbnail(file).await {
        let thumb_name = format!("bbs-{now}_thumb.jpg");
        let _ = upload_to_pod_signer(&thumb, &thumb_name, pubkey, signer, pod_api).await;
    }
    Ok(url)
}

/// Compress with default settings (1920 px max, 0.85 quality).
#[cfg(target_arch = "wasm32")]
pub async fn compress_image_default(file: &web_sys::File) -> Result<Blob, String> {
    resize_to_blob(file, DEFAULT_MAX_DIM, DEFAULT_QUALITY).await
}

/// Generate a small thumbnail (200 px, 0.7 quality).
#[cfg(target_arch = "wasm32")]
pub async fn generate_thumbnail(file: &web_sys::File) -> Result<Blob, String> {
    resize_to_blob(file, THUMB_SIZE, THUMB_QUALITY).await
}

/// Core resize: decode → scale on a canvas → export as a JPEG blob.
#[cfg(target_arch = "wasm32")]
async fn resize_to_blob(file: &web_sys::File, max_dim: u32, quality: f64) -> Result<Blob, String> {
    let window = web_sys::window().ok_or("No window")?;

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

    let (target_w, target_h) = scale_dimensions(bitmap.width(), bitmap.height(), max_dim);

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

    canvas_to_blob(&canvas, "image/jpeg", quality).await
}

/// Convert a canvas to a Blob via `toBlob()`, wrapped in a Promise for async.
#[cfg(target_arch = "wasm32")]
async fn canvas_to_blob(
    canvas: &HtmlCanvasElement,
    mime_type: &str,
    quality: f64,
) -> Result<Blob, String> {
    let mime = mime_type.to_string();
    let canvas_ref = canvas.clone();

    let promise = js_sys::Promise::new(&mut move |resolve, reject| {
        let reject_clone = reject.clone();
        let callback = Closure::once(Box::new(move |blob: JsValue| {
            if blob.is_null() || blob.is_undefined() {
                let _ =
                    reject_clone.call1(&JsValue::NULL, &JsValue::from_str("toBlob returned null"));
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

/// Scale dimensions to fit within `max_dim`, preserving aspect ratio.
#[cfg(target_arch = "wasm32")]
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

/// Build a NIP-98 `Authorization: Nostr <base64(signed 27235 event)>` header via
/// the `Signer` trait — mirrors the forum client's
/// `create_nip98_token_with_signer` (the BBS can't call that crate's `auth`
/// module, so the small builder is inlined here on top of `nostr_bbs_core`).
#[cfg(target_arch = "wasm32")]
async fn nip98_header(
    signer: &dyn nostr_bbs_core::signer::Signer,
    url: &str,
    method: &str,
    body: Option<&[u8]>,
) -> Result<String, String> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    use sha2::{Digest, Sha256};

    let now = (js_sys::Date::now() / 1000.0) as u64;
    let mut tags = vec![
        vec!["u".to_string(), url.to_string()],
        vec!["method".to_string(), method.to_string()],
    ];
    if let Some(bytes) = body {
        tags.push(vec!["payload".to_string(), hex::encode(Sha256::digest(bytes))]);
    }
    let unsigned = nostr_bbs_core::UnsignedEvent {
        pubkey: signer.public_key().to_string(),
        created_at: now,
        kind: 27235,
        tags,
        content: String::new(),
    };
    let signed = signer
        .sign_event(unsigned)
        .await
        .map_err(|e| format!("NIP-98 sign: {e}"))?;
    let json = serde_json::to_string(&signed).map_err(|e| format!("NIP-98 encode: {e}"))?;
    Ok(format!("Nostr {}", BASE64.encode(json.as_bytes())))
}

/// Upload a blob to the viewer's public pod media folder via `PUT` + NIP-98.
/// Returns the public URL on success. Adapted from the forum client's
/// `upload_to_pod_signer` (friendly errors, console detail retained).
#[cfg(target_arch = "wasm32")]
pub async fn upload_to_pod_signer(
    blob: &Blob,
    filename: &str,
    pubkey: &str,
    signer: &dyn nostr_bbs_core::signer::Signer,
    pod_api: &str,
) -> Result<String, String> {
    if pod_api.is_empty() {
        return Err("no pod configured".to_string());
    }
    let base = pod_api.trim_end_matches('/');
    let url = format!("{base}/pods/{pubkey}/media/public/{filename}");

    // Read the blob into bytes for the NIP-98 payload hash. A raw JsValue dump
    // is meaningless to a user, so surface friendly copy + log the detail.
    let array_buf = JsFuture::from(blob.array_buffer()).await.map_err(|e| {
        web_sys::console::error_1(&e);
        "could not read the image — please pick it again".to_string()
    })?;
    let bytes: Vec<u8> = js_sys::Uint8Array::new(&array_buf).to_vec();

    let auth_header = nip98_header(signer, &url, "PUT", Some(&bytes)).await?;

    let window = web_sys::window().ok_or("No window")?;
    let init = web_sys::RequestInit::new();
    init.set_method("PUT");
    let headers = web_sys::Headers::new().map_err(|e| format!("{e:?}"))?;
    headers
        .set("Authorization", &auth_header)
        .map_err(|e| format!("{e:?}"))?;
    headers
        .set("Content-Type", "application/octet-stream")
        .map_err(|e| format!("{e:?}"))?;
    init.set_headers(&headers);
    init.set_body(&js_sys::Uint8Array::from(bytes.as_slice()).into());

    let req = web_sys::Request::new_with_str_and_init(&url, &init).map_err(|e| format!("{e:?}"))?;
    let resp_val = JsFuture::from(window.fetch_with_request(&req))
        .await
        .map_err(|e| {
            web_sys::console::error_1(&e);
            "could not reach the media server — check your connection".to_string()
        })?;
    let resp: web_sys::Response = resp_val.unchecked_into();

    if !resp.ok() {
        let status = resp.status();
        if let Ok(tp) = resp.text() {
            if let Ok(t) = JsFuture::from(tp).await {
                if let Some(s) = t.as_string() {
                    return Err(format!("HTTP {status}: {s}"));
                }
            }
        }
        return Err(format!("HTTP {status}"));
    }

    let text_val = JsFuture::from(resp.text().map_err(|e| format!("{e:?}"))?)
        .await
        .map_err(|e| format!("{e:?}"))?;
    let body = text_val.as_string().unwrap_or_default();
    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&body) {
        if let Some(u) = parsed.get("url").and_then(|v| v.as_str()) {
            return Ok(u.to_string());
        }
    }
    if body.starts_with("http") {
        return Ok(body);
    }
    Ok(url)
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;

    #[test]
    fn max_file_size_is_five_megabytes() {
        assert_eq!(MAX_FILE_SIZE, 5 * 1024 * 1024);
    }
}
