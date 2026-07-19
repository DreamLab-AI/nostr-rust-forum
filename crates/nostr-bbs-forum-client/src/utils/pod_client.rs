//! Pod API upload client with NIP-98 authentication.
//!
//! Uploads compressed images and thumbnails to the user's Solid pod. Each
//! upload is authenticated with a NIP-98 `Authorization: Nostr <token>`
//! header and written with `PUT` — the Solid verb for creating/replacing a
//! resource at a known URL. Both backends accept it: the pod-api Cloudflare
//! Worker treats PUT as the primary resource write, and `solid-pod-rs`
//! accepts *only* PUT for direct file URLs (its POST is container-only, so
//! the previous POST-to-file upload 404'd against self-hosted pods).

use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::Blob;

/// Default pod API URL (overridden by VITE_POD_API_URL at compile time).
const POD_API: &str = match option_env!("VITE_POD_API_URL") {
    Some(u) => u,
    None => "https://pod.example.com",
};

/// Upload a blob to the user's public media folder on their Solid pod, using a
/// `Signer` for NIP-98 authentication. Returns the public URL on success.
///
/// Self-healing: an unprovisioned pod's WAC gate denies the write with 403
/// (deny-by-default) and a missing container yields 404. In either case the pod
/// is provisioned once and the upload retried, so a user whose eager signup
/// provisioning never happened (or 404'd against a bare `/.provision`) can still
/// upload without a manual step.
pub async fn upload_to_pod_signer(
    blob: &Blob,
    filename: &str,
    pubkey: &str,
    signer: &dyn nostr_bbs_core::signer::Signer,
    pod_api_url: Option<&str>,
) -> Result<String, String> {
    let base_url = pod_api_url.unwrap_or(POD_API);
    match put_blob_signer(blob, filename, pubkey, signer, base_url).await {
        Err(e) if e.starts_with("HTTP 403") || e.starts_with("HTTP 404") => {
            provision_pod_signer(pubkey, signer, base_url).await?;
            put_blob_signer(blob, filename, pubkey, signer, base_url).await
        }
        other => other,
    }
}

/// Provision the caller's pod on the pod-worker (`POST /pods/{pubkey}/.provision`,
/// NIP-98 authed — a bare `/.provision` is 404). 201 = created, 409 = already
/// exists; both are success.
pub async fn provision_pod_signer(
    pubkey: &str,
    signer: &dyn nostr_bbs_core::signer::Signer,
    base_url: &str,
) -> Result<(), String> {
    let url = format!("{}/pods/{}/.provision", base_url, pubkey);
    let token = crate::auth::nip98::create_nip98_token_with_signer(signer, &url, "POST", None)
        .await
        .map_err(|e| format!("NIP-98 error: {e}"))?;
    let window = web_sys::window().ok_or("No window")?;
    let init = web_sys::RequestInit::new();
    init.set_method("POST");
    let headers = web_sys::Headers::new().map_err(|e| format!("{e:?}"))?;
    headers
        .set("Authorization", &format!("Nostr {token}"))
        .map_err(|e| format!("{e:?}"))?;
    init.set_headers(&headers);
    let req = web_sys::Request::new_with_str_and_init(&url, &init).map_err(|e| format!("{e:?}"))?;
    let resp_val = JsFuture::from(window.fetch_with_request(&req))
        .await
        .map_err(|e| {
            web_sys::console::error_1(&e);
            "Could not reach the media server — check your connection.".to_string()
        })?;
    let resp: web_sys::Response = resp_val.unchecked_into();
    match resp.status() {
        201 | 409 => Ok(()),
        s => Err(format!("pod provisioning failed: HTTP {s}")),
    }
}

/// The single PUT of a blob to the pod media path. `upload_to_pod_signer` wraps
/// this with the provision-and-retry recovery above.
async fn put_blob_signer(
    blob: &Blob,
    filename: &str,
    pubkey: &str,
    signer: &dyn nostr_bbs_core::signer::Signer,
    base_url: &str,
) -> Result<String, String> {
    let url = format!("{}/pods/{}/media/public/{}", base_url, pubkey, filename);

    // Read blob into bytes for NIP-98 payload hash. A raw JsValue debug dump
    // here (e.g. `NotFoundError`) is meaningless to a user, so surface a
    // friendly message and log the underlying detail to the console (#16).
    let array_buf_promise = blob.array_buffer();
    let array_buf = JsFuture::from(array_buf_promise).await.map_err(|e| {
        web_sys::console::error_1(&e);
        "Could not read the selected file — please choose it again.".to_string()
    })?;
    let bytes: Vec<u8> = js_sys::Uint8Array::new(&array_buf).to_vec();

    // Create NIP-98 auth token via signer
    let token =
        crate::auth::nip98::create_nip98_token_with_signer(signer, &url, "PUT", Some(&bytes))
            .await
            .map_err(|e| format!("NIP-98 error: {e}"))?;
    let auth_header = format!("Nostr {}", token);
    let content_type = media_content_type(blob, filename);

    // PUT to pod API
    let window = web_sys::window().ok_or("No window")?;
    let init = web_sys::RequestInit::new();
    init.set_method("PUT");

    let headers = web_sys::Headers::new().map_err(|e| format!("{e:?}"))?;
    headers
        .set("Authorization", &auth_header)
        .map_err(|e| format!("{e:?}"))?;
    headers
        .set("Content-Type", &content_type)
        .map_err(|e| format!("{e:?}"))?;
    init.set_headers(&headers);
    init.set_body(&js_sys::Uint8Array::from(bytes.as_slice()).into());

    let req = web_sys::Request::new_with_str_and_init(&url, &init).map_err(|e| format!("{e:?}"))?;
    // A network-layer failure (offline, DNS, CORS) rejects the fetch promise
    // with an opaque JsValue — give the user something actionable and keep the
    // detail in the console (#16).
    let resp_val = JsFuture::from(window.fetch_with_request(&req))
        .await
        .map_err(|e| {
            web_sys::console::error_1(&e);
            "Could not reach the media server — check your connection.".to_string()
        })?;
    let resp: web_sys::Response = resp_val.unchecked_into();

    if !resp.ok() {
        let status = resp.status();
        if let Ok(tp) = resp.text() {
            if let Ok(t) = JsFuture::from(tp).await {
                if let Some(s) = t.as_string() {
                    return Err(format!("HTTP {}: {}", status, s));
                }
            }
        }
        return Err(format!("HTTP {}", status));
    }

    // Parse response for the final URL
    let text_promise = resp.text().map_err(|e| format!("{e:?}"))?;
    let text_val = JsFuture::from(text_promise)
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

/// Upload both a compressed image and its thumbnail via `Signer`, returning (image_url, thumb_url).
pub async fn upload_image_with_thumbnail_signer(
    image_blob: &Blob,
    thumb_blob: &Blob,
    filename: &str,
    pubkey: &str,
    signer: &dyn nostr_bbs_core::signer::Signer,
) -> Result<(String, String), String> {
    let thumb_name = thumb_filename(filename);
    let image_url = upload_to_pod_signer(image_blob, filename, pubkey, signer, None).await?;
    let thumb_url = upload_to_pod_signer(thumb_blob, &thumb_name, pubkey, signer, None).await?;
    Ok((image_url, thumb_url))
}

/// Resolve the media `Content-Type` to send on upload. Prefer the blob's own
/// MIME (the browser sets it from the picked file), falling back to the file
/// extension. A correct `image/*` type matters: the pod-worker stores and serves
/// exactly what we PUT, and it also emits `X-Content-Type-Options: nosniff` — so
/// an `application/octet-stream` image is refused by `<img>` and skipped by the
/// BBS ASCII-art transform (which only fires on `image/*`). Uploading the real
/// type is what makes posted images and avatars actually render.
fn media_content_type(blob: &Blob, filename: &str) -> String {
    let bt = blob.type_();
    if !bt.is_empty() && bt != "application/octet-stream" {
        return bt;
    }
    let ext = filename.rsplit('.').next().unwrap_or("").to_lowercase();
    match ext.as_str() {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "webp" => "image/webp",
        "gif" => "image/gif",
        "avif" => "image/avif",
        "svg" => "image/svg+xml",
        "bmp" => "image/bmp",
        _ => "application/octet-stream",
    }
    .to_string()
}

/// Generate a thumbnail filename from the original: "photo.jpg" -> "photo_thumb.jpg"
fn thumb_filename(filename: &str) -> String {
    if let Some(dot_pos) = filename.rfind('.') {
        format!("{}_thumb{}", &filename[..dot_pos], &filename[dot_pos..])
    } else {
        format!("{}_thumb", filename)
    }
}
