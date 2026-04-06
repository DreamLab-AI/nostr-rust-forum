//! Pod API upload client with NIP-98 authentication.
//!
//! Uploads compressed images and thumbnails to the user's Solid pod via the
//! pod-api Cloudflare Worker. Each upload is authenticated with a NIP-98
//! `Authorization: Nostr <token>` header.

use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::Blob;

/// Default pod API URL (overridden by VITE_POD_API_URL at compile time).
const POD_API: &str = match option_env!("VITE_POD_API_URL") {
    Some(u) => u,
    None => "https://your-pods.your-subdomain.workers.dev",
};

/// Upload a blob to the user's public media folder on their Solid pod.
///
/// Returns the public URL of the uploaded file on success.
pub async fn upload_to_pod(
    blob: &Blob,
    filename: &str,
    pubkey: &str,
    privkey: &[u8; 32],
    pod_api_url: Option<&str>,
) -> Result<String, String> {
    let base_url = pod_api_url.unwrap_or(POD_API);
    let url = format!("{}/pods/{}/media/public/{}", base_url, pubkey, filename);

    // Read blob into bytes for NIP-98 payload hash
    let array_buf_promise = blob.array_buffer();
    let array_buf = JsFuture::from(array_buf_promise)
        .await
        .map_err(|e| format!("Blob read: {e:?}"))?;
    let bytes: Vec<u8> = js_sys::Uint8Array::new(&array_buf).to_vec();

    // Create NIP-98 auth token
    let token =
        crate::auth::nip98::create_nip98_token(privkey, &url, "POST", Some(&bytes))
            .map_err(|e| format!("NIP-98 error: {e}"))?;
    let auth_header = format!("Nostr {}", token);

    // POST to pod API
    let window = web_sys::window().ok_or("No window")?;
    let init = web_sys::RequestInit::new();
    init.set_method("POST");

    let headers = web_sys::Headers::new().map_err(|e| format!("{e:?}"))?;
    headers
        .set("Authorization", &auth_header)
        .map_err(|e| format!("{e:?}"))?;
    headers
        .set("Content-Type", "application/octet-stream")
        .map_err(|e| format!("{e:?}"))?;
    init.set_headers(&headers);
    init.set_body(&js_sys::Uint8Array::from(bytes.as_slice()).into());

    let req =
        web_sys::Request::new_with_str_and_init(&url, &init).map_err(|e| format!("{e:?}"))?;
    let resp_val = JsFuture::from(window.fetch_with_request(&req))
        .await
        .map_err(|e| format!("Fetch: {e:?}"))?;
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

    // Try JSON { "url": "..." } first, then plain text URL, then constructed URL
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

/// Upload both a compressed image and its thumbnail, returning (image_url, thumb_url).
pub async fn upload_image_with_thumbnail(
    image_blob: &Blob,
    thumb_blob: &Blob,
    filename: &str,
    pubkey: &str,
    privkey: &[u8; 32],
) -> Result<(String, String), String> {
    // Derive thumbnail filename
    let thumb_name = thumb_filename(filename);

    // Upload both sequentially (pod API may not handle concurrent writes well)
    let image_url = upload_to_pod(image_blob, filename, pubkey, privkey, None).await?;
    let thumb_url = upload_to_pod(thumb_blob, &thumb_name, pubkey, privkey, None).await?;

    Ok((image_url, thumb_url))
}

/// Generate a thumbnail filename from the original: "photo.jpg" -> "photo_thumb.jpg"
fn thumb_filename(filename: &str) -> String {
    if let Some(dot_pos) = filename.rfind('.') {
        format!("{}_thumb{}", &filename[..dot_pos], &filename[dot_pos..])
    } else {
        format!("{}_thumb", filename)
    }
}
