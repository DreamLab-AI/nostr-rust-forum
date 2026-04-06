//! Nostr BBS pod-api Worker (Rust)
//!
//! Per-user Solid pod storage backed by R2 + KV, with NIP-98 authentication,
//! WAC (Web Access Control) enforcement, LDP container support, ACL CRUD,
//! pod provisioning, WebID profile management, remoteStorage compatibility,
//! and Solid Notifications (webhooks).
//!
//! Port of `workers/pod-api/index.ts`.

mod acl;
mod auth;
mod conditional;
mod container;
mod content_negotiation;
mod notifications;
mod patch;
mod provision;
mod quota;
mod remote_storage;
mod webid;

use acl::{evaluate_access, find_effective_acl, method_to_mode, wac_allow_header, AccessMode};
use worker::*;

/// Maximum request body size: 50 MB.
const MAX_BODY_SIZE: u64 = 50 * 1024 * 1024;

/// Regex-equivalent pattern for pod routes: `/pods/{64 hex chars}{optional path}`.
/// We parse manually instead of pulling in `regex` to keep the WASM binary small.
fn parse_pod_route(path: &str) -> Option<(&str, &str)> {
    let rest = path.strip_prefix("/pods/")?;
    if rest.len() < 64 {
        return None;
    }
    let (pubkey, remainder) = rest.split_at(64);
    // Validate hex characters
    if !pubkey.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    // Remainder must be empty or start with '/'
    if !remainder.is_empty() && !remainder.starts_with('/') {
        return None;
    }
    let resource_path = if remainder.is_empty() { "/" } else { remainder };
    Some((pubkey, resource_path))
}

/// Check whether a resource path targets an `.acl` sidecar document.
fn is_acl_path(path: &str) -> bool {
    path.ends_with(".acl")
}

/// Check whether a resource path targets the pod provisioning endpoint.
fn is_provision_path(path: &str) -> bool {
    path == "/.provision"
}

/// Map a `worker::Method` enum to its string name.
fn method_str(m: &Method) -> &'static str {
    match m {
        Method::Get => "GET",
        Method::Head => "HEAD",
        Method::Post => "POST",
        Method::Put => "PUT",
        Method::Delete => "DELETE",
        Method::Options => "OPTIONS",
        Method::Patch => "PATCH",
        Method::Connect => "CONNECT",
        Method::Trace => "TRACE",
        _ => "GET",
    }
}

/// Build CORS headers from the `EXPECTED_ORIGIN` env var.
fn cors_headers(env: &Env) -> Headers {
    let origin = env
        .var("EXPECTED_ORIGIN")
        .map(|v| v.to_string())
        .unwrap_or_else(|_| "https://example.com".to_string());

    let headers = Headers::new();
    headers.set("Access-Control-Allow-Origin", &origin).ok();
    headers
        .set(
            "Access-Control-Allow-Methods",
            "GET, PUT, POST, DELETE, PATCH, HEAD, OPTIONS",
        )
        .ok();
    headers
        .set(
            "Access-Control-Allow-Headers",
            "Content-Type, Authorization, Slug, If-Match, If-None-Match, Range",
        )
        .ok();
    headers.set("Access-Control-Max-Age", "86400").ok();
    headers
        .set(
            "Access-Control-Expose-Headers",
            "ETag, Accept-Ranges, Content-Range, Link, Location, WAC-Allow",
        )
        .ok();
    headers
}

/// Append LDP Link headers and ACL link to a response.
///
/// For non-`.acl` resources, includes `Link: <{path}.acl>; rel="acl"`.
fn add_ldp_headers(headers: &Headers, is_container: bool, resource_path: &str) {
    let mut link_parts = Vec::new();

    if is_container {
        link_parts.push(
            "<http://www.w3.org/ns/ldp#BasicContainer>; rel=\"type\"".to_string(),
        );
        link_parts.push("<http://www.w3.org/ns/ldp#Resource>; rel=\"type\"".to_string());
    } else {
        link_parts.push("<http://www.w3.org/ns/ldp#Resource>; rel=\"type\"".to_string());
    }

    // Add rel="acl" link for non-.acl resources
    if !is_acl_path(resource_path) {
        let acl_link = format!("<{resource_path}.acl>; rel=\"acl\"");
        link_parts.push(acl_link);
    }

    headers.set("Link", &link_parts.join(", ")).ok();
    headers.set("Accept-Ranges", "bytes").ok();
}

/// Add WAC-Allow header to a response.
fn add_wac_allow(
    headers: &Headers,
    acl_doc: Option<&acl::AclDocument>,
    agent_uri: Option<&str>,
    resource_path: &str,
) {
    let value = wac_allow_header(acl_doc, agent_uri, resource_path);
    headers.set("WAC-Allow", &value).ok();
}

/// Create a JSON error response with CORS headers.
fn json_error(env: &Env, message: &str, status: u16) -> Result<Response> {
    let body = serde_json::json!({ "error": message });
    let json_str = serde_json::to_string(&body).map_err(|e| Error::RustError(e.to_string()))?;
    let cors = cors_headers(env);
    let resp = Response::ok(json_str)?
        .with_status(status)
        .with_headers(cors);
    resp.headers().set("Content-Type", "application/json").ok();
    Ok(resp)
}

/// Create a JSON success response with CORS headers.
fn json_ok(env: &Env, body: &serde_json::Value, status: u16) -> Result<Response> {
    let json_str = serde_json::to_string(body).map_err(|e| Error::RustError(e.to_string()))?;
    let cors = cors_headers(env);
    let resp = Response::ok(json_str)?
        .with_status(status)
        .with_headers(cors);
    resp.headers().set("Content-Type", "application/json").ok();
    Ok(resp)
}

#[event(fetch)]
async fn fetch(mut req: Request, env: Env, _ctx: Context) -> Result<Response> {
    // CORS preflight
    if req.method() == Method::Options {
        return Ok(Response::empty()?
            .with_status(204)
            .with_headers(cors_headers(&env)));
    }

    let url = req.url()?;
    let path = url.path();

    // Health check
    if path == "/health" {
        return json_ok(
            &env,
            &serde_json::json!({
                "status": "ok",
                "service": "pod-api",
                "runtime": "workers-rs",
                "version": "6.0.0",
                "features": [
                    "ldp-containers",
                    "conditional-requests",
                    "quota",
                    "webid",
                    "acl-crud",
                    "pod-provisioning",
                    "wac-allow",
                    "jsonld-native",
                    "content-negotiation",
                    "remote-storage",
                    "solid-notifications",
                    "webfinger",
                    "nip-05"
                ]
            }),
            200,
        );
    }

    // -------------------------------------------------------------------
    // .well-known discovery endpoints (federation-ready, Stream 12)
    // -------------------------------------------------------------------

    // WebFinger: remoteStorage + Solid + ActivityPub discovery
    if path == "/.well-known/webfinger" {
        let resource = url
            .query_pairs()
            .find(|(k, _)| k == "resource")
            .map(|(_, v)| v.to_string())
            .unwrap_or_default();
        if let Some(pk) = remote_storage::parse_webfinger_resource(&resource) {
            let host = url.host_str().unwrap_or("your-domain.com");
            let pod_base = format!("https://{host}");
            let body = remote_storage::webfinger_response(&pk, host, &pod_base);
            let json_str = serde_json::to_string(&body)
                .map_err(|e| Error::RustError(e.to_string()))?;
            let cors = cors_headers(&env);
            let resp = Response::ok(json_str)?.with_headers(cors);
            resp.headers()
                .set("Content-Type", "application/jrd+json")
                .ok();
            return Ok(resp);
        }
        return json_error(&env, "Invalid resource parameter", 400);
    }

    // Solid discovery metadata
    if path == "/.well-known/solid" {
        let host = url.host_str().unwrap_or("your-domain.com");
        let body = remote_storage::solid_discovery(&format!("https://{host}"));
        let json_str =
            serde_json::to_string(&body).map_err(|e| Error::RustError(e.to_string()))?;
        let cors = cors_headers(&env);
        let resp = Response::ok(json_str)?.with_headers(cors);
        resp.headers().set("Content-Type", "application/json").ok();
        return Ok(resp);
    }

    // NIP-05 verification
    if path == "/.well-known/nostr.json" {
        let name = url
            .query_pairs()
            .find(|(k, _)| k == "name")
            .map(|(_, v)| v.to_string())
            .unwrap_or_default();
        if name.is_empty() {
            return json_error(&env, "Missing name parameter", 400);
        }
        // Look up pubkey from KV: nip05:{name} -> pubkey
        let kv = env.kv("POD_META")?;
        let key = format!("nip05:{name}");
        let pubkey = kv.get(&key).text().await.ok().flatten();
        if let Some(pk) = pubkey {
            let body = remote_storage::nostr_json(&pk, &name);
            let json_str = serde_json::to_string(&body)
                .map_err(|e| Error::RustError(e.to_string()))?;
            let cors = cors_headers(&env);
            let resp = Response::ok(json_str)?.with_headers(cors);
            resp.headers().set("Content-Type", "application/json").ok();
            resp.headers()
                .set("Access-Control-Allow-Origin", "*")
                .ok();
            return Ok(resp);
        }
        return json_error(&env, "Name not found", 404);
    }

    // Route: /pods/{pubkey}/...
    let (owner_pubkey, resource_path) = match parse_pod_route(path) {
        Some(parsed) => parsed,
        None => return json_error(&env, "Not found", 404),
    };

    // We need owned copies before we borrow `req` mutably for the body
    let owner_pubkey = owner_pubkey.to_string();
    let resource_path = resource_path.to_string();
    let method = req.method();
    let req_headers = req.headers().clone();
    let auth_header = req_headers.get("Authorization").ok().flatten();
    let slug_header = req_headers.get("Slug").ok().flatten();
    let accept_header = req_headers.get("Accept").ok().flatten();
    let content_type = req_headers
        .get("Content-Type")
        .ok()
        .flatten()
        .unwrap_or_else(|| "application/octet-stream".to_string());
    let content_length: u64 = req_headers
        .get("Content-Length")
        .ok()
        .flatten()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    // Read body early so we can use it for both NIP-98 payload verification and R2 upload
    let body_bytes: Option<Vec<u8>> = match method {
        Method::Put | Method::Post | Method::Patch => req.bytes().await.ok(),
        _ => None,
    };

    // Authenticate via NIP-98
    let expected_origin = env
        .var("EXPECTED_ORIGIN")
        .map(|v| v.to_string())
        .unwrap_or_else(|_| "https://example.com".to_string());
    let request_url = format!("{expected_origin}{path}");

    let requester_pubkey: Option<String> = if let Some(ref header) = auth_header {
        let method_name = method_str(&method);
        let body_ref = body_bytes.as_deref();
        match auth::verify_nip98(header, &request_url, method_name, body_ref) {
            Ok(token) => Some(token.pubkey),
            Err(_) => None,
        }
    } else {
        None
    };

    let kv = env.kv("POD_META")?;
    let bucket = env.bucket("PODS")?;

    let agent_uri = requester_pubkey
        .as_ref()
        .map(|pk| format!("did:nostr:{pk}"));

    // -----------------------------------------------------------------------
    // Provisioning endpoint: POST /pods/{pubkey}/.provision
    // -----------------------------------------------------------------------
    if is_provision_path(&resource_path) {
        if method != Method::Post {
            return json_error(&env, "Method not allowed; use POST", 405);
        }

        // Require authentication
        let req_pk = match requester_pubkey.as_ref() {
            Some(pk) => pk.clone(),
            None => return json_error(&env, "Authentication required", 401),
        };

        // Only the pod owner or an admin can provision
        let is_owner = req_pk == owner_pubkey;
        let is_admin = is_admin_user(&kv, &req_pk).await;
        if !is_owner && !is_admin {
            return json_error(&env, "Only the pod owner or admin can provision", 403);
        }

        // Check if pod already exists
        if provision::pod_exists(&bucket, &owner_pubkey).await {
            return json_error(&env, "Pod already provisioned", 409);
        }

        // Extract optional display_name from body
        let display_name: Option<String> = body_bytes
            .as_deref()
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(b).ok())
            .and_then(|v| {
                v.get("display_name")
                    .and_then(|n| n.as_str())
                    .map(String::from)
            });

        let pod_base = expected_origin.clone();
        provision::provision_pod(
            &bucket,
            &kv,
            &owner_pubkey,
            &pod_base,
            display_name.as_deref(),
        )
        .await?;

        let pod_url = format!("{expected_origin}/pods/{owner_pubkey}/");
        let webid_url = format!("{expected_origin}/pods/{owner_pubkey}/profile/card#me");
        return json_ok(
            &env,
            &serde_json::json!({
                "status": "provisioned",
                "podUrl": pod_url,
                "webId": webid_url,
                "didNostr": format!("did:nostr:{owner_pubkey}"),
                "containers": ["profile/", "public/", "private/", "inbox/", "settings/"]
            }),
            201,
        );
    }

    // -----------------------------------------------------------------------
    // ACL CRUD: paths ending with .acl
    // -----------------------------------------------------------------------
    if is_acl_path(&resource_path) {
        return handle_acl_request(
            &env,
            &bucket,
            &kv,
            &owner_pubkey,
            &resource_path,
            &method,
            &req_headers,
            body_bytes,
            content_length,
            requester_pubkey.as_deref(),
            agent_uri.as_deref(),
        )
        .await;
    }

    // -----------------------------------------------------------------------
    // Standard resource ACL check
    // -----------------------------------------------------------------------
    let required_mode = method_to_mode(method_str(&method));
    let acl_doc = find_effective_acl(&bucket, &kv, &owner_pubkey, &resource_path).await;

    let has_access = evaluate_access(
        acl_doc.as_ref(),
        agent_uri.as_deref(),
        &resource_path,
        required_mode,
    );

    if !has_access {
        return if requester_pubkey.is_some() {
            json_error(&env, "Forbidden", 403)
        } else {
            json_error(&env, "Authentication required", 401)
        };
    }

    // Detect container vs resource
    let is_container_path = container::is_container(&resource_path);

    // R2 operations
    let r2_key = format!("pods/{owner_pubkey}{resource_path}");

    match method {
        Method::Get | Method::Head => {
            // Container listing
            if is_container_path {
                let listing =
                    container::list_container(&bucket, &owner_pubkey, &resource_path).await?;
                let json_str = serde_json::to_string(&listing)
                    .map_err(|e| Error::RustError(e.to_string()))?;
                let cors = cors_headers(&env);
                let resp = Response::ok(json_str)?.with_headers(cors);
                resp.headers()
                    .set("Content-Type", "application/ld+json")
                    .ok();
                add_ldp_headers(resp.headers(), true, &resource_path);
                add_wac_allow(
                    resp.headers(),
                    acl_doc.as_ref(),
                    agent_uri.as_deref(),
                    &resource_path,
                );
                return Ok(resp);
            }

            // WebID profile document (special path): serve from R2 if stored,
            // otherwise generate dynamically.
            if resource_path == "/profile/card" {
                let html = match bucket.get(&r2_key).execute().await? {
                    Some(obj) => {
                        let body = obj
                            .body()
                            .ok_or_else(|| Error::RustError("R2 object has no body".into()))?;
                        let bytes = body.bytes().await?;
                        String::from_utf8(bytes).unwrap_or_else(|_| {
                            webid::generate_webid_html(
                                &owner_pubkey,
                                None,
                                &expected_origin,
                            )
                        })
                    }
                    None => {
                        webid::generate_webid_html(&owner_pubkey, None, &expected_origin)
                    }
                };
                let cors = cors_headers(&env);
                let resp = Response::ok(html)?.with_headers(cors);
                resp.headers().set("Content-Type", "text/html").ok();
                add_ldp_headers(resp.headers(), false, &resource_path);
                add_wac_allow(
                    resp.headers(),
                    acl_doc.as_ref(),
                    agent_uri.as_deref(),
                    &resource_path,
                );
                return Ok(resp);
            }

            // Regular resource GET
            let object = match bucket.get(&r2_key).execute().await? {
                Some(obj) => obj,
                None => return json_error(&env, "Not found", 404),
            };

            let stored_content_type = object
                .http_metadata()
                .content_type
                .unwrap_or_else(|| "application/octet-stream".to_string());
            let obj_content_type = content_negotiation::negotiate(
                accept_header.as_deref(),
                &stored_content_type,
            );
            let etag = object.etag();
            let cors = cors_headers(&env);

            // Conditional request check
            if let Some(status) = conditional::check_preconditions(&req_headers, &etag) {
                let resp = Response::empty()?.with_status(status).with_headers(cors);
                resp.headers().set("ETag", &format!("\"{etag}\"")).ok();
                add_ldp_headers(resp.headers(), false, &resource_path);
                add_wac_allow(
                    resp.headers(),
                    acl_doc.as_ref(),
                    agent_uri.as_deref(),
                    &resource_path,
                );
                return Ok(resp);
            }

            if method == Method::Head {
                let resp = Response::empty()?.with_headers(cors);
                resp.headers().set("Content-Type", &obj_content_type).ok();
                resp.headers().set("ETag", &format!("\"{etag}\"")).ok();
                resp.headers().set("Vary", "Accept").ok();
                add_ldp_headers(resp.headers(), false, &resource_path);
                add_wac_allow(
                    resp.headers(),
                    acl_doc.as_ref(),
                    agent_uri.as_deref(),
                    &resource_path,
                );
                return Ok(resp);
            }

            let body = object
                .body()
                .ok_or_else(|| Error::RustError("R2 object has no body".to_string()))?;
            let bytes = body.bytes().await?;

            // Range request support
            if let Some((start, end)) =
                conditional::parse_range(&req_headers, bytes.len() as u64)
            {
                let slice = &bytes[start as usize..=end as usize];
                let resp = Response::from_bytes(slice.to_vec())?
                    .with_status(206)
                    .with_headers(cors);
                resp.headers().set("Content-Type", &obj_content_type).ok();
                resp.headers().set("ETag", &format!("\"{etag}\"")).ok();
                resp.headers()
                    .set(
                        "Content-Range",
                        &format!("bytes {start}-{end}/{}", bytes.len()),
                    )
                    .ok();
                add_ldp_headers(resp.headers(), false, &resource_path);
                add_wac_allow(
                    resp.headers(),
                    acl_doc.as_ref(),
                    agent_uri.as_deref(),
                    &resource_path,
                );
                return Ok(resp);
            }

            let resp = Response::from_bytes(bytes)?.with_headers(cors);
            resp.headers().set("Content-Type", &obj_content_type).ok();
            resp.headers().set("ETag", &format!("\"{etag}\"")).ok();
            resp.headers().set("Vary", "Accept").ok();
            add_ldp_headers(resp.headers(), false, &resource_path);
            add_wac_allow(
                resp.headers(),
                acl_doc.as_ref(),
                agent_uri.as_deref(),
                &resource_path,
            );
            Ok(resp)
        }

        Method::Put => {
            // PUT replaces a resource (not valid on containers)
            if is_container_path {
                return json_error(&env, "Cannot PUT to a container; use POST", 405);
            }

            if content_length > MAX_BODY_SIZE {
                return json_error(
                    &env,
                    &format!("Body exceeds {} byte limit", MAX_BODY_SIZE),
                    413,
                );
            }

            let data = body_bytes.unwrap_or_default();
            let data_len = data.len() as u64;
            if data_len > MAX_BODY_SIZE {
                return json_error(
                    &env,
                    &format!("Body exceeds {} byte limit", MAX_BODY_SIZE),
                    413,
                );
            }

            // Conditional check: If-Match for safe overwrites
            if let Ok(Some(existing)) = bucket.get(&r2_key).execute().await {
                let etag = existing.etag();
                if let Some(status) = conditional::check_preconditions(&req_headers, &etag) {
                    return json_error(
                        &env,
                        if status == 412 {
                            "Precondition failed"
                        } else {
                            "Not modified"
                        },
                        status,
                    );
                }
            }

            // Quota check
            if let Err(e) = quota::check_quota(&kv, &owner_pubkey, data_len).await {
                return json_error(&env, &e.to_string(), 413);
            }

            // WebID profile: validate HTML with JSON-LD before storing
            if resource_path == "/profile/card" {
                if let Err(msg) = validate_webid_html(&data) {
                    return json_error(&env, &msg, 422);
                }
            }

            bucket
                .put(&r2_key, data)
                .http_metadata(HttpMetadata {
                    content_type: Some(content_type),
                    ..Default::default()
                })
                .execute()
                .await?;

            // Update quota usage
            quota::update_usage(&kv, &owner_pubkey, data_len as i64)
                .await
                .ok();

            // Fire notification webhooks (non-blocking)
            notifications::notify_change(&kv, &owner_pubkey, &resource_path, "Update").await;

            let resp_body = serde_json::json!({ "status": "ok" });
            let resp = json_ok(&env, &resp_body, 201)?;
            add_ldp_headers(resp.headers(), false, &resource_path);
            add_wac_allow(
                resp.headers(),
                acl_doc.as_ref(),
                agent_uri.as_deref(),
                &resource_path,
            );
            Ok(resp)
        }

        Method::Post => {
            // POST to a container creates a child resource
            if !is_container_path {
                // POST to a non-container: treat as regular write (backwards compat)
                if content_length > MAX_BODY_SIZE {
                    return json_error(
                        &env,
                        &format!("Body exceeds {} byte limit", MAX_BODY_SIZE),
                        413,
                    );
                }

                let data = body_bytes.unwrap_or_default();
                let data_len = data.len() as u64;
                if data_len > MAX_BODY_SIZE {
                    return json_error(
                        &env,
                        &format!("Body exceeds {} byte limit", MAX_BODY_SIZE),
                        413,
                    );
                }

                if let Err(e) = quota::check_quota(&kv, &owner_pubkey, data_len).await {
                    return json_error(&env, &e.to_string(), 413);
                }

                bucket
                    .put(&r2_key, data)
                    .http_metadata(HttpMetadata {
                        content_type: Some(content_type),
                        ..Default::default()
                    })
                    .execute()
                    .await?;

                quota::update_usage(&kv, &owner_pubkey, data_len as i64)
                    .await
                    .ok();

                // Fire notification webhooks (non-blocking)
                notifications::notify_change(&kv, &owner_pubkey, &resource_path, "Update")
                    .await;

                let resp_body = serde_json::json!({ "status": "ok" });
                let resp = json_ok(&env, &resp_body, 201)?;
                add_ldp_headers(resp.headers(), false, &resource_path);
                add_wac_allow(
                    resp.headers(),
                    acl_doc.as_ref(),
                    agent_uri.as_deref(),
                    &resource_path,
                );
                return Ok(resp);
            }

            // Container POST: create child resource
            if content_length > MAX_BODY_SIZE {
                return json_error(
                    &env,
                    &format!("Body exceeds {} byte limit", MAX_BODY_SIZE),
                    413,
                );
            }

            let data = body_bytes.unwrap_or_default();
            let data_len = data.len() as u64;
            if data_len > MAX_BODY_SIZE {
                return json_error(
                    &env,
                    &format!("Body exceeds {} byte limit", MAX_BODY_SIZE),
                    413,
                );
            }

            if let Err(e) = quota::check_quota(&kv, &owner_pubkey, data_len).await {
                return json_error(&env, &e.to_string(), 413);
            }

            let child_path =
                container::resolve_slug(&resource_path, slug_header.as_deref());
            let child_r2_key = format!("pods/{owner_pubkey}{child_path}");

            bucket
                .put(&child_r2_key, data)
                .http_metadata(HttpMetadata {
                    content_type: Some(content_type),
                    ..Default::default()
                })
                .execute()
                .await?;

            quota::update_usage(&kv, &owner_pubkey, data_len as i64)
                .await
                .ok();

            // Fire notification webhooks (non-blocking)
            notifications::notify_change(&kv, &owner_pubkey, &child_path, "Create").await;

            let location = format!("/pods/{owner_pubkey}{child_path}");
            let resp_body = serde_json::json!({
                "status": "created",
                "path": child_path,
                "location": location,
            });
            let resp = json_ok(&env, &resp_body, 201)?;
            resp.headers().set("Location", &location).ok();
            add_ldp_headers(resp.headers(), false, &resource_path);
            add_wac_allow(
                resp.headers(),
                acl_doc.as_ref(),
                agent_uri.as_deref(),
                &resource_path,
            );
            Ok(resp)
        }

        Method::Patch => {
            // PATCH applies JSON Patch (RFC 6902) to a resource
            if is_container_path {
                return json_error(&env, "Cannot PATCH a container", 405);
            }

            let patch_data = body_bytes.unwrap_or_default();

            // Parse patch operations
            let operations: Vec<patch::PatchOperation> =
                serde_json::from_slice(&patch_data)
                    .map_err(|e| Error::RustError(format!("Invalid JSON Patch: {e}")))?;

            // Read current document
            let current_bytes = match bucket.get(&r2_key).execute().await? {
                Some(obj) => {
                    let body = obj
                        .body()
                        .ok_or_else(|| Error::RustError("R2 object has no body".into()))?;
                    body.bytes().await?
                }
                None => return json_error(&env, "Not found", 404),
            };

            let mut document: serde_json::Value = serde_json::from_slice(&current_bytes)
                .map_err(|e| Error::RustError(format!("Resource is not JSON: {e}")))?;

            // Apply patches
            patch::apply_patches(&mut document, &operations)
                .map_err(|e| Error::RustError(format!("Patch failed: {e}")))?;

            let updated =
                serde_json::to_vec(&document).map_err(|e| Error::RustError(e.to_string()))?;
            let updated_len = updated.len() as u64;

            // Quota check for size difference
            if updated_len > current_bytes.len() as u64 {
                let delta = updated_len - current_bytes.len() as u64;
                if let Err(e) = quota::check_quota(&kv, &owner_pubkey, delta).await {
                    return json_error(&env, &e.to_string(), 413);
                }
            }

            // WebID profile: validate after patching
            if resource_path == "/profile/card" {
                if let Err(msg) = validate_webid_html(&updated) {
                    return json_error(&env, &msg, 422);
                }
            }

            bucket
                .put(&r2_key, updated)
                .http_metadata(HttpMetadata {
                    content_type: Some("application/ld+json".into()),
                    ..Default::default()
                })
                .execute()
                .await?;

            let size_delta = updated_len as i64 - current_bytes.len() as i64;
            if size_delta != 0 {
                quota::update_usage(&kv, &owner_pubkey, size_delta)
                    .await
                    .ok();
            }

            // Fire notification webhooks (non-blocking)
            notifications::notify_change(&kv, &owner_pubkey, &resource_path, "Update").await;

            let resp_body = serde_json::json!({ "status": "ok" });
            let resp = json_ok(&env, &resp_body, 200)?;
            add_ldp_headers(resp.headers(), false, &resource_path);
            add_wac_allow(
                resp.headers(),
                acl_doc.as_ref(),
                agent_uri.as_deref(),
                &resource_path,
            );
            Ok(resp)
        }

        Method::Delete => {
            // Estimate size of deleted resource for quota tracking
            let deleted_size: u64 = match bucket.get(&r2_key).execute().await? {
                Some(obj) => obj.size() as u64,
                None => return json_error(&env, "Not found", 404),
            };

            bucket.delete(&r2_key).await?;

            // Update quota (negative delta)
            quota::update_usage(&kv, &owner_pubkey, -(deleted_size as i64))
                .await
                .ok();

            // Fire notification webhooks (non-blocking)
            notifications::notify_change(&kv, &owner_pubkey, &resource_path, "Delete").await;

            let resp_body = serde_json::json!({ "status": "deleted" });
            let resp = json_ok(&env, &resp_body, 200)?;
            add_ldp_headers(resp.headers(), false, &resource_path);
            add_wac_allow(
                resp.headers(),
                acl_doc.as_ref(),
                agent_uri.as_deref(),
                &resource_path,
            );
            Ok(resp)
        }

        _ => json_error(&env, "Method not allowed", 405),
    }
}

// ---------------------------------------------------------------------------
// ACL request handler
// ---------------------------------------------------------------------------

/// Handle GET/PUT/DELETE on `.acl` sidecar resources.
///
/// ACL documents are stored in R2 alongside the resources they protect.
/// Writing an ACL requires `acl:Control` on the parent resource.
#[allow(clippy::too_many_arguments)]
async fn handle_acl_request(
    env: &Env,
    bucket: &Bucket,
    kv: &kv::KvStore,
    owner_pubkey: &str,
    acl_path: &str,
    method: &Method,
    req_headers: &Headers,
    body_bytes: Option<Vec<u8>>,
    content_length: u64,
    requester_pubkey: Option<&str>,
    agent_uri: Option<&str>,
) -> Result<Response> {
    let r2_key = format!("pods/{owner_pubkey}{acl_path}");

    // Derive the parent resource path: strip `.acl` suffix
    let parent_path = acl_path.strip_suffix(".acl").unwrap_or(acl_path);
    // Normalize empty parent to "/"
    let parent_path = if parent_path.is_empty() {
        "/"
    } else {
        parent_path
    };

    // Resolve effective ACL for the parent to determine access
    let parent_acl = find_effective_acl(bucket, kv, owner_pubkey, parent_path).await;

    match *method {
        Method::Get | Method::Head => {
            // Reading an ACL requires acl:Read on the parent OR acl:Control
            let can_read = evaluate_access(
                parent_acl.as_ref(),
                agent_uri,
                parent_path,
                AccessMode::Read,
            ) || evaluate_access(
                parent_acl.as_ref(),
                agent_uri,
                parent_path,
                AccessMode::Control,
            );

            if !can_read {
                return if requester_pubkey.is_some() {
                    json_error(env, "Forbidden", 403)
                } else {
                    json_error(env, "Authentication required", 401)
                };
            }

            let object = match bucket.get(&r2_key).execute().await? {
                Some(obj) => obj,
                None => return json_error(env, "No ACL document found", 404),
            };

            let etag = object.etag();
            let cors = cors_headers(env);

            if let Some(status) = conditional::check_preconditions(req_headers, &etag) {
                let resp = Response::empty()?.with_status(status).with_headers(cors);
                resp.headers().set("ETag", &format!("\"{etag}\"")).ok();
                return Ok(resp);
            }

            if *method == Method::Head {
                let resp = Response::empty()?.with_headers(cors);
                resp.headers()
                    .set("Content-Type", "application/ld+json")
                    .ok();
                resp.headers().set("ETag", &format!("\"{etag}\"")).ok();
                return Ok(resp);
            }

            let body = object
                .body()
                .ok_or_else(|| Error::RustError("R2 object has no body".into()))?;
            let bytes = body.bytes().await?;
            let resp = Response::from_bytes(bytes)?.with_headers(cors);
            resp.headers()
                .set("Content-Type", "application/ld+json")
                .ok();
            resp.headers().set("ETag", &format!("\"{etag}\"")).ok();
            add_wac_allow(resp.headers(), parent_acl.as_ref(), agent_uri, parent_path);
            Ok(resp)
        }

        Method::Put => {
            // Writing an ACL requires acl:Control on the parent resource
            let has_control = evaluate_access(
                parent_acl.as_ref(),
                agent_uri,
                parent_path,
                AccessMode::Control,
            );

            if !has_control {
                return if requester_pubkey.is_some() {
                    json_error(env, "acl:Control required to modify ACL", 403)
                } else {
                    json_error(env, "Authentication required", 401)
                };
            }

            if content_length > MAX_BODY_SIZE {
                return json_error(
                    env,
                    &format!("Body exceeds {} byte limit", MAX_BODY_SIZE),
                    413,
                );
            }

            let data = body_bytes.unwrap_or_default();

            // Validate that the body is a valid ACL document (parseable JSON-LD)
            if serde_json::from_slice::<acl::AclDocument>(&data).is_err() {
                return json_error(
                    env,
                    "Invalid ACL document: must be valid JSON-LD with @graph",
                    422,
                );
            }

            bucket
                .put(&r2_key, data)
                .http_metadata(HttpMetadata {
                    content_type: Some("application/ld+json".into()),
                    ..Default::default()
                })
                .execute()
                .await?;

            let resp_body = serde_json::json!({ "status": "ok" });
            json_ok(env, &resp_body, 201)
        }

        Method::Delete => {
            // Deleting an ACL requires acl:Control on the parent resource
            let has_control = evaluate_access(
                parent_acl.as_ref(),
                agent_uri,
                parent_path,
                AccessMode::Control,
            );

            if !has_control {
                return if requester_pubkey.is_some() {
                    json_error(env, "acl:Control required to delete ACL", 403)
                } else {
                    json_error(env, "Authentication required", 401)
                };
            }

            // Check it exists
            if bucket.get(&r2_key).execute().await?.is_none() {
                return json_error(env, "ACL document not found", 404);
            }

            bucket.delete(&r2_key).await?;

            let resp_body = serde_json::json!({ "status": "deleted" });
            json_ok(env, &resp_body, 200)
        }

        _ => json_error(env, "Method not allowed on ACL resource", 405),
    }
}

// ---------------------------------------------------------------------------
// WebID validation
// ---------------------------------------------------------------------------

/// Validate that a byte slice is a valid WebID profile document.
///
/// Checks that the content is valid UTF-8 and contains embedded JSON-LD
/// (a `<script type="application/ld+json">` block).
fn validate_webid_html(data: &[u8]) -> Result<(), String> {
    let text =
        std::str::from_utf8(data).map_err(|_| "WebID profile must be valid UTF-8".to_string())?;

    if !text.contains("application/ld+json") {
        return Err(
            "WebID profile must contain a <script type=\"application/ld+json\"> block".to_string(),
        );
    }

    // Extract the JSON-LD content and verify it parses
    if let Some(start) = text.find("application/ld+json") {
        // Find the closing > of the script tag
        if let Some(tag_end) = text[start..].find('>') {
            let json_start = start + tag_end + 1;
            if let Some(script_end) = text[json_start..].find("</script>") {
                let json_str = text[json_start..json_start + script_end].trim();
                serde_json::from_str::<serde_json::Value>(json_str)
                    .map_err(|e| format!("Invalid JSON-LD in WebID profile: {e}"))?;
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Admin check helper
// ---------------------------------------------------------------------------

/// Check if a pubkey is an admin user (via KV).
///
/// Uses KV key `admin:{pubkey}` as a lightweight check.
async fn is_admin_user(kv: &kv::KvStore, pubkey: &str) -> bool {
    let key = format!("admin:{pubkey}");
    kv.get(&key)
        .text()
        .await
        .ok()
        .flatten()
        .map(|v| v == "1" || v == "true")
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Unit tests (route parsing only -- full integration requires wasm-bindgen)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pod_route_valid() {
        let pubkey = "a".repeat(64);
        let path = format!("/pods/{pubkey}/profile/card");
        let (pk, rp) = parse_pod_route(&path).unwrap();
        assert_eq!(pk, pubkey);
        assert_eq!(rp, "/profile/card");
    }

    #[test]
    fn parse_pod_route_root() {
        let pubkey = "b".repeat(64);
        let path = format!("/pods/{pubkey}");
        let (pk, rp) = parse_pod_route(&path).unwrap();
        assert_eq!(pk, pubkey);
        assert_eq!(rp, "/");
    }

    #[test]
    fn parse_pod_route_with_trailing_slash() {
        let pubkey = "c".repeat(64);
        let path = format!("/pods/{pubkey}/");
        let (pk, rp) = parse_pod_route(&path).unwrap();
        assert_eq!(pk, pubkey);
        assert_eq!(rp, "/");
    }

    #[test]
    fn parse_pod_route_invalid_hex() {
        let path = format!("/pods/{}/file", "x".repeat(64));
        assert!(parse_pod_route(&path).is_none());
    }

    #[test]
    fn parse_pod_route_short_pubkey() {
        assert!(parse_pod_route("/pods/abc/file").is_none());
    }

    #[test]
    fn parse_pod_route_wrong_prefix() {
        assert!(parse_pod_route("/api/something").is_none());
    }

    #[test]
    fn parse_pod_route_no_slash_after_pubkey() {
        let pubkey = "d".repeat(64);
        let path = format!("/pods/{pubkey}extra");
        assert!(parse_pod_route(&path).is_none());
    }

    #[test]
    fn parse_pod_route_container_path() {
        let pubkey = "e".repeat(64);
        let path = format!("/pods/{pubkey}/media/");
        let (pk, rp) = parse_pod_route(&path).unwrap();
        assert_eq!(pk, pubkey);
        assert_eq!(rp, "/media/");
    }

    #[test]
    fn is_acl_path_detects_acl_suffix() {
        assert!(is_acl_path("/public/.acl"));
        assert!(is_acl_path("/.acl"));
        assert!(is_acl_path("/profile/card.acl"));
        assert!(!is_acl_path("/public/"));
        assert!(!is_acl_path("/profile/card"));
        assert!(!is_acl_path("/acl/resource"));
    }

    #[test]
    fn is_provision_path_detects_endpoint() {
        assert!(is_provision_path("/.provision"));
        assert!(!is_provision_path("/provision"));
        assert!(!is_provision_path("/.provision/extra"));
        assert!(!is_provision_path("/public/.provision"));
    }

    #[test]
    fn validate_webid_html_accepts_valid() {
        let html = r##"<!DOCTYPE html>
<html>
<head>
  <script type="application/ld+json">
  {"@context": {"foaf": "http://xmlns.com/foaf/0.1/"}, "@id": "#me", "@type": "foaf:Person"}
  </script>
</head>
<body></body>
</html>"##;
        assert!(validate_webid_html(html.as_bytes()).is_ok());
    }

    #[test]
    fn validate_webid_html_rejects_no_jsonld() {
        let html = "<!DOCTYPE html><html><body>No JSON-LD here</body></html>";
        assert!(validate_webid_html(html.as_bytes()).is_err());
    }

    #[test]
    fn validate_webid_html_rejects_invalid_utf8() {
        let bad_bytes: &[u8] = &[0xff, 0xfe, 0xfd];
        assert!(validate_webid_html(bad_bytes).is_err());
    }

    #[test]
    fn validate_webid_html_rejects_invalid_jsonld() {
        let html = r##"<!DOCTYPE html>
<html>
<head>
  <script type="application/ld+json">
  {not valid json}
  </script>
</head>
<body></body>
</html>"##;
        assert!(validate_webid_html(html.as_bytes()).is_err());
    }
}
