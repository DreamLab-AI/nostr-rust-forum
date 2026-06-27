//! Live Solid pod container listing (LDP) for the File Base screen.
//!
//! GETs the owner's pod container from the pod API and parses the LDP
//! membership (`ldp:contains`) into a resource list. The pod serves JSON-LD by
//! default (see the kit's `content_negotiation`), so we request
//! `application/ld+json` and tolerantly extract member references. The parser is
//! pure and unit-tested; the `fetch` itself is wasm-only.

use serde_json::Value;

/// A member of a pod container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PodResource {
    /// Last path segment (display name).
    pub name: String,
    /// Whether this member is itself a container (trailing slash).
    pub is_container: bool,
}

/// Async load state for the File Base listing.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum PodState {
    /// Not yet requested.
    #[default]
    Idle,
    /// Request in flight.
    Loading,
    /// Loaded container members.
    Loaded(Vec<PodResource>),
    /// Request failed (message for display).
    Error(String),
}

/// Build the pod container URL: `<pod>/pods/<hex>/<path>`.
pub fn container_url(pod_api: &str, pubkey_hex: &str, path: &str) -> String {
    let base = pod_api.trim_end_matches('/');
    let path = path.trim_start_matches('/');
    if path.is_empty() {
        format!("{base}/pods/{pubkey_hex}/")
    } else {
        format!("{base}/pods/{pubkey_hex}/{path}")
    }
}

/// Parse an LDP container document (JSON-LD) into its members.
///
/// Tolerant of shape: walks the JSON for any `*contains*` key (e.g.
/// `ldp:contains` / `contains`) and collects string or `{@id}` references,
/// including inside an `@graph`. Members are de-duplicated, containers first.
pub fn parse_container(body: &str) -> Vec<PodResource> {
    let mut refs: Vec<String> = Vec::new();
    if let Ok(v) = serde_json::from_str::<Value>(body) {
        collect_contains(&v, &mut refs);
    }

    let mut out: Vec<PodResource> = Vec::new();
    for r in refs {
        if let Some(res) = resource_from_ref(&r) {
            if !out.iter().any(|e| e.name == res.name) {
                out.push(res);
            }
        }
    }
    out.sort_by(|a, b| {
        b.is_container
            .cmp(&a.is_container)
            .then_with(|| a.name.cmp(&b.name))
    });
    out
}

fn collect_contains(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::Object(map) => {
            for (k, val) in map {
                if k.to_ascii_lowercase().contains("contains") {
                    push_refs(val, out);
                } else {
                    collect_contains(val, out);
                }
            }
        }
        Value::Array(items) => items.iter().for_each(|it| collect_contains(it, out)),
        _ => {}
    }
}

fn push_refs(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) => out.push(s.clone()),
        Value::Object(map) => {
            if let Some(id) = map
                .get("@id")
                .or_else(|| map.get("id"))
                .and_then(Value::as_str)
            {
                out.push(id.to_string());
            }
        }
        Value::Array(items) => items.iter().for_each(|it| push_refs(it, out)),
        _ => {}
    }
}

fn resource_from_ref(r: &str) -> Option<PodResource> {
    let r = r.trim();
    if r.is_empty() || r == "./" || r == "." {
        return None;
    }
    let is_container = r.ends_with('/');
    let trimmed = r.trim_end_matches('/');
    let name = trimmed.rsplit(['/', '#']).next()?.trim().to_string();
    if name.is_empty() {
        return None;
    }
    Some(PodResource { name, is_container })
}

/// Fetch + parse the owner's pod container. Wasm-only (uses the Fetch API).
#[cfg(target_arch = "wasm32")]
pub async fn fetch_container(
    pod_api: &str,
    pubkey_hex: &str,
    path: &str,
) -> Result<Vec<PodResource>, String> {
    use wasm_bindgen::JsCast;
    use wasm_bindgen_futures::JsFuture;

    if pod_api.is_empty() {
        return Err("no pod configured".into());
    }
    let url = container_url(pod_api, pubkey_hex, path);

    let init = web_sys::RequestInit::new();
    init.set_method("GET");
    init.set_mode(web_sys::RequestMode::Cors);
    if let Ok(headers) = web_sys::Headers::new() {
        let _ = headers.set("Accept", "application/ld+json");
        init.set_headers(&headers);
    }
    let request = web_sys::Request::new_with_str_and_init(&url, &init)
        .map_err(|e| format!("bad request: {e:?}"))?;
    let win = web_sys::window().ok_or("no window")?;
    let resp_val = JsFuture::from(win.fetch_with_request(&request))
        .await
        .map_err(|e| format!("fetch failed: {e:?}"))?;
    let resp: web_sys::Response = resp_val
        .dyn_into()
        .map_err(|_| "not a Response".to_string())?;
    if !resp.ok() {
        return Err(format!("HTTP {}", resp.status()));
    }
    let text_val = JsFuture::from(resp.text().map_err(|e| format!("{e:?}"))?)
        .await
        .map_err(|e| format!("read failed: {e:?}"))?;
    let body = text_val.as_string().unwrap_or_default();
    Ok(parse_container(&body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn container_url_root_and_path() {
        assert_eq!(
            container_url("https://pods.example.com/", "ab", ""),
            "https://pods.example.com/pods/ab/"
        );
        assert_eq!(
            container_url("https://pods.example.com", "ab", "/public/"),
            "https://pods.example.com/pods/ab/public/"
        );
    }

    #[test]
    fn parse_ldp_contains_objects() {
        let body = r#"{
            "@id": "./",
            "@type": ["ldp:BasicContainer"],
            "ldp:contains": [{"@id": "inbox/"}, {"@id": "profile/card"}, {"@id": "public/"}]
        }"#;
        let items = parse_container(body);
        assert_eq!(items.len(), 3);
        // Containers first, alphabetical.
        assert_eq!(
            items[0],
            PodResource {
                name: "inbox".into(),
                is_container: true
            }
        );
        assert_eq!(
            items[1],
            PodResource {
                name: "public".into(),
                is_container: true
            }
        );
        assert_eq!(
            items[2],
            PodResource {
                name: "card".into(),
                is_container: false
            }
        );
    }

    #[test]
    fn parse_contains_in_graph_and_string_refs() {
        let body = r#"{ "@graph": [ { "contains": ["a/", "b.ttl"] } ] }"#;
        let items = parse_container(body);
        assert_eq!(items.len(), 2);
        assert!(items.iter().any(|r| r.name == "a" && r.is_container));
        assert!(items.iter().any(|r| r.name == "b.ttl" && !r.is_container));
    }

    #[test]
    fn parse_dedups_and_ignores_self() {
        let body = r#"{ "ldp:contains": ["x/", "x/", "./"] }"#;
        let items = parse_container(body);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].name, "x");
    }

    #[test]
    fn parse_garbage_is_empty() {
        assert!(parse_container("not json").is_empty());
        assert!(parse_container("{}").is_empty());
    }
}
