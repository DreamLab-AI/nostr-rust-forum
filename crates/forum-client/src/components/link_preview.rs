//! Open Graph link preview card -- lazy-loaded via IntersectionObserver.

use leptos::prelude::*;
use serde::Deserialize;
use wasm_bindgen::prelude::*;

/// Default link-preview API endpoint.
const PREVIEW_API: &str = match option_env!("VITE_LINK_PREVIEW_API_URL") {
    Some(u) => u,
    None => "https://your-preview.your-subdomain.workers.dev",
};

/// JSON shape returned by the link-preview worker.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
struct OgData {
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    image: Option<String>,
    #[serde(default)]
    site_name: Option<String>,
    #[serde(default)]
    url: Option<String>,
}

/// Internal loading state for the preview fetch.
#[derive(Clone, Debug, PartialEq)]
enum PreviewState {
    Idle,
    Loading,
    Loaded(OgData),
    Failed,
}

/// Display an Open Graph preview card for a URL.
///
/// Lazy-loads: only fetches OG metadata when the card scrolls into view
/// via IntersectionObserver. Shows a skeleton while loading, and falls
/// back to a plain link on failure.
#[component]
pub(crate) fn LinkPreview(
    /// The URL to fetch a preview for.
    url: String,
) -> impl IntoView {
    let state = RwSignal::new(PreviewState::Idle);
    let container_ref = NodeRef::<leptos::html::Div>::new();
    let url_for_display = url.clone();
    let url_for_fetch = url.clone();
    let url_for_fallback = url.clone();

    // Set up IntersectionObserver to trigger fetch on visibility
    Effect::new(move |_| {
        let el = match container_ref.get() {
            Some(el) => el,
            None => return,
        };
        if state.get_untracked() != PreviewState::Idle {
            return;
        }

        let state_sig = state;
        let fetch_url = url_for_fetch.clone();

        let callback = Closure::wrap(Box::new(
            move |entries: js_sys::Array, observer: web_sys::IntersectionObserver| {
                for i in 0..entries.length() {
                    let entry: web_sys::IntersectionObserverEntry = entries.get(i).unchecked_into();
                    if entry.is_intersecting() {
                        observer.disconnect();
                        state_sig.set(PreviewState::Loading);
                        let url_clone = fetch_url.clone();
                        wasm_bindgen_futures::spawn_local(async move {
                            match fetch_og_data(&url_clone).await {
                                Ok(data) => state_sig.set(PreviewState::Loaded(data)),
                                Err(_) => state_sig.set(PreviewState::Failed),
                            }
                        });
                        break;
                    }
                }
            },
        )
            as Box<dyn FnMut(js_sys::Array, web_sys::IntersectionObserver)>);

        let opts = web_sys::IntersectionObserverInit::new();
        opts.set_threshold(&JsValue::from_f64(0.1));

        if let Ok(observer) = web_sys::IntersectionObserver::new_with_options(
            callback.as_ref().unchecked_ref(),
            &opts,
        ) {
            let html_el: &web_sys::Element = &el;
            observer.observe(html_el);
        }

        // Leak the closure intentionally -- observer holds the reference.
        // It disconnects after first intersection so only one fetch happens.
        callback.forget();
    });

    view! {
        <div node_ref=container_ref class="mt-2 max-w-lg">
            {move || {
                match state.get() {
                    PreviewState::Idle | PreviewState::Loading => {
                        // Skeleton
                        view! {
                            <div class="link-preview-card animate-pulse">
                                <div class="skeleton h-32 w-full"></div>
                                <div class="p-3 space-y-2">
                                    <div class="skeleton h-4 w-3/4"></div>
                                    <div class="skeleton h-3 w-full"></div>
                                    <div class="skeleton h-3 w-1/2"></div>
                                </div>
                            </div>
                        }.into_any()
                    }
                    PreviewState::Loaded(ref data) => {
                        let title = data.title.clone().unwrap_or_default();
                        let desc = data.description.clone().unwrap_or_default();
                        let image = data.image.clone();
                        let site = data.site_name.clone().unwrap_or_default();
                        let href = data.url.clone().unwrap_or_else(|| url_for_display.clone());

                        // Sanitize: strip any HTML tags from title/description
                        let title = strip_tags(&title);
                        let desc = strip_tags(&desc);

                        view! {
                            <a
                                href=href
                                target="_blank"
                                rel="noopener noreferrer"
                                class="block link-preview-card no-underline text-inherit"
                            >
                                {image.map(|src| view! {
                                    <div class="w-full h-40 overflow-hidden bg-gray-800">
                                        <img
                                            src=src
                                            alt=""
                                            class="w-full h-full object-cover"
                                            loading="lazy"
                                        />
                                    </div>
                                })}
                                <div class="p-3">
                                    {(!site.is_empty()).then(|| view! {
                                        <p class="text-xs text-gray-500 mb-1 uppercase tracking-wide">
                                            {site}
                                        </p>
                                    })}
                                    {(!title.is_empty()).then(|| view! {
                                        <h4 class="text-sm font-semibold text-white line-clamp-2 mb-1">
                                            {title}
                                        </h4>
                                    })}
                                    {(!desc.is_empty()).then(|| view! {
                                        <p class="text-xs text-gray-400 line-clamp-3">
                                            {desc}
                                        </p>
                                    })}
                                </div>
                            </a>
                        }.into_any()
                    }
                    PreviewState::Failed => {
                        let link_href = url_for_fallback.clone();
                        let link_text = url_for_fallback.clone();
                        view! {
                            <a
                                href=link_href
                                target="_blank"
                                rel="noopener noreferrer"
                                class="text-amber-400 hover:text-amber-300 text-sm underline break-all"
                            >
                                {link_text}
                            </a>
                        }.into_any()
                    }
                }
            }}
        </div>
    }
}

/// Fetch OG metadata from the link-preview worker.
async fn fetch_og_data(url: &str) -> Result<OgData, String> {
    let fetch_url = format!("{}?url={}", PREVIEW_API, js_sys::encode_uri_component(url));

    let opts = web_sys::RequestInit::new();
    opts.set_method("GET");

    let request = web_sys::Request::new_with_str_and_init(&fetch_url, &opts)
        .map_err(|e| format!("Request build error: {:?}", e))?;

    let window = web_sys::window().ok_or("No window")?;
    let resp_val = wasm_bindgen_futures::JsFuture::from(window.fetch_with_request(&request))
        .await
        .map_err(|e| format!("Fetch error: {:?}", e))?;

    let resp: web_sys::Response = resp_val.unchecked_into();
    if !resp.ok() {
        return Err(format!("HTTP {}", resp.status()));
    }

    let json_val = wasm_bindgen_futures::JsFuture::from(
        resp.json()
            .map_err(|e| format!("JSON parse error: {:?}", e))?,
    )
    .await
    .map_err(|e| format!("JSON error: {:?}", e))?;

    let data: OgData = serde_wasm_bindgen::from_value(json_val)
        .map_err(|e| format!("Deserialize error: {:?}", e))?;

    Ok(data)
}

/// Strip HTML tags from a string (naive approach, no regex crate needed).
fn strip_tags(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut in_tag = false;
    for ch in input.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => result.push(ch),
            _ => {}
        }
    }
    result
}
