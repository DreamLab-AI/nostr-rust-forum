//! nostr-bbs community forum -- Leptos CSR application entry point.

// WASM entry points and Leptos component helpers appear unused in native builds.
#![allow(dead_code)]

mod admin;
mod app;
mod auth;
mod components;
mod dm;
mod pages;
mod relay;
pub(crate) mod stores;
pub(crate) mod utils;

use app::App;

fn main() {
    // Surface WASM panics as console.error instead of swallowing them silently.
    console_error_panic_hook::set_once();

    web_sys::console::log_1(&"[nostr-bbs] WASM main() started".into());

    leptos::mount::mount_to_body(App);

    web_sys::console::log_1(&"[nostr-bbs] mount_to_body complete".into());

    // Remove the static loading screen now that the Leptos app has mounted.
    if let Some(el) = web_sys::window()
        .and_then(|w| w.document())
        .and_then(|d| d.get_element_by_id("loading-screen"))
    {
        el.remove();
    }

    // Register service worker and run offline startup tasks.
    register_service_worker();
    run_offline_startup();
}

/// Register the service worker for offline caching.
///
/// ADR-090: SW URL and scope are computed against `FORUM_BASE` so the
/// registration works from every route, not only `/community/`. A relative
/// `./sw.js` resolves against `document.baseURI` and 404s on every deep
/// route (e.g. `/community/forums/home/sw.js`).
fn register_service_worker() {
    let Some(window) = web_sys::window() else {
        return;
    };
    let navigator = window.navigator();
    let sw_container = navigator.service_worker();

    // FORUM_BASE is compile-time; mirror app::FORUM_BASE.
    let base: &str = option_env!("FORUM_BASE").unwrap_or_default();
    let sw_url = format!("{base}/sw.js");
    let scope = format!("{base}/");

    let options = web_sys::RegistrationOptions::new();
    options.set_scope(&scope);
    let promise = sw_container.register_with_options(&sw_url, &options);
    wasm_bindgen_futures::spawn_local(async move {
        match wasm_bindgen_futures::JsFuture::from(promise).await {
            Ok(_) => web_sys::console::log_1(
                &format!("[PWA] Service worker registered at {sw_url} (scope {scope})").into(),
            ),
            Err(e) => web_sys::console::warn_1(
                &format!("[PWA] Service worker registration failed: {:?}", e).into(),
            ),
        }
    });
}

/// Run startup tasks: evict stale IndexedDB data, check storage quota.
fn run_offline_startup() {
    wasm_bindgen_futures::spawn_local(async {
        // Open IndexedDB and evict messages older than 30 days
        match stores::indexed_db::ForumDb::open().await {
            Ok(db) => {
                let thirty_days = 30 * 24 * 60 * 60;
                match db.evict_old(thirty_days).await {
                    Ok(0) => {}
                    Ok(n) => web_sys::console::log_1(
                        &format!("[PWA] Evicted {} stale cached messages", n).into(),
                    ),
                    Err(e) => {
                        web_sys::console::warn_1(&format!("[PWA] Eviction failed: {:?}", e).into())
                    }
                }
            }
            Err(e) => {
                web_sys::console::warn_1(&format!("[PWA] IndexedDB open failed: {:?}", e).into());
            }
        }

        // Check storage quota
        if let Some((usage, quota)) = utils::check_storage_quota().await {
            let pct = if quota > 0.0 {
                usage / quota * 100.0
            } else {
                0.0
            };
            if pct > 80.0 {
                web_sys::console::warn_1(
                    &format!(
                        "[PWA] Storage usage at {:.1}% ({:.1}MB / {:.1}MB)",
                        pct,
                        usage / 1_048_576.0,
                        quota / 1_048_576.0
                    )
                    .into(),
                );
            }
        }
    });
}
