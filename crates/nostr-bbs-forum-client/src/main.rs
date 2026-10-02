//! nostr-bbs community forum -- Leptos CSR application entry point.

mod admin;
mod app;
mod auth;
mod components;
mod dm;
mod pages;
pub(crate) mod poker;
mod relay;
pub(crate) mod stores;
pub(crate) mod utils;
pub(crate) mod wallet;
pub(crate) mod zone_crypto;

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
    // Always revalidate sw.js itself on page load (skip the HTTP cache) so a
    // new deploy's worker installs on the FIRST visit, instead of whenever the
    // browser's sw.js cache heuristic expires.
    options.set_update_via_cache(web_sys::ServiceWorkerUpdateViaCache::None);

    // Auto-reload exactly once when a freshly-installed worker takes control,
    // so an already-open tab swaps onto the new build instead of running the old
    // WASM bundle until the user happens to reload. Guarded by a flag on
    // `window` to avoid the classic controllerchange reload loop (a reload
    // re-fires controllerchange under some browsers).
    install_controllerchange_reload(&sw_container);

    let promise = sw_container.register_with_options(&sw_url, &options);
    wasm_bindgen_futures::spawn_local(async move {
        match wasm_bindgen_futures::JsFuture::from(promise).await {
            Ok(reg) => {
                web_sys::console::log_1(
                    &format!("[PWA] Service worker registered at {sw_url} (scope {scope})").into(),
                );
                // Force an immediate update check on load so a new deploy's
                // worker is discovered now, not on the browser's own schedule.
                trigger_registration_update(&reg);
                install_foreground_update_check(reg);
            }
            Err(e) => web_sys::console::warn_1(
                &format!("[PWA] Service worker registration failed: {:?}", e).into(),
            ),
        }
    });
}

/// Call `registration.update()` to force an immediate check for a new worker.
///
/// Uses `js_sys::Reflect` to invoke the method so we don't need the typed
/// `ServiceWorkerRegistration` web-sys binding (the resolved `register()` value
/// is a `JsValue` that quacks like a registration). Failure is non-fatal.
fn trigger_registration_update(reg: &wasm_bindgen::JsValue) {
    use wasm_bindgen::JsCast;

    let Ok(update_fn) = js_sys::Reflect::get(reg, &"update".into()) else {
        return;
    };
    if let Ok(func) = update_fn.dyn_into::<js_sys::Function>() {
        // `update()` returns a promise; we don't need to await it.
        let _ = func.call0(reg);
    }
}

/// Minimum gap between foreground update checks.
const FOREGROUND_UPDATE_MIN_MS: f64 = 60_000.0;

/// Whether a foreground update check is due: the first one always is, later
/// ones once `min_ms` has passed. A clock that went backwards counts as due.
fn foreground_update_due(now_ms: f64, last_ms: Option<f64>, min_ms: f64) -> bool {
    match last_ms {
        None => true,
        Some(last) => now_ms < last || now_ms - last >= min_ms,
    }
}

/// Check for a new build whenever the app returns to the foreground.
///
/// An installed PWA is usually resumed from the background rather than
/// relaunched, and a resume makes no navigation request, so neither the
/// network-first `index.html` in `sw.js` nor the load-time `update()` above
/// runs: a phone can keep the old WASM for days. On `visibilitychange` to
/// visible this calls `registration.update()`; a new deploy's `sw.js` differs
/// (its build token), so the new worker installs, claims the page, and
/// `install_controllerchange_reload` reloads it once onto the new build.
fn install_foreground_update_check(reg: wasm_bindgen::JsValue) {
    use wasm_bindgen::JsCast;

    let Some(document) = web_sys::window().and_then(|w| w.document()) else {
        return;
    };
    let last: std::cell::Cell<Option<f64>> = std::cell::Cell::new(Some(js_sys::Date::now()));
    let doc = document.clone();
    let closure = wasm_bindgen::closure::Closure::<dyn FnMut()>::new(move || {
        if doc.hidden() {
            return;
        }
        let now = js_sys::Date::now();
        if foreground_update_due(now, last.get(), FOREGROUND_UPDATE_MIN_MS) {
            last.set(Some(now));
            trigger_registration_update(&reg);
        }
    });
    let _ = document
        .add_event_listener_with_callback("visibilitychange", closure.as_ref().unchecked_ref());
    // Leak the closure: it must outlive this fn for the lifetime of the page.
    closure.forget();
}

/// Reload the page once when a new service worker takes control, so an open tab
/// picks up the just-deployed build. A `window.__sw_reloaded__` sentinel
/// prevents the reload loop that `controllerchange` can otherwise trigger.
fn install_controllerchange_reload(sw_container: &web_sys::ServiceWorkerContainer) {
    use wasm_bindgen::JsCast;

    let closure = wasm_bindgen::closure::Closure::<dyn FnMut()>::new(move || {
        let Some(window) = web_sys::window() else {
            return;
        };
        // Reload at most once: bail if a previous controllerchange already did.
        let key = wasm_bindgen::JsValue::from_str("__sw_reloaded__");
        if js_sys::Reflect::get(&window, &key)
            .map(|v| v.is_truthy())
            .unwrap_or(false)
        {
            return;
        }
        let _ = js_sys::Reflect::set(&window, &key, &wasm_bindgen::JsValue::TRUE);
        web_sys::console::log_1(&"[PWA] New build active — reloading once".into());
        if let Ok(loc) = js_sys::Reflect::get(&window, &"location".into()) {
            if let Ok(reload) = js_sys::Reflect::get(&loc, &"reload".into()) {
                if let Ok(func) = reload.dyn_into::<js_sys::Function>() {
                    let _ = func.call0(&loc);
                }
            }
        }
    });

    let _ = sw_container
        .add_event_listener_with_callback("controllerchange", closure.as_ref().unchecked_ref());
    // Leak the closure: it must outlive this fn for the lifetime of the page.
    closure.forget();
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

#[cfg(test)]
mod tests {
    use super::foreground_update_due;

    #[test]
    fn foreground_update_is_throttled() {
        assert!(foreground_update_due(0.0, None, 60_000.0));
        assert!(!foreground_update_due(1_000.0, Some(0.0), 60_000.0));
        assert!(!foreground_update_due(59_999.0, Some(0.0), 60_000.0));
        assert!(foreground_update_due(60_000.0, Some(0.0), 60_000.0));
        // A clock that jumped backwards never suppresses the check for good.
        assert!(foreground_update_due(5.0, Some(10_000.0), 60_000.0));
    }
}
