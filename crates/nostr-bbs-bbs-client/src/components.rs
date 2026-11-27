//! Shared retro TUI UI primitives: toast bar, copy-key buttons, author badges,
//! phosphor Markdown renderer, and QR SVG helper.

use leptos::prelude::*;
use nostr_bbs_client_core::agent_disclosure::{
    badge_state, now_secs, try_use_agent_disclosure, BadgeState, DISCLOSURE_TTL_SECS,
};
use nostr_bbs_client_core::name_cache::use_display_name_tracked;
use nostr_bbs_client_core::toast::{use_toasts, ToastVariant};
use nostr_bbs_client_core::utils::{clipboard, sanitize, shorten_pubkey};

use crate::router::{use_router, Route};

/// Fixed terminal toast bar (wired to shared `nostr_bbs_client_core::toast::ToastStore`).
#[component]
pub fn BbsToastBar() -> impl IntoView {
    let store = use_toasts();
    let toasts = store.toasts();

    view! {
        <div class="bbs-toasts" role="status" aria-live="polite">
            <For
                each=move || toasts.get()
                key=|t| t.id
                let:toast
            >
                {
                    let cls = match toast.variant {
                        ToastVariant::Success => "bbs-toast bbs-toast-ok",
                        ToastVariant::Error => "bbs-toast bbs-toast-err",
                        ToastVariant::Warning => "bbs-toast bbs-toast-warn",
                        ToastVariant::Info => "bbs-toast bbs-toast-info",
                    };
                    let glyph = match toast.variant {
                        ToastVariant::Success => "[OK]",
                        ToastVariant::Error => "[ERR]",
                        ToastVariant::Warning => "[WARN]",
                        ToastVariant::Info => "[INFO]",
                    };
                    let id = toast.id;
                    view! {
                        <div class=cls>
                            <span class="bbs-toast-glyph">{glyph}</span>
                            <span class="bbs-toast-msg">{toast.message.clone()}</span>
                            <button
                                type="button"
                                class="bbs-icon-btn"
                                aria-label="Dismiss"
                                on:click=move |_| store.dismiss(id)
                            >"×"</button>
                        </div>
                    }
                }
            </For>
        </div>
    }
}

/// Click-to-copy button for a public key / npub / address.
#[component]
pub fn CopyKeyBtn(
    #[prop(into)] full: String,
    #[prop(optional, into)] label: Option<String>,
) -> impl IntoView {
    let copied = RwSignal::new(false);
    let shown = label.unwrap_or_else(|| shorten_pubkey(&full));
    let full_for_click = full.clone();
    view! {
        <button
            type="button"
            class="bbs-copy-btn"
            title=format!("Copy {full}")
            on:click=move |ev| {
                ev.stop_propagation();
                let f = full_for_click.clone();
                clipboard::copy_text_then(&f, move |ok| {
                    if ok {
                        copied.set(true);
                        nostr_bbs_client_core::utils::set_timeout_once(
                            move || { let _ = copied.try_set(false); },
                            1400,
                        );
                    }
                });
            }
        >
            {move || if copied.get() { "✓ copied".to_string() } else { format!("{shown} ⧉") }}
        </button>
    }
}

/// Author display chip: resolved display name (links to `#/profile/<pk>`) +
/// honest agent disclosure pill (when the registry marks them as an agent).
#[component]
pub fn AuthorChip(#[prop(into)] pubkey: String) -> impl IntoView {
    let router = use_router();
    let pk_name = pubkey.clone();
    let pk_nav = pubkey.clone();
    let pk_agent = pubkey.clone();

    view! {
        <span class="bbs-author-chip">
            <button
                type="button"
                class="bbs-author-btn"
                on:click=move |ev| {
                    ev.stop_propagation();
                    router.go(Route::Profile { pubkey: pk_nav.clone() });
                }
            >
                {move || use_display_name_tracked(&pk_name)}
            </button>
            {move || {
                let cache = try_use_agent_disclosure()?;
                let entry = cache.lookup(&pk_agent);
                let st = badge_state(&cache.status(), entry.as_ref(), now_secs(), DISCLOSURE_TTL_SECS);
                match st {
                    BadgeState::Agent { registered_by, .. } => {
                        let owner = use_display_name_tracked(&registered_by);
                        Some(view! {
                            <span class="bbs-badge bbs-badge-info" title=format!("Agent authorised by {owner}")>
                                "AGENT"
                            </span>
                        }.into_any())
                    }
                    _ => None,
                }
            }}
        </span>
    }
}

/// Render user-authored Markdown safely in phosphor terminal styling using
/// `nostr_bbs_client_core::utils::sanitize::render_markdown`.
#[component]
pub fn MarkdownBody(#[prop(into)] content: String) -> impl IntoView {
    let html = sanitize::sanitize_markdown(&content);
    view! { <div class="bbs-md" inner_html=html></div> }
}

/// Render an SVG QR code completely in-WASM (never exposes secrets to JS).
pub fn qr_svg(payload: &str) -> Option<String> {
    use qrcode::render::svg;
    use qrcode::{EcLevel, QrCode};
    let code = QrCode::with_error_correction_level(payload.as_bytes(), EcLevel::M).ok()?;
    Some(
        code.render::<svg::Color>()
            .min_dimensions(180, 180)
            .dark_color(svg::Color("#0a0a0a"))
            .light_color(svg::Color("#ffffff"))
            .build(),
    )
}

/// Launch the UA 571-C Aliens Sentry Gun overlay defined in `index.html`.
pub fn launch_sentry() {
    #[cfg(target_arch = "wasm32")]
    if let Some(doc) = web_sys::window().and_then(|w| w.document()) {
        if let Ok(ev) = web_sys::CustomEvent::new("bbs:sentry") {
            let _ = doc.dispatch_event(&ev);
        }
    }
}

/// Shared empty-state card with optional action hint.
#[component]
pub fn EmptyCard(#[prop(into)] title: String, #[prop(into)] body: String) -> impl IntoView {
    view! {
        <div class="tui-card tui-empty">
            <div class="tui-empty-title">{title}</div>
            <p class="tui-muted">{body}</p>
        </div>
    }
}
