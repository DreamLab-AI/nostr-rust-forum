//! Recovery & device-onboarding sheet (ADR-095).
//!
//! Renders a print-optimised one-page sheet of QR codes that simultaneously
//! (a) backs up the account and (b) onboards a mobile Nostr client (0xchat).
//!
//! ## Hard invariant
//!
//! The secret key is the in-browser key generated at signup. It MUST NEVER
//! leave the browser or touch the network. Everything here is rendered
//! 100% client-side:
//!
//! * the nsec is bech32-encoded in-WASM via the existing NIP-19 path
//!   (`nostr_bbs_core::encode_nsec` / `encode_npub`) — bech32 is never
//!   hand-rolled;
//! * QR codes are generated in-WASM by the pure-Rust `qrcode` crate
//!   (SVG strings, no JS QR dependency, so the secret never crosses the
//!   WASM/JS boundary into untrusted code);
//! * the sheet is materialised through `window.print()` — the inline
//!   `@media print` stylesheet hides everything but `.recovery-sheet`, so the
//!   browser print dialog yields a clean one-page Save-as-PDF / paper copy.
//!
//! No server round-trip ever sees the nsec.
//!
//! ## 0xchat onboarding (research facts)
//!
//! Target client: 0xchat (Android) — NIP-17 gift-wrap DMs by default, NIP-28
//! channels, NIP-42 AUTH. Login QR payload is a bare `nsec1…` (bech32). The
//! relay is added separately (the deployment already publishes a NIP-65
//! kind-10002 relay-list nudge). The optional "sweep" — removing 0xchat's
//! default relays to lock to one relay — is a privacy option, not required.
//!
//! ## ncryptsec (NIP-49) — deferred
//!
//! `nostr-bbs-core` does not expose a NIP-49 encryption surface, so the
//! optional `ncryptsec1…` QR is omitted (see ADR-095). When core adds NIP-49
//! this component gains a third optional QR behind its own checkbox.

use leptos::prelude::*;
use qrcode::render::svg;
use qrcode::{EcLevel, QrCode};

/// Render `data` as a self-contained SVG QR-code string (pure-Rust, in-WASM).
///
/// Returns an empty string on the (practically impossible for our payload
/// sizes) encode failure so the caller can degrade gracefully without panicking
/// the signup flow.
fn qr_svg(data: &str) -> String {
    match QrCode::with_error_correction_level(data.as_bytes(), EcLevel::M) {
        Ok(code) => code
            .render::<svg::Color>()
            .min_dimensions(220, 220)
            .quiet_zone(true)
            .dark_color(svg::Color("#000000"))
            .light_color(svg::Color("#ffffff"))
            .build(),
        Err(_) => String::new(),
    }
}

/// Recovery & device-onboarding sheet.
///
/// All inputs are plain strings sourced exactly where `NsecBackup` sources the
/// nsec (the in-browser hex key). This component bech32-encodes for display and
/// QR generation only; it never re-derives or re-fetches a key.
#[component]
pub(crate) fn RecoverySheet(
    /// Hex-encoded private key (64 chars) — the SAME source as `NsecBackup`.
    privkey_hex: String,
    /// Hex-encoded public key (64 chars).
    pubkey_hex: String,
    /// WebSocket relay URL (e.g. `wss://relay.example.com`).
    relay_url: String,
    /// Public display name / handle.
    display_name: String,
    /// NIP-05 handle (`user@host`), if one was claimed.
    nip05: Option<String>,
    /// Fired once the user has produced a copy AND ticked the confirmation —
    /// the parent uses this to enable its exit control.
    on_ready: Callback<()>,
) -> impl IntoView {
    // --- Bech32 encode via the existing NIP-19 path (never hand-rolled) ------
    let nsec = nostr_bbs_core::encode_nsec(&privkey_hex).unwrap_or_else(|_| privkey_hex.clone());
    let npub = nostr_bbs_core::encode_npub(&pubkey_hex).unwrap_or_else(|_| pubkey_hex.clone());

    // Created date (UTC, YYYY-MM-DD) for the sheet header. Best-effort.
    let created = created_date_utc();

    // --- QR SVGs (generated once at mount) -----------------------------------
    let nsec_qr = qr_svg(&nsec);
    let relay_qr = qr_svg(&relay_url);
    let npub_qr = qr_svg(&npub);

    // --- Gate state ----------------------------------------------------------
    let printed = RwSignal::new(false);
    let confirmed = RwSignal::new(false);

    // Drive the parent's gate: ready only when a copy was produced AND ticked.
    Effect::new(move |_| {
        if printed.get() && confirmed.get() {
            on_ready.run(());
        }
    });

    let on_print = move |_| {
        if let Some(window) = web_sys::window() {
            window.print().ok();
        }
        printed.set(true);
    };

    let on_toggle_confirm = move |ev: web_sys::Event| {
        confirmed.set(event_target_checked(&ev));
    };

    // Optional "lock my phone to this relay only" sweep block.
    let sweep = RwSignal::new(false);
    let on_toggle_sweep = move |ev: web_sys::Event| {
        sweep.set(event_target_checked(&ev));
    };

    view! {
        // Component-scoped print stylesheet. Hidden screen-side; on print it
        // hides every sibling of `.recovery-sheet` so the dialog produces a
        // clean one-page document. Kept inline so no global CSS file is touched.
        <style>
            "@media print {\n\
               body * { visibility: hidden !important; }\n\
               .recovery-sheet, .recovery-sheet * { visibility: visible !important; }\n\
               .recovery-sheet { position: absolute; left: 0; top: 0; width: 100%; \
                 background: #fff !important; color: #000 !important; padding: 16px; }\n\
               .recovery-sheet .rs-no-print { display: none !important; }\n\
               .rs-screen-controls { display: none !important; }\n\
               .rs-qr svg { width: 180px; height: 180px; }\n\
               @page { margin: 12mm; }\n\
             }\n\
             .rs-qr svg { width: 160px; height: 160px; }\n\
             .recovery-sheet code { word-break: break-all; }"
        </style>

        <div
            class="recovery-sheet bg-white text-gray-900 rounded-2xl border border-gray-300 p-6 space-y-5"
            data-testid="recovery-sheet"
        >
            // ── Header ────────────────────────────────────────────────
            <div class="border-b border-gray-300 pb-3">
                <h2 class="text-xl font-bold text-gray-900">"Recovery & Device Sheet"</h2>
                <p class="text-xs text-gray-600">
                    "Print this page (or Save as PDF) and store it safely. "
                    "It backs up your account and onboards the 0xchat mobile app."
                </p>
                <p class="text-xs text-gray-500 mt-1">
                    {format!("Account: {display_name}")}
                    {nip05.clone().map(|h| format!(" · {h}")).unwrap_or_default()}
                    {format!(" · Created {created}")}
                </p>
            </div>

            // ── 🔑 SECRET (nsec) — bearer credential ──────────────────
            <div class="border-2 border-red-600 rounded-xl p-4 bg-red-50">
                <div class="flex items-center gap-2 mb-2">
                    <span class="text-lg">"🔑"</span>
                    <span class="text-sm font-bold text-red-700 uppercase tracking-wide">
                        "Secret key — bearer credential"
                    </span>
                </div>
                <p class="text-xs text-red-700 mb-3 font-medium">
                    "ANYONE who scans or reads this controls your account. Keep this sheet "
                    "private. This is the 0xchat login QR."
                </p>
                <div class="flex flex-col sm:flex-row items-center gap-4">
                    <div class="rs-qr flex-shrink-0" inner_html=nsec_qr></div>
                    <div class="min-w-0 w-full">
                        <p class="text-[10px] uppercase tracking-wide text-red-600 mb-1">
                            "nsec (bech32)"
                        </p>
                        <code class="block text-xs text-gray-900 font-mono">{nsec}</code>
                    </div>
                </div>
            </div>

            // ── 📡 Relay ──────────────────────────────────────────────
            <div class="border border-gray-300 rounded-xl p-4">
                <div class="flex items-center gap-2 mb-2">
                    <span class="text-lg">"📡"</span>
                    <span class="text-sm font-bold text-gray-800 uppercase tracking-wide">"Relay"</span>
                </div>
                <div class="flex flex-col sm:flex-row items-center gap-4">
                    <div class="rs-qr flex-shrink-0" inner_html=relay_qr></div>
                    <div class="min-w-0 w-full">
                        <p class="text-[10px] uppercase tracking-wide text-gray-500 mb-1">"Add this relay in your client"</p>
                        <code class="block text-xs text-gray-900 font-mono">{relay_url}</code>
                    </div>
                </div>
            </div>

            // ── 🪪 Public identity (npub) ─────────────────────────────
            <div class="border border-gray-300 rounded-xl p-4">
                <div class="flex items-center gap-2 mb-2">
                    <span class="text-lg">"🪪"</span>
                    <span class="text-sm font-bold text-gray-800 uppercase tracking-wide">"Public identity"</span>
                </div>
                <div class="flex flex-col sm:flex-row items-center gap-4">
                    <div class="rs-qr flex-shrink-0" inner_html=npub_qr></div>
                    <div class="min-w-0 w-full space-y-1">
                        <p class="text-xs text-gray-700">
                            <span class="font-semibold">"Name: "</span>{display_name.clone()}
                        </p>
                        {nip05.clone().map(|h| view! {
                            <p class="text-xs text-gray-700">
                                <span class="font-semibold">"NIP-05: "</span>{h}
                            </p>
                        })}
                        <p class="text-xs text-gray-700">
                            <span class="font-semibold">"Created: "</span>{created.clone()}
                        </p>
                        <p class="text-[10px] uppercase tracking-wide text-gray-500 mt-1">"npub (bech32)"</p>
                        <code class="block text-xs text-gray-900 font-mono">{npub}</code>
                    </div>
                </div>
            </div>

            // ── 📖 Restore steps ──────────────────────────────────────
            <div class="border border-gray-300 rounded-xl p-4 text-sm text-gray-800">
                <div class="flex items-center gap-2 mb-2">
                    <span class="text-lg">"📖"</span>
                    <span class="font-bold uppercase tracking-wide">"How to restore"</span>
                </div>
                <div class="grid sm:grid-cols-2 gap-4">
                    <div>
                        <p class="font-semibold text-gray-900 mb-1">"On the web"</p>
                        <ol class="list-decimal list-inside space-y-1 text-xs text-gray-700">
                            <li>"Open the forum sign-in page."</li>
                            <li>"Paste your nsec (or scan the 🔑 QR)."</li>
                            <li>"You're back in — same account."</li>
                        </ol>
                    </div>
                    <div>
                        <p class="font-semibold text-gray-900 mb-1">"On mobile (0xchat)"</p>
                        <ol class="list-decimal list-inside space-y-1 text-xs text-gray-700">
                            <li>"Install 0xchat (Android)."</li>
                            <li>"Login → scan the 🔑 nsec QR above."</li>
                            <li>"Add the 📡 relay (scan its QR / paste the URL)."</li>
                        </ol>
                    </div>
                </div>
            </div>

            // ── ⚙️ Optional sweep (privacy) — screen-only control ─────
            <div class="rs-screen-controls border border-gray-300 rounded-xl p-4">
                <label class="flex items-start gap-2 cursor-pointer text-sm text-gray-800">
                    <input
                        type="checkbox"
                        class="mt-1"
                        on:change=on_toggle_sweep
                        data-testid="recovery-sweep-toggle"
                    />
                    <span>
                        <span class="font-semibold">"Lock my phone to this relay only "</span>
                        <span class="text-xs text-gray-500">"(optional privacy step)"</span>
                    </span>
                </label>
            </div>

            // The sweep block prints only when ticked.
            <Show when=move || sweep.get()>
                <div class="border border-amber-500 rounded-xl p-4 bg-amber-50 text-sm text-gray-800">
                    <div class="flex items-center gap-2 mb-2">
                        <span class="text-lg">"⚙️"</span>
                        <span class="font-bold uppercase tracking-wide text-amber-700">"Single-relay lockdown"</span>
                    </div>
                    <ol class="list-decimal list-inside space-y-1 text-xs text-gray-700">
                        <li>"In 0xchat open Settings → Relays."</li>
                        <li>"Remove every default relay that is NOT the 📡 relay above."</li>
                        <li>"Keep only the one relay so your traffic stays on this deployment."</li>
                    </ol>
                    <p class="text-xs text-amber-700 mt-2">
                        "Privacy note: this stops your phone broadcasting to public relays. "
                        "It is optional — not required for the account to work."
                    </p>
                </div>
            </Show>

            // ── Print / gate controls (never printed) ─────────────────
            <div class="rs-screen-controls border-t border-gray-300 pt-4 space-y-3">
                <button
                    on:click=on_print
                    class="w-full bg-gray-900 hover:bg-gray-700 text-white font-semibold py-3 px-4 rounded-xl transition-colors text-sm"
                    data-testid="recovery-print"
                >
                    "Download / Print sheet"
                </button>
                <label class="flex items-center gap-2 cursor-pointer text-sm text-gray-800">
                    <input
                        type="checkbox"
                        on:change=on_toggle_confirm
                        data-testid="recovery-confirm"
                    />
                    <span>"I've saved my recovery sheet"</span>
                </label>
                <Show when=move || printed.get() && confirmed.get()>
                    <p class="text-xs text-green-700 font-medium" data-testid="recovery-ready">
                        "✓ Sheet saved — you can finish signup."
                    </p>
                </Show>
            </div>
        </div>
    }
}

/// Current UTC date as `YYYY-MM-DD` from the browser clock. Best-effort; on a
/// non-browser context returns an empty string.
fn created_date_utc() -> String {
    let date = js_sys::Date::new_0();
    let y = date.get_utc_full_year();
    let m = date.get_utc_month() + 1; // 0-indexed
    let d = date.get_utc_date();
    format!("{y:04}-{m:02}-{d:02}")
}
