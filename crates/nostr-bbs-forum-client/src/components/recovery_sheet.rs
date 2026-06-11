//! Recovery & device-onboarding sheet (ADR-095, extended by ADR-098).
//!
//! Renders a print-optimised one-page sheet of QR codes that simultaneously
//! (a) backs up the account, (b) onboards this user's phone into the forum PWA
//! via the `/connect` magic-link QR (ADR-098 — scan with the phone camera, the
//! forum opens and signs you in), and (c) optionally onboards a third-party
//! mobile Nostr client (0xchat / Amber) for power users.
//!
//! ## /connect magic-link QR (primary mobile path — ADR-098)
//!
//! The 📱 block encodes `{origin}{FORUM_BASE}/connect#k=<nsec1…>`, computed
//! from the LIVE browser origin so the printed/scanned link points at the same
//! deployment the user signed up on. The nsec rides in the URL *fragment*
//! (after `#`) — fragments are never transmitted to the server. `/connect`
//! strips the fragment from history before importing the key. This QR IS the
//! account (bearer credential), hence the red warning. It is the recommended
//! mobile path because it lands the user in the full forum surface, not a
//! third-party client.
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

use crate::app::base_href;
use crate::utils::devices::{device_connect_url, device_keys_enabled, register_device_with_master};

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

    // --- /connect magic-link URL (ADR-098) -----------------------------------
    // Computed from the LIVE origin so the printed link targets the exact
    // deployment the user signed up on. The nsec rides in the URL *fragment*
    // (after `#`) — never a query string — so it is never transmitted to the
    // server. `base_href("/connect")` applies the FORUM_BASE prefix (e.g.
    // `/community/connect`) when the forum is mounted in a sub-directory.
    let connect_url = web_sys::window()
        .and_then(|w| w.location().origin().ok())
        .map(|origin| format!("{origin}{}#k={nsec}", base_href("/connect")));

    // --- QR SVGs (generated once at mount) -----------------------------------
    let connect_qr = connect_url.as_deref().map(qr_svg).unwrap_or_default();
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

    // --- Tear-off device key (ADR-099, gated) --------------------------------
    // Only rendered when `window.__ENV__.DEVICE_KEYS_ENABLED` is truthy.
    // A device key is a deterministic subkey of the master (ADR-094); its
    // /connect QR carries the DEVICE nsec (never the master) so a lost phone is
    // revoked from Settings without rotating the master identity.
    let device_keys_on = device_keys_enabled();
    // QR SVG for the device /connect link, rendered after Generate. Empty until
    // a device key is produced on click.
    let device_qr = RwSignal::new(String::new());
    let device_connect = RwSignal::new(String::new());
    let device_busy = RwSignal::new(false);
    let device_err: RwSignal<Option<String>> = RwSignal::new(None);

    // Hold the master hex in a Copy `StoredValue` so the click handler can be a
    // `Fn` closure (required inside `<Show>` children) without moving a String.
    let master_for_device = StoredValue::new(privkey_hex.clone());
    let on_generate_device = move |_| {
        if device_busy.get_untracked() {
            return;
        }
        device_busy.set(true);
        device_err.set(None);
        let master = master_for_device.get_value();
        wasm_bindgen_futures::spawn_local(async move {
            // Label the device by creation date — the phone is named in Settings.
            let label = format!("Phone added {}", created_date_utc());
            match register_device_with_master(&master, &label).await {
                Ok(reg) => {
                    let url = device_connect_url(&reg.device_nsec).unwrap_or_default();
                    device_qr.set(qr_svg(&url));
                    device_connect.set(url);
                }
                Err(e) => device_err.set(Some(e.to_string())),
            }
            device_busy.set(false);
        });
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
                 .recovery-sheet code { word-break: break-all; }\n\
                 .rs-tearoff { border: 2px dashed #6b7280; border-radius: 0; \
                   position: relative; }\n\
                 @media print { .rs-tearoff { break-inside: avoid; } }"
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
                        "It backs up your account and lets you sign in on your phone "
                        "(scan the 📱 QR with your camera)."
                    </p>
                    <p class="text-xs text-gray-500 mt-1">
                        {format!("Account: {display_name}")}
                        {nip05.clone().map(|h| format!(" · {h}")).unwrap_or_default()}
                        {format!(" · Created {created}")}
                    </p>
                </div>

                // ── 📱 Open on this phone (PRIMARY mobile path — ADR-098) ──
                // A phone-camera scan of this QR opens the forum PWA and signs the
                // user in. This is the recommended mobile path: it lands them in
                // the full forum surface, not a third-party client.
                <Show when={
                    let has = connect_url.is_some();
                    move || has
                }>
                    <div class="border-2 border-red-600 rounded-xl p-4 bg-red-50">
                        <div class="flex items-center gap-2 mb-2">
                            <span class="text-lg">"📱"</span>
                            <span class="text-sm font-bold text-red-700 uppercase tracking-wide">
                                "Open on this phone — bearer credential"
                            </span>
                        </div>
                        <p class="text-xs text-gray-800 mb-2 font-medium">
                            "Scan with your phone camera → opens the forum and signs you in."
                        </p>
                        <p class="text-xs text-red-700 mb-3 font-bold">
                            "⚠ This link/QR IS your account. Anyone who scans or copies it can sign in "
                            "as you. Keep this sheet private."
                        </p>
                        <div class="flex flex-col sm:flex-row items-center gap-4">
                            <div class="rs-qr flex-shrink-0" inner_html=connect_qr.clone()></div>
                            <div class="min-w-0 w-full">
                                <p class="text-[10px] uppercase tracking-wide text-red-600 mb-1">
                                    "forum sign-in link"
                                </p>
                                <code class="block text-[10px] text-gray-900 font-mono">
                                    {connect_url.clone().unwrap_or_default()}
                                </code>
                            </div>
                        </div>
                    </div>
                </Show>

                // ── 🔑 SECRET (nsec) — bearer credential ──────────────────
                // This is the raw private key for power users importing into a
                // third-party signer. It is NOT 0xchat's "Login with QR".
                <div class="border-2 border-red-600 rounded-xl p-4 bg-red-50">
                    <div class="flex items-center gap-2 mb-2">
                        <span class="text-lg">"🔑"</span>
                        <span class="text-sm font-bold text-red-700 uppercase tracking-wide">
                            "Secret key (nsec) — bearer credential"
                        </span>
                    </div>
                    <p class="text-xs text-red-700 mb-2 font-medium">
                        "ANYONE who scans or reads this controls your account. Keep this sheet private."
                    </p>
                    <p class="text-xs text-gray-800 mb-3">
                        "Paste into 0xchat via "
                        <span class="font-semibold">"\u{201c}Login with private key\u{201d}"</span>
                        ", or scan into a signer app (Amber). "
                        <span class="font-semibold text-red-700">
                            "Do NOT use 0xchat\u{2019}s \u{201c}Login with QR code\u{201d}"
                        </span>
                        " — that is a remote-signer QR, not this key."
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

                // ── ✂ TEAR-OFF — ADD A PHONE (ADR-099, gated) ────────────
                // A *separable* card carrying a REVOCABLE device key's /connect QR.
                // Unlike the 📱 master link above, this grants forum access you can
                // kill from Settings → Devices without rotating your master identity.
                // The dashed border is the cut line; it prints as a tear-off strip.
                // Hidden entirely unless DEVICE_KEYS_ENABLED is set — zero change off.
                <Show when=move || device_keys_on>
                    <div class="rs-tearoff p-4 bg-gray-50">
                        <div class="flex items-center gap-2 mb-2">
                            <span class="text-lg">"\u{2702}"</span>
                            <span class="text-sm font-bold text-gray-800 uppercase tracking-wide">
                                "Tear-off — add a phone"
                            </span>
                        </div>
                        <p class="text-xs text-gray-700 mb-2">
                            "Generate a "
                            <span class="font-semibold">"revocable device key"</span>
                            " for a phone. Scan its QR to sign in on that device. "
                            "Revoke it anytime in Settings → Devices — your main "
                            "account and recovery keys above are untouched."
                        </p>
                        <p class="text-xs text-amber-700 mb-3 font-medium">
                            "\u{26a0} The QR below grants forum access AS YOU until revoked. "
                            "Cut along the dashed line and keep it private."
                        </p>

                        // Screen-only generate control (never printed).
                        <div class="rs-screen-controls mb-3">
                            <button
                                on:click=on_generate_device
                                prop:disabled=move || device_busy.get()
                                class="text-sm bg-gray-900 hover:bg-gray-700 disabled:bg-gray-400 text-white font-semibold py-2 px-4 rounded-lg transition-colors"
                                data-testid="recovery-device-generate"
                            >
                                {move || if device_busy.get() {
                                    "Generating…"
                                } else if device_connect.get().is_empty() {
                                    "Generate device key"
                                } else {
                                    "Generate another device key"
                                }}
                            </button>
                            <Show when=move || device_err.get().is_some()>
                                <p class="text-xs text-red-600 mt-2" data-testid="recovery-device-error">
                                    {move || device_err.get().unwrap_or_default()}
                                </p>
                            </Show>
                        </div>

                        // The QR + link render once a device key exists.
                        <Show when=move || !device_connect.get().is_empty()>
                            <div class="flex flex-col sm:flex-row items-center gap-4">
                                <div
                                    class="rs-qr flex-shrink-0"
                                    inner_html=move || device_qr.get()
                                    data-testid="recovery-device-qr"
                                ></div>
                                <div class="min-w-0 w-full">
                                    <p class="text-[10px] uppercase tracking-wide text-gray-500 mb-1">
                                        "device sign-in link"
                                    </p>
                                    <p class="text-xs text-gray-800 mb-1">
                                        "Scan with your phone; revoke anytime in Settings → Devices."
                                    </p>
                                    <code class="block text-[10px] text-gray-900 font-mono">
                                        {move || device_connect.get()}
                                    </code>
                                </div>
                            </div>
                        </Show>
                    </div>
                </Show>

                // ── 📖 Restore steps ──────────────────────────────────────
                <div class="border border-gray-300 rounded-xl p-4 text-sm text-gray-800">
                    <div class="flex items-center gap-2 mb-2">
                        <span class="text-lg">"📖"</span>
                        <span class="font-bold uppercase tracking-wide">"How to restore"</span>
                    </div>
                    <div class="grid sm:grid-cols-2 gap-4">
                        <div>
                            <p class="font-semibold text-gray-900 mb-1">"On mobile (recommended)"</p>
                            <ol class="list-decimal list-inside space-y-1 text-xs text-gray-700">
                                <li>"Scan the 📱 QR with your phone camera."</li>
                                <li>"The forum opens and signs you in automatically."</li>
                                <li>
                                    "Power users: 0xchat → "
                                    <span class="font-semibold">"Login with private key"</span>
                                    " → paste the nsec; or import the nsec into Amber and use "
                                    <span class="font-semibold">"Login with Amber"</span>
                                    "."
                                </li>
                            </ol>
                        </div>
                        <div>
                            <p class="font-semibold text-gray-900 mb-1">"On the web"</p>
                            <ol class="list-decimal list-inside space-y-1 text-xs text-gray-700">
                                <li>"Open the forum sign-in page."</li>
                                <li>"Paste your nsec (or scan the 🔑 QR)."</li>
                                <li>"You're back in — same account."</li>
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
