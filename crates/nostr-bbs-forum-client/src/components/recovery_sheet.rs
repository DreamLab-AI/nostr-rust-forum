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
use wasm_bindgen::JsCast;

use crate::app::base_href;
use crate::components::info_term::InfoTerm;
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

/// Trigger a browser download of a self-contained HTML recovery document.
///
/// Builds a standalone HTML page with all QR codes (inline SVG), the recovery
/// key, relay address, and restore instructions — identical content to the
/// printable sheet but delivered as a direct file download. On Android this
/// prompts the download permission once and saves immediately, bypassing the
/// `window.print()` dialog entirely.
///
/// The secret key never leaves the browser: the Blob is constructed in WASM,
/// the object-URL is ephemeral, and the hidden `<a>` is removed after click.
struct RecoveryDownload<'a> {
    display_name: &'a str,
    created: &'a str,
    nip05: Option<&'a str>,
    connect_url: Option<&'a str>,
    connect_qr: &'a str,
    nsec: &'a str,
    nsec_qr: &'a str,
    relay_url: &'a str,
    relay_qr: &'a str,
    npub: &'a str,
    npub_qr: &'a str,
}

fn download_recovery_html(sheet: RecoveryDownload<'_>) {
    let RecoveryDownload {
        display_name,
        created,
        nip05,
        connect_url,
        connect_qr,
        nsec,
        nsec_qr,
        relay_url,
        relay_qr,
        npub,
        npub_qr,
    } = sheet;
    let nip05_line = nip05
        .filter(|h| !h.is_empty())
        .map(|h| format!(" &middot; {h}"))
        .unwrap_or_default();

    let connect_section = connect_url
        .map(|url| {
            format!(
                r#"<div style="border:2px solid #dc2626;border-radius:12px;padding:16px;background:#fef2f2">
  <p style="font-size:14px;font-weight:bold;color:#b91c1c;text-transform:uppercase;letter-spacing:0.05em">📱 Sign in on your phone</p>
  <p style="font-size:12px;color:#1f2937;margin:6px 0">Scan this code with your phone's camera — the forum opens and signs you in.</p>
  <p style="font-size:11px;color:#b91c1c;font-weight:bold;margin-bottom:10px">⚠ Treat this code like a key to your account.</p>
  <div style="display:flex;gap:16px;align-items:flex-start;flex-wrap:wrap">
    <div style="flex-shrink:0">{connect_qr}</div>
    <div style="min-width:0;flex:1"><p style="font-size:10px;color:#dc2626;text-transform:uppercase;margin-bottom:4px">your sign-in link</p><code style="font-size:10px;word-break:break-all">{url}</code></div>
  </div>
</div>"#
            )
        })
        .unwrap_or_default();

    let html = format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Recovery Sheet – {display_name}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; max-width: 700px; margin: 0 auto; padding: 20px; color: #111; background: #fff; }}
  code {{ font-family: "SF Mono", "Cascadia Code", "Fira Code", monospace; word-break: break-all; }}
  svg {{ width: 180px; height: 180px; }}
  .section {{ border: 1px solid #d1d5db; border-radius: 12px; padding: 16px; margin-bottom: 16px; }}
  .secret {{ border: 2px solid #dc2626; background: #fef2f2; }}
  h1 {{ font-size: 20px; margin: 0 0 4px; }}
  @media print {{ @page {{ margin: 12mm; }} }}
</style>
</head>
<body>
<div style="border-bottom:1px solid #d1d5db;padding-bottom:12px;margin-bottom:16px">
  <h1>Your account &amp; sign-in sheet</h1>
  <p style="font-size:12px;color:#4b5563">Save this file and keep it somewhere safe — it's how you get back into your account. Everything here is private to you; don't share it.</p>
  <p style="font-size:11px;color:#6b7280;margin-top:4px">Account: {display_name}{nip05_line} &middot; Created {created}</p>
</div>

{connect_section}

<div class="section secret">
  <p style="font-size:14px;font-weight:bold;color:#b91c1c;text-transform:uppercase;letter-spacing:0.05em">🔑 Your recovery key</p>
  <p style="font-size:12px;color:#1f2937;margin:6px 0">This is the master key to your account. Anyone who reads it can sign in as you.</p>
  <div style="display:flex;gap:16px;align-items:flex-start;flex-wrap:wrap">
    <div style="flex-shrink:0">{nsec_qr}</div>
    <div style="min-width:0;flex:1"><p style="font-size:10px;color:#dc2626;text-transform:uppercase;margin-bottom:4px">recovery key (nsec)</p><code style="font-size:12px">{nsec}</code></div>
  </div>
</div>

<div class="section">
  <p style="font-size:14px;font-weight:bold;text-transform:uppercase;letter-spacing:0.05em">📡 Server address</p>
  <p style="font-size:12px;color:#4b5563;margin:6px 0">Only needed if you connect a separate messaging app.</p>
  <div style="display:flex;gap:16px;align-items:flex-start;flex-wrap:wrap">
    <div style="flex-shrink:0">{relay_qr}</div>
    <div style="min-width:0;flex:1"><p style="font-size:10px;color:#6b7280;text-transform:uppercase;margin-bottom:4px">address (relay)</p><code style="font-size:12px">{relay_url}</code></div>
  </div>
</div>

<div class="section">
  <p style="font-size:14px;font-weight:bold;text-transform:uppercase;letter-spacing:0.05em">🪪 Your public profile</p>
  <p style="font-size:12px;color:#4b5563;margin:6px 0">Safe to share — it's how people find you.</p>
  <div style="display:flex;gap:16px;align-items:flex-start;flex-wrap:wrap">
    <div style="flex-shrink:0">{npub_qr}</div>
    <div style="min-width:0;flex:1">
      <p style="font-size:12px"><strong>Name:</strong> {display_name}</p>
      <p style="font-size:10px;color:#6b7280;text-transform:uppercase;margin-top:6px">public ID (npub)</p>
      <code style="font-size:12px">{npub}</code>
    </div>
  </div>
</div>

<div class="section" style="background:#f9fafb">
  <p style="font-size:14px;font-weight:bold;text-transform:uppercase;letter-spacing:0.05em">📖 How to restore</p>
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-top:8px">
    <div>
      <p style="font-size:13px;font-weight:600;margin-bottom:4px">On your phone (easiest)</p>
      <ol style="font-size:11px;color:#374151;padding-left:16px;margin:0">
        <li>Point your phone's camera at the 📱 code.</li>
        <li>The forum opens and signs you in automatically.</li>
      </ol>
    </div>
    <div>
      <p style="font-size:13px;font-weight:600;margin-bottom:4px">On a computer</p>
      <ol style="font-size:11px;color:#374151;padding-left:16px;margin:0">
        <li>Open the forum's sign-in page.</li>
        <li>Paste your recovery key (the 🔑 key above).</li>
        <li>You're back in — same account.</li>
      </ol>
    </div>
  </div>
</div>
</body>
</html>"##
    );

    let Some(window) = web_sys::window() else {
        return;
    };
    let Some(document) = window.document() else {
        return;
    };

    let parts = js_sys::Array::new();
    parts.push(&html.into());

    let opts = web_sys::BlobPropertyBag::new();
    opts.set_type("text/html;charset=utf-8");

    let Ok(blob) = web_sys::Blob::new_with_str_sequence_and_options(&parts, &opts) else {
        return;
    };
    let Ok(url) = web_sys::Url::create_object_url_with_blob(&blob) else {
        return;
    };

    if let Ok(a) = document.create_element("a") {
        let _ = a.set_attribute("href", &url);
        let _ = a.set_attribute("download", "nostr-bbs-recovery.html");
        let _ = a.set_attribute("style", "display:none");
        if let Some(body) = document.body() {
            let _ = body.append_child(&a);
            if let Some(el) = a.dyn_ref::<web_sys::HtmlElement>() {
                el.click();
            }
            let _ = body.remove_child(&a);
        }
        let _ = web_sys::Url::revoke_object_url(&url);
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

    // Capture values for the download closure (cloned once; the closure is Fn).
    let dl_display = display_name.clone();
    let dl_created = created.clone();
    let dl_nip05 = nip05.clone();
    let dl_connect_url = connect_url.clone();
    let dl_connect_qr = connect_qr.clone();
    let dl_nsec = nsec.clone();
    let dl_nsec_qr = nsec_qr.clone();
    let dl_relay = relay_url.clone();
    let dl_relay_qr = relay_qr.clone();
    let dl_npub = npub.clone();
    let dl_npub_qr = npub_qr.clone();
    let on_download = move |_| {
        download_recovery_html(RecoveryDownload {
            display_name: &dl_display,
            created: &dl_created,
            nip05: dl_nip05.as_deref(),
            connect_url: dl_connect_url.as_deref(),
            connect_qr: &dl_connect_qr,
            nsec: &dl_nsec,
            nsec_qr: &dl_nsec_qr,
            relay_url: &dl_relay,
            relay_qr: &dl_relay_qr,
            npub: &dl_npub,
            npub_qr: &dl_npub_qr,
        });
        printed.set(true);
    };

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
                    <h2 class="text-xl font-bold text-gray-900">"Your account & sign-in sheet"</h2>
                    <p class="text-xs text-gray-600">
                        "Save this page as a PDF (or print it) and keep it somewhere safe — "
                        "it\u{2019}s how you get back into your account if you lose this browser. "
                        "To sign in on your phone, just scan the 📱 code with your camera. "
                        "Everything on this sheet is private to you; don\u{2019}t share it."
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
                                "Sign in on your phone"
                            </span>
                        </div>
                        <p class="text-xs text-gray-800 mb-2 font-medium">
                            "Scan this code with your phone\u{2019}s camera — the forum opens and signs you in. That\u{2019}s it."
                        </p>
                        <p class="text-xs text-red-700 mb-3 font-bold">
                            "\u{26a0} Treat this code like a key to your account. Anyone who scans or photographs it can sign in as you, so keep this sheet private."
                        </p>
                        <div class="flex flex-col sm:flex-row items-center gap-4">
                            <div class="rs-qr flex-shrink-0" inner_html=connect_qr.clone()></div>
                            <div class="min-w-0 w-full">
                                <p class="text-[10px] uppercase tracking-wide text-red-600 mb-1">
                                    "your sign-in link"
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
                            "Your recovery key"
                        </span>
                    </div>
                    <p class="text-xs text-gray-800 mb-2">
                        "This is the master key to your account — keep it on this sheet as your backup. "
                        "Anyone who reads it can sign in as you, so don\u{2019}t share it or type it anywhere except a trusted sign-in screen."
                    </p>
                    <details class="mb-3 rs-no-print">
                        <summary class="text-xs text-gray-600 cursor-pointer hover:text-gray-900">
                            "Using another app? (advanced)"
                        </summary>
                        <p class="text-xs text-gray-700 mt-2">
                            "In a compatible app (e.g. 0xchat) choose "
                            <span class="font-semibold">"\u{201c}Login with private key\u{201d}"</span>
                            " and paste the key below, or import it into a signer app such as Amber. "
                            <span class="font-semibold text-red-700">
                                "Don\u{2019}t use \u{201c}Login with QR code\u{201d}"
                            </span>
                            " in those apps — that\u{2019}s a different feature, not this key."
                        </p>
                    </details>
                    <div class="flex flex-col sm:flex-row items-center gap-4">
                        <div class="rs-qr flex-shrink-0" inner_html=nsec_qr></div>
                        <div class="min-w-0 w-full">
                            <p class="text-[10px] uppercase tracking-wide text-red-600 mb-1">
                                "recovery key "
                                <InfoTerm
                                    term="(nsec)"
                                    explainer="Your account's secret key — the technical name is \"nsec\". It's the master password for your account; never share it."
                                    slug="nsec"
                                />
                            </p>
                            <code class="block text-xs text-gray-900 font-mono">{nsec}</code>
                        </div>
                    </div>
                </div>

                // ── 📡 Server address (relay) ─────────────────────────────
                <div class="border border-gray-300 rounded-xl p-4">
                    <div class="flex items-center gap-2 mb-2">
                        <span class="text-lg">"📡"</span>
                        <span class="text-sm font-bold text-gray-800 uppercase tracking-wide">
                            "Server address"
                        </span>
                    </div>
                    <p class="text-xs text-gray-600 mb-2">
                        "You don\u{2019}t need this for the website — it\u{2019}s only if you connect a separate "
                        <InfoTerm
                            term="messaging app"
                            explainer="An optional third-party app that can show this forum's messages. Most people never need this."
                            slug="giftwrap"
                        />
                        ". Paste the address below to point it at this community."
                    </p>
                    <div class="flex flex-col sm:flex-row items-center gap-4">
                        <div class="rs-qr flex-shrink-0" inner_html=relay_qr></div>
                        <div class="min-w-0 w-full">
                            <p class="text-[10px] uppercase tracking-wide text-gray-500 mb-1">
                                "address "
                                <InfoTerm
                                    term="(relay)"
                                    explainer="The server that stores and shares this community's messages. The technical name is \"relay\"."
                                    slug="relay"
                                />
                            </p>
                            <code class="block text-xs text-gray-900 font-mono">{relay_url}</code>
                        </div>
                    </div>
                </div>

                // ── 🪪 Public profile (npub) ──────────────────────────────
                <div class="border border-gray-300 rounded-xl p-4">
                    <div class="flex items-center gap-2 mb-2">
                        <span class="text-lg">"🪪"</span>
                        <span class="text-sm font-bold text-gray-800 uppercase tracking-wide">"Your public profile"</span>
                    </div>
                    <p class="text-xs text-gray-600 mb-2">
                        "This part is safe to share — it\u{2019}s how people find and follow you. It can\u{2019}t be used to sign in as you."
                    </p>
                    <div class="flex flex-col sm:flex-row items-center gap-4">
                        <div class="rs-qr flex-shrink-0" inner_html=npub_qr></div>
                        <div class="min-w-0 w-full space-y-1">
                            <p class="text-xs text-gray-700">
                                <span class="font-semibold">"Name: "</span>{display_name.clone()}
                            </p>
                            {nip05.clone().map(|h| view! {
                                <p class="text-xs text-gray-700">
                                    <span class="font-semibold">"Handle: "</span>{h}
                                </p>
                            })}
                            <p class="text-xs text-gray-700">
                                <span class="font-semibold">"Created: "</span>{created.clone()}
                            </p>
                            <p class="text-[10px] uppercase tracking-wide text-gray-500 mt-1">
                                "public ID "
                                <InfoTerm
                                    term="(npub)"
                                    explainer="Your public username code — the technical name is \"npub\". Safe to share so others can find you."
                                    slug="npub"
                                />
                            </p>
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
                                "Tear-off — add another phone"
                            </span>
                        </div>
                        <p class="text-xs text-gray-700 mb-2">
                            "Want to sign in on an extra phone without sharing your main recovery key? "
                            "Create a separate sign-in code for it below, then scan that code on the phone. "
                            "You can switch it off anytime in Settings \u{2192} Devices — your main account and the keys above stay untouched."
                        </p>
                        <p class="text-xs text-amber-700 mb-3 font-medium">
                            "\u{26a0} This code lets that phone sign in as you until you switch it off. "
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
                                    "Creating…"
                                } else if device_connect.get().is_empty() {
                                    "Create a sign-in code for another phone"
                                } else {
                                    "Create another sign-in code"
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
                                        "sign-in code for the other phone"
                                    </p>
                                    <p class="text-xs text-gray-800 mb-1">
                                        "Scan it with that phone. Switch it off anytime in Settings \u{2192} Devices."
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
                            <p class="font-semibold text-gray-900 mb-1">"On your phone (easiest)"</p>
                            <ol class="list-decimal list-inside space-y-1 text-xs text-gray-700">
                                <li>"Point your phone\u{2019}s camera at the 📱 code."</li>
                                <li>"The forum opens and signs you in automatically."</li>
                                <li>
                                    "Using another app? In a compatible app, choose "
                                    <span class="font-semibold">"Login with private key"</span>
                                    " and paste your recovery key (or scan the 🔑 code)."
                                </li>
                            </ol>
                        </div>
                        <div>
                            <p class="font-semibold text-gray-900 mb-1">"On a computer"</p>
                            <ol class="list-decimal list-inside space-y-1 text-xs text-gray-700">
                                <li>"Open the forum\u{2019}s sign-in page."</li>
                                <li>"Paste your recovery key (or scan the 🔑 code)."</li>
                                <li>"You\u{2019}re back in — same account."</li>
                            </ol>
                        </div>
                    </div>
                </div>

                // ── Advanced privacy option — hidden from the basic flow ──
                // The single-relay "sweep" is a power-user privacy step; it
                // confused newcomers, so it now lives behind an Advanced
                // disclosure (screen-only) and is described in plain language.
                <details class="rs-screen-controls border border-gray-300 rounded-xl p-4">
                    <summary class="text-sm text-gray-700 cursor-pointer hover:text-gray-900">
                        "Advanced privacy options"
                    </summary>
                    <label class="flex items-start gap-2 cursor-pointer text-sm text-gray-800 mt-3">
                        <input
                            type="checkbox"
                            class="mt-1"
                            on:change=on_toggle_sweep
                            data-testid="recovery-sweep-toggle"
                        />
                        <span>
                            <span class="font-semibold">"Keep my messaging app on this community only "</span>
                            <span class="text-xs text-gray-500">"(optional)"</span>
                            <span class="block text-xs text-gray-500 mt-0.5">
                                "If you connect a separate messaging app, this adds steps to stop it sharing your activity with other public servers. Not needed to use the website."
                            </span>
                        </span>
                    </label>
                </details>

                // The detailed steps print only when ticked.
                <Show when=move || sweep.get()>
                    <div class="border border-amber-500 rounded-xl p-4 bg-amber-50 text-sm text-gray-800">
                        <div class="flex items-center gap-2 mb-2">
                            <span class="text-lg">"⚙️"</span>
                            <span class="font-bold uppercase tracking-wide text-amber-700">
                                "Keep to one community"
                            </span>
                        </div>
                        <ol class="list-decimal list-inside space-y-1 text-xs text-gray-700">
                            <li>"In your messaging app, open its Servers (or Relays) settings."</li>
                            <li>"Remove every address except the 📡 Server address shown above."</li>
                            <li>"Keep only that one, so your activity stays within this community."</li>
                        </ol>
                        <p class="text-xs text-amber-700 mt-2">
                            "This is optional and only affects a separate messaging app — it stops that app sharing your activity with other public servers. Your account works fine without it."
                        </p>
                    </div>
                </Show>

                // ── Download + print / gate controls (never printed) ────
                <div class="rs-screen-controls border-t border-gray-300 pt-4 space-y-3">
                    <button
                        on:click=on_download
                        class="w-full bg-gray-900 hover:bg-gray-700 text-white font-semibold py-3 px-4 rounded-xl transition-colors text-sm"
                        data-testid="recovery-download"
                    >
                        "Download recovery file"
                    </button>
                    <p class="text-xs text-gray-500">
                        "Downloads a file with your sign-in QR codes and recovery key. Keep it somewhere safe — that one file keeps your access."
                    </p>
                    <button
                        on:click=on_print
                        class="w-full border border-gray-400 hover:bg-gray-100 text-gray-700 font-medium py-2 px-4 rounded-xl transition-colors text-xs"
                        data-testid="recovery-print"
                    >
                        "Print a paper copy instead"
                    </button>
                    <label class="flex items-center gap-2 cursor-pointer text-sm text-gray-800">
                        <input
                            type="checkbox"
                            on:change=on_toggle_confirm
                            data-testid="recovery-confirm"
                        />
                        <span>"I\u{2019}ve saved this somewhere safe"</span>
                    </label>
                    <Show when=move || printed.get() && confirmed.get()>
                        <p class="text-xs text-green-700 font-medium" data-testid="recovery-ready">
                            "\u{2713} Saved — you\u{2019}re ready to finish."
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
