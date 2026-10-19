//! Settings card for Web Push alerts (ADR-2023).
//!
//! Hidden entirely unless the browser supports push and the relay reports the
//! feature as enabled, so a deployment that has not set up VAPID shows nothing.
//! Turning alerts on subscribes *this device*; the category toggles and quiet
//! hours are the member's server-side preferences, shared by all their devices.

use leptos::prelude::*;
use nostr_bbs_core::push::{PushPrefs, QuietHours};

use crate::auth::use_auth;
use crate::components::toast::{use_toasts, ToastVariant};
use crate::utils::push::{self, Permission};

/// Default quiet window when the member first switches quiet hours on.
const DEFAULT_QUIET: (u16, u16) = (22 * 60, 7 * 60);

/// Which controls the card offers.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Hidden,
    Push,
    LocalOnly,
}

#[component]
pub fn PushSettings() -> impl IntoView {
    let auth = use_auth();
    let toasts = use_toasts();

    // None while loading. `Push`: server push is on, full controls. `LocalOnly`:
    // the relay has push off but this browser can show system alerts while the
    // app sits in a background tab, so only the permission is offered.
    let mode: RwSignal<Option<Mode>> = RwSignal::new(None);
    let permission = RwSignal::new(push::permission());
    let active = RwSignal::new(push::active_on_device());
    let busy = RwSignal::new(false);
    let prefs: RwSignal<Option<PushPrefs>> = RwSignal::new(None);
    // The last state the server confirmed; a failed save rolls the toggles back to it.
    let confirmed: RwSignal<Option<PushPrefs>> = RwSignal::new(None);
    let needs_install = push::needs_install();

    // Is the feature switched on at the relay?
    // iOS Safari does not even expose PushManager until the app is on the Home
    // Screen, so `supported()` is false there. Still show the card (with the
    // install hint) as long as the relay has push on.
    leptos::task::spawn_local(async move {
        let server_push =
            (push::supported() || needs_install) && push::fetch_config().await.is_some();
        mode.set(Some(if server_push {
            Mode::Push
        } else if push::notifications_supported() {
            Mode::LocalOnly
        } else {
            Mode::Hidden
        }));
    });

    // Load the member's preferences once this device is subscribed.
    Effect::new(move |_| {
        if !active.get() || prefs.get_untracked().is_some() {
            return;
        }
        let Some(signer) = auth.get_signer() else {
            return;
        };
        leptos::task::spawn_local(async move {
            match push::load_prefs(signer.as_ref()).await {
                Ok(p) => {
                    confirmed.set(Some(p.clone()));
                    prefs.set(Some(p));
                }
                Err(e) => toasts.show(e, ToastVariant::Error),
            }
        });
    });

    // Saves can be in flight together (two quick toggles). Only the newest
    // request may write its echo back, otherwise a slow earlier response lands
    // last and puts the old state on screen.
    let save_seq = StoredValue::new(0u64);
    let persist = move || {
        let Some(p) = prefs.get_untracked() else {
            return;
        };
        let Some(signer) = auth.get_signer() else {
            return;
        };
        let seq = save_seq.get_value() + 1;
        save_seq.set_value(seq);
        leptos::task::spawn_local(async move {
            match push::save_prefs(signer.as_ref(), &p).await {
                Ok(saved) => {
                    confirmed.set(Some(saved.clone()));
                    if save_seq.try_get_value() == Some(seq) {
                        prefs.set(Some(saved));
                    }
                }
                Err(e) => {
                    // Put the toggles back to what the server actually holds.
                    if save_seq.try_get_value() == Some(seq) {
                        prefs.set(confirmed.get_untracked());
                    }
                    toasts.show(e, ToastVariant::Error);
                }
            }
        });
    };

    let turn_on = move |_| {
        let Some(signer) = auth.get_signer() else {
            toasts.show("Sign in first.", ToastVariant::Warning);
            return;
        };
        busy.set(true);
        // The permission prompt must be raised inside this click handler.
        let asked = push::request_permission_now();
        leptos::task::spawn_local(async move {
            match push::enable(signer, push::brand_label(), asked).await {
                Ok(()) => {
                    active.set(true);
                    toasts.show("Alerts are on for this device.", ToastVariant::Success);
                }
                Err(e) => toasts.show(e, ToastVariant::Error),
            }
            permission.set(push::permission());
            busy.set(false);
        });
    };

    let turn_off = move |_| {
        let Some(signer) = auth.get_signer() else {
            return;
        };
        busy.set(true);
        leptos::task::spawn_local(async move {
            match push::disable(signer).await {
                Ok(()) => {
                    active.set(false);
                    prefs.set(None);
                    confirmed.set(None);
                    toasts.show("Alerts are off for this device.", ToastVariant::Info);
                }
                Err(e) => toasts.show(e, ToastVariant::Error),
            }
            busy.set(false);
        });
    };

    let toggle = move |pick: fn(&mut PushPrefs) -> &mut bool| {
        move |_| {
            prefs.update(|p| {
                if let Some(p) = p {
                    let flag = pick(p);
                    *flag = !*flag;
                }
            });
            persist();
        }
    };

    let quiet_on = move || prefs.get().is_some_and(|p| p.quiet.is_some());
    let quiet_edit = move |edit: fn(&mut QuietHours, u16)| {
        move |ev: leptos::ev::Event| {
            let Some(minutes) = push::parse_hhmm(&event_target_value(&ev)) else {
                return;
            };
            prefs.update(|p| {
                if let Some(q) = p.as_mut().and_then(|p| p.quiet.as_mut()) {
                    edit(q, minutes);
                    q.tz_offset_min = push::local_tz_offset_min();
                }
            });
            persist();
        }
    };
    let toggle_quiet = move |_| {
        prefs.update(|p| {
            if let Some(p) = p {
                p.quiet = match p.quiet {
                    Some(_) => None,
                    None => Some(QuietHours {
                        start_min: DEFAULT_QUIET.0,
                        end_min: DEFAULT_QUIET.1,
                        tz_offset_min: push::local_tz_offset_min(),
                    }),
                };
            }
        });
        persist();
    };

    let allow_local = move |_| {
        let asked = push::request_permission_now();
        leptos::task::spawn_local(async move {
            if let Some(prompt) = asked {
                permission.set(push::await_permission(prompt).await);
            } else {
                permission.set(push::permission());
            }
        });
    };

    view! {
        <Show when=move || mode.get() == Some(Mode::LocalOnly)>
            <div class="glass-card p-6 space-y-4" data-testid="local-alert-settings">
                <h2 class="text-lg font-semibold text-white">"Browser alerts"</h2>
                <div class="border-t border-gray-700/50"></div>
                <p class="text-sm text-gray-400">
                    "Get a system alert for direct messages and mentions while this app is open in a \
                     background tab or window. Alerts only say what kind of thing happened."
                </p>
                <Show when=move || permission.get() == Permission::Denied>
                    <p class="text-sm text-amber-400" role="note">
                        "Notifications are blocked for this site. Allow them in your browser's site settings, then come back."
                    </p>
                </Show>
                <Show
                    when=move || permission.get() == Permission::Granted
                    fallback=move || view! {
                        <button
                            class="px-4 py-2 rounded-lg bg-amber-500 hover:bg-amber-400 text-gray-900 text-sm font-medium disabled:opacity-50"
                            disabled=move || permission.get() == Permission::Denied
                            on:click=allow_local
                        >
                            "Allow browser alerts"
                        </button>
                    }
                >
                    <p class="text-sm text-gray-300">"Browser alerts are on."</p>
                </Show>
            </div>
        </Show>
        <Show when=move || mode.get() == Some(Mode::Push)>
            <div class="glass-card p-6 space-y-4" data-testid="push-settings">
                <h2 class="text-lg font-semibold text-white">"Push notifications"</h2>
                <div class="border-t border-gray-700/50"></div>
                <p class="text-sm text-gray-400">
                    "Get an alert on this device when something needs you, even with the app closed. \
                     Alerts only say what kind of thing happened; open the app to read it."
                </p>

                <Show when=move || needs_install && !active.get()>
                    <p class="text-sm text-amber-400" role="note">
                        "On iPhone and iPad, add this app to your Home Screen first \
                         (Share, then Add to Home Screen), then open it from there to turn alerts on."
                    </p>
                </Show>
                <Show when=move || permission.get() == Permission::Denied>
                    <p class="text-sm text-amber-400" role="note">
                        "Notifications are blocked for this site. Allow them in your browser's site settings, then come back."
                    </p>
                </Show>

                <Show
                    when=move || active.get()
                    fallback=move || view! {
                      <Show when=move || push::supported()>
                        <button
                            class="px-4 py-2 rounded-lg bg-amber-500 hover:bg-amber-400 text-gray-900 text-sm font-medium disabled:opacity-50"
                            disabled=move || busy.get() || permission.get() == Permission::Denied
                            on:click=turn_on
                        >
                            {move || if busy.get() { "Turning on…" } else { "Turn on alerts for this device" }}
                        </button>
                      </Show>
                    }
                >
                    <div class="space-y-3">
                        <label class="flex items-center justify-between cursor-pointer">
                            <span class="text-sm text-gray-300">"Replies and mentions"</span>
                            <input type="checkbox"
                                class="rounded border-gray-600 bg-gray-900 text-amber-500 focus:ring-amber-500"
                                prop:checked=move || prefs.get().is_some_and(|p| p.replies)
                                on:change=toggle(|p| &mut p.replies) />
                        </label>
                        <label class="flex items-center justify-between cursor-pointer">
                            <span class="text-sm text-gray-300">"Direct messages"</span>
                            <input type="checkbox"
                                class="rounded border-gray-600 bg-gray-900 text-amber-500 focus:ring-amber-500"
                                prop:checked=move || prefs.get().is_some_and(|p| p.dms)
                                on:change=toggle(|p| &mut p.dms) />
                        </label>
                        <label class="flex items-center justify-between cursor-pointer">
                            <span class="text-sm text-gray-300">"New topics"</span>
                            <input type="checkbox"
                                class="rounded border-gray-600 bg-gray-900 text-amber-500 focus:ring-amber-500"
                                prop:checked=move || prefs.get().is_some_and(|p| p.new_topics)
                                on:change=toggle(|p| &mut p.new_topics) />
                        </label>
                        <label class="flex items-center justify-between cursor-pointer">
                            <span class="text-sm text-gray-300">"Every new message in zones I can read"</span>
                            <input type="checkbox"
                                class="rounded border-gray-600 bg-gray-900 text-amber-500 focus:ring-amber-500"
                                prop:checked=move || prefs.get().is_some_and(|p| p.new_posts)
                                on:change=toggle(|p| &mut p.new_posts) />
                        </label>

                        <label class="flex items-center justify-between cursor-pointer">
                            <span class="text-sm text-gray-300">"Quiet hours"</span>
                            <input type="checkbox"
                                class="rounded border-gray-600 bg-gray-900 text-amber-500 focus:ring-amber-500"
                                prop:checked=quiet_on
                                on:change=toggle_quiet />
                        </label>
                        <Show when=quiet_on>
                            <div class="flex items-center gap-3 text-sm text-gray-300">
                                <label class="flex items-center gap-2">
                                    "From"
                                    <input type="time"
                                        class="bg-gray-800 border border-gray-600 rounded px-2 py-1 text-white"
                                        prop:value=move || prefs.get().and_then(|p| p.quiet).map(|q| push::format_hhmm(q.start_min)).unwrap_or_default()
                                        on:change=quiet_edit(|q, m| q.start_min = m) />
                                </label>
                                <label class="flex items-center gap-2">
                                    "to"
                                    <input type="time"
                                        class="bg-gray-800 border border-gray-600 rounded px-2 py-1 text-white"
                                        prop:value=move || prefs.get().and_then(|p| p.quiet).map(|q| push::format_hhmm(q.end_min)).unwrap_or_default()
                                        on:change=quiet_edit(|q, m| q.end_min = m) />
                                </label>
                            </div>
                        </Show>
                    </div>

                    <button
                        class="px-4 py-2 rounded-lg border border-gray-600 text-gray-200 hover:bg-gray-800 text-sm disabled:opacity-50"
                        disabled=move || busy.get()
                        on:click=turn_off
                    >
                        "Turn off alerts for this device"
                    </button>
                </Show>
            </div>
        </Show>
    }
}
