//! Pod Browser — navigate and manage the user's Solid data pod.
//!
//! Provides an LDP-aware file browser with NIP-98 authenticated requests.
//! Displays containers as navigable folders and resources as viewable items,
//! with quick-access links to well-known pod endpoints (profile, inbox,
//! type indexes, media).

use leptos::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;

use crate::auth::use_auth;

const POD_API: &str = match option_env!("VITE_POD_API_URL") {
    Some(u) => u,
    None => "https://pod.example.com",
};

// ── Data types ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct PodEntry {
    id: String,
    name: String,
    is_container: bool,
    modified: String,
}

#[derive(Clone, Debug)]
enum FetchState {
    Idle,
    Loading,
    Loaded(Vec<PodEntry>),
    Error(String),
}

// ── Authenticated fetch ─────────────────────────────────────────────────────

async fn pod_fetch(
    url: &str,
    signer: &dyn nostr_bbs_core::signer::Signer,
) -> Result<String, String> {
    let token = crate::auth::nip98::create_nip98_token_with_signer(signer, url, "GET", None)
        .await
        .map_err(|e| format!("NIP-98: {e}"))?;

    let win = web_sys::window().ok_or("No window")?;
    let init = web_sys::RequestInit::new();
    init.set_method("GET");

    let headers = web_sys::Headers::new().map_err(|e| format!("{e:?}"))?;
    headers
        .set("Authorization", &format!("Nostr {token}"))
        .map_err(|e| format!("{e:?}"))?;
    headers
        .set(
            "Accept",
            "application/ld+json, application/json, text/turtle, */*",
        )
        .map_err(|e| format!("{e:?}"))?;
    init.set_headers(&headers);

    let req = web_sys::Request::new_with_str_and_init(url, &init).map_err(|e| format!("{e:?}"))?;
    let resp_val = JsFuture::from(win.fetch_with_request(&req))
        .await
        .map_err(|e| format!("Fetch: {e:?}"))?;
    let resp: web_sys::Response = resp_val
        .dyn_into()
        .map_err(|_| "Not a Response".to_string())?;

    if !resp.ok() {
        return Err(format!("HTTP {}", resp.status()));
    }

    let text_promise = resp.text().map_err(|e| format!("{e:?}"))?;
    let text_val = JsFuture::from(text_promise)
        .await
        .map_err(|e| format!("{e:?}"))?;
    text_val.as_string().ok_or_else(|| "Empty response".into())
}

async fn pod_provision(
    base_url: &str,
    signer: &dyn nostr_bbs_core::signer::Signer,
) -> Result<(), String> {
    let url = format!("{base_url}/.provision");
    let token = crate::auth::nip98::create_nip98_token_with_signer(signer, &url, "POST", None)
        .await
        .map_err(|e| format!("NIP-98: {e}"))?;

    let win = web_sys::window().ok_or("No window")?;
    let init = web_sys::RequestInit::new();
    init.set_method("POST");

    let headers = web_sys::Headers::new().map_err(|e| format!("{e:?}"))?;
    headers
        .set("Authorization", &format!("Nostr {token}"))
        .map_err(|e| format!("{e:?}"))?;
    headers
        .set("Content-Type", "application/json")
        .map_err(|e| format!("{e:?}"))?;
    init.set_headers(&headers);

    let req = web_sys::Request::new_with_str_and_init(&url, &init).map_err(|e| format!("{e:?}"))?;
    let resp_val = JsFuture::from(win.fetch_with_request(&req))
        .await
        .map_err(|e| format!("Fetch: {e:?}"))?;
    let resp: web_sys::Response = resp_val
        .dyn_into()
        .map_err(|_| "Not a Response".to_string())?;

    let status = resp.status();
    if status == 201 || status == 409 {
        Ok(())
    } else {
        Err(format!("Provision failed: HTTP {status}"))
    }
}

fn parse_container_listing(json_str: &str) -> Vec<PodEntry> {
    let val: serde_json::Value = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let members = match val.get("ldp:contains") {
        Some(serde_json::Value::Array(arr)) => arr.clone(),
        Some(single) => vec![single.clone()],
        None => return Vec::new(),
    };

    members
        .iter()
        .filter_map(|m| {
            let id = m.get("@id")?.as_str()?.to_string();
            let is_container = id.ends_with('/');
            let name = id
                .trim_end_matches('/')
                .rsplit('/')
                .next()
                .unwrap_or(&id)
                .to_string();
            let name = if is_container {
                format!("{name}/")
            } else {
                name
            };
            let modified = m
                .get("dcterms:modified")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            Some(PodEntry {
                id,
                name,
                is_container,
                modified,
            })
        })
        .collect()
}

// ── Quick-access cards ──────────────────────────────────────────────────────

struct QuickLink {
    label: &'static str,
    path: &'static str,
    icon: &'static str,
    description: &'static str,
}

const QUICK_LINKS: &[QuickLink] = &[
    QuickLink {
        label: "Profile",
        path: "/profile/card",
        icon: "M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z",
        description: "WebID document",
    },
    QuickLink {
        label: "Inbox",
        path: "/inbox/",
        icon: "M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z",
        description: "Linked Data Notifications",
    },
    QuickLink {
        label: "Public Index",
        path: "/settings/publicTypeIndex",
        icon: "M4 6h16M4 10h16M4 14h16M4 18h16",
        description: "Public type registrations",
    },
    QuickLink {
        label: "Media",
        path: "/media/public/",
        icon: "M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z",
        description: "Uploaded files",
    },
];

// ── Resource viewer ─────────────────────────────────────────────────────────

#[component]
fn ResourceViewer(content: String, path: String) -> impl IntoView {
    let is_json = content.trim_start().starts_with('{') || content.trim_start().starts_with('[');
    let display = if is_json {
        serde_json::from_str::<serde_json::Value>(&content)
            .ok()
            .and_then(|v| serde_json::to_string_pretty(&v).ok())
            .unwrap_or(content)
    } else {
        content
    };

    view! {
        <div class="bg-gray-900 rounded-lg border border-gray-700/50 overflow-hidden">
            <div class="flex items-center justify-between px-4 py-2 bg-gray-800 border-b border-gray-700/50">
                <span class="text-sm text-gray-400 font-mono truncate">{path}</span>
                <span class="text-xs px-2 py-0.5 rounded bg-gray-700 text-gray-300">
                    {if is_json { "JSON-LD" } else { "Text" }}
                </span>
            </div>
            <pre class="p-4 text-sm text-gray-300 overflow-x-auto whitespace-pre-wrap font-mono max-h-96 overflow-y-auto">
                {display}
            </pre>
        </div>
    }
}

// ── Main page component ─────────────────────────────────────────────────────

/// Result of probing the pod for a `.git/HEAD` file. The CF Workers tier
/// returns 404 (no git-init); native/agentbox tiers serve the HEAD ref.
#[derive(Clone, Debug, PartialEq, Eq)]
enum GitProbeState {
    Idle,
    Probing,
    Available { branch: String },
    Unavailable, // 404 / no HEAD
    Error(String),
}

#[component]
pub fn PodBrowserPage() -> impl IntoView {
    let auth = use_auth();
    let pubkey = auth.pubkey();

    let current_path = RwSignal::new("/".to_string());
    let fetch_state = RwSignal::new(FetchState::Idle);
    let resource_content = RwSignal::new(None::<(String, String)>);
    let viewing_resource = RwSignal::new(false);
    let git_probe = RwSignal::new(GitProbeState::Idle);
    let toasts = crate::components::toast::use_toasts();

    let pod_base_url = Memo::new(move |_| {
        pubkey
            .get()
            .map(|pk| format!("{}/pods/{}", POD_API.trim_end_matches('/'), pk))
    });

    // Per-user pod git clone command (ADR-089). Mirrors `pages::settings`
    // surface — both derive from the same `POD_API` env that flows from
    // `[pod].base_url` in nostr-bbs-config. Resolves only when git-init at
    // pod provisioning is enabled on the operator's deployment.
    let pod_clone_command = Memo::new(move |_| {
        pod_base_url
            .get()
            .map(|base| format!("git clone {}/", base.trim_end_matches('/')))
            .unwrap_or_default()
    });

    // Copy the clone command to clipboard.
    let toasts_for_copy = toasts.clone();
    let on_copy_clone = move |_| {
        let cmd = pod_clone_command.get_untracked();
        if cmd.is_empty() {
            toasts_for_copy.show("No clone URL available", crate::components::toast::ToastVariant::Warning);
            return;
        }
        if let Some(window) = web_sys::window() {
            let nav = window.navigator().clipboard();
            let _ = nav.write_text(&cmd);
        }
        toasts_for_copy.show("Clone command copied", crate::components::toast::ToastVariant::Success);
    };

    // Probe `<pod_base>/HEAD` (NOT `.git/HEAD`; smart-HTTP-style serves the
    // refs at the root in solid-pod-rs-git's design). 200 means git-init
    // ran at provisioning; 404 means this operator's tier doesn't support
    // it. Idempotent; safe to call repeatedly.
    let on_probe_git = move |_| {
        let Some(base) = pod_base_url.get() else { return; };
        let Some(signer) = auth.get_signer() else { return; };
        git_probe.set(GitProbeState::Probing);
        let url = format!("{}/HEAD", base.trim_end_matches('/'));
        wasm_bindgen_futures::spawn_local(async move {
            match pod_fetch(&url, &*signer).await {
                Ok(body) => {
                    // Format: `ref: refs/heads/<branch>\n`
                    let branch = body
                        .trim()
                        .strip_prefix("ref: refs/heads/")
                        .unwrap_or(body.trim())
                        .to_string();
                    if branch.is_empty() {
                        git_probe.set(GitProbeState::Unavailable);
                    } else {
                        git_probe.set(GitProbeState::Available { branch });
                    }
                }
                Err(e) if e.contains("404") => git_probe.set(GitProbeState::Unavailable),
                Err(e) => git_probe.set(GitProbeState::Error(e)),
            }
        });
    };

    let navigate_to = move |path: String| {
        resource_content.set(None);
        viewing_resource.set(false);
        current_path.set(path);
    };

    // Fetch container listing whenever current_path changes
    Effect::new(move |_| {
        let path = current_path.get();
        let signer = auth.get_signer();

        if let (Some(base), Some(signer)) = (pod_base_url.get(), signer) {
            fetch_state.set(FetchState::Loading);
            let url = format!("{}{}", base, path);
            let is_container = path.ends_with('/') || path == "/";

            wasm_bindgen_futures::spawn_local(async move {
                let result = match pod_fetch(&url, &*signer).await {
                    Ok(body) => Ok(body),
                    Err(ref e) if path == "/" && (e.contains("403") || e.contains("404")) => {
                        // Pod likely not provisioned — try auto-provisioning
                        if pod_provision(&base, &*signer).await.is_ok() {
                            pod_fetch(&url, &*signer).await
                        } else {
                            Err(e.clone())
                        }
                    }
                    Err(e) => Err(e),
                };

                match result {
                    Ok(body) => {
                        if is_container {
                            let entries = parse_container_listing(&body);
                            fetch_state.set(FetchState::Loaded(entries));
                        } else {
                            resource_content.set(Some((body, path)));
                            viewing_resource.set(true);
                            fetch_state.set(FetchState::Idle);
                        }
                    }
                    Err(e) => fetch_state.set(FetchState::Error(e)),
                }
            });
        }
    });

    let breadcrumbs = Memo::new(move |_| {
        let path = current_path.get();
        let mut crumbs: Vec<(String, String)> = vec![("Pod".into(), "/".into())];
        let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        let mut accumulated = String::new();
        for part in parts {
            accumulated.push('/');
            accumulated.push_str(part);
            accumulated.push('/');
            crumbs.push((part.to_string(), accumulated.clone()));
        }
        crumbs
    });

    let on_quick_link = move |path: &'static str| {
        let path = path.to_string();
        move |_: web_sys::MouseEvent| {
            navigate_to(path.clone());
        }
    };

    view! {
        <div class="pod-browser max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
            // Header
            <div class="mb-6">
                <h1 class="text-2xl font-bold text-white mb-1">"Pod Browser"</h1>
                <p class="text-gray-400 text-sm">
                    {move || pod_base_url.get().unwrap_or_else(|| "Connecting...".into())}
                </p>
            </div>

            // Git pod card (ADR-089). Per-user pods become clone-able git
            // repositories on deployments that ran `git init` at provisioning.
            // The CF Workers tier can't subprocess, so the URL still renders
            // but resolves only when the operator's backend supports it.
            <section
                data-section="git-pod"
                aria-labelledby="git-pod-heading"
                class="mb-6 bg-gradient-to-br from-amber-500/10 to-orange-500/5 border border-amber-400/20 rounded-lg p-4"
            >
                <div class="flex items-center gap-2 mb-2">
                    <svg class="w-5 h-5 text-amber-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <circle cx="12" cy="12" r="3"/>
                        <path d="M12 1v6m0 6v6m11-7h-6m-6 0H1"/>
                    </svg>
                    <h2 id="git-pod-heading" class="text-base font-semibold text-white">"Your pod is a git repository"</h2>
                </div>
                <p class="text-sm text-gray-300 mb-3">
                    "Clone, push, and pull your pod with standard git. Branch defaults to "
                    <code class="text-xs bg-gray-800 px-1.5 py-0.5 rounded text-amber-300">"main"</code>
                    " with "
                    <code class="text-xs bg-gray-800 px-1.5 py-0.5 rounded text-amber-300">"receive.denyCurrentBranch=updateInstead"</code>
                    " — clone, edit, push, and the working tree updates server-side."
                </p>
                <div class="bg-gray-900/80 border border-gray-700/50 rounded px-3 py-2 mb-3">
                    <code data-testid="pod-clone-command" class="text-xs text-amber-300 font-mono break-all">
                        {move || pod_clone_command.get()}
                    </code>
                </div>
                <div class="flex flex-wrap items-center gap-2">
                    <button
                        data-testid="pod-clone-copy"
                        on:click=on_copy_clone
                        class="text-sm bg-amber-500 hover:bg-amber-400 text-gray-900 font-semibold px-3 py-1.5 rounded-md transition-colors"
                    >
                        "Copy clone command"
                    </button>
                    <button
                        data-testid="pod-git-probe"
                        on:click=on_probe_git
                        class="text-sm bg-gray-700 hover:bg-gray-600 text-gray-100 font-medium px-3 py-1.5 rounded-md transition-colors disabled:opacity-50"
                        disabled=move || matches!(git_probe.get(), GitProbeState::Probing)
                    >
                        {move || match git_probe.get() {
                            GitProbeState::Probing => "Checking…",
                            GitProbeState::Available { .. } => "Re-check status",
                            _ => "Check status",
                        }}
                    </button>
                    <span data-testid="pod-git-status" class="text-xs">
                        {move || match git_probe.get() {
                            GitProbeState::Idle => view! { <span class="text-gray-500">""</span> }.into_any(),
                            GitProbeState::Probing => view! { <span class="text-gray-400">"probing…"</span> }.into_any(),
                            GitProbeState::Available { branch } => view! {
                                <span class="text-green-400">
                                    {format!("✓ git-init OK on branch {branch}")}
                                </span>
                            }.into_any(),
                            GitProbeState::Unavailable => view! {
                                <span class="text-amber-400" title="Operator has not enabled git-init at provisioning (e.g. CF Workers tier — see ADR-089)">
                                    "✕ git-init not enabled on this deployment"
                                </span>
                            }.into_any(),
                            GitProbeState::Error(e) => view! {
                                <span class="text-red-400">{format!("error: {e}")}</span>
                            }.into_any(),
                        }}
                    </span>
                </div>
                <p class="text-xs text-gray-500 mt-3">
                    "Powered by "
                    <code class="text-amber-300">"solid-pod-rs ≥ 0.4.0-alpha.12"</code>
                    " · ADR-089 covers the CF Workers limitation."
                </p>
            </section>

            // Quick-access cards
            <div class="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6">
                {QUICK_LINKS.iter().map(|link| {
                    let path_svg = link.icon;
                    let label = link.label;
                    let desc = link.description;
                    let handler = on_quick_link(link.path);
                    view! {
                        <button
                            class="bg-gray-800 hover:bg-gray-750 border border-gray-700/50 hover:border-amber-400/30 rounded-lg p-3 text-left transition-colors group"
                            on:click=handler
                        >
                            <div class="flex items-center gap-2 mb-1">
                                <svg class="w-4 h-4 text-amber-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                    <path d=path_svg />
                                </svg>
                                <span class="text-sm font-medium text-white">{label}</span>
                            </div>
                            <span class="text-xs text-gray-500">{desc}</span>
                        </button>
                    }
                }).collect_view()}
            </div>

            // Breadcrumb navigation
            <nav class="flex items-center gap-1 text-sm mb-4 overflow-x-auto pb-1" aria-label="Pod path">
                {move || {
                    let crumbs = breadcrumbs.get();
                    crumbs.into_iter().enumerate().map(|(i, (label, path))| {
                        let is_last = i == breadcrumbs.get().len() - 1;
                        let nav = navigate_to;
                        view! {
                            {if i > 0 {
                                Some(view! { <span class="text-gray-600">"/"</span> })
                            } else {
                                None
                            }}
                            {if is_last {
                                view! {
                                    <span class="text-amber-400 font-medium">{label}</span>
                                }.into_any()
                            } else {
                                let p = path.clone();
                                view! {
                                    <button
                                        class="text-gray-400 hover:text-white transition-colors"
                                        on:click=move |_| nav(p.clone())
                                    >
                                        {label}
                                    </button>
                                }.into_any()
                            }}
                        }
                    }).collect_view()
                }}
            </nav>

            // Resource viewer (when viewing a non-container resource)
            {move || {
                resource_content.get().map(|(content, path)| {
                    let nav = navigate_to;
                    let parent = {
                        let mut p = path.rsplit_once('/').map(|(a, _)| format!("{a}/")).unwrap_or_else(|| "/".into());
                        if p.is_empty() { p = "/".into(); }
                        p
                    };
                    view! {
                        <div class="mb-4">
                            <button
                                class="text-sm text-gray-400 hover:text-amber-400 transition-colors flex items-center gap-1 mb-3"
                                on:click=move |_| nav(parent.clone())
                            >
                                <svg class="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <path d="M19 12H5M12 19l-7-7 7-7" stroke-linecap="round" stroke-linejoin="round"/>
                                </svg>
                                "Back to folder"
                            </button>
                            <ResourceViewer content=content path=path />
                        </div>
                    }
                })
            }}

            // Container listing
            <Show when=move || !viewing_resource.get()>
                {move || match fetch_state.get() {
                    FetchState::Loading => view! {
                        <div class="flex items-center justify-center py-12">
                            <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-amber-400"></div>
                        </div>
                    }.into_any(),

                    FetchState::Error(e) => view! {
                        <div class="bg-red-900/20 border border-red-500/30 rounded-lg p-4 text-center">
                            <p class="text-red-400 text-sm">{format!("Failed to load: {e}")}</p>
                            <p class="text-gray-500 text-xs mt-1">"The pod may not be provisioned yet, or the resource may not exist."</p>
                        </div>
                    }.into_any(),

                    FetchState::Loaded(entries) if entries.is_empty() => view! {
                        <div class="bg-gray-800/50 rounded-lg p-8 text-center">
                            <svg class="w-12 h-12 mx-auto text-gray-600 mb-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                                <path d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" stroke-linecap="round" stroke-linejoin="round"/>
                            </svg>
                            <p class="text-gray-500">"This container is empty."</p>
                        </div>
                    }.into_any(),

                    FetchState::Loaded(entries) => {
                        let nav = navigate_to;
                        view! {
                            <div class="bg-gray-800 rounded-lg border border-gray-700/50 divide-y divide-gray-700/30 overflow-hidden">
                                {entries.into_iter().map(|entry| {
                                    let id = entry.id.clone();
                                    let name = entry.name.clone();
                                    let is_container = entry.is_container;
                                    let modified = entry.modified.clone();
                                    view! {
                                        <button
                                            class="w-full flex items-center gap-3 px-4 py-3 hover:bg-gray-750 transition-colors text-left group"
                                            on:click=move |_| nav(id.clone())
                                        >
                                            {if is_container {
                                                view! {
                                                    <svg class="w-5 h-5 text-amber-400 flex-shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                                        <path d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" stroke-linecap="round" stroke-linejoin="round"/>
                                                    </svg>
                                                }.into_any()
                                            } else {
                                                view! {
                                                    <svg class="w-5 h-5 text-gray-500 flex-shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                                        <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" stroke-linecap="round" stroke-linejoin="round"/>
                                                        <polyline points="14 2 14 8 20 8" stroke-linecap="round" stroke-linejoin="round"/>
                                                    </svg>
                                                }.into_any()
                                            }}
                                            <div class="flex-1 min-w-0">
                                                <span class="text-sm text-white group-hover:text-amber-400 transition-colors block truncate">
                                                    {name}
                                                </span>
                                                {if !modified.is_empty() {
                                                    Some(view! {
                                                        <span class="text-xs text-gray-600 block truncate">{modified}</span>
                                                    })
                                                } else {
                                                    None
                                                }}
                                            </div>
                                            <svg class="w-4 h-4 text-gray-600 group-hover:text-gray-400 flex-shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                                <path d="M9 18l6-6-6-6" stroke-linecap="round" stroke-linejoin="round"/>
                                            </svg>
                                        </button>
                                    }
                                }).collect_view()}
                            </div>
                        }.into_any()
                    },

                    FetchState::Idle => view! { <div></div> }.into_any(),
                }}
            </Show>
        </div>
    }
}
