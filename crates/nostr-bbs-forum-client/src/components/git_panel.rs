//! VS Code-style Git Source Control panel for a Solid pod with git enabled.
//!
//! Talks to the `/_git/` REST API served by `solid-pod-rs-server --features git`.
//! All requests are NIP-98 authenticated.  The component is mounted by
//! `pod_browser.rs` when the git probe comes back `Available`.

use leptos::prelude::*;
use serde::{Deserialize, Serialize};
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::{spawn_local, JsFuture};

use crate::auth::use_auth;
use crate::components::toast::{use_toasts, ToastVariant};

// ── API response types ───────────────────────────────────────────────────────

#[derive(Clone, Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct GitStatus {
    pub branch: String,
    pub ahead: u32,
    pub behind: u32,
    pub staged: Vec<GitFileStatus>,
    pub unstaged: Vec<GitFileStatus>,
    pub untracked: Vec<String>,
    pub is_clean: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GitFileStatus {
    pub path: String,
    pub change_type: String, // "modified", "added", "deleted", "renamed", "copied"
    pub old_path: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GitCommit {
    pub hash: String,
    pub short_hash: String,
    pub message: String,
    pub author: String,
    pub date: String,
    pub date_relative: String,
}

// ── Request body types ───────────────────────────────────────────────────────

#[derive(Serialize)]
struct StagePaths<'a> {
    paths: &'a [String],
}

#[derive(Serialize)]
struct StageAll {
    all: bool,
}

#[derive(Serialize)]
struct CommitBody<'a> {
    message: &'a str,
}

// ── NIP-98 authenticated fetch helper ───────────────────────────────────────

async fn git_fetch_raw(
    url: &str,
    method: &'static str,
    body: Option<String>,
    signer: &dyn nostr_bbs_core::signer::Signer,
) -> Result<(u16, String), String> {
    let body_bytes: Option<Vec<u8>> = body.as_ref().map(|s| s.as_bytes().to_vec());
    let token = crate::auth::nip98::create_nip98_token_with_signer(
        signer,
        url,
        method,
        body_bytes.as_deref(),
    )
    .await
    .map_err(|e| format!("NIP-98: {e}"))?;

    let win = web_sys::window().ok_or("No window")?;
    let init = web_sys::RequestInit::new();
    init.set_method(method);

    let headers = web_sys::Headers::new().map_err(|e| format!("{e:?}"))?;
    headers
        .set("Authorization", &format!("Nostr {token}"))
        .map_err(|e| format!("{e:?}"))?;
    headers
        .set("Accept", "application/json")
        .map_err(|e| format!("{e:?}"))?;

    if let Some(ref b) = body {
        headers
            .set("Content-Type", "application/json")
            .map_err(|e| format!("{e:?}"))?;
        init.set_body(&wasm_bindgen::JsValue::from_str(b));
    }
    init.set_headers(&headers);

    let req =
        web_sys::Request::new_with_str_and_init(url, &init).map_err(|e| format!("{e:?}"))?;
    let resp_val = JsFuture::from(win.fetch_with_request(&req))
        .await
        .map_err(|e| format!("Fetch: {e:?}"))?;
    let resp: web_sys::Response = resp_val
        .dyn_into()
        .map_err(|_| "Not a Response".to_string())?;

    let status = resp.status();
    let text_promise = resp.text().map_err(|e| format!("{e:?}"))?;
    let text_val = JsFuture::from(text_promise)
        .await
        .map_err(|e| format!("{e:?}"))?;
    let body_str = text_val.as_string().unwrap_or_default();
    Ok((status, body_str))
}

// ── Change type badge ────────────────────────────────────────────────────────

fn change_badge(change_type: &str) -> (&'static str, &'static str) {
    match change_type {
        "added" => ("A", "text-green-400 bg-green-900/40"),
        "deleted" => ("D", "text-red-400 bg-red-900/40"),
        "renamed" => ("R", "text-blue-400 bg-blue-900/40"),
        "copied" => ("C", "text-purple-400 bg-purple-900/40"),
        _ => ("M", "text-amber-400 bg-amber-900/40"), // modified + unknown
    }
}

// ── Diff renderer ────────────────────────────────────────────────────────────

#[component]
fn DiffViewer(path: String, diff: String) -> impl IntoView {
    let lines: Vec<_> = diff
        .lines()
        .map(|line| {
            let (class, text) = if line.starts_with("+++") || line.starts_with("---") {
                ("text-gray-500", line.to_string())
            } else if line.starts_with('+') {
                ("text-green-400 bg-green-950/30", line.to_string())
            } else if line.starts_with('-') {
                ("text-red-400 bg-red-950/30", line.to_string())
            } else if line.starts_with("@@") {
                ("text-blue-400 bg-blue-950/20", line.to_string())
            } else {
                ("text-gray-400", line.to_string())
            };
            (class, text)
        })
        .collect();

    view! {
        <div class="mt-2 rounded border border-gray-700/50 overflow-hidden">
            <div class="flex items-center gap-2 px-3 py-1.5 bg-gray-800/80 border-b border-gray-700/50">
                <svg class="w-3.5 h-3.5 text-gray-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" stroke-linecap="round" stroke-linejoin="round"/>
                    <polyline points="14 2 14 8 20 8" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
                <span class="text-xs text-gray-400 font-mono truncate">{path}</span>
            </div>
            <pre class="text-xs font-mono overflow-x-auto overflow-y-auto max-h-80 p-0 leading-5 bg-gray-900">
                {lines.into_iter().map(|(cls, text)| {
                    view! {
                        <span class=format!("block px-3 whitespace-pre {cls}")>{text}</span>
                    }
                }).collect_view()}
            </pre>
        </div>
    }
}

// ── Git Source Control panel ─────────────────────────────────────────────────

#[component]
pub fn GitPanel(pod_base_url: Memo<Option<String>>, branch: Signal<String>) -> impl IntoView {
    // `branch` is surfaced in the status API response; accepting the prop keeps
    // the interface stable for callers that pass the initial branch hint.
    let _ = branch;
    let auth = use_auth();
    let toasts = use_toasts();

    let status = RwSignal::new(None::<GitStatus>);
    let status_loading = RwSignal::new(true);
    let diff_view = RwSignal::new(None::<(String, String)>); // (path, diff_text)
    let commit_msg = RwSignal::new(String::new());
    let log = RwSignal::new(Vec::<GitCommit>::new());
    let log_expanded = RwSignal::new(false);
    let busy = RwSignal::new(false);
    let git_unavailable = RwSignal::new(false);

    // ── fetch helpers (closures capturing signals) ───────────────────────────

    let load_status = {
        let auth = auth.clone();
        move || {
            let Some(base) = pod_base_url.get() else {
                return;
            };
            let Some(signer) = auth.get_signer() else {
                return;
            };
            let url = format!("{}/_git/status", base.trim_end_matches('/'));
            status_loading.set(true);
            spawn_local(async move {
                match git_fetch_raw(&url, "GET", None, &*signer).await {
                    Ok((501, _)) | Ok((404, _)) => {
                        git_unavailable.set(true);
                        status_loading.set(false);
                    }
                    Ok((200, body)) => {
                        match serde_json::from_str::<GitStatus>(&body) {
                            Ok(s) => {
                                status.set(Some(s));
                                git_unavailable.set(false);
                            }
                            Err(e) => {
                                status.set(None);
                                leptos::logging::warn!("git status parse error: {e}");
                            }
                        }
                        status_loading.set(false);
                    }
                    Ok((code, body)) => {
                        leptos::logging::warn!("git status HTTP {code}: {body}");
                        status_loading.set(false);
                    }
                    Err(e) => {
                        leptos::logging::warn!("git status fetch error: {e}");
                        status_loading.set(false);
                    }
                }
            });
        }
    };

    // Auto-load once pod URL is known.
    {
        let load_status = load_status.clone();
        Effect::new(move |ran: Option<bool>| {
            if ran == Some(true) {
                return true;
            }
            if pod_base_url.get().is_some() && auth.get_signer().is_some() {
                load_status();
                true
            } else {
                false
            }
        });
    }

    // ── stage / unstage actions ──────────────────────────────────────────────

    let stage_file = {
        let auth = auth.clone();
        let load_status = load_status.clone();
        move |path: String| {
            let Some(base) = pod_base_url.get() else {
                return;
            };
            let Some(signer) = auth.get_signer() else {
                return;
            };
            let url = format!("{}/_git/stage", base.trim_end_matches('/'));
            let body = serde_json::to_string(&StagePaths { paths: &[path] }).unwrap();
            busy.set(true);
            let load_status = load_status.clone();
            spawn_local(async move {
                let _ = git_fetch_raw(&url, "POST", Some(body), &*signer).await;
                busy.set(false);
                load_status();
            });
        }
    };

    let stage_all = {
        let auth = auth.clone();
        let load_status = load_status.clone();
        move || {
            let Some(base) = pod_base_url.get() else {
                return;
            };
            let Some(signer) = auth.get_signer() else {
                return;
            };
            let url = format!("{}/_git/stage", base.trim_end_matches('/'));
            let body = serde_json::to_string(&StageAll { all: true }).unwrap();
            busy.set(true);
            let load_status = load_status.clone();
            spawn_local(async move {
                let _ = git_fetch_raw(&url, "POST", Some(body), &*signer).await;
                busy.set(false);
                load_status();
            });
        }
    };

    let unstage_file = {
        let auth = auth.clone();
        let load_status = load_status.clone();
        move |path: String| {
            let Some(base) = pod_base_url.get() else {
                return;
            };
            let Some(signer) = auth.get_signer() else {
                return;
            };
            let url = format!("{}/_git/unstage", base.trim_end_matches('/'));
            let body = serde_json::to_string(&StagePaths { paths: &[path] }).unwrap();
            busy.set(true);
            let load_status = load_status.clone();
            spawn_local(async move {
                let _ = git_fetch_raw(&url, "POST", Some(body), &*signer).await;
                busy.set(false);
                load_status();
            });
        }
    };

    let unstage_all = {
        let auth = auth.clone();
        let load_status = load_status.clone();
        move || {
            let Some(base) = pod_base_url.get() else {
                return;
            };
            let Some(signer) = auth.get_signer() else {
                return;
            };
            let url = format!("{}/_git/unstage", base.trim_end_matches('/'));
            let body = serde_json::to_string(&StageAll { all: true }).unwrap();
            busy.set(true);
            let load_status = load_status.clone();
            spawn_local(async move {
                let _ = git_fetch_raw(&url, "POST", Some(body), &*signer).await;
                busy.set(false);
                load_status();
            });
        }
    };

    let discard_file = {
        let auth = auth.clone();
        let load_status = load_status.clone();
        move |path: String| {
            let confirmed = web_sys::window()
                .and_then(|w| {
                    w.confirm_with_message(&format!(
                        "Discard changes to '{path}'? This cannot be undone."
                    ))
                    .ok()
                })
                .unwrap_or(false);
            if !confirmed {
                return;
            }
            let Some(base) = pod_base_url.get() else {
                return;
            };
            let Some(signer) = auth.get_signer() else {
                return;
            };
            let url = format!("{}/_git/discard", base.trim_end_matches('/'));
            let body = serde_json::to_string(&StagePaths { paths: &[path] }).unwrap();
            busy.set(true);
            let load_status = load_status.clone();
            spawn_local(async move {
                let _ = git_fetch_raw(&url, "POST", Some(body), &*signer).await;
                busy.set(false);
                load_status();
            });
        }
    };

    // ── commit action ────────────────────────────────────────────────────────

    let do_commit = {
        let auth = auth.clone();
        let load_status = load_status.clone();
        move || {
            let msg = commit_msg.get_untracked();
            if msg.trim().is_empty() {
                toasts.show("Commit message cannot be empty", ToastVariant::Warning);
                return;
            }
            let Some(base) = pod_base_url.get() else {
                return;
            };
            let Some(signer) = auth.get_signer() else {
                return;
            };
            let url = format!("{}/_git/commit", base.trim_end_matches('/'));
            let body = serde_json::to_string(&CommitBody { message: &msg }).unwrap();
            busy.set(true);
            let load_status = load_status.clone();
            spawn_local(async move {
                match git_fetch_raw(&url, "POST", Some(body), &*signer).await {
                    Ok((200, _)) | Ok((201, _)) => {
                        commit_msg.set(String::new());
                        toasts.show("Committed successfully", ToastVariant::Success);
                        load_status();
                    }
                    Ok((code, body)) => {
                        toasts.show(
                            &format!("Commit failed: HTTP {code} — {body}"),
                            ToastVariant::Error,
                        );
                    }
                    Err(e) => {
                        toasts.show(&format!("Commit error: {e}"), ToastVariant::Error);
                    }
                }
                busy.set(false);
            });
        }
    };

    // ── diff view ────────────────────────────────────────────────────────────

    let view_diff = {
        let auth = auth.clone();
        move |path: String, staged: bool| {
            let Some(base) = pod_base_url.get() else {
                return;
            };
            let Some(signer) = auth.get_signer() else {
                return;
            };
            // Toggle off if same path already shown
            if diff_view
                .get_untracked()
                .as_ref()
                .map(|(p, _)| p == &path)
                .unwrap_or(false)
            {
                diff_view.set(None);
                return;
            }
            let staged_param = if staged { "true" } else { "false" };
            // Percent-encode the path using the browser's built-in encodeURIComponent.
            let encoded_path = js_sys::encode_uri_component(&path);
            let url = format!(
                "{}/_git/diff?path={}&staged={}",
                base.trim_end_matches('/'),
                encoded_path,
                staged_param
            );
            let path_for_signal = path.clone();
            spawn_local(async move {
                match git_fetch_raw(&url, "GET", None, &*signer).await {
                    Ok((200, body)) => {
                        diff_view.set(Some((path_for_signal, body)));
                    }
                    Ok((code, _)) => {
                        leptos::logging::warn!("diff HTTP {code}");
                    }
                    Err(e) => {
                        leptos::logging::warn!("diff fetch: {e}");
                    }
                }
            });
        }
    };

    // ── log loading ──────────────────────────────────────────────────────────

    let load_log = {
        let auth = auth.clone();
        move || {
            let Some(base) = pod_base_url.get() else {
                return;
            };
            let Some(signer) = auth.get_signer() else {
                return;
            };
            let url = format!("{}/_git/log?limit=20", base.trim_end_matches('/'));
            spawn_local(async move {
                match git_fetch_raw(&url, "GET", None, &*signer).await {
                    Ok((200, body)) => {
                        if let Ok(commits) = serde_json::from_str::<Vec<GitCommit>>(&body) {
                            log.set(commits);
                        }
                    }
                    Ok((code, _)) => leptos::logging::warn!("git log HTTP {code}"),
                    Err(e) => leptos::logging::warn!("git log error: {e}"),
                }
            });
        }
    };

    // ── view ─────────────────────────────────────────────────────────────────

    view! {
        <section
            data-section="git-source-control"
            class="mb-4 bg-gray-900 border border-gray-700/50 rounded-lg overflow-hidden"
        >
            // Panel header
            <div class="flex items-center justify-between px-4 py-2.5 bg-gray-800/80 border-b border-gray-700/50">
                <div class="flex items-center gap-2">
                    <svg class="w-4 h-4 text-amber-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <circle cx="12" cy="12" r="3"/>
                        <path d="M12 1v6m0 6v6m11-7h-6m-6 0H1"/>
                    </svg>
                    <span class="text-sm font-semibold text-white">"Source Control"</span>
                    {move || status.get().map(|s| view! {
                        <span class="text-xs text-gray-500">
                            {format!("· {} ↑{} ↓{}", s.branch, s.ahead, s.behind)}
                        </span>
                    })}
                </div>
                <button
                    class="p-1 rounded hover:bg-gray-700 text-gray-400 hover:text-white transition-colors disabled:opacity-40"
                    title="Refresh"
                    disabled=move || busy.get() || status_loading.get()
                    on:click={
                        let load_status = load_status.clone();
                        move |_| load_status()
                    }
                >
                    <svg
                        class=move || if status_loading.get() { "w-4 h-4 animate-spin" } else { "w-4 h-4" }
                        viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"
                    >
                        <polyline points="23 4 23 10 17 10"/>
                        <path d="M20.49 15a9 9 0 11-2.12-9.36L23 10"/>
                    </svg>
                </button>
            </div>

            // Unavailable message
            {move || if git_unavailable.get() {
                view! {
                    <div class="px-4 py-6 text-center">
                        <p class="text-sm text-gray-400 mb-1">"Git API not available on this deployment"</p>
                        <p class="text-xs text-gray-600">
                            "Enable it by starting the server with "
                            <code class="text-amber-500/80 bg-gray-800 px-1 py-0.5 rounded">"--features git"</code>
                        </p>
                    </div>
                }.into_any()
            } else if status_loading.get() && status.get().is_none() {
                view! {
                    <div class="flex items-center justify-center py-8 gap-2 text-sm text-gray-500">
                        <div class="animate-spin rounded-full h-4 w-4 border-b-2 border-amber-400/50"></div>
                        "Loading git status…"
                    </div>
                }.into_any()
            } else {
                view! {
                    <div class="divide-y divide-gray-700/30">

                        // ── Staged Changes ───────────────────────────────────
                        {move || {
                            let staged = status.get().map(|s| s.staged).unwrap_or_default();
                            let count = staged.len();
                            view! {
                                <div>
                                    <div class="flex items-center justify-between px-4 py-1.5 bg-gray-800/40">
                                        <span class="text-xs font-semibold text-gray-300 uppercase tracking-wide">
                                            {format!("Staged Changes ({})", count)}
                                        </span>
                                        {if count > 0 {
                                            let unstage_all = unstage_all.clone();
                                            view! {
                                                <button
                                                    class="text-xs text-gray-400 hover:text-white transition-colors px-2 py-0.5 rounded hover:bg-gray-700"
                                                    on:click=move |_| unstage_all()
                                                >
                                                    "Unstage All"
                                                </button>
                                            }.into_any()
                                        } else {
                                            view! { <span></span> }.into_any()
                                        }}
                                    </div>
                                    {staged.into_iter().map(|f| {
                                        let path = f.path.clone();
                                        let (badge_letter, badge_cls) = change_badge(&f.change_type);
                                        let display_name = f.path
                                            .rsplit('/')
                                            .next()
                                            .unwrap_or(&f.path)
                                            .to_string();
                                        let full_path = f.path.clone();
                                        let diff_path = f.path.clone();
                                        let unstage_file = unstage_file.clone();
                                        let view_diff = view_diff.clone();
                                        let is_diff_shown = {
                                            let diff_path2 = diff_path.clone();
                                            move || diff_view.get().map(|(p, _)| p == diff_path2).unwrap_or(false)
                                        };
                                        let diff_text = {
                                            let diff_path3 = diff_path.clone();
                                            move || diff_view.get().and_then(|(p, d)| if p == diff_path3 { Some(d) } else { None })
                                        };
                                        view! {
                                            <div>
                                                <div class="flex items-center gap-2 px-4 py-1.5 hover:bg-gray-800/60 group">
                                                    <span class=format!("text-xs font-bold px-1 rounded {badge_cls}")>
                                                        {badge_letter}
                                                    </span>
                                                    <span class="flex-1 text-sm text-gray-300 font-mono truncate" title=full_path.clone()>
                                                        {display_name}
                                                    </span>
                                                    // Unstage button
                                                    <button
                                                        class="opacity-0 group-hover:opacity-100 text-xs text-gray-400 hover:text-amber-400 transition-all px-1.5 py-0.5 rounded hover:bg-gray-700"
                                                        title="Unstage"
                                                        on:click={
                                                            let path = path.clone();
                                                            let unstage_file = unstage_file.clone();
                                                            move |_| unstage_file(path.clone())
                                                        }
                                                    >
                                                        "−"
                                                    </button>
                                                    // Diff button
                                                    <button
                                                        class="opacity-0 group-hover:opacity-100 text-xs text-gray-500 hover:text-blue-400 transition-all px-1.5 py-0.5 rounded hover:bg-gray-700"
                                                        title="View diff"
                                                        on:click={
                                                            let diff_path4 = diff_path.clone();
                                                            let view_diff = view_diff.clone();
                                                            move |_| view_diff(diff_path4.clone(), true)
                                                        }
                                                    >
                                                        {move || if is_diff_shown() { "▲ diff" } else { "diff" }}
                                                    </button>
                                                </div>
                                                {move || diff_text().map(|d| view! {
                                                    <div class="px-4 pb-2">
                                                        <DiffViewer path=diff_path.clone() diff=d />
                                                    </div>
                                                })}
                                            </div>
                                        }
                                    }).collect_view()}
                                </div>
                            }
                        }}

                        // ── Unstaged Changes ─────────────────────────────────
                        {move || {
                            let unstaged = status.get().map(|s| s.unstaged).unwrap_or_default();
                            let count = unstaged.len();
                            view! {
                                <div>
                                    <div class="flex items-center justify-between px-4 py-1.5 bg-gray-800/40">
                                        <span class="text-xs font-semibold text-gray-300 uppercase tracking-wide">
                                            {format!("Changes ({})", count)}
                                        </span>
                                        {if count > 0 {
                                            let stage_all = stage_all.clone();
                                            view! {
                                                <button
                                                    class="text-xs text-gray-400 hover:text-white transition-colors px-2 py-0.5 rounded hover:bg-gray-700"
                                                    on:click=move |_| stage_all()
                                                >
                                                    "Stage All"
                                                </button>
                                            }.into_any()
                                        } else {
                                            view! { <span></span> }.into_any()
                                        }}
                                    </div>
                                    {unstaged.into_iter().map(|f| {
                                        let path = f.path.clone();
                                        let (badge_letter, badge_cls) = change_badge(&f.change_type);
                                        let display_name = f.path
                                            .rsplit('/')
                                            .next()
                                            .unwrap_or(&f.path)
                                            .to_string();
                                        let full_path = f.path.clone();
                                        let stage_path = f.path.clone();
                                        let discard_path = f.path.clone();
                                        let diff_path = f.path.clone();
                                        let stage_file = stage_file.clone();
                                        let discard_file = discard_file.clone();
                                        let view_diff = view_diff.clone();
                                        let is_diff_shown = {
                                            let diff_path2 = diff_path.clone();
                                            move || diff_view.get().map(|(p, _)| p == diff_path2).unwrap_or(false)
                                        };
                                        let diff_text = {
                                            let diff_path3 = diff_path.clone();
                                            move || diff_view.get().and_then(|(p, d)| if p == diff_path3 { Some(d) } else { None })
                                        };
                                        view! {
                                            <div>
                                                <div class="flex items-center gap-2 px-4 py-1.5 hover:bg-gray-800/60 group">
                                                    <span class=format!("text-xs font-bold px-1 rounded {badge_cls}")>
                                                        {badge_letter}
                                                    </span>
                                                    <span class="flex-1 text-sm text-gray-300 font-mono truncate" title=full_path>
                                                        {display_name}
                                                    </span>
                                                    // Stage button
                                                    <button
                                                        class="opacity-0 group-hover:opacity-100 text-xs text-green-500 hover:text-green-400 transition-all px-1.5 py-0.5 rounded hover:bg-gray-700"
                                                        title="Stage"
                                                        on:click={
                                                            let stage_file = stage_file.clone();
                                                            move |_| stage_file(stage_path.clone())
                                                        }
                                                    >
                                                        "+"
                                                    </button>
                                                    // Discard button
                                                    <button
                                                        class="opacity-0 group-hover:opacity-100 text-xs text-red-500 hover:text-red-400 transition-all px-1.5 py-0.5 rounded hover:bg-gray-700"
                                                        title="Discard changes"
                                                        on:click={
                                                            let discard_file = discard_file.clone();
                                                            move |_| discard_file(discard_path.clone())
                                                        }
                                                    >
                                                        "✕"
                                                    </button>
                                                    // Diff button
                                                    <button
                                                        class="opacity-0 group-hover:opacity-100 text-xs text-gray-500 hover:text-blue-400 transition-all px-1.5 py-0.5 rounded hover:bg-gray-700"
                                                        title="View diff"
                                                        on:click={
                                                            let view_diff = view_diff.clone();
                                                            move |_| view_diff(diff_path.clone(), false)
                                                        }
                                                    >
                                                        {move || if is_diff_shown() { "▲ diff" } else { "diff" }}
                                                    </button>
                                                </div>
                                                {move || diff_text().map(|d| view! {
                                                    <div class="px-4 pb-2">
                                                        <DiffViewer path=path.clone() diff=d />
                                                    </div>
                                                })}
                                            </div>
                                        }
                                    }).collect_view()}
                                </div>
                            }
                        }}

                        // ── Untracked Files ──────────────────────────────────
                        {move || {
                            let untracked = status.get().map(|s| s.untracked).unwrap_or_default();
                            if untracked.is_empty() {
                                return view! { <div></div> }.into_any();
                            }
                            let count = untracked.len();
                            view! {
                                <div>
                                    <div class="px-4 py-1.5 bg-gray-800/40">
                                        <span class="text-xs font-semibold text-gray-300 uppercase tracking-wide">
                                            {format!("Untracked ({})", count)}
                                        </span>
                                    </div>
                                    {untracked.into_iter().map(|path| {
                                        let stage_path = path.clone();
                                        let display_name = path
                                            .rsplit('/')
                                            .next()
                                            .unwrap_or(&path)
                                            .to_string();
                                        let stage_file = stage_file.clone();
                                        view! {
                                            <div class="flex items-center gap-2 px-4 py-1.5 hover:bg-gray-800/60 group">
                                                <span class="text-xs font-bold px-1 rounded text-gray-500 bg-gray-800">
                                                    "?"
                                                </span>
                                                <span class="flex-1 text-sm text-gray-400 font-mono truncate" title=path.clone()>
                                                    {display_name}
                                                </span>
                                                <button
                                                    class="opacity-0 group-hover:opacity-100 text-xs text-green-500 hover:text-green-400 transition-all px-1.5 py-0.5 rounded hover:bg-gray-700"
                                                    title="Stage"
                                                    on:click={
                                                        let stage_file = stage_file.clone();
                                                        move |_| stage_file(stage_path.clone())
                                                    }
                                                >
                                                    "+"
                                                </button>
                                            </div>
                                        }
                                    }).collect_view()}
                                </div>
                            }.into_any()
                        }}

                        // ── Commit area ──────────────────────────────────────
                        <div class="px-4 py-3 bg-gray-850/20">
                            <textarea
                                class="w-full bg-gray-800 border border-gray-700/50 rounded px-3 py-2 text-sm text-gray-200 placeholder-gray-600 resize-none focus:outline-none focus:border-amber-500/50 font-mono"
                                rows="3"
                                placeholder="Commit message (required)"
                                prop:value=move || commit_msg.get()
                                on:input=move |ev| {
                                    let target = ev.target().unwrap();
                                    let el: web_sys::HtmlTextAreaElement = target.dyn_into().unwrap();
                                    commit_msg.set(el.value());
                                }
                            ></textarea>
                            <div class="flex items-center gap-2 mt-2">
                                <button
                                    class="flex-1 bg-amber-600 hover:bg-amber-500 disabled:opacity-40 text-white text-sm font-semibold px-3 py-1.5 rounded-md transition-colors"
                                    disabled=move || busy.get() || commit_msg.get().trim().is_empty()
                                    on:click={
                                        let do_commit = do_commit.clone();
                                        move |_| do_commit()
                                    }
                                >
                                    "Commit"
                                </button>
                            </div>
                        </div>

                        // ── History (lazy) ────────────────────────────────────
                        <div>
                            <button
                                class="w-full flex items-center gap-2 px-4 py-2 text-xs text-gray-400 hover:text-white hover:bg-gray-800/60 transition-colors text-left"
                                on:click={
                                    let load_log = load_log.clone();
                                    move |_| {
                                        let expanded = !log_expanded.get_untracked();
                                        log_expanded.set(expanded);
                                        if expanded && log.get_untracked().is_empty() {
                                            load_log();
                                        }
                                    }
                                }
                            >
                                <span class=move || if log_expanded.get() { "text-amber-400" } else { "text-gray-500" }>
                                    {move || if log_expanded.get() { "▼" } else { "▶" }}
                                </span>
                                <span class="font-semibold uppercase tracking-wide">"History"</span>
                                {move || {
                                    let n = log.get().len();
                                    if n > 0 {
                                        view! { <span class="text-gray-600">{format!("({n})")}</span> }.into_any()
                                    } else {
                                        view! { <span></span> }.into_any()
                                    }
                                }}
                            </button>
                            <Show when=move || log_expanded.get()>
                                <div class="divide-y divide-gray-800/80 max-h-64 overflow-y-auto">
                                    {move || {
                                        let commits = log.get();
                                        if commits.is_empty() {
                                            return view! {
                                                <div class="px-4 py-3 text-xs text-gray-600 italic">"No commits yet"</div>
                                            }.into_any();
                                        }
                                        commits.into_iter().map(|c| view! {
                                            <div class="px-4 py-2 hover:bg-gray-800/40">
                                                <div class="flex items-baseline gap-2">
                                                    <code class="text-xs text-amber-500/80 font-mono flex-shrink-0">
                                                        {c.short_hash}
                                                    </code>
                                                    <span class="text-sm text-gray-300 truncate flex-1">{c.message}</span>
                                                </div>
                                                <div class="text-xs text-gray-600 mt-0.5">
                                                    {format!("{} · {}", c.author, c.date_relative)}
                                                </div>
                                            </div>
                                        }).collect_view().into_any()
                                    }}
                                </div>
                            </Show>
                        </div>

                    </div>
                }.into_any()
            }}
        </section>
    }
}

// ── App Manifest Panel ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct AppManifest {
    name: String,
    description: String,
    #[serde(default)]
    git_source: String,
    #[serde(default = "default_version")]
    version: String,
}

fn default_version() -> String {
    "1.0.0".to_string()
}

#[component]
pub fn AppManifestPanel(pod_base_url: Memo<Option<String>>) -> impl IntoView {
    let auth = use_auth();
    let toasts = use_toasts();

    let expanded = RwSignal::new(false);
    let name = RwSignal::new(String::new());
    let description = RwSignal::new(String::new());
    let git_source = RwSignal::new(String::new());
    let version = RwSignal::new("1.0.0".to_string());
    let loading = RwSignal::new(false);
    let saving = RwSignal::new(false);
    let git_source_error = RwSignal::new(false);

    // Load manifest when panel is expanded and URL is available
    let load_manifest = {
        let auth = auth.clone();
        move || {
            let Some(base) = pod_base_url.get() else {
                return;
            };
            let Some(signer) = auth.get_signer() else {
                return;
            };
            let url = format!("{}/apps/manifest.json", base.trim_end_matches('/'));
            loading.set(true);
            spawn_local(async move {
                match git_fetch_raw(&url, "GET", None, &*signer).await {
                    Ok((200, body)) => {
                        if let Ok(m) = serde_json::from_str::<AppManifest>(&body) {
                            name.set(m.name);
                            description.set(m.description);
                            git_source.set(m.git_source);
                            version.set(m.version);
                        }
                    }
                    Ok((404, _)) => {} // empty form is correct
                    Ok((code, _)) => leptos::logging::warn!("manifest load HTTP {code}"),
                    Err(e) => leptos::logging::warn!("manifest load error: {e}"),
                }
                loading.set(false);
            });
        }
    };

    let save_manifest = {
        let auth = auth.clone();
        move || {
            let gs = git_source.get_untracked();
            if !gs.is_empty() && !gs.starts_with("https://") {
                git_source_error.set(true);
                toasts.show(
                    "Git source URL must start with https://",
                    ToastVariant::Warning,
                );
                return;
            }
            git_source_error.set(false);

            let Some(base) = pod_base_url.get() else {
                return;
            };
            let Some(signer) = auth.get_signer() else {
                return;
            };
            let manifest = AppManifest {
                name: name.get_untracked(),
                description: description.get_untracked(),
                git_source: gs,
                version: version.get_untracked(),
            };
            let body = match serde_json::to_string_pretty(&manifest) {
                Ok(s) => s,
                Err(e) => {
                    toasts.show(&format!("Serialization error: {e}"), ToastVariant::Error);
                    return;
                }
            };
            let url = format!("{}/apps/manifest.json", base.trim_end_matches('/'));
            saving.set(true);
            spawn_local(async move {
                match git_fetch_raw(&url, "PUT", Some(body), &*signer).await {
                    Ok((200, _)) | Ok((201, _)) | Ok((204, _)) => {
                        toasts.show("App manifest saved", ToastVariant::Success);
                    }
                    Ok((code, body)) => {
                        toasts.show(
                            &format!("Save failed: HTTP {code} — {body}"),
                            ToastVariant::Error,
                        );
                    }
                    Err(e) => {
                        toasts.show(&format!("Save error: {e}"), ToastVariant::Error);
                    }
                }
                saving.set(false);
            });
        }
    };

    view! {
        <section
            data-section="app-manifest"
            class="mb-4 bg-gray-900 border border-gray-700/50 rounded-lg overflow-hidden"
        >
            // Collapsible header
            <button
                class="w-full flex items-center justify-between px-4 py-2.5 bg-gray-800/80 hover:bg-gray-800 transition-colors text-left"
                on:click={
                    let load_manifest = load_manifest.clone();
                    move |_| {
                        let will_expand = !expanded.get_untracked();
                        expanded.set(will_expand);
                        if will_expand {
                            load_manifest();
                        }
                    }
                }
            >
                <div class="flex items-center gap-2">
                    <svg class="w-4 h-4 text-purple-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <rect x="3" y="3" width="18" height="18" rx="2" ry="2"/>
                        <line x1="3" y1="9" x2="21" y2="9"/>
                        <line x1="9" y1="21" x2="9" y2="9"/>
                    </svg>
                    <span class="text-sm font-semibold text-white">"App Manifest"</span>
                    <span class="text-xs text-gray-600">"(JSS #464)"</span>
                </div>
                <span class=move || if expanded.get() { "text-gray-400" } else { "text-gray-600" }>
                    {move || if expanded.get() { "▲" } else { "▼" }}
                </span>
            </button>

            <Show when=move || expanded.get()>
                {move || if loading.get() {
                    view! {
                        <div class="flex items-center justify-center py-6 gap-2 text-sm text-gray-500">
                            <div class="animate-spin rounded-full h-4 w-4 border-b-2 border-purple-400/50"></div>
                            "Loading manifest…"
                        </div>
                    }.into_any()
                } else {
                    view! {
                        <div class="px-4 py-3 space-y-3">
                            // Name
                            <div>
                                <label class="block text-xs text-gray-400 mb-1 font-medium">"App Name"</label>
                                <input
                                    type="text"
                                    class="w-full bg-gray-800 border border-gray-700/50 rounded px-3 py-1.5 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-purple-500/50"
                                    placeholder="My App"
                                    prop:value=move || name.get()
                                    on:input=move |ev| {
                                        let target = ev.target().unwrap();
                                        let el: web_sys::HtmlInputElement = target.dyn_into().unwrap();
                                        name.set(el.value());
                                    }
                                />
                            </div>

                            // Description
                            <div>
                                <label class="block text-xs text-gray-400 mb-1 font-medium">"Description"</label>
                                <textarea
                                    class="w-full bg-gray-800 border border-gray-700/50 rounded px-3 py-1.5 text-sm text-gray-200 placeholder-gray-600 resize-none focus:outline-none focus:border-purple-500/50"
                                    rows="2"
                                    placeholder="What does this app do?"
                                    prop:value=move || description.get()
                                    on:input=move |ev| {
                                        let target = ev.target().unwrap();
                                        let el: web_sys::HtmlTextAreaElement = target.dyn_into().unwrap();
                                        description.set(el.value());
                                    }
                                ></textarea>
                            </div>

                            // Git source URL
                            <div>
                                <label class="block text-xs text-gray-400 mb-1 font-medium">"Git Source URL"</label>
                                <input
                                    type="url"
                                    class=move || format!(
                                        "w-full bg-gray-800 border rounded px-3 py-1.5 text-sm text-gray-200 placeholder-gray-600 focus:outline-none {}",
                                        if git_source_error.get() {
                                            "border-red-500/60 focus:border-red-500"
                                        } else {
                                            "border-gray-700/50 focus:border-purple-500/50"
                                        }
                                    )
                                    placeholder="https://github.com/org/repo"
                                    prop:value=move || git_source.get()
                                    on:input=move |ev| {
                                        let target = ev.target().unwrap();
                                        let el: web_sys::HtmlInputElement = target.dyn_into().unwrap();
                                        let val = el.value();
                                        git_source_error.set(!val.is_empty() && !val.starts_with("https://"));
                                        git_source.set(val);
                                    }
                                />
                                <Show when=move || git_source_error.get()>
                                    <p class="text-xs text-red-400 mt-1">"URL must start with https://"</p>
                                </Show>
                            </div>

                            // Version
                            <div>
                                <label class="block text-xs text-gray-400 mb-1 font-medium">"Version"</label>
                                <input
                                    type="text"
                                    class="w-full bg-gray-800 border border-gray-700/50 rounded px-3 py-1.5 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-purple-500/50"
                                    placeholder="1.0.0"
                                    prop:value=move || version.get()
                                    on:input=move |ev| {
                                        let target = ev.target().unwrap();
                                        let el: web_sys::HtmlInputElement = target.dyn_into().unwrap();
                                        version.set(el.value());
                                    }
                                />
                            </div>

                            // Save button
                            <button
                                class="w-full bg-purple-600 hover:bg-purple-500 disabled:opacity-40 text-white text-sm font-semibold px-3 py-1.5 rounded-md transition-colors"
                                disabled=move || saving.get() || git_source_error.get()
                                on:click={
                                    let save_manifest = save_manifest.clone();
                                    move |_| save_manifest()
                                }
                            >
                                {move || if saving.get() { "Saving…" } else { "Save Manifest" }}
                            </button>
                        </div>
                    }.into_any()
                }}
            </Show>
        </section>
    }
}
