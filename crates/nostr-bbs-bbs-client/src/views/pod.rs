//! Authenticated Solid Pod Browser + Pod Git Panel.
//!
//! Fixes the legacy BBS 401 bug by authenticating every LDP container GET and
//! `/_git/*` call with NIP-98 (`nostr_bbs_client_core::auth::nip98`), supports
//! full sub-container descent, text/JSON-LD inspection, on-theme `AsciiImg`
//! previews, and a terminal Git status/stage/commit/log surface.

use leptos::prelude::*;
use nostr_bbs_client_core::auth::nip98::{
    fetch_with_nip98_get_signer, fetch_with_nip98_post_signer,
};
use nostr_bbs_client_core::auth::use_auth;
use nostr_bbs_client_core::toast::{use_toasts, ToastVariant};

use crate::ascii_img::{is_image_name, AsciiImg};
use crate::components::{CopyKeyBtn, EmptyCard};
use crate::config::BbsConfig;
use crate::identity::Identity;
use crate::pod::{container_url, parse_container, PodResource};
use crate::router::{use_router, Route};

/// Solid Pod browser + Git panel (`#/pod` or `#/pod/<subpath>`).
#[component]
pub fn PodView(path: String) -> impl IntoView {
    let router = use_router();
    let auth = use_auth();
    let cfg = use_context::<StoredValue<BbsConfig>>().expect("BbsConfig");
    let toasts = use_toasts();

    let pod_api = cfg.with_value(|c| c.pod_api.clone());
    let tab = RwSignal::new("files"); // "files" | "git"
    let items = RwSignal::new(Vec::<PodResource>::new());
    let loading = RwSignal::new(false);
    let err = RwSignal::new(Option::<String>::None);
    let preview_file = RwSignal::new(Option::<(String, String)>::None);

    // Git panel signals
    let git_status = RwSignal::new(String::new());
    let git_log = RwSignal::new(String::new());
    let git_commit_msg = RwSignal::new(String::new());
    let git_busy = RwSignal::new(false);

    let path_fetch = path.clone();
    let pod_api_fetch = pod_api.clone();
    Effect::new(move |_| {
        let Some(pk) = auth.pubkey().get() else {
            return;
        };
        let Some(signer) = auth.get_signer() else {
            return;
        };
        if pod_api_fetch.is_empty() {
            err.set(Some("No POD_API configured for this node.".into()));
            return;
        }
        let url = container_url(&pod_api_fetch, &pk, &path_fetch);
        loading.set(true);
        err.set(None);
        preview_file.set(None);
        wasm_bindgen_futures::spawn_local(async move {
            match fetch_with_nip98_get_signer(&url, signer.as_ref()).await {
                Ok(body) => items.set(parse_container(&body)),
                Err(e) => err.set(Some(e.to_string())),
            }
            loading.set(false);
        });
    });

    let refresh_git = {
        let pod_api = pod_api.clone();
        move || {
            let Some(pk) = auth.pubkey().get_untracked() else {
                return;
            };
            let Some(signer) = auth.get_signer() else {
                return;
            };
            if pod_api.is_empty() {
                return;
            }
            let base = format!("{}/pods/{pk}/_git", pod_api.trim_end_matches('/'));
            git_busy.set(true);
            wasm_bindgen_futures::spawn_local(async move {
                match fetch_with_nip98_get_signer(&format!("{base}/status"), signer.as_ref()).await
                {
                    Ok(s) => git_status.set(s),
                    Err(e) => git_status.set(format!("Git endpoint unavailable: {e}")),
                }
                if let Ok(l) =
                    fetch_with_nip98_get_signer(&format!("{base}/log"), signer.as_ref()).await
                {
                    git_log.set(l);
                }
                git_busy.set(false);
            });
        }
    };

    let commit_git = {
        let pod_api = pod_api.clone();
        let refresh_git = refresh_git.clone();
        move |_| {
            let msg = git_commit_msg.get_untracked().trim().to_string();
            if msg.is_empty() {
                return;
            }
            let Some(pk) = auth.pubkey().get_untracked() else {
                return;
            };
            let Some(signer) = auth.get_signer() else {
                return;
            };
            let url = format!("{}/pods/{pk}/_git/commit", pod_api.trim_end_matches('/'));
            let payload = serde_json::json!({ "message": msg }).to_string();
            let refresh_git = refresh_git.clone();
            git_busy.set(true);
            wasm_bindgen_futures::spawn_local(async move {
                match fetch_with_nip98_post_signer(&url, &payload, signer.as_ref()).await {
                    Ok(_) => {
                        git_commit_msg.set(String::new());
                        toasts.show("Committed pod changes", ToastVariant::Success);
                        refresh_git();
                    }
                    Err(e) => toasts.show(format!("Commit failed: {e}"), ToastVariant::Error),
                }
                git_busy.set(false);
            });
        }
    };

    let path_disp = path.clone();
    let pod_api_view = pod_api.clone();
    let refresh_git_tab = refresh_git.clone();

    view! {
        <div class="tui-container">
            <div class="tui-page-head">
                <div>
                    <h1 class="tui-page-title">"▤ Solid Pod & Git"</h1>
                    <p class="tui-page-sub">
                        "NIP-98 authenticated WebID storage with WAC access control and pod-git history."
                    </p>
                </div>
                <div class="tui-actions">
                    {(!path.is_empty()).then(|| view! {
                        <button
                            type="button"
                            class="bbs-btn bbs-btn-sm"
                            on:click=move |_| router.back()
                        >"← Up"</button>
                    })}
                </div>
            </div>

            {move || match auth.pubkey().get() {
                None => view! {
                    <EmptyCard
                        title="Sign in to browse your Solid pod"
                        body="Your pod is private (WAC deny-by-default) and requires NIP-98 signed requests."
                    />
                }.into_any(),
                Some(pk) => {
                    let id = Identity::derive(&pk, &pod_api_view);
                    let pk_files = pk.clone();
                    let pod_files = pod_api_view.clone();
                    let path_files = path_disp.clone();
                    let refresh_g = Callback::new({
                        let r = refresh_git_tab.clone();
                        move |_: ()| r()
                    });
                    let commit_g = Callback::new(commit_git.clone());

                    view! {
                        {id.map(|i| view! {
                            <div class="tui-card bbs-id-block tui-stack">
                                <div class="tui-row-between">
                                    <span><strong>"WebID: "</strong>{i.webid.clone()}</span>
                                    <CopyKeyBtn full=i.webid label="copy WebID" />
                                </div>
                                <div class="tui-row-between">
                                    <span class="tui-muted">"git clone " {i.git_clone.clone()}</span>
                                    <CopyKeyBtn full=format!("git clone {}", i.git_clone) label="copy git" />
                                </div>
                            </div>
                        })}

                        <div class="tui-tabs">
                            <button
                                type="button"
                                class="tui-tab"
                                class:active=move || tab.get() == "files"
                                on:click=move |_| tab.set("files")
                            >"Files (" {if path_files.is_empty() { "/".into() } else { format!("/{path_files}") }} ")"</button>
                            <button
                                type="button"
                                class="tui-tab"
                                class:active=move || tab.get() == "git"
                                on:click=move |_| {
                                    tab.set("git");
                                    refresh_g.run(());
                                }
                            >"Pod Git"</button>
                        </div>

                        {move || if tab.get() == "git" {
                            view! {
                                <div class="tui-stack">
                                    <div class="tui-card tui-stack">
                                        <div class="tui-row-between">
                                            <strong>"Working Tree Status"</strong>
                                            <button
                                                type="button"
                                                class="bbs-btn bbs-btn-sm"
                                                disabled=move || git_busy.get()
                                                on:click=move |_| refresh_g.run(())
                                            >"↻ Refresh"</button>
                                        </div>
                                        <pre style="margin:0;overflow-x:auto;font-size:0.82rem">
                                            {move || {
                                                let s = git_status.get();
                                                if s.is_empty() { "(loading…)" .into() } else { s }
                                            }}
                                        </pre>
                                    </div>
                                    <div class="tui-card tui-row">
                                        <input
                                            class="bbs-input"
                                            style="flex:1 1 200px"
                                            type="text"
                                            placeholder="Commit message…"
                                            prop:value=move || git_commit_msg.get()
                                            on:input=move |ev| git_commit_msg.set(event_target_value(&ev))
                                        />
                                        <button
                                            type="button"
                                            class="bbs-btn bbs-btn-primary"
                                            disabled=move || git_busy.get() || git_commit_msg.get().trim().is_empty()
                                            on:click=move |ev| commit_g.run(ev)
                                        >"Commit"</button>
                                    </div>
                                    {move || (!git_log.get().is_empty()).then(|| view! {
                                        <div class="tui-card tui-stack">
                                            <strong>"Recent Commits"</strong>
                                            <pre style="margin:0;overflow-x:auto;font-size:0.8rem">{git_log.get()}</pre>
                                        </div>
                                    })}
                                </div>
                            }.into_any()
                        } else {
                            let pf = pk_files.clone();
                            let pa = pod_files.clone();
                            let cur_p = path_files.clone();
                            view! {
                                {move || err.get().map(|e| view! {
                                    <div class="tui-card" style="color:var(--danger)">{e}</div>
                                })}
                                {move || loading.get().then(|| view! {
                                    <div class="tui-card tui-muted">"… Loading container"</div>
                                })}
                                {move || {
                                    let list = items.get();
                                    if !loading.get() && list.is_empty() && err.get().is_none() {
                                        return view! { <EmptyCard title="Empty container" body="No files or sub-containers here yet." /> }.into_any();
                                    }
                                    view! {
                                        <div class="tui-stack">
                                            {list.into_iter().map(|r| {
                                                let next_path = if cur_p.is_empty() {
                                                    if r.is_container { format!("{}/", r.name) } else { r.name.clone() }
                                                } else {
                                                    let base = cur_p.trim_end_matches('/');
                                                    if r.is_container { format!("{base}/{}/", r.name) } else { format!("{base}/{}", r.name) }
                                                };
                                                let img_url = (!r.is_container && is_image_name(&r.name))
                                                    .then(|| container_url(&pa, &pf, &next_path));
                                                let full_url = container_url(&pa, &pf, &next_path);
                                                let r_name = r.name.clone();
                                                let is_dir = r.is_container;

                                                view! {
                                                    <div class="tui-card tui-stack">
                                                        <div class="tui-row-between">
                                                            <button
                                                                type="button"
                                                                class="bbs-btn bbs-btn-ghost"
                                                                on:click=move |_| {
                                                                    if is_dir {
                                                                        router.go(Route::Pod { path: next_path.clone() });
                                                                    } else if let Some(signer) = auth.get_signer() {
                                                                        let u = full_url.clone();
                                                                        let nm = r_name.clone();
                                                                        wasm_bindgen_futures::spawn_local(async move {
                                                                            match fetch_with_nip98_get_signer(&u, signer.as_ref()).await {
                                                                                Ok(txt) => preview_file.set(Some((nm, txt.chars().take(8000).collect()))),
                                                                                Err(e) => toasts.show(format!("Read failed: {e}"), ToastVariant::Error),
                                                                            }
                                                                        });
                                                                    }
                                                                }
                                                            >
                                                                <span>{if is_dir { "▸" } else { "·" }}</span>
                                                                <strong>{r.name.clone()} {if is_dir { "/" } else { "" }}</strong>
                                                            </button>
                                                            <span class="bbs-badge">{if is_dir { "DIR" } else { "FILE" }}</span>
                                                        </div>
                                                        {img_url.map(|src| view! {
                                                            <div class="bbs-ascii-card">
                                                                <AsciiImg src=src cols=64 />
                                                            </div>
                                                        })}
                                                    </div>
                                                }
                                            }).collect_view()}
                                        </div>
                                    }.into_any()
                                }}
                                {move || preview_file.get().map(|(name, body)| view! {
                                    <div class="tui-card tui-card-accent tui-stack">
                                        <div class="tui-row-between">
                                            <strong>{name}</strong>
                                            <button type="button" class="bbs-btn bbs-btn-sm" on:click=move |_| preview_file.set(None)>"Close"</button>
                                        </div>
                                        <pre style="margin:0;overflow-x:auto;font-size:0.8rem;max-height:420px">{body}</pre>
                                    </div>
                                })}
                            }.into_any()
                        }}
                    }.into_any()
                }
            }}
        </div>
    }
}
