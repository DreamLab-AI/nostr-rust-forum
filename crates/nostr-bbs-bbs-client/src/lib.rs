//! Retro ASCII/BBS terminal client for the nostr-rust-forum kit.
//!
//! A Leptos CSR/WASM app served at `/community/bbs/` and driven entirely by
//! `forum.toml` (projected to `window.__ENV__`). It is a faithful BBS *face*
//! over the kit's real infrastructure — config-driven zones, did:nostr identity,
//! Solid pods (via `solid-pod-rs`), and the agent-governance control-panel plane
//! (`nostr_bbs_core::governance`) — not a standalone reimplementation.
//!
//! Pure logic (`config`, `theme`, `menu`, `agent`, `identity`) is unit-tested on
//! the native target; `chrome`, `screens`, and `app` render the Leptos UI.

pub mod agent;
pub mod ascii_img;
pub mod chrome;
pub mod config;
pub mod identity;
pub mod menu;
pub mod pod;
pub mod relay;
pub mod screens;
pub mod theme;

mod app;
pub use app::App;
