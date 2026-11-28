//! Modern retro ASCII/BBS terminal client for the nostr-rust-forum kit.
//!
//! A responsive Leptos CSR/WASM application served at `/community/bbs/` that
//! shares the headless [`nostr_bbs_client_core`] engine with the main forum
//! client (zero drift across auth, relay, encrypted zones, governance, DMs,
//! Kanban, Calendar, Colloquy, Poker, and Sidestr wallets) while presenting a
//! retro phosphor TUI aesthetic tuned for both desktop keyboards and mobile
//! phone surfaces.

pub mod ascii_img;
pub mod components;
pub mod config;
pub mod identity;
pub mod pod;
pub mod prefs;
pub mod pwa;
pub mod router;
pub mod shell;
pub mod subs;
pub mod theme;
pub mod upload;
pub mod views;

mod app;
pub use app::App;
