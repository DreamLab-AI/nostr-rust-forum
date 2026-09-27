//! `nostr-bbs-zone-migrate` binary. See the library docs and
//! `docs/security/encrypted-zone-history-migration.md`.
//!
//! The binary is native-only; on wasm32 it compiles to an empty `main` so the
//! workspace-wide wasm32 check still covers the library.

#[cfg(not(target_arch = "wasm32"))]
mod cli;
#[cfg(not(target_arch = "wasm32"))]
mod net;

#[cfg(not(target_arch = "wasm32"))]
fn main() -> std::process::ExitCode {
    cli::main()
}

#[cfg(target_arch = "wasm32")]
fn main() {}
