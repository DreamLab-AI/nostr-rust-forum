//! `nostr-bbs-poker-coach` binary: the practice table's coach. See
//! [`nostr_bbs_poker_citizen::coach`] for the pure half.
//!
//! Native-only; on wasm32 it compiles to an empty `main` so the
//! workspace-wide wasm32 check still covers the library.

#[cfg(not(target_arch = "wasm32"))]
mod coach_run;

#[cfg(not(target_arch = "wasm32"))]
fn main() -> std::process::ExitCode {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("runtime: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    match rt.block_on(coach_run::main()) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("nostr-bbs-poker-coach: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(target_arch = "wasm32")]
fn main() {}
