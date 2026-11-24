//! `nostr-bbs-import` binary (native only).

#[cfg(not(target_arch = "wasm32"))]
fn main() -> std::process::ExitCode {
    std::process::ExitCode::SUCCESS
}

#[cfg(target_arch = "wasm32")]
fn main() {}
