//! WASM entry point: mount the BBS app.

fn main() {
    console_error_panic_hook::set_once();
    leptos::mount::mount_to_body(nostr_bbs_bbs_client::App);
}
