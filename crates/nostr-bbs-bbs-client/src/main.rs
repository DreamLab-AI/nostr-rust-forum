//! WASM entry point: mount the BBS app.

fn main() {
    console_error_panic_hook::set_once();
    // The BBS shares the forum's origin storage (IndexedDB `members-forum`,
    // the sealed-search index, relay-scoped localStorage), so it runs the
    // same relay-scope check before anything reads it, with the same 3 s
    // ceiling as the forum.
    wasm_bindgen_futures::spawn_local(async {
        nostr_bbs_client_core::stores::relay_scope::enforce_within(3_000).await;
        leptos::mount::mount_to_body(nostr_bbs_bbs_client::App);
    });
}
