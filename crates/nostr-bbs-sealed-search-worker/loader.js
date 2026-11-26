// Boots the sealed-search Web Worker (wasm-bindgen `no-modules` glue). The Rust
// side installs its message handler and posts {op:"booted"} once ready.
// Built by stack/build-client.sh (or the deploy pipeline) into <base>/sealed-search/.
importScripts('nostr-bbs-sealed-search-worker.js');
wasm_bindgen('nostr-bbs-sealed-search-worker_bg.wasm');
