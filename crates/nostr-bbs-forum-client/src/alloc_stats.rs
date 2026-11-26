//! Opt-in heap accounting for memory investigations (`--features alloc-stats`).
//!
//! Wraps the default allocator and counts live bytes and allocations, and
//! installs `window.__allocStats()` returning `{live, peak, count, hist}`
//! (`hist[b]`: live allocations of size `[2^(b-1), 2^b)`). Wasm
//! linear memory never shrinks, so its page count shows only the high-water
//! mark: comparing it with `live` tells a true leak (live bytes climb) from
//! allocator fragmentation (live bytes flat while pages climb). Off by
//! default; never enable in a release build.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static COUNT: AtomicUsize = AtomicUsize::new(0);
/// Live allocations per size class: bucket `b` holds sizes in
/// `[2^(b-1), 2^b)` (bucket 0: size 0), the last bucket everything larger.
const BUCKETS: usize = 24;
static HIST: [AtomicUsize; BUCKETS] = [const { AtomicUsize::new(0) }; BUCKETS];

fn bucket(size: usize) -> usize {
    ((usize::BITS - size.leading_zeros()) as usize).min(BUCKETS - 1)
}

struct Counting;

fn grew(by: usize) {
    let now = LIVE.fetch_add(by, Ordering::Relaxed) + by;
    PEAK.fetch_max(now, Ordering::Relaxed);
}

// SAFETY: every method forwards to `System` with the caller's layout and
// only adjusts counters; allocation behaviour is unchanged.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            grew(layout.size());
            COUNT.fetch_add(1, Ordering::Relaxed);
            HIST[bucket(layout.size())].fetch_add(1, Ordering::Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        COUNT.fetch_sub(1, Ordering::Relaxed);
        HIST[bucket(layout.size())].fetch_sub(1, Ordering::Relaxed);
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let p = unsafe { System.realloc(ptr, layout, new_size) };
        if !p.is_null() {
            LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
            grew(new_size);
            HIST[bucket(layout.size())].fetch_sub(1, Ordering::Relaxed);
            HIST[bucket(new_size)].fetch_add(1, Ordering::Relaxed);
        }
        p
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

/// Install `window.__allocStats()`.
pub fn install() {
    use wasm_bindgen::prelude::*;
    let f = Closure::<dyn Fn() -> JsValue>::new(|| {
        let o = js_sys::Object::new();
        for (k, v) in [
            ("live", LIVE.load(Ordering::Relaxed)),
            ("peak", PEAK.load(Ordering::Relaxed)),
            ("count", COUNT.load(Ordering::Relaxed)),
        ] {
            let _ = js_sys::Reflect::set(&o, &k.into(), &(v as f64).into());
        }
        let hist = js_sys::Array::new();
        for b in &HIST {
            hist.push(&(b.load(Ordering::Relaxed) as f64).into());
        }
        let _ = js_sys::Reflect::set(&o, &"hist".into(), &hist);
        o.into()
    });
    if let Some(w) = web_sys::window() {
        let _ = js_sys::Reflect::set(&w, &"__allocStats".into(), f.as_ref());
    }
    f.forget();
}

/// Install `window.__storeStats()`: the sizes of the relay, channel-store
/// and zone-store per-id collections, to find which one grows.
pub fn install_store_stats(
    relay: crate::relay::RelayConnection,
    channels: crate::stores::channels::ChannelStore,
    zone: crate::zone_crypto::store::ZoneKeyStore,
) {
    use wasm_bindgen::prelude::*;
    let f = Closure::<dyn Fn() -> JsValue>::new(move || {
        let o = js_sys::Object::new();
        for (k, v) in relay
            .debug_sizes()
            .into_iter()
            .chain(channels.debug_sizes())
            .chain(zone.debug_sizes())
        {
            let _ = js_sys::Reflect::set(&o, &k.into(), &(v as f64).into());
        }
        o.into()
    });
    if let Some(w) = web_sys::window() {
        let _ = js_sys::Reflect::set(&w, &"__storeStats".into(), f.as_ref());
    }
    f.forget();
}
