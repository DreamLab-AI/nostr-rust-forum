//! Profile-picture avatar with generative identicon fallback.
//!
//! Resolves the pubkey's kind-0 `picture` from the reactive `ProfileCache`
//! (tracked read — the avatar fills in as soon as metadata arrives). When a
//! non-empty http(s) URL is cached, renders a round lazily-loaded `<img>`
//! clipped by the identicon disc; the initials disc remains the fallback for
//! missing pictures and for images that fail to load (`on:error`).
//!
//! The identicon derives a deterministic hue from the pubkey (same algo as
//! `utils::pubkey_color`) and displays the first two hex characters as
//! initials inside a colored circle.

use leptos::prelude::*;

use crate::stores::profile_cache::try_use_profile_cache;
use crate::utils::pubkey_color;

/// Avatar size presets.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[allow(dead_code)]
pub enum AvatarSize {
    /// 28px
    Sm,
    /// 36px (default)
    #[default]
    Md,
    /// 48px
    Lg,
    /// 80px
    Xl,
}

impl AvatarSize {
    fn px(self) -> u32 {
        match self {
            Self::Sm => 28,
            Self::Md => 36,
            Self::Lg => 48,
            Self::Xl => 80,
        }
    }

    fn text_class(self) -> &'static str {
        match self {
            Self::Sm => "text-[10px]",
            Self::Md => "text-xs",
            Self::Lg => "text-sm",
            Self::Xl => "text-xl",
        }
    }
}

/// Avatar rendered from a hex pubkey.
///
/// Shows the kind-0 profile picture when the `ProfileCache` resolves one,
/// falling back to the first two pubkey characters as initials on a
/// deterministic HSL background. Supports an optional online-indicator dot
/// and four size presets.
#[component]
pub(crate) fn Avatar(
    /// Hex pubkey used for picture lookup, color derivation, and initials.
    pubkey: String,
    /// Visual size. Defaults to `Md` (36 px).
    #[prop(optional)]
    size: AvatarSize,
    /// Show a green online-indicator dot.
    #[prop(optional)]
    online: bool,
) -> impl IntoView {
    let bg = pubkey_color(&pubkey);
    let initials = pubkey.chars().take(2).collect::<String>().to_uppercase();

    let px = size.px();
    let dim = format!("width: {}px; height: {}px; min-width: {}px;", px, px, px);
    let style = format!("background-color: {}; {}", bg, dim);
    let text_cls = size.text_class();

    let outer_class = format!("avatar-identicon text-white {} relative", text_cls,);

    // Tracked picture resolution: re-evaluates when kind-0 metadata fills the
    // cache. `failed_src` remembers the last URL that errored so we flip back
    // to initials for it, while still retrying if the profile later points at
    // a different URL.
    let cache = try_use_profile_cache();
    let failed_src = RwSignal::new(Option::<String>::None);
    let pk_for_pic = pubkey.clone();
    let picture = Memo::new(move |_| {
        let url = cache
            .as_ref()
            .and_then(|c| c.picture_reactive(&pk_for_pic))?;
        if failed_src.get().as_deref() == Some(url.as_str()) {
            return None;
        }
        Some(url)
    });

    // Online dot sizing scales with the avatar.
    let dot_px = if px >= 48 { 12 } else { 8 };
    let dot_style = format!(
        "width: {}px; height: {}px; bottom: -1px; right: -1px;",
        dot_px, dot_px,
    );

    view! {
        <div class=outer_class style=style>
            {initials}
            {move || picture.get().map(|url| {
                let url_for_error = url.clone();
                view! {
                    <img
                        src=url
                        loading="lazy"
                        alt=""
                        class="absolute inset-0 w-full h-full object-cover rounded-full"
                        on:error=move |_| failed_src.set(Some(url_for_error.clone()))
                    />
                }
            })}
            {online.then(|| view! {
                <span
                    class="absolute rounded-full bg-green-500 ring-2 ring-gray-900"
                    style=dot_style
                />
            })}
        </div>
    }
}
