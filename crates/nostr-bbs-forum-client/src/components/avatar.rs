//! Generative identicon avatar component.
//!
//! Derives a deterministic hue from the pubkey (same algo as `utils::pubkey_color`)
//! and displays the first two hex characters as initials inside a colored circle.

use leptos::prelude::*;

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

/// Generative identicon avatar rendered from a hex pubkey.
///
/// Displays the first two characters as initials on a deterministic HSL
/// background. Supports an optional online-indicator dot and four size presets.
#[component]
pub(crate) fn Avatar(
    /// Hex pubkey used for color derivation and initials.
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

    // Online dot sizing scales with the avatar.
    let dot_px = if px >= 48 { 12 } else { 8 };
    let dot_style = format!(
        "width: {}px; height: {}px; bottom: -1px; right: -1px;",
        dot_px, dot_px,
    );

    view! {
        <div class=outer_class style=style>
            {initials}
            {online.then(|| view! {
                <span
                    class="absolute rounded-full bg-green-500 ring-2 ring-gray-900"
                    style=dot_style
                />
            })}
        </div>
    }
}
