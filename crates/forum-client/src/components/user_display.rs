//! Compact inline user display component.
//!
//! Shows a small identicon avatar and display name (or shortened pubkey) in a
//! single-line layout. Used in message headers, user lists, and other compact
//! contexts. Resolves display names from a shared context cache.

use std::collections::HashMap;

use leptos::prelude::*;

use crate::components::avatar::{Avatar, AvatarSize};
use crate::utils::shorten_pubkey;

// -- Name cache context -------------------------------------------------------

/// Shared name cache: maps hex pubkey -> display name.
/// Provided at the app level; components can read from and write to it.
#[derive(Clone, Copy)]
pub struct NameCache(pub RwSignal<HashMap<String, String>>);

/// Provide the name cache context. Call once at the app root.
#[allow(dead_code)]
pub fn provide_name_cache() {
    provide_context(NameCache(RwSignal::new(HashMap::new())));
}

/// Get the name cache from context. Returns None if not provided.
fn try_use_name_cache() -> Option<NameCache> {
    use_context::<NameCache>()
}

/// Resolve a pubkey to a display name using the shared NameCache.
///
/// Returns the cached name if available, otherwise falls back to
/// `shorten_pubkey`. This is the canonical way to get a display name —
/// use it in every component that shows a user identity.
pub fn use_display_name(pubkey: &str) -> String {
    if let Some(cache) = try_use_name_cache() {
        if let Some(name) = cache.0.get_untracked().get(pubkey).cloned() {
            return name;
        }
    }
    shorten_pubkey(pubkey)
}

/// Reactive version of `use_display_name` for use inside `view!` macros.
/// Returns a `Memo<String>` that re-evaluates when the NameCache changes.
pub fn use_display_name_memo(pubkey: String) -> Memo<String> {
    Memo::new(move |_| {
        if let Some(cache) = try_use_name_cache() {
            if let Some(name) = cache.0.get().get(&pubkey).cloned() {
                return name;
            }
        }
        shorten_pubkey(&pubkey)
    })
}

// -- Component ----------------------------------------------------------------

/// Size presets for the inline user display.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[allow(dead_code)]
pub enum UserDisplaySize {
    /// Small: 20px avatar, text-xs
    Sm,
    /// Medium (default): 28px avatar, text-sm
    #[default]
    Md,
}

impl UserDisplaySize {
    fn avatar_size(self) -> AvatarSize {
        match self {
            Self::Sm => AvatarSize::Sm,
            Self::Md => AvatarSize::Sm,
        }
    }

    fn text_class(self) -> &'static str {
        match self {
            Self::Sm => "text-xs",
            Self::Md => "text-sm",
        }
    }

    fn gap_class(self) -> &'static str {
        match self {
            Self::Sm => "gap-1.5",
            Self::Md => "gap-2",
        }
    }
}

/// Compact inline user display with avatar + name.
///
/// Resolves the display name from the shared `NameCache` context if available,
/// otherwise falls back to a shortened hex pubkey.
#[allow(dead_code)]
#[component]
pub(crate) fn UserDisplay(
    /// Hex pubkey of the user.
    pubkey: String,
    /// Whether to show the avatar. Defaults to true.
    #[prop(optional, default = true)]
    show_avatar: bool,
    /// Display size preset. Defaults to `Md`.
    #[prop(optional)]
    size: UserDisplaySize,
    /// Optional callback when the user display is clicked.
    #[prop(optional, into)]
    on_click: Option<Callback<String>>,
) -> impl IntoView {
    let pk = pubkey.clone();
    let pk_for_click = pubkey.clone();
    let pk_for_title = pubkey.clone();

    let display_name = Memo::new(move |_| {
        // Try the name cache first
        if let Some(cache) = try_use_name_cache() {
            if let Some(name) = cache.0.get().get(&pk).cloned() {
                return name;
            }
        }
        shorten_pubkey(&pk)
    });

    let text_class = size.text_class();
    let gap_class = size.gap_class();

    let wrapper_class = format!(
        "inline-flex items-center {} {} font-medium text-gray-300 hover:text-amber-400 transition-colors {}",
        gap_class,
        text_class,
        if on_click.is_some() { "cursor-pointer" } else { "" },
    );

    let handle_click = move |_| {
        if let Some(ref cb) = on_click {
            cb.run(pk_for_click.clone());
        }
    };

    view! {
        <span class=wrapper_class title=pk_for_title on:click=handle_click>
            {show_avatar.then(|| {
                let pk_avatar = pubkey.clone();
                view! {
                    <Avatar pubkey=pk_avatar size=size.avatar_size() />
                }
            })}
            <span class="truncate max-w-[120px]">
                {move || display_name.get()}
            </span>
        </span>
    }
}
