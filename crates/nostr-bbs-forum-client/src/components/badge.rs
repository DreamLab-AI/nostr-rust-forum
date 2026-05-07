//! Reusable status badge / pill component.
//!
//! Renders a rounded-full pill with variant-specific coloring.
//! Supports an optional pulsing neon effect via the `neon-pulse` CSS class.

use leptos::prelude::*;

/// Color variant for a badge.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[allow(dead_code)]
pub enum BadgeVariant {
    /// Amber accent (default).
    #[default]
    Primary,
    /// Green.
    Success,
    /// Yellow.
    Warning,
    /// Red.
    Error,
    /// Blue.
    Info,
    /// Gray / muted.
    Ghost,
}

impl BadgeVariant {
    fn classes(self) -> &'static str {
        match self {
            Self::Primary => "bg-amber-500/15 text-amber-400 border-amber-500/30",
            Self::Success => "bg-green-500/15 text-green-400 border-green-500/30",
            Self::Warning => "bg-yellow-500/15 text-yellow-300 border-yellow-500/30",
            Self::Error => "bg-red-500/15 text-red-400 border-red-500/30",
            Self::Info => "bg-blue-500/15 text-blue-400 border-blue-500/30",
            Self::Ghost => "bg-gray-700/40 text-gray-400 border-gray-600/40",
        }
    }
}

/// Badge size presets.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[allow(dead_code)]
pub enum BadgeSize {
    /// Compact: text-[10px] px-1.5 py-0.
    Sm,
    /// Standard (default): text-xs px-2 py-0.5.
    #[default]
    Md,
}

impl BadgeSize {
    fn classes(self) -> &'static str {
        match self {
            Self::Sm => "text-[10px] px-1.5 py-0 leading-4",
            Self::Md => "text-xs px-2 py-0.5",
        }
    }
}

/// Rounded-full status badge with optional neon pulse.
#[component]
pub(crate) fn Badge(
    /// Display text.
    text: String,
    /// Color variant.
    #[prop(optional)]
    variant: BadgeVariant,
    /// Size preset.
    #[prop(optional)]
    size: BadgeSize,
    /// Enable pulsing neon glow effect.
    #[prop(optional)]
    pulse: bool,
    /// Optional icon content rendered before the text.
    #[prop(optional)]
    icon: Option<Children>,
) -> impl IntoView {
    let cls = format!(
        "inline-flex items-center gap-1 rounded-full border font-medium {} {} {}",
        variant.classes(),
        size.classes(),
        if pulse { "neon-pulse" } else { "" },
    );

    view! {
        <span class=cls>
            {icon.map(|c| c())}
            {text}
        </span>
    }
}
