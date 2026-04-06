//! Confirm dialog for destructive or important actions.
//!
//! Wraps `Modal` internally and provides confirm / cancel buttons with
//! variant-specific styling (danger = red tint, warning = amber).

use leptos::prelude::*;

use super::modal::Modal;

/// Visual variant for the confirm dialog.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[allow(dead_code)]
pub enum ConfirmVariant {
    /// Red-tinted confirm button (default for destructive actions).
    #[default]
    Danger,
    /// Amber-tinted confirm button.
    Warning,
}

impl ConfirmVariant {
    fn confirm_class(self) -> &'static str {
        match self {
            Self::Danger => "bg-red-600 hover:bg-red-500 text-white font-semibold px-4 py-2 rounded-lg transition-colors text-sm",
            Self::Warning => "bg-amber-500 hover:bg-amber-400 text-gray-900 font-semibold px-4 py-2 rounded-lg transition-colors text-sm",
        }
    }

    fn icon_path(self) -> &'static str {
        match self {
            Self::Danger => "M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z",
            Self::Warning => "M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z",
        }
    }

    fn icon_color(self) -> &'static str {
        match self {
            Self::Danger => "text-red-400",
            Self::Warning => "text-amber-400",
        }
    }
}

/// Confirmation modal for destructive or significant actions.
///
/// Uses `Modal` internally. The confirm button fires `on_confirm` and closes
/// the dialog. The cancel button simply closes.
#[component]
pub(crate) fn ConfirmDialog(
    /// Controls visibility.
    is_open: RwSignal<bool>,
    /// Dialog title.
    title: String,
    /// Explanatory message body.
    message: String,
    /// Label for the confirm button (e.g. "Delete", "Remove").
    confirm_label: String,
    /// Fired when the user confirms.
    on_confirm: Callback<()>,
    /// Visual variant. Defaults to `Danger`.
    #[prop(optional)]
    variant: ConfirmVariant,
    /// Label for the cancel button. Defaults to "Cancel".
    #[prop(optional)]
    cancel_label: Option<String>,
) -> impl IntoView {
    let cancel_text = cancel_label.unwrap_or_else(|| "Cancel".to_string());
    let confirm_cls = variant.confirm_class();
    let icon_path = variant.icon_path();
    let icon_color = variant.icon_color();

    view! {
        <Modal is_open=is_open title=title.clone() max_width="420px".to_string()>
            <div class="space-y-4">
                // Icon + message
                <div class="flex gap-3">
                    <div class=format!("flex-shrink-0 {}", icon_color)>
                        <svg class="w-6 h-6" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d=icon_path stroke-linecap="round" stroke-linejoin="round"/>
                        </svg>
                    </div>
                    <p class="text-sm text-gray-300 leading-relaxed">{message}</p>
                </div>

                // Action buttons
                <div class="confirm-actions pt-2">
                    <button
                        class="text-gray-400 hover:text-white px-4 py-2 rounded-lg transition-colors text-sm border border-gray-700 hover:border-gray-600 hover:bg-gray-800"
                        on:click=move |_| is_open.set(false)
                    >
                        {cancel_text.clone()}
                    </button>
                    <button
                        class=confirm_cls
                        on:click=move |_| {
                            on_confirm.run(());
                            is_open.set(false);
                        }
                    >
                        {confirm_label.clone()}
                    </button>
                </div>
            </div>
        </Modal>
    }
}
