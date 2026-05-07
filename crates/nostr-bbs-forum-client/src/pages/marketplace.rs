//! NIP-90 DVM Marketplace page.
//!
//! Displays available Data Vending Machines (DVMs) discovered via kind-31990
//! handler information events. Users can browse available AI/automation services
//! and submit job requests.
//!
//! This is the Wave 3 skeleton implementation. Full interactive functionality
//! (job submission, result display, payment flow) will be added in subsequent
//! sprints.

use leptos::prelude::*;

// ── Placeholder DVM data type ─────────────────────────────────────────────────

/// Display data for a single DVM in the marketplace listing.
#[derive(Debug, Clone, PartialEq)]
pub struct DvmListing {
    /// DVM's pubkey (64-char hex).
    pub pubkey: String,
    /// Human-readable name.
    pub name: String,
    /// Description of what this DVM does.
    pub about: String,
    /// Job kinds supported (5000-5999).
    pub supported_kinds: Vec<u64>,
    /// Price in millisatoshis (0 = free).
    pub price_msats: u64,
    /// Whether the DVM supports NIP-44 encrypted requests.
    pub encryption_supported: bool,
}

impl DvmListing {
    /// Return a human-readable label for a job kind.
    pub fn kind_label(kind: u64) -> &'static str {
        match kind {
            5000 => "Text Generation",
            5001 => "Text Summarization",
            5002 => "Translation",
            5003 => "Text Classification",
            5004 => "NLP Processing",
            5005 => "Content Discovery",
            5006 => "Content Ranking",
            5007 => "Language Detection",
            5050 => "Image Generation",
            5100 => "Video Transcription",
            5200 => "Code Generation",
            5300 => "Event Analysis",
            5400 => "Web Retrieval",
            5600 => "Content Moderation",
            5900 => "Search Query",
            _ => "Custom Job",
        }
    }

    pub fn price_display(&self) -> String {
        if self.price_msats == 0 {
            "Free".to_string()
        } else if self.price_msats < 1000 {
            format!("{} msat", self.price_msats)
        } else {
            format!("{} sat", self.price_msats / 1000)
        }
    }
}

// ── Marketplace page component ────────────────────────────────────────────────

/// The NIP-90 DVM Marketplace page.
///
/// Shows a grid of available DVMs fetched from the relay via kind-31990 events.
/// Currently renders a static skeleton with placeholder data pending relay
/// integration in the next sprint.
#[component]
pub fn MarketplacePage() -> impl IntoView {
    // Placeholder DVM listings until relay subscription is wired up.
    let listings = vec![
        DvmListing {
            pubkey: "00".repeat(32),
            name: "Text Summarizer".into(),
            about: "Summarizes long-form content into concise bullet points.".into(),
            supported_kinds: vec![5001],
            price_msats: 0,
            encryption_supported: true,
        },
        DvmListing {
            pubkey: "11".repeat(32),
            name: "Code Assistant".into(),
            about: "Generates and reviews Rust/TypeScript/Python code on demand.".into(),
            supported_kinds: vec![5200],
            price_msats: 1000,
            encryption_supported: true,
        },
    ];

    view! {
        <div class="marketplace-page">
            <div class="marketplace-header">
                <h1>"DVM Marketplace"</h1>
                <p class="marketplace-subtitle">
                    "Browse and interact with Data Vending Machines powered by NIP-90."
                </p>
            </div>

            <div class="marketplace-grid">
                {listings.into_iter().map(|dvm| view! {
                    <DvmCard dvm=dvm />
                }).collect_view()}
            </div>
        </div>
    }
}

// ── DVM card component ────────────────────────────────────────────────────────

/// A single DVM listing card in the marketplace grid.
#[component]
fn DvmCard(dvm: DvmListing) -> impl IntoView {
    let price = dvm.price_display();
    let encryption_badge = dvm.encryption_supported;
    let name = dvm.name.clone();
    let about = dvm.about.clone();
    let kinds: Vec<String> = dvm
        .supported_kinds
        .iter()
        .map(|k| DvmListing::kind_label(*k).to_string())
        .collect();

    view! {
        <div class="dvm-card">
            <div class="dvm-card-header">
                <h3 class="dvm-name">{name}</h3>
                <span class="dvm-price">{price}</span>
            </div>
            <p class="dvm-about">{about}</p>
            <div class="dvm-capabilities">
                {kinds.into_iter().map(|kind| view! {
                    <span class="dvm-kind-badge">{kind}</span>
                }).collect_view()}
                {encryption_badge.then(|| view! {
                    <span class="dvm-encrypt-badge">"NIP-44"</span>
                })}
            </div>
            <div class="dvm-card-actions">
                <button class="btn-primary" disabled=true>
                    "Submit Job (coming soon)"
                </button>
            </div>
        </div>
    }
}
