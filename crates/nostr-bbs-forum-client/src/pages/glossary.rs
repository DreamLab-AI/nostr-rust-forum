//! Glossary — plain-English explanations of the technical terms surfaced in
//! the UI (issue #19).
//!
//! Route: `/glossary` (public — info pages are not auth-gated).
//!
//! The onboarding and DM surfaces lead with benefits and keep jargon out of the
//! primary reading path, but a few protocol terms still appear in the
//! *good-to-know* corners (e.g. "NIP-44 Encrypted", "relay", "npub"). Those are
//! wrapped in [`crate::components::info_term::InfoTerm`], whose hover bubble now
//! carries a "Learn more →" link pointing at the matching anchor on this page.
//!
//! Each entry is an `<h2 id="…">` so `InfoTerm`'s `slug` prop can deep-link to
//! it (e.g. `/glossary#nip44`). The slugs used by call sites must stay in sync
//! with the `id`s defined here — they are listed in [`SLUGS`] for reference.
//!
//! Brand-neutral by construction: this page references only generic protocol
//! concepts and the in-app feature names, never a deploy-specific brand.

use leptos::prelude::*;
use leptos_router::components::A;

use crate::app::base_href;

/// Anchor slugs defined on this page. `InfoTerm` call sites link to
/// `/glossary#<slug>`; keep these in sync with the `id=` attributes below.
pub(crate) const SLUGS: &[&str] = &[
    "encryption",
    "nip44",
    "relay",
    "nip98",
    "giftwrap",
    "pod",
    "keys",
    "npub",
    "nsec",
    "zones",
];

/// A single glossary entry: an anchored heading plus a plain-English body.
#[component]
fn Entry(
    /// The anchor id (used by `InfoTerm` deep-links, e.g. `nip44`).
    id: &'static str,
    /// The human-readable heading shown above the explanation.
    title: &'static str,
    /// The explanation body (already-rendered view).
    children: Children,
) -> impl IntoView {
    view! {
        <section id=id class="glass-card p-6 space-y-3 scroll-mt-24">
            <h2 class="text-lg font-semibold text-white">{title}</h2>
            <div class="border-t border-gray-700/50"></div>
            <div class="text-sm text-gray-300 leading-relaxed space-y-2">
                {children()}
            </div>
        </section>
    }
}

/// Plain-English glossary of the technical terms used across the forum.
#[component]
pub fn GlossaryPage() -> impl IntoView {
    view! {
        <div class="max-w-2xl mx-auto p-4 sm:p-6">
            // Breadcrumb
            <div class="flex items-center gap-2 text-sm text-gray-500 mb-6">
                <A href=base_href("/") attr:class="hover:text-amber-400 transition-colors">"Home"</A>
                <span class="breadcrumb-separator">{"\u{203A}"}</span>
                <span class="text-gray-300">"Glossary"</span>
            </div>

            <h1 class="text-3xl font-bold bg-gradient-to-r from-amber-400 to-orange-500 bg-clip-text text-transparent mb-3">
                "Glossary"
            </h1>
            <p class="text-sm text-gray-400 mb-8 max-w-prose">
                "Plain-English explanations of the technical words you might see around the \
                 forum. None of this is required reading — everything works without it — but \
                 if a term ever made you pause, here's what it means."
            </p>

            <div class="space-y-6">
                <Entry id="encryption" title="End-to-end encryption">
                    <p>
                        "When something is "
                        <em>"end-to-end encrypted"</em>
                        ", it is scrambled on your device and only unscrambled on the other \
                         person's device. The server that carries the message — and anyone who \
                         might be watching it — only ever sees gibberish."
                    </p>
                    <p class="text-gray-400">
                        "Your private messages on this forum are end-to-end encrypted, so no one \
                         in the middle can read them."
                    </p>
                </Entry>

                <Entry id="nip44" title="\"NIP-44 Encrypted\"">
                    <p>
                        "\"NIP-44\" is simply the name of the modern encryption recipe this forum \
                         uses to scramble private messages. \"NIP\" stands for "
                        <em>"Nostr Implementation Possibility"</em>
                        " — a numbered standard that apps agree to follow so they all encrypt \
                         and decrypt the same way."
                    </p>
                    <p class="text-gray-400">
                        "In short: \"NIP-44 encrypted\" means your message is locked with a \
                         strong, well-reviewed method that only you and the recipient can open. \
                         See "
                        <a href="#encryption" class="text-amber-400 hover:text-amber-300 underline">
                            "end-to-end encryption"
                        </a>
                        "."
                    </p>
                </Entry>

                <Entry id="relay" title="Relay (the server address)">
                    <p>
                        "A "
                        <em>"relay"</em>
                        " is the server that stores this community's messages and passes them \
                         between everyone taking part. Think of it as the post office for the \
                         forum: you don't talk to it directly, but it's what carries posts and \
                         messages from one person to another."
                    </p>
                    <p class="text-gray-400">
                        "You never need the relay address to use the website. It only matters if \
                         you want to point a separate "
                        <a href="#giftwrap" class="text-amber-400 hover:text-amber-300 underline">
                            "messaging app"
                        </a>
                        " at this community."
                    </p>
                </Entry>

                <Entry id="nip98" title="\"NIP-98\" (proving it's really you)">
                    <p>
                        "\"NIP-98\" is the standard that lets the forum's helper services confirm a \
                         request genuinely came from you, without you typing a password. Your app \
                         signs the request with your secret key, and the service checks the \
                         signature."
                    </p>
                    <p class="text-gray-400">
                        "You won't normally see this happen — it works quietly in the background \
                         whenever the app needs to prove your identity to a service."
                    </p>
                </Entry>

                <Entry id="giftwrap" title="Gift wrap & private messages">
                    <p>
                        "When you send a direct message, the forum doesn't just encrypt the words \
                         — it also "
                        <em>"gift wraps"</em>
                        " the whole message so that even the fact that you two are talking, and \
                         when, is hidden from onlookers. Only the recipient can unwrap it."
                    </p>
                    <p class="text-gray-400">
                        "A "
                        <em>"messaging app"</em>
                        " here means any optional third-party app that can show this forum's \
                         messages. Most people never need one — the website does everything."
                    </p>
                </Entry>

                <Entry id="pod" title="Pod / personal space (Solid)">
                    <p>
                        "A "
                        <em>"pod"</em>
                        " is your own personal storage space on the web — a private place that \
                         belongs to you, where things like your profile and files can live. It's \
                         based on an open standard called "
                        <em>"Solid"</em>
                        ", designed so that you stay in control of your own data."
                    </p>
                    <p class="text-gray-400">
                        "Your "
                        <em>"space address"</em>
                        " (sometimes called a WebID) is just the web link to that space — a \
                         portable online profile and storage that's yours to keep."
                    </p>
                </Entry>

                <Entry id="keys" title="Your keys (npub & nsec)">
                    <p>
                        "Your account isn't protected by a username and password — it's protected \
                         by a pair of "
                        <em>"keys"</em>
                        ". One is public and safe to share; the other is secret and must be kept \
                         private."
                    </p>
                </Entry>

                <Entry id="npub" title="npub (your public ID)">
                    <p>
                        "Your "
                        <em>"npub"</em>
                        " is your public username code — it always starts with the letters "
                        <code class="text-amber-300">"npub"</code>
                        ". It's completely safe to share: it's how other people find and follow \
                         you, and it can't be used to sign in as you."
                    </p>
                </Entry>

                <Entry id="nsec" title="nsec (your secret recovery key)">
                    <p>
                        "Your "
                        <em>"nsec"</em>
                        " is your account's secret key — it starts with the letters "
                        <code class="text-amber-300">"nsec"</code>
                        ". It is effectively the master password for your account: anyone who has \
                         it has full control of your account."
                    </p>
                    <p class="text-red-400">
                        "Never share your nsec with anyone, and store it somewhere safe — it's how \
                         you recover your account if you lose access."
                    </p>
                </Entry>

                <Entry id="zones" title="Zones & cohorts">
                    <p>
                        "The forum is divided into "
                        <em>"zones"</em>
                        " — separate areas with different audiences (for example a public area and \
                         more private ones). Which zones you can see depends on the access you've \
                         been granted."
                    </p>
                    <p class="text-gray-400">
                        "A "
                        <em>"cohort"</em>
                        " is a named group of people — such as everyone on a particular programme \
                         — that an area or event can be shared with."
                    </p>
                </Entry>
            </div>

            <div class="mt-10 text-center">
                <A
                    href=base_href("/")
                    attr:class="text-amber-400 hover:text-amber-300 underline text-sm"
                >
                    "← Back to home"
                </A>
            </div>
        </div>
    }
}
