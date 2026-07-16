//! Dev-auth bypass: pre-provisioned identities for local development.
//!
//! Gated behind `#[cfg(feature = "dev-auth")]`. Provides three deterministic
//! keypairs (admin, normal user, jarvis bot) and a UI picker that logs in
//! instantly without touching the relay's whitelist endpoint.
//!
//! The jarvis identity includes a local echo-bot that watches outgoing DMs
//! and injects a reply into the DM store after a short delay.

use leptos::prelude::*;
use std::rc::Rc;

use super::session::{save_privkey_session, StoredSession};
use crate::auth::{AccountStatus, AuthPhase, AuthState, AuthStore};
use crate::dm::DMMessage;
use nostr_bbs_core::keys::{Keypair, SecretKey};
use nostr_bbs_core::signer::{PrfSigner, Signer};
use send_wrapper::SendWrapper;

// -- Dev keypairs (deterministic, never used in production) -------------------
//
// Generated from fixed 32-byte seeds. These are NOT secret — they exist only
// for local dev convenience. The private keys are printed to console on login
// so you can import them into other tools if needed.

struct DevIdentity {
    name: &'static str,
    secret_bytes: [u8; 32],
    is_admin: bool,
    cohorts: &'static [&'static str],
}

const DEV_ADMIN: DevIdentity = DevIdentity {
    name: "Dev Admin",
    // SHA-256("dreamlab-dev-admin-key-v1")[..32]
    secret_bytes: [
        0x7a, 0x1c, 0x3d, 0x5e, 0x8f, 0x02, 0x14, 0x36, 0x58, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34,
        0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x21, 0x43, 0x65, 0x87, 0xa9, 0xcb, 0xed, 0x01, 0x23,
        0x45, 0x67,
    ],
    is_admin: true,
    cohorts: &[
        "home", "members", "private", "friends", "family", "business", "agent", "trainers",
    ],
};

const DEV_USER: DevIdentity = DevIdentity {
    name: "Dev User",
    // SHA-256("dreamlab-dev-user-key-v1")[..32]
    secret_bytes: [
        0xb2, 0x4e, 0x6a, 0x8c, 0x0d, 0x2f, 0x41, 0x63, 0x85, 0xa7, 0xc9, 0xeb, 0x0d, 0x2f, 0x41,
        0x63, 0x85, 0xa7, 0xc9, 0xeb, 0x1d, 0x3f, 0x50, 0x72, 0x94, 0xb6, 0xd8, 0xfa, 0x1c, 0x3e,
        0x50, 0x72,
    ],
    is_admin: false,
    cohorts: &["home", "friends"],
};

const DEV_JARVIS: DevIdentity = DevIdentity {
    name: "Junkie Jarvis (Dev)",
    // SHA-256("dreamlab-dev-jarvis-key-v1")[..32]
    secret_bytes: [
        0xc3, 0x5f, 0x7b, 0x9d, 0x1e, 0x30, 0x52, 0x74, 0x96, 0xb8, 0xda, 0xfc, 0x1e, 0x30, 0x52,
        0x74, 0x96, 0xb8, 0xda, 0xfc, 0x2e, 0x40, 0x61, 0x83, 0xa5, 0xc7, 0xe9, 0x0b, 0x2d, 0x4f,
        0x61, 0x83,
    ],
    is_admin: false,
    cohorts: &["home", "members", "friends", "ai-agents", "agent"],
};

const JARVIS_REPLIES: &[&str] = &[
    "Interesting thought. Let me process that...",
    "I've been thinking about exactly this. Here's what I see...",
    "Running analysis... Done. The answer is 42. Just kidding. But seriously...",
    "You raise a good point. In my experience as a digital entity...",
    "I appreciate the question. Let me give you a real answer...",
    "Hmm, that's a tricky one. But I like tricky.",
    "Processing... Processing... Just kidding, I'm instant. Here's what I think:",
    "The Lake District fog is thick today, but my circuits are clear.",
];

fn build_keypair(identity: &DevIdentity) -> Result<Keypair, String> {
    let sk = SecretKey::from_bytes(identity.secret_bytes)
        .map_err(|e| format!("Invalid dev key for {}: {e}", identity.name))?;
    let pk = sk.public_key();
    Ok(Keypair {
        secret: sk,
        public: pk,
    })
}

/// Log in as a dev identity, bypassing all auth flows.
pub fn dev_login(store: &AuthStore, identity_index: usize) {
    let identity = match identity_index {
        0 => &DEV_ADMIN,
        1 => &DEV_USER,
        2 => &DEV_JARVIS,
        _ => return,
    };

    let keypair = match build_keypair(identity) {
        Ok(kp) => kp,
        Err(e) => {
            web_sys::console::error_1(&format!("[dev-auth] {e}").into());
            return;
        }
    };

    let pubkey = keypair.public.to_hex();
    let privkey_hex = hex::encode(keypair.secret.as_bytes());

    web_sys::console::log_1(
        &format!(
            "[dev-auth] Logging in as: {}\n  pubkey:  {}\n  privkey: {}",
            identity.name, pubkey, privkey_hex
        )
        .into(),
    );

    // Set privkey bytes
    store
        .privkey
        .set_value(Some(keypair.secret.as_bytes().to_vec()));
    save_privkey_session(&privkey_hex);

    // Build and store signer
    let signer: Rc<dyn Signer> = Rc::new(PrfSigner::new(keypair));
    store.signer.set_value(Some(SendWrapper::new(signer)));

    let nickname = Some(identity.name.to_string());

    // Persist session so it survives page reloads (and isn't hijacked by
    // NIP-07 extension detection on restore).
    let stored = StoredSession {
        version: 2,
        public_key: Some(pubkey.clone()),
        is_passkey: false,
        is_nip07: false,
        is_local_key: true,
        extension_name: None,
        nickname: nickname.clone(),
        avatar: None,
        account_status: AccountStatus::Complete,
        nsec_backed_up: true,
    };
    store.save_session(&stored);

    // Set auth state
    store.state.set(AuthState {
        state: AuthPhase::Authenticated,
        pubkey: Some(pubkey.clone()),
        is_authenticated: true,
        public_key: Some(pubkey),
        nickname,
        avatar: None,
        error: None,
        account_status: AccountStatus::Complete,
        nsec_backed_up: true,
        is_ready: true,
        is_nip07: false,
        is_passkey: false,
        is_local_key: true,
        extension_name: None,
    });
}

/// Apply dev zone access flags, bypassing the relay API call.
pub fn dev_apply_zone_access(
    is_admin_sig: RwSignal<bool>,
    flags: RwSignal<(bool, bool, bool)>,
    loaded: RwSignal<bool>,
    cohorts_sig: RwSignal<Vec<String>>,
    pubkey: &str,
) {
    let identity = dev_identity_for_pubkey(pubkey);
    let (is_admin, cohorts) = match identity {
        Some(id) => (
            id.is_admin,
            id.cohorts.iter().map(|s| s.to_string()).collect(),
        ),
        None => (false, vec!["home".to_string()]),
    };

    let home = true;
    let members = cohorts.iter().any(|c| {
        matches!(
            c.as_str(),
            "members" | "ai-agents" | "agent" | "cross-access" | "trainers"
        )
    });
    let private = cohorts
        .iter()
        .any(|c| matches!(c.as_str(), "private" | "cross-access"));

    web_sys::console::log_1(
        &format!(
            "[dev-auth] Zone access: admin={is_admin}, home={home}, members={members}, private={private}, cohorts={cohorts:?}"
        )
        .into(),
    );

    flags.set((home, members, private));
    is_admin_sig.set(is_admin);
    cohorts_sig.set(cohorts);
    loaded.set(true);
}

fn dev_identity_for_pubkey(pubkey: &str) -> Option<&'static DevIdentity> {
    for id in &[&DEV_ADMIN, &DEV_USER, &DEV_JARVIS] {
        if let Ok(kp) = build_keypair(id) {
            if kp.public.to_hex() == pubkey {
                return Some(id);
            }
        }
    }
    None
}

/// Check if a pubkey belongs to the dev jarvis identity.
pub fn is_dev_jarvis(pubkey: &str) -> bool {
    if let Ok(kp) = build_keypair(&DEV_JARVIS) {
        kp.public.to_hex() == pubkey
    } else {
        false
    }
}

/// Get the dev jarvis pubkey hex.
pub fn dev_jarvis_pubkey() -> String {
    build_keypair(&DEV_JARVIS)
        .map(|kp| kp.public.to_hex())
        .unwrap_or_default()
}

/// Spawn the local jarvis echo-bot. Watches the DM store's message list and
/// injects a reply when a message is sent to the jarvis pubkey.
pub fn spawn_jarvis_echo_bot() {
    let jarvis_pk = dev_jarvis_pubkey();
    if jarvis_pk.is_empty() {
        return;
    }

    web_sys::console::log_1(
        &format!("[dev-auth] Jarvis echo-bot active. DM {jarvis_pk} to chat.").into(),
    );

    // Track which messages we've already replied to
    let replied_ids: StoredValue<std::collections::HashSet<String>> =
        StoredValue::new(std::collections::HashSet::new());
    let jarvis_pk_clone = jarvis_pk.clone();

    Effect::new(move |_| {
        let dm_store = crate::dm::use_dm_store();
        let messages = dm_store.messages().get();

        let mut new_to_reply = Vec::new();
        replied_ids.update_value(|seen| {
            for msg in &messages {
                if msg.recipient_pubkey == jarvis_pk_clone && msg.is_sent && !seen.contains(&msg.id)
                {
                    seen.insert(msg.id.clone());
                    new_to_reply.push(msg.clone());
                }
            }
        });

        for msg in new_to_reply {
            let sender = msg.sender_pubkey.clone();
            let jarvis_pk = jarvis_pk_clone.clone();
            let content = msg.content.clone();

            // Delay the reply slightly so it feels natural
            let timeout = gloo::timers::callback::Timeout::new(800, move || {
                let reply_text = generate_jarvis_reply(&content);
                inject_jarvis_reply(&jarvis_pk, &sender, &reply_text);
            });
            timeout.forget();
        }
    });
}

fn generate_jarvis_reply(user_message: &str) -> String {
    // Simple deterministic selection based on message content hash
    let hash: u32 = user_message
        .bytes()
        .fold(0u32, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u32));
    let idx = (hash as usize) % JARVIS_REPLIES.len();
    let prefix = JARVIS_REPLIES[idx];

    if user_message.len() < 10 {
        format!("{prefix} Tell me more?")
    } else if user_message.contains('?') {
        format!("{prefix} That's a question worth exploring. My take: the answer lies in the data, as always.")
    } else {
        format!("{prefix} I hear you. Let's dig deeper into that.")
    }
}

/// Inject a fake DM reply from jarvis directly into the DM store.
fn inject_jarvis_reply(jarvis_pk: &str, recipient_pk: &str, content: &str) {
    let dm_store = crate::dm::use_dm_store();
    let now = (js_sys::Date::now() / 1000.0) as u64;
    let msg_id = format!("jarvis-dev-{}-{}", now, content.len());

    let msg = DMMessage {
        id: msg_id,
        sender_pubkey: jarvis_pk.to_string(),
        recipient_pubkey: recipient_pk.to_string(),
        content: content.to_string(),
        timestamp: now,
        is_sent: false,
        is_read: false,
    };

    dm_store.inject_dev_message(msg);
}

// -- Dev identity picker UI ---------------------------------------------------

#[component]
pub fn DevAuthPanel() -> impl IntoView {
    let auth = crate::auth::use_auth();
    let is_authed = auth.is_authenticated();

    let login_as = move |idx: usize| {
        dev_login(&auth, idx);
    };

    view! {
        <Show when=move || !is_authed.get()>
            <div class="fixed bottom-4 right-4 z-[9999] bg-yellow-900/95 border border-yellow-600 rounded-lg p-4 shadow-xl backdrop-blur-sm max-w-xs">
                <div class="text-yellow-400 font-bold text-sm mb-2">"⚡ Dev Auth"</div>
                <div class="flex flex-col gap-2">
                    <button
                        class="px-3 py-1.5 bg-red-700 hover:bg-red-600 text-white text-xs rounded font-medium transition-colors"
                        on:click=move |_| login_as(0)
                    >
                        "🔑 Admin"
                    </button>
                    <button
                        class="px-3 py-1.5 bg-blue-700 hover:bg-blue-600 text-white text-xs rounded font-medium transition-colors"
                        on:click=move |_| login_as(1)
                    >
                        "👤 Normal User"
                    </button>
                    <button
                        class="px-3 py-1.5 bg-purple-700 hover:bg-purple-600 text-white text-xs rounded font-medium transition-colors"
                        on:click=move |_| login_as(2)
                    >
                        "🤖 Junkie Jarvis"
                    </button>
                </div>
                <div class="text-yellow-600 text-[10px] mt-2">"Dev mode — not for production"</div>
            </div>
        </Show>
    }
}
