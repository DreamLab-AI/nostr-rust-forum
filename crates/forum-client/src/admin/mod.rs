//! Admin state management and API interactions for whitelist/channel management.
//!
//! Provides `AdminStore` with reactive signals for admin panel state, plus
//! methods for calling the relay-worker admin endpoints with NIP-98 auth and
//! creating kind-40 channel events.

pub mod audit_log;
pub mod calendar;
pub mod channel_form;
pub mod overview;
pub mod registrations;
pub mod relay_settings;
pub mod reports;
pub mod section_requests;
pub mod settings;
pub mod stats;
pub mod user_table;

use leptos::prelude::*;
use serde::{Deserialize, Serialize};
use std::rc::Rc;

use crate::auth::nip98::{fetch_with_nip98_get, fetch_with_nip98_post};
use crate::relay::{ConnectionState, Filter, RelayConnection};
use crate::stores::zone_access::use_zone_access;

// -- Types --------------------------------------------------------------------

/// Tabs in the admin panel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdminTab {
    Overview,
    Channels,
    Users,
    Sections,
    Calendar,
    Settings,
    Reports,
    AuditLog,
}

/// A whitelisted user returned from the relay API.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WhitelistUser {
    pub pubkey: String,
    #[serde(default)]
    pub cohorts: Vec<String>,
    #[serde(default, alias = "displayName")]
    pub display_name: Option<String>,
    #[serde(default, alias = "addedAt")]
    pub added_at: Option<u64>,
    #[serde(default, alias = "isAdmin")]
    pub is_admin: bool,
}

/// A channel parsed from a kind-40 event on the relay.
#[derive(Clone, Debug)]
pub struct AdminChannel {
    pub id: String,
    pub name: String,
    pub description: String,
    pub section: String,
    #[allow(dead_code)]
    pub created_at: u64,
    #[allow(dead_code)]
    pub creator: String,
}

/// Aggregate statistics for the admin overview.
#[derive(Clone, Debug, Default)]
pub struct AdminStats {
    pub total_users: u32,
    pub total_channels: u32,
    pub total_messages: u32,
    pub pending_approvals: u32,
}

/// Reactive admin state held in signals.
#[derive(Clone)]
pub struct AdminState {
    pub users: RwSignal<Vec<WhitelistUser>>,
    pub channels: RwSignal<Vec<AdminChannel>>,
    pub stats: RwSignal<AdminStats>,
    pub is_loading: RwSignal<bool>,
    pub error: RwSignal<Option<String>>,
    pub success: RwSignal<Option<String>>,
    pub active_tab: RwSignal<AdminTab>,
}

// -- AdminStore ---------------------------------------------------------------

/// Admin store provided via Leptos context. Holds reactive state and provides
/// methods for admin API calls (whitelist management, channel creation).
#[derive(Clone)]
pub struct AdminStore {
    pub state: AdminState,
}

impl AdminStore {
    /// Create a new admin store with default empty state.
    fn new() -> Self {
        Self {
            state: AdminState {
                users: RwSignal::new(Vec::new()),
                channels: RwSignal::new(Vec::new()),
                stats: RwSignal::new(AdminStats::default()),
                is_loading: RwSignal::new(false),
                error: RwSignal::new(None),
                success: RwSignal::new(None),
                active_tab: RwSignal::new(AdminTab::Overview),
            },
        }
    }

    /// Check whether the current user is admin using the zone_access context.
    #[allow(dead_code)]
    pub fn is_current_user_admin() -> bool {
        use_zone_access().is_admin.get_untracked()
    }

    /// Resolve the API base URL for whitelist/admin operations.
    ///
    /// Whitelist endpoints (`/api/whitelist/*`, `/api/check-whitelist`) live on the
    /// **relay worker**, not the auth worker. Delegates to the centralized
    /// `relay_url::relay_api_base()`.
    fn api_base() -> String {
        crate::utils::relay_url::relay_api_base()
    }

    // -- Whitelist API --------------------------------------------------------

    /// Fetch the full whitelist from the relay-worker admin API.
    pub async fn fetch_whitelist(&self, privkey: &[u8; 32]) -> Result<(), String> {
        self.state.is_loading.set(true);
        self.state.error.set(None);

        let url = format!("{}/api/whitelist/list", Self::api_base());
        match fetch_with_nip98_get(&url, privkey).await {
            Ok(body) => {
                let parsed: WhitelistResponse = serde_json::from_str(&body)
                    .map_err(|e| format!("Failed to parse whitelist: {e}"))?;
                if parsed.users.is_empty() {
                    self.state.error.set(Some(
                        "Whitelist is empty. No users have been approved yet.".to_string(),
                    ));
                }
                self.state.users.set(parsed.users);
                self.state.stats.update(|s| {
                    s.total_users = self.state.users.get_untracked().len() as u32;
                });
                self.state.is_loading.set(false);
                Ok(())
            }
            Err(e) => {
                let msg = e.to_string();
                let user_msg = if msg.contains("401") || msg.contains("403") || msg.contains("Unauthorized") {
                    format!("Auth failure: your admin key was rejected by the API. {}", msg)
                } else if msg.contains("404") {
                    format!("Whitelist endpoint not found. Check API URL configuration. {}", msg)
                } else if msg.contains("NetworkError") || msg.contains("Failed to fetch") {
                    format!("Network error: cannot reach the auth API. Check your connection. {}", msg)
                } else {
                    format!("Failed to fetch whitelist: {}", msg)
                };
                self.state.error.set(Some(user_msg.clone()));
                self.state.is_loading.set(false);
                Err(user_msg)
            }
        }
    }

    /// Add a pubkey to the whitelist with the given cohorts.
    pub async fn add_to_whitelist(
        &self,
        pubkey: &str,
        cohorts: &[String],
        privkey: &[u8; 32],
    ) -> Result<(), String> {
        self.state.is_loading.set(true);
        self.state.error.set(None);
        self.state.success.set(None);

        let body = serde_json::json!({
            "pubkey": pubkey,
            "cohorts": cohorts,
        });
        let body_json = serde_json::to_string(&body)
            .map_err(|e| format!("JSON serialization failed: {e}"))?;
        let url = format!("{}/api/whitelist/add", Self::api_base());
        match fetch_with_nip98_post(&url, &body_json, privkey).await {
            Ok(_) => {
                self.state.success.set(Some(format!(
                    "Added {}...{} to whitelist",
                    &pubkey[..8],
                    &pubkey[pubkey.len().saturating_sub(4)..]
                )));
                self.state.is_loading.set(false);
                // Refresh the whitelist
                let _ = self.fetch_whitelist(privkey).await;
                Ok(())
            }
            Err(e) => {
                let msg = e.to_string();
                self.state.error.set(Some(msg.clone()));
                self.state.is_loading.set(false);
                Err(msg)
            }
        }
    }

    /// Update cohorts for an existing whitelisted pubkey.
    pub async fn update_cohorts(
        &self,
        pubkey: &str,
        cohorts: &[String],
        privkey: &[u8; 32],
    ) -> Result<(), String> {
        self.state.is_loading.set(true);
        self.state.error.set(None);
        self.state.success.set(None);

        let body = serde_json::json!({
            "pubkey": pubkey,
            "cohorts": cohorts,
        });
        let body_json = serde_json::to_string(&body)
            .map_err(|e| format!("JSON serialization failed: {e}"))?;
        let url = format!("{}/api/whitelist/update-cohorts", Self::api_base());
        match fetch_with_nip98_post(&url, &body_json, privkey).await {
            Ok(_) => {
                self.state.success.set(Some(format!(
                    "Updated cohorts for {}...{}",
                    &pubkey[..8],
                    &pubkey[pubkey.len().saturating_sub(4)..]
                )));
                self.state.is_loading.set(false);
                // Refresh the whitelist
                let _ = self.fetch_whitelist(privkey).await;
                Ok(())
            }
            Err(e) => {
                let msg = e.to_string();
                self.state.error.set(Some(msg.clone()));
                self.state.is_loading.set(false);
                Err(msg)
            }
        }
    }

    // -- Admin management -----------------------------------------------------

    /// Set or revoke admin status for a pubkey via the relay API.
    pub async fn set_admin(
        &self,
        pubkey: &str,
        is_admin: bool,
        privkey: &[u8; 32],
    ) -> Result<(), String> {
        self.state.is_loading.set(true);
        self.state.error.set(None);
        self.state.success.set(None);

        let body = serde_json::json!({
            "pubkey": pubkey,
            "is_admin": is_admin,
        });
        let body_json = serde_json::to_string(&body)
            .map_err(|e| format!("JSON serialization failed: {e}"))?;
        let url = format!("{}/api/whitelist/set-admin", Self::api_base());
        match fetch_with_nip98_post(&url, &body_json, privkey).await {
            Ok(_) => {
                let action = if is_admin { "promoted to admin" } else { "demoted from admin" };
                self.state.success.set(Some(format!(
                    "{}...{} {}",
                    &pubkey[..8],
                    &pubkey[pubkey.len().saturating_sub(4)..],
                    action
                )));
                self.state.is_loading.set(false);
                let _ = self.fetch_whitelist(privkey).await;
                Ok(())
            }
            Err(e) => {
                let msg = e.to_string();
                self.state.error.set(Some(msg.clone()));
                self.state.is_loading.set(false);
                Err(msg)
            }
        }
    }

    // -- Channel management ---------------------------------------------------

    /// Create a kind-40 channel creation event and publish it to the relay.
    #[allow(dead_code)]
    pub fn create_channel(
        &self,
        name: &str,
        description: &str,
        section: &str,
        privkey: &[u8; 32],
    ) -> Result<(), String> {
        self.create_channel_with_zone(name, description, section, "", 0, None, privkey)
    }

    /// Create a kind-40 channel with explicit zone and optional cohort tags.
    pub fn create_channel_with_zone(
        &self,
        name: &str,
        description: &str,
        section: &str,
        picture: &str,
        zone: u8,
        cohort: Option<&str>,
        privkey: &[u8; 32],
    ) -> Result<(), String> {
        let relay = expect_context::<RelayConnection>();
        let conn = relay.connection_state();
        if conn.get_untracked() != ConnectionState::Connected {
            return Err("Relay not connected".to_string());
        }

        let sk = k256::schnorr::SigningKey::from_bytes(privkey)
            .map_err(|e| format!("Invalid signing key: {e}"))?;
        let pubkey_hex = hex::encode(sk.verifying_key().to_bytes());

        let content = serde_json::json!({
            "name": name,
            "about": description,
            "picture": picture
        });

        let now = (js_sys::Date::now() / 1000.0) as u64;

        let mut tags = vec![
            vec!["section".into(), section.into()],
            vec!["zone".into(), zone.to_string()],
        ];
        if let Some(c) = cohort {
            tags.push(vec!["cohort".into(), c.into()]);
        }

        let content_json = serde_json::to_string(&content)
            .map_err(|e| format!("JSON serialization failed: {e}"))?;
        let unsigned = nostr_core::UnsignedEvent {
            pubkey: pubkey_hex,
            created_at: now,
            kind: 40,
            tags,
            content: content_json,
        };

        let signed =
            nostr_core::sign_event(unsigned, &sk).map_err(|e| format!("Signing failed: {e}"))?;

        // Publish with ack — only update local state on relay acceptance
        let success_sig = self.state.success;
        let error_sig = self.state.error;
        let channels_sig = self.state.channels;
        let stats_sig = self.state.stats;
        let channel_name = name.to_string();
        let channel_desc = description.to_string();
        let channel_section = section.to_string();
        let event_id = signed.id.clone();
        let event_created_at = signed.created_at;
        let event_pubkey = signed.pubkey.clone();

        let ack = Rc::new(move |accepted: bool, message: String| {
            if accepted {
                success_sig.set(Some(format!("Channel '{}' created", channel_name)));
                channels_sig.update(|list| {
                    if !list.iter().any(|c| c.id == event_id) {
                        list.push(AdminChannel {
                            id: event_id.clone(),
                            name: channel_name.clone(),
                            description: channel_desc.clone(),
                            section: channel_section.clone(),
                            created_at: event_created_at,
                            creator: event_pubkey.clone(),
                        });
                    }
                });
                stats_sig.update(|s| {
                    s.total_channels = channels_sig.get_untracked().len() as u32;
                });
            } else {
                error_sig.set(Some(format!("Relay rejected: {}", message)));
            }
        });
        let _ = relay.publish_with_ack(&signed, Some(ack));

        Ok(())
    }

    /// Fetch stats by subscribing to the relay for kind 40 (channels) and kind 42
    /// (messages). Updates the stats signal reactively.
    pub fn fetch_stats(&self) {
        let relay = expect_context::<RelayConnection>();
        let conn = relay.connection_state();
        if conn.get_untracked() != ConnectionState::Connected {
            return;
        }

        let channels_sig = self.state.channels;
        let stats_sig = self.state.stats;
        let loading_sig = self.state.is_loading;

        loading_sig.set(true);

        // Subscribe for kind 40 (channel creation) events
        let channels_for_event = channels_sig;
        let on_channel_event = Rc::new(move |event: nostr_core::NostrEvent| {
            if event.kind != 40 {
                return;
            }
            let (name, description) = parse_channel_content(&event.content);
            let section = event
                .tags
                .iter()
                .find(|t| t.len() >= 2 && t[0] == "section")
                .map(|t| t[1].clone())
                .unwrap_or_else(|| infer_legacy_section(&name));

            channels_for_event.update(|list| {
                if !list.iter().any(|c| c.id == event.id) {
                    list.push(AdminChannel {
                        id: event.id.clone(),
                        name,
                        description,
                        section,
                        created_at: event.created_at,
                        creator: event.pubkey.clone(),
                    });
                }
            });
        });

        let stats_for_eose = stats_sig;
        let channels_for_eose = channels_sig;
        let loading_for_eose = loading_sig;
        let on_channel_eose = Rc::new(move || {
            stats_for_eose.update(|s| {
                s.total_channels = channels_for_eose.get_untracked().len() as u32;
            });
            loading_for_eose.set(false);
        });

        let relay_for_channels = relay.clone();
        relay_for_channels.subscribe(
            vec![Filter {
                kinds: Some(vec![40]),
                ..Default::default()
            }],
            on_channel_event,
            Some(on_channel_eose),
        );

        // Subscribe for kind 42 (messages) to count them
        let stats_for_msgs = stats_sig;
        let msg_counter = RwSignal::new(0u32);
        let on_msg_event = Rc::new(move |_event: nostr_core::NostrEvent| {
            msg_counter.update(|c| *c += 1);
            stats_for_msgs.update(|s| {
                s.total_messages = msg_counter.get_untracked();
            });
        });

        relay.subscribe(
            vec![Filter {
                kinds: Some(vec![42]),
                ..Default::default()
            }],
            on_msg_event,
            None,
        );
    }

    /// Reset the database (delete all events and whitelist entries).
    pub async fn reset_db(&self, privkey: &[u8; 32]) -> Result<(), String> {
        self.state.is_loading.set(true);
        self.state.error.set(None);
        self.state.success.set(None);

        let url = format!("{}/api/admin/reset-db", Self::api_base());
        match fetch_with_nip98_post(&url, "{}", privkey).await {
            Ok(_) => {
                self.state.users.set(Vec::new());
                self.state.channels.set(Vec::new());
                self.state.stats.set(AdminStats::default());
                self.state.success.set(Some(
                    "Database reset. First user to register will become admin.".to_string(),
                ));
                self.state.is_loading.set(false);
                Ok(())
            }
            Err(e) => {
                let msg = e.to_string();
                self.state.error.set(Some(msg.clone()));
                self.state.is_loading.set(false);
                Err(msg)
            }
        }
    }

    /// Clear the current error.
    pub fn clear_error(&self) {
        self.state.error.set(None);
    }

    /// Clear the current success message.
    pub fn clear_success(&self) {
        self.state.success.set(None);
    }
}

// -- Context providers --------------------------------------------------------

/// Create and provide the admin store context. Call once in the admin page component.
pub fn provide_admin() {
    let store = AdminStore::new();
    provide_context(store);
}

/// Get the admin store from context. Panics if `provide_admin()` was not called.
pub fn use_admin() -> AdminStore {
    expect_context::<AdminStore>()
}

// -- Internal helpers ---------------------------------------------------------

/// API response shape for GET /api/whitelist/list.
#[derive(Deserialize)]
struct WhitelistResponse {
    users: Vec<WhitelistUser>,
}

/// Infer a legacy section ID from a channel name for channels that lack a
/// section tag. Returns an empty string if no match is found.
fn infer_legacy_section(name: &str) -> String {
    match name.to_lowercase().as_str() {
        "general" => "public-lobby".into(),
        "off-topic" => "public-lobby".into(),
        "help-desk" => "members-training".into(),
        "ai-projects" => "ai-general".into(),
        _ => String::new(),
    }
}

/// Parse kind-40 channel content JSON into (name, description).
fn parse_channel_content(content: &str) -> (String, String) {
    match serde_json::from_str::<serde_json::Value>(content) {
        Ok(val) => {
            let name = val
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("Unnamed Channel")
                .to_string();
            let description = val
                .get("about")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            (name, description)
        }
        Err(_) => ("Unnamed Channel".to_string(), String::new()),
    }
}

