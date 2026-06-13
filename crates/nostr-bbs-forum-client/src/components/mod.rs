//! Shared UI components for the nostr-bbs forum client.
//!
//! Header and AuthGate are provided by `app.rs` (the layout shell).
//! This module houses all reusable display components.

// -- Existing components ------------------------------------------------------
pub mod channel_card;
pub mod message_bubble;
pub mod particle_canvas;

// -- Visual effects (WebGPU / Canvas2D / CSS fallback) -----------------------
pub mod fx;

// -- Core UI (Stream 1) ------------------------------------------------------
pub mod avatar;
pub mod badge;
pub mod confirm_dialog;
pub mod empty_state;
// Inline plain-English explainer for hard terms (relay / WebID / encrypted …)
// used across the de-jargoned onboarding surfaces.
pub mod info_term;
pub mod modal;
pub mod popover_coord;
pub mod toast;

// -- Rich Messages (Stream 2) ------------------------------------------------
pub mod link_preview;
pub mod media_embed;
pub mod mention_autocomplete;
pub mod mention_text;
pub mod message_input;
pub mod quoted_message;
pub mod reaction_bar;
pub mod typing_indicator;

// -- Auth Flow + Profile (Stream 3) ------------------------------------------
pub mod profile_modal;
pub mod user_display;

// -- Navigation + Mobile (Stream 4) ------------------------------------------
pub mod breadcrumb;
pub mod mobile_bottom_nav;
pub mod notification_bell;
pub mod session_timeout;

// -- Forum/BBS Hierarchy (Stream 5) ------------------------------------------
pub mod category_card;
pub mod section_card;
pub mod topic_list;

// -- Calendar/Events (Stream 6) ----------------------------------------------
pub mod create_event_modal;
pub mod event_card;
pub mod mini_calendar;
pub mod notification_center;
pub mod rsvp_buttons;

// -- Search + DM Enhancement (Stream 8) --------------------------------------
pub mod bookmarks_modal;
pub mod global_search;
pub mod image_upload;
pub mod virtual_list;

// -- Social Features (Stream 9) ----------------------------------------------
pub mod draft_indicator;
pub mod export_modal;
pub mod join_request;
pub mod pinned_messages;

// -- Zone Access (Stream 10) -------------------------------------------------
pub mod access_denied;
pub mod section_request;

// -- Board Stats (Stream 13) ------------------------------------------------
pub mod activity_graph;
pub mod board_stats;
pub mod moderator_team;
pub mod todays_activity;
pub mod top_posters;
pub mod welcome_modal;

// -- PWA / Offline (Stream 12) -----------------------------------------------
pub mod offline_banner;

// -- Accessibility & Polish (Stream 11) --------------------------------------
pub mod nsec_backup;
// Recovery & device-onboarding sheet (ADR-095): printable one-page QR sheet
// that backs up the account and onboards 0xchat — client-side only.
pub mod recovery_sheet;
pub mod screen_reader;
pub mod swipeable_message;

// -- Integration (Stream 14) ------------------------------------------------
pub mod channel_stats;
pub mod mark_all_read;
pub mod zone_hero;

// -- Moderation (Phase 3 / P2) ----------------------------------------------
pub mod hidden_message;
pub mod report_button;
pub mod thread_view;

// -- UX Completion (Stream 6) -----------------------------------------------
pub mod admin_checklist;

// -- Onboarding & Badges (Phase 2 P1) --------------------------------------
pub mod badge_display;
pub mod onboarding_modal;

// -- Git Source Control + App Manifest (JSS Phase 1 / ADR-089) -------------
pub mod git_panel;
