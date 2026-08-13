//! Per-zone kanban boards and collaborative task cards.
//!
//! Implements the Kanbanstr NIP-100-compatible kinds:
//! - Kind 30301: Kanban board (parameterized replaceable via `d` tag) —
//!   columns are `["col", "<id>", "<name>", "<order>"]` tags on the board,
//!   maintainers are `p` tags.
//! - Kind 30302: Kanban card (parameterized replaceable via `d` tag) — one
//!   event per card, associated to its board via an `a` coordinate tag,
//!   column via the `s` tag, ordering via `rank`, assignees via `p` tags.
//!
//! Plus two repo-local bridges:
//! - Kind 31402 (ACSP ActionRequest) **kanban approval requests**: a card move
//!   into an approval-gated column is requested, not performed — the card is
//!   republished with a `pending_move` tag and a kanban-tagged 31402 is raised;
//!   an admin's kind-31403 ActionResponse (Approve/Reject) resolves it. A
//!   kanban approval request is identified by its `["k", "30302"]` tag; the
//!   relay admits these from ordinary whitelisted members (unlike all other
//!   31402s, which stay agent-registry-gated).
//! - Kind 38000 **agent intents**: dispatching a card to an agent publishes an
//!   agent-intent referencing the card, which the agentbox bridge routes to the
//!   agent's inbox.
//!
//! ## Zone scoping
//!
//! Boards and cards reuse the calendar's zone-binding tag
//! (`["zone", "<zone-slug>"]`, see [`crate::calendar::ZONE_TAG`]). The relay is
//! the security boundary: zone-tagged kanban events require zone write access
//! to publish and zone read access (member / admin / owner) to receive. An
//! untagged board is unscoped (public read), mirroring the calendar posture.
//!
//! ## Collaboration model (multi-author cards)
//!
//! Nostr addressable events are last-write-wins per `(pubkey, kind, d)` — the
//! key includes the author, so there is no native multi-writer object. Cards
//! therefore follow the Kanbanstr/NIP-34 convention: a card's identity is
//! `(board coordinate, d tag)` and the authoritative version is the **latest
//! `created_at` across authors** ([`fold_cards`]; ties broken by lowest event
//! id). Authorship rights are enforced by the relay's zone write gate — anyone
//! who may write to the zone may move any card in it, which is the intended
//! collaboration semantic for a zone task board.

use std::collections::HashMap;

use k256::schnorr::SigningKey;
use thiserror::Error;

use crate::calendar::read_zone_tag;
use crate::event::{sign_event, NostrEvent, UnsignedEvent};
use crate::signer::Signer;

// -- Kind constants -----------------------------------------------------------

/// Kind 30301: kanban board (Kanbanstr NIP-100).
pub const KIND_KANBAN_BOARD: u64 = 30301;
/// Kind 30302: kanban card (Kanbanstr NIP-100).
pub const KIND_KANBAN_CARD: u64 = 30302;
/// Kind 38000: agent intent (VisionFlow agent-intent band) — dispatch a task
/// to an agent via the nostr→agentbox bridge.
pub const KIND_AGENT_INTENT: u64 = 38000;

/// Whether a kind is a kanban kind subject to the zone read/write gates.
pub fn is_kanban_kind(kind: u64) -> bool {
    matches!(kind, KIND_KANBAN_BOARD | KIND_KANBAN_CARD)
}

// -- Tag conventions ------------------------------------------------------------

/// Board column tag: `["col", "<id>", "<name>", "<order>"]`.
pub const COL_TAG: &str = "col";
/// Repo-local: `["approval_col", "<col-id>"]` — entering this column requires a
/// human kind-31403 Approve decision.
pub const APPROVAL_COL_TAG: &str = "approval_col";
/// Card column/status tag: `["s", "<col-id>"]`.
pub const STATUS_TAG: &str = "s";
/// Card ordering within a column: `["rank", "<integer>"]`.
pub const RANK_TAG: &str = "rank";
/// Repo-local card due date: `["due", "<unix-seconds>"]`.
pub const DUE_TAG: &str = "due";
/// Repo-local pending move: `["pending_move", "<target-col>", "<31402-event-id>"]`.
pub const PENDING_MOVE_TAG: &str = "pending_move";
/// Repo-local deletion tombstone: `["deleted", "1"]`. Under the multi-author
/// fold a kind-5 deletion only removes ONE author's replaceable row (the key
/// includes the pubkey), so an older sibling version would resurface; a
/// tombstone republish IS the newest version for every viewer and hides the
/// card everywhere while preserving the audit trail.
pub const DELETED_TAG: &str = "deleted";

// -- Errors ---------------------------------------------------------------------

/// Errors specific to kanban event creation.
#[derive(Debug, Error)]
pub enum KanbanError {
    /// The title is empty.
    #[error("title must not be empty")]
    EmptyTitle,
    /// A board needs at least one column.
    #[error("board must define at least one column")]
    NoColumns,
    /// The referenced column id is not defined on the board.
    #[error("unknown column: {0}")]
    UnknownColumn(String),
    /// The board coordinate is malformed.
    #[error("invalid board coordinate: {0}")]
    InvalidCoord(String),
    /// The signing key is invalid.
    #[error("invalid signing key: {0}")]
    InvalidKey(String),
    /// Signing the event failed.
    #[error("signing failed: {0}")]
    SigningFailed(String),
}

// -- Helpers --------------------------------------------------------------------

/// Get current Unix timestamp, platform-aware.
fn now_secs() -> u64 {
    #[cfg(target_arch = "wasm32")]
    {
        (js_sys::Date::now() / 1000.0) as u64
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before UNIX epoch")
            .as_secs()
    }
}

/// Generate a simple UUID-like identifier from random bytes.
fn random_d_tag() -> String {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).expect("getrandom for d-tag");
    hex::encode(bytes)
}

fn tag_value<'a>(event: &'a NostrEvent, name: &str) -> Option<&'a str> {
    event
        .tags
        .iter()
        .find(|t| t.len() >= 2 && t[0] == name)
        .map(|t| t[1].as_str())
}

// -- Board coordinate -------------------------------------------------------------

/// NIP-01 addressable coordinate for a board: `30301:<pubkey>:<d>`.
pub fn board_coord(pubkey: &str, d_tag: &str) -> String {
    format!("{KIND_KANBAN_BOARD}:{pubkey}:{d_tag}")
}

/// NIP-01 addressable coordinate for a card: `30302:<pubkey>:<d>`.
pub fn card_coord(pubkey: &str, d_tag: &str) -> String {
    format!("{KIND_KANBAN_CARD}:{pubkey}:{d_tag}")
}

/// Parse an addressable coordinate `<kind>:<pubkey>:<d>` into its parts.
pub fn parse_coord(coord: &str) -> Option<(u64, &str, &str)> {
    let mut parts = coord.splitn(3, ':');
    let kind = parts.next()?.parse::<u64>().ok()?;
    let pubkey = parts.next()?;
    let d = parts.next()?;
    if pubkey.is_empty() || d.is_empty() {
        return None;
    }
    Some((kind, pubkey, d))
}

// -- Parsed types -----------------------------------------------------------------

/// A single board column.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoardColumn {
    /// Stable column id (referenced by cards' `s` tags).
    pub id: String,
    /// Display name.
    pub name: String,
    /// Sort order (ascending).
    pub order: u32,
}

/// A parsed kanban board (kind 30301).
#[derive(Debug, Clone, PartialEq)]
pub struct KanbanBoard {
    /// Event id of this board version.
    pub id: String,
    /// Board creator (the coordinate's pubkey).
    pub pubkey: String,
    /// Replaceable identity.
    pub d_tag: String,
    /// Board title.
    pub title: String,
    /// Markdown description (event content).
    pub description: String,
    /// Columns in declared order.
    pub columns: Vec<BoardColumn>,
    /// Column ids whose ENTRY requires a human kind-31403 Approve.
    pub approval_columns: Vec<String>,
    /// Maintainer pubkeys (`p` tags). Advisory for unscoped boards; zone-tagged
    /// boards defer to the relay's zone write gate instead.
    pub maintainers: Vec<String>,
    /// Owning zone slug, when zone-bound.
    pub zone: Option<String>,
    /// Version timestamp.
    pub created_at: u64,
}

impl KanbanBoard {
    /// The board's addressable coordinate `30301:<pubkey>:<d>`.
    pub fn coord(&self) -> String {
        board_coord(&self.pubkey, &self.d_tag)
    }

    /// Whether entering `col_id` requires a human approval decision.
    pub fn column_needs_approval(&self, col_id: &str) -> bool {
        self.approval_columns.iter().any(|c| c == col_id)
    }

    /// Parse a kind-30301 event. Returns `None` for other kinds or a board
    /// with no `d` tag / no columns.
    pub fn from_event(event: &NostrEvent) -> Option<Self> {
        if event.kind != KIND_KANBAN_BOARD {
            return None;
        }
        let d_tag = tag_value(event, "d")?.to_string();

        let mut columns: Vec<BoardColumn> = event
            .tags
            .iter()
            .filter(|t| t.len() >= 3 && t[0] == COL_TAG)
            .map(|t| BoardColumn {
                id: t[1].clone(),
                name: t[2].clone(),
                order: t.get(3).and_then(|o| o.parse().ok()).unwrap_or(0),
            })
            .collect();
        if columns.is_empty() {
            return None;
        }
        columns.sort_by_key(|c| c.order);

        Some(KanbanBoard {
            id: event.id.clone(),
            pubkey: event.pubkey.clone(),
            d_tag,
            title: tag_value(event, "title").unwrap_or("Untitled board").to_string(),
            description: event.content.clone(),
            columns,
            approval_columns: event
                .tags
                .iter()
                .filter(|t| t.len() >= 2 && t[0] == APPROVAL_COL_TAG)
                .map(|t| t[1].clone())
                .collect(),
            maintainers: event
                .tags
                .iter()
                .filter(|t| t.len() >= 2 && t[0] == "p")
                .map(|t| t[1].clone())
                .collect(),
            zone: read_zone_tag(event).map(str::to_string),
            created_at: event.created_at,
        })
    }
}

/// A parsed kanban card (kind 30302).
#[derive(Debug, Clone, PartialEq)]
pub struct KanbanCard {
    /// Event id of this card version.
    pub id: String,
    /// Author of THIS version (may differ from the card's original author
    /// under the multi-author fold).
    pub pubkey: String,
    /// Replaceable identity — with `board` this is the card's stable key.
    pub d_tag: String,
    /// Owning board coordinate (`a` tag, `30301:<pubkey>:<d>`).
    pub board: String,
    /// Card title.
    pub title: String,
    /// Markdown description (event content).
    pub description: String,
    /// Current column id (`s` tag).
    pub column: String,
    /// Ordering within the column (ascending).
    pub rank: i64,
    /// Assignee pubkeys (`p` tags).
    pub assignees: Vec<String>,
    /// Optional due date (unix seconds).
    pub due: Option<u64>,
    /// Owning zone slug, when zone-bound.
    pub zone: Option<String>,
    /// Pending approval-gated move: `(target column, 31402 request event id)`.
    pub pending_move: Option<(String, String)>,
    /// Deletion tombstone — the card is hidden from boards but the version
    /// history remains foldable.
    pub deleted: bool,
    /// Version timestamp.
    pub created_at: u64,
}

impl KanbanCard {
    /// The stable multi-author identity of this card.
    pub fn key(&self) -> (String, String) {
        (self.board.clone(), self.d_tag.clone())
    }

    /// Parse a kind-30302 event. Returns `None` for other kinds or a card
    /// missing its `d` tag / board association.
    pub fn from_event(event: &NostrEvent) -> Option<Self> {
        if event.kind != KIND_KANBAN_CARD {
            return None;
        }
        let d_tag = tag_value(event, "d")?.to_string();
        let board = event
            .tags
            .iter()
            .find(|t| t.len() >= 2 && t[0] == "a" && t[1].starts_with("30301:"))
            .map(|t| t[1].clone())?;

        let pending_move = event
            .tags
            .iter()
            .find(|t| t.len() >= 3 && t[0] == PENDING_MOVE_TAG)
            .map(|t| (t[1].clone(), t[2].clone()));

        Some(KanbanCard {
            id: event.id.clone(),
            pubkey: event.pubkey.clone(),
            d_tag,
            board,
            title: tag_value(event, "title").unwrap_or("Untitled").to_string(),
            description: event.content.clone(),
            column: tag_value(event, STATUS_TAG).unwrap_or_default().to_string(),
            rank: tag_value(event, RANK_TAG)
                .and_then(|r| r.parse().ok())
                .unwrap_or(0),
            assignees: event
                .tags
                .iter()
                .filter(|t| t.len() >= 2 && t[0] == "p")
                .map(|t| t[1].clone())
                .collect(),
            due: tag_value(event, DUE_TAG).and_then(|v| v.parse().ok()),
            zone: read_zone_tag(event).map(str::to_string),
            pending_move,
            deleted: tag_value(event, DELETED_TAG).is_some(),
            created_at: event.created_at,
        })
    }
}

/// Fold raw card versions into the authoritative card set.
///
/// Card identity is `(board coordinate, d tag)`; the latest `created_at` wins
/// across authors (the relay's zone write gate is what bounds who may author a
/// version). Ties break to the lexicographically lowest event id, mirroring
/// relay replaceable-event tie-breaking.
pub fn fold_cards<I: IntoIterator<Item = KanbanCard>>(cards: I) -> Vec<KanbanCard> {
    let mut latest: HashMap<(String, String), KanbanCard> = HashMap::new();
    for card in cards {
        let key = card.key();
        match latest.get(&key) {
            Some(cur)
                if cur.created_at > card.created_at
                    || (cur.created_at == card.created_at && cur.id <= card.id) => {}
            _ => {
                latest.insert(key, card);
            }
        }
    }
    let mut out: Vec<KanbanCard> = latest.into_values().collect();
    out.sort_by(|a, b| a.column.cmp(&b.column).then(a.rank.cmp(&b.rank)));
    out
}

// -- Builders ---------------------------------------------------------------------

/// Input for creating or republishing a card. `d_tag: None` mints a new card.
#[derive(Debug, Clone, Default)]
pub struct CardInput {
    /// Existing card identity, or `None` for a new card.
    pub d_tag: Option<String>,
    /// Owning board coordinate (`30301:<pubkey>:<d>`).
    pub board: String,
    /// Card title (required, non-empty).
    pub title: String,
    /// Markdown description.
    pub description: String,
    /// Column id.
    pub column: String,
    /// Ordering within the column.
    pub rank: i64,
    /// Assignee pubkeys.
    pub assignees: Vec<String>,
    /// Optional due date (unix seconds).
    pub due: Option<u64>,
    /// Zone slug (should mirror the board's zone).
    pub zone: Option<String>,
    /// Pending approval-gated move `(target column, 31402 event id)`.
    pub pending_move: Option<(String, String)>,
    /// Publish this version as a deletion tombstone.
    pub deleted: bool,
}

fn board_tags(
    title: &str,
    columns: &[(String, String)],
    approval_columns: &[String],
    maintainers: &[String],
    d_tag: String,
) -> Vec<Vec<String>> {
    let mut tags = vec![
        vec!["d".to_string(), d_tag],
        vec!["title".to_string(), title.to_string()],
    ];
    for (i, (id, name)) in columns.iter().enumerate() {
        tags.push(vec![
            COL_TAG.to_string(),
            id.clone(),
            name.clone(),
            i.to_string(),
        ]);
    }
    for col in approval_columns {
        tags.push(vec![APPROVAL_COL_TAG.to_string(), col.clone()]);
    }
    for m in maintainers {
        tags.push(vec!["p".to_string(), m.clone()]);
    }
    tags.push(vec!["t".to_string(), "kanban".to_string()]);
    tags
}

fn validate_board(
    title: &str,
    columns: &[(String, String)],
    approval_columns: &[String],
) -> Result<(), KanbanError> {
    if title.is_empty() {
        return Err(KanbanError::EmptyTitle);
    }
    if columns.is_empty() {
        return Err(KanbanError::NoColumns);
    }
    for col in approval_columns {
        if !columns.iter().any(|(id, _)| id == col) {
            return Err(KanbanError::UnknownColumn(col.clone()));
        }
    }
    Ok(())
}

/// Create a kanban board (kind 30301) with a private key. Used by native
/// tests/tools; the client uses [`create_board_signer`].
///
/// `columns` are `(id, name)` pairs in display order; `approval_columns` must
/// reference declared column ids. `d_tag: None` mints a new board.
#[allow(clippy::too_many_arguments)]
pub fn create_board(
    privkey: &[u8; 32],
    title: &str,
    description: &str,
    columns: &[(String, String)],
    approval_columns: &[String],
    maintainers: &[String],
    zone: Option<&str>,
    d_tag: Option<String>,
) -> Result<NostrEvent, KanbanError> {
    validate_board(title, columns, approval_columns)?;
    let signing_key =
        SigningKey::from_bytes(privkey).map_err(|e| KanbanError::InvalidKey(e.to_string()))?;
    let pubkey = hex::encode(signing_key.verifying_key().to_bytes());
    let mut tags = board_tags(
        title,
        columns,
        approval_columns,
        maintainers,
        d_tag.unwrap_or_else(random_d_tag),
    );
    if let Some(z) = zone {
        tags.push(vec![crate::calendar::ZONE_TAG.to_string(), z.to_string()]);
    }
    let unsigned = UnsignedEvent {
        pubkey,
        created_at: now_secs(),
        kind: KIND_KANBAN_BOARD,
        tags,
        content: description.to_string(),
    };
    sign_event(unsigned, &signing_key).map_err(|e| KanbanError::SigningFailed(e.to_string()))
}

/// Create a kanban board (kind 30301) using a [`Signer`]. See [`create_board`].
#[allow(clippy::too_many_arguments)]
pub async fn create_board_signer(
    signer: &dyn Signer,
    title: &str,
    description: &str,
    columns: &[(String, String)],
    approval_columns: &[String],
    maintainers: &[String],
    zone: Option<&str>,
    d_tag: Option<String>,
) -> Result<NostrEvent, KanbanError> {
    validate_board(title, columns, approval_columns)?;
    let mut tags = board_tags(
        title,
        columns,
        approval_columns,
        maintainers,
        d_tag.unwrap_or_else(random_d_tag),
    );
    if let Some(z) = zone {
        tags.push(vec![crate::calendar::ZONE_TAG.to_string(), z.to_string()]);
    }
    let unsigned = UnsignedEvent {
        pubkey: signer.public_key().to_string(),
        created_at: now_secs(),
        kind: KIND_KANBAN_BOARD,
        tags,
        content: description.to_string(),
    };
    signer
        .sign_event(unsigned)
        .await
        .map_err(|e| KanbanError::SigningFailed(e.to_string()))
}

fn card_tags(input: &CardInput, d_tag: String) -> Vec<Vec<String>> {
    let mut tags = vec![
        vec!["d".to_string(), d_tag],
        vec!["a".to_string(), input.board.clone()],
        vec!["title".to_string(), input.title.clone()],
        vec![STATUS_TAG.to_string(), input.column.clone()],
        vec![RANK_TAG.to_string(), input.rank.to_string()],
    ];
    for p in &input.assignees {
        tags.push(vec!["p".to_string(), p.clone()]);
    }
    if let Some(due) = input.due {
        tags.push(vec![DUE_TAG.to_string(), due.to_string()]);
    }
    if let Some((col, req)) = &input.pending_move {
        tags.push(vec![PENDING_MOVE_TAG.to_string(), col.clone(), req.clone()]);
    }
    if input.deleted {
        tags.push(vec![DELETED_TAG.to_string(), "1".to_string()]);
    }
    if let Some(z) = &input.zone {
        tags.push(vec![crate::calendar::ZONE_TAG.to_string(), z.clone()]);
    }
    tags
}

fn validate_card(input: &CardInput) -> Result<(), KanbanError> {
    if input.title.is_empty() {
        return Err(KanbanError::EmptyTitle);
    }
    if parse_coord(&input.board).map(|(k, _, _)| k) != Some(KIND_KANBAN_BOARD) {
        return Err(KanbanError::InvalidCoord(input.board.clone()));
    }
    Ok(())
}

/// Create or republish a kanban card (kind 30302) with a private key.
pub fn create_card(privkey: &[u8; 32], input: &CardInput) -> Result<NostrEvent, KanbanError> {
    validate_card(input)?;
    let signing_key =
        SigningKey::from_bytes(privkey).map_err(|e| KanbanError::InvalidKey(e.to_string()))?;
    let pubkey = hex::encode(signing_key.verifying_key().to_bytes());
    let unsigned = UnsignedEvent {
        pubkey,
        created_at: now_secs(),
        kind: KIND_KANBAN_CARD,
        tags: card_tags(input, input.d_tag.clone().unwrap_or_else(random_d_tag)),
        content: input.description.clone(),
    };
    sign_event(unsigned, &signing_key).map_err(|e| KanbanError::SigningFailed(e.to_string()))
}

/// Create or republish a kanban card (kind 30302) using a [`Signer`].
pub async fn create_card_signer(
    signer: &dyn Signer,
    input: &CardInput,
) -> Result<NostrEvent, KanbanError> {
    validate_card(input)?;
    let unsigned = UnsignedEvent {
        pubkey: signer.public_key().to_string(),
        created_at: now_secs(),
        kind: KIND_KANBAN_CARD,
        tags: card_tags(input, input.d_tag.clone().unwrap_or_else(random_d_tag)),
        content: input.description.clone(),
    };
    signer
        .sign_event(unsigned)
        .await
        .map_err(|e| KanbanError::SigningFailed(e.to_string()))
}

// -- ACSP approval bridge -----------------------------------------------------------

/// Whether a kind-31402 ActionRequest is a kanban card approval request
/// (carries `["k", "30302"]`). The relay's governance gate admits these from
/// ordinary whitelisted members; all other 31402s remain agent-registry-gated.
pub fn is_kanban_approval_request(event: &NostrEvent) -> bool {
    event.kind == crate::governance::KIND_ACTION_REQUEST
        && event
            .tags
            .iter()
            .any(|t| t.len() >= 2 && t[0] == "k" && t[1] == "30302")
}

fn approval_request_tags(card: &KanbanCard, target_col: &str) -> Vec<Vec<String>> {
    let mut tags = vec![
        vec!["d".to_string(), random_d_tag()],
        vec!["k".to_string(), KIND_KANBAN_CARD.to_string()],
        vec![
            "a".to_string(),
            card_coord(&card.pubkey, &card.d_tag),
        ],
        vec!["board".to_string(), card.board.clone()],
        vec!["card_d".to_string(), card.d_tag.clone()],
        vec!["target_col".to_string(), target_col.to_string()],
    ];
    if let Some(z) = &card.zone {
        tags.push(vec![crate::calendar::ZONE_TAG.to_string(), z.clone()]);
    }
    tags
}

/// Build a kanban approval request (kind 31402) for moving `card` into the
/// approval-gated `target_col`, using a [`Signer`]. The content is a short
/// human-readable summary rendered in the governance surface.
pub async fn create_card_approval_request_signer(
    signer: &dyn Signer,
    card: &KanbanCard,
    target_col: &str,
    note: &str,
) -> Result<NostrEvent, KanbanError> {
    let summary = if note.is_empty() {
        format!("Move card \"{}\" to column \"{}\"", card.title, target_col)
    } else {
        format!(
            "Move card \"{}\" to column \"{}\" — {}",
            card.title, target_col, note
        )
    };
    // ActionRequest-shaped JSON so the governance panel registry ingests the
    // request into its actions list (a plain-string content is silently
    // dropped by `PanelRegistry::ingest_event`).
    let content = serde_json::json!({
        "fields": {
            "card_title": card.title,
            "card_d": card.d_tag,
            "board": card.board,
            "target_col": target_col,
        },
        "reasoning": summary,
        "risk_tier": "medium",
    })
    .to_string();
    let unsigned = UnsignedEvent {
        pubkey: signer.public_key().to_string(),
        created_at: now_secs(),
        kind: crate::governance::KIND_ACTION_REQUEST,
        tags: approval_request_tags(card, target_col),
        content,
    };
    signer
        .sign_event(unsigned)
        .await
        .map_err(|e| KanbanError::SigningFailed(e.to_string()))
}

/// Build a kanban approval response (kind 31403) deciding request `request`,
/// using a [`Signer`]. `approve: true` ⇒ content `"approve"`, else `"reject"`
/// (parsed by [`crate::governance::broker::DecisionOutcome::from_response_content`]).
/// The relay admits 31403 from admins only; the `e` tag references the request
/// so the response is not an orphan.
pub async fn create_card_approval_response_signer(
    signer: &dyn Signer,
    request: &NostrEvent,
    approve: bool,
) -> Result<NostrEvent, KanbanError> {
    let mut tags = vec![
        vec!["d".to_string(), random_d_tag()],
        vec!["e".to_string(), request.id.clone()],
        vec!["k".to_string(), KIND_KANBAN_CARD.to_string()],
    ];
    // Mirror the card reference so board clients can match responses without
    // fetching the request.
    for name in ["a", "board", "card_d", "target_col"] {
        if let Some(t) = request.tags.iter().find(|t| t.len() >= 2 && t[0] == name) {
            tags.push(t.clone());
        }
    }
    if let Some(z) = read_zone_tag(request) {
        tags.push(vec![crate::calendar::ZONE_TAG.to_string(), z.to_string()]);
    }
    let unsigned = UnsignedEvent {
        pubkey: signer.public_key().to_string(),
        created_at: now_secs(),
        kind: crate::governance::KIND_ACTION_RESPONSE,
        tags,
        // Internally-tagged DecisionOutcome JSON, the format
        // `DecisionOutcome::from_response_content` parses.
        content: if approve {
            r#"{"action":"approve"}"#
        } else {
            r#"{"action":"reject"}"#
        }
        .to_string(),
    };
    signer
        .sign_event(unsigned)
        .await
        .map_err(|e| KanbanError::SigningFailed(e.to_string()))
}

/// Parsed kanban approval decision (a kind-31403 that references a kanban
/// approval request).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalDecision {
    /// The 31402 request event id this decision resolves.
    pub request_id: String,
    /// Whether the move was approved.
    pub approved: bool,
    /// Board coordinate, when mirrored onto the response.
    pub board: Option<String>,
    /// Card `d` tag, when mirrored onto the response.
    pub card_d: Option<String>,
    /// Target column, when mirrored onto the response.
    pub target_col: Option<String>,
}

/// Parse a kind-31403 ActionResponse into a kanban [`ApprovalDecision`].
/// Returns `None` for other kinds, responses without an `e` reference, or
/// contents that don't parse to Approve/Reject.
pub fn parse_approval_decision(event: &NostrEvent) -> Option<ApprovalDecision> {
    if event.kind != crate::governance::KIND_ACTION_RESPONSE {
        return None;
    }
    let request_id = tag_value(event, "e")?.to_string();
    let approved = match crate::governance::broker::DecisionOutcome::from_response_content(
        &event.content,
    )? {
        crate::governance::broker::DecisionOutcome::Approve => true,
        crate::governance::broker::DecisionOutcome::Reject => false,
        _ => return None,
    };
    Some(ApprovalDecision {
        request_id,
        approved,
        board: tag_value(event, "board").map(str::to_string),
        card_d: tag_value(event, "card_d").map(str::to_string),
        target_col: tag_value(event, "target_col").map(str::to_string),
    })
}

// -- Calendar bridge ------------------------------------------------------------------

/// Build a zone-tagged NIP-52 time-based calendar event (kind 31923) for a
/// card's due date, using a [`Signer`]. The event lands in the card's zone
/// calendar (relay-projected like any other zone calendar event) and links
/// back to the card via `a`/`board`/`card_d` tags. Returns an error when the
/// card has no due date.
pub async fn create_card_due_event_signer(
    signer: &dyn Signer,
    card: &KanbanCard,
) -> Result<NostrEvent, KanbanError> {
    let due = card
        .due
        .ok_or_else(|| KanbanError::SigningFailed("card has no due date".into()))?;
    let mut tags = vec![
        vec!["d".to_string(), format!("card-due-{}", card.d_tag)],
        vec!["title".to_string(), format!("Due: {}", card.title)],
        vec!["start".to_string(), due.to_string()],
        vec!["a".to_string(), card_coord(&card.pubkey, &card.d_tag)],
        vec!["board".to_string(), card.board.clone()],
        vec!["card_d".to_string(), card.d_tag.clone()],
        vec!["t".to_string(), "calendar-event".to_string()],
    ];
    if let Some(z) = &card.zone {
        tags.push(vec![crate::calendar::ZONE_TAG.to_string(), z.clone()]);
    }
    let unsigned = UnsignedEvent {
        pubkey: signer.public_key().to_string(),
        created_at: now_secs(),
        kind: crate::calendar::KIND_CALENDAR_EVENT,
        tags,
        content: card.description.clone(),
    };
    signer
        .sign_event(unsigned)
        .await
        .map_err(|e| KanbanError::SigningFailed(e.to_string()))
}

// -- Agent dispatch -------------------------------------------------------------------

/// Build a kind-38000 agent intent dispatching `card` to `agent_pubkey`, using
/// a [`Signer`]. The content is a JSON task envelope the agentbox bridge
/// forwards to the agent's inbox.
pub async fn create_agent_intent_signer(
    signer: &dyn Signer,
    card: &KanbanCard,
    agent_pubkey: &str,
    instructions: &str,
) -> Result<NostrEvent, KanbanError> {
    let mut tags = vec![
        vec!["p".to_string(), agent_pubkey.to_string()],
        vec![
            "a".to_string(),
            card_coord(&card.pubkey, &card.d_tag),
        ],
        vec!["board".to_string(), card.board.clone()],
        vec!["card_d".to_string(), card.d_tag.clone()],
    ];
    if let Some(z) = &card.zone {
        tags.push(vec![crate::calendar::ZONE_TAG.to_string(), z.clone()]);
    }
    let content = serde_json::json!({
        "type": "kanban_card_task",
        "title": card.title,
        "description": card.description,
        "board": card.board,
        "card_d": card.d_tag,
        "column": card.column,
        "due": card.due,
        "instructions": instructions,
    })
    .to_string();
    let unsigned = UnsignedEvent {
        pubkey: signer.public_key().to_string(),
        created_at: now_secs(),
        kind: KIND_AGENT_INTENT,
        tags,
        content,
    };
    signer
        .sign_event(unsigned)
        .await
        .map_err(|e| KanbanError::SigningFailed(e.to_string()))
}

// -- Tests ------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::verify_event;

    fn test_key() -> [u8; 32] {
        [0x02u8; 32]
    }

    fn default_columns() -> Vec<(String, String)> {
        vec![
            ("todo".into(), "To do".into()),
            ("doing".into(), "Doing".into()),
            ("done".into(), "Done".into()),
        ]
    }

    fn make_board() -> NostrEvent {
        create_board(
            &test_key(),
            "Sprint board",
            "The zone task board",
            &default_columns(),
            &["done".to_string()],
            &[],
            Some("family"),
            None,
        )
        .unwrap()
    }

    // -- Board ---------------------------------------------------------------

    #[test]
    fn board_roundtrip() {
        let event = make_board();
        assert_eq!(event.kind, 30301);
        assert!(verify_event(&event));

        let board = KanbanBoard::from_event(&event).unwrap();
        assert_eq!(board.title, "Sprint board");
        assert_eq!(board.description, "The zone task board");
        assert_eq!(board.columns.len(), 3);
        assert_eq!(board.columns[0].id, "todo");
        assert_eq!(board.columns[2].name, "Done");
        assert_eq!(board.zone.as_deref(), Some("family"));
        assert!(board.column_needs_approval("done"));
        assert!(!board.column_needs_approval("todo"));
        assert_eq!(board.coord(), board_coord(&board.pubkey, &board.d_tag));
    }

    #[test]
    fn board_requires_title_and_columns() {
        let cols = default_columns();
        assert!(matches!(
            create_board(&test_key(), "", "", &cols, &[], &[], None, None),
            Err(KanbanError::EmptyTitle)
        ));
        assert!(matches!(
            create_board(&test_key(), "B", "", &[], &[], &[], None, None),
            Err(KanbanError::NoColumns)
        ));
        assert!(matches!(
            create_board(
                &test_key(),
                "B",
                "",
                &cols,
                &["nope".to_string()],
                &[],
                None,
                None
            ),
            Err(KanbanError::UnknownColumn(_))
        ));
    }

    #[test]
    fn unzoned_board_has_no_zone_tag() {
        let event = create_board(
            &test_key(),
            "B",
            "",
            &default_columns(),
            &[],
            &[],
            None,
            None,
        )
        .unwrap();
        assert_eq!(read_zone_tag(&event), None);
        assert_eq!(KanbanBoard::from_event(&event).unwrap().zone, None);
    }

    // -- Card ----------------------------------------------------------------

    fn make_card(board: &KanbanBoard, d: Option<String>, column: &str, rank: i64) -> NostrEvent {
        create_card(
            &test_key(),
            &CardInput {
                d_tag: d,
                board: board.coord(),
                title: "Fix the gate".into(),
                description: "Details in thread".into(),
                column: column.into(),
                rank,
                assignees: vec!["ab".repeat(32)],
                due: Some(1_800_000_000),
                zone: board.zone.clone(),
                pending_move: None,
                deleted: false,
            },
        )
        .unwrap()
    }

    #[test]
    fn card_roundtrip() {
        let board = KanbanBoard::from_event(&make_board()).unwrap();
        let event = make_card(&board, None, "todo", 10);
        assert_eq!(event.kind, 30302);
        assert!(verify_event(&event));

        let card = KanbanCard::from_event(&event).unwrap();
        assert_eq!(card.board, board.coord());
        assert_eq!(card.title, "Fix the gate");
        assert_eq!(card.column, "todo");
        assert_eq!(card.rank, 10);
        assert_eq!(card.assignees.len(), 1);
        assert_eq!(card.due, Some(1_800_000_000));
        assert_eq!(card.zone.as_deref(), Some("family"));
        assert_eq!(card.pending_move, None);
    }

    #[test]
    fn card_requires_valid_board_coord() {
        let bad = CardInput {
            board: "not-a-coord".into(),
            title: "T".into(),
            column: "todo".into(),
            ..Default::default()
        };
        assert!(matches!(
            create_card(&test_key(), &bad),
            Err(KanbanError::InvalidCoord(_))
        ));
        // A card coordinate is not a board coordinate.
        let card_coord_as_board = CardInput {
            board: format!("30302:{}:{}", "ab".repeat(32), "d1"),
            title: "T".into(),
            column: "todo".into(),
            ..Default::default()
        };
        assert!(matches!(
            create_card(&test_key(), &card_coord_as_board),
            Err(KanbanError::InvalidCoord(_))
        ));
    }

    #[test]
    fn republish_preserves_identity() {
        let board = KanbanBoard::from_event(&make_board()).unwrap();
        let v1 = KanbanCard::from_event(&make_card(&board, None, "todo", 10)).unwrap();
        let v2_event = make_card(&board, Some(v1.d_tag.clone()), "doing", 20);
        let v2 = KanbanCard::from_event(&v2_event).unwrap();
        assert_eq!(v1.key(), v2.key());
        assert_eq!(v2.column, "doing");
    }

    #[test]
    fn coord_parsing() {
        let pk = "cd".repeat(32);
        let coord = board_coord(&pk, "abc");
        let (kind, pubkey, d) = parse_coord(&coord).unwrap();
        assert_eq!(kind, KIND_KANBAN_BOARD);
        assert_eq!(pubkey, pk);
        assert_eq!(d, "abc");
        assert!(parse_coord("30301:x").is_none());
        assert!(parse_coord("nope:x:y").is_none());
        assert!(parse_coord("30301::d").is_none());
    }

    // -- Fold ------------------------------------------------------------------

    #[test]
    fn fold_latest_version_wins_across_authors() {
        let board = KanbanBoard::from_event(&make_board()).unwrap();
        let mut v1 = KanbanCard::from_event(&make_card(&board, None, "todo", 10)).unwrap();
        let mut v2 = v1.clone();
        // A second author moves the card later.
        v2.pubkey = "ef".repeat(32);
        v2.id = "11".repeat(32);
        v2.column = "doing".into();
        v2.created_at = v1.created_at + 100;
        v1.id = "22".repeat(32);

        let folded = fold_cards(vec![v1.clone(), v2.clone()]);
        assert_eq!(folded.len(), 1);
        assert_eq!(folded[0].column, "doing");
        assert_eq!(folded[0].pubkey, v2.pubkey);

        // Order of ingestion must not matter.
        let folded_rev = fold_cards(vec![v2, v1]);
        assert_eq!(folded_rev[0].column, "doing");
    }

    #[test]
    fn fold_tie_breaks_to_lowest_id() {
        let board = KanbanBoard::from_event(&make_board()).unwrap();
        let base = KanbanCard::from_event(&make_card(&board, None, "todo", 10)).unwrap();
        let mut a = base.clone();
        let mut b = base;
        a.id = "aa".repeat(32);
        a.column = "todo".into();
        b.id = "bb".repeat(32);
        b.column = "doing".into();
        b.created_at = a.created_at; // tie

        let folded = fold_cards(vec![a.clone(), b.clone()]);
        assert_eq!(folded.len(), 1);
        assert_eq!(folded[0].id, a.id, "lowest id wins the tie");
        let folded_rev = fold_cards(vec![b, a]);
        assert_eq!(folded_rev[0].id, "aa".repeat(32));
    }

    #[test]
    fn fold_distinct_cards_kept() {
        let board = KanbanBoard::from_event(&make_board()).unwrap();
        let c1 = KanbanCard::from_event(&make_card(&board, None, "todo", 10)).unwrap();
        let c2 = KanbanCard::from_event(&make_card(&board, None, "todo", 20)).unwrap();
        assert_eq!(fold_cards(vec![c1, c2]).len(), 2);
    }

    // -- Approval bridge ---------------------------------------------------------

    use crate::keys::Keypair;
    use crate::signer::PrfSigner;

    /// Minimal synchronous executor for the I/O-free `PrfSigner` futures
    /// (same pattern as `gift_wrap::tests::block_on`).
    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
        fn noop(_: *const ()) {}
        fn clone(p: *const ()) -> RawWaker {
            RawWaker::new(p, &VTAB)
        }
        static VTAB: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
        let waker = unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTAB)) };
        let mut cx = Context::from_waker(&waker);
        let mut fut = std::pin::pin!(fut);
        loop {
            if let Poll::Ready(out) = fut.as_mut().poll(&mut cx) {
                return out;
            }
        }
    }

    fn test_signer() -> PrfSigner {
        let secret = crate::keys::SecretKey::from_bytes(test_key()).unwrap();
        let public = secret.public_key();
        PrfSigner::new(Keypair { secret, public })
    }

    #[test]
    fn approval_request_and_decision_roundtrip() {
        block_on(async {
            let signer = test_signer();
            let board = KanbanBoard::from_event(&make_board()).unwrap();
            let card = KanbanCard::from_event(&make_card(&board, None, "doing", 10)).unwrap();

            let request = create_card_approval_request_signer(&signer, &card, "done", "ready")
                .await
                .unwrap();
            assert_eq!(request.kind, 31402);
            assert!(verify_event(&request));
            assert!(is_kanban_approval_request(&request));
            // Governance validation requires a d tag; ours carries one.
            assert!(request.tags.iter().any(|t| t[0] == "d" && !t[1].is_empty()));
            assert_eq!(read_zone_tag(&request), Some("family"));

            // A non-kanban 31402 is not matched.
            let mut plain = request.clone();
            plain.tags.retain(|t| t[0] != "k");
            assert!(!is_kanban_approval_request(&plain));

            let approve = create_card_approval_response_signer(&signer, &request, true)
                .await
                .unwrap();
            assert_eq!(approve.kind, 31403);
            assert!(verify_event(&approve));
            let decision = parse_approval_decision(&approve).unwrap();
            assert_eq!(decision.request_id, request.id);
            assert!(decision.approved);
            assert_eq!(decision.board.as_deref(), Some(card.board.as_str()));
            assert_eq!(decision.card_d.as_deref(), Some(card.d_tag.as_str()));
            assert_eq!(decision.target_col.as_deref(), Some("done"));

            let reject = create_card_approval_response_signer(&signer, &request, false)
                .await
                .unwrap();
            let decision = parse_approval_decision(&reject).unwrap();
            assert!(!decision.approved);
        });
    }

    #[test]
    fn agent_intent_envelope() {
        block_on(async {
            let signer = test_signer();
            let board = KanbanBoard::from_event(&make_board()).unwrap();
            let card = KanbanCard::from_event(&make_card(&board, None, "todo", 10)).unwrap();
            let agent = "12".repeat(32);

            let intent = create_agent_intent_signer(&signer, &card, &agent, "please fix")
                .await
                .unwrap();
            assert_eq!(intent.kind, 38000);
            assert!(verify_event(&intent));
            assert!(intent.tags.iter().any(|t| t[0] == "p" && t[1] == agent));
            let body: serde_json::Value = serde_json::from_str(&intent.content).unwrap();
            assert_eq!(body["type"], "kanban_card_task");
            assert_eq!(body["title"], "Fix the gate");
            assert_eq!(body["instructions"], "please fix");
        });
    }

    #[test]
    fn deletion_tombstone_roundtrip_and_fold() {
        let board = KanbanBoard::from_event(&make_board()).unwrap();
        let live = KanbanCard::from_event(&make_card(&board, None, "todo", 10)).unwrap();
        assert!(!live.deleted);

        // Republish as a tombstone (any zone member may, per the fold model).
        let tomb_event = create_card(
            &test_key(),
            &CardInput {
                d_tag: Some(live.d_tag.clone()),
                board: live.board.clone(),
                title: live.title.clone(),
                description: live.description.clone(),
                column: live.column.clone(),
                rank: live.rank,
                assignees: live.assignees.clone(),
                due: live.due,
                zone: live.zone.clone(),
                pending_move: None,
                deleted: true,
            },
        )
        .unwrap();
        let mut tomb = KanbanCard::from_event(&tomb_event).unwrap();
        assert!(tomb.deleted);

        // The tombstone is the NEWEST version, so the fold surfaces it (the
        // client then hides deleted cards) — an older live sibling must not win.
        tomb.created_at = live.created_at + 10;
        let folded = fold_cards(vec![live.clone(), tomb.clone()]);
        assert_eq!(folded.len(), 1);
        assert!(folded[0].deleted);
        let folded_rev = fold_cards(vec![tomb, live]);
        assert!(folded_rev[0].deleted);
    }

    #[test]
    fn pending_move_tag_roundtrip() {
        let board = KanbanBoard::from_event(&make_board()).unwrap();
        let event = create_card(
            &test_key(),
            &CardInput {
                board: board.coord(),
                title: "T".into(),
                column: "doing".into(),
                pending_move: Some(("done".into(), "77".repeat(32))),
                zone: board.zone.clone(),
                ..Default::default()
            },
        )
        .unwrap();
        let card = KanbanCard::from_event(&event).unwrap();
        assert_eq!(
            card.pending_move,
            Some(("done".to_string(), "77".repeat(32)))
        );
    }
}
