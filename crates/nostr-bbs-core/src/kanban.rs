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
//!   31402s, which stay agent-registry-gated). The relay also verifies the
//!   *entry*: a non-admin card version that enters an approval column must
//!   follow a stored, admin-approved, unspent request
//!   ([`check_approved_entry`]; `KANBAN_APPROVAL_GATE`, `warn` by default).
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
            title: tag_value(event, "title")
                .unwrap_or("Untitled board")
                .to_string(),
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
    let signing_key = SigningKey::from_bytes((privkey).into())
        .map_err(|e| KanbanError::InvalidKey(e.to_string()))?;
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
    let signing_key = SigningKey::from_bytes((privkey).into())
        .map_err(|e| KanbanError::InvalidKey(e.to_string()))?;
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
        vec!["a".to_string(), card_coord(&card.pubkey, &card.d_tag)],
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
    let content = crate::governance::canonical_json_string(&serde_json::json!({
        "fields": {
            "card_title": card.title,
            "card_d": card.d_tag,
            "board": card.board,
            "target_col": target_col,
        },
        "reasoning": summary,
        "risk_tier": "medium",
    }));
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

/// The request a kanban 31403 is bound to: the value of an `e` tag marked
/// `request`, else the first unmarked `e` tag (the shape the forum client
/// signs). A tag with any other marker (`supersedes`, `appeal`, ...) never
/// binds a kanban decision, unlike the case projection's appeal fallback.
/// The relay gate and the client both use this rule, so they agree on which
/// request a decision decides.
pub fn decision_request_link(event: &NostrEvent) -> Option<&str> {
    let e_tags = || event.tags.iter().filter(|t| t.len() >= 2 && t[0] == "e");
    e_tags()
        .find(|t| t.get(3).is_some_and(|m| m == "request"))
        .or_else(|| e_tags().find(|t| t.get(3).is_none_or(|m| m.is_empty())))
        .map(|t| t[1].as_str())
}

/// Parse a kind-31403 ActionResponse into a kanban [`ApprovalDecision`].
/// Returns `None` for other kinds, responses without an `e` reference, or
/// contents that don't parse to Approve/Reject.
pub fn parse_approval_decision(event: &NostrEvent) -> Option<ApprovalDecision> {
    if event.kind != crate::governance::KIND_ACTION_RESPONSE {
        return None;
    }
    let request_id = decision_request_link(event)?.to_string();
    let approved =
        match crate::governance::broker::DecisionOutcome::from_response_content(&event.content)? {
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

// -- Relay approval gate -----------------------------------------------------------

/// Whether publishing `incoming` is an *entry* into an approval-gated column.
///
/// True when the board is known, lists `incoming.column` in its approval
/// columns, and the latest prior version of the card (if any) sits in a
/// different column. A card with no prior version counts as entering. Edits,
/// claims, reranks and tombstones that leave the card where it already is are
/// not entries, so cards already sitting in an approval column are
/// grandfathered.
pub fn entry_requires_approval(
    board: Option<&KanbanBoard>,
    prior: Option<&KanbanCard>,
    incoming: &KanbanCard,
) -> bool {
    let Some(board) = board else {
        return false;
    };
    board.column_needs_approval(&incoming.column)
        && prior.map(|p| p.column != incoming.column).unwrap_or(true)
}

/// How far in the future a card version may be dated before the gate treats it
/// as an entry regardless of the prior version (seconds). A future-dated
/// version would otherwise win the fold over any later, legitimate move.
pub const FUTURE_SKEW_SECS: u64 = 600;

/// [`entry_requires_approval`], plus: a version dated more than
/// [`FUTURE_SKEW_SECS`] after `now` that sits in an approval column is treated
/// as an entry even when the prior version is in the same column.
pub fn entry_requires_approval_at(
    board: Option<&KanbanBoard>,
    prior: Option<&KanbanCard>,
    incoming: &KanbanCard,
    now: u64,
) -> bool {
    if entry_requires_approval(board, prior, incoming) {
        return true;
    }
    board.is_some_and(|b| b.column_needs_approval(&incoming.column))
        && incoming.created_at > now.saturating_add(FUTURE_SKEW_SECS)
}

/// The latest admin-signed kind-31403 that cites an approval request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionFacts<'a> {
    /// Event id of the decision.
    pub event_id: &'a str,
    /// `true` for Approve, `false` for Reject.
    pub approved: bool,
    /// The decider's effective principal (device key resolved to its owner).
    pub decider_principal: &'a str,
    /// The decision's `created_at`, from which the approval's lifetime runs.
    pub signed_at: u64,
}

/// Everything [`check_approved_entry`] needs, gathered by the caller.
///
/// The core crate does no I/O: the relay reads the prior card version, the
/// request, the decision and the spent-approval table, then hands the facts in.
#[derive(Debug, Clone)]
pub struct ApprovalFacts<'a> {
    /// The card version being published.
    pub incoming: &'a KanbanCard,
    /// The latest stored version of the same card, if any.
    pub prior: Option<&'a KanbanCard>,
    /// The stored event the prior version's `pending_move` names, if found.
    pub request: Option<&'a NostrEvent>,
    /// The request signer's effective principal. When `None`, the request's
    /// own `pubkey` is used.
    pub requester_principal: Option<&'a str>,
    /// The latest admin-signed decision citing the request, if any.
    pub decision: Option<DecisionFacts<'a>>,
    /// The card event id that already spent this approval, if any.
    pub consumed_by: Option<&'a str>,
    /// The current time (unix seconds).
    pub now: u64,
    /// How long an approval stays usable, counted from the decision's
    /// `created_at`.
    pub ttl_secs: u64,
}

/// An entry the gate has admitted: the facts to record as spent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedEntry {
    /// The kind-31402 request being spent.
    pub request_id: String,
    /// The kind-31403 decision that approved it.
    pub decision_id: String,
    /// Board coordinate of the card.
    pub board: String,
    /// The card's `d` tag.
    pub card_d: String,
    /// The approval column entered.
    pub target_col: String,
}

/// Why the relay refused a card version that enters an approval column.
///
/// Each variant has a stable wire token, see [`ApprovalRefusal::token`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalRefusal {
    /// The prior version carries no `pending_move`.
    Missing,
    /// The `pending_move` target, or the request's `target_col`, differs from
    /// the column being entered.
    ColumnMismatch,
    /// The request is not stored, or is not a kanban 31402.
    RequestMissing,
    /// The request's `board` or `card_d` differs from the card's.
    CardMismatch,
    /// No admin-signed 31403 cites the request.
    Undecided,
    /// The latest eligible decision is Reject.
    Denied,
    /// The decider and the requester resolve to one principal.
    SelfReview,
    /// The request was already spent on a different card event.
    Consumed,
    /// A storage error after the entry was found to be gated.
    Unverifiable,
    /// The incoming version does not beat the prior one in fold order, so it
    /// would not become the card's current version.
    Stale,
    /// The approval is older than its lifetime.
    Expired,
}

impl ApprovalRefusal {
    /// The stable machine token, sent to the client as `blocked: <token>`.
    pub fn token(&self) -> &'static str {
        match self {
            Self::Missing => "kanban_approval_missing",
            Self::ColumnMismatch => "kanban_approval_column_mismatch",
            Self::RequestMissing => "kanban_approval_request_missing",
            Self::CardMismatch => "kanban_approval_card_mismatch",
            Self::Undecided => "kanban_approval_undecided",
            Self::Denied => "kanban_approval_denied",
            Self::SelfReview => "kanban_approval_self_review",
            Self::Consumed => "kanban_approval_consumed",
            Self::Unverifiable => "kanban_approval_unverifiable",
            Self::Stale => "kanban_approval_stale",
            Self::Expired => "kanban_approval_expired",
        }
    }
}

/// Decide whether a card version that enters an approval column carries a
/// valid, unspent, human approval.
///
/// The caller has already established the entry is gated
/// ([`entry_requires_approval`]). Checks run in this order and the first
/// failure wins: [`Missing`](ApprovalRefusal::Missing),
/// [`ColumnMismatch`](ApprovalRefusal::ColumnMismatch) (pending target),
/// [`RequestMissing`](ApprovalRefusal::RequestMissing),
/// [`CardMismatch`](ApprovalRefusal::CardMismatch),
/// [`ColumnMismatch`](ApprovalRefusal::ColumnMismatch) (request target),
/// [`Undecided`](ApprovalRefusal::Undecided),
/// [`SelfReview`](ApprovalRefusal::SelfReview),
/// [`Denied`](ApprovalRefusal::Denied),
/// [`Consumed`](ApprovalRefusal::Consumed),
/// [`Expired`](ApprovalRefusal::Expired); [`Stale`](ApprovalRefusal::Stale)
/// follows the pending-target check. Principals compare
/// case-insensitively. A redelivery of the card event that already spent the
/// approval (`consumed_by == incoming.id`) is admitted.
///
/// The request is matched on `board` + `card_d`, never on its `a` tag, because
/// the `a` tag carries the coordinate of whichever author published the card
/// version that raised the request.
pub fn check_approved_entry(f: &ApprovalFacts<'_>) -> Result<ApprovedEntry, ApprovalRefusal> {
    let Some(prior) = f.prior else {
        return Err(ApprovalRefusal::Missing);
    };
    let Some((pending_col, request_id)) = prior.pending_move.as_ref() else {
        return Err(ApprovalRefusal::Missing);
    };
    if *pending_col != f.incoming.column {
        return Err(ApprovalRefusal::ColumnMismatch);
    }
    // Fold order: a version that would not become the card's current one must
    // not claim an approval (a past-dated entry would burn it for nothing).
    let beats_prior = f.incoming.created_at > prior.created_at
        || (f.incoming.created_at == prior.created_at && f.incoming.id < prior.id);
    if !beats_prior {
        return Err(ApprovalRefusal::Stale);
    }
    let request = match f.request {
        Some(r) if is_kanban_approval_request(r) && r.id == *request_id => r,
        _ => return Err(ApprovalRefusal::RequestMissing),
    };
    if tag_value(request, "board") != Some(f.incoming.board.as_str())
        || tag_value(request, "card_d") != Some(f.incoming.d_tag.as_str())
    {
        return Err(ApprovalRefusal::CardMismatch);
    }
    if tag_value(request, "target_col") != Some(f.incoming.column.as_str()) {
        return Err(ApprovalRefusal::ColumnMismatch);
    }
    let Some(decision) = f.decision.as_ref() else {
        return Err(ApprovalRefusal::Undecided);
    };
    let requester = f.requester_principal.unwrap_or(request.pubkey.as_str());
    if decision.decider_principal.eq_ignore_ascii_case(requester) {
        return Err(ApprovalRefusal::SelfReview);
    }
    if !decision.approved {
        return Err(ApprovalRefusal::Denied);
    }
    let redelivery = f.consumed_by == Some(f.incoming.id.as_str());
    if let Some(spent_on) = f.consumed_by {
        if spent_on != f.incoming.id {
            return Err(ApprovalRefusal::Consumed);
        }
    }
    if !redelivery && f.now > decision.signed_at.saturating_add(f.ttl_secs) {
        return Err(ApprovalRefusal::Expired);
    }
    Ok(ApprovedEntry {
        request_id: request.id.clone(),
        decision_id: decision.event_id.to_string(),
        board: f.incoming.board.clone(),
        card_d: f.incoming.d_tag.clone(),
        target_col: f.incoming.column.clone(),
    })
}

/// What a client may show for a card's pending move.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingMoveState {
    /// No eligible decision yet.
    Awaiting,
    /// The latest eligible decision approves the move.
    Approved,
    /// The latest eligible decision rejects it.
    Rejected,
}

/// The client-side mirror of the relay gate's decision rules, for badges and
/// the finalise button. Returns `None` (show nothing) when the card has no
/// pending move or `request` is not the kanban request for exactly this card
/// and target column.
///
/// A decision counts only if `is_admin(signer)` holds and it binds the request
/// through [`decision_request_link`]. The latest by `(created_at DESC, id ASC)`
/// wins. A decision signed by the requester's own key is ignored (the relay
/// refuses self-review). A client that cannot tell who is an admin passes
/// `|_| true`; the relay stays the authority either way.
pub fn evaluate_pending_move<F: Fn(&str) -> bool>(
    card: &KanbanCard,
    request: Option<&NostrEvent>,
    decisions: &[NostrEvent],
    is_admin: F,
) -> Option<PendingMoveState> {
    let (target, request_id) = card.pending_move.as_ref()?;
    let request = request?;
    if !is_kanban_approval_request(request)
        || request.id != *request_id
        || tag_value(request, "board") != Some(card.board.as_str())
        || tag_value(request, "card_d") != Some(card.d_tag.as_str())
        || tag_value(request, "target_col") != Some(target.as_str())
    {
        return None;
    }
    let latest = decisions
        .iter()
        .filter(|d| is_admin(&d.pubkey))
        .filter(|d| d.pubkey != request.pubkey)
        .filter_map(|d| parse_approval_decision(d).map(|p| (d, p)))
        .filter(|(_, p)| p.request_id == *request_id)
        .min_by(|(a, _), (b, _)| {
            b.created_at
                .cmp(&a.created_at)
                .then_with(|| a.id.cmp(&b.id))
        });
    Some(match latest {
        None => PendingMoveState::Awaiting,
        Some((_, p)) if p.approved => PendingMoveState::Approved,
        Some(_) => PendingMoveState::Rejected,
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
    // `actor` names the agent explicitly. Without it a consumer that falls back
    // to the `a` coordinate would read the card's own d-tag as the actor.
    let mut tags = vec![
        vec!["p".to_string(), agent_pubkey.to_string()],
        vec!["actor".to_string(), agent_pubkey.to_string()],
        vec!["a".to_string(), card_coord(&card.pubkey, &card.d_tag)],
        vec!["board".to_string(), card.board.clone()],
        vec!["card_d".to_string(), card.d_tag.clone()],
    ];
    if let Some(z) = &card.zone {
        tags.push(vec![crate::calendar::ZONE_TAG.to_string(), z.clone()]);
    }
    let content = crate::governance::canonical_json_string(&serde_json::json!({
        "type": "kanban_card_task",
        "title": card.title,
        "description": card.description,
        "board": card.board,
        "card_d": card.d_tag,
        "column": card.column,
        "due": card.due,
        "instructions": instructions,
    }));
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

    /// The intent names the agent explicitly: `actor` equals `p` and is never
    /// the card's d-tag (AB-INTENT-ACTOR-FROM-CARD-DTAG).
    #[test]
    fn agent_intent_actor_tag_is_the_agent_not_the_card() {
        block_on(async {
            let signer = test_signer();
            let board = KanbanBoard::from_event(&make_board()).unwrap();
            let card = KanbanCard::from_event(&make_card(&board, None, "todo", 10)).unwrap();
            let agent = "12".repeat(32);
            let intent = create_agent_intent_signer(&signer, &card, &agent, "please fix")
                .await
                .unwrap();
            let values = |name: &str| -> Vec<&str> {
                intent
                    .tags
                    .iter()
                    .filter(|t| t[0] == name)
                    .map(|t| t[1].as_str())
                    .collect()
            };
            assert_eq!(values("actor"), vec![agent.as_str()]);
            assert_eq!(values("actor"), values("p"));
            assert!(!values("actor").contains(&card.d_tag.as_str()));
        });
    }

    /// The task envelope is signed content, so its bytes (and so the event id)
    /// must not depend on whether a crate in the build turned on serde_json's
    /// `preserve_order`. This crate's dev-dependencies turn it on, so this test
    /// runs in the insertion-ordered build, where `json!(..).to_string()` would
    /// write `type` first.
    #[test]
    fn agent_intent_content_is_key_sorted_in_every_build() {
        block_on(async {
            let signer = test_signer();
            let board = KanbanBoard::from_event(&make_board()).unwrap();
            let card = KanbanCard::from_event(&make_card(&board, None, "todo", 10)).unwrap();
            let agent = "12".repeat(32);
            let intent = create_agent_intent_signer(&signer, &card, &agent, "please fix")
                .await
                .unwrap();
            let keys: Vec<&str> = intent
                .content
                .trim_matches(|c| c == '{' || c == '}')
                .split(",\"")
                .map(|kv| kv.trim_start_matches('"').split('"').next().unwrap())
                .collect();
            assert_eq!(
                keys,
                [
                    "board",
                    "card_d",
                    "column",
                    "description",
                    "due",
                    "instructions",
                    "title",
                    "type"
                ]
            );
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

    // -- Relay approval gate -----------------------------------------------------

    const BOARD_COORD: &str = "30301:aa:board1";

    fn gate_board(approval: &[&str]) -> KanbanBoard {
        KanbanBoard {
            id: "b1".into(),
            pubkey: "aa".into(),
            d_tag: "board1".into(),
            title: "B".into(),
            description: String::new(),
            columns: vec![],
            approval_columns: approval.iter().map(|c| c.to_string()).collect(),
            maintainers: vec![],
            zone: Some("family".into()),
            created_at: 1,
        }
    }

    fn gate_card(id: &str, col: &str, pending: Option<(&str, &str)>) -> KanbanCard {
        KanbanCard {
            id: id.into(),
            pubkey: "cc".into(),
            d_tag: "card1".into(),
            board: BOARD_COORD.into(),
            title: "T".into(),
            description: String::new(),
            column: col.into(),
            rank: 0,
            assignees: vec![],
            due: None,
            zone: Some("family".into()),
            pending_move: pending.map(|(c, r)| (c.to_string(), r.to_string())),
            deleted: false,
            created_at: 10,
        }
    }

    fn gate_request(id: &str, board: &str, card_d: &str, target: &str, k: bool) -> NostrEvent {
        let mut tags = vec![
            vec!["d".to_string(), "req-d".to_string()],
            vec!["board".to_string(), board.to_string()],
            vec!["card_d".to_string(), card_d.to_string()],
            vec!["target_col".to_string(), target.to_string()],
            // Deliberately the requester's own coordinate, not the board's.
            vec!["a".to_string(), "30302:cc:card1".to_string()],
        ];
        if k {
            tags.push(vec!["k".to_string(), "30302".to_string()]);
        }
        NostrEvent {
            id: id.into(),
            pubkey: "dd".into(),
            created_at: 5,
            kind: crate::governance::KIND_ACTION_REQUEST,
            tags,
            content: String::new(),
            sig: String::new(),
        }
    }

    const R: &str = "r1";

    fn decision<'a>(approved: bool, decider: &'a str) -> Option<DecisionFacts<'a>> {
        Some(DecisionFacts {
            event_id: "dec1",
            approved,
            decider_principal: decider,
            signed_at: 100,
        })
    }

    struct Honest {
        incoming: KanbanCard,
        prior: KanbanCard,
        request: NostrEvent,
    }

    fn honest() -> Honest {
        Honest {
            incoming: {
                let mut c = gate_card("fin", "done", None);
                c.created_at = 20;
                c
            },
            prior: gate_card("pend", "doing", Some(("done", R))),
            request: gate_request(R, BOARD_COORD, "card1", "done", true),
        }
    }

    fn facts<'a>(h: &'a Honest, decision: Option<DecisionFacts<'a>>) -> ApprovalFacts<'a> {
        ApprovalFacts {
            incoming: &h.incoming,
            prior: Some(&h.prior),
            request: Some(&h.request),
            requester_principal: None,
            decision,
            consumed_by: None,
            now: 200,
            ttl_secs: 1000,
        }
    }

    #[test]
    fn gate_honest_path_is_admitted() {
        let h = honest();
        let entry = check_approved_entry(&facts(&h, decision(true, "ee"))).unwrap();
        assert_eq!(entry.request_id, R);
        assert_eq!(entry.decision_id, "dec1");
        assert_eq!(entry.board, BOARD_COORD);
        assert_eq!(entry.card_d, "card1");
        assert_eq!(entry.target_col, "done");
    }

    #[test]
    fn gate_no_pending_move_is_missing() {
        let mut h = honest();
        h.prior.pending_move = None;
        assert_eq!(
            check_approved_entry(&facts(&h, decision(true, "ee"))),
            Err(ApprovalRefusal::Missing)
        );
        let mut f = facts(&h, decision(true, "ee"));
        f.prior = None;
        assert_eq!(check_approved_entry(&f), Err(ApprovalRefusal::Missing));
    }

    #[test]
    fn gate_no_decision_is_undecided() {
        let h = honest();
        assert_eq!(
            check_approved_entry(&facts(&h, None)),
            Err(ApprovalRefusal::Undecided)
        );
    }

    #[test]
    fn gate_reject_is_denied() {
        let h = honest();
        assert_eq!(
            check_approved_entry(&facts(&h, decision(false, "ee"))),
            Err(ApprovalRefusal::Denied)
        );
    }

    #[test]
    fn gate_card_a_approval_on_card_b_is_card_mismatch() {
        let mut h = honest();
        h.request = gate_request(R, BOARD_COORD, "other-card", "done", true);
        assert_eq!(
            check_approved_entry(&facts(&h, decision(true, "ee"))),
            Err(ApprovalRefusal::CardMismatch)
        );
        h.request = gate_request(R, "30301:aa:other-board", "card1", "done", true);
        assert_eq!(
            check_approved_entry(&facts(&h, decision(true, "ee"))),
            Err(ApprovalRefusal::CardMismatch)
        );
    }

    #[test]
    fn gate_column_x_approval_for_column_y_is_column_mismatch() {
        // Pending target differs from the column entered.
        let mut h = honest();
        h.incoming.column = "review".into();
        assert_eq!(
            check_approved_entry(&facts(&h, decision(true, "ee"))),
            Err(ApprovalRefusal::ColumnMismatch)
        );
        // Pending target matches, but the stored request was for another column.
        let mut h = honest();
        h.request = gate_request(R, BOARD_COORD, "card1", "review", true);
        assert_eq!(
            check_approved_entry(&facts(&h, decision(true, "ee"))),
            Err(ApprovalRefusal::ColumnMismatch)
        );
    }

    #[test]
    fn gate_spent_approval_copied_back_is_consumed() {
        let h = honest();
        let mut f = facts(&h, decision(true, "ee"));
        f.consumed_by = Some("earlier-finalise");
        assert_eq!(check_approved_entry(&f), Err(ApprovalRefusal::Consumed));
    }

    #[test]
    fn gate_self_review_is_refused_including_aliases_and_case() {
        let h = honest();
        // Requester "dd" decided by the same key.
        assert_eq!(
            check_approved_entry(&facts(&h, decision(true, "dd"))),
            Err(ApprovalRefusal::SelfReview)
        );
        // Requester device key resolved to its owner, who is the decider.
        let mut f = facts(&h, decision(true, "ab12"));
        f.requester_principal = Some("ab12");
        assert_eq!(check_approved_entry(&f), Err(ApprovalRefusal::SelfReview));
        // Mixed-case hex still collides.
        let mut f = facts(&h, decision(true, "AB12"));
        f.requester_principal = Some("ab12");
        assert_eq!(check_approved_entry(&f), Err(ApprovalRefusal::SelfReview));
    }

    #[test]
    fn gate_request_missing_or_not_kanban() {
        let mut h = honest();
        let mut f = facts(&h, decision(true, "ee"));
        f.request = None;
        assert_eq!(
            check_approved_entry(&f),
            Err(ApprovalRefusal::RequestMissing)
        );
        h.request = gate_request(R, BOARD_COORD, "card1", "done", false);
        assert_eq!(
            check_approved_entry(&facts(&h, decision(true, "ee"))),
            Err(ApprovalRefusal::RequestMissing)
        );
        // A different stored event than the one the pending move names.
        let mut h = honest();
        h.request.id = "someone-else".into();
        assert_eq!(
            check_approved_entry(&facts(&h, decision(true, "ee"))),
            Err(ApprovalRefusal::RequestMissing)
        );
    }

    #[test]
    fn gate_non_entries_are_not_gated() {
        let board = gate_board(&["done"]);
        // Edit, claim, rerank: prior and incoming both already in `done`.
        let prior = gate_card("p", "done", None);
        let mut edit = gate_card("e", "done", None);
        edit.rank = 99;
        assert!(!entry_requires_approval(Some(&board), Some(&prior), &edit));
        // A tombstone of a card already in `done`.
        let mut tomb = gate_card("t", "done", None);
        tomb.deleted = true;
        assert!(!entry_requires_approval(Some(&board), Some(&prior), &tomb));
        // Moving into a column that is not an approval column.
        let into_todo = gate_card("m", "todo", None);
        assert!(!entry_requires_approval(
            Some(&board),
            Some(&prior),
            &into_todo
        ));
    }

    #[test]
    fn gate_tombstone_that_enters_is_gated() {
        let board = gate_board(&["done"]);
        let prior = gate_card("p", "doing", None);
        let mut tomb = gate_card("t", "done", None);
        tomb.deleted = true;
        assert!(entry_requires_approval(Some(&board), Some(&prior), &tomb));
    }

    #[test]
    fn gate_new_card_straight_into_approval_column_is_gated() {
        let board = gate_board(&["done"]);
        let fresh = gate_card("n", "done", None);
        assert!(entry_requires_approval(Some(&board), None, &fresh));
    }

    #[test]
    fn gate_adr_2035_agent_republish_is_not_gated() {
        // The agent keeps `s` on its own column and sets pending_move plus
        // result/run; that version is not an entry into the approval column.
        let board = gate_board(&["review"]);
        let prior = gate_card("p", "todo", None);
        let agent = gate_card("a", "agent", Some(("review", R)));
        assert!(!entry_requires_approval(Some(&board), Some(&prior), &agent));
        // Setting `s` straight to the approval column would be gated.
        let direct = gate_card("d", "review", Some(("review", R)));
        assert!(entry_requires_approval(Some(&board), Some(&prior), &direct));
    }

    #[test]
    fn gate_board_that_drops_the_column_is_not_gated() {
        // Policy is owned by the board's author: removing the approval column
        // from the latest board version lifts the gate.
        let incoming = gate_card("i", "done", None);
        let prior = gate_card("p", "doing", None);
        let relaxed = gate_board(&[]);
        assert!(!entry_requires_approval(
            Some(&relaxed),
            Some(&prior),
            &incoming
        ));
        // An unknown board never gates.
        assert!(!entry_requires_approval(None, Some(&prior), &incoming));
    }

    #[test]
    fn gate_redelivery_of_the_spending_event_is_admitted() {
        let h = honest();
        let mut f = facts(&h, decision(true, "ee"));
        f.consumed_by = Some("fin");
        assert!(check_approved_entry(&f).is_ok());
    }

    #[test]
    fn gate_stale_incoming_is_refused() {
        // Older than the prior: it would not become the current version.
        let mut h = honest();
        h.incoming.created_at = 5;
        assert_eq!(
            check_approved_entry(&facts(&h, decision(true, "ee"))),
            Err(ApprovalRefusal::Stale)
        );
        // Equal time: the lower id wins the fold; a higher id is stale.
        let mut h = honest();
        h.incoming.created_at = h.prior.created_at;
        h.incoming.id = "zzz".into();
        assert_eq!(
            check_approved_entry(&facts(&h, decision(true, "ee"))),
            Err(ApprovalRefusal::Stale)
        );
        h.incoming.id = "aaa".into();
        assert!(check_approved_entry(&facts(&h, decision(true, "ee"))).is_ok());
    }

    #[test]
    fn gate_expired_approval_is_refused_but_a_redelivery_is_not() {
        let h = honest();
        let mut f = facts(&h, decision(true, "ee"));
        f.now = 100 + 1000; // exactly at the limit: still valid
        assert!(check_approved_entry(&f).is_ok());
        f.now = 100 + 1001;
        assert_eq!(check_approved_entry(&f), Err(ApprovalRefusal::Expired));
        f.consumed_by = Some("fin");
        assert!(
            check_approved_entry(&f).is_ok(),
            "redelivery is not re-expired"
        );
    }

    #[test]
    fn gate_future_dated_version_in_the_column_is_an_entry() {
        let board = gate_board(&["done"]);
        let prior = gate_card("p", "done", None);
        let mut future = gate_card("f", "done", None);
        future.created_at = 1_000 + FUTURE_SKEW_SECS + 1;
        assert!(entry_requires_approval_at(
            Some(&board),
            Some(&prior),
            &future,
            1_000
        ));
        future.created_at = 1_000 + FUTURE_SKEW_SECS;
        assert!(!entry_requires_approval_at(
            Some(&board),
            Some(&prior),
            &future,
            1_000
        ));
        // Not an approval column: skew does not matter.
        let mut other = gate_card("o", "todo", None);
        other.created_at = u64::MAX;
        assert!(!entry_requires_approval_at(
            Some(&board),
            Some(&prior),
            &other,
            1_000
        ));
    }

    fn resp(id: &str, signer: &str, at: u64, tags: Vec<Vec<String>>, approve: bool) -> NostrEvent {
        NostrEvent {
            id: id.into(),
            pubkey: signer.into(),
            created_at: at,
            kind: crate::governance::KIND_ACTION_RESPONSE,
            tags,
            content: if approve {
                r#"{"action":"approve"}"#
            } else {
                r#"{"action":"reject"}"#
            }
            .into(),
            sig: String::new(),
        }
    }

    fn e_tag(parts: &[&str]) -> Vec<String> {
        let mut t = vec!["e".to_string()];
        t.extend(parts.iter().map(|s| s.to_string()));
        t
    }

    #[test]
    fn decision_link_rule_ignores_appeal_and_supersedes_markers() {
        let plain = resp("a", "x", 1, vec![e_tag(&["r1"])], true);
        assert_eq!(decision_request_link(&plain), Some("r1"));
        let marked = resp("b", "x", 1, vec![e_tag(&["r1", "", "request"])], true);
        assert_eq!(decision_request_link(&marked), Some("r1"));
        // `request` wins over an earlier unmarked tag.
        let both = resp(
            "c",
            "x",
            1,
            vec![e_tag(&["old"]), e_tag(&["r1", "", "request"])],
            true,
        );
        assert_eq!(decision_request_link(&both), Some("r1"));
        for marker in ["appeal", "supersedes"] {
            let ev = resp("d", "x", 1, vec![e_tag(&["r1", "", marker])], true);
            assert_eq!(decision_request_link(&ev), None, "{marker}");
            assert!(parse_approval_decision(&ev).is_none(), "{marker}");
        }
    }

    #[test]
    fn evaluate_pending_move_follows_the_relay_rules() {
        let card = gate_card("pend", "doing", Some(("done", R)));
        let req = gate_request(R, BOARD_COORD, "card1", "done", true);
        let ok = resp("d1", "ee", 10, vec![e_tag(&[R])], true);
        let any = |_: &str| true;
        assert_eq!(
            evaluate_pending_move(&card, Some(&req), &[], any),
            Some(PendingMoveState::Awaiting)
        );
        assert_eq!(
            evaluate_pending_move(&card, Some(&req), std::slice::from_ref(&ok), any),
            Some(PendingMoveState::Approved)
        );
        // A later reject wins.
        let rej = resp("d2", "ee", 20, vec![e_tag(&[R])], false);
        assert_eq!(
            evaluate_pending_move(&card, Some(&req), &[ok.clone(), rej], any),
            Some(PendingMoveState::Rejected)
        );
        // Non-admin signer, self-review and a foreign request id do not count.
        assert_eq!(
            evaluate_pending_move(&card, Some(&req), std::slice::from_ref(&ok), |_| false),
            Some(PendingMoveState::Awaiting)
        );
        let own = resp("d3", "dd", 10, vec![e_tag(&[R])], true);
        assert_eq!(
            evaluate_pending_move(&card, Some(&req), &[own], any),
            Some(PendingMoveState::Awaiting)
        );
        let other = resp("d4", "ee", 10, vec![e_tag(&["r2"])], true);
        assert_eq!(
            evaluate_pending_move(&card, Some(&req), &[other], any),
            Some(PendingMoveState::Awaiting)
        );
    }

    #[test]
    fn evaluate_pending_move_ignores_an_approval_copied_onto_another_card() {
        // H1: an approved R copied onto a different card must not show.
        let ok = resp("d1", "ee", 10, vec![e_tag(&[R])], true);
        let req = gate_request(R, BOARD_COORD, "card1", "done", true);
        let mut other = gate_card("pend", "doing", Some(("done", R)));
        other.d_tag = "someone-elses-card".into();
        assert_eq!(
            evaluate_pending_move(&other, Some(&req), std::slice::from_ref(&ok), |_| true),
            None
        );
        // Wrong target column, unknown request, and no pending move at all.
        let card = gate_card("pend", "doing", Some(("review", R)));
        assert_eq!(
            evaluate_pending_move(&card, Some(&req), std::slice::from_ref(&ok), |_| true),
            None
        );
        let card = gate_card("pend", "doing", Some(("done", R)));
        assert_eq!(
            evaluate_pending_move(&card, None, std::slice::from_ref(&ok), |_| true),
            None
        );
        let plain = gate_card("p", "doing", None);
        assert_eq!(
            evaluate_pending_move(&plain, Some(&req), &[ok], |_| true),
            None
        );
    }

    #[test]
    fn gate_refusal_tokens_are_stable() {
        use ApprovalRefusal::*;
        let all = [
            (Missing, "kanban_approval_missing"),
            (ColumnMismatch, "kanban_approval_column_mismatch"),
            (RequestMissing, "kanban_approval_request_missing"),
            (CardMismatch, "kanban_approval_card_mismatch"),
            (Undecided, "kanban_approval_undecided"),
            (Denied, "kanban_approval_denied"),
            (SelfReview, "kanban_approval_self_review"),
            (Consumed, "kanban_approval_consumed"),
            (Unverifiable, "kanban_approval_unverifiable"),
            (Stale, "kanban_approval_stale"),
            (Expired, "kanban_approval_expired"),
        ];
        for (r, t) in all {
            assert_eq!(r.token(), t);
        }
    }
}
