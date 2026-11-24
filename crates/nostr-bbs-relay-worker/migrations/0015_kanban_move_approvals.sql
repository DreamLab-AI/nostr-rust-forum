-- One row per kanban approval request (31402) spent on a card move: one
-- approval admits one entry into an approval column. Idempotent.
-- Held identical to KANBAN_MOVE_APPROVALS_CREATE_SQL / _INDEX_SQL in
-- src/relay_do/kanban_gate.rs (mirrored into ensure_schema) by a test.
CREATE TABLE IF NOT EXISTS kanban_move_approvals (
  request_event_id TEXT PRIMARY KEY NOT NULL,
  board TEXT NOT NULL,
  card_d TEXT NOT NULL,
  target_col TEXT NOT NULL,
  decision_event_id TEXT NOT NULL,
  card_event_id TEXT NOT NULL,
  gate_mode TEXT NOT NULL,          -- warn | enforce at claim time
  consumed_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_kanban_move_approvals_card
  ON kanban_move_approvals(board, card_d);
