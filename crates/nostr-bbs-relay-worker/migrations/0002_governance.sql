-- Agent Control Surface Protocol: governance tables for kinds 31400-31405.
-- Idempotent — safe to re-run.

-- Registry of agent pubkeys allowed to publish governance events.
CREATE TABLE IF NOT EXISTS agent_registry (
    pubkey TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    registered_by TEXT NOT NULL,
    registered_at INTEGER NOT NULL,
    rate_limit_per_min INTEGER NOT NULL DEFAULT 60,
    active INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_agent_registry_active ON agent_registry(active);

-- Broker case aggregate: human-in-the-loop governance decisions.
CREATE TABLE IF NOT EXISTS broker_cases (
    id TEXT PRIMARY KEY NOT NULL,
    category TEXT NOT NULL,
    subject_kind TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    title TEXT NOT NULL,
    summary TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL DEFAULT 'open',
    priority INTEGER NOT NULL DEFAULT 50,
    from_share_state TEXT,
    to_share_state TEXT,
    created_by TEXT NOT NULL,
    assigned_to TEXT,
    nostr_event_id TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_broker_cases_state ON broker_cases(state);
CREATE INDEX IF NOT EXISTS idx_broker_cases_category ON broker_cases(category);
CREATE INDEX IF NOT EXISTS idx_broker_cases_assigned ON broker_cases(assigned_to);

-- Individual decisions on broker cases (append-only audit trail).
CREATE TABLE IF NOT EXISTS broker_decisions (
    decision_id TEXT PRIMARY KEY NOT NULL,
    case_id TEXT NOT NULL REFERENCES broker_cases(id),
    outcome TEXT NOT NULL,
    outcome_detail TEXT,
    broker_pubkey TEXT NOT NULL,
    reasoning TEXT NOT NULL DEFAULT '',
    prior_decision_id TEXT,
    decided_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_broker_decisions_case ON broker_decisions(case_id);

-- Role assignments for broker governance.
CREATE TABLE IF NOT EXISTS broker_roles (
    pubkey TEXT NOT NULL,
    role TEXT NOT NULL,
    granted_by TEXT NOT NULL,
    granted_at INTEGER NOT NULL,
    PRIMARY KEY (pubkey, role)
);
CREATE INDEX IF NOT EXISTS idx_broker_roles_pubkey ON broker_roles(pubkey);
