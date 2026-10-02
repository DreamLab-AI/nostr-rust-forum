-- Migration 0004: the pod-worker's credit journal (ADR-2012 D1, D6)
--
-- The pod-worker's /pay/ ledger lives in this database (its REPLAY_DB binding
-- is nostr-bbs-auth). Every credit to `webledger_accounts` is a row here that
-- names its evidence: a deposit's outpoint keyed with its chain
-- (credit_ref = 'txo:<chain>:<txid>:<vout>'), or the NIP-98 signed request
-- that released a job hold (credit_ref = 'job:<job_id>:release'). The CHECK
-- refuses a row with neither. Additive: no existing table or row is touched;
-- the legacy `txo_deposits` receipts stay as a read-only replay guard.
--
-- Applied idempotently at worker start-up by the pod-worker's
-- `payments::ensure_payment_schema`, which runs the identical DDL
-- (`pay_ledger::DDL_PAY_CREDITS`; a test compares the two).

-- UP:
CREATE TABLE IF NOT EXISTS pay_credits (
    credit_ref TEXT PRIMARY KEY,
    did TEXT NOT NULL,
    amount_sats INTEGER NOT NULL CHECK (amount_sats >= 0),
    kind TEXT NOT NULL CHECK (kind IN ('deposit', 'job-release')),
    chain TEXT,
    txid TEXT,
    vout INTEGER,
    request_id TEXT,
    applied INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    CHECK ((chain IS NOT NULL AND txid IS NOT NULL AND vout IS NOT NULL)
           OR request_id IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS pay_credits_did ON pay_credits (did);
-- DOWN: DROP INDEX pay_credits_did; DROP TABLE pay_credits;
