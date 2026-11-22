-- Phase 2 follow-up (deepsec HIGH): bind each inbox key to its owner.
--
-- The auth-worker stores the member's verified kind-27237 registration proof
-- (signed by the member's identity key, `k` tag = the inbox key, with `exp`)
-- verbatim. The separate kind-27238 possession proof, signed by the inbox key,
-- is checked at registration and not stored. A grant issuer re-verifies the
-- stored proof before wrapping a zone key to the inbox key, so a wrong or
-- hostile row can never redirect zone keys. NULL for epoch rows and for rows
-- registered before this column existed; issuers refuse those.
ALTER TABLE recipient_keys ADD COLUMN proof TEXT;
