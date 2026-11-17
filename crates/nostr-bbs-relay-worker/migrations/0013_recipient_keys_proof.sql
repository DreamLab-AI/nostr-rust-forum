-- Phase 2 follow-up (deepsec HIGH): bind each inbox key to its owner.
--
-- The auth-worker stores the member's verified kind-27237 registration proof
-- (signed by the inbox key, `owner` tag = member) verbatim. A grant issuer
-- re-verifies it before wrapping a zone key to the inbox key, so a wrong or
-- hostile row can never redirect zone keys. NULL for epoch rows and for rows
-- registered before this column existed; issuers refuse those.
ALTER TABLE recipient_keys ADD COLUMN proof TEXT;
