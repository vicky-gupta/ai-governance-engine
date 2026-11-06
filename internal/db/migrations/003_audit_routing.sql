-- Record where each request was sent, as evidence of data residency.
-- Existing rows get '' (not routed), which their hashes already assume.
ALTER TABLE audit_log
    ADD COLUMN provider text NOT NULL DEFAULT '',
    ADD COLUMN region   text NOT NULL DEFAULT '';