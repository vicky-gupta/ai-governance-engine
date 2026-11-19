-- A per-system rate limit, in requests per minute. NULL means the
-- gateway's default limit applies.
ALTER TABLE ai_systems
    ADD COLUMN rate_limit_rpm integer CHECK (rate_limit_rpm > 0);