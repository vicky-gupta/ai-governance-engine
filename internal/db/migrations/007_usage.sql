-- A per-system monthly token budget. NULL means no budget.
ALTER TABLE ai_systems
    ADD COLUMN monthly_token_budget bigint CHECK (monthly_token_budget > 0);

-- Tokens used per request, as reported by the provider. One row per
-- request; request_id links it to the audit log.
CREATE TABLE usage_records (
    id                bigserial   PRIMARY KEY,
    request_id        text        NOT NULL UNIQUE,
    ai_system_id      uuid        NOT NULL,
    model             text        NOT NULL,
    provider          text        NOT NULL,
    prompt_tokens     bigint      NOT NULL CHECK (prompt_tokens >= 0),
    completion_tokens bigint      NOT NULL CHECK (completion_tokens >= 0),
    total_tokens      bigint      NOT NULL CHECK (total_tokens >= 0),
    created_at        timestamptz NOT NULL DEFAULT now()
);

-- "How much has this system used this month?" runs on every request.
CREATE INDEX usage_records_system_time ON usage_records (ai_system_id, created_at);