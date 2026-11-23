-- People who may approve or reject held requests. Each has their own
-- token, so every decision is tied to a named person.
CREATE TABLE reviewers (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    name         text        NOT NULL UNIQUE,
    token_hash   bytea       NOT NULL UNIQUE,
    token_prefix text        NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    revoked_at   timestamptz
);

-- One row per held request.
--   pending  -> approved | rejected   (by a reviewer, before expires_at)
--   approved -> used                  (the request was sent again, once)
-- "Expired" is not stored: it is any pending or approved row past
-- expires_at.
CREATE TABLE approvals (
    id                 uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id         text        NOT NULL UNIQUE, -- the held request, as in the audit log
    ai_system_id       uuid        NOT NULL,
    request_hash       text        NOT NULL,        -- the resent request must match this
    content            bytea       NOT NULL,        -- what the reviewer sees, encrypted
    content_hash       text        NOT NULL,        -- SHA-256 of that content
    status             text        NOT NULL DEFAULT 'pending'
                           CHECK (status IN ('pending', 'approved', 'rejected', 'used')),
    created_at         timestamptz NOT NULL DEFAULT now(),
    expires_at         timestamptz NOT NULL,
    decided_by         uuid        REFERENCES reviewers (id),
    decided_at         timestamptz,
    note               text        NOT NULL DEFAULT '',
    used_at            timestamptz,
    used_by_request_id text
);

CREATE INDEX approvals_status ON approvals (status, created_at);