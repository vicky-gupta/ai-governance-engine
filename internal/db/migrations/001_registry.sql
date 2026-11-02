-- AI systems: every application allowed to call models through the gateway.
-- risk_tier follows the EU AI Act's four levels.
CREATE TABLE ai_systems (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name       text NOT NULL UNIQUE,
    owner      text NOT NULL,
    purpose    text NOT NULL,
    risk_tier  text NOT NULL CHECK (risk_tier IN ('minimal', 'limited', 'high', 'unacceptable')),
    status     text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    created_at timestamptz NOT NULL DEFAULT now()
);

-- Gateway API keys. Only a SHA-256 hash of each key is stored.
CREATE TABLE api_keys (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    ai_system_id uuid NOT NULL REFERENCES ai_systems (id) ON DELETE CASCADE,
    prefix       text NOT NULL,
    key_hash     bytea NOT NULL UNIQUE,
    created_at   timestamptz NOT NULL DEFAULT now(),
    revoked_at   timestamptz
);

CREATE INDEX api_keys_ai_system_id_idx ON api_keys (ai_system_id);