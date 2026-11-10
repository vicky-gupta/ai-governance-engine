-- The PII vault: the original values behind redaction tokens, encrypted.
-- Unlike the audit log, rows here MUST be deletable: this is where a
-- person's data is erased when they ask (GDPR Article 17).
CREATE TABLE pii_vault (
    id          bigserial PRIMARY KEY,
    request_id  text NOT NULL,
    token       text NOT NULL,
    kind        text NOT NULL,
    fingerprint bytea NOT NULL, -- keyed hash of the value, to find it for erasure
    ciphertext  bytea NOT NULL, -- the value, encrypted with AES-256-GCM
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (request_id, token)
);

CREATE INDEX pii_vault_fingerprint_idx ON pii_vault (fingerprint);
CREATE INDEX pii_vault_created_at_idx ON pii_vault (created_at);