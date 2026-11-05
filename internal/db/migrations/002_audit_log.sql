-- The audit log: one row per governance decision. Rows are linked in a
-- hash chain, so any change to a past row can be detected.
--
-- There is deliberately no foreign key to ai_systems: audit records must
-- survive even if the AI system is later deleted.
CREATE TABLE audit_log (
    id             bigserial PRIMARY KEY,
    created_at     timestamptz NOT NULL,
    request_id     text NOT NULL,
    ai_system_id   text NOT NULL,
    ai_system_name text NOT NULL,
    model          text NOT NULL,
    action         text NOT NULL,
    check_name     text NOT NULL DEFAULT '',
    reason         text NOT NULL DEFAULT '',
    trace          json NOT NULL,
    request_hash   text NOT NULL,
    forwarded_hash text NOT NULL DEFAULT '',
    prev_hash      text NOT NULL,
    hash           text NOT NULL UNIQUE
);

CREATE INDEX audit_log_ai_system_id_idx ON audit_log (ai_system_id);
CREATE INDEX audit_log_created_at_idx ON audit_log (created_at);

-- First line of defence: the database refuses to change or delete rows.
-- (The hash chain is the second line: it catches changes made by someone
-- who disables this trigger.)
CREATE FUNCTION audit_log_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_log_no_update_delete
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_append_only();

CREATE TRIGGER audit_log_no_truncate
    BEFORE TRUNCATE ON audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION audit_log_append_only();