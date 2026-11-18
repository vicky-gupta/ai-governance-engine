-- Record which version of the policy files judged each request.
ALTER TABLE audit_log
    ADD COLUMN policy_version text NOT NULL DEFAULT '';