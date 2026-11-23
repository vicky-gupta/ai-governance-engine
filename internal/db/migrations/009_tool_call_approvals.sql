-- Approvals can now be for a held request (as before) or for the tool
-- calls in a model's answer. For tool calls, the answer itself is kept,
-- encrypted, so that after approval exactly that answer is given back:
-- asking the model again could produce a different tool call.
ALTER TABLE approvals
    ADD COLUMN kind text NOT NULL DEFAULT 'request'
        CHECK (kind IN ('request', 'tool_calls')),
    ADD COLUMN held_response bytea,              -- NULL again once used
    ADD COLUMN response_type text NOT NULL DEFAULT '';