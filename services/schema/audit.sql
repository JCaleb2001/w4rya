-- Audit log of authed state-changing actions.
-- Idempotent; also recreated by audit.init_schema() on api startup.

CREATE TABLE IF NOT EXISTS audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    when_ts TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT,
    details JSONB
);

CREATE INDEX IF NOT EXISTS audit_log_when_idx ON audit_log(when_ts DESC);
