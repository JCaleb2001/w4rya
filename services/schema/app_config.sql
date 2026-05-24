-- Runtime-editable config for the w4rya api.
-- Idempotent: also recreated by app_config.init_schema() on api startup, so
-- this file is only needed for fresh databases (mounted under
-- /docker-entrypoint-initdb.d/).

CREATE TABLE IF NOT EXISTS app_config (
    key TEXT PRIMARY KEY,
    value JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
