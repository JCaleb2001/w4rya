-- Per-flow notes (team coordination scratch pad).
-- Idempotent; also recreated by notes.init_schema() on api startup.

CREATE TABLE IF NOT EXISTS flow_notes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    flow_id UUID NOT NULL,
    author TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS flow_notes_flow_id_idx
    ON flow_notes(flow_id, created_at DESC);
