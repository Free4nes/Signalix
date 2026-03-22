-- +goose Up
CREATE TABLE events (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id  UUID        NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    event       TEXT        NOT NULL,
    received_at TIMESTAMPTZ NOT NULL,
    payload     JSONB       NOT NULL
);

CREATE INDEX idx_events_project_received ON events(project_id, received_at DESC);

-- +goose Down
DROP TABLE IF EXISTS events;
