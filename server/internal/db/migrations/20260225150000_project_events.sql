-- +goose Up
CREATE TABLE project_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  actor_user_id UUID NOT NULL REFERENCES users(id),
  event_type TEXT NOT NULL,
  payload JSONB NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_project_events_project_created
ON project_events (project_id, created_at DESC);

-- +goose Down
DROP INDEX IF EXISTS idx_project_events_project_created;
DROP TABLE IF EXISTS project_events;
