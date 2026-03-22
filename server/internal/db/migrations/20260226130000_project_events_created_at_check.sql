-- +goose Up
-- Prevent future-dated created_at. created_at is always NOW() from INSERT default; this guard blocks manual override.
ALTER TABLE project_events ADD CONSTRAINT project_events_created_at_not_future CHECK (created_at <= NOW());

-- +goose Down
ALTER TABLE project_events DROP CONSTRAINT IF EXISTS project_events_created_at_not_future;
