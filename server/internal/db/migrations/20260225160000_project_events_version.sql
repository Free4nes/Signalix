-- +goose Up
ALTER TABLE project_events ADD COLUMN version INT NOT NULL DEFAULT 1;

-- +goose Down
ALTER TABLE project_events DROP COLUMN IF EXISTS version;
