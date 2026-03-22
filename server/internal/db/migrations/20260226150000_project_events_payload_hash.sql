-- +goose Up
ALTER TABLE project_events ADD COLUMN payload_hash TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE project_events DROP COLUMN IF EXISTS payload_hash;
