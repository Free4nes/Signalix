-- +goose Up
ALTER TABLE project_events ADD COLUMN actor_display_name TEXT NULL;
ALTER TABLE project_events ADD COLUMN actor_phone_number TEXT NULL;

-- +goose Down
ALTER TABLE project_events DROP COLUMN IF EXISTS actor_display_name;
ALTER TABLE project_events DROP COLUMN IF EXISTS actor_phone_number;
