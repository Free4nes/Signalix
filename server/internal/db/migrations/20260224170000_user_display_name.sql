-- +goose Up
ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name TEXT NULL;
-- +goose Down
ALTER TABLE users DROP COLUMN IF EXISTS display_name;
