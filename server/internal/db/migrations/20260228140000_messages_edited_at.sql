-- +goose Up
ALTER TABLE messages ADD COLUMN edited_at TIMESTAMPTZ;

-- +goose Down
ALTER TABLE messages DROP COLUMN IF EXISTS edited_at;
