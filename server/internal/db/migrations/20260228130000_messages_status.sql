-- +goose Up
ALTER TABLE messages
    ADD COLUMN status TEXT NOT NULL DEFAULT 'sent',
    ADD COLUMN read_at TIMESTAMPTZ;

-- +goose Down
ALTER TABLE messages
    DROP COLUMN IF EXISTS status,
    DROP COLUMN IF EXISTS read_at;
