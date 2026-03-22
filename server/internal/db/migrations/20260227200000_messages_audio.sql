-- +goose Up
ALTER TABLE messages
    ADD COLUMN msg_type       TEXT    NOT NULL DEFAULT 'text',
    ADD COLUMN audio_url      TEXT,
    ADD COLUMN audio_duration_ms INT,
    ADD COLUMN audio_mime     TEXT;

-- +goose Down
ALTER TABLE messages
    DROP COLUMN IF EXISTS msg_type,
    DROP COLUMN IF EXISTS audio_url,
    DROP COLUMN IF EXISTS audio_duration_ms,
    DROP COLUMN IF EXISTS audio_mime;
