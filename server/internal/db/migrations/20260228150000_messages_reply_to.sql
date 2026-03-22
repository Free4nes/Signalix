-- +goose Up
ALTER TABLE messages ADD COLUMN reply_to_id UUID REFERENCES messages(id) ON DELETE SET NULL;

-- +goose Down
ALTER TABLE messages DROP COLUMN IF EXISTS reply_to_id;
