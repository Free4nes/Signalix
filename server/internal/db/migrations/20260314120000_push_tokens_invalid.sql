-- +goose Up
ALTER TABLE user_push_tokens ADD COLUMN invalid_at TIMESTAMPTZ DEFAULT NULL;

-- +goose Down
ALTER TABLE user_push_tokens DROP COLUMN invalid_at;
