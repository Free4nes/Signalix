-- +goose Up
ALTER TABLE messages
    ADD COLUMN deleted_for_everyone BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN deleted_at TIMESTAMPTZ;

CREATE TABLE message_hidden (
    message_id UUID NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (message_id, user_id)
);

CREATE INDEX idx_message_hidden_user_id ON message_hidden(user_id);

-- +goose Down
DROP TABLE IF EXISTS message_hidden;
ALTER TABLE messages
    DROP COLUMN IF EXISTS deleted_for_everyone,
    DROP COLUMN IF EXISTS deleted_at;
