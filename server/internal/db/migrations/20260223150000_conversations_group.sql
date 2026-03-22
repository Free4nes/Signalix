-- +goose Up
ALTER TABLE conversations
    ADD COLUMN is_group BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN title TEXT NULL;

-- +goose Down
ALTER TABLE conversations DROP COLUMN IF EXISTS is_group;
ALTER TABLE conversations DROP COLUMN IF EXISTS title;
