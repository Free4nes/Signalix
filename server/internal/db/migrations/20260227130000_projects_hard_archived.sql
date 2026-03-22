-- +goose Up
-- hard_archived is set by DELETE /projects/:id (permanent block on new conversations/keys).
-- archived_at (soft archive via POST /archive) does not set this flag and does not block mutations.
ALTER TABLE projects ADD COLUMN hard_archived BOOLEAN NOT NULL DEFAULT FALSE;

-- +goose Down
ALTER TABLE projects DROP COLUMN IF EXISTS hard_archived;
