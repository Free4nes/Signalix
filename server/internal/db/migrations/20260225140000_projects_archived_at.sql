-- +goose Up
ALTER TABLE projects ADD COLUMN archived_at TIMESTAMPTZ NULL;

CREATE INDEX idx_projects_owner_active
ON projects (owner_user_id, archived_at)
WHERE archived_at IS NULL;

-- +goose Down
DROP INDEX IF EXISTS idx_projects_owner_active;
ALTER TABLE projects DROP COLUMN IF EXISTS archived_at;
