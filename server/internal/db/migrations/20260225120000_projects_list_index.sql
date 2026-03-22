-- +goose Up
CREATE INDEX IF NOT EXISTS idx_projects_owner_created ON projects(owner_user_id, created_at DESC);
-- +goose Down
DROP INDEX IF EXISTS idx_projects_owner_created;
