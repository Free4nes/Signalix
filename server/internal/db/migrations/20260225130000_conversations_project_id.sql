-- +goose Up
ALTER TABLE conversations ADD COLUMN project_id UUID NULL REFERENCES projects(id) ON DELETE SET NULL;
CREATE INDEX idx_conversations_project_id ON conversations(project_id);
-- +goose Down
DROP INDEX IF EXISTS idx_conversations_project_id;
ALTER TABLE conversations DROP COLUMN IF EXISTS project_id;
