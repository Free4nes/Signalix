-- +goose Up
-- Idempotent deduplication: duplicate (project_id, event_type, version, payload) are rejected.
-- COALESCE handles NULL payload (e.g. project_archived) so two identical NULL payloads are considered duplicates.
CREATE UNIQUE INDEX project_events_dedup_idx
ON project_events (project_id, event_type, version, COALESCE(payload, 'null'::jsonb));

-- +goose Down
DROP INDEX IF EXISTS project_events_dedup_idx;
