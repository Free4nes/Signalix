-- +goose Up
-- Drop the DB-level dedup index. Idempotency is now enforced at the application layer
-- in AddProjectEvent via payload_hash lookup, which allows direct SQL inserts of duplicate
-- events (e.g. in tests or migrations) while still preventing accidental double-writes
-- through the service layer.
DROP INDEX IF EXISTS project_events_dedup_idx;

-- +goose Down
CREATE UNIQUE INDEX project_events_dedup_idx
ON project_events (project_id, event_type, version, COALESCE(payload, 'null'::jsonb));
