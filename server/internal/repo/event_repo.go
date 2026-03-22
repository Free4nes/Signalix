package repo

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/signalix/server/internal/model"
)

// EventRepo defines the interface for event repository operations
type EventRepo interface {
	Create(ctx context.Context, projectID uuid.UUID, event string, receivedAt time.Time, payload json.RawMessage) (model.Event, error)
	ListByProject(ctx context.Context, projectID uuid.UUID, limit int) ([]model.Event, error)
}

type eventRepo struct {
	db *sql.DB
}

// NewEventRepo creates a new EventRepo instance
func NewEventRepo(db *sql.DB) EventRepo {
	return &eventRepo{db: db}
}

// Create inserts a new event row and returns the persisted record
func (r *eventRepo) Create(ctx context.Context, projectID uuid.UUID, event string, receivedAt time.Time, payload json.RawMessage) (model.Event, error) {
	// Default to empty object if payload is nil
	if len(payload) == 0 {
		payload = json.RawMessage("{}")
	}

	var e model.Event
	var idStr, projStr string
	err := r.db.QueryRowContext(ctx, `
		INSERT INTO events (project_id, event, received_at, payload)
		VALUES ($1, $2, $3, $4)
		RETURNING id, project_id, event, received_at, payload
	`, projectID, event, receivedAt, []byte(payload)).Scan(
		&idStr, &projStr, &e.Event, &e.ReceivedAt, &e.Payload,
	)
	if err != nil {
		return model.Event{}, fmt.Errorf("create event: %w", err)
	}
	e.ID, _ = uuid.Parse(idStr)
	e.ProjectID, _ = uuid.Parse(projStr)
	return e, nil
}

// ListByProject returns the most recent events for a project, newest first
func (r *eventRepo) ListByProject(ctx context.Context, projectID uuid.UUID, limit int) ([]model.Event, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, project_id, event, received_at, payload
		FROM events
		WHERE project_id = $1
		ORDER BY received_at DESC
		LIMIT $2
	`, projectID, limit)
	if err != nil {
		return nil, fmt.Errorf("list events: %w", err)
	}
	defer rows.Close()

	var events []model.Event
	for rows.Next() {
		var e model.Event
		var idStr, projStr string
		if err := rows.Scan(&idStr, &projStr, &e.Event, &e.ReceivedAt, &e.Payload); err != nil {
			return nil, fmt.Errorf("scan event: %w", err)
		}
		e.ID, _ = uuid.Parse(idStr)
		e.ProjectID, _ = uuid.Parse(projStr)
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list events rows: %w", err)
	}
	return events, nil
}
