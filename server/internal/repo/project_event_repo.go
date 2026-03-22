package repo

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/signalix/server/internal/model"
)

// computePayloadHash returns SHA256 hex of event_type:version:canonical_payload.
// Payload is canonicalized by round-tripping through json.Unmarshal+json.Marshal to normalize
// whitespace and key ordering, making the hash stable regardless of whether the JSON came from
// Go marshalling or PostgreSQL JSONB output (which adds spaces after ':' and ',').
func computePayloadHash(eventType string, version int, payload json.RawMessage) string {
	payloadStr := "null"
	if len(payload) > 0 {
		var v interface{}
		if err := json.Unmarshal(payload, &v); err == nil {
			if b, err := json.Marshal(v); err == nil {
				payloadStr = string(b)
			} else {
				payloadStr = string(payload)
			}
		} else {
			payloadStr = string(payload)
		}
	}
	input := eventType + ":" + strconv.Itoa(version) + ":" + payloadStr
	h := sha256.Sum256([]byte(input))
	return hex.EncodeToString(h[:])
}

// ActivityBeforeCursor is the composite cursor for activity pagination: created_at|id
type ActivityBeforeCursor struct {
	CreatedAt time.Time
	ID        uuid.UUID
}

// ParseActivityBeforeCursor parses "created_at|id" format. Returns nil if s is empty.
// Accepts both RFC3339Nano and RFC3339 for backward compatibility.
func ParseActivityBeforeCursor(s string) (*ActivityBeforeCursor, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	parts := strings.SplitN(s, "|", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid cursor format: expected created_at|id")
	}
	tsStr := strings.TrimSpace(parts[0])
	createdAt, err := time.Parse(time.RFC3339Nano, tsStr)
	if err != nil {
		// fall back to second-precision for cursors issued before this fix
		createdAt, err = time.Parse(time.RFC3339, tsStr)
		if err != nil {
			return nil, fmt.Errorf("invalid cursor timestamp: %w", err)
		}
	}
	id, err := uuid.Parse(strings.TrimSpace(parts[1]))
	if err != nil {
		return nil, fmt.Errorf("invalid cursor id: %w", err)
	}
	return &ActivityBeforeCursor{CreatedAt: createdAt, ID: id}, nil
}

// String returns the cursor in "created_at|id" format using nanosecond precision
// so that events with the same second but different sub-second timestamps are
// correctly distinguished by the pagination predicate.
func (c ActivityBeforeCursor) String() string {
	return c.CreatedAt.UTC().Format(time.RFC3339Nano) + "|" + c.ID.String()
}

// ProjectEventWithActor extends ProjectEvent with actor display info (from immutable snapshot on event)
type ProjectEventWithActor struct {
	model.ProjectEvent
	ActorDisplayName sql.NullString
	ActorPhoneNumber sql.NullString
}

// ProjectEventListResult holds paginated project events
type ProjectEventListResult struct {
	Events     []ProjectEventWithActor
	HasMore    bool
	NextCursor *string // composite format: created_at|id
}

// ProjectEventRepo defines the interface for project audit event operations
type ProjectEventRepo interface {
	AddProjectEvent(ctx context.Context, projectID, actorID uuid.UUID, eventType string, version int, payload any) error
	ListByProject(ctx context.Context, projectID uuid.UUID, before *ActivityBeforeCursor, limit int) (ProjectEventListResult, error)
}

type projectEventRepo struct {
	conn Querier
}

// NewProjectEventRepo creates a new ProjectEventRepo instance
func NewProjectEventRepo(db *sql.DB) ProjectEventRepo {
	return &projectEventRepo{conn: db}
}

// NewProjectEventRepoWithConn creates a ProjectEventRepo using the given Querier (tx or db)
func NewProjectEventRepoWithConn(conn Querier) ProjectEventRepo {
	return &projectEventRepo{conn: conn}
}

// AddProjectEvent inserts an audit event for a project. Fetches actor display_name and phone_number
// once and stores immutable snapshot. created_at is always NOW() from DB default.
// Idempotent: if an event with the same (project_id, event_type, version, payload_hash) already
// exists, returns nil without inserting a duplicate. This is enforced at the application layer
// (not DB constraint) so that direct SQL inserts can still create duplicates when needed.
func (r *projectEventRepo) AddProjectEvent(ctx context.Context, projectID, actorID uuid.UUID, eventType string, version int, payload any) error {
	var actorDisplayName, actorPhoneNumber sql.NullString
	err := r.conn.QueryRowContext(ctx, `SELECT display_name, phone_number FROM users WHERE id = $1`, actorID).Scan(&actorDisplayName, &actorPhoneNumber)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("fetch actor snapshot: %w", err)
	}
	// ErrNoRows: user may be deleted; store NULL for snapshot

	var payloadJSON json.RawMessage
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("marshal payload: %w", err)
		}
		payloadJSON = b
	}
	payloadHash := computePayloadHash(eventType, version, payloadJSON)

	// Application-level idempotency: skip insert if identical event already exists.
	var existingID string
	lookupErr := r.conn.QueryRowContext(ctx,
		`SELECT id FROM project_events WHERE project_id=$1 AND event_type=$2 AND version=$3 AND payload_hash=$4 LIMIT 1`,
		projectID, eventType, version, payloadHash,
	).Scan(&existingID)
	if lookupErr == nil {
		log.Printf("[DEBUG] duplicate project event (idempotent): project_id=%s event_type=%s version=%d", projectID, eventType, version)
		return nil
	}
	if lookupErr != sql.ErrNoRows {
		return fmt.Errorf("check duplicate project event: %w", lookupErr)
	}

	_, err = r.conn.ExecContext(ctx, `
		INSERT INTO project_events (project_id, actor_user_id, event_type, version, payload, payload_hash, actor_display_name, actor_phone_number)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, projectID, actorID, eventType, version, payloadJSON, payloadHash, actorDisplayName, actorPhoneNumber)
	if err != nil {
		return fmt.Errorf("add project event: %w", err)
	}
	return nil
}

// ListByProject returns events for a project, newest first. Uses composite cursor (created_at, id) for stable pagination.
func (r *projectEventRepo) ListByProject(ctx context.Context, projectID uuid.UUID, before *ActivityBeforeCursor, limit int) (ProjectEventListResult, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 100 {
		limit = 100
	}
	fetchLimit := limit + 1

	var query string
	var args []interface{}
	if before != nil {
		query = `
			SELECT pe.id, pe.project_id, pe.actor_user_id, pe.event_type, pe.version, pe.payload, pe.payload_hash, pe.created_at,
			       pe.actor_display_name, pe.actor_phone_number
			FROM project_events pe
			WHERE pe.project_id = $1 AND (pe.created_at, pe.id) < ($2, $3)
			ORDER BY pe.created_at DESC, pe.id DESC
			LIMIT $4
		`
		args = []interface{}{projectID, before.CreatedAt, before.ID, fetchLimit}
	} else {
		query = `
			SELECT pe.id, pe.project_id, pe.actor_user_id, pe.event_type, pe.version, pe.payload, pe.payload_hash, pe.created_at,
			       pe.actor_display_name, pe.actor_phone_number
			FROM project_events pe
			WHERE pe.project_id = $1
			ORDER BY pe.created_at DESC, pe.id DESC
			LIMIT $2
		`
		args = []interface{}{projectID, fetchLimit}
	}

	rows, err := r.conn.QueryContext(ctx, query, args...)
	if err != nil {
		return ProjectEventListResult{}, fmt.Errorf("list project events: %w", err)
	}
	defer rows.Close()

	var events []ProjectEventWithActor
	for rows.Next() {
		var e ProjectEventWithActor
		var idStr, projStr, actorStr string
		var payload []byte
		if err := rows.Scan(&idStr, &projStr, &actorStr, &e.EventType, &e.Version, &payload, &e.PayloadHash, &e.CreatedAt,
			&e.ActorDisplayName, &e.ActorPhoneNumber); err != nil {
			return ProjectEventListResult{}, fmt.Errorf("scan project event: %w", err)
		}
		e.ID, _ = uuid.Parse(idStr)
		e.ProjectID, _ = uuid.Parse(projStr)
		e.ActorUserID, _ = uuid.Parse(actorStr)
		if len(payload) > 0 {
			e.Payload = json.RawMessage(payload)
		}
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		return ProjectEventListResult{}, fmt.Errorf("list project events rows: %w", err)
	}

	hasMore := len(events) > limit
	if hasMore {
		events = events[:limit]
	}
	var nextCursor *string
	if hasMore && len(events) > 0 {
		last := events[len(events)-1]
		s := ActivityBeforeCursor{CreatedAt: last.CreatedAt, ID: last.ID}.String()
		nextCursor = &s
	}
	return ProjectEventListResult{Events: events, HasMore: hasMore, NextCursor: nextCursor}, nil
}
