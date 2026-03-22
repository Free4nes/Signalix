package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/signalix/server/internal/repo"
)

// Ack is the response returned to the caller after a successful ingest
type Ack struct {
	OK         bool      `json:"ok"`
	ProjectID  string    `json:"project_id"`
	ReceivedAt time.Time `json:"received_at"`
	Event      string    `json:"event"`
}

// RawPayload is the JSON body accepted by POST /ingest
type RawPayload struct {
	Event     string          `json:"event"`
	Timestamp *time.Time      `json:"timestamp,omitempty"`
	Data      json.RawMessage `json:"data,omitempty"`
}

// Service validates ingest payloads, persists them, and returns Ack responses
type Service struct {
	events repo.EventRepo
}

// NewService creates a new ingest Service
func NewService(events repo.EventRepo) *Service {
	return &Service{events: events}
}

// Process validates the raw payload, persists the event, and returns an Ack.
// projectID is taken from the authenticated context (set by APIKeyMiddleware).
func (s *Service) Process(ctx context.Context, projectID uuid.UUID, raw RawPayload) (Ack, error) {
	if raw.Event == "" {
		return Ack{}, fmt.Errorf("event field is required")
	}

	now := time.Now().UTC()

	receivedAt := now
	if raw.Timestamp != nil && !raw.Timestamp.IsZero() {
		receivedAt = raw.Timestamp.UTC()
	}

	// Build the full payload JSON to store (includes event + data + timestamp)
	payload, err := buildPayload(raw)
	if err != nil {
		return Ack{}, fmt.Errorf("build payload: %w", err)
	}

	if _, err := s.events.Create(ctx, projectID, raw.Event, receivedAt, payload); err != nil {
		return Ack{}, fmt.Errorf("persist event: %w", err)
	}

	return Ack{
		OK:         true,
		ProjectID:  projectID.String(),
		ReceivedAt: receivedAt,
		Event:      raw.Event,
	}, nil
}

// buildPayload serialises the full incoming payload as a JSON object for storage.
// We store the whole thing (event + data + timestamp) so nothing is lost.
func buildPayload(raw RawPayload) (json.RawMessage, error) {
	m := map[string]interface{}{
		"event": raw.Event,
	}
	if raw.Timestamp != nil {
		m["timestamp"] = raw.Timestamp.UTC().Format(time.RFC3339)
	}
	if len(raw.Data) > 0 {
		m["data"] = raw.Data
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return b, nil
}
