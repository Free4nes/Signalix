package project

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/signalix/server/internal/model"
)

// EventForProjection carries event and actor snapshot for pure projection (no DB/HTTP).
type EventForProjection struct {
	Event            model.ProjectEvent
	ActorDisplayName string
	ActorPhoneNumber string
}

// actorLabelFromSnapshot returns display_name if non-empty, else phone_number, else "".
func actorLabelFromSnapshot(displayName, phoneNumber string) string {
	if strings.TrimSpace(displayName) != "" {
		return strings.TrimSpace(displayName)
	}
	if phoneNumber != "" {
		return phoneNumber
	}
	return ""
}

// cursorString returns the composite cursor "created_at|id" for the event.
// Uses RFC3339Nano to preserve sub-second precision so the pagination predicate
// (created_at, id) < (cursor_ts, cursor_id) works correctly when events share the same second.
func cursorString(createdAt time.Time, id uuid.UUID) string {
	return createdAt.UTC().Format(time.RFC3339Nano) + "|" + id.String()
}

// BuildProjectActivity converts raw events into ActivityItems deterministically.
// Input must be sorted DESC by (created_at, id). Unknown events produce "Unknown activity" (non-fatal).
// hasMore: when true and len(events)>0, nextCursor is set from the last item.
func BuildProjectActivity(events []EventForProjection, hasMore bool) ([]ActivityItem, *string, error) {
	items := make([]ActivityItem, 0, len(events))
	for _, ew := range events {
		ev, err := DecodeProjectEvent(ew.Event)
		if err != nil {
			continue
		}
		actorLabel := actorLabelFromSnapshot(ew.ActorDisplayName, ew.ActorPhoneNumber)
		items = append(items, ProjectToActivityItem(ew.Event, ev, actorLabel))
	}
	var nextCursor *string
	if hasMore && len(events) > 0 {
		last := events[len(events)-1]
		s := cursorString(last.Event.CreatedAt, last.Event.ID)
		nextCursor = &s
	}
	return items, nextCursor, nil
}

// ComputePayloadHash returns SHA256 hex of event_type:version:canonical_payload.
// Payload is canonicalized by round-tripping through json.Unmarshal+json.Marshal to normalize
// whitespace and key ordering, making the hash stable regardless of JSON source formatting.
func ComputePayloadHash(eventType string, version int, payload json.RawMessage) string {
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

// UnknownEventObserver is an optional hook for observability when an unknown event type/version is decoded.
type UnknownEventObserver interface {
	OnUnknownEvent(eventType string, version int)
}

var (
	unknownEventObserver     UnknownEventObserver
	unknownEventObserverMu   sync.RWMutex
)

// SetUnknownEventObserver sets the optional observer for unknown events. Safe for concurrent use.
func SetUnknownEventObserver(o UnknownEventObserver) {
	unknownEventObserverMu.Lock()
	defer unknownEventObserverMu.Unlock()
	unknownEventObserver = o
}

func getUnknownEventObserver() UnknownEventObserver {
	unknownEventObserverMu.RLock()
	defer unknownEventObserverMu.RUnlock()
	return unknownEventObserver
}

// ProjectEventType identifies the kind of project audit event
type ProjectEventType string

const (
	ProjectCreated    ProjectEventType = "project_created"
	ProjectArchived   ProjectEventType = "project_archived"
	ConversationAdded ProjectEventType = "conversation_added"
)

// Version constants per event type (future-proofing for V2/V3)
const (
	ProjectCreatedV1    = 1
	ProjectArchivedV1   = 1
	ConversationAddedV1 = 1
)

// isValidTypeVersion returns true only for valid type/version combinations
func isValidTypeVersion(t ProjectEventType, v int) bool {
	switch t {
	case ProjectCreated:
		return v == ProjectCreatedV1
	case ProjectArchived:
		return v == ProjectArchivedV1
	case ConversationAdded:
		return v == ConversationAddedV1
	default:
		return false
	}
}

// ProjectCreatedPayload is the payload for project_created
type ProjectCreatedPayload struct {
	Name string `json:"name"`
}

// Validate ensures required fields are set
func (p ProjectCreatedPayload) Validate() error {
	if p.Name == "" {
		return fmt.Errorf("name is required")
	}
	return nil
}

// ConversationAddedPayload is the payload for conversation_added
type ConversationAddedPayload struct {
	ConversationID uuid.UUID `json:"conversation_id"`
	DisplayTitle   string    `json:"display_title"`
}

// Validate ensures required fields are set
func (p ConversationAddedPayload) Validate() error {
	if p.ConversationID == uuid.Nil {
		return fmt.Errorf("conversation_id is required")
	}
	return nil
}

// ProjectArchivedPayload has no fields (event has no payload)
type ProjectArchivedPayload struct{}

// ProjectEvent is the canonical event shape for persistence. Only factories produce valid instances.
type ProjectEvent struct {
	EventType ProjectEventType
	Version   int
	Payload   any // marshalled to JSON; nil for ProjectArchived
}

// NewProjectCreatedEvent creates a project_created event. Never accepts arbitrary version.
func NewProjectCreatedEvent(name string) ProjectEvent {
	payload := ProjectCreatedPayload{Name: name}
	return ProjectEvent{
		EventType: ProjectCreated,
		Version:   ProjectCreatedV1,
		Payload:   payload,
	}
}

// NewProjectArchivedEvent creates a project_archived event. Never accepts arbitrary version.
func NewProjectArchivedEvent() ProjectEvent {
	return ProjectEvent{
		EventType: ProjectArchived,
		Version:   ProjectArchivedV1,
		Payload:   ProjectArchivedPayload{},
	}
}

// NewConversationAddedEvent creates a conversation_added event. Never accepts arbitrary version.
func NewConversationAddedEvent(conversationID uuid.UUID, displayTitle string) ProjectEvent {
	payload := ConversationAddedPayload{
		ConversationID: conversationID,
		DisplayTitle:   displayTitle,
	}
	return ProjectEvent{
		EventType: ConversationAdded,
		Version:   ConversationAddedV1,
		Payload:   payload,
	}
}

// DomainEvent is the typed representation of a decoded project event
type DomainEvent interface {
	Type() ProjectEventType
	Version() int
	Summary() string
}

// projectCreatedEvent implements DomainEvent
type projectCreatedEvent struct {
	Payload ProjectCreatedPayload
}

func (e projectCreatedEvent) Type() ProjectEventType   { return ProjectCreated }
func (e projectCreatedEvent) Version() int             { return 1 }
func (e projectCreatedEvent) Summary() string          { return "Project created: " + e.Payload.Name }

// projectArchivedEvent implements DomainEvent
type projectArchivedEvent struct{}

func (e projectArchivedEvent) Type() ProjectEventType { return ProjectArchived }
func (e projectArchivedEvent) Version() int           { return 1 }
func (e projectArchivedEvent) Summary() string        { return "Project archived" }

// conversationAddedEvent implements DomainEvent
type conversationAddedEvent struct {
	Payload ConversationAddedPayload
}

func (e conversationAddedEvent) Type() ProjectEventType { return ConversationAdded }
func (e conversationAddedEvent) Version() int           { return 1 }
func (e conversationAddedEvent) Summary() string        { return "Chat added: " + e.Payload.DisplayTitle }

// onUnknownEvent logs at WARN and notifies the optional observer. Non-fatal; caller should return unknownEvent.
func onUnknownEvent(e model.ProjectEvent, eventType ProjectEventType, version int) {
	log.Printf("[WARN] project event unknown: event_type=%s version=%d project_id=%s event_id=%s",
		eventType, version, e.ProjectID, e.ID)
	if obs := getUnknownEventObserver(); obs != nil {
		obs.OnUnknownEvent(string(eventType), version)
	}
}

// verifyPayloadHash returns false if payload_hash is set and does not match recomputed hash (tamper detected).
func verifyPayloadHash(e model.ProjectEvent) bool {
	if e.PayloadHash == "" {
		return true // backward compat: pre-migration events have no hash
	}
	computed := ComputePayloadHash(e.EventType, e.Version, e.Payload)
	return computed == e.PayloadHash
}

// DecodeProjectEvent unmarshals a stored event into a typed DomainEvent.
// Forward-compatible: missing JSON fields decode as zero-values; do not fail.
// Unknown type returns unknownEvent. Known type with unknown version returns unknownEvent (version switch is strict).
// Unknown events are logged at WARN and reported via UnknownEventObserver if set.
func DecodeProjectEvent(e model.ProjectEvent) (DomainEvent, error) {
	eventType := ProjectEventType(e.EventType)
	switch eventType {
	case ProjectCreated:
		if e.Version != ProjectCreatedV1 {
			onUnknownEvent(e, eventType, e.Version)
			return unknownEvent{eventType: eventType, version: e.Version}, nil
		}
		var p ProjectCreatedPayload
		if len(e.Payload) > 0 {
			if err := json.Unmarshal(e.Payload, &p); err != nil {
				onUnknownEvent(e, eventType, e.Version)
				return unknownEvent{eventType: eventType, version: e.Version}, nil
			}
		}
		if !verifyPayloadHash(e) {
			log.Printf("[WARN] project event payload tamper: event_type=%s version=%d project_id=%s event_id=%s",
				eventType, e.Version, e.ProjectID, e.ID)
			onUnknownEvent(e, eventType, e.Version)
			return unknownEvent{eventType: eventType, version: e.Version}, nil
		}
		return projectCreatedEvent{Payload: p}, nil
	case ProjectArchived:
		if e.Version != ProjectArchivedV1 {
			onUnknownEvent(e, eventType, e.Version)
			return unknownEvent{eventType: eventType, version: e.Version}, nil
		}
		if !verifyPayloadHash(e) {
			log.Printf("[WARN] project event payload tamper: event_type=%s version=%d project_id=%s event_id=%s",
				eventType, e.Version, e.ProjectID, e.ID)
			onUnknownEvent(e, eventType, e.Version)
			return unknownEvent{eventType: eventType, version: e.Version}, nil
		}
		return projectArchivedEvent{}, nil
	case ConversationAdded:
		if e.Version != ConversationAddedV1 {
			onUnknownEvent(e, eventType, e.Version)
			return unknownEvent{eventType: eventType, version: e.Version}, nil
		}
		var p ConversationAddedPayload
		if len(e.Payload) > 0 {
			if err := json.Unmarshal(e.Payload, &p); err != nil {
				onUnknownEvent(e, eventType, e.Version)
				return unknownEvent{eventType: eventType, version: e.Version}, nil
			}
		}
		if !verifyPayloadHash(e) {
			log.Printf("[WARN] project event payload tamper: event_type=%s version=%d project_id=%s event_id=%s",
				eventType, e.Version, e.ProjectID, e.ID)
			onUnknownEvent(e, eventType, e.Version)
			return unknownEvent{eventType: eventType, version: e.Version}, nil
		}
		return conversationAddedEvent{Payload: p}, nil
	default:
		onUnknownEvent(e, eventType, e.Version)
		return unknownEvent{eventType: eventType, version: e.Version}, nil
	}
}

// unknownEvent represents an event type/version we don't yet handle
type unknownEvent struct {
	eventType ProjectEventType
	version   int
}

func (e unknownEvent) Type() ProjectEventType { return e.eventType }
func (e unknownEvent) Version() int           { return e.version }
func (e unknownEvent) Summary() string        { return "Unknown activity" }

// ActivityItem is the projected view of an event for API display
type ActivityItem struct {
	ID         uuid.UUID
	Type       ProjectEventType
	Timestamp  time.Time
	ActorID    uuid.UUID
	ActorLabel string // display_name if non-empty, else phone_number; fallback to actor_id string
	Summary    string
}

// ProjectToActivityItem maps a raw event and its decoded DomainEvent to an ActivityItem
func ProjectToActivityItem(e model.ProjectEvent, ev DomainEvent, actorLabel string) ActivityItem {
	if actorLabel == "" {
		actorLabel = e.ActorUserID.String()
	}
	return ActivityItem{
		ID:         e.ID,
		Type:       ev.Type(),
		Timestamp:  e.CreatedAt,
		ActorID:    e.ActorUserID,
		ActorLabel: actorLabel,
		Summary:    ev.Summary(),
	}
}
