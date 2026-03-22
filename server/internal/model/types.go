package model

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// User represents a user in the system
type User struct {
	ID          uuid.UUID
	PhoneNumber string
	DisplayName string // optional; empty means not set
	AvatarURL   string // optional; empty means not set
	CreatedAt   time.Time
}

// Device represents a device belonging to a user
type Device struct {
	ID            uuid.UUID
	UserID        uuid.UUID
	DeviceName    string
	IdentityKeyPub []byte
	CreatedAt     time.Time
	LastSeenAt    *time.Time
}

// OtpSession represents an OTP session for phone verification
type OtpSession struct {
	ID            uuid.UUID
	PhoneNumber   string
	OTPHash       []byte
	ExpiresAt     time.Time
	ConsumedAt    *time.Time
	CreatedAt     time.Time
	AttemptCount  int
	LastAttemptAt *time.Time
	RequestIP     *string
	UserAgent     *string
}

// RefreshSession represents a refresh token session
type RefreshSession struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	TokenHash  string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	RevokedAt  *time.Time
	ReplacedBy *uuid.UUID
}

// Project represents a project owned by a user
type Project struct {
	ID           uuid.UUID
	OwnerUserID  uuid.UUID
	Name         string
	CreatedAt    time.Time
	ArchivedAt   *time.Time
	HardArchived bool // set by DELETE /projects/:id; blocks new conversations and keys
}

// ProjectConversationItem is a minimal conversation entry for project detail
type ProjectConversationItem struct {
	ID                 uuid.UUID
	DisplayTitle       string
	LastMessagePreview string
	UpdatedAt          time.Time
}

// ProjectWithConversations aggregates project and its conversations
type ProjectWithConversations struct {
	Project       Project
	Conversations []ProjectConversationItem
}

// ProjectAPIKey represents an API key belonging to a project.
// The plaintext key is never stored; only key_hash and last4 are persisted.
type ProjectAPIKey struct {
	ID        uuid.UUID
	ProjectID uuid.UUID
	Name      string
	KeyHash   string
	Last4     string
	RevokedAt *time.Time
	CreatedAt time.Time
}

// Event represents a persisted ingest event
type Event struct {
	ID         uuid.UUID
	ProjectID  uuid.UUID
	Event      string
	ReceivedAt time.Time
	Payload    json.RawMessage
}

// ProjectEvent represents an audit event for a project
type ProjectEvent struct {
	ID          uuid.UUID
	ProjectID   uuid.UUID
	ActorUserID uuid.UUID
	EventType   string
	Version     int
	Payload     json.RawMessage
	PayloadHash string
	CreatedAt   time.Time
}

// ── Chat ───────────────────────────────────────────────────────────────────

// Conversation represents a chat conversation
type Conversation struct {
	ID        uuid.UUID
	CreatedAt time.Time
	IsGroup   bool
	Title     *string
	ProjectID *uuid.UUID
}

// ConversationMember represents a user's membership in a conversation
type ConversationMember struct {
	ConversationID uuid.UUID
	UserID         uuid.UUID
	JoinedAt       time.Time
}

// Message represents a chat message (body_ciphertext is opaque for E2E)
type Message struct {
	ID             uuid.UUID
	ConversationID uuid.UUID
	SenderUserID   uuid.UUID
	SentAt         time.Time
	BodyCiphertext []byte
	BodyPreview    string
	// Audio fields (non-nil only when MsgType == "audio")
	MsgType        string  // "text" | "audio" | "image"
	AudioURL       *string
	AudioDurationMs *int
	AudioMime      *string
	// Deletion
	DeletedForEveryone bool
	DeletedAt         *time.Time
	// Status: sent, delivered, read
	Status string
	ReadAt *time.Time
	EditedAt   *time.Time
	ReplyToID  *uuid.UUID
	ReplyToPreview string // body of the replied-to message
}

// ConversationWithPreview is used for list responses; includes last message info and display_title
type ConversationWithPreview struct {
	ID                 uuid.UUID
	CreatedAt          time.Time
	Members            []uuid.UUID
	IsGroup            bool
	Title              *string
	ProjectID          *uuid.UUID
	ProjectName        string
	DisplayTitle       string
	OtherUserAvatarURL *string   // 1:1 only: other participant's avatar_url
	LastMessagePreview string
	LastMessageAt      *time.Time
}
