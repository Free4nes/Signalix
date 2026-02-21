package model

import (
	"time"

	"github.com/google/uuid"
)

// User represents a user in the system
type User struct {
	ID          uuid.UUID
	PhoneNumber string
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
	ID        uuid.UUID
	UserID    uuid.UUID
	TokenHash string
	CreatedAt time.Time
	ExpiresAt time.Time
	RevokedAt *time.Time
	ReplacedBy *uuid.UUID
}
