package repo

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/signalix/server/internal/model"
)

// RefreshRepo defines the interface for refresh session repository operations
type RefreshRepo interface {
	Create(ctx context.Context, userID uuid.UUID, tokenHash string, expiresAt time.Time) (uuid.UUID, error)
	FindByTokenHash(ctx context.Context, tokenHash string) (model.RefreshSession, error)
	FindByTokenHashIncludeRevoked(ctx context.Context, tokenHash string) (model.RefreshSession, error)
	RevokeAndSetReplacedBy(ctx context.Context, sessionID uuid.UUID, replacedBy uuid.UUID) error
	Revoke(ctx context.Context, sessionID uuid.UUID) error
	RevokeAllForUser(ctx context.Context, userID uuid.UUID) error
}

type refreshRepo struct {
	db *sql.DB
}

// NewRefreshRepo creates a new RefreshRepo instance
func NewRefreshRepo(db *sql.DB) RefreshRepo {
	return &refreshRepo{db: db}
}

// Create inserts a new refresh session
func (r *refreshRepo) Create(ctx context.Context, userID uuid.UUID, tokenHash string, expiresAt time.Time) (uuid.UUID, error) {
	var idStr string
	err := r.db.QueryRowContext(ctx, `
		INSERT INTO refresh_sessions (user_id, token_hash, expires_at)
		VALUES ($1, $2, $3)
		RETURNING id
	`, userID, tokenHash, expiresAt).Scan(&idStr)
	if err != nil {
		return uuid.Nil, fmt.Errorf("insert refresh session: %w", err)
	}
	id, err := uuid.Parse(idStr)
	if err != nil {
		return uuid.Nil, fmt.Errorf("parse session ID: %w", err)
	}
	return id, nil
}

// FindByTokenHash returns the session if it exists, is not revoked, and not expired
func (r *refreshRepo) FindByTokenHash(ctx context.Context, tokenHash string) (model.RefreshSession, error) {
	var s model.RefreshSession
	var idStr, userIDStr string
	var replacedByStr sql.NullString
	err := r.db.QueryRowContext(ctx, `
		SELECT id, user_id, token_hash, created_at, expires_at, revoked_at, replaced_by
		FROM refresh_sessions
		WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > now()
	`, tokenHash).Scan(
		&idStr,
		&userIDStr,
		&s.TokenHash,
		&s.CreatedAt,
		&s.ExpiresAt,
		&s.RevokedAt,
		&replacedByStr,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return model.RefreshSession{}, fmt.Errorf("session not found or invalid")
		}
		return model.RefreshSession{}, fmt.Errorf("find session: %w", err)
	}
	s.ID, _ = uuid.Parse(idStr)
	s.UserID, _ = uuid.Parse(userIDStr)
	if replacedByStr.Valid && replacedByStr.String != "" {
		u, _ := uuid.Parse(replacedByStr.String)
		s.ReplacedBy = &u
	}
	return s, nil
}

// RevokeAndSetReplacedBy sets revoked_at and replaced_by for the session
func (r *refreshRepo) RevokeAndSetReplacedBy(ctx context.Context, sessionID uuid.UUID, replacedBy uuid.UUID) error {
	result, err := r.db.ExecContext(ctx, `
		UPDATE refresh_sessions
		SET revoked_at = now(), replaced_by = $2
		WHERE id = $1
	`, sessionID, replacedBy)
	if err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("session not found")
	}
	return nil
}

// Revoke sets revoked_at for the session
func (r *refreshRepo) Revoke(ctx context.Context, sessionID uuid.UUID) error {
	result, err := r.db.ExecContext(ctx, `
		UPDATE refresh_sessions SET revoked_at = now() WHERE id = $1
	`, sessionID)
	if err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("session not found")
	}
	return nil
}

// FindByTokenHashIncludeRevoked returns the session regardless of revocation status (used for reuse detection)
func (r *refreshRepo) FindByTokenHashIncludeRevoked(ctx context.Context, tokenHash string) (model.RefreshSession, error) {
	var s model.RefreshSession
	var idStr, userIDStr string
	var replacedByStr sql.NullString
	err := r.db.QueryRowContext(ctx, `
		SELECT id, user_id, token_hash, created_at, expires_at, revoked_at, replaced_by
		FROM refresh_sessions
		WHERE token_hash = $1
	`, tokenHash).Scan(
		&idStr,
		&userIDStr,
		&s.TokenHash,
		&s.CreatedAt,
		&s.ExpiresAt,
		&s.RevokedAt,
		&replacedByStr,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return model.RefreshSession{}, fmt.Errorf("session not found")
		}
		return model.RefreshSession{}, fmt.Errorf("find session: %w", err)
	}
	s.ID, _ = uuid.Parse(idStr)
	s.UserID, _ = uuid.Parse(userIDStr)
	if replacedByStr.Valid && replacedByStr.String != "" {
		u, _ := uuid.Parse(replacedByStr.String)
		s.ReplacedBy = &u
	}
	return s, nil
}

// RevokeAllForUser revokes all active refresh sessions for a user (reuse/theft response)
func (r *refreshRepo) RevokeAllForUser(ctx context.Context, userID uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE refresh_sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL
	`, userID)
	if err != nil {
		return fmt.Errorf("revoke all sessions for user: %w", err)
	}
	return nil
}
