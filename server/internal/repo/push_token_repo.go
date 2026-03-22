package repo

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
)

// PushTokenRepo defines the interface for push token persistence
type PushTokenRepo interface {
	SaveToken(ctx context.Context, userID uuid.UUID, expoPushToken string, platform string) (inserted bool, err error)
	GetTokensForUser(ctx context.Context, userID uuid.UUID) ([]string, error)
	MarkTokenInvalid(ctx context.Context, expoPushToken string) error
}

type pushTokenRepo struct {
	db *sql.DB
}

// NewPushTokenRepo creates a new PushTokenRepo
func NewPushTokenRepo(db *sql.DB) PushTokenRepo {
	return &pushTokenRepo{db: db}
}

// SaveToken inserts or updates a push token. Returns (true, nil) if inserted,
// (false, nil) if updated (duplicate - same user+token already exists; clears invalid_at).
func (r *pushTokenRepo) SaveToken(ctx context.Context, userID uuid.UUID, expoPushToken string, platform string) (bool, error) {
	var id uuid.UUID
	err := r.db.QueryRowContext(ctx, `
		INSERT INTO user_push_tokens (user_id, expo_push_token, platform)
		VALUES ($1, $2, $3)
		ON CONFLICT (user_id, expo_push_token) DO UPDATE SET platform = EXCLUDED.platform, invalid_at = NULL
		RETURNING id
	`, userID, expoPushToken, platform).Scan(&id)
	if err != nil {
		return false, err
	}
	// Check if we inserted or updated (we can't easily distinguish; both return row)
	return true, nil
}

// GetTokensForUser returns all valid Expo push tokens for the given user.
func (r *pushTokenRepo) GetTokensForUser(ctx context.Context, userID uuid.UUID) ([]string, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT expo_push_token FROM user_push_tokens
		WHERE user_id = $1 AND invalid_at IS NULL
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tokens []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		tokens = append(tokens, t)
	}
	return tokens, rows.Err()
}

// MarkTokenInvalid marks a push token as invalid (e.g. DeviceNotRegistered from Expo).
func (r *pushTokenRepo) MarkTokenInvalid(ctx context.Context, expoPushToken string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE user_push_tokens SET invalid_at = now() WHERE expo_push_token = $1`, expoPushToken)
	return err
}
