package repo

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
)

// BlockedUser is a user blocked by the caller (for list response)
type BlockedUser struct {
	ID          uuid.UUID
	PhoneNumber string
	DisplayName string
}

// BlockedRepo defines the interface for blocked users
type BlockedRepo interface {
	Block(ctx context.Context, userID uuid.UUID, blockedUserID uuid.UUID) error
	Unblock(ctx context.Context, userID uuid.UUID, blockedUserID uuid.UUID) error
	IsBlocked(ctx context.Context, userID uuid.UUID, otherUserID uuid.UUID) (bool, error)
	ListBlocked(ctx context.Context, userID uuid.UUID) ([]BlockedUser, error)
}

type blockedRepo struct {
	db *sql.DB
}

// NewBlockedRepo creates a new BlockedRepo
func NewBlockedRepo(db *sql.DB) BlockedRepo {
	return &blockedRepo{db: db}
}

// Block blocks another user. Idempotent (no error if already blocked).
func (r *blockedRepo) Block(ctx context.Context, userID uuid.UUID, blockedUserID uuid.UUID) error {
	if userID == blockedUserID {
		return nil
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO blocked_users (user_id, blocked_user_id)
		VALUES ($1, $2)
		ON CONFLICT (user_id, blocked_user_id) DO NOTHING
	`, userID, blockedUserID)
	return err
}

// Unblock removes a block. Idempotent.
func (r *blockedRepo) Unblock(ctx context.Context, userID uuid.UUID, blockedUserID uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, `
		DELETE FROM blocked_users WHERE user_id = $1 AND blocked_user_id = $2
	`, userID, blockedUserID)
	return err
}

// IsBlocked returns true if either user has blocked the other.
func (r *blockedRepo) IsBlocked(ctx context.Context, userID uuid.UUID, otherUserID uuid.UUID) (bool, error) {
	var count int
	err := r.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM blocked_users
		WHERE (user_id = $1 AND blocked_user_id = $2)
		   OR (user_id = $2 AND blocked_user_id = $1)
	`, userID, otherUserID).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// ListBlocked returns all users blocked by userID.
func (r *blockedRepo) ListBlocked(ctx context.Context, userID uuid.UUID) ([]BlockedUser, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT u.id, u.phone_number, COALESCE(u.display_name, '') AS display_name
		FROM blocked_users b
		JOIN users u ON u.id = b.blocked_user_id
		WHERE b.user_id = $1
		ORDER BY u.phone_number
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BlockedUser
	for rows.Next() {
		var bu BlockedUser
		if err := rows.Scan(&bu.ID, &bu.PhoneNumber, &bu.DisplayName); err != nil {
			return nil, err
		}
		out = append(out, bu)
	}
	return out, rows.Err()
}
