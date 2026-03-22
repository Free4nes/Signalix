package repo

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/signalix/server/internal/model"
)

// UserRepo defines the interface for user repository operations
type UserRepo interface {
	GetByID(ctx context.Context, id string) (model.User, error)
	GetOrCreateByPhone(ctx context.Context, phone string) (model.User, error)
	GetByPhone(ctx context.Context, phone string) (model.User, error)
	FindUsersByPhones(ctx context.Context, phones []string) ([]model.User, error)
	FindUsersByIDs(ctx context.Context, ids []uuid.UUID) ([]model.User, error)
	UpdateDisplayName(ctx context.Context, userID string, displayName *string) error
	UpdateAvatarURL(ctx context.Context, userID string, avatarURL *string) error
	UpdateOnlineStatus(ctx context.Context, userID string, online bool) error
	GetOnlineStatus(ctx context.Context, userID string) (online bool, lastSeen *string, err error)
}

type userRepo struct {
	db *sql.DB
}

// NewUserRepo creates a new UserRepo instance
func NewUserRepo(db *sql.DB) UserRepo {
	return &userRepo{db: db}
}

// GetByID retrieves a user by ID
func (r *userRepo) GetByID(ctx context.Context, id string) (model.User, error) {
	query := `
		SELECT id, phone_number, COALESCE(display_name, ''), COALESCE(avatar_url, ''), created_at
		FROM users
		WHERE id = $1
	`
	var user model.User
	var idStr string
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&idStr,
		&user.PhoneNumber,
		&user.DisplayName,
		&user.AvatarURL,
		&user.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return model.User{}, fmt.Errorf("user not found: %w", err)
		}
		return model.User{}, fmt.Errorf("failed to query user: %w", err)
	}
	user.ID, err = uuid.Parse(idStr)
	if err != nil {
		return model.User{}, fmt.Errorf("failed to parse user ID: %w", err)
	}
	return user, nil
}

// GetOrCreateByPhone retrieves a user by phone number or creates one if it doesn't exist
func (r *userRepo) GetOrCreateByPhone(ctx context.Context, phone string) (model.User, error) {
	// Try to insert first, using ON CONFLICT DO NOTHING
	query := `
		INSERT INTO users (phone_number)
		VALUES ($1)
		ON CONFLICT (phone_number) DO NOTHING
	`
	_, err := r.db.ExecContext(ctx, query, phone)
	if err != nil {
		return model.User{}, fmt.Errorf("failed to insert user: %w", err)
	}

	// Now select the user (whether it was just created or already existed)
	return r.GetByPhone(ctx, phone)
}

// GetByPhone retrieves a user by phone number
func (r *userRepo) GetByPhone(ctx context.Context, phone string) (model.User, error) {
	query := `
		SELECT id, phone_number, COALESCE(display_name, ''), COALESCE(avatar_url, ''), created_at
		FROM users
		WHERE phone_number = $1
	`

	var user model.User
	var idStr string
	err := r.db.QueryRowContext(ctx, query, phone).Scan(
		&idStr,
		&user.PhoneNumber,
		&user.DisplayName,
		&user.AvatarURL,
		&user.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return model.User{}, fmt.Errorf("user not found: %w", err)
		}
		return model.User{}, fmt.Errorf("failed to query user: %w", err)
	}

	user.ID, err = uuid.Parse(idStr)
	if err != nil {
		return model.User{}, fmt.Errorf("failed to parse user ID: %w", err)
	}

	return user, nil
}

// FindUsersByPhones returns users whose phone_number is in the given slice
func (r *userRepo) FindUsersByPhones(ctx context.Context, phones []string) ([]model.User, error) {
	if len(phones) == 0 {
		return nil, nil
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, phone_number, COALESCE(display_name, ''), COALESCE(avatar_url, '') FROM users WHERE phone_number = ANY($1)
	`, pq.Array(phones))
	if err != nil {
		return nil, fmt.Errorf("find users by phones: %w", err)
	}
	defer rows.Close()

	var result []model.User
	for rows.Next() {
		var u model.User
		var idStr string
		if err := rows.Scan(&idStr, &u.PhoneNumber, &u.DisplayName, &u.AvatarURL); err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		u.ID, _ = uuid.Parse(idStr)
		result = append(result, u)
	}
	return result, rows.Err()
}

// FindUsersByIDs returns users whose id is in the given slice.
func (r *userRepo) FindUsersByIDs(ctx context.Context, ids []uuid.UUID) ([]model.User, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	idsStr := make([]string, len(ids))
	for i, id := range ids {
		idsStr[i] = id.String()
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, phone_number, COALESCE(display_name, ''), COALESCE(avatar_url, '') FROM users WHERE id = ANY($1::uuid[])
	`, pq.Array(idsStr))
	if err != nil {
		return nil, fmt.Errorf("find users by ids: %w", err)
	}
	defer rows.Close()

	var result []model.User
	for rows.Next() {
		var u model.User
		var idStr string
		if err := rows.Scan(&idStr, &u.PhoneNumber, &u.DisplayName, &u.AvatarURL); err != nil {
			return nil, err
		}
		u.ID, _ = uuid.Parse(idStr)
		result = append(result, u)
	}
	return result, rows.Err()
}

// UpdateDisplayName sets the user's display_name. Nil or empty/whitespace => NULL in DB.
func (r *userRepo) UpdateDisplayName(ctx context.Context, userID string, displayName *string) error {
	var val interface{}
	if displayName != nil && strings.TrimSpace(*displayName) != "" {
		val = strings.TrimSpace(*displayName)
	} else {
		val = nil
	}
	_, err := r.db.ExecContext(ctx, `UPDATE users SET display_name = $1 WHERE id = $2`, val, userID)
	if err != nil {
		return fmt.Errorf("update display_name: %w", err)
	}
	return nil
}

// UpdateAvatarURL sets the user's avatar_url. Nil or empty => NULL in DB.
func (r *userRepo) UpdateAvatarURL(ctx context.Context, userID string, avatarURL *string) error {
	var val interface{}
	if avatarURL != nil && strings.TrimSpace(*avatarURL) != "" {
		val = strings.TrimSpace(*avatarURL)
	} else {
		val = nil
	}
	_, err := r.db.ExecContext(ctx, `UPDATE users SET avatar_url = $1 WHERE id = $2`, val, userID)
	if err != nil {
		return fmt.Errorf("update avatar_url: %w", err)
	}
	return nil
}

// UpdateOnlineStatus sets the user's online flag and last_seen timestamp.
func (r *userRepo) UpdateOnlineStatus(ctx context.Context, userID string, online bool) error {
	_, err := r.db.ExecContext(ctx, `UPDATE users SET online = $1, last_seen = now() WHERE id = $2`, online, userID)
	if err != nil {
		return fmt.Errorf("update online status: %w", err)
	}
	return nil
}

// GetOnlineStatus returns the user's online flag and last_seen timestamp (RFC3339).
func (r *userRepo) GetOnlineStatus(ctx context.Context, userID string) (online bool, lastSeen *string, err error) {
	var ls sql.NullTime
	err = r.db.QueryRowContext(ctx, `SELECT online, last_seen FROM users WHERE id = $1`, userID).Scan(&online, &ls)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil, fmt.Errorf("user not found: %w", err)
		}
		return false, nil, fmt.Errorf("get online status: %w", err)
	}
	if ls.Valid {
		s := ls.Time.Format(time.RFC3339)
		lastSeen = &s
	}
	return online, lastSeen, nil
}
