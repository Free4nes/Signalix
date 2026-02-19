package repo

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"github.com/signalix/server/internal/model"
)

// UserRepo defines the interface for user repository operations
type UserRepo interface {
	GetByID(ctx context.Context, id string) (model.User, error)
	GetOrCreateByPhone(ctx context.Context, phone string) (model.User, error)
	GetByPhone(ctx context.Context, phone string) (model.User, error)
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
		SELECT id, phone_number, created_at
		FROM users
		WHERE id = $1
	`
	var user model.User
	var idStr string
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&idStr,
		&user.PhoneNumber,
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
		SELECT id, phone_number, created_at
		FROM users
		WHERE phone_number = $1
	`

	var user model.User
	var idStr string
	err := r.db.QueryRowContext(ctx, query, phone).Scan(
		&idStr,
		&user.PhoneNumber,
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
