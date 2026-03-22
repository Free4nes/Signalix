package repo

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"github.com/signalix/server/internal/model"
)

// ProjectKeyRepo defines the interface for project API key repository operations
type ProjectKeyRepo interface {
	CreateKey(ctx context.Context, projectID uuid.UUID, name, keyHash, last4 string) (model.ProjectAPIKey, error)
	ListKeys(ctx context.Context, projectID uuid.UUID) ([]model.ProjectAPIKey, error)
	RevokeKey(ctx context.Context, keyID uuid.UUID) error
	// FindByKeyHash returns only non-revoked keys (used for normal auth flow).
	FindByKeyHash(ctx context.Context, keyHash string) (model.ProjectAPIKey, error)
	// FindByKeyHashAny returns the key regardless of revocation status (used by middleware
	// to distinguish "not found" from "revoked").
	FindByKeyHashAny(ctx context.Context, keyHash string) (model.ProjectAPIKey, error)
}

type projectKeyRepo struct {
	db *sql.DB
}

// NewProjectKeyRepo creates a new ProjectKeyRepo instance
func NewProjectKeyRepo(db *sql.DB) ProjectKeyRepo {
	return &projectKeyRepo{db: db}
}

// CreateKey inserts a new API key record (plaintext key must be hashed by the caller)
func (r *projectKeyRepo) CreateKey(ctx context.Context, projectID uuid.UUID, name, keyHash, last4 string) (model.ProjectAPIKey, error) {
	var k model.ProjectAPIKey
	var idStr, projStr string
	err := r.db.QueryRowContext(ctx, `
		INSERT INTO project_api_keys (project_id, name, key_hash, last4)
		VALUES ($1, $2, $3, $4)
		RETURNING id, project_id, name, key_hash, last4, revoked_at, created_at
	`, projectID, name, keyHash, last4).Scan(
		&idStr, &projStr, &k.Name, &k.KeyHash, &k.Last4, &k.RevokedAt, &k.CreatedAt,
	)
	if err != nil {
		return model.ProjectAPIKey{}, fmt.Errorf("create api key: %w", err)
	}
	k.ID, _ = uuid.Parse(idStr)
	k.ProjectID, _ = uuid.Parse(projStr)
	return k, nil
}

// ListKeys returns all API keys for a project (including revoked)
func (r *projectKeyRepo) ListKeys(ctx context.Context, projectID uuid.UUID) ([]model.ProjectAPIKey, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, project_id, name, key_hash, last4, revoked_at, created_at
		FROM project_api_keys
		WHERE project_id = $1
		ORDER BY created_at DESC
	`, projectID)
	if err != nil {
		return nil, fmt.Errorf("list api keys: %w", err)
	}
	defer rows.Close()

	var keys []model.ProjectAPIKey
	for rows.Next() {
		var k model.ProjectAPIKey
		var idStr, projStr string
		if err := rows.Scan(&idStr, &projStr, &k.Name, &k.KeyHash, &k.Last4, &k.RevokedAt, &k.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan api key: %w", err)
		}
		k.ID, _ = uuid.Parse(idStr)
		k.ProjectID, _ = uuid.Parse(projStr)
		keys = append(keys, k)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list api keys rows: %w", err)
	}
	return keys, nil
}

// RevokeKey sets revoked_at for the given key
func (r *projectKeyRepo) RevokeKey(ctx context.Context, keyID uuid.UUID) error {
	result, err := r.db.ExecContext(ctx, `
		UPDATE project_api_keys SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL
	`, keyID)
	if err != nil {
		return fmt.Errorf("revoke api key: %w", err)
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("api key not found or already revoked")
	}
	return nil
}

// FindByKeyHash returns a non-revoked key by its hash (used by API key auth middleware)
func (r *projectKeyRepo) FindByKeyHash(ctx context.Context, keyHash string) (model.ProjectAPIKey, error) {
	var k model.ProjectAPIKey
	var idStr, projStr string
	err := r.db.QueryRowContext(ctx, `
		SELECT id, project_id, name, key_hash, last4, revoked_at, created_at
		FROM project_api_keys
		WHERE key_hash = $1 AND revoked_at IS NULL
	`, keyHash).Scan(&idStr, &projStr, &k.Name, &k.KeyHash, &k.Last4, &k.RevokedAt, &k.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return model.ProjectAPIKey{}, fmt.Errorf("api key not found or revoked")
		}
		return model.ProjectAPIKey{}, fmt.Errorf("find api key: %w", err)
	}
	k.ID, _ = uuid.Parse(idStr)
	k.ProjectID, _ = uuid.Parse(projStr)
	return k, nil
}

// FindByKeyHashAny returns the key regardless of revocation status.
// Used by APIKeyMiddleware to distinguish "not found" from "revoked".
func (r *projectKeyRepo) FindByKeyHashAny(ctx context.Context, keyHash string) (model.ProjectAPIKey, error) {
	var k model.ProjectAPIKey
	var idStr, projStr string
	err := r.db.QueryRowContext(ctx, `
		SELECT id, project_id, name, key_hash, last4, revoked_at, created_at
		FROM project_api_keys
		WHERE key_hash = $1
	`, keyHash).Scan(&idStr, &projStr, &k.Name, &k.KeyHash, &k.Last4, &k.RevokedAt, &k.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return model.ProjectAPIKey{}, fmt.Errorf("api key not found")
		}
		return model.ProjectAPIKey{}, fmt.Errorf("find api key: %w", err)
	}
	k.ID, _ = uuid.Parse(idStr)
	k.ProjectID, _ = uuid.Parse(projStr)
	return k, nil
}
