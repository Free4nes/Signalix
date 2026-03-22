package repo

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"github.com/signalix/server/internal/model"
)

// ProjectRepo defines the interface for project repository operations
type ProjectRepo interface {
	CreateProject(ctx context.Context, ownerID uuid.UUID, name string) (model.Project, error)
	ListProjectsByOwner(ctx context.Context, ownerID uuid.UUID) ([]model.Project, error)
	GetProjectByID(ctx context.Context, id uuid.UUID) (model.Project, error)
	ArchiveProject(ctx context.Context, projectID uuid.UUID) error
	HardArchiveProject(ctx context.Context, projectID uuid.UUID) error
}

type projectRepo struct {
	conn Querier
}

// NewProjectRepo creates a new ProjectRepo instance
func NewProjectRepo(db *sql.DB) ProjectRepo {
	return &projectRepo{conn: db}
}

// NewProjectRepoWithConn creates a ProjectRepo using the given Querier (tx or db)
func NewProjectRepoWithConn(conn Querier) ProjectRepo {
	return &projectRepo{conn: conn}
}

// CreateProject inserts a new project and returns the created record
func (r *projectRepo) CreateProject(ctx context.Context, ownerID uuid.UUID, name string) (model.Project, error) {
	var p model.Project
	var idStr, ownerStr string
	err := r.conn.QueryRowContext(ctx, `
		INSERT INTO projects (owner_user_id, name)
		VALUES ($1, $2)
		RETURNING id, owner_user_id, name, created_at
	`, ownerID, name).Scan(&idStr, &ownerStr, &p.Name, &p.CreatedAt)
	if err != nil {
		return model.Project{}, fmt.Errorf("create project: %w", err)
	}
	p.ID, _ = uuid.Parse(idStr)
	p.OwnerUserID, _ = uuid.Parse(ownerStr)
	return p, nil
}

// ListProjectsByOwner returns all non-archived projects owned by the given user
func (r *projectRepo) ListProjectsByOwner(ctx context.Context, ownerID uuid.UUID) ([]model.Project, error) {
	rows, err := r.conn.QueryContext(ctx, `
		SELECT id, owner_user_id, name, created_at, archived_at
		FROM projects
		WHERE owner_user_id = $1 AND archived_at IS NULL
		ORDER BY created_at DESC
	`, ownerID)
	if err != nil {
		return nil, fmt.Errorf("list projects: %w", err)
	}
	defer rows.Close()

	var projects []model.Project
	for rows.Next() {
		var p model.Project
		var idStr, ownerStr string
		var archivedAt sql.NullTime
		if err := rows.Scan(&idStr, &ownerStr, &p.Name, &p.CreatedAt, &archivedAt); err != nil {
			return nil, fmt.Errorf("scan project: %w", err)
		}
		p.ID, _ = uuid.Parse(idStr)
		p.OwnerUserID, _ = uuid.Parse(ownerStr)
		if archivedAt.Valid {
			p.ArchivedAt = &archivedAt.Time
		}
		projects = append(projects, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list projects rows: %w", err)
	}
	return projects, nil
}

// GetProjectByID returns a project by its ID (including archived)
func (r *projectRepo) GetProjectByID(ctx context.Context, id uuid.UUID) (model.Project, error) {
	var p model.Project
	var idStr, ownerStr string
	var archivedAt sql.NullTime
	err := r.conn.QueryRowContext(ctx, `
		SELECT id, owner_user_id, name, created_at, archived_at, hard_archived
		FROM projects
		WHERE id = $1
	`, id).Scan(&idStr, &ownerStr, &p.Name, &p.CreatedAt, &archivedAt, &p.HardArchived)
	if err != nil {
		if err == sql.ErrNoRows {
			return model.Project{}, fmt.Errorf("project not found")
		}
		return model.Project{}, fmt.Errorf("get project: %w", err)
	}
	p.ID, _ = uuid.Parse(idStr)
	p.OwnerUserID, _ = uuid.Parse(ownerStr)
	if archivedAt.Valid {
		p.ArchivedAt = &archivedAt.Time
	}
	return p, nil
}

// ArchiveProject sets archived_at = now() for the project. Caller must verify ownership.
func (r *projectRepo) ArchiveProject(ctx context.Context, projectID uuid.UUID) error {
	_, err := r.conn.ExecContext(ctx, `
		UPDATE projects SET archived_at = now() WHERE id = $1 AND archived_at IS NULL
	`, projectID)
	if err != nil {
		return fmt.Errorf("archive project: %w", err)
	}
	return nil
}

// HardArchiveProject sets both archived_at and hard_archived = true. Used by DELETE /projects/:id.
// hard_archived blocks new conversations and API keys; archived_at (soft) does not.
func (r *projectRepo) HardArchiveProject(ctx context.Context, projectID uuid.UUID) error {
	_, err := r.conn.ExecContext(ctx, `
		UPDATE projects SET archived_at = COALESCE(archived_at, now()), hard_archived = TRUE WHERE id = $1
	`, projectID)
	if err != nil {
		return fmt.Errorf("hard archive project: %w", err)
	}
	return nil
}
