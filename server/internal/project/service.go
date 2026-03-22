package project

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"github.com/google/uuid"
	"github.com/signalix/server/internal/model"
	"github.com/signalix/server/internal/repo"
)

// ErrNotFound is returned when a resource does not exist
var ErrNotFound = errors.New("not found")

// ErrForbidden is returned when the caller does not own the resource
var ErrForbidden = errors.New("forbidden")

// ErrInvalidInput is returned for validation errors (e.g. invalid cursor)
var ErrInvalidInput = errors.New("invalid input")

// ErrRevoked is returned when an API key exists but has been revoked
var ErrRevoked = errors.New("revoked")

// ErrProjectArchived is returned when a mutation is attempted on an archived project
var ErrProjectArchived = errors.New("project archived")

// KeyCreated is returned from CreateKey and includes the one-time plaintext key
type KeyCreated struct {
	Key  model.ProjectAPIKey
	// PlaintextKey is returned exactly once; it is never stored in the DB
	PlaintextKey string
}

// Service provides project and API key management with ownership enforcement
type Service struct {
	db          *sql.DB
	projects    repo.ProjectRepo
	keys        repo.ProjectKeyRepo
	convs       repo.ConversationRepo
	projectEvts repo.ProjectEventRepo

	// CreateProjectTestHook, when non-nil, is called before AddProjectEvent in CreateProject.
	// Return an error to simulate failure and trigger rollback. Used for integration tests.
	CreateProjectTestHook func() error
}

// NewService creates a new project Service. db is used for transactional operations (CreateProject, ArchiveProject).
func NewService(db *sql.DB, projects repo.ProjectRepo, keys repo.ProjectKeyRepo, convs repo.ConversationRepo, projectEvts repo.ProjectEventRepo) *Service {
	return &Service{db: db, projects: projects, keys: keys, convs: convs, projectEvts: projectEvts}
}

// CreateProject creates a new project owned by ownerID. Project and project_created event are atomic.
func (s *Service) CreateProject(ctx context.Context, ownerID uuid.UUID, name string) (model.Project, error) {
	if name == "" {
		return model.Project{}, fmt.Errorf("project name is required")
	}
	payload := ProjectCreatedPayload{Name: name}
	if err := payload.Validate(); err != nil {
		return model.Project{}, fmt.Errorf("event payload: %w", err)
	}
	ev := NewProjectCreatedEvent(name)
	var p model.Project
	err := repo.WithTx(ctx, s.db, func(tx *repo.Tx) error {
		var err error
		p, err = tx.Projects.CreateProject(ctx, ownerID, name)
		if err != nil {
			return err
		}
		if s.CreateProjectTestHook != nil {
			if err := s.CreateProjectTestHook(); err != nil {
				return err
			}
		}
		return s.addProjectEvent(ctx, tx.ProjectEvts, p.ID, ownerID, ev)
	})
	if err != nil {
		return model.Project{}, err
	}
	return p, nil
}

// ListProjects returns all projects owned by ownerID
func (s *Service) ListProjects(ctx context.Context, ownerID uuid.UUID) ([]model.Project, error) {
	return s.projects.ListProjectsByOwner(ctx, ownerID)
}

// ProjectEventsPage holds paginated project activity items
type ProjectEventsPage struct {
	Items      []ActivityItem
	HasMore    bool
	NextCursor *string // composite format: created_at|id
}

// ListProjectEvents returns projected activity for a project. Only the project owner can access.
// Owner may view activity even for archived projects.
// Authorization: ErrNotFound if project missing, ErrForbidden if not owner.
// before is the composite cursor "created_at|id"; empty means no filter.
func (s *Service) ListProjectEvents(ctx context.Context, callerID uuid.UUID, projectID uuid.UUID, before string, limit int) (ProjectEventsPage, error) {
	if err := s.assertOwnerForActivity(ctx, callerID, projectID); err != nil {
		return ProjectEventsPage{}, err
	}
	if limit <= 0 {
		limit = 50
	}
	if limit > 100 {
		limit = 100
	}
	beforeCursor, err := repo.ParseActivityBeforeCursor(before)
	if err != nil {
		return ProjectEventsPage{}, fmt.Errorf("%w: %w", ErrInvalidInput, err)
	}
	res, err := s.projectEvts.ListByProject(ctx, projectID, beforeCursor, limit)
	if err != nil {
		return ProjectEventsPage{}, err
	}
	events := make([]EventForProjection, len(res.Events))
	for i, ew := range res.Events {
		events[i] = EventForProjection{
			Event:            ew.ProjectEvent,
			ActorDisplayName: nullStringToString(ew.ActorDisplayName),
			ActorPhoneNumber: nullStringToString(ew.ActorPhoneNumber),
		}
	}
	items, nextCursor, err := BuildProjectActivity(events, res.HasMore)
	if err != nil {
		return ProjectEventsPage{}, err
	}
	return ProjectEventsPage{
		Items:      items,
		HasMore:    res.HasMore,
		NextCursor: nextCursor,
	}, nil
}

// addProjectEvent records an audit event. Internal only. Only service layer methods call it with factory-produced events.
func (s *Service) addProjectEvent(ctx context.Context, r repo.ProjectEventRepo, projectID, actorID uuid.UUID, ev ProjectEvent) error {
	return r.AddProjectEvent(ctx, projectID, actorID, string(ev.EventType), ev.Version, ev.Payload)
}

// GetProjectWithConversations returns a project and its conversations for the caller. Returns ErrNotFound if project doesn't exist or is archived, ErrForbidden if not owned.
func (s *Service) GetProjectWithConversations(ctx context.Context, callerID uuid.UUID, projectID uuid.UUID) (model.ProjectWithConversations, error) {
	p, err := s.projects.GetProjectByID(ctx, projectID)
	if err != nil {
		return model.ProjectWithConversations{}, ErrNotFound
	}
	if p.ArchivedAt != nil {
		return model.ProjectWithConversations{}, ErrNotFound
	}
	if p.OwnerUserID != callerID {
		return model.ProjectWithConversations{}, ErrForbidden
	}
	convs, err := s.convs.ListConversationsForUserByProject(ctx, callerID, projectID)
	if err != nil {
		return model.ProjectWithConversations{}, fmt.Errorf("list conversations: %w", err)
	}
	return model.ProjectWithConversations{Project: p, Conversations: convs}, nil
}

// CreateKey generates a new API key for the project, enforcing ownership
func (s *Service) CreateKey(ctx context.Context, callerID uuid.UUID, projectID uuid.UUID, keyName string) (KeyCreated, error) {
	if err := s.assertOwner(ctx, callerID, projectID); err != nil {
		return KeyCreated{}, err
	}
	if keyName == "" {
		return KeyCreated{}, fmt.Errorf("key name is required")
	}

	plaintext, keyHash, last4, err := generateAPIKey()
	if err != nil {
		return KeyCreated{}, fmt.Errorf("generate api key: %w", err)
	}

	k, err := s.keys.CreateKey(ctx, projectID, keyName, keyHash, last4)
	if err != nil {
		return KeyCreated{}, fmt.Errorf("store api key: %w", err)
	}
	return KeyCreated{Key: k, PlaintextKey: plaintext}, nil
}

// ListKeys returns all API keys for a project, enforcing ownership
func (s *Service) ListKeys(ctx context.Context, callerID uuid.UUID, projectID uuid.UUID) ([]model.ProjectAPIKey, error) {
	if err := s.assertOwner(ctx, callerID, projectID); err != nil {
		return nil, err
	}
	return s.keys.ListKeys(ctx, projectID)
}

// RevokeKey revokes an API key, enforcing project ownership
func (s *Service) RevokeKey(ctx context.Context, callerID uuid.UUID, projectID uuid.UUID, keyID uuid.UUID) error {
	if err := s.assertOwner(ctx, callerID, projectID); err != nil {
		return err
	}
	return s.keys.RevokeKey(ctx, keyID)
}

// ArchiveProject soft-archives a project (POST /archive). Returns ErrNotFound if not found, ErrForbidden if not owner.
// Idempotent: if already archived, returns nil without emitting another project_archived event.
// Soft-archive does NOT set hard_archived and does NOT block new conversations or API keys.
func (s *Service) ArchiveProject(ctx context.Context, callerID uuid.UUID, projectID uuid.UUID) error {
	p, err := s.projects.GetProjectByID(ctx, projectID)
	if err != nil {
		return ErrNotFound
	}
	if p.OwnerUserID != callerID {
		return ErrForbidden
	}
	if p.ArchivedAt != nil {
		return nil // already archived, idempotent no-op
	}
	return repo.WithTx(ctx, s.db, func(tx *repo.Tx) error {
		if err := tx.Projects.ArchiveProject(ctx, projectID); err != nil {
			return err
		}
		return s.addProjectEvent(ctx, tx.ProjectEvts, projectID, callerID, NewProjectArchivedEvent())
	})
}

// HardArchiveProject hard-archives a project (DELETE /projects/:id). Returns ErrNotFound if not found, ErrForbidden if not owner.
// Idempotent: if already hard-archived, returns nil without emitting another project_archived event.
// Hard-archive sets hard_archived=true which blocks new conversations and API keys.
func (s *Service) HardArchiveProject(ctx context.Context, callerID uuid.UUID, projectID uuid.UUID) error {
	p, err := s.projects.GetProjectByID(ctx, projectID)
	if err != nil {
		return ErrNotFound
	}
	if p.OwnerUserID != callerID {
		return ErrForbidden
	}
	if p.HardArchived {
		return nil // already hard-archived, idempotent no-op
	}
	return repo.WithTx(ctx, s.db, func(tx *repo.Tx) error {
		if err := tx.Projects.HardArchiveProject(ctx, projectID); err != nil {
			return err
		}
		if p.ArchivedAt != nil {
			// already soft-archived; don't emit a second project_archived event
			return nil
		}
		return s.addProjectEvent(ctx, tx.ProjectEvts, projectID, callerID, NewProjectArchivedEvent())
	})
}

// FindProjectByAPIKey looks up the project associated with a raw API key.
// Returns ErrNotFound if the hash is unknown, ErrRevoked if the key is revoked.
func (s *Service) FindProjectByAPIKey(ctx context.Context, rawKey string) (model.ProjectAPIKey, error) {
	hash := hashKey(rawKey)
	k, err := s.keys.FindByKeyHashAny(ctx, hash)
	if err != nil {
		return model.ProjectAPIKey{}, ErrNotFound
	}
	if k.RevokedAt != nil {
		return model.ProjectAPIKey{}, ErrRevoked
	}
	return k, nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

func nullStringToString(n sql.NullString) string {
	if n.Valid {
		return n.String
	}
	return ""
}

func (s *Service) assertOwner(ctx context.Context, callerID uuid.UUID, projectID uuid.UUID) error {
	p, err := s.projects.GetProjectByID(ctx, projectID)
	if err != nil {
		return ErrNotFound
	}
	if p.ArchivedAt != nil {
		return ErrProjectArchived
	}
	if p.OwnerUserID != callerID {
		return ErrForbidden
	}
	return nil
}

// assertOwnerForActivity allows owner to view activity even when project is archived
func (s *Service) assertOwnerForActivity(ctx context.Context, callerID uuid.UUID, projectID uuid.UUID) error {
	p, err := s.projects.GetProjectByID(ctx, projectID)
	if err != nil {
		return ErrNotFound
	}
	if p.OwnerUserID != callerID {
		return ErrForbidden
	}
	return nil
}

// generateAPIKey produces a "sk_live_<base64url>" token, its SHA-256 hex hash,
// and the last 4 characters of the token (for display).
// An optional API_KEY_PEPPER env var is mixed into the hash.
func generateAPIKey() (plaintext, keyHash, last4 string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return
	}
	random := base64.RawURLEncoding.EncodeToString(b)
	plaintext = "sk_live_" + random
	keyHash = hashKey(plaintext)
	last4 = plaintext[len(plaintext)-4:]
	return
}

func hashKey(key string) string {
	pepper := os.Getenv("API_KEY_PEPPER")
	h := sha256.Sum256([]byte(key + pepper))
	return hex.EncodeToString(h[:])
}
