package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/signalix/server/internal/middleware"
	"github.com/signalix/server/internal/project"
)

// ProjectHandler handles /projects endpoints
type ProjectHandler struct {
	svc *project.Service
}

// NewProjectHandler creates a new ProjectHandler
func NewProjectHandler(svc *project.Service) *ProjectHandler {
	return &ProjectHandler{svc: svc}
}

// ── request / response types ──────────────────────────────────────────────────

type createProjectRequest struct {
	Name string `json:"name"`
}

type projectResponse struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

type projectConversationResponse struct {
	ID                 string    `json:"id"`
	DisplayTitle       string    `json:"display_title"`
	LastMessagePreview string    `json:"last_message_preview"`
	UpdatedAt          time.Time `json:"updated_at"`
}

type projectWithConversationsResponse struct {
	ID            string                         `json:"id"`
	Name          string                         `json:"name"`
	CreatedAt     time.Time                      `json:"created_at"`
	Conversations []projectConversationResponse  `json:"conversations"`
}

type projectActivityItemResponse struct {
	ID         string    `json:"id"`
	Type       string    `json:"type"`
	Timestamp  time.Time `json:"timestamp"`
	ActorID    string    `json:"actor_id"`
	ActorLabel string    `json:"actor_label"`
	Summary    string    `json:"summary"`
}

type createKeyRequest struct {
	Name string `json:"name"`
}

type keyResponse struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Last4     string     `json:"last4"`
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

type createKeyResponse struct {
	keyResponse
	APIKey string `json:"api_key"`
}

// ── handlers ─────────────────────────────────────────────────────────────────

// HandleCreateProject handles POST /projects
func (h *ProjectHandler) HandleCreateProject(w http.ResponseWriter, r *http.Request) {
	callerID, ok := callerUserID(w, r)
	if !ok {
		return
	}

	var req createProjectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		respondWithError(w, http.StatusBadRequest, "name is required")
		return
	}
	if len(name) > 80 {
		respondWithError(w, http.StatusBadRequest, "name must be at most 80 characters")
		return
	}

	p, err := h.svc.CreateProject(r.Context(), callerID, name)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "failed to create project")
		return
	}

	respondJSON(w, http.StatusCreated, projectResponse{
		ID:        p.ID.String(),
		Name:      p.Name,
		CreatedAt: p.CreatedAt,
	})
}

// HandleGetProject handles GET /projects/{projectId}
func (h *ProjectHandler) HandleGetProject(w http.ResponseWriter, r *http.Request) {
	callerID, ok := callerUserID(w, r)
	if !ok {
		return
	}
	projectID, ok := parseProjectID(w, r)
	if !ok {
		return
	}

	out, err := h.svc.GetProjectWithConversations(r.Context(), callerID, projectID)
	if err != nil {
		if errors.Is(err, project.ErrNotFound) {
			respondWithError(w, http.StatusNotFound, "project not found")
			return
		}
		if errors.Is(err, project.ErrForbidden) {
			respondWithError(w, http.StatusForbidden, "forbidden")
			return
		}
		respondWithError(w, http.StatusInternalServerError, "failed to get project")
		return
	}

	convs := make([]projectConversationResponse, 0, len(out.Conversations))
	for _, c := range out.Conversations {
		convs = append(convs, projectConversationResponse{
			ID:                 c.ID.String(),
			DisplayTitle:       c.DisplayTitle,
			LastMessagePreview: c.LastMessagePreview,
			UpdatedAt:          c.UpdatedAt,
		})
	}
	respondJSON(w, http.StatusOK, projectWithConversationsResponse{
		ID:            out.Project.ID.String(),
		Name:          out.Project.Name,
		CreatedAt:     out.Project.CreatedAt,
		Conversations: convs,
	})
}

// projectActivityResponse is the JSON shape for GET /projects/:id/activity
type projectActivityResponse struct {
	Items      []projectActivityItemResponse `json:"items"`
	NextCursor *string                       `json:"next_cursor,omitempty"`
	HasMore    bool                          `json:"has_more"`
}

// HandleListProjectEvents handles GET /projects/{projectId}/activity?before=TIMESTAMP&limit=20
func (h *ProjectHandler) HandleListProjectEvents(w http.ResponseWriter, r *http.Request) {
	callerID, ok := callerUserID(w, r)
	if !ok {
		return
	}
	projectID, ok := parseProjectID(w, r)
	if !ok {
		return
	}

	limit := 50
	if q := r.URL.Query().Get("limit"); q != "" {
		n, err := strconv.Atoi(q)
		if err != nil || n < 1 || n > 100 {
			respondWithError(w, http.StatusBadRequest, "limit must be 1-100")
			return
		}
		limit = n
	}

	before := strings.TrimSpace(r.URL.Query().Get("before"))

	page, err := h.svc.ListProjectEvents(r.Context(), callerID, projectID, before, limit)
	if err != nil {
		if errors.Is(err, project.ErrNotFound) {
			respondWithError(w, http.StatusNotFound, "project not found")
			return
		}
		if errors.Is(err, project.ErrForbidden) {
			respondWithError(w, http.StatusForbidden, "forbidden")
			return
		}
		if errors.Is(err, project.ErrInvalidInput) {
			respondWithError(w, http.StatusBadRequest, err.Error())
			return
		}
		respondWithError(w, http.StatusInternalServerError, "failed to list events")
		return
	}

	items := make([]projectActivityItemResponse, 0, len(page.Items))
	for _, a := range page.Items {
		items = append(items, projectActivityItemResponse{
			ID:         a.ID.String(),
			Type:       string(a.Type),
			Timestamp:  a.Timestamp,
			ActorID:    a.ActorID.String(),
			ActorLabel: a.ActorLabel,
			Summary:    a.Summary,
		})
	}

	var nextCursor *string
	if page.NextCursor != nil {
		nextCursor = page.NextCursor // composite format: created_at|id
	}
	respondJSON(w, http.StatusOK, projectActivityResponse{
		Items:      items,
		NextCursor: nextCursor,
		HasMore:    page.HasMore,
	})
}

// HandleArchiveProject handles DELETE /projects/{projectId} (hard archive)
func (h *ProjectHandler) HandleArchiveProject(w http.ResponseWriter, r *http.Request) {
	callerID, ok := callerUserID(w, r)
	if !ok {
		return
	}
	projectID, ok := parseProjectID(w, r)
	if !ok {
		return
	}

	err := h.svc.HardArchiveProject(r.Context(), callerID, projectID)
	if err != nil {
		if errors.Is(err, project.ErrNotFound) {
			respondWithError(w, http.StatusNotFound, "project not found")
			return
		}
		if errors.Is(err, project.ErrForbidden) {
			respondWithError(w, http.StatusForbidden, "forbidden")
			return
		}
		respondWithError(w, http.StatusInternalServerError, "failed to archive project")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// HandleSoftArchiveProject handles POST /projects/{projectId}/archive (soft archive)
func (h *ProjectHandler) HandleSoftArchiveProject(w http.ResponseWriter, r *http.Request) {
	callerID, ok := callerUserID(w, r)
	if !ok {
		return
	}
	projectID, ok := parseProjectID(w, r)
	if !ok {
		return
	}

	err := h.svc.ArchiveProject(r.Context(), callerID, projectID)
	if err != nil {
		if errors.Is(err, project.ErrNotFound) {
			respondWithError(w, http.StatusNotFound, "project not found")
			return
		}
		if errors.Is(err, project.ErrForbidden) {
			respondWithError(w, http.StatusForbidden, "forbidden")
			return
		}
		if errors.Is(err, project.ErrProjectArchived) {
			respondWithError(w, http.StatusConflict, "project archived")
			return
		}
		respondWithError(w, http.StatusInternalServerError, "failed to archive project")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// HandleListProjects handles GET /projects
func (h *ProjectHandler) HandleListProjects(w http.ResponseWriter, r *http.Request) {
	callerID, ok := callerUserID(w, r)
	if !ok {
		return
	}

	projects, err := h.svc.ListProjects(r.Context(), callerID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "failed to list projects")
		return
	}

	resp := make([]projectResponse, 0, len(projects))
	for _, p := range projects {
		resp = append(resp, projectResponse{
			ID:        p.ID.String(),
			Name:      p.Name,
			CreatedAt: p.CreatedAt,
		})
	}
	respondJSON(w, http.StatusOK, resp)
}

// HandleCreateKey handles POST /projects/{projectId}/keys
func (h *ProjectHandler) HandleCreateKey(w http.ResponseWriter, r *http.Request) {
	callerID, ok := callerUserID(w, r)
	if !ok {
		return
	}
	projectID, ok := parseProjectID(w, r)
	if !ok {
		return
	}

	var req createKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Name == "" {
		respondWithError(w, http.StatusBadRequest, "name is required")
		return
	}

	created, err := h.svc.CreateKey(r.Context(), callerID, projectID, req.Name)
	if err != nil {
		if errors.Is(err, project.ErrNotFound) {
			respondWithError(w, http.StatusNotFound, "project not found")
			return
		}
		if errors.Is(err, project.ErrForbidden) {
			respondWithError(w, http.StatusForbidden, "forbidden")
			return
		}
		if errors.Is(err, project.ErrProjectArchived) {
			respondWithError(w, http.StatusConflict, "project archived")
			return
		}
		respondWithError(w, http.StatusInternalServerError, "failed to create api key")
		return
	}

	respondJSON(w, http.StatusCreated, createKeyResponse{
		keyResponse: keyResponse{
			ID:        created.Key.ID.String(),
			Name:      created.Key.Name,
			Last4:     created.Key.Last4,
			CreatedAt: created.Key.CreatedAt,
		},
		APIKey: created.PlaintextKey,
	})
}

// HandleListKeys handles GET /projects/{projectId}/keys
func (h *ProjectHandler) HandleListKeys(w http.ResponseWriter, r *http.Request) {
	callerID, ok := callerUserID(w, r)
	if !ok {
		return
	}
	projectID, ok := parseProjectID(w, r)
	if !ok {
		return
	}

	keys, err := h.svc.ListKeys(r.Context(), callerID, projectID)
	if err != nil {
		if errors.Is(err, project.ErrNotFound) {
			respondWithError(w, http.StatusNotFound, "project not found")
			return
		}
		if errors.Is(err, project.ErrForbidden) {
			respondWithError(w, http.StatusForbidden, "forbidden")
			return
		}
		respondWithError(w, http.StatusInternalServerError, "failed to list api keys")
		return
	}

	resp := make([]keyResponse, 0, len(keys))
	for _, k := range keys {
		resp = append(resp, keyResponse{
			ID:        k.ID.String(),
			Name:      k.Name,
			Last4:     k.Last4,
			CreatedAt: k.CreatedAt,
			RevokedAt: k.RevokedAt,
		})
	}
	respondJSON(w, http.StatusOK, resp)
}

// HandleRevokeKey handles POST /projects/{projectId}/keys/{keyId}/revoke
func (h *ProjectHandler) HandleRevokeKey(w http.ResponseWriter, r *http.Request) {
	callerID, ok := callerUserID(w, r)
	if !ok {
		return
	}
	projectID, ok := parseProjectID(w, r)
	if !ok {
		return
	}

	keyIDStr := chi.URLParam(r, "keyId")
	keyID, err := uuid.Parse(keyIDStr)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid key id")
		return
	}

	if err := h.svc.RevokeKey(r.Context(), callerID, projectID, keyID); err != nil {
		if errors.Is(err, project.ErrNotFound) {
			respondWithError(w, http.StatusNotFound, "project not found")
			return
		}
		if errors.Is(err, project.ErrForbidden) {
			respondWithError(w, http.StatusForbidden, "forbidden")
			return
		}
		if errors.Is(err, project.ErrProjectArchived) {
			respondWithError(w, http.StatusConflict, "project archived")
			return
		}
		respondWithError(w, http.StatusInternalServerError, "failed to revoke api key")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ── helpers ───────────────────────────────────────────────────────────────────

func callerUserID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, ok := middleware.GetUserID(r.Context())
	if !ok {
		respondWithError(w, http.StatusUnauthorized, "unauthorized")
		return uuid.Nil, false
	}
	return id, true
}

func parseProjectID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	raw := chi.URLParam(r, "projectId")
	id, err := uuid.Parse(raw)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid project id")
		return uuid.Nil, false
	}
	return id, true
}

func respondJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
