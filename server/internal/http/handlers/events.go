package handlers

import (
	"errors"
	"net/http"
	"time"

	"github.com/signalix/server/internal/middleware"
	"github.com/signalix/server/internal/project"
	"github.com/signalix/server/internal/repo"
)

// EventsHandler handles event listing endpoints
type EventsHandler struct {
	events   repo.EventRepo
	projects repo.ProjectRepo
}

// NewEventsHandler creates a new EventsHandler
func NewEventsHandler(events repo.EventRepo, projects repo.ProjectRepo) *EventsHandler {
	return &EventsHandler{events: events, projects: projects}
}

// eventResponse is the JSON shape returned for each event
type eventResponse struct {
	ID         string          `json:"id"`
	Event      string          `json:"event"`
	ReceivedAt time.Time       `json:"received_at"`
	Payload    interface{}     `json:"payload"`
}

// HandleListEvents handles GET /projects/{projectId}/events
func (h *EventsHandler) HandleListEvents(w http.ResponseWriter, r *http.Request) {
	callerID, ok := middleware.GetUserID(r.Context())
	if !ok {
		respondWithError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	projectID, ok := parseProjectID(w, r)
	if !ok {
		return
	}

	// Ownership check: load project and verify caller owns it
	proj, err := h.projects.GetProjectByID(r.Context(), projectID)
	if err != nil {
		respondWithError(w, http.StatusNotFound, "project not found")
		return
	}
	if proj.OwnerUserID != callerID {
		respondWithError(w, http.StatusForbidden, "forbidden")
		return
	}

	events, err := h.events.ListByProject(r.Context(), projectID, 50)
	if err != nil {
		if errors.Is(err, project.ErrNotFound) {
			respondWithError(w, http.StatusNotFound, "project not found")
			return
		}
		respondWithError(w, http.StatusInternalServerError, "failed to list events")
		return
	}

	resp := make([]eventResponse, 0, len(events))
	for _, e := range events {
		resp = append(resp, eventResponse{
			ID:         e.ID.String(),
			Event:      e.Event,
			ReceivedAt: e.ReceivedAt,
			Payload:    e.Payload,
		})
	}
	respondJSON(w, http.StatusOK, resp)
}

