package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/signalix/server/internal/ingest"
	"github.com/signalix/server/internal/middleware"
)

// IngestHandler handles POST /ingest (protected by APIKeyMiddleware)
type IngestHandler struct {
	svc *ingest.Service
}

// NewIngestHandler creates a new IngestHandler
func NewIngestHandler(svc *ingest.Service) *IngestHandler {
	return &IngestHandler{svc: svc}
}

// HandleIngest handles POST /ingest
func (h *IngestHandler) HandleIngest(w http.ResponseWriter, r *http.Request) {
	projectID, ok := middleware.GetProjectID(r.Context())
	if !ok {
		respondWithError(w, http.StatusUnauthorized, "missing_api_key")
		return
	}

	var payload ingest.RawPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid_payload")
		return
	}

	ack, err := h.svc.Process(r.Context(), projectID, payload)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid_payload")
		return
	}

	respondJSON(w, http.StatusOK, ack)
}
