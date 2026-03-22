package middleware

import (
	"context"
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/signalix/server/internal/project"
)

const projectIDKey contextKey = "project_id"

// APIKeyMiddleware authenticates requests via the X-API-Key header.
// It hashes the raw key (SHA-256 + optional API_KEY_PEPPER, matching project.hashKey),
// looks it up in the DB, and attaches project_id to the request context.
//
// Error responses use the exact codes specified in the API contract:
//   - missing header  → 401 { "error": "missing_api_key" }
//   - unknown hash    → 401 { "error": "invalid_api_key" }
//   - revoked key     → 401 { "error": "revoked_api_key" }
func APIKeyMiddleware(svc *project.Service) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rawKey := r.Header.Get("X-API-Key")
			if rawKey == "" {
				respondWithError(w, http.StatusUnauthorized, "missing_api_key")
				return
			}

			apiKey, err := svc.FindProjectByAPIKey(r.Context(), rawKey)
			if err != nil {
				if errors.Is(err, project.ErrRevoked) {
					respondWithError(w, http.StatusUnauthorized, "revoked_api_key")
					return
				}
				respondWithError(w, http.StatusUnauthorized, "invalid_api_key")
				return
			}

			ctx := context.WithValue(r.Context(), projectIDKey, apiKey.ProjectID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetProjectID returns the project ID attached by APIKeyMiddleware
func GetProjectID(ctx context.Context) (uuid.UUID, bool) {
	id, ok := ctx.Value(projectIDKey).(uuid.UUID)
	return id, ok
}
