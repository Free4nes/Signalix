package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/signalix/server/internal/auth"
	"github.com/signalix/server/internal/model"
	"github.com/signalix/server/internal/repo"
)

type contextKey string

const (
	userKey   contextKey = "user"
	userIDKey contextKey = "user_id"
	deviceIDKey contextKey = "device_id"
)

// AuthMiddleware validates JWT tokens, loads user from DB, and attaches user to context
func AuthMiddleware(jwtService *auth.JWTService, userRepo repo.UserRepo) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				respondWithError(w, http.StatusUnauthorized, "missing authorization header")
				return
			}

			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || parts[0] != "Bearer" {
				respondWithError(w, http.StatusUnauthorized, "invalid authorization header format")
				return
			}

			tokenString := strings.TrimSpace(parts[1])
			if tokenString == "" {
				respondWithError(w, http.StatusUnauthorized, "missing token")
				return
			}

			claims, err := jwtService.VerifyToken(tokenString)
			if err != nil {
				respondWithError(w, http.StatusUnauthorized, "invalid or expired token")
				return
			}

			user, err := userRepo.GetByID(r.Context(), claims.UserID.String())
			if err != nil {
				respondWithError(w, http.StatusUnauthorized, "user not found")
				return
			}

			ctx := context.WithValue(r.Context(), userKey, &user)
			ctx = context.WithValue(ctx, userIDKey, claims.UserID)
			if claims.DeviceID != uuid.Nil {
				ctx = context.WithValue(ctx, deviceIDKey, claims.DeviceID)
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetUser returns the user attached to the request context (set by AuthMiddleware)
func GetUser(ctx context.Context) (*model.User, bool) {
	u, ok := ctx.Value(userKey).(*model.User)
	return u, ok
}

// GetUserID extracts user ID from context
func GetUserID(ctx context.Context) (uuid.UUID, bool) {
	userID, ok := ctx.Value(userIDKey).(uuid.UUID)
	return userID, ok
}

// GetDeviceID extracts device ID from context
func GetDeviceID(ctx context.Context) (uuid.UUID, bool) {
	deviceID, ok := ctx.Value(deviceIDKey).(uuid.UUID)
	return deviceID, ok
}

// respondWithError sends a JSON error response
func respondWithError(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	response := map[string]string{"error": message}
	_ = json.NewEncoder(w).Encode(response)
}
