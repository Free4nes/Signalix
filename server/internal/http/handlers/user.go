package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/signalix/server/internal/middleware"
	"github.com/signalix/server/internal/repo"
)

// UserHandler handles /users block endpoints
type UserHandler struct {
	blockedRepo repo.BlockedRepo
}

// NewUserHandler creates a new UserHandler
func NewUserHandler(blockedRepo repo.BlockedRepo) *UserHandler {
	return &UserHandler{blockedRepo: blockedRepo}
}

type blockRequest struct {
	BlockedUserID string `json:"blocked_user_id"`
}

// HandleBlock handles POST /users/block
func (h *UserHandler) HandleBlock(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserID(r.Context())
	if !ok || userID == uuid.Nil {
		respondWithError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req blockRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	blockedID, err := uuid.Parse(strings.TrimSpace(req.BlockedUserID))
	if err != nil || blockedID == uuid.Nil {
		respondWithError(w, http.StatusBadRequest, "blocked_user_id is required")
		return
	}
	if blockedID == userID {
		respondWithError(w, http.StatusBadRequest, "cannot block yourself")
		return
	}
	if err := h.blockedRepo.Block(r.Context(), userID, blockedID); err != nil {
		respondWithError(w, http.StatusInternalServerError, "failed to block user")
		return
	}
	log.Printf("BLOCK_USER_CREATED blocker=%s blocked=%s", userID, blockedID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// blockedUserResponse is the JSON shape for GET /users/blocked
type blockedUserResponse struct {
	UserID      string `json:"user_id"`
	Phone       string `json:"phone"`
	DisplayName string `json:"display_name"`
}

// HandleGetBlockedUsers handles GET /users/blocked
func (h *UserHandler) HandleGetBlockedUsers(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserID(r.Context())
	if !ok || userID == uuid.Nil {
		respondWithError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	list, err := h.blockedRepo.ListBlocked(r.Context(), userID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "failed to list blocked users")
		return
	}
	log.Printf("BLOCKED_USERS_FETCH user=%s count=%d", userID, len(list))
	out := make([]blockedUserResponse, 0, len(list))
	for _, u := range list {
		out = append(out, blockedUserResponse{
			UserID:      u.ID.String(),
			Phone:       u.PhoneNumber,
			DisplayName: u.DisplayName,
		})
	}
	respondJSON(w, http.StatusOK, out)
}

// HandleUnblock handles DELETE /users/block/{blockedUserId}
func (h *UserHandler) HandleUnblock(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserID(r.Context())
	if !ok || userID == uuid.Nil {
		respondWithError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	blockedIDStr := chi.URLParam(r, "blockedUserId")
	blockedID, err := uuid.Parse(blockedIDStr)
	if err != nil || blockedID == uuid.Nil {
		respondWithError(w, http.StatusBadRequest, "invalid blocked_user_id")
		return
	}
	if err := h.blockedRepo.Unblock(r.Context(), userID, blockedID); err != nil {
		respondWithError(w, http.StatusInternalServerError, "failed to unblock user")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}
