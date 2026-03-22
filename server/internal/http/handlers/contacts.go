package handlers

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"

	"github.com/signalix/server/internal/phone"
	"github.com/signalix/server/internal/repo"
)

// ContactsHandler handles /contacts endpoints
type ContactsHandler struct {
	userRepo          repo.UserRepo
	devAutoCreateUsers bool // when true, unknown phones are auto-provisioned (DEV only)
}

// NewContactsHandler creates a new ContactsHandler.
// devAutoCreate mirrors config.DevAutoCreateUsers; must be false in production.
func NewContactsHandler(userRepo repo.UserRepo, devAutoCreate bool) *ContactsHandler {
	return &ContactsHandler{userRepo: userRepo, devAutoCreateUsers: devAutoCreate}
}

// ── request / response types ──────────────────────────────────────────────────

type lookupRequest struct {
	PhoneNumber string `json:"phone_number"`
}

type lookupResponse struct {
	UserID string `json:"user_id"`
}

type syncRequest struct {
	Phones []string `json:"phones"`
}

type syncUser struct {
	UserID      string `json:"user_id"`
	PhoneNumber string `json:"phone_number"`
	DisplayName string `json:"display_name,omitempty"`
}

type syncResponse struct {
	Users []syncUser `json:"users"`
}

// ── handlers ──────────────────────────────────────────────────────────────────

// HandleLookup handles POST /contacts/lookup
func (h *ContactsHandler) HandleLookup(w http.ResponseWriter, r *http.Request) {
	_, ok := callerUserID(w, r)
	if !ok {
		return
	}

	var req lookupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	raw := strings.TrimSpace(req.PhoneNumber)
	if raw == "" {
		respondWithError(w, http.StatusBadRequest, "phone_number is required")
		return
	}
	normalized, err := phone.Normalize(raw)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid phone_number: "+err.Error())
		return
	}

	user, err := h.userRepo.GetByPhone(r.Context(), normalized)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			if h.devAutoCreateUsers {
				// DEV_AUTOCREATE_USERS: provision a minimal user record so we can test
				// messaging without needing a real second phone to log in.
				user, err = h.userRepo.GetOrCreateByPhone(r.Context(), normalized)
				if err != nil {
					respondWithError(w, http.StatusInternalServerError, "failed to auto-create user")
					return
				}
				log.Printf("[DEV] auto-created user for phone %s id=%s", normalized, user.ID)
			} else {
				respondWithError(w, http.StatusNotFound, "user not found")
				return
			}
		} else {
			respondWithError(w, http.StatusInternalServerError, "failed to lookup user")
			return
		}
	}

	respondJSON(w, http.StatusOK, lookupResponse{
		UserID: user.ID.String(),
	})
}

// HandleSync handles POST /contacts/sync
func (h *ContactsHandler) HandleSync(w http.ResponseWriter, r *http.Request) {
	_, ok := callerUserID(w, r)
	if !ok {
		return
	}

	var req syncRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	phones := normalizeAndDedupePhones(req.Phones)
	if len(phones) == 0 {
		respondJSON(w, http.StatusOK, syncResponse{Users: []syncUser{}})
		return
	}
	log.Printf("[contacts/sync] request with %d phone(s)", len(phones))
	users, err := h.userRepo.FindUsersByPhones(r.Context(), phones)
	if err != nil {
		log.Printf("[contacts/sync] FindUsersByPhones error: %v", err)
		respondWithError(w, http.StatusInternalServerError, "failed to sync contacts")
		return
	}
	out := make([]syncUser, 0, len(users))
	for _, u := range users {
		out = append(out, syncUser{UserID: u.ID.String(), PhoneNumber: u.PhoneNumber, DisplayName: u.DisplayName})
	}
	log.Printf("[contacts/sync] matched %d user(s)", len(out))
	respondJSON(w, http.StatusOK, syncResponse{Users: out})
}

// normalizeAndDedupePhones uses phone.NormalizeOrEmpty for each input and dedupes
func normalizeAndDedupePhones(phones []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, p := range phones {
		s := phone.NormalizeOrEmpty(p)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		result = append(result, s)
	}
	return result
}
