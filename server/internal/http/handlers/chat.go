package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/signalix/server/internal/chat"
	"github.com/signalix/server/internal/model"
	"github.com/signalix/server/internal/project"
	"github.com/signalix/server/internal/push"
	"github.com/signalix/server/internal/ratelimit"
	"github.com/signalix/server/internal/repo"
	"github.com/signalix/server/internal/ws"
)

// ChatHandler handles /conversations endpoints
type ChatHandler struct {
	svc           *chat.Service
	hub           *ws.Hub
	convRepo      repo.ConversationRepo
	pushTokenRepo repo.PushTokenRepo
	userRepo      repo.UserRepo
	reactionRepo  repo.ReactionRepo
	blockedRepo   repo.BlockedRepo
	msgLimiter    *ratelimit.MessageLimiter
}

// NewChatHandler creates a new ChatHandler
func NewChatHandler(svc *chat.Service, hub *ws.Hub, convRepo repo.ConversationRepo, pushTokenRepo repo.PushTokenRepo, userRepo repo.UserRepo, reactionRepo repo.ReactionRepo, blockedRepo repo.BlockedRepo, msgLimiter *ratelimit.MessageLimiter) *ChatHandler {
	return &ChatHandler{svc: svc, hub: hub, convRepo: convRepo, pushTokenRepo: pushTokenRepo, userRepo: userRepo, reactionRepo: reactionRepo, blockedRepo: blockedRepo, msgLimiter: msgLimiter}
}

// ── request / response types ──────────────────────────────────────────────────

type createConversationRequest struct {
	MemberUserIDs []string `json:"member_user_ids"`
	Title         *string  `json:"title,omitempty"`
	ProjectID     *string  `json:"project_id,omitempty"`
}

type createConversationResponse struct {
	ID                 string     `json:"id"`
	IsGroup            bool       `json:"is_group"`
	Title              *string    `json:"title,omitempty"`
	DisplayTitle       string     `json:"display_title"`
	Members            []string   `json:"members"`
	ProjectID          *string    `json:"project_id,omitempty"`
	ProjectName        string     `json:"project_name,omitempty"`
	LastMessagePreview string     `json:"last_message_preview"`
	LastMessageAt      *time.Time `json:"last_message_at,omitempty"`
}

type conversationResponse struct {
	ID                 string     `json:"id"`
	IsGroup            bool       `json:"is_group"`
	Title              *string    `json:"title,omitempty"`
	DisplayTitle       string     `json:"display_title"`
	Members            []string   `json:"members"`
	OtherAvatarURL     *string    `json:"other_avatar_url,omitempty"` // 1:1 only: the other participant's avatar
	ProjectID          *string    `json:"project_id,omitempty"`
	ProjectName        string     `json:"project_name,omitempty"`
	LastMessagePreview string     `json:"last_message_preview"`
	LastMessageAt      *time.Time `json:"last_message_at,omitempty"`
}

type memberDetail struct {
	UserID      string `json:"user_id"`
	PhoneNumber string `json:"phone_number"`
	Phone       string `json:"phone"` // alias for phone_number
	DisplayName string `json:"display_name,omitempty"`
	AvatarURL   string `json:"avatar_url,omitempty"`
}

type conversationDetailResponse struct {
	ID           string         `json:"id"`
	Name         string         `json:"name"`
	IsGroup      bool           `json:"is_group"`
	Title        *string        `json:"title,omitempty"`
	DisplayTitle string         `json:"display_title"`
	Members      []memberDetail `json:"members"`
	ProjectID    *string        `json:"project_id,omitempty"`
	ProjectName  string         `json:"project_name,omitempty"`
}

type patchConversationRequest struct {
	Title *string `json:"title,omitempty"`
}

type addMemberRequest struct {
	UserID string `json:"user_id"`
}

type messageResponse struct {
	ID                 string            `json:"id"`
	SenderUserID       string            `json:"sender_user_id"`
	SenderDisplayName  string            `json:"sender_display_name,omitempty"`
	SentAt             time.Time         `json:"sent_at"`
	BodyCiphertext     string            `json:"body_ciphertext"` // base64
	BodyPreview        string            `json:"body_preview"`
	MsgType            string            `json:"msg_type"` // "text" | "audio"
	AudioURL           *string           `json:"audio_url,omitempty"`
	AudioDurationMs    *int              `json:"audio_duration_ms,omitempty"`
	AudioMime          *string           `json:"audio_mime,omitempty"`
	DeletedForEveryone bool              `json:"deleted_for_everyone"`
	DeletedAt         *time.Time         `json:"deleted_at,omitempty"`
	Status             string            `json:"status"` // sent, delivered, read
	ReadAt             *time.Time        `json:"read_at,omitempty"`
	EditedAt           *time.Time        `json:"edited_at,omitempty"`
	ReplyToID          *string           `json:"reply_to_id,omitempty"`
	ReplyTo            *struct {
		ID   string `json:"id"`
		Body string `json:"body"`
	} `json:"reply_to,omitempty"`
	Reactions  map[string]int `json:"reactions,omitempty"`
	MyReaction string         `json:"my_reaction,omitempty"`
}

type createMessageRequest struct {
	BodyCiphertextBase64 string  `json:"body_ciphertext_base64"`
	BodyPreview          string  `json:"body_preview"`
	Body                 string  `json:"body"`    // alternative: plaintext body when body_ciphertext_base64 omitted
	MsgType              string  `json:"msg_type"` // "text" | "image" (optional, default "text")
	ReplyToID            *string `json:"reply_to_id,omitempty"`
}

type uploadImageResponse struct {
	URL string `json:"url"`
}

type editMessageRequest struct {
	Body string `json:"body"`
}

type audioUploadResponse struct {
	AudioURL        string `json:"audio_url"`
	AudioDurationMs int    `json:"audio_duration_ms"`
	AudioMime       string `json:"audio_mime"`
	MessageID       string `json:"message_id"`
}

const (
	maxAudioSize  = 10 << 20 // 10 MB
	maxImageSize  = 10 << 20 // 10 MB
	uploadsDir    = "/app/uploads/audio"
	uploadsDirDev = "uploads/audio"
	imagesDir     = "/app/uploads/images"
	imagesDirDev  = "uploads/images"
)

// ── handlers ──────────────────────────────────────────────────────────────────

// HandleCreateConversation handles POST /conversations
func (h *ChatHandler) HandleCreateConversation(w http.ResponseWriter, r *http.Request) {
	callerID, ok := callerUserID(w, r)
	if !ok {
		return
	}

	var req createConversationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.MemberUserIDs) == 0 {
		respondWithError(w, http.StatusBadRequest, "member_user_ids is required")
		return
	}

	ids := make([]uuid.UUID, 0, len(req.MemberUserIDs))
	for _, s := range req.MemberUserIDs {
		u, err := uuid.Parse(s)
		if err != nil {
			respondWithError(w, http.StatusBadRequest, "invalid member_user_id: "+s)
			return
		}
		ids = append(ids, u)
	}

	var projectID *uuid.UUID
	if req.ProjectID != nil && *req.ProjectID != "" {
		p, err := uuid.Parse(*req.ProjectID)
		if err != nil {
			respondWithError(w, http.StatusBadRequest, "invalid project_id")
			return
		}
		projectID = &p
	}

	conv, err := h.svc.CreateConversation(r.Context(), callerID, ids, req.Title, projectID)
	if err != nil {
		if errors.Is(err, chat.ErrInvalidInput) {
			respondWithError(w, http.StatusBadRequest, err.Error())
			return
		}
		if errors.Is(err, chat.ErrForbidden) {
			respondWithError(w, http.StatusForbidden, "project not owned by you")
			return
		}
		if errors.Is(err, project.ErrProjectArchived) {
			respondWithError(w, http.StatusConflict, "project archived")
			return
		}
		respondWithError(w, http.StatusInternalServerError, "failed to create conversation")
		return
	}

	members := make([]string, 0, len(conv.Members))
	for _, m := range conv.Members {
		members = append(members, m.String())
	}
	var projectIDStr *string
	if conv.ProjectID != nil {
		s := conv.ProjectID.String()
		projectIDStr = &s
	}
	respondJSON(w, http.StatusCreated, createConversationResponse{
		ID:                 conv.ID.String(),
		IsGroup:            conv.IsGroup,
		Title:              conv.Title,
		DisplayTitle:       conv.DisplayTitle,
		Members:            members,
		ProjectID:          projectIDStr,
		ProjectName:        conv.ProjectName,
		LastMessagePreview: conv.LastMessagePreview,
		LastMessageAt:      conv.LastMessageAt,
	})
}

// HandleListConversations handles GET /conversations
func (h *ChatHandler) HandleListConversations(w http.ResponseWriter, r *http.Request) {
	callerID, ok := callerUserID(w, r)
	if !ok {
		return
	}

	convs, err := h.svc.ListConversations(r.Context(), callerID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "failed to list conversations")
		return
	}

	log.Printf("CONVERSATION_LIST_FETCH user=%s convs=%d", callerID.String(), len(convs))

	resp := make([]conversationResponse, 0, len(convs))
	for _, c := range convs {
		members := make([]string, 0, len(c.Members))
		for _, m := range c.Members {
			members = append(members, m.String())
		}
		var projectIDStr *string
		if c.ProjectID != nil {
			s := c.ProjectID.String()
			projectIDStr = &s
		}
		resp = append(resp, conversationResponse{
			ID:                 c.ID.String(),
			IsGroup:            c.IsGroup,
			Title:              c.Title,
			DisplayTitle:       c.DisplayTitle,
			Members:            members,
			OtherAvatarURL:     c.OtherUserAvatarURL,
			ProjectID:          projectIDStr,
			ProjectName:        c.ProjectName,
			LastMessagePreview: c.LastMessagePreview,
			LastMessageAt:      c.LastMessageAt,
		})
	}
	respondJSON(w, http.StatusOK, resp)
}

// HandleGetConversation handles GET /conversations/:id
func (h *ChatHandler) HandleGetConversation(w http.ResponseWriter, r *http.Request) {
	log.Printf("CONVERSATION_DETAILS_FETCH id=%s", chi.URLParam(r, "id"))
	callerID, ok := callerUserID(w, r)
	if !ok {
		log.Printf("CONVERSATION_DETAILS_FETCH_ERROR id=%s err=unauthorized", chi.URLParam(r, "id"))
		return
	}
	convID, ok := parseConversationID(w, r)
	if !ok {
		log.Printf("CONVERSATION_DETAILS_FETCH_ERROR id=%s err=invalid_conversation_id", chi.URLParam(r, "id"))
		return
	}

	conv, err := h.svc.GetConversation(r.Context(), callerID, convID)
	if err != nil {
		idParam := chi.URLParam(r, "id")
		if errors.Is(err, chat.ErrForbidden) {
			log.Printf("CONVERSATION_DETAILS_FETCH_ERROR id=%s err=forbidden", idParam)
			respondWithError(w, http.StatusForbidden, "forbidden")
			return
		}
		log.Printf("CONVERSATION_DETAILS_FETCH_ERROR id=%s err=%v", idParam, err)
		respondWithError(w, http.StatusInternalServerError, "failed to get conversation")
		return
	}

	log.Printf("CONVERSATION_DETAILS_FETCH_OK id=%s members=%d", convID, len(conv.Members))
	members := make([]memberDetail, 0, len(conv.Members))
	ctx := r.Context()
	for _, mID := range conv.Members {
		u, err := h.userRepo.GetByID(ctx, mID.String())
		if err != nil {
			members = append(members, memberDetail{UserID: mID.String(), PhoneNumber: "", Phone: "", DisplayName: "", AvatarURL: ""})
			continue
		}
		dn := ""
		if strings.TrimSpace(u.DisplayName) != "" {
			dn = u.DisplayName
		}
		members = append(members, memberDetail{
			UserID:      mID.String(),
			PhoneNumber: u.PhoneNumber,
			Phone:       u.PhoneNumber,
			DisplayName: dn,
			AvatarURL:   u.AvatarURL,
		})
	}

	name := conv.DisplayTitle
	if conv.Title != nil && strings.TrimSpace(*conv.Title) != "" {
		name = strings.TrimSpace(*conv.Title)
	}
	if name == "" {
		name = "Group"
	}

	var projectIDStr *string
	if conv.ProjectID != nil {
		s := conv.ProjectID.String()
		projectIDStr = &s
	}
	respondJSON(w, http.StatusOK, conversationDetailResponse{
		ID:           conv.ID.String(),
		Name:         name,
		IsGroup:      conv.IsGroup,
		Title:        conv.Title,
		DisplayTitle: conv.DisplayTitle,
		Members:      members,
		ProjectID:    projectIDStr,
		ProjectName:  conv.ProjectName,
	})
}

// HandlePatchConversation handles PATCH /conversations/:id (rename group)
func (h *ChatHandler) HandlePatchConversation(w http.ResponseWriter, r *http.Request) {
	callerID, ok := callerUserID(w, r)
	if !ok {
		return
	}
	convID, ok := parseConversationID(w, r)
	if !ok {
		return
	}

	var req patchConversationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	conv, err := h.svc.UpdateConversationTitle(r.Context(), callerID, convID, req.Title)
	if err != nil {
		if errors.Is(err, chat.ErrForbidden) {
			respondWithError(w, http.StatusForbidden, "forbidden")
			return
		}
		respondWithError(w, http.StatusInternalServerError, "failed to update conversation")
		return
	}

	members := make([]string, 0, len(conv.Members))
	for _, m := range conv.Members {
		members = append(members, m.String())
	}
	var projectIDStr *string
	if conv.ProjectID != nil {
		s := conv.ProjectID.String()
		projectIDStr = &s
	}
	respondJSON(w, http.StatusOK, conversationResponse{
		ID:                 conv.ID.String(),
		IsGroup:            conv.IsGroup,
		Title:              conv.Title,
		DisplayTitle:       conv.DisplayTitle,
		Members:            members,
		ProjectID:          projectIDStr,
		ProjectName:        conv.ProjectName,
		LastMessagePreview: conv.LastMessagePreview,
		LastMessageAt:      conv.LastMessageAt,
	})
}

// HandleAddMember handles POST /conversations/:id/members
func (h *ChatHandler) HandleAddMember(w http.ResponseWriter, r *http.Request) {
	callerID, ok := callerUserID(w, r)
	if !ok {
		return
	}
	convID, ok := parseConversationID(w, r)
	if !ok {
		return
	}

	var req addMemberRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.UserID == "" {
		respondWithError(w, http.StatusBadRequest, "user_id is required")
		return
	}
	userID, err := uuid.Parse(req.UserID)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid user_id")
		return
	}

	conv, err := h.svc.AddConversationMember(r.Context(), callerID, convID, userID)
	if err != nil {
		if errors.Is(err, chat.ErrForbidden) {
			respondWithError(w, http.StatusForbidden, "forbidden")
			return
		}
		respondWithError(w, http.StatusInternalServerError, "failed to add member")
		return
	}

	members := make([]string, 0, len(conv.Members))
	for _, m := range conv.Members {
		members = append(members, m.String())
	}
	var projectIDStr *string
	if conv.ProjectID != nil {
		s := conv.ProjectID.String()
		projectIDStr = &s
	}
	respondJSON(w, http.StatusOK, conversationResponse{
		ID:                 conv.ID.String(),
		IsGroup:            conv.IsGroup,
		Title:              conv.Title,
		DisplayTitle:       conv.DisplayTitle,
		Members:            members,
		ProjectID:          projectIDStr,
		ProjectName:        conv.ProjectName,
		LastMessagePreview: conv.LastMessagePreview,
		LastMessageAt:      conv.LastMessageAt,
	})
}

// HandleRemoveMember handles DELETE /conversations/:id/members/:userId
func (h *ChatHandler) HandleRemoveMember(w http.ResponseWriter, r *http.Request) {
	callerID, ok := callerUserID(w, r)
	if !ok {
		return
	}
	convID, ok := parseConversationID(w, r)
	if !ok {
		return
	}
	userIDStr := chi.URLParam(r, "userId")
	if userIDStr == "" {
		respondWithError(w, http.StatusBadRequest, "user_id is required")
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid user_id")
		return
	}

	conv, err := h.svc.RemoveConversationMember(r.Context(), callerID, convID, userID)
	if err != nil {
		if errors.Is(err, chat.ErrForbidden) {
			respondWithError(w, http.StatusForbidden, "forbidden")
			return
		}
		respondWithError(w, http.StatusInternalServerError, "failed to remove member")
		return
	}

	members := make([]string, 0, len(conv.Members))
	for _, m := range conv.Members {
		members = append(members, m.String())
	}
	var projectIDStr *string
	if conv.ProjectID != nil {
		s := conv.ProjectID.String()
		projectIDStr = &s
	}
	respondJSON(w, http.StatusOK, conversationResponse{
		ID:                 conv.ID.String(),
		IsGroup:            conv.IsGroup,
		Title:              conv.Title,
		DisplayTitle:       conv.DisplayTitle,
		Members:            members,
		ProjectID:          projectIDStr,
		ProjectName:        conv.ProjectName,
		LastMessagePreview: conv.LastMessagePreview,
		LastMessageAt:      conv.LastMessageAt,
	})
}

// HandleListMessages handles GET /conversations/:id/messages
func (h *ChatHandler) HandleListMessages(w http.ResponseWriter, r *http.Request) {
	callerID, ok := callerUserID(w, r)
	if !ok {
		return
	}
	convID, ok := parseConversationID(w, r)
	if !ok {
		return
	}

	limit := 50
	if q := r.URL.Query().Get("limit"); q != "" {
		if n, err := strconv.Atoi(q); err == nil && n > 0 && n <= 100 {
			limit = n
		}
	}
	var beforeSentAt *time.Time
	if q := r.URL.Query().Get("before"); q != "" {
		t, err := time.Parse(time.RFC3339Nano, q)
		if err != nil {
			t, err = time.Parse(time.RFC3339, q)
		}
		if err == nil {
			beforeSentAt = &t
		}
	}

	msgs, err := h.svc.ListMessages(r.Context(), callerID, convID, limit, beforeSentAt)
	if err != nil {
		if errors.Is(err, chat.ErrForbidden) {
			respondWithError(w, http.StatusForbidden, "forbidden")
			return
		}
		respondWithError(w, http.StatusInternalServerError, "failed to list messages")
		return
	}

	msgIDs := make([]uuid.UUID, 0, len(msgs))
	for _, m := range msgs {
		msgIDs = append(msgIDs, m.ID)
	}
	var reactionsMap map[uuid.UUID]repo.ReactionSummary
	if h.reactionRepo != nil && len(msgIDs) > 0 {
		reactionsMap, _ = h.reactionRepo.GetReactionsByMessageIDs(r.Context(), msgIDs, callerID)
	}

	ctx := r.Context()
	senderNames := make(map[string]string)
	resp := make([]messageResponse, 0, len(msgs))
	for _, m := range msgs {
		var summary *repo.ReactionSummary
		if s, ok := reactionsMap[m.ID]; ok {
			summary = &s
		}
		item := toMessageResponse(m, summary)
		if name, ok := senderNames[m.SenderUserID.String()]; ok {
			item.SenderDisplayName = name
		} else if u, err := h.userRepo.GetByID(ctx, m.SenderUserID.String()); err == nil {
			name := u.PhoneNumber
			if strings.TrimSpace(u.DisplayName) != "" {
				name = u.DisplayName
			}
			senderNames[m.SenderUserID.String()] = name
			item.SenderDisplayName = name
		}
		resp = append(resp, item)
	}
	respondJSON(w, http.StatusOK, resp)
}

// HandleSearchMessages handles GET /conversations/:id/messages/search?q=...
func (h *ChatHandler) HandleSearchMessages(w http.ResponseWriter, r *http.Request) {
	callerID, ok := callerUserID(w, r)
	if !ok {
		return
	}
	convID, ok := parseConversationID(w, r)
	if !ok {
		return
	}
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q == "" {
		respondJSON(w, http.StatusOK, []messageResponse{})
		return
	}
	msgs, err := h.svc.SearchMessages(r.Context(), callerID, convID, q)
	if err != nil {
		if errors.Is(err, chat.ErrForbidden) {
			respondWithError(w, http.StatusForbidden, "forbidden")
			return
		}
		respondWithError(w, http.StatusInternalServerError, "failed to search messages")
		return
	}
	msgIDs := make([]uuid.UUID, 0, len(msgs))
	for _, m := range msgs {
		msgIDs = append(msgIDs, m.ID)
	}
	var reactionsMap map[uuid.UUID]repo.ReactionSummary
	if h.reactionRepo != nil && len(msgIDs) > 0 {
		reactionsMap, _ = h.reactionRepo.GetReactionsByMessageIDs(r.Context(), msgIDs, callerID)
	}
	ctx := r.Context()
	senderNames := make(map[string]string)
	resp := make([]messageResponse, 0, len(msgs))
	for _, m := range msgs {
		var summary *repo.ReactionSummary
		if s, ok := reactionsMap[m.ID]; ok {
			summary = &s
		}
		item := toMessageResponse(m, summary)
		if name, ok := senderNames[m.SenderUserID.String()]; ok {
			item.SenderDisplayName = name
		} else if u, err := h.userRepo.GetByID(ctx, m.SenderUserID.String()); err == nil {
			name := u.PhoneNumber
			if strings.TrimSpace(u.DisplayName) != "" {
				name = u.DisplayName
			}
			senderNames[m.SenderUserID.String()] = name
			item.SenderDisplayName = name
		}
		resp = append(resp, item)
	}
	respondJSON(w, http.StatusOK, resp)
}

// checkBlockedBeforeSend returns an error if caller is blocked by or has blocked any conversation member.
func (h *ChatHandler) checkBlockedBeforeSend(ctx context.Context, callerID uuid.UUID, convID uuid.UUID) error {
	if h.blockedRepo == nil {
		return nil
	}
	members, err := h.convRepo.ListMembers(ctx, convID)
	if err != nil {
		return err
	}
	for _, memberID := range members {
		if memberID == callerID {
			continue
		}
		blocked, err := h.blockedRepo.IsBlocked(ctx, callerID, memberID)
		if err != nil {
			return err
		}
		if blocked {
			return errors.New("blocked")
		}
	}
	return nil
}

// HandleCreateMessage handles POST /conversations/:id/messages
func (h *ChatHandler) HandleCreateMessage(w http.ResponseWriter, r *http.Request) {
	log.Printf("[create_message] HANDLER_ENTRY path=%s method=%s", r.URL.Path, r.Method)
	callerID, ok := callerUserID(w, r)
	if !ok {
		return
	}
	convID, ok := parseConversationID(w, r)
	if !ok {
		return
	}

	if err := h.checkBlockedBeforeSend(r.Context(), callerID, convID); err != nil {
		respondWithError(w, http.StatusForbidden, "user blocked")
		return
	}

	if h.msgLimiter != nil {
		allowed, retryAfter := h.msgLimiter.AllowWithRetry(callerID)
		if !allowed {
			log.Printf("RATE_LIMIT_HIT user=%s", callerID.String())
			respondRateLimitExceeded(w, retryAfter)
			return
		}
		log.Printf("RATE_LIMIT_OK user=%s", callerID.String())
	}

	var req createMessageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	msgType := req.MsgType
	if msgType == "" {
		msgType = "text"
	}
	var replyToID *uuid.UUID
	if req.ReplyToID != nil && *req.ReplyToID != "" {
		parsed, err := uuid.Parse(*req.ReplyToID)
		if err != nil {
			respondWithError(w, http.StatusBadRequest, "invalid reply_to_id")
			return
		}
		replyToID = &parsed
		log.Printf("[create_message] reply_to_id=%s", parsed.String())
	}

	var msg model.Message
	if msgType == "image" {
		imageURL := strings.TrimSpace(req.BodyPreview)
		if imageURL == "" {
			respondWithError(w, http.StatusBadRequest, "body_preview (image URL) is required for image messages")
			return
		}
		var err error
		msg, err = h.svc.CreateImageMessage(r.Context(), callerID, convID, imageURL, replyToID)
		if err != nil {
			if errors.Is(err, chat.ErrForbidden) {
				respondWithError(w, http.StatusForbidden, "forbidden")
				return
			}
			if errors.Is(err, chat.ErrNotFound) {
				respondWithError(w, http.StatusBadRequest, "reply_to message not found")
				return
			}
			if errors.Is(err, chat.ErrInvalidInput) {
				respondWithError(w, http.StatusBadRequest, "reply_to message must be in same conversation")
				return
			}
			respondWithError(w, http.StatusInternalServerError, "failed to create message")
			return
		}
	} else {
		var ciphertext []byte
		var preview string
		if req.BodyCiphertextBase64 != "" {
			var err error
			ciphertext, err = base64.StdEncoding.DecodeString(req.BodyCiphertextBase64)
			if err != nil {
				respondWithError(w, http.StatusBadRequest, "body_ciphertext_base64 must be valid base64")
				return
			}
			preview = req.BodyPreview
		} else if req.Body != "" {
			ciphertext = []byte(req.Body)
			preview = req.Body
		} else {
			respondWithError(w, http.StatusBadRequest, "body or body_ciphertext_base64 is required for text messages")
			return
		}
		if len(ciphertext) == 0 {
			respondWithError(w, http.StatusBadRequest, "body is required and must be non-empty")
			return
		}
		var err error
		msg, err = h.svc.CreateMessage(r.Context(), callerID, convID, ciphertext, preview, replyToID)
		if err != nil {
			if errors.Is(err, chat.ErrForbidden) {
				respondWithError(w, http.StatusForbidden, "forbidden")
				return
			}
			if errors.Is(err, chat.ErrNotFound) {
				respondWithError(w, http.StatusBadRequest, "reply_to message not found")
				return
			}
			if errors.Is(err, chat.ErrInvalidInput) {
				respondWithError(w, http.StatusBadRequest, "reply_to message must be in same conversation")
				return
			}
			respondWithError(w, http.StatusInternalServerError, "failed to create message")
			return
		}
	}

	resp := toMessageResponse(msg, nil)
	if u, err := h.userRepo.GetByID(r.Context(), msg.SenderUserID.String()); err == nil {
		if strings.TrimSpace(u.DisplayName) != "" {
			resp.SenderDisplayName = u.DisplayName
		} else {
			resp.SenderDisplayName = u.PhoneNumber
		}
	}
	if resp.ReplyToID != nil {
		log.Printf("[create_message] response includes reply_to_id=%s", *resp.ReplyToID)
	}
	if h.hub != nil {
		h.broadcastMessageCreated(r.Context(), convID, msg)
	}
	h.sendPushForNewMessage(r.Context(), convID, callerID, msg.BodyPreview)
	respondJSON(w, http.StatusCreated, resp)
}

// HandleGetUserOnlineStatus handles GET /users/:userId/online-status. Caller must share a conversation with the user.
func (h *ChatHandler) HandleGetUserOnlineStatus(w http.ResponseWriter, r *http.Request) {
	callerID, ok := callerUserID(w, r)
	if !ok {
		return
	}
	userIDStr := chi.URLParam(r, "userId")
	if userIDStr == "" {
		respondWithError(w, http.StatusBadRequest, "user_id required")
		return
	}
	targetID, err := uuid.Parse(userIDStr)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid user id")
		return
	}
	peers, err := h.convRepo.ListUsersWhoShareConversationWith(r.Context(), targetID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "failed to check permission")
		return
	}
	allowed := false
	for _, p := range peers {
		if p == callerID {
			allowed = true
			break
		}
	}
	if !allowed {
		respondWithError(w, http.StatusForbidden, "not in a conversation with this user")
		return
	}
	online, lastSeen, err := h.userRepo.GetOnlineStatus(r.Context(), userIDStr)
	if err != nil {
		respondWithError(w, http.StatusNotFound, "user not found")
		return
	}
	resp := map[string]interface{}{"online": online}
	if lastSeen != nil {
		resp["last_seen"] = *lastSeen
	}
	respondJSON(w, http.StatusOK, resp)
}

// HandleDeleteMessage handles DELETE /conversations/:id/messages/:messageId?mode=everyone|me
func (h *ChatHandler) HandleDeleteMessage(w http.ResponseWriter, r *http.Request) {
	callerID, ok := callerUserID(w, r)
	if !ok {
		return
	}
	convID, ok := parseConversationID(w, r)
	if !ok {
		return
	}
	messageIDStr := chi.URLParam(r, "messageId")
	messageID, err := uuid.Parse(messageIDStr)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid message id")
		return
	}
	mode := r.URL.Query().Get("mode")
	if mode != "everyone" && mode != "me" {
		respondWithError(w, http.StatusBadRequest, "mode must be 'everyone' or 'me'")
		return
	}

	msg, err := h.svc.DeleteMessage(r.Context(), callerID, convID, messageID, mode)
	if err != nil {
		writeDeleteMessageError(w, err)
		return
	}
	if h.hub != nil {
		h.broadcastMessageDeleted(r.Context(), convID, msg)
	}
	respondDeleteMessageOK(w, msg)
}

// HandleClearConversationMessages handles DELETE /conversations/:id/messages
func (h *ChatHandler) HandleClearConversationMessages(w http.ResponseWriter, r *http.Request) {
	callerID, ok := callerUserID(w, r)
	if !ok {
		return
	}
	convID, ok := parseConversationID(w, r)
	if !ok {
		return
	}
	if err := h.svc.ClearConversation(r.Context(), callerID, convID); err != nil {
		if errors.Is(err, chat.ErrForbidden) {
			respondWithError(w, http.StatusForbidden, "forbidden")
			return
		}
		respondWithError(w, http.StatusInternalServerError, "failed to clear conversation")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// HandleDeleteMessageByID handles DELETE /messages/:messageId?mode=everyone|me (top-level route)
func (h *ChatHandler) HandleDeleteMessageByID(w http.ResponseWriter, r *http.Request) {
	messageIDStr := chi.URLParam(r, "messageId")
	mode := r.URL.Query().Get("mode")
	log.Printf("[delete] DELETE /messages/%s?mode=%s hit (path=%s)", messageIDStr, mode, r.URL.Path)

	callerID, ok := callerUserID(w, r)
	if !ok {
		return
	}
	messageID, err := uuid.Parse(messageIDStr)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid message id")
		return
	}
	if mode != "everyone" && mode != "me" {
		respondWithError(w, http.StatusBadRequest, "mode must be 'everyone' or 'me'")
		return
	}

	msg, err := h.svc.DeleteMessageByID(r.Context(), callerID, messageID, mode)
	if err != nil {
		log.Printf("[delete] 404 from handler: messageId=%s err=%v", messageIDStr, err)
		writeDeleteMessageError(w, err)
		return
	}
	log.Printf("[delete] success messageId=%s mode=%s", messageIDStr, mode)
	if h.hub != nil {
		h.broadcastMessageDeleted(r.Context(), msg.ConversationID, msg)
	}
	respondDeleteMessageOK(w, msg)
}

// HandleEditMessage handles PUT /messages/:messageId
func (h *ChatHandler) HandleEditMessage(w http.ResponseWriter, r *http.Request) {
	log.Printf("PUT /messages/:id hit")
	callerID, ok := callerUserID(w, r)
	if !ok {
		return
	}
	messageIDStr := chi.URLParam(r, "messageId")
	messageID, err := uuid.Parse(messageIDStr)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid message id")
		return
	}

	var req editMessageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	body := strings.TrimSpace(req.Body)
	if body == "" {
		respondWithError(w, http.StatusBadRequest, "body is required and must be non-empty")
		return
	}

	ciphertext := []byte(body)
	preview := body
	msg, err := h.svc.EditMessage(r.Context(), callerID, messageID, ciphertext, preview)
	if err != nil {
		if errors.Is(err, chat.ErrForbidden) {
			respondWithError(w, http.StatusForbidden, "forbidden")
			return
		}
		if errors.Is(err, chat.ErrNotFound) {
			respondWithError(w, http.StatusNotFound, "message not found")
			return
		}
		if errors.Is(err, chat.ErrInvalidInput) {
			respondWithError(w, http.StatusBadRequest, err.Error())
			return
		}
		respondWithError(w, http.StatusInternalServerError, "failed to edit message")
		return
	}

	if h.hub != nil {
		h.broadcastMessageUpdated(r.Context(), msg)
	}
	respondJSON(w, http.StatusOK, toMessageResponse(msg, nil))
}

func writeDeleteMessageError(w http.ResponseWriter, err error) {
	if errors.Is(err, chat.ErrForbidden) {
		respondWithError(w, http.StatusForbidden, "forbidden")
		return
	}
	if errors.Is(err, chat.ErrNotFound) {
		log.Printf("[delete] responding 404 message not found")
		respondWithError(w, http.StatusNotFound, "message not found")
		return
	}
	if errors.Is(err, chat.ErrInvalidInput) {
		respondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	respondWithError(w, http.StatusInternalServerError, "failed to delete message")
}

func respondDeleteMessageOK(w http.ResponseWriter, msg model.Message) {
	respondJSON(w, http.StatusOK, toMessageResponse(msg, nil))
}

func toMessageResponse(m model.Message, summary *repo.ReactionSummary) messageResponse {
	msgType := m.MsgType
	if msgType == "" {
		msgType = "text"
	}
	status := m.Status
	if status == "" {
		status = "sent"
	}
	resp := messageResponse{
		ID:                 m.ID.String(),
		SenderUserID:       m.SenderUserID.String(),
		SentAt:             m.SentAt,
		BodyCiphertext:     base64.StdEncoding.EncodeToString(m.BodyCiphertext),
		BodyPreview:        m.BodyPreview,
		MsgType:            msgType,
		AudioURL:           m.AudioURL,
		AudioDurationMs:    m.AudioDurationMs,
		AudioMime:          m.AudioMime,
		DeletedForEveryone: m.DeletedForEveryone,
		DeletedAt:          m.DeletedAt,
		Status:             status,
		ReadAt:             m.ReadAt,
		EditedAt:           m.EditedAt,
	}
	if summary != nil && len(summary.Counts) > 0 {
		resp.Reactions = summary.Counts
		resp.MyReaction = summary.MyReaction
	}
	if m.ReplyToID != nil {
		id := m.ReplyToID.String()
		resp.ReplyToID = &id
		resp.ReplyTo = &struct {
			ID   string `json:"id"`
			Body string `json:"body"`
		}{ID: id, Body: m.ReplyToPreview}
	}
	return resp
}

func messageToEventMap(m model.Message) map[string]interface{} {
	msgType := m.MsgType
	if msgType == "" {
		msgType = "text"
	}
	status := m.Status
	if status == "" {
		status = "sent"
	}
	out := map[string]interface{}{
		"id":                    m.ID.String(),
		"sender_user_id":        m.SenderUserID.String(),
		"body_preview":          m.BodyPreview,
		"msg_type":              msgType,
		"deleted_for_everyone":  m.DeletedForEveryone,
		"status":                status,
		"sent_at":               m.SentAt.Format(time.RFC3339Nano),
	}
	if m.ReplyToID != nil {
		out["reply_to_id"] = m.ReplyToID.String()
	} else {
		out["reply_to_id"] = nil
	}
	if msgType == "audio" {
		out["audio_url"] = m.AudioURL
		out["audio_duration_ms"] = m.AudioDurationMs
		out["audio_mime"] = m.AudioMime
	}
	return out
}

func (h *ChatHandler) broadcastToConversation(ctx context.Context, convID uuid.UUID, event ws.MessageEvent) {
	members, err := h.convRepo.ListMembers(ctx, convID)
	if err != nil {
		log.Printf("[ws] list members: %v", err)
		return
	}
	h.hub.BroadcastToUsers(members, event)
}

func (h *ChatHandler) broadcastMessageCreated(ctx context.Context, convID uuid.UUID, msg model.Message) {
	m := messageToEventMap(msg)
	if u, err := h.userRepo.GetByID(ctx, msg.SenderUserID.String()); err == nil {
		if strings.TrimSpace(u.DisplayName) != "" {
			m["sender_display_name"] = u.DisplayName
		} else {
			m["sender_display_name"] = u.PhoneNumber
		}
	}
	h.broadcastToConversation(ctx, convID, ws.MessageEvent{
		Type:           "message.created",
		ConversationID: convID.String(),
		Message:        m,
	})
}

// sendPushForNewMessage sends push notifications to conversation members (except sender).
func (h *ChatHandler) sendPushForNewMessage(ctx context.Context, convID uuid.UUID, senderID uuid.UUID, preview string) {
	if h.pushTokenRepo == nil || h.userRepo == nil {
		log.Printf("PUSH_ERROR pushTokenRepo or userRepo is nil, skip")
		return
	}
	members, err := h.convRepo.ListMembers(ctx, convID)
	if err != nil {
		log.Printf("PUSH_ERROR list members conv=%s: %v", convID, err)
		return
	}
	sender, err := h.userRepo.GetByID(ctx, senderID.String())
	if err != nil {
		log.Printf("PUSH_ERROR get sender: %v", err)
		return
	}
	senderName := sender.DisplayName
	if senderName == "" {
		senderName = sender.PhoneNumber
		if len(senderName) > 12 {
			senderName = senderName[len(senderName)-8:]
		}
	}
	var allTokens []string
	for _, memberID := range members {
		if memberID == senderID {
			continue
		}
		if h.hub != nil && h.hub.IsUserViewingConversation(memberID, convID.String()) {
			log.Printf("PUSH_SKIP user=%s already viewing conv=%s", memberID, convID)
			continue
		}
		tokens, err := h.pushTokenRepo.GetTokensForUser(ctx, memberID)
		if err != nil {
			log.Printf("PUSH_ERROR get tokens user=%s: %v", memberID, err)
			continue
		}
		allTokens = append(allTokens, tokens...)
	}
	if len(allTokens) > 0 {
		log.Printf("PUSH sending to %d token(s) conv=%s", len(allTokens), convID.String())
		onInvalid := func(tokens []string) {
			bg := context.Background()
			for _, t := range tokens {
				if err := h.pushTokenRepo.MarkTokenInvalid(bg, t); err != nil {
					log.Printf("PUSH_ERROR mark invalid: %v", err)
				}
			}
		}
		push.SendNewMessagePush(ctx, allTokens, senderName, preview, convID.String(), onInvalid)
	} else {
		log.Printf("PUSH_ERROR no tokens for recipients conv=%s", convID.String())
	}
}

func (h *ChatHandler) broadcastMessageUpdated(ctx context.Context, msg model.Message) {
	h.broadcastToConversation(ctx, msg.ConversationID, ws.MessageEvent{
		Type:           "message.updated",
		ConversationID: msg.ConversationID.String(),
		Message:        messageToEventMap(msg),
	})
}

func (h *ChatHandler) broadcastMessageDeleted(ctx context.Context, convID uuid.UUID, msg model.Message) {
	h.broadcastToConversation(ctx, convID, ws.MessageEvent{
		Type:                 "message.deleted",
		ConversationID:       convID.String(),
		MessageID:            msg.ID.String(),
		DeletedForEveryone:   msg.DeletedForEveryone,
		Message:              messageToEventMap(msg),
	})
}

// HandleUploadImage handles POST /upload
// Accepts multipart/form-data with field "file" (image/*). Stores in uploads/images/ and returns URL.
func (h *ChatHandler) HandleUploadImage(w http.ResponseWriter, r *http.Request) {
	_, ok := callerUserID(w, r)
	if !ok {
		return
	}
	if err := r.ParseMultipartForm(maxImageSize + (1 << 20)); err != nil {
		log.Printf("IMAGE_UPLOAD_ERROR parse form: %v", err)
		respondWithError(w, http.StatusBadRequest, "failed to parse multipart form")
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		log.Printf("IMAGE_UPLOAD_ERROR form file: %v", err)
		respondWithError(w, http.StatusBadRequest, "field 'file' is required")
		return
	}
	defer file.Close()
	if header.Size > maxImageSize {
		log.Printf("IMAGE_UPLOAD_ERROR file too large size=%d max=%d", header.Size, maxImageSize)
		respondWithError(w, http.StatusBadRequest, fmt.Sprintf("file too large (max %d MB)", maxImageSize>>20))
		return
	}
	mime := header.Header.Get("Content-Type")
	if mime == "" {
		mime = "image/jpeg"
	}
	if !strings.HasPrefix(mime, "image/") {
		log.Printf("IMAGE_UPLOAD_ERROR invalid content-type mime=%s", mime)
		respondWithError(w, http.StatusBadRequest, "file must be image/*")
		return
	}
	ext := filepath.Ext(header.Filename)
	if ext == "" {
		ext = imageExtForMime(mime)
	}
	ext = sanitizeImageExt(ext)
	dir := imagesDir
	if _, statErr := os.Stat("/app"); os.IsNotExist(statErr) {
		dir = imagesDirDev
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Printf("IMAGE_UPLOAD_ERROR mkdir: %v", err)
		respondWithError(w, http.StatusInternalServerError, "failed to create upload directory")
		return
	}
	fileID := uuid.New().String()
	filename := fileID + ext
	destPath := filepath.Join(dir, filename)
	dst, err := os.Create(destPath)
	if err != nil {
		log.Printf("IMAGE_UPLOAD_ERROR create file: %v", err)
		respondWithError(w, http.StatusInternalServerError, "failed to store image")
		return
	}
	defer dst.Close()
	if _, err := io.Copy(dst, file); err != nil {
		log.Printf("IMAGE_UPLOAD_ERROR write file: %v", err)
		respondWithError(w, http.StatusInternalServerError, "failed to write image")
		return
	}
	log.Printf("IMAGE_UPLOAD_SUCCESS size=%d filename=%s", header.Size, filename)
	url := "/uploads/images/" + filename
	respondJSON(w, http.StatusOK, uploadImageResponse{URL: url})
}

func imageExtForMime(mime string) string {
	switch mime {
	case "image/jpeg", "image/jpg":
		return ".jpg"
	case "image/png":
		return ".png"
	case "image/gif":
		return ".gif"
	case "image/webp":
		return ".webp"
	default:
		return ".jpg"
	}
}

func sanitizeImageExt(ext string) string {
	allowed := map[string]bool{".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".webp": true}
	ext = strings.ToLower(ext)
	if allowed[ext] {
		return ext
	}
	return ".jpg"
}

// HandleUploadAudio handles POST /conversations/:id/audio
// Accepts multipart/form-data with field "file" (audio/*) and optional "duration_ms".
// Stores the file, creates an audio message, and returns the message details.
func (h *ChatHandler) HandleUploadAudio(w http.ResponseWriter, r *http.Request) {
	log.Printf("[create_message] HANDLER_ENTRY audio path=%s method=%s", r.URL.Path, r.Method)
	callerID, ok := callerUserID(w, r)
	if !ok {
		return
	}
	convID, ok := parseConversationID(w, r)
	if !ok {
		return
	}

	if err := h.checkBlockedBeforeSend(r.Context(), callerID, convID); err != nil {
		respondWithError(w, http.StatusForbidden, "user blocked")
		return
	}

	if h.msgLimiter != nil {
		allowed, retryAfter := h.msgLimiter.AllowWithRetry(callerID)
		if !allowed {
			log.Printf("RATE_LIMIT_HIT user=%s", callerID.String())
			respondRateLimitExceeded(w, retryAfter)
			return
		}
		log.Printf("RATE_LIMIT_OK user=%s", callerID.String())
	}

	if err := r.ParseMultipartForm(maxAudioSize + (1 << 20)); err != nil {
		respondWithError(w, http.StatusBadRequest, "failed to parse multipart form")
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "field 'file' is required")
		return
	}
	defer file.Close()

	if header.Size > maxAudioSize {
		respondWithError(w, http.StatusBadRequest, fmt.Sprintf("file too large (max %d MB)", maxAudioSize>>20))
		return
	}

	// Validate MIME type
	mime := header.Header.Get("Content-Type")
	if mime == "" {
		mime = "audio/m4a"
	}
	if !strings.HasPrefix(mime, "audio/") {
		respondWithError(w, http.StatusBadRequest, "file must be audio/*")
		return
	}

	// Parse optional duration_ms
	durationMs := 0
	if d := r.FormValue("duration_ms"); d != "" {
		if v, err2 := strconv.Atoi(d); err2 == nil && v > 0 {
			durationMs = v
		}
	}

	// Determine safe extension
	ext := filepath.Ext(header.Filename)
	if ext == "" {
		ext = audioExtForMime(mime)
	}
	ext = sanitizeExt(ext)

	// Resolve uploads directory (works both in Docker /app and local dev)
	dir := uploadsDir
	if _, statErr := os.Stat("/app"); os.IsNotExist(statErr) {
		dir = uploadsDirDev
	}
	convDir := filepath.Join(dir, convID.String())
	if err := os.MkdirAll(convDir, 0755); err != nil {
		log.Printf("[audio] mkdir %s: %v", convDir, err)
		respondWithError(w, http.StatusInternalServerError, "failed to create upload directory")
		return
	}

	fileID := uuid.New().String()
	filename := fileID + ext
	destPath := filepath.Join(convDir, filename)

	dst, err := os.Create(destPath)
	if err != nil {
		log.Printf("[audio] create file %s: %v", destPath, err)
		respondWithError(w, http.StatusInternalServerError, "failed to store audio file")
		return
	}
	defer dst.Close()

	if _, err := io.Copy(dst, file); err != nil {
		log.Printf("[audio] write file %s: %v", destPath, err)
		respondWithError(w, http.StatusInternalServerError, "failed to write audio file")
		return
	}

	// Build served URL — use request Host so it works on any port/IP
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host := r.Host
	audioURL := fmt.Sprintf("%s://%s/uploads/audio/%s/%s", scheme, host, convID.String(), filename)

	msg, err := h.svc.CreateAudioMessage(r.Context(), callerID, convID, audioURL, durationMs, mime)
	if err != nil {
		if errors.Is(err, chat.ErrForbidden) {
			respondWithError(w, http.StatusForbidden, "forbidden")
			return
		}
		respondWithError(w, http.StatusInternalServerError, "failed to create audio message")
		return
	}

	if h.hub != nil {
		h.broadcastMessageCreated(r.Context(), convID, msg)
	}
	audioPreview := "Sprachnachricht"
	if durationMs > 0 {
		sec := durationMs / 1000
		audioPreview = fmt.Sprintf("Sprachnachricht (%ds)", sec)
	}
	h.sendPushForNewMessage(r.Context(), convID, callerID, audioPreview)

	respondJSON(w, http.StatusCreated, audioUploadResponse{
		AudioURL:        audioURL,
		AudioDurationMs: durationMs,
		AudioMime:       mime,
		MessageID:       msg.ID.String(),
	})
}

func audioExtForMime(mime string) string {
	switch mime {
	case "audio/m4a", "audio/x-m4a", "audio/mp4":
		return ".m4a"
	case "audio/aac":
		return ".aac"
	case "audio/mpeg", "audio/mp3":
		return ".mp3"
	case "audio/ogg":
		return ".ogg"
	case "audio/webm":
		return ".webm"
	default:
		return ".m4a"
	}
}

func sanitizeExt(ext string) string {
	allowed := map[string]bool{
		".m4a": true, ".aac": true, ".mp3": true,
		".ogg": true, ".webm": true, ".wav": true, ".caf": true,
	}
	ext = strings.ToLower(ext)
	if allowed[ext] {
		return ext
	}
	return ".m4a"
}

// ── helpers ───────────────────────────────────────────────────────────────────

func parseConversationID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	raw := chi.URLParam(r, "id")
	convID, err := uuid.Parse(raw)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid conversation id")
		return uuid.Nil, false
	}
	return convID, true
}
