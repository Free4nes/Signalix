package handlers

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/signalix/server/internal/auth"
	"github.com/signalix/server/internal/repo"
	"github.com/signalix/server/internal/ws"
)

const rfc3339 = "2006-01-02T15:04:05Z07:00"

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

// WsHandler handles WebSocket connections
type WsHandler struct {
	hub      *ws.Hub
	jwtSvc   *auth.JWTService
	userRepo repo.UserRepo
	convRepo repo.ConversationRepo
	chatSvc  ChatService
}

// ChatService is the minimal interface for reaction handling
type ChatService interface {
	AddReaction(ctx context.Context, callerID, messageID uuid.UUID, reaction string) (convID uuid.UUID, err error)
}

// NewWsHandler creates a new WsHandler
func NewWsHandler(hub *ws.Hub, jwtSvc *auth.JWTService, userRepo repo.UserRepo, convRepo repo.ConversationRepo, chatSvc ChatService) *WsHandler {
	h := &WsHandler{hub: hub, jwtSvc: jwtSvc, userRepo: userRepo, convRepo: convRepo, chatSvc: chatSvc}
	hub.SetIncomingMessageHandler(h.handleIncomingMessage)
	return h
}

func (h *WsHandler) handleIncomingMessage(conn *ws.Conn, data []byte) {
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return
	}
	typ, _ := raw["type"].(string)
	switch typ {
	case "typing":
		h.handleTyping(conn, raw)
	case "reaction":
		h.handleReaction(conn, raw)
	case "active_chat":
		convIDStr, _ := raw["conversation_id"].(string)
		conn.SetActiveConversation(convIDStr)
		log.Printf("[ws] active_chat user=%s conversation=%s", conn.UserID, convIDStr)
	}
}

func (h *WsHandler) handleTyping(conn *ws.Conn, raw map[string]interface{}) {
	convIDStr, _ := raw["conversation_id"].(string)
	if convIDStr == "" {
		return
	}
	convID, err := uuid.Parse(convIDStr)
	if err != nil {
		return
	}
	isTyping, _ := raw["is_typing"].(bool)

	log.Printf("[typing] received conversation=%s user=%s is_typing=%v", convIDStr, conn.UserID, isTyping)

	ok, err := h.convRepo.IsMember(context.Background(), convID, conn.UserID)
	if err != nil || !ok {
		return
	}
	members, err := h.convRepo.ListMembers(context.Background(), convID)
	if err != nil {
		return
	}
	var otherIDs []uuid.UUID
	for _, m := range members {
		if m == conn.UserID {
			log.Printf("[typing] skipping sender=%s", conn.UserID)
			continue
		}
		otherIDs = append(otherIDs, m)
	}
	if len(otherIDs) == 0 {
		log.Printf("[typing] no other participants, broadcast skipped")
		return
	}

	for _, uid := range otherIDs {
		log.Printf("[typing] broadcasting to participant=%s", uid)
	}
	ev := ws.MessageEvent{
		Type:           "typing",
		ConversationID: convID.String(),
		UserID:         conn.UserID.String(),
		IsTyping:       &isTyping,
	}
	h.hub.BroadcastToUsers(otherIDs, ev)
	log.Printf("[typing] broadcast done")
}

func (h *WsHandler) handleReaction(conn *ws.Conn, raw map[string]interface{}) {
	if h.chatSvc == nil {
		return
	}
	messageIDStr, _ := raw["message_id"].(string)
	reaction, _ := raw["reaction"].(string)
	if messageIDStr == "" || reaction == "" {
		return
	}
	messageID, err := uuid.Parse(messageIDStr)
	if err != nil {
		return
	}
	convID, err := h.chatSvc.AddReaction(context.Background(), conn.UserID, messageID, reaction)
	if err != nil {
		log.Printf("[reaction] add failed: %v", err)
		return
	}
	members, err := h.convRepo.ListMembers(context.Background(), convID)
	if err != nil {
		return
	}
	ev := ws.MessageEvent{
		Type:           "message.reaction",
		ConversationID: convID.String(),
		MessageID:      messageIDStr,
		UserID:         conn.UserID.String(),
		Reaction:       reaction,
	}
	h.hub.BroadcastToUsers(members, ev)
	log.Printf("[reaction] broadcast message_id=%s user=%s reaction=%s", messageIDStr, conn.UserID, reaction)
}

func (h *WsHandler) broadcastOnlineStatus(userID uuid.UUID, online bool) {
	peers, err := h.convRepo.ListUsersWhoShareConversationWith(context.Background(), userID)
	if err != nil {
		log.Printf("[ws] list peers for online_status: %v", err)
		return
	}
	if len(peers) == 0 {
		return
	}
	now := time.Now().Format(rfc3339)
	ev := ws.MessageEvent{
		Type:     "online_status",
		UserID:   userID.String(),
		Online:   &online,
		LastSeen: now,
	}
	h.hub.BroadcastToUsers(peers, ev)
	log.Printf("ONLINE_STATUS_UPDATE user=%s online=%v last_seen=%s peers=%d", userID, online, now, len(peers))
}

func (h *WsHandler) respondAuthError(w http.ResponseWriter, status int, msg string) {
	log.Printf("[ws] auth error %d: %s", status, msg)
	http.Error(w, msg, status)
}

// ServeHTTP upgrades the HTTP connection to WebSocket and runs the connection loop.
// Token can be passed via ?token=xxx (required for browser WS) or Authorization: Bearer xxx
func (h *WsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("[ws] panic recovered: %v", rec)
		}
	}()

	log.Printf("[ws] incoming path=%s raw_query=%s", r.URL.Path, r.URL.RawQuery)

	// Guard against nil handler deps (server misconfiguration)
	if h == nil {
		log.Printf("[ws] nil handler")
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	if h.hub == nil || h.jwtSvc == nil || h.userRepo == nil {
		log.Printf("[ws] nil hub/jwtSvc/userRepo")
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	// Token: query param first (for browsers), then Authorization header
	tokenStr := r.URL.Query().Get("token")
	tokenSource := "query"
	if tokenStr == "" {
		if ah := r.Header.Get("Authorization"); len(ah) > 7 && strings.HasPrefix(ah, "Bearer ") {
			tokenStr = strings.TrimSpace(ah[7:])
			tokenSource = "header"
		}
	}

	if tokenStr == "" {
		log.Printf("[ws] token not found")
		h.respondAuthError(w, http.StatusUnauthorized, "unauthorized: token required")
		return
	}
	log.Printf("[ws] token source=%s", tokenSource)

	claims, err := h.jwtSvc.VerifyToken(tokenStr)
	if err != nil {
		log.Printf("[ws] token verify failed: %v", err)
		h.respondAuthError(w, http.StatusUnauthorized, "unauthorized: invalid token")
		return
	}
	if claims == nil {
		log.Printf("[ws] claims nil after verify")
		h.respondAuthError(w, http.StatusUnauthorized, "unauthorized: invalid token")
		return
	}

	_, err = h.userRepo.GetByID(r.Context(), claims.UserID.String())
	if err != nil {
		log.Printf("[ws] user not found: %v", err)
		h.respondAuthError(w, http.StatusUnauthorized, "unauthorized: user not found")
		return
	}
	userID := claims.UserID
	log.Printf("[ws] auth ok user=%s", userID)

	log.Printf("[ws] upgrade start")
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[ws] upgrade error: %v", err)
		return
	}
	defer conn.Close()
	log.Printf("[ws] upgraded")

	c := h.hub.Register(userID, conn)
	if c == nil {
		log.Printf("[ws] hub register returned nil")
		return
	}
	defer func() {
		ctx := context.Background()
		if err := h.userRepo.UpdateOnlineStatus(ctx, userID.String(), false); err != nil {
			log.Printf("[ws] update online status on disconnect: %v", err)
		}
		h.broadcastOnlineStatus(userID, false)
		h.hub.Unregister(c)
	}()
	if err := h.userRepo.UpdateOnlineStatus(r.Context(), userID.String(), true); err != nil {
		log.Printf("[ws] update online status on connect: %v", err)
	}
	h.broadcastOnlineStatus(userID, true)
	log.Printf("[ws] registered")

	conn.SetReadLimit(512)
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	go c.WritePump()
	c.ReadPump(h.hub)
}
