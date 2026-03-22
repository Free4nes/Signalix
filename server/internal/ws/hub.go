package ws

import (
	"encoding/json"
	"log"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

// MessageEvent represents a broadcast event to clients
type MessageEvent struct {
	Type               string                 `json:"type"`
	ConversationID     string                 `json:"conversation_id,omitempty"`
	Message            map[string]interface{} `json:"message,omitempty"`
	MessageID          string                 `json:"message_id,omitempty"`
	DeletedForEveryone bool                   `json:"deleted_for_everyone,omitempty"`
	UserID             string                 `json:"user_id,omitempty"`
	IsTyping           *bool                  `json:"is_typing,omitempty"`
	Online             *bool                  `json:"online,omitempty"`
	LastSeen           string                 `json:"last_seen,omitempty"`
	Reaction           string                 `json:"reaction,omitempty"`
}

// IncomingMessageHandler is called when a client sends a message over WebSocket
type IncomingMessageHandler func(conn *Conn, data []byte)

// Conn wraps a WebSocket connection with its user ID
type Conn struct {
	UserID               uuid.UUID
	Ws                   *websocket.Conn
	Send                 chan []byte
	mu                   sync.Mutex
	activeConversationID string
}

// SetActiveConversation sets the conversation this connection is currently viewing.
func (c *Conn) SetActiveConversation(convID string) {
	c.mu.Lock()
	c.activeConversationID = convID
	c.mu.Unlock()
}

// GetActiveConversation returns the conversation ID this connection is viewing.
func (c *Conn) GetActiveConversation() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.activeConversationID
}

// Hub maintains active connections per user and broadcasts events
type Hub struct {
	mu                 sync.RWMutex
	connections        map[uuid.UUID][]*Conn
	incomingHandler    IncomingMessageHandler
}

// NewHub creates a new Hub
func NewHub() *Hub {
	return &Hub{
		connections: make(map[uuid.UUID][]*Conn),
	}
}

// Register adds a connection for a user
func (h *Hub) Register(userID uuid.UUID, wsConn *websocket.Conn) *Conn {
	c := &Conn{
		UserID: userID,
		Ws:     wsConn,
		Send:   make(chan []byte, 256),
	}
	h.mu.Lock()
	h.connections[userID] = append(h.connections[userID], c)
	h.mu.Unlock()
	log.Printf("[ws] user %s connected, total conns for user: %d", userID, len(h.connections[userID]))
	return c
}

// Unregister removes a connection
func (h *Hub) Unregister(c *Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	conns := h.connections[c.UserID]
	for i, cc := range conns {
		if cc == c {
			h.connections[c.UserID] = append(conns[:i], conns[i+1:]...)
			if len(h.connections[c.UserID]) == 0 {
				delete(h.connections, c.UserID)
			}
			break
		}
	}
	close(c.Send)
	log.Printf("[ws] user %s disconnected", c.UserID)
}

// BroadcastToUsers sends an event to all connections of the given user IDs
func (h *Hub) BroadcastToUsers(userIDs []uuid.UUID, event MessageEvent) {
	data, err := json.Marshal(event)
	if err != nil {
		log.Printf("[ws] marshal event: %v", err)
		return
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	seen := make(map[uuid.UUID]bool)
	for _, uid := range userIDs {
		if seen[uid] {
			continue
		}
		seen[uid] = true
		for _, c := range h.connections[uid] {
			select {
			case c.Send <- data:
			default:
				log.Printf("[ws] send buffer full for user %s", uid)
			}
		}
	}
}

// IsUserViewingConversation returns true if any connection for userID has the given conversation active.
func (h *Hub) IsUserViewingConversation(userID uuid.UUID, conversationID string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, c := range h.connections[userID] {
		if c.GetActiveConversation() == conversationID {
			return true
		}
	}
	return false
}

// WritePump pumps messages from the send channel to the websocket
func (c *Conn) WritePump() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case msg, ok := <-c.Send:
			c.Ws.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				c.Ws.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			if err := c.Ws.WriteMessage(websocket.TextMessage, msg); err != nil {
				return
			}
		case <-ticker.C:
			c.Ws.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.Ws.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// SetIncomingMessageHandler sets the handler for incoming client messages (e.g. typing)
func (h *Hub) SetIncomingMessageHandler(handler IncomingMessageHandler) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.incomingHandler = handler
}

// ReadPump reads messages from the websocket and forwards to incomingHandler when set
func (c *Conn) ReadPump(h *Hub) {
	defer func() {
		c.Ws.Close()
	}()
	for {
		_, data, err := c.Ws.ReadMessage()
		if err != nil {
			break
		}
		h.mu.RLock()
		fn := h.incomingHandler
		h.mu.RUnlock()
		if fn != nil {
			fn(c, data)
		}
	}
}
