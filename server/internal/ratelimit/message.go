package ratelimit

import (
	"sync"
	"time"

	"github.com/google/uuid"
)

// MessageLimiter limits messages per user (sliding window, in-memory).
type MessageLimiter struct {
	mu     sync.Mutex
	hits   map[uuid.UUID][]time.Time
	limit  int
	window time.Duration
}

// NewMessageLimiter creates a limiter: max limit messages per window (e.g. 20 per 10s).
func NewMessageLimiter(limit int, window time.Duration) *MessageLimiter {
	return &MessageLimiter{
		hits:   make(map[uuid.UUID][]time.Time),
		limit:  limit,
		window: window,
	}
}

// Allow returns true if the user is within the rate limit. If true, records the hit.
func (m *MessageLimiter) Allow(userID uuid.UUID) bool {
	allowed, _ := m.AllowWithRetry(userID)
	return allowed
}

// AllowWithRetry returns (allowed, retryAfterSeconds). When allowed is false, retryAfterSeconds is seconds until the client can retry (>= 1).
func (m *MessageLimiter) AllowWithRetry(userID uuid.UUID) (allowed bool, retryAfterSeconds int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-m.window)

	list := m.hits[userID]
	var kept []time.Time
	for _, t := range list {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}

	if len(kept) >= m.limit {
		// Oldest hit in window expires at kept[0] + window
		expiresAt := kept[0].Add(m.window)
		sec := int(time.Until(expiresAt).Seconds())
		if sec < 1 {
			sec = 1
		}
		return false, sec
	}

	kept = append(kept, now)
	m.hits[userID] = kept
	return true, 0
}

// cleanup removes user entries with no hits in the current window to avoid unbounded map growth.
func (m *MessageLimiter) cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()
	cutoff := time.Now().Add(-m.window)
	for id, list := range m.hits {
		var kept []time.Time
		for _, t := range list {
			if t.After(cutoff) {
				kept = append(kept, t)
			}
		}
		if len(kept) == 0 {
			delete(m.hits, id)
		} else {
			m.hits[id] = kept
		}
	}
}

// StartCleanup runs cleanup periodically to remove stale user entries. Call once after creating the limiter (e.g. in main).
func (m *MessageLimiter) StartCleanup() {
	go func() {
		ticker := time.NewTicker(m.window * 2)
		defer ticker.Stop()
		for range ticker.C {
			m.cleanup()
		}
	}()
}
