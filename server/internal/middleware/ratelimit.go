package middleware

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// RateLimiter implements a simple in-memory rate limiter using a sliding window
type RateLimiter struct {
	mu       sync.RWMutex
	requests map[string][]time.Time
	window   time.Duration
	maxReqs  int
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(window time.Duration, maxReqs int) *RateLimiter {
	rl := &RateLimiter{
		requests: make(map[string][]time.Time),
		window:   window,
		maxReqs:  maxReqs,
	}

	// Cleanup goroutine to remove old entries
	go rl.cleanup()

	return rl
}

// Allow checks if a request is allowed for the given key
func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)

	// Get existing requests for this key
	reqs, exists := rl.requests[key]
	if !exists {
		reqs = make([]time.Time, 0)
	}

	// Remove requests outside the window
	filtered := make([]time.Time, 0, len(reqs))
	for _, t := range reqs {
		if t.After(cutoff) {
			filtered = append(filtered, t)
		}
	}

	// Check if we've exceeded the limit
	if len(filtered) >= rl.maxReqs {
		return false
	}

	// Add current request
	filtered = append(filtered, now)
	rl.requests[key] = filtered

	return true
}

// cleanup periodically removes old entries to prevent memory leaks
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		cutoff := time.Now().Add(-rl.window * 2) // Keep entries for 2x window

		for key, reqs := range rl.requests {
			filtered := make([]time.Time, 0)
			for _, t := range reqs {
				if t.After(cutoff) {
					filtered = append(filtered, t)
				}
			}

			if len(filtered) == 0 {
				delete(rl.requests, key)
			} else {
				rl.requests[key] = filtered
			}
		}
		rl.mu.Unlock()
	}
}

// RateLimitMiddleware creates a rate limiting middleware
func RateLimitMiddleware(limiter *RateLimiter, keyFunc func(*http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := keyFunc(r)
			if !limiter.Allow(key) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				response := map[string]string{"error": "rate limit exceeded"}
				_ = json.NewEncoder(w).Encode(response)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// GetIPKey extracts IP address from request for rate limiting
func GetIPKey(r *http.Request) string {
	// Try X-Forwarded-For first (for proxies)
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		// Take first IP if multiple
		return "ip:" + forwarded
	}

	// Fallback to RemoteAddr
	return "ip:" + r.RemoteAddr
}

// GetPhoneKey creates a rate limit key from phone number
func GetPhoneKey(phone string) string {
	return "phone:" + phone
}
