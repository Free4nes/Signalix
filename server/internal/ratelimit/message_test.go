package ratelimit

import (
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMessageLimiter_AllowsWithinLimit(t *testing.T) {
	limiter := NewMessageLimiter(20, 10*time.Second)
	userID := uuid.New()

	for i := 0; i < 20; i++ {
		if !limiter.Allow(userID) {
			t.Fatalf("message %d should be allowed", i+1)
		}
	}
}

func TestMessageLimiter_RejectsOverLimit(t *testing.T) {
	limiter := NewMessageLimiter(20, 10*time.Second)
	userID := uuid.New()

	for i := 0; i < 20; i++ {
		limiter.Allow(userID)
	}
	if limiter.Allow(userID) {
		t.Fatal("21st message should be rejected")
	}
}

func TestMessageLimiter_SlidingWindow(t *testing.T) {
	limiter := NewMessageLimiter(2, 100*time.Millisecond)
	userID := uuid.New()

	limiter.Allow(userID)
	limiter.Allow(userID)
	if limiter.Allow(userID) {
		t.Fatal("3rd message within 100ms should be rejected")
	}
	time.Sleep(110 * time.Millisecond)
	if !limiter.Allow(userID) {
		t.Fatal("message after window should be allowed")
	}
}

func TestMessageLimiter_PerUser(t *testing.T) {
	limiter := NewMessageLimiter(2, 10*time.Second)
	userA := uuid.New()
	userB := uuid.New()

	limiter.Allow(userA)
	limiter.Allow(userA)
	if limiter.Allow(userA) {
		t.Fatal("user A 3rd message should be rejected")
	}
	if !limiter.Allow(userB) {
		t.Fatal("user B 1st message should be allowed")
	}
}

func TestMessageLimiter_Concurrent(t *testing.T) {
	limiter := NewMessageLimiter(100, 10*time.Second)
	userID := uuid.New()

	var wg sync.WaitGroup
	allowed := 0
	var mu sync.Mutex
	for i := 0; i < 150; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if limiter.Allow(userID) {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if allowed > 100 {
		t.Errorf("expected at most 100 allowed, got %d", allowed)
	}
}
