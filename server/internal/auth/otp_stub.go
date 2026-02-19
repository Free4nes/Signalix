package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/signalix/server/internal/repo"
)

const (
	otpLength       = 6
	otpExpiry       = 5 * time.Minute
	maxAttempts     = 5
	minAttemptDelay = 2 * time.Second
	requestWindow   = 10 * time.Minute
	maxRequestsPerWindow = 3
)

// OtpStub implements OtpProvider with PostgreSQL-backed sessions
type OtpStub struct {
	otpRepo repo.OtpRepo
	salt    string
}

// NewOtpStub creates a new OTP provider
func NewOtpStub(otpRepo repo.OtpRepo, salt string) *OtpStub {
	return &OtpStub{
		otpRepo: otpRepo,
		salt:    salt,
	}
}

// RequestOTP creates or replaces an OTP session. Rate limit: max 3 requests per 10 min per phone (DB-based).
// In OTP_DEV_MODE a session is created with hash of "123456"; otherwise a 6-digit OTP is generated and only its hash is stored.
func (p *OtpStub) RequestOTP(ctx context.Context, phone, ip, userAgent string) error {
	since := time.Now().Add(-requestWindow)
	count, err := p.otpRepo.CountRecentRequests(ctx, phone, since)
	if err != nil {
		return fmt.Errorf("rate limit check: %w", err)
	}
	if count >= maxRequestsPerWindow {
		return fmt.Errorf("rate limit exceeded: max %d OTP requests per %v per phone", maxRequestsPerWindow, requestWindow)
	}

	expiresAt := time.Now().Add(otpExpiry)
	var requestIP, ua *string
	if ip != "" {
		requestIP = &ip
	}
	if userAgent != "" {
		ua = &userAgent
	}

	if os.Getenv("OTP_DEV_MODE") == "true" {
		hashHex := hashOTPHex(phone, "123456", p.salt)
		_, err = p.otpRepo.CreateOrReplaceSession(ctx, phone, hashHex, expiresAt, requestIP, ua)
		if err != nil {
			return fmt.Errorf("create session: %w", err)
		}
		return nil
	}

	code := generateOTPCode()
	hashHex := hashOTPHex(phone, code, p.salt)
	_, err = p.otpRepo.CreateOrReplaceSession(ctx, phone, hashHex, expiresAt, requestIP, ua)
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	// Never log or return plaintext OTP
	_ = code
	return nil
}

// VerifyOTP verifies the code against the active session: attempt limit 5, min 2s between attempts, hash comparison, then mark consumed.
func (p *OtpStub) VerifyOTP(ctx context.Context, phone, code, ip string) error {
	session, err := p.otpRepo.GetActiveSessionByPhone(ctx, phone)
	if err != nil {
		return fmt.Errorf("invalid or expired OTP")
	}

	now := time.Now()
	if session.LastAttemptAt != nil {
		elapsed := now.Sub(*session.LastAttemptAt)
		if elapsed < minAttemptDelay {
			return fmt.Errorf("too many attempts, try again later")
		}
	}

	newCount, err := p.otpRepo.IncrementAttempt(ctx, session.ID)
	if err != nil {
		return fmt.Errorf("failed to record attempt: %w", err)
	}
	if newCount >= maxAttempts {
		_ = p.otpRepo.MarkConsumed(ctx, session.ID)
		return fmt.Errorf("invalid or expired OTP")
	}

	providedHash := hashOTPBytes(phone, code, p.salt)
	if !constantTimeCompare(providedHash, session.OTPHash) {
		return fmt.Errorf("invalid or expired OTP")
	}

	if err := p.otpRepo.MarkConsumed(ctx, session.ID); err != nil {
		return fmt.Errorf("failed to consume session: %w", err)
	}
	return nil
}

func generateOTPCode() string {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	code := rng.Intn(900000) + 100000
	return fmt.Sprintf("%06d", code)
}

// hashOTPHex returns SHA-256(phone:code:salt) as hex for DB storage
func hashOTPHex(phone, code, salt string) string {
	b := hashOTPBytes(phone, code, salt)
	return hex.EncodeToString(b)
}

func hashOTPBytes(phone, code, salt string) []byte {
	data := fmt.Sprintf("%s:%s:%s", phone, code, salt)
	hash := sha256.Sum256([]byte(data))
	return hash[:]
}

func constantTimeCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var result int
	for i := 0; i < len(a); i++ {
		result |= int(a[i]) ^ int(b[i])
	}
	return result == 0
}
