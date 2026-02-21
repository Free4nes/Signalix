package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/signalix/server/internal/model"
	"github.com/signalix/server/internal/repo"
)

// ErrRefreshTokenReuseDetected is returned when a revoked refresh token is presented,
// indicating possible token theft. All sessions for the user are revoked.
var ErrRefreshTokenReuseDetected = errors.New("refresh_token_reuse_detected")

// AuthService orchestrates authentication operations
type AuthService struct {
	otpProvider     OtpProvider
	jwtService      *JWTService
	userRepo        repo.UserRepo
	deviceRepo      repo.DeviceRepo
	refreshRepo     repo.RefreshRepo
	refreshTokenTTL time.Duration
}

// NewAuthService creates a new auth service
func NewAuthService(
	otpProvider OtpProvider,
	jwtService *JWTService,
	userRepo repo.UserRepo,
	deviceRepo repo.DeviceRepo,
	refreshRepo repo.RefreshRepo,
	refreshTokenTTL time.Duration,
) *AuthService {
	if refreshTokenTTL <= 0 {
		refreshTokenTTL = 720 * time.Hour
	}
	return &AuthService{
		otpProvider:     otpProvider,
		jwtService:      jwtService,
		userRepo:        userRepo,
		deviceRepo:      deviceRepo,
		refreshRepo:     refreshRepo,
		refreshTokenTTL: refreshTokenTTL,
	}
}

// VerifyOTPAndCreateSession verifies OTP and creates user/device session
func (s *AuthService) VerifyOTPAndCreateSession(
	ctx context.Context,
	phone, code, ip string,
	deviceName string,
	identityKeyPubB64 string,
) (*model.User, *model.Device, string, error) {
	// Verify OTP
	if err := s.otpProvider.VerifyOTP(ctx, phone, code, ip); err != nil {
		return nil, nil, "", fmt.Errorf("OTP verification failed: %w", err)
	}

	// Decode identity key
	identityKeyPub, err := base64.StdEncoding.DecodeString(identityKeyPubB64)
	if err != nil {
		return nil, nil, "", fmt.Errorf("invalid identity_key_pub_b64: %w", err)
	}

	// Get or create user
	user, err := s.userRepo.GetOrCreateByPhone(ctx, phone)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to get or create user: %w", err)
	}

	// Create device
	device, err := s.deviceRepo.Create(ctx, user.ID, deviceName, identityKeyPub)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to create device: %w", err)
	}

	// Generate JWT token
	token, err := s.jwtService.SignToken(user.ID, device.ID)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to generate token: %w", err)
	}

	return &user, &device, token, nil
}

// VerifyOTPAndIssueAccessToken verifies OTP (with OTP_DEV_MODE support), gets or creates user,
// returns JWT access token and refresh token.
func (s *AuthService) VerifyOTPAndIssueAccessToken(ctx context.Context, phone, otp, ip string) (*model.User, string, string, error) {
	// OTP_DEV_MODE: accept only "123456"
	if os.Getenv("OTP_DEV_MODE") == "true" {
		if otp != "123456" {
			return nil, "", "", fmt.Errorf("invalid OTP")
		}
	} else {
		if err := s.otpProvider.VerifyOTP(ctx, phone, otp, ip); err != nil {
			return nil, "", "", fmt.Errorf("OTP verification failed: %w", err)
		}
	}

	user, err := s.userRepo.GetOrCreateByPhone(ctx, phone)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to get or create user: %w", err)
	}

	accessToken, err := s.jwtService.SignAccessToken(user.ID, user.PhoneNumber)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, err := s.createRefreshSession(ctx, user.ID)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to create refresh session: %w", err)
	}

	return &user, accessToken, refreshToken, nil
}

// createRefreshSession generates a refresh token, stores its hash, and returns the plain token
func (s *AuthService) createRefreshSession(ctx context.Context, userID uuid.UUID) (string, error) {
	token, _, err := s.createRefreshSessionWithID(ctx, userID)
	return token, err
}

// createRefreshSessionWithID creates a session and returns (token, sessionID)
func (s *AuthService) createRefreshSessionWithID(ctx context.Context, userID uuid.UUID) (token string, sessionID uuid.UUID, err error) {
	token, hashHex, err := GenerateRefreshToken()
	if err != nil {
		return "", uuid.Nil, err
	}
	expiresAt := time.Now().Add(s.refreshTokenTTL)
	sessionID, err = s.refreshRepo.Create(ctx, userID, hashHex, expiresAt)
	if err != nil {
		return "", uuid.Nil, err
	}
	return token, sessionID, nil
}

// RefreshTokens validates the refresh token, issues new access token and rotates to a new refresh token.
// If the token exists but is already revoked, all sessions for the user are revoked and
// ErrRefreshTokenReuseDetected is returned.
func (s *AuthService) RefreshTokens(ctx context.Context, refreshToken string) (accessToken, newRefreshToken string, err error) {
	if refreshToken == "" {
		return "", "", fmt.Errorf("refresh token required")
	}
	hashHex := HashRefreshToken(refreshToken)

	// Look up the session including revoked ones to distinguish reuse from unknown token.
	session, err := s.refreshRepo.FindByTokenHashIncludeRevoked(ctx, hashHex)
	if err != nil {
		// Token hash not found at all — treat as invalid/expired.
		return "", "", fmt.Errorf("invalid or expired refresh token")
	}

	// Reuse detection: token exists but was already revoked.
	if session.RevokedAt != nil {
		_ = s.refreshRepo.RevokeAllForUser(ctx, session.UserID)
		return "", "", ErrRefreshTokenReuseDetected
	}

	// Token is valid but check expiry explicitly (FindByTokenHashIncludeRevoked doesn't filter expiry).
	if session.ExpiresAt.Before(timeNow()) {
		return "", "", fmt.Errorf("invalid or expired refresh token")
	}

	user, err := s.userRepo.GetByID(ctx, session.UserID.String())
	if err != nil {
		return "", "", fmt.Errorf("user not found")
	}
	newRefreshToken, newSessionID, err := s.createRefreshSessionWithID(ctx, user.ID)
	if err != nil {
		return "", "", fmt.Errorf("failed to rotate refresh token: %w", err)
	}
	if err := s.refreshRepo.RevokeAndSetReplacedBy(ctx, session.ID, newSessionID); err != nil {
		return "", "", fmt.Errorf("failed to revoke old session: %w", err)
	}
	accessToken, err = s.jwtService.SignAccessToken(user.ID, user.PhoneNumber)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate access token: %w", err)
	}
	return accessToken, newRefreshToken, nil
}

// timeNow is a variable so tests can override it.
var timeNow = func() time.Time { return time.Now() }

// Logout revokes the refresh session
func (s *AuthService) Logout(ctx context.Context, refreshToken string) error {
	if refreshToken == "" {
		return fmt.Errorf("refresh token required")
	}
	hashHex := HashRefreshToken(refreshToken)
	session, err := s.refreshRepo.FindByTokenHash(ctx, hashHex)
	if err != nil {
		return fmt.Errorf("invalid or expired refresh token")
	}
	return s.refreshRepo.Revoke(ctx, session.ID)
}
