package auth

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/signalix/server/internal/model"
	"github.com/signalix/server/internal/repo"
)

// AuthService orchestrates authentication operations
type AuthService struct {
	otpProvider OtpProvider
	jwtService *JWTService
	userRepo   repo.UserRepo
	deviceRepo repo.DeviceRepo
}

// NewAuthService creates a new auth service
func NewAuthService(
	otpProvider OtpProvider,
	jwtService *JWTService,
	userRepo repo.UserRepo,
	deviceRepo repo.DeviceRepo,
) *AuthService {
	return &AuthService{
		otpProvider: otpProvider,
		jwtService:  jwtService,
		userRepo:    userRepo,
		deviceRepo:  deviceRepo,
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

// VerifyOTPAndIssueAccessToken verifies OTP (with OTP_DEV_MODE support), gets or creates user, returns JWT access token.
func (s *AuthService) VerifyOTPAndIssueAccessToken(ctx context.Context, phone, otp, ip string) (*model.User, string, error) {
	// OTP_DEV_MODE: accept only "123456"
	if os.Getenv("OTP_DEV_MODE") == "true" {
		if otp != "123456" {
			return nil, "", fmt.Errorf("invalid OTP")
		}
	} else {
		if err := s.otpProvider.VerifyOTP(ctx, phone, otp, ip); err != nil {
			return nil, "", fmt.Errorf("OTP verification failed: %w", err)
		}
	}

	user, err := s.userRepo.GetOrCreateByPhone(ctx, phone)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get or create user: %w", err)
	}

	token, err := s.jwtService.SignAccessToken(user.ID, user.PhoneNumber)
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate token: %w", err)
	}

	return &user, token, nil
}
