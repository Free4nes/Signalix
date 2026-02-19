package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const (
	tokenExpiry       = 7 * 24 * time.Hour  // 7 days (device tokens)
	accessTokenExpiry = 24 * time.Hour      // 24h (access tokens)
)

// JWTClaims represents the JWT token claims (supports both device and access tokens)
type JWTClaims struct {
	UserID     uuid.UUID `json:"sub"`
	PhoneNumber string   `json:"phone_number,omitempty"`
	DeviceID   uuid.UUID `json:"device_id,omitempty"`
	jwt.RegisteredClaims
}

// JWTService handles JWT token operations
type JWTService struct {
	secret []byte
}

// NewJWTService creates a new JWT service
func NewJWTService(secret string) *JWTService {
	return &JWTService{
		secret: []byte(secret),
	}
}

// SignToken creates a new JWT token for a user and device (7-day expiry)
func (s *JWTService) SignToken(userID, deviceID uuid.UUID) (string, error) {
	now := time.Now()
	claims := &JWTClaims{
		UserID:   userID,
		DeviceID: deviceID,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(tokenExpiry)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(s.secret)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

// SignAccessToken creates a JWT access token with user_id and phone_number (24h expiry)
func (s *JWTService) SignAccessToken(userID uuid.UUID, phoneNumber string) (string, error) {
	now := time.Now()
	claims := &JWTClaims{
		UserID:     userID,
		PhoneNumber: phoneNumber,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(accessTokenExpiry)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(s.secret)
	if err != nil {
		return "", fmt.Errorf("failed to sign access token: %w", err)
	}

	return tokenString, nil
}

// VerifyToken verifies and parses a JWT token
func (s *JWTService) VerifyToken(tokenString string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.secret, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}
