package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

// GenerateRefreshToken returns a random Base64URL token (32 bytes) and its SHA256 hash as hex
func GenerateRefreshToken() (token string, hashHex string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	token = base64.RawURLEncoding.EncodeToString(b)
	hash := sha256.Sum256([]byte(token))
	hashHex = hex.EncodeToString(hash[:])
	return token, hashHex, nil
}

// HashRefreshToken returns SHA256 hex of the token
func HashRefreshToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}
