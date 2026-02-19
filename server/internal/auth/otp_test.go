package auth

import (
	"encoding/hex"
	"testing"
)

func TestHashOTPHex_consistency(t *testing.T) {
	phone, code, salt := "+49123", "123456", "test-salt"
	h1 := hashOTPHex(phone, code, salt)
	h2 := hashOTPHex(phone, code, salt)
	if h1 != h2 {
		t.Errorf("hash should be deterministic: %q != %q", h1, h2)
	}
	decoded, err := hex.DecodeString(h1)
	if err != nil {
		t.Fatalf("hash should be valid hex: %v", err)
	}
	if len(decoded) != 32 {
		t.Errorf("SHA-256 hash should be 32 bytes, got %d", len(decoded))
	}
}

func TestHashOTPHex_differentInputsDifferentHash(t *testing.T) {
	salt := "salt"
	h1 := hashOTPHex("+49123", "123456", salt)
	h2 := hashOTPHex("+49124", "123456", salt)
	h3 := hashOTPHex("+49123", "654321", salt)
	if h1 == h2 || h1 == h3 || h2 == h3 {
		t.Error("different inputs should produce different hashes")
	}
}

func TestConstantTimeCompare(t *testing.T) {
	a := []byte("same")
	b := []byte("same")
	if !constantTimeCompare(a, b) {
		t.Error("identical slices should compare equal")
	}
	b = []byte("diff")
	if constantTimeCompare(a, b) {
		t.Error("different slices should not compare equal")
	}
	if constantTimeCompare([]byte("a"), []byte("ab")) {
		t.Error("different length slices should not compare equal")
	}
	if constantTimeCompare(nil, []byte("x")) {
		t.Error("nil and non-nil should not compare equal")
	}
}
