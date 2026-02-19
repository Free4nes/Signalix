package auth

import "context"

// OtpProvider defines the interface for OTP operations
type OtpProvider interface {
	RequestOTP(ctx context.Context, phone, ip, userAgent string) (err error)
	VerifyOTP(ctx context.Context, phone, code, ip string) error
}
