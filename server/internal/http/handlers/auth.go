package handlers

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/signalix/server/internal/auth"
	"github.com/signalix/server/internal/middleware"
)

func isRateLimitErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), "rate limit")
}

// AuthHandler handles authentication endpoints
type AuthHandler struct {
	authService     *auth.AuthService
	otpProvider     auth.OtpProvider
	ipLimiter       *middleware.RateLimiter
	verifyIPLimiter *middleware.RateLimiter
}

// NewAuthHandler creates a new auth handler
func NewAuthHandler(
	authService *auth.AuthService,
	otpProvider auth.OtpProvider,
) *AuthHandler {
	// IP rate limiters: 10 per 10min for request_otp, 20 per 10min for verify_otp (phone limit is DB-based)
	return &AuthHandler{
		authService:     authService,
		otpProvider:     otpProvider,
		ipLimiter:       middleware.NewRateLimiter(10*60*time.Second, 10),
		verifyIPLimiter: middleware.NewRateLimiter(10*60*time.Second, 20),
	}
}

// requestOTPRequest is the request body for POST /auth/request_otp
type requestOTPRequest struct {
	PhoneNumber string `json:"phone_number"`
}

// requestOTPResponse is the JSON response for request_otp
type requestOTPResponse struct {
	Message string `json:"message"`
	DevOTP  string `json:"dev_otp,omitempty"`
}

// verifyOTPRequest is the request body for POST /auth/verify_otp
type verifyOTPRequest struct {
	PhoneNumber string `json:"phone_number"`
	OTP         string `json:"otp"`
}

// verifyOTPResponse is the JSON response for verify_otp
type verifyOTPResponse struct {
	AccessToken  string       `json:"access_token"`
	RefreshToken string       `json:"refresh_token"`
	TokenType    string       `json:"token_type"`
	User         userResponse `json:"user"`
}

// userResponse is the user object in API responses
type userResponse struct {
	ID          string `json:"id"`
	PhoneNumber string `json:"phone_number"`
}

// HandleRequestOTP handles POST /auth/request_otp
func (h *AuthHandler) HandleRequestOTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondWithError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req requestOTPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Don't return 400 for decode errors; only 400 for empty phone_number
		respondWithError(w, http.StatusUnprocessableEntity, "invalid request body")
		return
	}

	req.PhoneNumber = strings.TrimSpace(req.PhoneNumber)
	if req.PhoneNumber == "" {
		respondWithError(w, http.StatusBadRequest, "phone_number is required")
		return
	}

	ipKey := middleware.GetIPKey(r)
	if !h.ipLimiter.Allow(ipKey) {
		respondWithError(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}

	ip := getClientIP(r)
	userAgent := r.UserAgent()

	err := h.otpProvider.RequestOTP(r.Context(), req.PhoneNumber, ip, userAgent)
	if err != nil {
		logMaskedPhone(req.PhoneNumber, "Failed to request OTP", err)
		if isRateLimitErr(err) {
			respondWithError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		respondWithError(w, http.StatusInternalServerError, "failed to request OTP")
		return
	}

	devMode := os.Getenv("OTP_DEV_MODE") == "true"

	response := requestOTPResponse{Message: "otp_sent"}
	if devMode {
		response.DevOTP = "123456"
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		logMaskedPhone(req.PhoneNumber, "Failed to encode response", err)
	}
}

// HandleVerifyOTP handles POST /auth/verify_otp
func (h *AuthHandler) HandleVerifyOTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondWithError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req verifyOTPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.PhoneNumber = strings.TrimSpace(req.PhoneNumber)
	req.OTP = strings.TrimSpace(req.OTP)

	if req.PhoneNumber == "" || req.OTP == "" {
		respondWithError(w, http.StatusBadRequest, "phone_number and otp are required")
		return
	}

	ipKey := middleware.GetIPKey(r)
	if !h.verifyIPLimiter.Allow(ipKey) {
		respondWithError(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}

	ip := getClientIP(r)

	user, accessToken, refreshToken, err := h.authService.VerifyOTPAndIssueAccessToken(r.Context(), req.PhoneNumber, req.OTP, ip)
	if err != nil {
		logMaskedPhone(req.PhoneNumber, "OTP verification failed", err)
		respondWithError(w, http.StatusUnauthorized, "invalid or expired OTP")
		return
	}

	response := verifyOTPResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "bearer",
		User: userResponse{
			ID:          user.ID.String(),
			PhoneNumber: user.PhoneNumber,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		logMaskedPhone(req.PhoneNumber, "Failed to encode response", err)
	}
}

// refreshRequest is the request body for POST /auth/refresh
type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// refreshResponse is the JSON response for refresh
type refreshResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
}

// HandleRefresh handles POST /auth/refresh
func (h *AuthHandler) HandleRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondWithError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req refreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.RefreshToken = strings.TrimSpace(req.RefreshToken)
	if req.RefreshToken == "" {
		respondWithError(w, http.StatusBadRequest, "refresh_token is required")
		return
	}
	accessToken, refreshToken, err := h.authService.RefreshTokens(r.Context(), req.RefreshToken)
	if err != nil {
		if errors.Is(err, auth.ErrRefreshTokenReuseDetected) {
			respondWithError(w, http.StatusUnauthorized, "refresh_token_reuse_detected")
			return
		}
		respondWithError(w, http.StatusUnauthorized, "invalid or expired refresh token")
		return
	}
	response := refreshResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "bearer",
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

// logoutRequest is the request body for POST /auth/logout
type logoutRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// HandleLogout handles POST /auth/logout
func (h *AuthHandler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondWithError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req logoutRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.RefreshToken = strings.TrimSpace(req.RefreshToken)
	if req.RefreshToken == "" {
		respondWithError(w, http.StatusBadRequest, "refresh_token is required")
		return
	}
	if err := h.authService.Logout(r.Context(), req.RefreshToken); err != nil {
		respondWithError(w, http.StatusUnauthorized, "invalid or expired refresh token")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"message": "logged out"})
}

// HandleMe handles GET /me (protected). Returns the authenticated user.
func (h *AuthHandler) HandleMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondWithError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	user, ok := middleware.GetUser(r.Context())
	if !ok || user == nil {
		respondWithError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	response := userResponse{
		ID:          user.ID.String(),
		PhoneNumber: user.PhoneNumber,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Failed to encode /me response: %v", err)
	}
}

// respondWithError sends a JSON error response
func respondWithError(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	response := map[string]string{"error": message}
	_ = json.NewEncoder(w).Encode(response)
}

// getClientIP extracts the client IP from the request
func getClientIP(r *http.Request) string {
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		// Take first IP if multiple
		ips := strings.Split(forwarded, ",")
		return strings.TrimSpace(ips[0])
	}

	return r.RemoteAddr
}

// logMaskedPhone logs a message with masked phone number
func logMaskedPhone(phone, format string, args ...interface{}) {
	masked := maskPhone(phone)
	// Replace first %v or %s in format with masked phone
	log.Printf("Phone "+masked+": "+format, args...)
}

// maskPhone masks a phone number for logging (e.g., +49******89)
func maskPhone(phone string) string {
	if len(phone) <= 4 {
		return "****"
	}

	// Keep first 2 and last 2 characters, mask the rest
	prefix := phone[:2]
	suffix := phone[len(phone)-2:]
	masked := strings.Repeat("*", len(phone)-4)
	return prefix + masked + suffix
}
