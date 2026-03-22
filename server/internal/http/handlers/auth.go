package handlers

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/signalix/server/internal/auth"
	"github.com/signalix/server/internal/middleware"
	"github.com/signalix/server/internal/phone"
	"github.com/signalix/server/internal/repo"
)

func isRateLimitErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), "rate limit")
}

// AuthHandler handles authentication endpoints
type AuthHandler struct {
	authService     *auth.AuthService
	otpProvider     auth.OtpProvider
	userRepo        repo.UserRepo
	pushTokenRepo   repo.PushTokenRepo
	ipLimiter       *middleware.RateLimiter
	verifyIPLimiter *middleware.RateLimiter
}

// NewAuthHandler creates a new auth handler
func NewAuthHandler(
	authService *auth.AuthService,
	otpProvider auth.OtpProvider,
	userRepo repo.UserRepo,
	pushTokenRepo repo.PushTokenRepo,
) *AuthHandler {
	// IP rate limiters: 10 per 10min for request_otp, 20 per 10min for verify_otp (phone limit is DB-based)
	return &AuthHandler{
		authService:     authService,
		otpProvider:     otpProvider,
		userRepo:        userRepo,
		pushTokenRepo:   pushTokenRepo,
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
	DisplayName string `json:"display_name,omitempty"`
	AvatarURL   string `json:"avatar_url,omitempty"`
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
	normalized, err := phone.Normalize(req.PhoneNumber)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid phone_number: "+err.Error())
		return
	}
	req.PhoneNumber = normalized

	if isGoogleReviewRequestOTPPhone(req.PhoneNumber) {
		log.Printf("GOOGLE_REVIEW request_otp hit phone=%s", maskPhone(req.PhoneNumber))
		response := requestOTPResponse{Message: "otp_sent"}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(response); err != nil {
			logMaskedPhone(req.PhoneNumber, "Failed to encode response", err)
		}
		return
	}

	ipKey := middleware.GetIPKey(r)
	if !h.ipLimiter.Allow(ipKey) {
		respondWithError(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}

	ip := getClientIP(r)
	userAgent := r.UserAgent()

	err = h.otpProvider.RequestOTP(r.Context(), req.PhoneNumber, ip, userAgent)
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
	normalized, err := phone.Normalize(req.PhoneNumber)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid phone_number: "+err.Error())
		return
	}
	req.PhoneNumber = normalized

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
			DisplayName: user.DisplayName,
			AvatarURL:   user.AvatarURL,
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

// patchMeRequest is the body for PATCH /me
type patchMeRequest struct {
	DisplayName *string `json:"display_name"`
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
		DisplayName: user.DisplayName,
		AvatarURL:   user.AvatarURL,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Failed to encode /me response: %v", err)
	}
}

// HandlePatchMe handles PATCH /me (protected). Updates display_name, returns current user like GET /me.
func (h *AuthHandler) HandlePatchMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPatch {
		respondWithError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	userID, ok := middleware.GetUserID(r.Context())
	if !ok || userID == uuid.Nil {
		respondWithError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req patchMeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	var displayName *string
	if req.DisplayName != nil {
		s := strings.TrimSpace(*req.DisplayName)
		if s != "" {
			displayName = &s
		}
	}
	if err := h.userRepo.UpdateDisplayName(r.Context(), userID.String(), displayName); err != nil {
		respondWithError(w, http.StatusInternalServerError, "failed to update profile")
		return
	}

	user, err := h.userRepo.GetByID(r.Context(), userID.String())
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "failed to load user")
		return
	}

	response := userResponse{
		ID:          user.ID.String(),
		PhoneNumber: user.PhoneNumber,
		DisplayName: user.DisplayName,
		AvatarURL:   user.AvatarURL,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

// putMeAvatarRequest is the body for PUT /me/avatar
type putMeAvatarRequest struct {
	AvatarURL *string `json:"avatar_url"`
}

// HandlePutMeAvatar handles PUT /me/avatar (protected). Sets avatar from URL (client uploads via POST /upload first). Returns updated user.
func (h *AuthHandler) HandlePutMeAvatar(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserID(r.Context())
	if !ok || userID == uuid.Nil {
		log.Printf("AVATAR_UPDATE_ERROR user= err=unauthorized")
		respondWithError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	log.Printf("AVATAR_UPDATE user=%s", userID.String())

	if r.Method != http.MethodPut {
		log.Printf("AVATAR_UPDATE_ERROR user=%s err=method_not_allowed", userID.String())
		respondWithError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req putMeAvatarRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("AVATAR_UPDATE_ERROR user=%s err=%v", userID.String(), err)
		respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	var avatarURL *string
	if req.AvatarURL != nil && strings.TrimSpace(*req.AvatarURL) != "" {
		u := strings.TrimSpace(*req.AvatarURL)
		if !strings.HasPrefix(u, "/uploads/") {
			log.Printf("AVATAR_UPDATE_ERROR user=%s err=avatar_url_must_start_with_uploads", userID.String())
			respondWithError(w, http.StatusBadRequest, "avatar_url must start with /uploads/")
			return
		}
		avatarURL = &u
	}

	if err := h.userRepo.UpdateAvatarURL(r.Context(), userID.String(), avatarURL); err != nil {
		log.Printf("AVATAR_UPDATE_ERROR user=%s err=%v", userID.String(), err)
		respondWithError(w, http.StatusInternalServerError, "failed to update avatar")
		return
	}

	user, err := h.userRepo.GetByID(r.Context(), userID.String())
	if err != nil {
		log.Printf("AVATAR_UPDATE_ERROR user=%s err=%v", userID.String(), err)
		respondWithError(w, http.StatusInternalServerError, "failed to load user")
		return
	}

	urlVal := ""
	if user.AvatarURL != "" {
		urlVal = user.AvatarURL
	}
	log.Printf("AVATAR_UPDATE_OK user=%s url=%s", userID.String(), urlVal)

	response := userResponse{
		ID:          user.ID.String(),
		PhoneNumber: user.PhoneNumber,
		DisplayName: user.DisplayName,
		AvatarURL:   user.AvatarURL,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

// savePushTokenRequest is the body for POST /me/push-token
type savePushTokenRequest struct {
	ExpoPushToken string `json:"expo_push_token"`
	Platform      string `json:"platform"`
}

// HandleSavePushToken handles POST /me/push-token (protected). Saves the Expo push token for the current user.
func (h *AuthHandler) HandleSavePushToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondWithError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	userID, ok := middleware.GetUserID(r.Context())
	if !ok || userID == uuid.Nil {
		respondWithError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req savePushTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.ExpoPushToken = strings.TrimSpace(req.ExpoPushToken)
	req.Platform = strings.TrimSpace(strings.ToLower(req.Platform))

	if req.ExpoPushToken == "" {
		respondWithError(w, http.StatusBadRequest, "expo_push_token is required")
		return
	}
	if req.Platform != "android" && req.Platform != "ios" {
		respondWithError(w, http.StatusBadRequest, "platform must be android or ios")
		return
	}

	log.Printf("PUSH_REGISTER_START user=%s platform=%s", userID, req.Platform)

	_, err := h.pushTokenRepo.SaveToken(r.Context(), userID, req.ExpoPushToken, req.Platform)
	if err != nil {
		log.Printf("PUSH_ERROR save token: %v", err)
		respondWithError(w, http.StatusInternalServerError, "failed to save push token")
		return
	}

	log.Printf("PUSH_TOKEN_SAVE_SUCCESS user=%s", userID)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"message": "ok"})
}

// respondWithError sends a JSON error response
func respondWithError(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	response := map[string]string{"error": message}
	_ = json.NewEncoder(w).Encode(response)
}

// respondRateLimitExceeded sends 429 with error and retry_after for message rate limiting.
func respondRateLimitExceeded(w http.ResponseWriter, retryAfterSeconds int) {
	if retryAfterSeconds < 1 {
		retryAfterSeconds = 1
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds))
	w.WriteHeader(http.StatusTooManyRequests)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error":        "rate_limit_exceeded",
		"retry_after":  retryAfterSeconds,
	})
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

func isGoogleReviewRequestOTPPhone(normalizedPhone string) bool {
	if os.Getenv("GOOGLE_REVIEW_ACCESS_ENABLED") != "true" {
		return false
	}

	reviewPhone := strings.TrimSpace(os.Getenv("GOOGLE_REVIEW_PHONE"))
	if reviewPhone == "" {
		return false
	}

	normalizedReviewPhone, err := phone.Normalize(reviewPhone)
	if err != nil {
		return false
	}

	return normalizedPhone == normalizedReviewPhone
}
