package tests

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/signalix/server/internal/auth"
	"github.com/signalix/server/internal/config"
	"github.com/signalix/server/internal/db"
	httphandler "github.com/signalix/server/internal/http"
	"github.com/signalix/server/internal/http/handlers"
	"github.com/signalix/server/internal/repo"
	_ "github.com/lib/pq"
)

func TestMain(m *testing.M) {
	// Set env if unset. Do NOT set DATABASE_URL; integration tests skip if missing.
	if os.Getenv("JWT_SECRET") == "" {
		os.Setenv("JWT_SECRET", "test-jwt-secret-at-least-32-characters-long")
	}
	if os.Getenv("OTP_SALT") == "" {
		os.Setenv("OTP_SALT", "test-otp-salt")
	}
	if os.Getenv("OTP_DEV_MODE") == "" {
		os.Setenv("OTP_DEV_MODE", "true")
	}

	code := m.Run()
	os.Exit(code)
}

// testServer holds the server and DB for integration tests
type testServer struct {
	Server *httptest.Server
	DB     *sql.DB
}

func newTestServer(t *testing.T) *testServer {
	t.Helper()

	cfg, err := config.Load()
	require.NoError(t, err, "config load must succeed for integration test")

	ctx := context.Background()
	database, err := db.Open(ctx, cfg.DatabaseURL)
	require.NoError(t, err, "database open must succeed; check DATABASE_URL and that test DB exists")
	t.Cleanup(func() { database.Close() })

	err = RunMigrations(database)
	require.NoError(t, err, "migrations must run successfully")

	userRepo := repo.NewUserRepo(database)
	deviceRepo := repo.NewDeviceRepo(database)
	otpRepo := repo.NewOtpRepo(database)
	refreshRepo := repo.NewRefreshRepo(database)

	otpProvider := auth.NewOtpStub(otpRepo, cfg.OTPSalt)
	jwtService := auth.NewJWTService(cfg.JWTSecret, cfg.AccessTokenTTL)
	authService := auth.NewAuthService(otpProvider, jwtService, userRepo, deviceRepo, refreshRepo, cfg.RefreshTokenTTL)
	authHandler := handlers.NewAuthHandler(authService, otpProvider)

	router := httphandler.NewRouter(authHandler, jwtService, userRepo)
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)

	return &testServer{Server: server, DB: database}
}

func (s *testServer) BaseURL() string { return s.Server.URL }

func (s *testServer) TruncateAuth(t *testing.T) {
	t.Helper()
	require.NoError(t, TruncateAuthTables(context.Background(), s.DB), "truncate auth tables")
}

// requestOTPResponse matches POST /auth/request_otp response
type requestOTPResponse struct {
	Message string `json:"message"`
	DevOTP  string `json:"dev_otp"`
}

// verifyOTPResponse matches POST /auth/verify_otp response
type verifyOTPResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	User         struct {
		ID          string `json:"id"`
		PhoneNumber string `json:"phone_number"`
	} `json:"user"`
}

// refreshResponse matches POST /auth/refresh response
type refreshResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
}

// meResponse matches GET /me response
type meResponse struct {
	ID          string `json:"id"`
	PhoneNumber string `json:"phone_number"`
}

// errorResponse matches error JSON body
type errorResponse struct {
	Error string `json:"error"`
}

func TestAuthIntegration(t *testing.T) {
	if os.Getenv("DATABASE_URL") == "" {
		t.Skip("DATABASE_URL not set; skipping integration test")
	}

	ts := newTestServer(t)
	baseURL := ts.BaseURL()
	client := ts.Server.Client()

	t.Run("A_HealthCheck", func(t *testing.T) {
		resp, err := client.Get(baseURL + "/health")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode, "GET /health must return 200")
		var body map[string]bool
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		assert.True(t, body["ok"], "response must contain {\"ok\":true}")
	})

	t.Run("B_RequestOTP", func(t *testing.T) {
		ts.TruncateAuth(t)
		body := map[string]string{"phone_number": "+491234567890"}
		bodyBytes, _ := json.Marshal(body)
		resp, err := client.Post(baseURL+"/auth/request_otp", "application/json", bytes.NewReader(bodyBytes))
		require.NoError(t, err)
		defer resp.Body.Close()
		respBody := readBody(resp)
		assert.Equal(t, http.StatusOK, resp.StatusCode, "POST /auth/request_otp must return 200; body: %s", respBody)
		var res requestOTPResponse
		require.NoError(t, json.Unmarshal([]byte(respBody), &res))
		assert.Equal(t, "otp_sent", res.Message)
		assert.NotEmpty(t, res.DevOTP, "dev_otp must be present when OTP_DEV_MODE=true")
	})

	t.Run("B2_RequestOTP_TwiceSamePhone", func(t *testing.T) {
		ts.TruncateAuth(t)
		bodyBytes, _ := json.Marshal(map[string]string{"phone_number": "+491234567890"})
		// First request
		resp1, err := client.Post(baseURL+"/auth/request_otp", "application/json", bytes.NewReader(bodyBytes))
		require.NoError(t, err)
		resp1Body := readBody(resp1)
		resp1.Body.Close()
		assert.Equal(t, http.StatusOK, resp1.StatusCode, "1st request_otp must return 200; body: %s", resp1Body)
		var res1 requestOTPResponse
		require.NoError(t, json.Unmarshal([]byte(resp1Body), &res1))
		assert.NotEmpty(t, res1.DevOTP)
		// Second request for same phone – must also return 200 (replaces previous session)
		resp2, err := client.Post(baseURL+"/auth/request_otp", "application/json", bytes.NewReader(bodyBytes))
		require.NoError(t, err)
		defer resp2.Body.Close()
		resp2Body := readBody(resp2)
		assert.Equal(t, http.StatusOK, resp2.StatusCode, "2nd request_otp for same phone must return 200; body: %s", resp2Body)
		var res2 requestOTPResponse
		require.NoError(t, json.Unmarshal([]byte(resp2Body), &res2))
		assert.NotEmpty(t, res2.DevOTP, "dev_otp must be present on 2nd request")
		// Verify the latest OTP works
		verifyBytes, _ := json.Marshal(map[string]string{"phone_number": "+491234567890", "otp": res2.DevOTP})
		respVerify, err := client.Post(baseURL+"/auth/verify_otp", "application/json", bytes.NewReader(verifyBytes))
		require.NoError(t, err)
		defer respVerify.Body.Close()
		assert.Equal(t, http.StatusOK, respVerify.StatusCode, "verify with 2nd OTP must succeed; body: %s", readBody(respVerify))
	})

	t.Run("C_VerifyOTP", func(t *testing.T) {
		ts.TruncateAuth(t)
		// Request OTP first to get dev_otp
		reqBody := map[string]string{"phone_number": "+491234567890"}
		reqBytes, _ := json.Marshal(reqBody)
		respReq, err := client.Post(baseURL+"/auth/request_otp", "application/json", bytes.NewReader(reqBytes))
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, respReq.StatusCode)
		var reqRes requestOTPResponse
		require.NoError(t, json.NewDecoder(respReq.Body).Decode(&reqRes))
		respReq.Body.Close()
		require.NotEmpty(t, reqRes.DevOTP, "dev_otp required for verify step")

		// Verify OTP
		verifyBody := map[string]string{"phone_number": "+491234567890", "otp": reqRes.DevOTP}
		verifyBytes, _ := json.Marshal(verifyBody)
		respVerify, err := client.Post(baseURL+"/auth/verify_otp", "application/json", bytes.NewReader(verifyBytes))
		require.NoError(t, err)
		defer respVerify.Body.Close()
		verifyRespBody := readBody(respVerify)
		assert.Equal(t, http.StatusOK, respVerify.StatusCode, "POST /auth/verify_otp must return 200; body: %s", verifyRespBody)
		var verifyRes verifyOTPResponse
		require.NoError(t, json.Unmarshal([]byte(verifyRespBody), &verifyRes))
		assert.NotEmpty(t, verifyRes.AccessToken, "access_token must be present")
		assert.NotEmpty(t, verifyRes.RefreshToken, "refresh_token must be present")
		assert.Equal(t, "bearer", verifyRes.TokenType)
		assert.Equal(t, "+491234567890", verifyRes.User.PhoneNumber)
	})

	t.Run("C2_RefreshToken_HappyPath", func(t *testing.T) {
		ts.TruncateAuth(t)
		reqBytes, _ := json.Marshal(map[string]string{"phone_number": "+491234567890"})
		respReq, _ := client.Post(baseURL+"/auth/request_otp", "application/json", bytes.NewReader(reqBytes))
		require.Equal(t, http.StatusOK, respReq.StatusCode)
		var reqRes requestOTPResponse
		require.NoError(t, json.NewDecoder(respReq.Body).Decode(&reqRes))
		respReq.Body.Close()
		verifyBytes, _ := json.Marshal(map[string]string{"phone_number": "+491234567890", "otp": reqRes.DevOTP})
		respVerify, _ := client.Post(baseURL+"/auth/verify_otp", "application/json", bytes.NewReader(verifyBytes))
		require.Equal(t, http.StatusOK, respVerify.StatusCode)
		var verifyRes verifyOTPResponse
		require.NoError(t, json.NewDecoder(respVerify.Body).Decode(&verifyRes))
		respVerify.Body.Close()
		require.NotEmpty(t, verifyRes.RefreshToken)

		refreshBytes, _ := json.Marshal(map[string]string{"refresh_token": verifyRes.RefreshToken})
		respRefresh, err := client.Post(baseURL+"/auth/refresh", "application/json", bytes.NewReader(refreshBytes))
		require.NoError(t, err)
		defer respRefresh.Body.Close()
		assert.Equal(t, http.StatusOK, respRefresh.StatusCode, "POST /auth/refresh must return 200; body: %s", readBody(respRefresh))
		var refreshRes refreshResponse
		require.NoError(t, json.NewDecoder(respRefresh.Body).Decode(&refreshRes))
		assert.NotEmpty(t, refreshRes.AccessToken)
		assert.NotEmpty(t, refreshRes.RefreshToken)
		assert.Equal(t, "bearer", refreshRes.TokenType)

		req, _ := http.NewRequest(http.MethodGet, baseURL+"/me", nil)
		req.Header.Set("Authorization", "Bearer "+refreshRes.AccessToken)
		respMe, err := client.Do(req)
		require.NoError(t, err)
		defer respMe.Body.Close()
		assert.Equal(t, http.StatusOK, respMe.StatusCode, "GET /me with new access_token must return 200")
	})

	t.Run("C3_RefreshToken_RotationInvalidatesOld", func(t *testing.T) {
		ts.TruncateAuth(t)
		reqBytes, _ := json.Marshal(map[string]string{"phone_number": "+491234567890"})
		respReq, _ := client.Post(baseURL+"/auth/request_otp", "application/json", bytes.NewReader(reqBytes))
		require.Equal(t, http.StatusOK, respReq.StatusCode)
		var reqRes requestOTPResponse
		require.NoError(t, json.NewDecoder(respReq.Body).Decode(&reqRes))
		respReq.Body.Close()
		verifyBytes, _ := json.Marshal(map[string]string{"phone_number": "+491234567890", "otp": reqRes.DevOTP})
		respVerify, _ := client.Post(baseURL+"/auth/verify_otp", "application/json", bytes.NewReader(verifyBytes))
		require.Equal(t, http.StatusOK, respVerify.StatusCode)
		var verifyRes verifyOTPResponse
		require.NoError(t, json.NewDecoder(respVerify.Body).Decode(&verifyRes))
		respVerify.Body.Close()
		oldRefresh := verifyRes.RefreshToken
		require.NotEmpty(t, oldRefresh)

		refreshBytes, _ := json.Marshal(map[string]string{"refresh_token": oldRefresh})
		respRefresh, _ := client.Post(baseURL+"/auth/refresh", "application/json", bytes.NewReader(refreshBytes))
		require.Equal(t, http.StatusOK, respRefresh.StatusCode)
		var refreshRes refreshResponse
		require.NoError(t, json.NewDecoder(respRefresh.Body).Decode(&refreshRes))
		respRefresh.Body.Close()
		require.NotEmpty(t, refreshRes.RefreshToken)

		// Using old refresh token again must fail (401)
		oldRefreshBytes, _ := json.Marshal(map[string]string{"refresh_token": oldRefresh})
		respOld, err := client.Post(baseURL+"/auth/refresh", "application/json", bytes.NewReader(oldRefreshBytes))
		require.NoError(t, err)
		defer respOld.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, respOld.StatusCode, "using rotated (old) refresh token must return 401")
	})

	t.Run("C4_RefreshToken_ReuseDetected_RevokesAllSessions", func(t *testing.T) {
		ts.TruncateAuth(t)
		// Obtain refresh_token_1 via verify_otp
		reqBytes, _ := json.Marshal(map[string]string{"phone_number": "+491234567890"})
		respReq, _ := client.Post(baseURL+"/auth/request_otp", "application/json", bytes.NewReader(reqBytes))
		require.Equal(t, http.StatusOK, respReq.StatusCode)
		var reqRes requestOTPResponse
		require.NoError(t, json.NewDecoder(respReq.Body).Decode(&reqRes))
		respReq.Body.Close()

		verifyBytes, _ := json.Marshal(map[string]string{"phone_number": "+491234567890", "otp": reqRes.DevOTP})
		respVerify, _ := client.Post(baseURL+"/auth/verify_otp", "application/json", bytes.NewReader(verifyBytes))
		require.Equal(t, http.StatusOK, respVerify.StatusCode)
		var verifyRes verifyOTPResponse
		require.NoError(t, json.NewDecoder(respVerify.Body).Decode(&verifyRes))
		respVerify.Body.Close()
		refreshToken1 := verifyRes.RefreshToken
		require.NotEmpty(t, refreshToken1)

		// Rotate: refresh(refresh_token_1) -> refresh_token_2
		refresh1Bytes, _ := json.Marshal(map[string]string{"refresh_token": refreshToken1})
		respRefresh1, _ := client.Post(baseURL+"/auth/refresh", "application/json", bytes.NewReader(refresh1Bytes))
		require.Equal(t, http.StatusOK, respRefresh1.StatusCode)
		var refreshRes1 refreshResponse
		require.NoError(t, json.NewDecoder(respRefresh1.Body).Decode(&refreshRes1))
		respRefresh1.Body.Close()
		refreshToken2 := refreshRes1.RefreshToken
		require.NotEmpty(t, refreshToken2)

		// Reuse: refresh(refresh_token_1) again -> 401 with refresh_token_reuse_detected
		refresh1BytesAgain, _ := json.Marshal(map[string]string{"refresh_token": refreshToken1})
		respReuse, err := client.Post(baseURL+"/auth/refresh", "application/json", bytes.NewReader(refresh1BytesAgain))
		require.NoError(t, err)
		reuseBody := readBody(respReuse)
		respReuse.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, respReuse.StatusCode, "reused token must return 401; body: %s", reuseBody)
		var reuseErr errorResponse
		require.NoError(t, json.Unmarshal([]byte(reuseBody), &reuseErr))
		assert.Equal(t, "refresh_token_reuse_detected", reuseErr.Error, "error must be refresh_token_reuse_detected")

		// Global revoke: refresh(refresh_token_2) must now also fail (all sessions revoked)
		refresh2Bytes, _ := json.Marshal(map[string]string{"refresh_token": refreshToken2})
		respRevoked, err := client.Post(baseURL+"/auth/refresh", "application/json", bytes.NewReader(refresh2Bytes))
		require.NoError(t, err)
		revokedBody := readBody(respRevoked)
		respRevoked.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, respRevoked.StatusCode, "globally revoked token must return 401; body: %s", revokedBody)
	})

	t.Run("D_AuthenticatedMe", func(t *testing.T) {
		ts.TruncateAuth(t)
		// Get token via request_otp + verify_otp
		reqBytes, _ := json.Marshal(map[string]string{"phone_number": "+491234567890"})
		respReq, err := client.Post(baseURL+"/auth/request_otp", "application/json", bytes.NewReader(reqBytes))
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, respReq.StatusCode)
		var reqRes requestOTPResponse
		require.NoError(t, json.NewDecoder(respReq.Body).Decode(&reqRes))
		respReq.Body.Close()
		verifyBytes, _ := json.Marshal(map[string]string{"phone_number": "+491234567890", "otp": reqRes.DevOTP})
		respVerify, err := client.Post(baseURL+"/auth/verify_otp", "application/json", bytes.NewReader(verifyBytes))
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, respVerify.StatusCode)
		var verifyRes verifyOTPResponse
		require.NoError(t, json.NewDecoder(respVerify.Body).Decode(&verifyRes))
		respVerify.Body.Close()

		req, _ := http.NewRequest(http.MethodGet, baseURL+"/me", nil)
		req.Header.Set("Authorization", "Bearer "+verifyRes.AccessToken)
		respMe, err := client.Do(req)
		require.NoError(t, err)
		defer respMe.Body.Close()
		meRespBody := readBody(respMe)
		assert.Equal(t, http.StatusOK, respMe.StatusCode, "GET /me must return 200; body: %s", meRespBody)
		var meRes meResponse
		require.NoError(t, json.Unmarshal([]byte(meRespBody), &meRes))
		assert.Equal(t, "+491234567890", meRes.PhoneNumber, "response must contain correct phone_number")
		assert.NotEmpty(t, meRes.ID)
	})

	t.Run("E_InvalidOTP", func(t *testing.T) {
		ts.TruncateAuth(t)
		// Create a session first
		reqBytes, _ := json.Marshal(map[string]string{"phone_number": "+491234567890"})
		_, _ = client.Post(baseURL+"/auth/request_otp", "application/json", bytes.NewReader(reqBytes))
		// Verify with wrong OTP
		verifyBytes, _ := json.Marshal(map[string]string{"phone_number": "+491234567890", "otp": "000000"})
		resp, err := client.Post(baseURL+"/auth/verify_otp", "application/json", bytes.NewReader(verifyBytes))
		require.NoError(t, err)
		defer resp.Body.Close()
		errRespBody := readBody(resp)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "wrong OTP must return 401; body: %s", errRespBody)
		var errRes errorResponse
		_ = json.Unmarshal([]byte(errRespBody), &errRes)
		assert.NotEmpty(t, errRes.Error)
	})

	t.Run("F_RateLimit", func(t *testing.T) {
		ts.TruncateAuth(t)
		body, _ := json.Marshal(map[string]string{"phone_number": "+491234567890"})
		var lastResp *http.Response
		for i := 0; i < 4; i++ {
			resp, err := client.Post(baseURL+"/auth/request_otp", "application/json", bytes.NewReader(body))
			require.NoError(t, err)
			lastResp = resp
			if resp.StatusCode == http.StatusTooManyRequests {
				break
			}
			resp.Body.Close()
		}
		require.NotNil(t, lastResp)
		defer lastResp.Body.Close()
		rateLimitBody := readBody(lastResp)
		assert.Equal(t, http.StatusTooManyRequests, lastResp.StatusCode, "4th request_otp must return 429 (rate limit); body: %s", rateLimitBody)
	})
}

// readBody reads and returns the response body (consumes it). Use for error messages only.
func readBody(resp *http.Response) string {
	if resp == nil || resp.Body == nil {
		return ""
	}
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}
