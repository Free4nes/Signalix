package tests

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testPhone = "+491234567890"

// TestAuthE2E runs the complete E2E flow: health, request_otp, verify_otp, me, rate limit, production mode.
// Uses httptest.NewServer (no real port). Deterministic: TruncateAuth before each section.
func TestAuthE2E(t *testing.T) {
	if os.Getenv("DATABASE_URL") == "" {
		t.Skip("DATABASE_URL not set; skipping E2E test")
	}

	ts := newTestServer(t)
	baseURL := ts.BaseURL()
	client := ts.Server.Client()

	t.Run("A_Health", func(t *testing.T) {
		ts.TruncateAuth(t)
		resp, err := client.Get(baseURL + "/health")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode, "GET /health must return 200")
		var body map[string]bool
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		assert.True(t, body["ok"])
	})

	t.Run("B_FullFlow", func(t *testing.T) {
		ts.TruncateAuth(t)

		// request_otp
		reqBody := map[string]string{"phone_number": testPhone}
		reqBytes, _ := json.Marshal(reqBody)
		respReq, err := client.Post(baseURL+"/auth/request_otp", "application/json", bytes.NewReader(reqBytes))
		require.NoError(t, err)
		defer respReq.Body.Close()
		reqRespBody := readBody(respReq)
		assert.Equal(t, http.StatusOK, respReq.StatusCode, "POST /auth/request_otp must return 200; body: %s", reqRespBody)
		var reqRes requestOTPResponse
		require.NoError(t, json.Unmarshal([]byte(reqRespBody), &reqRes))
		assert.Equal(t, "otp_sent", reqRes.Message)
		require.NotEmpty(t, reqRes.DevOTP, "dev_otp must be present when OTP_DEV_MODE=true")

		// verify_otp
		verifyBody := map[string]string{"phone_number": testPhone, "otp": reqRes.DevOTP}
		verifyBytes, _ := json.Marshal(verifyBody)
		respVerify, err := client.Post(baseURL+"/auth/verify_otp", "application/json", bytes.NewReader(verifyBytes))
		require.NoError(t, err)
		defer respVerify.Body.Close()
		verifyRespBody := readBody(respVerify)
		assert.Equal(t, http.StatusOK, respVerify.StatusCode, "POST /auth/verify_otp must return 200; body: %s", verifyRespBody)
		var verifyRes verifyOTPResponse
		require.NoError(t, json.Unmarshal([]byte(verifyRespBody), &verifyRes))
		assert.NotEmpty(t, verifyRes.AccessToken)
		assert.NotEmpty(t, verifyRes.RefreshToken)
		assert.Equal(t, "bearer", verifyRes.TokenType)
		assert.Equal(t, testPhone, verifyRes.User.PhoneNumber)

		// me
		req, _ := http.NewRequest(http.MethodGet, baseURL+"/me", nil)
		req.Header.Set("Authorization", "Bearer "+verifyRes.AccessToken)
		respMe, err := client.Do(req)
		require.NoError(t, err)
		defer respMe.Body.Close()
		meRespBody := readBody(respMe)
		assert.Equal(t, http.StatusOK, respMe.StatusCode, "GET /me must return 200; body: %s", meRespBody)
		var meRes meResponse
		require.NoError(t, json.Unmarshal([]byte(meRespBody), &meRes))
		assert.Equal(t, testPhone, meRes.PhoneNumber)
		assert.NotEmpty(t, meRes.ID)
	})

	t.Run("C_RateLimit", func(t *testing.T) {
		ts.TruncateAuth(t)
		body, _ := json.Marshal(map[string]string{"phone_number": testPhone})
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
		assert.Equal(t, http.StatusTooManyRequests, lastResp.StatusCode,
			"4th request_otp must return 429 (rate limit); body: %s", readBody(lastResp))
	})

	t.Run("D_ProductionMode", func(t *testing.T) {
		ts.TruncateAuth(t)
		old := os.Getenv("OTP_DEV_MODE")
		defer func() { _ = os.Setenv("OTP_DEV_MODE", old) }()
		_ = os.Setenv("OTP_DEV_MODE", "false")

		reqBody := map[string]string{"phone_number": testPhone}
		reqBytes, _ := json.Marshal(reqBody)
		resp, err := client.Post(baseURL+"/auth/request_otp", "application/json", bytes.NewReader(reqBytes))
		require.NoError(t, err)
		defer resp.Body.Close()
		respBody := readBody(resp)
		assert.Equal(t, http.StatusOK, resp.StatusCode, "POST /auth/request_otp in prod mode must return 200; body: %s", respBody)
		var res requestOTPResponse
		require.NoError(t, json.Unmarshal([]byte(respBody), &res))
		assert.Equal(t, "otp_sent", res.Message)
		assert.Empty(t, res.DevOTP, "dev_otp must not be exposed when OTP_DEV_MODE=false")
	})
}
