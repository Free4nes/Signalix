package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// TwilioVerifyOtpProvider uses Twilio Verify to request and verify OTP codes.
type TwilioVerifyOtpProvider struct {
	accountSID string
	authToken  string
	serviceSID string
	client     *http.Client
	mu         sync.RWMutex
	verifySID  map[string]string
}

func NewTwilioVerifyOtpProvider(accountSID, authToken, serviceSID string) *TwilioVerifyOtpProvider {
	return &TwilioVerifyOtpProvider{
		accountSID: strings.TrimSpace(accountSID),
		authToken:  strings.TrimSpace(authToken),
		serviceSID: strings.TrimSpace(serviceSID),
		client:     &http.Client{Timeout: 10 * time.Second},
		verifySID:  make(map[string]string),
	}
}

func (p *TwilioVerifyOtpProvider) RequestOTP(ctx context.Context, phone, ip, userAgent string) error {
	endpoint := fmt.Sprintf(
		"https://verify.twilio.com/v2/Services/%s/Verifications",
		p.serviceSID,
	)
	form := url.Values{}
	form.Set("To", phone)
	form.Set("Channel", "sms")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("build twilio verify request: %w", err)
	}
	req.SetBasicAuth(p.accountSID, p.authToken)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("twilio verify request failed: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	body := strings.TrimSpace(string(bodyBytes))

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("twilio verify create failed: status=%d body=%s", resp.StatusCode, body)
	}

	var createResp struct {
		SID string `json:"sid"`
	}
	if err := json.Unmarshal(bodyBytes, &createResp); err != nil {
		return fmt.Errorf("twilio verify create parse error: %w", err)
	}
	if strings.TrimSpace(createResp.SID) == "" {
		return fmt.Errorf("twilio verify create missing verification sid")
	}

	p.mu.Lock()
	p.verifySID[phone] = strings.TrimSpace(createResp.SID)
	p.mu.Unlock()
	return nil
}

func (p *TwilioVerifyOtpProvider) VerifyOTP(ctx context.Context, phone, code, ip string) error {
	endpoint := fmt.Sprintf(
		"https://verify.twilio.com/v2/Services/%s/VerificationCheck",
		p.serviceSID,
	)

	p.mu.RLock()
	verificationSID := p.verifySID[phone]
	p.mu.RUnlock()
	if verificationSID == "" {
		return fmt.Errorf("invalid or expired OTP")
	}

	form := url.Values{}
	form.Set("VerificationSid", verificationSID)
	form.Set("Code", code)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("build twilio verify check request: %w", err)
	}
	req.SetBasicAuth(p.accountSID, p.authToken)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("twilio verify check request failed: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	body := string(bodyBytes)
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("twilio verify check upstream error: status=%d body=%s", resp.StatusCode, strings.TrimSpace(body))
	}

	var checkResp struct {
		Status string `json:"status"`
		Valid  bool   `json:"valid"`
	}
	if err := json.Unmarshal(bodyBytes, &checkResp); err != nil {
		return fmt.Errorf("twilio verify check parse error: %w", err)
	}

	if checkResp.Status != "approved" && !checkResp.Valid {
		return fmt.Errorf("invalid or expired OTP")
	}

	p.mu.Lock()
	delete(p.verifySID, phone)
	p.mu.Unlock()
	return nil
}
