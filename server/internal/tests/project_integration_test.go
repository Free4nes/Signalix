package tests

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/signalix/server/internal/model"
	"github.com/signalix/server/internal/project"
	"github.com/signalix/server/internal/repo"
)

// mockUnknownEventObserver implements project.UnknownEventObserver for tests
type mockUnknownEventObserver struct {
	onUnknownEvent func(eventType string, version int)
}

func (m *mockUnknownEventObserver) OnUnknownEvent(eventType string, version int) {
	if m.onUnknownEvent != nil {
		m.onUnknownEvent(eventType, version)
	}
}

// projectResponse mirrors the API JSON shape
type projectAPIResponse struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

// keyAPIResponse mirrors the API JSON shape for a key (list)
type keyAPIResponse struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Last4     string     `json:"last4"`
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at"`
}

// createKeyAPIResponse includes the one-time api_key field
type createKeyAPIResponse struct {
	keyAPIResponse
	APIKey string `json:"api_key"`
}

// loginAndGetToken is a helper that does request_otp + verify_otp and returns the access token
func loginAndGetToken(t *testing.T, client *http.Client, baseURL, phone string) string {
	t.Helper()

	reqBytes, _ := json.Marshal(map[string]string{"phone_number": phone})
	respReq, err := client.Post(baseURL+"/auth/request_otp", "application/json", bytes.NewReader(reqBytes))
	require.NoError(t, err)
	var reqRes requestOTPResponse
	require.NoError(t, json.NewDecoder(respReq.Body).Decode(&reqRes))
	respReq.Body.Close()
	require.NotEmpty(t, reqRes.DevOTP)

	verifyBytes, _ := json.Marshal(map[string]string{"phone_number": phone, "otp": reqRes.DevOTP})
	respVerify, err := client.Post(baseURL+"/auth/verify_otp", "application/json", bytes.NewReader(verifyBytes))
	require.NoError(t, err)
	var verifyRes verifyOTPResponse
	require.NoError(t, json.NewDecoder(respVerify.Body).Decode(&verifyRes))
	respVerify.Body.Close()
	require.NotEmpty(t, verifyRes.AccessToken)
	return verifyRes.AccessToken
}

func TestProjectIntegration(t *testing.T) {
	if os.Getenv("DATABASE_URL") == "" {
		t.Skip("DATABASE_URL not set; skipping integration test")
	}

	ts := newTestServer(t)
	baseURL := ts.BaseURL()
	client := ts.Server.Client()

	t.Run("P1_CreateAndListProjects", func(t *testing.T) {
		ts.TruncateAuth(t)
		token := loginAndGetToken(t, client, baseURL, "+491111111111")

		// Create project 1
		body1, _ := json.Marshal(map[string]string{"name": "Alpha"})
		req1, _ := http.NewRequest(http.MethodPost, baseURL+"/projects", bytes.NewReader(body1))
		req1.Header.Set("Authorization", "Bearer "+token)
		req1.Header.Set("Content-Type", "application/json")
		resp1, err := client.Do(req1)
		require.NoError(t, err)
		defer resp1.Body.Close()
		assert.Equal(t, http.StatusCreated, resp1.StatusCode)
		var p1 projectAPIResponse
		require.NoError(t, json.NewDecoder(resp1.Body).Decode(&p1))
		assert.Equal(t, "Alpha", p1.Name)
		assert.NotEmpty(t, p1.ID)

		// Create project 2
		body2, _ := json.Marshal(map[string]string{"name": "Beta"})
		req2, _ := http.NewRequest(http.MethodPost, baseURL+"/projects", bytes.NewReader(body2))
		req2.Header.Set("Authorization", "Bearer "+token)
		req2.Header.Set("Content-Type", "application/json")
		resp2, err := client.Do(req2)
		require.NoError(t, err)
		defer resp2.Body.Close()
		assert.Equal(t, http.StatusCreated, resp2.StatusCode)
		var p2 projectAPIResponse
		require.NoError(t, json.NewDecoder(resp2.Body).Decode(&p2))
		assert.Equal(t, "Beta", p2.Name)

		// List projects — must contain both
		listReq, _ := http.NewRequest(http.MethodGet, baseURL+"/projects", nil)
		listReq.Header.Set("Authorization", "Bearer "+token)
		listResp, err := client.Do(listReq)
		require.NoError(t, err)
		defer listResp.Body.Close()
		assert.Equal(t, http.StatusOK, listResp.StatusCode)
		var projects []projectAPIResponse
		require.NoError(t, json.NewDecoder(listResp.Body).Decode(&projects))
		assert.Len(t, projects, 2)

		names := []string{projects[0].Name, projects[1].Name}
		assert.Contains(t, names, "Alpha")
		assert.Contains(t, names, "Beta")
	})

	t.Run("P2_CreateKey_ReturnsPlaintextOnce_StoresHashAndLast4", func(t *testing.T) {
		ts.TruncateAuth(t)
		token := loginAndGetToken(t, client, baseURL, "+492222222222")

		// Create a project
		projBody, _ := json.Marshal(map[string]string{"name": "KeyTest"})
		projReq, _ := http.NewRequest(http.MethodPost, baseURL+"/projects", bytes.NewReader(projBody))
		projReq.Header.Set("Authorization", "Bearer "+token)
		projReq.Header.Set("Content-Type", "application/json")
		projResp, err := client.Do(projReq)
		require.NoError(t, err)
		var proj projectAPIResponse
		require.NoError(t, json.NewDecoder(projResp.Body).Decode(&proj))
		projResp.Body.Close()

		// Create a key
		keyBody, _ := json.Marshal(map[string]string{"name": "Default Key"})
		keyReq, _ := http.NewRequest(http.MethodPost, baseURL+"/projects/"+proj.ID+"/keys", bytes.NewReader(keyBody))
		keyReq.Header.Set("Authorization", "Bearer "+token)
		keyReq.Header.Set("Content-Type", "application/json")
		keyResp, err := client.Do(keyReq)
		require.NoError(t, err)
		defer keyResp.Body.Close()
		assert.Equal(t, http.StatusCreated, keyResp.StatusCode)

		var created createKeyAPIResponse
		require.NoError(t, json.NewDecoder(keyResp.Body).Decode(&created))

		// Plaintext key is returned and starts with "sk_live_"
		assert.NotEmpty(t, created.APIKey)
		assert.Contains(t, created.APIKey, "sk_live_")

		// last4 matches the last 4 chars of the plaintext key
		assert.Equal(t, created.APIKey[len(created.APIKey)-4:], created.Last4)

		// api_key field is NOT present in list endpoint (only hash+last4 stored)
		listReq, _ := http.NewRequest(http.MethodGet, baseURL+"/projects/"+proj.ID+"/keys", nil)
		listReq.Header.Set("Authorization", "Bearer "+token)
		listResp, err := client.Do(listReq)
		require.NoError(t, err)
		defer listResp.Body.Close()
		assert.Equal(t, http.StatusOK, listResp.StatusCode)

		var keys []json.RawMessage
		require.NoError(t, json.NewDecoder(listResp.Body).Decode(&keys))
		require.Len(t, keys, 1)

		// Verify no "api_key" field in list response
		var rawMap map[string]interface{}
		require.NoError(t, json.Unmarshal(keys[0], &rawMap))
		_, hasAPIKey := rawMap["api_key"]
		assert.False(t, hasAPIKey, "api_key must NOT appear in list response")
		assert.NotEmpty(t, rawMap["last4"])
	})

	t.Run("P3_RevokeKey_SetsRevokedAt", func(t *testing.T) {
		ts.TruncateAuth(t)
		token := loginAndGetToken(t, client, baseURL, "+493333333333")

		// Create project + key
		projBody, _ := json.Marshal(map[string]string{"name": "RevokeTest"})
		projReq, _ := http.NewRequest(http.MethodPost, baseURL+"/projects", bytes.NewReader(projBody))
		projReq.Header.Set("Authorization", "Bearer "+token)
		projReq.Header.Set("Content-Type", "application/json")
		projResp, err := client.Do(projReq)
		require.NoError(t, err)
		var proj projectAPIResponse
		require.NoError(t, json.NewDecoder(projResp.Body).Decode(&proj))
		projResp.Body.Close()

		keyBody, _ := json.Marshal(map[string]string{"name": "ToRevoke"})
		keyReq, _ := http.NewRequest(http.MethodPost, baseURL+"/projects/"+proj.ID+"/keys", bytes.NewReader(keyBody))
		keyReq.Header.Set("Authorization", "Bearer "+token)
		keyReq.Header.Set("Content-Type", "application/json")
		keyResp, err := client.Do(keyReq)
		require.NoError(t, err)
		var created createKeyAPIResponse
		require.NoError(t, json.NewDecoder(keyResp.Body).Decode(&created))
		keyResp.Body.Close()

		// Revoke the key
		revokeReq, _ := http.NewRequest(http.MethodPost, baseURL+"/projects/"+proj.ID+"/keys/"+created.ID+"/revoke", nil)
		revokeReq.Header.Set("Authorization", "Bearer "+token)
		revokeResp, err := client.Do(revokeReq)
		require.NoError(t, err)
		revokeResp.Body.Close()
		assert.Equal(t, http.StatusNoContent, revokeResp.StatusCode)

		// List keys — revoked_at must be set
		listReq, _ := http.NewRequest(http.MethodGet, baseURL+"/projects/"+proj.ID+"/keys", nil)
		listReq.Header.Set("Authorization", "Bearer "+token)
		listResp, err := client.Do(listReq)
		require.NoError(t, err)
		defer listResp.Body.Close()
		var keys []keyAPIResponse
		require.NoError(t, json.NewDecoder(listResp.Body).Decode(&keys))
		require.Len(t, keys, 1)
		assert.NotNil(t, keys[0].RevokedAt, "revoked_at must be set after revoke")
	})

	t.Run("P4_ForbiddenCrossUser", func(t *testing.T) {
		ts.TruncateAuth(t)
		tokenA := loginAndGetToken(t, client, baseURL, "+494444444444")
		tokenB := loginAndGetToken(t, client, baseURL, "+495555555555")

		// User A creates a project
		projBody, _ := json.Marshal(map[string]string{"name": "UserAProject"})
		projReq, _ := http.NewRequest(http.MethodPost, baseURL+"/projects", bytes.NewReader(projBody))
		projReq.Header.Set("Authorization", "Bearer "+tokenA)
		projReq.Header.Set("Content-Type", "application/json")
		projResp, err := client.Do(projReq)
		require.NoError(t, err)
		var proj projectAPIResponse
		require.NoError(t, json.NewDecoder(projResp.Body).Decode(&proj))
		projResp.Body.Close()

		// User B tries to create a key in User A's project — must get 403
		keyBody, _ := json.Marshal(map[string]string{"name": "Sneaky"})
		keyReq, _ := http.NewRequest(http.MethodPost, baseURL+"/projects/"+proj.ID+"/keys", bytes.NewReader(keyBody))
		keyReq.Header.Set("Authorization", "Bearer "+tokenB)
		keyReq.Header.Set("Content-Type", "application/json")
		keyResp, err := client.Do(keyReq)
		require.NoError(t, err)
		defer keyResp.Body.Close()
		assert.Equal(t, http.StatusForbidden, keyResp.StatusCode)
	})

	t.Run("P5_EmptyName_Returns400", func(t *testing.T) {
		ts.TruncateAuth(t)
		token := loginAndGetToken(t, client, baseURL, "+496666666666")
		body, _ := json.Marshal(map[string]string{"name": "   "})
		req, _ := http.NewRequest(http.MethodPost, baseURL+"/projects", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("P6_NoToken_Returns401", func(t *testing.T) {
		body, _ := json.Marshal(map[string]string{"name": "Test"})
		req, _ := http.NewRequest(http.MethodPost, baseURL+"/projects", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

		getReq, _ := http.NewRequest(http.MethodGet, baseURL+"/projects", nil)
		getResp, err := client.Do(getReq)
		require.NoError(t, err)
		defer getResp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, getResp.StatusCode)
	})

	t.Run("P7_Activity_ActorLabel_DisplayName", func(t *testing.T) {
		ts.TruncateAuth(t)
		tokenA, userAID := loginAndGetTokenAndUserID(t, client, baseURL, "+497111111111")
		_, userBID := loginAndGetTokenAndUserID(t, client, baseURL, "+497222222222")

		// User A sets display_name
		patchBody, _ := json.Marshal(map[string]string{"display_name": "Alice"})
		patchReq, _ := http.NewRequest(http.MethodPatch, baseURL+"/me", bytes.NewReader(patchBody))
		patchReq.Header.Set("Authorization", "Bearer "+tokenA)
		patchReq.Header.Set("Content-Type", "application/json")
		patchResp, err := client.Do(patchReq)
		require.NoError(t, err)
		patchResp.Body.Close()
		require.Equal(t, http.StatusOK, patchResp.StatusCode)

		// User A creates project
		projBody, _ := json.Marshal(map[string]string{"name": "ActorLabelTest"})
		projReq, _ := http.NewRequest(http.MethodPost, baseURL+"/projects", bytes.NewReader(projBody))
		projReq.Header.Set("Authorization", "Bearer "+tokenA)
		projReq.Header.Set("Content-Type", "application/json")
		projResp, err := client.Do(projReq)
		require.NoError(t, err)
		var proj projectAPIResponse
		require.NoError(t, json.NewDecoder(projResp.Body).Decode(&proj))
		projResp.Body.Close()

		// User A creates conversation in project -> emits ConversationAdded
		convBody, _ := json.Marshal(map[string]interface{}{
			"member_user_ids": []string{userAID, userBID},
			"project_id":      proj.ID,
		})
		convReq, _ := http.NewRequest(http.MethodPost, baseURL+"/conversations", bytes.NewReader(convBody))
		convReq.Header.Set("Authorization", "Bearer "+tokenA)
		convReq.Header.Set("Content-Type", "application/json")
		convResp, err := client.Do(convReq)
		require.NoError(t, err)
		convResp.Body.Close()
		require.Equal(t, http.StatusCreated, convResp.StatusCode)

		// Fetch activity
		actReq, _ := http.NewRequest(http.MethodGet, baseURL+"/projects/"+proj.ID+"/activity", nil)
		actReq.Header.Set("Authorization", "Bearer "+tokenA)
		actResp, err := client.Do(actReq)
		require.NoError(t, err)
		defer actResp.Body.Close()
		require.Equal(t, http.StatusOK, actResp.StatusCode)

		var actRespData projectActivityAPIResponse
		require.NoError(t, json.NewDecoder(actResp.Body).Decode(&actRespData))
		require.NotEmpty(t, actRespData.Items, "activity should have items")
		// First item is project_created, second is conversation_added
		var found bool
		for _, item := range actRespData.Items {
			if item.Type == "conversation_added" {
				assert.Equal(t, "Alice", item.ActorLabel, "actor_label should be display_name when set")
				found = true
				break
			}
		}
		assert.True(t, found, "conversation_added event should exist")
	})

	t.Run("P8_Activity_ActorLabel_PhoneWhenNoDisplayName", func(t *testing.T) {
		ts.TruncateAuth(t)
		phoneC := "+498333333333"
		tokenC, userCID := loginAndGetTokenAndUserID(t, client, baseURL, phoneC)
		_, userDID := loginAndGetTokenAndUserID(t, client, baseURL, "+498444444444")

		// User C does NOT set display_name

		// User C creates project
		projBody, _ := json.Marshal(map[string]string{"name": "ActorPhoneTest"})
		projReq, _ := http.NewRequest(http.MethodPost, baseURL+"/projects", bytes.NewReader(projBody))
		projReq.Header.Set("Authorization", "Bearer "+tokenC)
		projReq.Header.Set("Content-Type", "application/json")
		projResp, err := client.Do(projReq)
		require.NoError(t, err)
		var proj projectAPIResponse
		require.NoError(t, json.NewDecoder(projResp.Body).Decode(&proj))
		projResp.Body.Close()

		// User C creates conversation in project
		convBody, _ := json.Marshal(map[string]interface{}{
			"member_user_ids": []string{userCID, userDID},
			"project_id":      proj.ID,
		})
		convReq, _ := http.NewRequest(http.MethodPost, baseURL+"/conversations", bytes.NewReader(convBody))
		convReq.Header.Set("Authorization", "Bearer "+tokenC)
		convReq.Header.Set("Content-Type", "application/json")
		convResp, err := client.Do(convReq)
		require.NoError(t, err)
		convResp.Body.Close()
		require.Equal(t, http.StatusCreated, convResp.StatusCode)

		// Fetch activity
		actReq, _ := http.NewRequest(http.MethodGet, baseURL+"/projects/"+proj.ID+"/activity", nil)
		actReq.Header.Set("Authorization", "Bearer "+tokenC)
		actResp, err := client.Do(actReq)
		require.NoError(t, err)
		defer actResp.Body.Close()
		require.Equal(t, http.StatusOK, actResp.StatusCode)

		var actRespData projectActivityAPIResponse
		require.NoError(t, json.NewDecoder(actResp.Body).Decode(&actRespData))
		var found bool
		for _, item := range actRespData.Items {
			if item.Type == "conversation_added" {
				assert.Equal(t, phoneC, item.ActorLabel, "actor_label should be phone when display_name empty")
				found = true
				break
			}
		}
		assert.True(t, found, "conversation_added event should exist")
	})

	t.Run("P9_Activity_CompositeCursor_NoDuplicates", func(t *testing.T) {
		ts.TruncateAuth(t)
		token, userAID := loginAndGetTokenAndUserID(t, client, baseURL, "+499111111111")
		_, userBID := loginAndGetTokenAndUserID(t, client, baseURL, "+499122222222")
		_, userCID := loginAndGetTokenAndUserID(t, client, baseURL, "+499133333333")
		_, userDID := loginAndGetTokenAndUserID(t, client, baseURL, "+499144444444")

		// Create project via API (emits 1 project_created event)
		projBody, _ := json.Marshal(map[string]string{"name": "CursorTest"})
		projReq, _ := http.NewRequest(http.MethodPost, baseURL+"/projects", bytes.NewReader(projBody))
		projReq.Header.Set("Authorization", "Bearer "+token)
		projReq.Header.Set("Content-Type", "application/json")
		projResp, err := client.Do(projReq)
		require.NoError(t, err)
		var proj projectAPIResponse
		require.NoError(t, json.NewDecoder(projResp.Body).Decode(&proj))
		projResp.Body.Close()

		// Create 3 conversations in project with distinct member sets (emits 3 conversation_added events).
		// Distinct sets defeat the idempotency guard so each call creates a new conversation.
		ctx := context.Background()
		for _, memberID := range []string{userBID, userCID, userDID} {
			convBody, _ := json.Marshal(map[string]interface{}{
				"member_user_ids": []string{userAID, memberID},
				"project_id":      proj.ID,
			})
			convReq, _ := http.NewRequest(http.MethodPost, baseURL+"/conversations", bytes.NewReader(convBody))
			convReq.Header.Set("Authorization", "Bearer "+token)
			convReq.Header.Set("Content-Type", "application/json")
			convResp, err := client.Do(convReq)
			require.NoError(t, err)
			convResp.Body.Close()
			require.Equal(t, http.StatusCreated, convResp.StatusCode)
		}

		// Set same created_at for all 4 events to test composite cursor with duplicate timestamps
		var createdAt time.Time
		err = ts.DB.QueryRowContext(ctx, "SELECT created_at FROM project_events WHERE project_id = $1 ORDER BY created_at DESC, id DESC LIMIT 1", proj.ID).Scan(&createdAt)
		require.NoError(t, err)
		_, err = ts.DB.ExecContext(ctx, "UPDATE project_events SET created_at = $1 WHERE project_id = $2", createdAt, proj.ID)
		require.NoError(t, err)

		// Page1 (limit 2)
		actReq1, _ := http.NewRequest(http.MethodGet, baseURL+"/projects/"+proj.ID+"/activity?limit=2", nil)
		actReq1.Header.Set("Authorization", "Bearer "+token)
		resp1, err := client.Do(actReq1)
		require.NoError(t, err)
		defer resp1.Body.Close()
		require.Equal(t, http.StatusOK, resp1.StatusCode)
		var page1 projectActivityAPIResponse
		require.NoError(t, json.NewDecoder(resp1.Body).Decode(&page1))
		require.Len(t, page1.Items, 2, "page1 must have 2 items")
		require.True(t, page1.HasMore)
		require.NotNil(t, page1.NextCursor, "next_cursor must be set")
		assert.Contains(t, *page1.NextCursor, "|", "cursor must be composite format")

		// Page2 with next_cursor
		actReq2, _ := http.NewRequest(http.MethodGet, baseURL+"/projects/"+proj.ID+"/activity?limit=2&before="+url.QueryEscape(*page1.NextCursor), nil)
		actReq2.Header.Set("Authorization", "Bearer "+token)
		resp2, err := client.Do(actReq2)
		require.NoError(t, err)
		defer resp2.Body.Close()
		require.Equal(t, http.StatusOK, resp2.StatusCode)
		var page2 projectActivityAPIResponse
		require.NoError(t, json.NewDecoder(resp2.Body).Decode(&page2))
		require.Len(t, page2.Items, 2, "page2 must have 2 items")
		require.False(t, page2.HasMore, "no more pages")

		// No duplicates across pages
		seen := make(map[string]bool)
		for _, item := range page1.Items {
			assert.False(t, seen[item.ID], "duplicate in page1: %s", item.ID)
			seen[item.ID] = true
		}
		for _, item := range page2.Items {
			assert.False(t, seen[item.ID], "duplicate across pages: %s", item.ID)
			seen[item.ID] = true
		}
		assert.Len(t, seen, 4, "all 4 events returned exactly once")

		// Order strictly descending (created_at DESC, id DESC)
		allItems := append(page1.Items, page2.Items...)
		for i := 1; i < len(allItems); i++ {
			prev := allItems[i-1]
			curr := allItems[i]
			prevTime, _ := time.Parse(time.RFC3339, prev.Timestamp)
			currTime, _ := time.Parse(time.RFC3339, curr.Timestamp)
			assert.True(t, prevTime.After(currTime) || (prevTime.Equal(currTime) && prev.ID > curr.ID),
				"order must be strictly descending: prev=%s curr=%s", prev.ID, curr.ID)
		}
	})

	t.Run("P10_ProjectEvent_IdempotentInsert", func(t *testing.T) {
		ts.TruncateAuth(t)
		token, userAID := loginAndGetTokenAndUserID(t, client, baseURL, "+499211111111")
		_, userBID := loginAndGetTokenAndUserID(t, client, baseURL, "+499222222222")
		ctx := context.Background()
		projectEventRepo := repo.NewProjectEventRepo(ts.DB)

		// Create project via API (emits 1 project_created event)
		projBody, _ := json.Marshal(map[string]string{"name": "IdempotentTest"})
		projReq, _ := http.NewRequest(http.MethodPost, baseURL+"/projects", bytes.NewReader(projBody))
		projReq.Header.Set("Authorization", "Bearer "+token)
		projReq.Header.Set("Content-Type", "application/json")
		projResp, err := client.Do(projReq)
		require.NoError(t, err)
		var proj projectAPIResponse
		require.NoError(t, json.NewDecoder(projResp.Body).Decode(&proj))
		projResp.Body.Close()
		projectID, _ := uuid.Parse(proj.ID)
		ownerID, _ := uuid.Parse(userAID)

		// Add same project_created event again (simulate retry) - should succeed (idempotent)
		ev := project.NewProjectCreatedEvent("IdempotentTest")
		err = projectEventRepo.AddProjectEvent(ctx, projectID, ownerID, string(ev.EventType), ev.Version, ev.Payload)
		require.NoError(t, err)

		// Fetch activity - only 1 project_created event
		actReq, _ := http.NewRequest(http.MethodGet, baseURL+"/projects/"+proj.ID+"/activity", nil)
		actReq.Header.Set("Authorization", "Bearer "+token)
		actResp, err := client.Do(actReq)
		require.NoError(t, err)
		defer actResp.Body.Close()
		var act projectActivityAPIResponse
		require.NoError(t, json.NewDecoder(actResp.Body).Decode(&act))
		projectCreatedCount := 0
		for _, item := range act.Items {
			if item.Type == "project_created" {
				projectCreatedCount++
			}
		}
		assert.Equal(t, 1, projectCreatedCount, "only one project_created event must exist")

		// Create conversation in project
		convBody, _ := json.Marshal(map[string]interface{}{
			"member_user_ids": []string{userAID, userBID},
			"project_id":      proj.ID,
		})
		convReq, _ := http.NewRequest(http.MethodPost, baseURL+"/conversations", bytes.NewReader(convBody))
		convReq.Header.Set("Authorization", "Bearer "+token)
		convReq.Header.Set("Content-Type", "application/json")
		convResp, err := client.Do(convReq)
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, convResp.StatusCode)
		var convRespData struct {
			ID           string `json:"id"`
			DisplayTitle string `json:"display_title"`
		}
		require.NoError(t, json.NewDecoder(convResp.Body).Decode(&convRespData))
		convResp.Body.Close()

		// Add same conversation_added event again (simulate retry) - should succeed (idempotent)
		convID, _ := uuid.Parse(convRespData.ID)
		ev = project.NewConversationAddedEvent(convID, convRespData.DisplayTitle)
		err = projectEventRepo.AddProjectEvent(ctx, projectID, ownerID, string(ev.EventType), ev.Version, ev.Payload)
		require.NoError(t, err)

		// Fetch activity - only 1 conversation_added event
		actReq2, _ := http.NewRequest(http.MethodGet, baseURL+"/projects/"+proj.ID+"/activity", nil)
		actReq2.Header.Set("Authorization", "Bearer "+token)
		actResp2, err := client.Do(actReq2)
		require.NoError(t, err)
		defer actResp2.Body.Close()
		var act2 projectActivityAPIResponse
		require.NoError(t, json.NewDecoder(actResp2.Body).Decode(&act2))
		conversationAddedCount := 0
		for _, item := range act2.Items {
			if item.Type == "conversation_added" {
				conversationAddedCount++
			}
		}
		assert.Equal(t, 1, conversationAddedCount, "only one conversation_added event must exist")
	})

	t.Run("P11_EventVersion_UnknownVersionHandled", func(t *testing.T) {
		ts.TruncateAuth(t)
		token, userID := loginAndGetTokenAndUserID(t, client, baseURL, "+499311111111")
		ctx := context.Background()

		// Create project via API (emits 1 project_created v1)
		projBody, _ := json.Marshal(map[string]string{"name": "VersionTest"})
		projReq, _ := http.NewRequest(http.MethodPost, baseURL+"/projects", bytes.NewReader(projBody))
		projReq.Header.Set("Authorization", "Bearer "+token)
		projReq.Header.Set("Content-Type", "application/json")
		projResp, err := client.Do(projReq)
		require.NoError(t, err)
		var proj projectAPIResponse
		require.NoError(t, json.NewDecoder(projResp.Body).Decode(&proj))
		projResp.Body.Close()

		// Manually insert event with unknown version (project_created v99)
		payload := `{"name":"VersionTest"}`
		_, err = ts.DB.ExecContext(ctx, `INSERT INTO project_events (project_id, actor_user_id, event_type, version, payload)
			VALUES ($1, $2, 'project_created', 99, $3::jsonb)`, proj.ID, userID, payload)
		require.NoError(t, err)

		// Fetch activity - must not panic, activity loads normally
		actReq, _ := http.NewRequest(http.MethodGet, baseURL+"/projects/"+proj.ID+"/activity", nil)
		actReq.Header.Set("Authorization", "Bearer "+token)
		actResp, err := client.Do(actReq)
		require.NoError(t, err)
		defer actResp.Body.Close()
		require.Equal(t, http.StatusOK, actResp.StatusCode)

		var act projectActivityAPIResponse
		require.NoError(t, json.NewDecoder(actResp.Body).Decode(&act))
		require.NotEmpty(t, act.Items, "activity must return items")

		// Version-99 event must appear as unknownEvent (summary "Unknown activity")
		var foundUnknown bool
		for _, item := range act.Items {
			if item.Type == "project_created" && item.Summary == "Unknown activity" {
				foundUnknown = true
				break
			}
		}
		assert.True(t, foundUnknown, "unknown version event must be returned as unknownEvent (summary=Unknown activity)")
	})

	t.Run("P12_ProjectCreation_AtomicWithEvent", func(t *testing.T) {
		ts.TruncateAuth(t)
		token, userID := loginAndGetTokenAndUserID(t, client, baseURL, "+499411111111")
		ctx := context.Background()

		// Inject failure after project insert but before event insert
		ts.ProjectSvc.CreateProjectTestHook = func() error { return fmt.Errorf("injected failure") }
		defer func() { ts.ProjectSvc.CreateProjectTestHook = nil }()

		projBody, _ := json.Marshal(map[string]string{"name": "AtomicTest"})
		projReq, _ := http.NewRequest(http.MethodPost, baseURL+"/projects", bytes.NewReader(projBody))
		projReq.Header.Set("Authorization", "Bearer "+token)
		projReq.Header.Set("Content-Type", "application/json")
		projResp, err := client.Do(projReq)
		require.NoError(t, err)
		projResp.Body.Close()
		require.Equal(t, http.StatusInternalServerError, projResp.StatusCode)

		// No project row, no project_event row
		var projectCount int
		err = ts.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM projects WHERE owner_user_id::text = $1", userID).Scan(&projectCount)
		require.NoError(t, err)
		assert.Equal(t, 0, projectCount, "no project row must exist")

		var eventCount int
		err = ts.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM project_events").Scan(&eventCount)
		require.NoError(t, err)
		assert.Equal(t, 0, eventCount, "no project_event row must exist")
	})

	t.Run("P13_ConversationCreation_AtomicWithEvent", func(t *testing.T) {
		ts.TruncateAuth(t)
		token, userAID := loginAndGetTokenAndUserID(t, client, baseURL, "+499511111111")
		_, userBID := loginAndGetTokenAndUserID(t, client, baseURL, "+499522222222")
		ctx := context.Background()

		// Create project first (without hook)
		projBody, _ := json.Marshal(map[string]string{"name": "ConvAtomicTest"})
		projReq, _ := http.NewRequest(http.MethodPost, baseURL+"/projects", bytes.NewReader(projBody))
		projReq.Header.Set("Authorization", "Bearer "+token)
		projReq.Header.Set("Content-Type", "application/json")
		projResp, err := client.Do(projReq)
		require.NoError(t, err)
		var proj projectAPIResponse
		require.NoError(t, json.NewDecoder(projResp.Body).Decode(&proj))
		projResp.Body.Close()

		// Inject failure before AddProjectEvent
		ts.ChatSvc.CreateConversationTestHook = func() error { return fmt.Errorf("injected failure") }
		defer func() { ts.ChatSvc.CreateConversationTestHook = nil }()

		convBody, _ := json.Marshal(map[string]interface{}{
			"member_user_ids": []string{userAID, userBID},
			"project_id":      proj.ID,
		})
		convReq, _ := http.NewRequest(http.MethodPost, baseURL+"/conversations", bytes.NewReader(convBody))
		convReq.Header.Set("Authorization", "Bearer "+token)
		convReq.Header.Set("Content-Type", "application/json")
		convResp, err := client.Do(convReq)
		require.NoError(t, err)
		convResp.Body.Close()
		require.Equal(t, http.StatusInternalServerError, convResp.StatusCode)

		// Only 1 project_event (project_created), no conversation_added
		var eventCount int
		err = ts.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM project_events WHERE project_id = $1", proj.ID).Scan(&eventCount)
		require.NoError(t, err)
		assert.Equal(t, 1, eventCount, "only project_created event must exist, no conversation_added")

		// No new conversation in this project
		var convCount int
		err = ts.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM conversations WHERE project_id = $1", proj.ID).Scan(&convCount)
		require.NoError(t, err)
		assert.Equal(t, 0, convCount, "no conversation row must exist")
	})

	t.Run("P14_ProjectActivity_ForbiddenForNonOwner", func(t *testing.T) {
		ts.TruncateAuth(t)
		tokenA, _ := loginAndGetTokenAndUserID(t, client, baseURL, "+499611111111")
		tokenB, _ := loginAndGetTokenAndUserID(t, client, baseURL, "+499622222222")

		// User A creates project
		projBody, _ := json.Marshal(map[string]string{"name": "OwnerProject"})
		projReq, _ := http.NewRequest(http.MethodPost, baseURL+"/projects", bytes.NewReader(projBody))
		projReq.Header.Set("Authorization", "Bearer "+tokenA)
		projReq.Header.Set("Content-Type", "application/json")
		projResp, err := client.Do(projReq)
		require.NoError(t, err)
		var proj projectAPIResponse
		require.NoError(t, json.NewDecoder(projResp.Body).Decode(&proj))
		projResp.Body.Close()

		// User B calls GET /projects/:id/activity - expect 403
		actReq, _ := http.NewRequest(http.MethodGet, baseURL+"/projects/"+proj.ID+"/activity", nil)
		actReq.Header.Set("Authorization", "Bearer "+tokenB)
		actResp, err := client.Do(actReq)
		require.NoError(t, err)
		defer actResp.Body.Close()
		assert.Equal(t, http.StatusForbidden, actResp.StatusCode)
	})

	t.Run("P15_ProjectActivity_OwnerAccessWorks", func(t *testing.T) {
		ts.TruncateAuth(t)
		token, _ := loginAndGetTokenAndUserID(t, client, baseURL, "+499711111111")

		// Create project (emits project_created event)
		projBody, _ := json.Marshal(map[string]string{"name": "OwnerAccessTest"})
		projReq, _ := http.NewRequest(http.MethodPost, baseURL+"/projects", bytes.NewReader(projBody))
		projReq.Header.Set("Authorization", "Bearer "+token)
		projReq.Header.Set("Content-Type", "application/json")
		projResp, err := client.Do(projReq)
		require.NoError(t, err)
		var proj projectAPIResponse
		require.NoError(t, json.NewDecoder(projResp.Body).Decode(&proj))
		projResp.Body.Close()

		// Owner calls GET /projects/:id/activity - expect 200
		actReq, _ := http.NewRequest(http.MethodGet, baseURL+"/projects/"+proj.ID+"/activity", nil)
		actReq.Header.Set("Authorization", "Bearer "+token)
		actResp, err := client.Do(actReq)
		require.NoError(t, err)
		defer actResp.Body.Close()
		require.Equal(t, http.StatusOK, actResp.StatusCode)

		var act projectActivityAPIResponse
		require.NoError(t, json.NewDecoder(actResp.Body).Decode(&act))
		require.Len(t, act.Items, 1)
		assert.Equal(t, "project_created", act.Items[0].Type)
		assert.Equal(t, "Project created: OwnerAccessTest", act.Items[0].Summary)
	})

	t.Run("P16_ProjectArchived_PreventsConversation", func(t *testing.T) {
		ts.TruncateAuth(t)
		token, userAID := loginAndGetTokenAndUserID(t, client, baseURL, "+499811111111")
		_, userBID := loginAndGetTokenAndUserID(t, client, baseURL, "+499822222222")
		ctx := context.Background()

		// Create project
		projBody, _ := json.Marshal(map[string]string{"name": "ArchiveTest"})
		projReq, _ := http.NewRequest(http.MethodPost, baseURL+"/projects", bytes.NewReader(projBody))
		projReq.Header.Set("Authorization", "Bearer "+token)
		projReq.Header.Set("Content-Type", "application/json")
		projResp, err := client.Do(projReq)
		require.NoError(t, err)
		var proj projectAPIResponse
		require.NoError(t, json.NewDecoder(projResp.Body).Decode(&proj))
		projResp.Body.Close()

		// Archive project
		delReq, _ := http.NewRequest(http.MethodDelete, baseURL+"/projects/"+proj.ID, nil)
		delReq.Header.Set("Authorization", "Bearer "+token)
		delResp, err := client.Do(delReq)
		require.NoError(t, err)
		delResp.Body.Close()
		require.Equal(t, http.StatusNoContent, delResp.StatusCode)

		// Try to create conversation in archived project - expect 409
		convBody, _ := json.Marshal(map[string]interface{}{
			"member_user_ids": []string{userAID, userBID},
			"project_id":      proj.ID,
		})
		convReq, _ := http.NewRequest(http.MethodPost, baseURL+"/conversations", bytes.NewReader(convBody))
		convReq.Header.Set("Authorization", "Bearer "+token)
		convReq.Header.Set("Content-Type", "application/json")
		convResp, err := client.Do(convReq)
		require.NoError(t, err)
		convResp.Body.Close()
		require.Equal(t, http.StatusConflict, convResp.StatusCode)

		// No conversation row, no new event (only project_created + project_archived)
		var convCount int
		err = ts.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM conversations WHERE project_id = $1", proj.ID).Scan(&convCount)
		require.NoError(t, err)
		assert.Equal(t, 0, convCount, "no conversation row must exist")

		var eventCount int
		err = ts.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM project_events WHERE project_id = $1", proj.ID).Scan(&eventCount)
		require.NoError(t, err)
		assert.Equal(t, 2, eventCount, "only project_created and project_archived, no conversation_added")
	})

	t.Run("P17_ProjectArchived_ActivityStillVisible", func(t *testing.T) {
		ts.TruncateAuth(t)
		token, _ := loginAndGetTokenAndUserID(t, client, baseURL, "+499911111111")

		// Create project
		projBody, _ := json.Marshal(map[string]string{"name": "ActivityArchivedTest"})
		projReq, _ := http.NewRequest(http.MethodPost, baseURL+"/projects", bytes.NewReader(projBody))
		projReq.Header.Set("Authorization", "Bearer "+token)
		projReq.Header.Set("Content-Type", "application/json")
		projResp, err := client.Do(projReq)
		require.NoError(t, err)
		var proj projectAPIResponse
		require.NoError(t, json.NewDecoder(projResp.Body).Decode(&proj))
		projResp.Body.Close()

		// Archive project
		delReq, _ := http.NewRequest(http.MethodDelete, baseURL+"/projects/"+proj.ID, nil)
		delReq.Header.Set("Authorization", "Bearer "+token)
		delResp, err := client.Do(delReq)
		require.NoError(t, err)
		delResp.Body.Close()
		require.Equal(t, http.StatusNoContent, delResp.StatusCode)

		// Owner calls GET /projects/:id/activity - expect 200
		actReq, _ := http.NewRequest(http.MethodGet, baseURL+"/projects/"+proj.ID+"/activity", nil)
		actReq.Header.Set("Authorization", "Bearer "+token)
		actResp, err := client.Do(actReq)
		require.NoError(t, err)
		defer actResp.Body.Close()
		require.Equal(t, http.StatusOK, actResp.StatusCode)

		var act projectActivityAPIResponse
		require.NoError(t, json.NewDecoder(actResp.Body).Decode(&act))
		require.Len(t, act.Items, 2, "activity must contain project_created and project_archived")

		types := []string{act.Items[0].Type, act.Items[1].Type}
		assert.Contains(t, types, "project_created")
		assert.Contains(t, types, "project_archived")
	})

	t.Run("P20_ProjectEvent_FactoryEnforced", func(t *testing.T) {
		ts.TruncateAuth(t)
		token, userID := loginAndGetTokenAndUserID(t, client, baseURL, "+499911111114")

		// CreateProject uses factory - project_created event must be recorded
		projBody, _ := json.Marshal(map[string]string{"name": "FactoryTest"})
		projReq, _ := http.NewRequest(http.MethodPost, baseURL+"/projects", bytes.NewReader(projBody))
		projReq.Header.Set("Authorization", "Bearer "+token)
		projReq.Header.Set("Content-Type", "application/json")
		projResp, err := client.Do(projReq)
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, projResp.StatusCode)
		var proj projectAPIResponse
		require.NoError(t, json.NewDecoder(projResp.Body).Decode(&proj))
		projResp.Body.Close()

		actReq, _ := http.NewRequest(http.MethodGet, baseURL+"/projects/"+proj.ID+"/activity", nil)
		actReq.Header.Set("Authorization", "Bearer "+token)
		actResp, err := client.Do(actReq)
		require.NoError(t, err)
		defer actResp.Body.Close()
		var act projectActivityAPIResponse
		require.NoError(t, json.NewDecoder(actResp.Body).Decode(&act))
		require.NotEmpty(t, act.Items)
		assert.Equal(t, "project_created", act.Items[0].Type)
		assert.Contains(t, act.Items[0].Summary, "FactoryTest")

		// ArchiveProject uses factory - project_archived event must be recorded
		archiveReq, _ := http.NewRequest(http.MethodPost, baseURL+"/projects/"+proj.ID+"/archive", nil)
		archiveReq.Header.Set("Authorization", "Bearer "+token)
		archiveResp, err := client.Do(archiveReq)
		require.NoError(t, err)
		require.Equal(t, http.StatusNoContent, archiveResp.StatusCode)

		actReq2, _ := http.NewRequest(http.MethodGet, baseURL+"/projects/"+proj.ID+"/activity", nil)
		actReq2.Header.Set("Authorization", "Bearer "+token)
		actResp2, err := client.Do(actReq2)
		require.NoError(t, err)
		defer actResp2.Body.Close()
		var act2 projectActivityAPIResponse
		require.NoError(t, json.NewDecoder(actResp2.Body).Decode(&act2))
		var types []string
		for _, item := range act2.Items {
			types = append(types, item.Type)
		}
		assert.Contains(t, types, "project_created")
		assert.Contains(t, types, "project_archived")

		// CreateConversation uses factory - create project first (unarchive not possible), new project for conv
		proj2Body, _ := json.Marshal(map[string]string{"name": "FactoryConvTest"})
		proj2Req, _ := http.NewRequest(http.MethodPost, baseURL+"/projects", bytes.NewReader(proj2Body))
		proj2Req.Header.Set("Authorization", "Bearer "+token)
		proj2Req.Header.Set("Content-Type", "application/json")
		proj2Resp, err := client.Do(proj2Req)
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, proj2Resp.StatusCode)
		var proj2 projectAPIResponse
		require.NoError(t, json.NewDecoder(proj2Resp.Body).Decode(&proj2))
		proj2Resp.Body.Close()

		_, userBID := loginAndGetTokenAndUserID(t, client, baseURL, "+499911111115")
		convBody, _ := json.Marshal(map[string]interface{}{
			"member_user_ids": []string{userID, userBID},
			"project_id":      proj2.ID,
		})
		convReq, _ := http.NewRequest(http.MethodPost, baseURL+"/conversations", bytes.NewReader(convBody))
		convReq.Header.Set("Authorization", "Bearer "+token)
		convReq.Header.Set("Content-Type", "application/json")
		convResp, err := client.Do(convReq)
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, convResp.StatusCode)

		actReq3, _ := http.NewRequest(http.MethodGet, baseURL+"/projects/"+proj2.ID+"/activity", nil)
		actReq3.Header.Set("Authorization", "Bearer "+token)
		actResp3, err := client.Do(actReq3)
		require.NoError(t, err)
		defer actResp3.Body.Close()
		var act3 projectActivityAPIResponse
		require.NoError(t, json.NewDecoder(actResp3.Body).Decode(&act3))
		var foundConvAdded bool
		for _, item := range act3.Items {
			if item.Type == "conversation_added" {
				foundConvAdded = true
				break
			}
		}
		assert.True(t, foundConvAdded, "conversation_added event must exist via factory")

		// No external path can inject custom type/version - AddProjectEvent is unexported
		// Only constructors (NewProjectCreatedEvent, NewProjectArchivedEvent, NewConversationAddedEvent) produce valid events
	})

	t.Run("P21_ProjectEvent_PayloadTyped", func(t *testing.T) {
		ts.TruncateAuth(t)
		token, userID := loginAndGetTokenAndUserID(t, client, baseURL, "+499911111116")
		_, userBID := loginAndGetTokenAndUserID(t, client, baseURL, "+499911111117")

		// Create project - payload is ProjectCreatedPayload{Name: "TypedPayloadTest"}
		projBody, _ := json.Marshal(map[string]string{"name": "TypedPayloadTest"})
		projReq, _ := http.NewRequest(http.MethodPost, baseURL+"/projects", bytes.NewReader(projBody))
		projReq.Header.Set("Authorization", "Bearer "+token)
		projReq.Header.Set("Content-Type", "application/json")
		projResp, err := client.Do(projReq)
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, projResp.StatusCode)
		var proj projectAPIResponse
		require.NoError(t, json.NewDecoder(projResp.Body).Decode(&proj))
		projResp.Body.Close()

		// Fetch activity - decoder unmarshals into ProjectCreatedPayload, Summary uses Payload.Name
		actReq, _ := http.NewRequest(http.MethodGet, baseURL+"/projects/"+proj.ID+"/activity", nil)
		actReq.Header.Set("Authorization", "Bearer "+token)
		actResp, err := client.Do(actReq)
		require.NoError(t, err)
		defer actResp.Body.Close()
		var act projectActivityAPIResponse
		require.NoError(t, json.NewDecoder(actResp.Body).Decode(&act))
		require.NotEmpty(t, act.Items)
		require.Equal(t, "project_created", act.Items[0].Type)
		assert.Equal(t, "Project created: TypedPayloadTest", act.Items[0].Summary, "decoded payload must be ProjectCreatedPayload.Name, not generic map")

		// Archive - payload is ProjectArchivedPayload{}
		archiveReq, _ := http.NewRequest(http.MethodPost, baseURL+"/projects/"+proj.ID+"/archive", nil)
		archiveReq.Header.Set("Authorization", "Bearer "+token)
		archiveResp, err := client.Do(archiveReq)
		require.NoError(t, err)
		require.Equal(t, http.StatusNoContent, archiveResp.StatusCode)

		actReq2, _ := http.NewRequest(http.MethodGet, baseURL+"/projects/"+proj.ID+"/activity", nil)
		actReq2.Header.Set("Authorization", "Bearer "+token)
		actResp2, err := client.Do(actReq2)
		require.NoError(t, err)
		defer actResp2.Body.Close()
		var act2 projectActivityAPIResponse
		require.NoError(t, json.NewDecoder(actResp2.Body).Decode(&act2))
		var foundArchived bool
		for _, item := range act2.Items {
			if item.Type == "project_archived" && item.Summary == "Project archived" {
				foundArchived = true
				break
			}
		}
		assert.True(t, foundArchived, "project_archived must decode via ProjectArchivedPayload (typed struct, not map)")

		// Create conversation - payload is ConversationAddedPayload{ConversationID, DisplayTitle}
		// Need unarchived project - create new one (proj was archived)
		proj2Body, _ := json.Marshal(map[string]string{"name": "ConvPayloadTest"})
		proj2Req, _ := http.NewRequest(http.MethodPost, baseURL+"/projects", bytes.NewReader(proj2Body))
		proj2Req.Header.Set("Authorization", "Bearer "+token)
		proj2Req.Header.Set("Content-Type", "application/json")
		proj2Resp, err := client.Do(proj2Req)
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, proj2Resp.StatusCode)
		var proj2 projectAPIResponse
		require.NoError(t, json.NewDecoder(proj2Resp.Body).Decode(&proj2))
		proj2Resp.Body.Close()

		convBody2, _ := json.Marshal(map[string]interface{}{
			"member_user_ids": []string{userID, userBID},
			"project_id":      proj2.ID,
		})
		convReq, _ := http.NewRequest(http.MethodPost, baseURL+"/conversations", bytes.NewReader(convBody2))
		convReq.Header.Set("Authorization", "Bearer "+token)
		convReq.Header.Set("Content-Type", "application/json")
		convResp, err := client.Do(convReq)
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, convResp.StatusCode)
		var convData struct {
			ID           string `json:"id"`
			DisplayTitle string `json:"display_title"`
		}
		require.NoError(t, json.NewDecoder(convResp.Body).Decode(&convData))
		convResp.Body.Close()

		actReq3, _ := http.NewRequest(http.MethodGet, baseURL+"/projects/"+proj2.ID+"/activity", nil)
		actReq3.Header.Set("Authorization", "Bearer "+token)
		actResp3, err := client.Do(actReq3)
		require.NoError(t, err)
		defer actResp3.Body.Close()
		var act3 projectActivityAPIResponse
		require.NoError(t, json.NewDecoder(actResp3.Body).Decode(&act3))
		var foundConvAdded bool
		for _, item := range act3.Items {
			if item.Type == "conversation_added" {
				foundConvAdded = true
				assert.Contains(t, item.Summary, convData.DisplayTitle, "decoded payload must be ConversationAddedPayload.DisplayTitle, not generic map")
				break
			}
		}
		assert.True(t, foundConvAdded, "conversation_added must decode via ConversationAddedPayload")
	})

	t.Run("P22_ProjectEvent_CreatedAtMonotonic", func(t *testing.T) {
		ts.TruncateAuth(t)
		token, userID := loginAndGetTokenAndUserID(t, client, baseURL, "+499911111118")
		_, userBID := loginAndGetTokenAndUserID(t, client, baseURL, "+499911111119")

		// 1. Insert project_created (via CreateProject)
		projBody, _ := json.Marshal(map[string]string{"name": "MonotonicTest"})
		projReq, _ := http.NewRequest(http.MethodPost, baseURL+"/projects", bytes.NewReader(projBody))
		projReq.Header.Set("Authorization", "Bearer "+token)
		projReq.Header.Set("Content-Type", "application/json")
		projResp, err := client.Do(projReq)
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, projResp.StatusCode)
		var proj projectAPIResponse
		require.NoError(t, json.NewDecoder(projResp.Body).Decode(&proj))
		projResp.Body.Close()

		// 2. Insert conversation_added (via CreateConversation)
		convBody, _ := json.Marshal(map[string]interface{}{
			"member_user_ids": []string{userID, userBID},
			"project_id":      proj.ID,
		})
		convReq, _ := http.NewRequest(http.MethodPost, baseURL+"/conversations", bytes.NewReader(convBody))
		convReq.Header.Set("Authorization", "Bearer "+token)
		convReq.Header.Set("Content-Type", "application/json")
		convResp, err := client.Do(convReq)
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, convResp.StatusCode)
		convResp.Body.Close()

		// 3. Insert project_archived (via ArchiveProject)
		archiveReq, _ := http.NewRequest(http.MethodPost, baseURL+"/projects/"+proj.ID+"/archive", nil)
		archiveReq.Header.Set("Authorization", "Bearer "+token)
		archiveResp, err := client.Do(archiveReq)
		require.NoError(t, err)
		require.Equal(t, http.StatusNoContent, archiveResp.StatusCode)

		// 4. Load activity - ORDER BY created_at DESC, id DESC
		actReq, _ := http.NewRequest(http.MethodGet, baseURL+"/projects/"+proj.ID+"/activity", nil)
		actReq.Header.Set("Authorization", "Bearer "+token)
		actResp, err := client.Do(actReq)
		require.NoError(t, err)
		defer actResp.Body.Close()
		var act projectActivityAPIResponse
		require.NoError(t, json.NewDecoder(actResp.Body).Decode(&act))
		require.Len(t, act.Items, 3, "must have project_created, conversation_added, project_archived")

		// Logical order: project_created < conversation_added < project_archived
		// DESC order: project_archived, conversation_added, project_created
		assert.Equal(t, "project_archived", act.Items[0].Type, "newest must be project_archived")
		assert.Equal(t, "conversation_added", act.Items[1].Type, "middle must be conversation_added")
		assert.Equal(t, "project_created", act.Items[2].Type, "oldest must be project_created")

		// Assert strict DESC ordering: created_at DESC, id DESC
		for i := 1; i < len(act.Items); i++ {
			prev := act.Items[i-1]
			curr := act.Items[i]
			prevTime, err := time.Parse(time.RFC3339, prev.Timestamp)
			require.NoError(t, err)
			currTime, err := time.Parse(time.RFC3339, curr.Timestamp)
			require.NoError(t, err)
			assert.True(t, prevTime.After(currTime) || (prevTime.Equal(currTime) && prev.ID > curr.ID),
				"order must be strictly descending: prev=%s curr=%s", prev.ID, curr.ID)
		}
	})

	t.Run("P23_ProjectArchive_Idempotent", func(t *testing.T) {
		ts.TruncateAuth(t)
		token := loginAndGetToken(t, client, baseURL, "+499911111120")
		ctx := context.Background()

		// Create project
		projBody, _ := json.Marshal(map[string]string{"name": "ArchiveIdempotentTest"})
		projReq, _ := http.NewRequest(http.MethodPost, baseURL+"/projects", bytes.NewReader(projBody))
		projReq.Header.Set("Authorization", "Bearer "+token)
		projReq.Header.Set("Content-Type", "application/json")
		projResp, err := client.Do(projReq)
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, projResp.StatusCode)
		var proj projectAPIResponse
		require.NoError(t, json.NewDecoder(projResp.Body).Decode(&proj))
		projResp.Body.Close()

		// Archive project
		archiveReq1, _ := http.NewRequest(http.MethodPost, baseURL+"/projects/"+proj.ID+"/archive", nil)
		archiveReq1.Header.Set("Authorization", "Bearer "+token)
		archiveResp1, err := client.Do(archiveReq1)
		require.NoError(t, err)
		require.Equal(t, http.StatusNoContent, archiveResp1.StatusCode)

		// Archive project again - idempotent, no error
		archiveReq2, _ := http.NewRequest(http.MethodPost, baseURL+"/projects/"+proj.ID+"/archive", nil)
		archiveReq2.Header.Set("Authorization", "Bearer "+token)
		archiveResp2, err := client.Do(archiveReq2)
		require.NoError(t, err)
		require.Equal(t, http.StatusNoContent, archiveResp2.StatusCode)

		// Only 1 project_archived event
		var eventCount int
		err = ts.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM project_events WHERE project_id = $1 AND event_type = 'project_archived'", proj.ID).Scan(&eventCount)
		require.NoError(t, err)
		assert.Equal(t, 1, eventCount, "only one project_archived event must exist")
	})

	t.Run("P24_CreateConversation_Idempotent", func(t *testing.T) {
		ts.TruncateAuth(t)
		token, userAID := loginAndGetTokenAndUserID(t, client, baseURL, "+499911111121")
		_, userBID := loginAndGetTokenAndUserID(t, client, baseURL, "+499911111122")
		ctx := context.Background()

		// Create project
		projBody, _ := json.Marshal(map[string]string{"name": "ConvIdempotentTest"})
		projReq, _ := http.NewRequest(http.MethodPost, baseURL+"/projects", bytes.NewReader(projBody))
		projReq.Header.Set("Authorization", "Bearer "+token)
		projReq.Header.Set("Content-Type", "application/json")
		projResp, err := client.Do(projReq)
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, projResp.StatusCode)
		var proj projectAPIResponse
		require.NoError(t, json.NewDecoder(projResp.Body).Decode(&proj))
		projResp.Body.Close()

		// Create conversation
		convBody, _ := json.Marshal(map[string]interface{}{
			"member_user_ids": []string{userAID, userBID},
			"project_id":      proj.ID,
		})
		convReq1, _ := http.NewRequest(http.MethodPost, baseURL+"/conversations", bytes.NewReader(convBody))
		convReq1.Header.Set("Authorization", "Bearer "+token)
		convReq1.Header.Set("Content-Type", "application/json")
		convResp1, err := client.Do(convReq1)
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, convResp1.StatusCode)
		var conv1 struct {
			ID string `json:"id"`
		}
		require.NoError(t, json.NewDecoder(convResp1.Body).Decode(&conv1))
		convResp1.Body.Close()

		// Create same conversation again - idempotent, returns existing
		convReq2, _ := http.NewRequest(http.MethodPost, baseURL+"/conversations", bytes.NewReader(convBody))
		convReq2.Header.Set("Authorization", "Bearer "+token)
		convReq2.Header.Set("Content-Type", "application/json")
		convResp2, err := client.Do(convReq2)
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, convResp2.StatusCode)
		var conv2 struct {
			ID string `json:"id"`
		}
		require.NoError(t, json.NewDecoder(convResp2.Body).Decode(&conv2))
		convResp2.Body.Close()

		assert.Equal(t, conv1.ID, conv2.ID, "same conversation must be returned")

		// No duplicate conversation row
		var convCount int
		err = ts.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM conversations WHERE project_id = $1", proj.ID).Scan(&convCount)
		require.NoError(t, err)
		assert.Equal(t, 1, convCount, "only one conversation row must exist")

		// Only 1 conversation_added event
		var eventCount int
		err = ts.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM project_events WHERE project_id = $1 AND event_type = 'conversation_added'", proj.ID).Scan(&eventCount)
		require.NoError(t, err)
		assert.Equal(t, 1, eventCount, "only one conversation_added event must exist")
	})

	t.Run("P25_ProjectEvent_ActorSnapshotImmutable", func(t *testing.T) {
		ts.TruncateAuth(t)
		token := loginAndGetToken(t, client, baseURL, "+499911111123")

		// User A sets display_name = "Alice"
		patchBody, _ := json.Marshal(map[string]string{"display_name": "Alice"})
		patchReq, _ := http.NewRequest(http.MethodPatch, baseURL+"/me", bytes.NewReader(patchBody))
		patchReq.Header.Set("Authorization", "Bearer "+token)
		patchReq.Header.Set("Content-Type", "application/json")
		patchResp, err := client.Do(patchReq)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, patchResp.StatusCode)
		patchResp.Body.Close()

		// Create project (emits project_created with actor snapshot "Alice")
		projBody, _ := json.Marshal(map[string]string{"name": "ActorSnapshotTest"})
		projReq, _ := http.NewRequest(http.MethodPost, baseURL+"/projects", bytes.NewReader(projBody))
		projReq.Header.Set("Authorization", "Bearer "+token)
		projReq.Header.Set("Content-Type", "application/json")
		projResp, err := client.Do(projReq)
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, projResp.StatusCode)
		var proj projectAPIResponse
		require.NoError(t, json.NewDecoder(projResp.Body).Decode(&proj))
		projResp.Body.Close()

		// Change display_name to "Alice2"
		patchBody2, _ := json.Marshal(map[string]string{"display_name": "Alice2"})
		patchReq2, _ := http.NewRequest(http.MethodPatch, baseURL+"/me", bytes.NewReader(patchBody2))
		patchReq2.Header.Set("Authorization", "Bearer "+token)
		patchReq2.Header.Set("Content-Type", "application/json")
		patchResp2, err := client.Do(patchReq2)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, patchResp2.StatusCode)
		patchResp2.Body.Close()

		// Load activity - must show "Alice" from immutable snapshot, not "Alice2"
		actReq, _ := http.NewRequest(http.MethodGet, baseURL+"/projects/"+proj.ID+"/activity", nil)
		actReq.Header.Set("Authorization", "Bearer "+token)
		actResp, err := client.Do(actReq)
		require.NoError(t, err)
		defer actResp.Body.Close()
		var act projectActivityAPIResponse
		require.NoError(t, json.NewDecoder(actResp.Body).Decode(&act))
		require.NotEmpty(t, act.Items)
		assert.Equal(t, "Alice", act.Items[0].ActorLabel, "actor_label must be immutable snapshot (Alice), not live (Alice2)")
	})

	t.Run("P26_ProjectEvent_ForwardCompatible", func(t *testing.T) {
		ts.TruncateAuth(t)
		_, userID := loginAndGetTokenAndUserID(t, client, baseURL, "+499911111124")
		ctx := context.Background()

		// Insert project_created v1 event (minimal payload: name only)
		projectID := uuid.MustParse("a0000000-0000-0000-0000-000000000001")
		_, err := ts.DB.ExecContext(ctx, `
			INSERT INTO projects (id, owner_user_id, name) VALUES ($1, $2, 'CompatProject')
		`, projectID, userID)
		require.NoError(t, err)
		payload := `{"name": "CompatTest"}`
		_, err = ts.DB.ExecContext(ctx, `
			INSERT INTO project_events (project_id, actor_user_id, event_type, version, payload)
			VALUES ($1, $2, 'project_created', 1, $3::jsonb)
		`, projectID, userID, payload)
		require.NoError(t, err)

		// Simulate evolved struct with extra field (forward compat: missing JSON fields -> zero-values)
		type projectCreatedPayloadFuture struct {
			Name        string `json:"name"`
			Description string `json:"description"` // future field not in stored payload
		}
		var rawPayload []byte
		err = ts.DB.QueryRowContext(ctx, "SELECT payload FROM project_events WHERE event_type = 'project_created' AND project_id = $1 LIMIT 1", projectID).Scan(&rawPayload)
		require.NoError(t, err)
		var pFuture projectCreatedPayloadFuture
		err = json.Unmarshal(rawPayload, &pFuture)
		require.NoError(t, err)
		assert.Equal(t, "CompatTest", pFuture.Name, "old field must be correct")
		assert.Equal(t, "", pFuture.Description, "extra field must be zero when missing from JSON")

		// Decode via DecodeProjectEvent
		var modelEvent model.ProjectEvent
		var idStr, projStr, actorStr string
		var pl []byte
		err = ts.DB.QueryRowContext(ctx, `SELECT id, project_id, actor_user_id, event_type, version, payload, created_at FROM project_events WHERE event_type = 'project_created' AND project_id = $1 LIMIT 1`, projectID).Scan(&idStr, &projStr, &actorStr, &modelEvent.EventType, &modelEvent.Version, &pl, &modelEvent.CreatedAt)
		require.NoError(t, err)
		modelEvent.ID = uuid.MustParse(idStr)
		modelEvent.ProjectID = uuid.MustParse(projStr)
		modelEvent.ActorUserID = uuid.MustParse(actorStr)
		modelEvent.Payload = pl
		ev, err := project.DecodeProjectEvent(modelEvent)
		require.NoError(t, err)
		require.NotNil(t, ev)
		assert.Equal(t, project.ProjectCreated, ev.Type())
		assert.Equal(t, 1, ev.Version())
		assert.Equal(t, "Project created: CompatTest", ev.Summary())
	})

	t.Run("P27_ProjectEvent_UnknownVersionLogged", func(t *testing.T) {
		ts.TruncateAuth(t)
		token, userID := loginAndGetTokenAndUserID(t, client, baseURL, "+499911111125")
		ctx := context.Background()

		// Mock observer that records OnUnknownEvent calls
		var observerCallCount int
		var observerMu sync.Mutex
		mockObserver := &mockUnknownEventObserver{
			onUnknownEvent: func(eventType string, version int) {
				observerMu.Lock()
				observerCallCount++
				observerMu.Unlock()
			},
		}
		project.SetUnknownEventObserver(mockObserver)
		defer project.SetUnknownEventObserver(nil)

		// Create project (emits project_created v1)
		projBody, _ := json.Marshal(map[string]string{"name": "UnknownVersionTest"})
		projReq, _ := http.NewRequest(http.MethodPost, baseURL+"/projects", bytes.NewReader(projBody))
		projReq.Header.Set("Authorization", "Bearer "+token)
		projReq.Header.Set("Content-Type", "application/json")
		projResp, err := client.Do(projReq)
		require.NoError(t, err)
		var proj projectAPIResponse
		require.NoError(t, json.NewDecoder(projResp.Body).Decode(&proj))
		projResp.Body.Close()

		// Insert event with valid type but version 99
		payload := `{"name":"UnknownVersionTest"}`
		_, err = ts.DB.ExecContext(ctx, `INSERT INTO project_events (project_id, actor_user_id, event_type, version, payload)
			VALUES ($1, $2, 'project_created', 99, $3::jsonb)`, proj.ID, userID, payload)
		require.NoError(t, err)

		// Load activity
		actReq, _ := http.NewRequest(http.MethodGet, baseURL+"/projects/"+proj.ID+"/activity", nil)
		actReq.Header.Set("Authorization", "Bearer "+token)
		actResp, err := client.Do(actReq)
		require.NoError(t, err)
		defer actResp.Body.Close()
		require.Equal(t, http.StatusOK, actResp.StatusCode)

		var act projectActivityAPIResponse
		require.NoError(t, json.NewDecoder(actResp.Body).Decode(&act))
		require.NotEmpty(t, act.Items)

		// Unknown activity present
		var foundUnknown bool
		for _, item := range act.Items {
			if item.Type == "project_created" && item.Summary == "Unknown activity" {
				foundUnknown = true
				break
			}
		}
		assert.True(t, foundUnknown, "unknown version event must appear as Unknown activity")

		// Observer triggered exactly once
		observerMu.Lock()
		n := observerCallCount
		observerMu.Unlock()
		assert.Equal(t, 1, n, "observer must be triggered exactly once")
	})

	t.Run("P28_ProjectEvent_PayloadTamperDetected", func(t *testing.T) {
		ts.TruncateAuth(t)
		token, _ := loginAndGetTokenAndUserID(t, client, baseURL, "+499911111126")
		ctx := context.Background()

		// Mock observer
		var observerCallCount int
		var observerMu sync.Mutex
		mockObserver := &mockUnknownEventObserver{
			onUnknownEvent: func(eventType string, version int) {
				observerMu.Lock()
				observerCallCount++
				observerMu.Unlock()
			},
		}
		project.SetUnknownEventObserver(mockObserver)
		defer project.SetUnknownEventObserver(nil)

		// Insert valid event via API (create project)
		projBody, _ := json.Marshal(map[string]string{"name": "TamperTest"})
		projReq, _ := http.NewRequest(http.MethodPost, baseURL+"/projects", bytes.NewReader(projBody))
		projReq.Header.Set("Authorization", "Bearer "+token)
		projReq.Header.Set("Content-Type", "application/json")
		projResp, err := client.Do(projReq)
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, projResp.StatusCode)
		var proj projectAPIResponse
		require.NoError(t, json.NewDecoder(projResp.Body).Decode(&proj))
		projResp.Body.Close()

		// Update payload directly in DB (tamper - hash no longer matches)
		_, err = ts.DB.ExecContext(ctx, `UPDATE project_events SET payload = '{"name":"Tampered"}'::jsonb WHERE project_id = $1 AND event_type = 'project_created'`, proj.ID)
		require.NoError(t, err)

		// Load activity
		actReq, _ := http.NewRequest(http.MethodGet, baseURL+"/projects/"+proj.ID+"/activity", nil)
		actReq.Header.Set("Authorization", "Bearer "+token)
		actResp, err := client.Do(actReq)
		require.NoError(t, err)
		defer actResp.Body.Close()
		require.Equal(t, http.StatusOK, actResp.StatusCode)

		var act projectActivityAPIResponse
		require.NoError(t, json.NewDecoder(actResp.Body).Decode(&act))
		require.NotEmpty(t, act.Items)

		// Unknown activity present (tampered event decoded as unknown)
		var foundUnknown bool
		for _, item := range act.Items {
			if item.Type == "project_created" && item.Summary == "Unknown activity" {
				foundUnknown = true
				break
			}
		}
		assert.True(t, foundUnknown, "tampered event must appear as Unknown activity")

		// Observer triggered
		observerMu.Lock()
		n := observerCallCount
		observerMu.Unlock()
		assert.Equal(t, 1, n, "observer must be triggered")
	})

	t.Run("P29_ProjectEvent_ReplayDeterministic", func(t *testing.T) {
		ts.TruncateAuth(t)
		token, userID := loginAndGetTokenAndUserID(t, client, baseURL, "+499911111127")
		_, userBID := loginAndGetTokenAndUserID(t, client, baseURL, "+499911111128")
		ctx := context.Background()

		// 1. Create project
		projBody, _ := json.Marshal(map[string]string{"name": "ReplayTest"})
		projReq, _ := http.NewRequest(http.MethodPost, baseURL+"/projects", bytes.NewReader(projBody))
		projReq.Header.Set("Authorization", "Bearer "+token)
		projReq.Header.Set("Content-Type", "application/json")
		projResp, err := client.Do(projReq)
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, projResp.StatusCode)
		var proj projectAPIResponse
		require.NoError(t, json.NewDecoder(projResp.Body).Decode(&proj))
		projResp.Body.Close()

		// 2. Add conversation
		convBody, _ := json.Marshal(map[string]interface{}{
			"member_user_ids": []string{userID, userBID},
			"project_id":      proj.ID,
		})
		convReq, _ := http.NewRequest(http.MethodPost, baseURL+"/conversations", bytes.NewReader(convBody))
		convReq.Header.Set("Authorization", "Bearer "+token)
		convReq.Header.Set("Content-Type", "application/json")
		convResp, err := client.Do(convReq)
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, convResp.StatusCode)
		convResp.Body.Close()

		// 3. Archive project
		archiveReq, _ := http.NewRequest(http.MethodPost, baseURL+"/projects/"+proj.ID+"/archive", nil)
		archiveReq.Header.Set("Authorization", "Bearer "+token)
		archiveResp, err := client.Do(archiveReq)
		require.NoError(t, err)
		require.Equal(t, http.StatusNoContent, archiveResp.StatusCode)

		// 4. Load activity list A (API returns DESC: newest first)
		actReq, _ := http.NewRequest(http.MethodGet, baseURL+"/projects/"+proj.ID+"/activity", nil)
		actReq.Header.Set("Authorization", "Bearer "+token)
		actResp, err := client.Do(actReq)
		require.NoError(t, err)
		defer actResp.Body.Close()
		var act projectActivityAPIResponse
		require.NoError(t, json.NewDecoder(actResp.Body).Decode(&act))
		require.Len(t, act.Items, 3, "must have 3 events")

		// 5. Fetch raw project_events ordered by created_at ASC, id ASC
		projectID, _ := uuid.Parse(proj.ID)
		rows, err := ts.DB.QueryContext(ctx, `
			SELECT id, project_id, actor_user_id, event_type, version, payload, payload_hash, created_at
			FROM project_events WHERE project_id = $1 ORDER BY created_at ASC, id ASC
		`, projectID)
		require.NoError(t, err)
		defer rows.Close()

		// 6. Replay decode + summary generation manually
		// 7. Build list B (summaries in ASC order, then reverse to match A's DESC order)
		var listB []string
		for rows.Next() {
			var pe model.ProjectEvent
			var idStr, projStr, actorStr string
			var pl []byte
			require.NoError(t, rows.Scan(&idStr, &projStr, &actorStr, &pe.EventType, &pe.Version, &pl, &pe.PayloadHash, &pe.CreatedAt))
			pe.ID = uuid.MustParse(idStr)
			pe.ProjectID = uuid.MustParse(projStr)
			pe.ActorUserID = uuid.MustParse(actorStr)
			if len(pl) > 0 {
				pe.Payload = pl
			}
			ev, err := project.DecodeProjectEvent(pe)
			require.NoError(t, err)
			listB = append(listB, ev.Summary())
		}
		require.NoError(t, rows.Err())

		// Reverse B to match A's order (A is DESC, B was ASC)
		for i, j := 0, len(listB)-1; i < j; i, j = i+1, j-1 {
			listB[i], listB[j] = listB[j], listB[i]
		}

		// Assert: len(A) == len(B), each Summary matches in order
		require.Len(t, listB, len(act.Items), "replay must produce same count")
		for i := range act.Items {
			assert.Equal(t, act.Items[i].Summary, listB[i], "summary at index %d must match", i)
		}
	})

	t.Run("P30_ProjectActivity_PureProjection", func(t *testing.T) {
		ts.TruncateAuth(t)
		token, userID := loginAndGetTokenAndUserID(t, client, baseURL, "+499911111129")
		_, userBID := loginAndGetTokenAndUserID(t, client, baseURL, "+499911111130")
		ctx := context.Background()

		// 1. Create project
		projBody, _ := json.Marshal(map[string]string{"name": "PureProjectionTest"})
		projReq, _ := http.NewRequest(http.MethodPost, baseURL+"/projects", bytes.NewReader(projBody))
		projReq.Header.Set("Authorization", "Bearer "+token)
		projReq.Header.Set("Content-Type", "application/json")
		projResp, err := client.Do(projReq)
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, projResp.StatusCode)
		var proj projectAPIResponse
		require.NoError(t, json.NewDecoder(projResp.Body).Decode(&proj))
		projResp.Body.Close()

		// 2. Add conversation
		convBody, _ := json.Marshal(map[string]interface{}{
			"member_user_ids": []string{userID, userBID},
			"project_id":      proj.ID,
		})
		convReq, _ := http.NewRequest(http.MethodPost, baseURL+"/conversations", bytes.NewReader(convBody))
		convReq.Header.Set("Authorization", "Bearer "+token)
		convReq.Header.Set("Content-Type", "application/json")
		convResp, err := client.Do(convReq)
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, convResp.StatusCode)
		convResp.Body.Close()

		// 3. Archive project
		archiveReq, _ := http.NewRequest(http.MethodPost, baseURL+"/projects/"+proj.ID+"/archive", nil)
		archiveReq.Header.Set("Authorization", "Bearer "+token)
		archiveResp, err := client.Do(archiveReq)
		require.NoError(t, err)
		require.Equal(t, http.StatusNoContent, archiveResp.StatusCode)

		// 4. Fetch activity via HTTP (A)
		actReq, _ := http.NewRequest(http.MethodGet, baseURL+"/projects/"+proj.ID+"/activity", nil)
		actReq.Header.Set("Authorization", "Bearer "+token)
		actResp, err := client.Do(actReq)
		require.NoError(t, err)
		defer actResp.Body.Close()
		var act projectActivityAPIResponse
		require.NoError(t, json.NewDecoder(actResp.Body).Decode(&act))
		require.Len(t, act.Items, 3)

		// 5. Fetch raw events via repo (DESC)
		projectEventRepo := repo.NewProjectEventRepo(ts.DB)
		projectID, _ := uuid.Parse(proj.ID)
		res, err := projectEventRepo.ListByProject(ctx, projectID, nil, 50)
		require.NoError(t, err)
		require.Len(t, res.Events, 3)

		// 6. Convert to EventForProjection and call BuildProjectActivity (B)
		events := make([]project.EventForProjection, len(res.Events))
		for i, ew := range res.Events {
			displayName := ""
			if ew.ActorDisplayName.Valid {
				displayName = ew.ActorDisplayName.String
			}
			phoneNumber := ""
			if ew.ActorPhoneNumber.Valid {
				phoneNumber = ew.ActorPhoneNumber.String
			}
			events[i] = project.EventForProjection{
				Event:            ew.ProjectEvent,
				ActorDisplayName: displayName,
				ActorPhoneNumber: phoneNumber,
			}
		}
		itemsB, nextCursorB, err := project.BuildProjectActivity(events, res.HasMore)
		require.NoError(t, err)

		// 7. Assert
		require.Len(t, itemsB, len(act.Items), "len(A.Items) == len(B.Items)")
		for i := range act.Items {
			assert.Equal(t, act.Items[i].Summary, itemsB[i].Summary, "summary at index %d must match", i)
		}
		if act.NextCursor != nil {
			require.NotNil(t, nextCursorB, "next_cursor must match")
			assert.Equal(t, *act.NextCursor, *nextCursorB)
		} else {
			assert.Nil(t, nextCursorB)
		}
	})

	t.Run("P31_ProjectActivity_SummaryStable", func(t *testing.T) {
		phone := "+499911111131"
		// Server A
		tsA, closeA := newTestServerForRestart(t)
		tsA.TruncateAuth(t)
		clientA := tsA.Server.Client()
		baseURLA := tsA.BaseURL()

		tokenA := loginAndGetToken(t, clientA, baseURLA, phone)
		projBody, _ := json.Marshal(map[string]string{"name": "StableTest"})
		projReq, _ := http.NewRequest(http.MethodPost, baseURLA+"/projects", bytes.NewReader(projBody))
		projReq.Header.Set("Authorization", "Bearer "+tokenA)
		projReq.Header.Set("Content-Type", "application/json")
		projResp, err := clientA.Do(projReq)
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, projResp.StatusCode)
		var proj projectAPIResponse
		require.NoError(t, json.NewDecoder(projResp.Body).Decode(&proj))
		projResp.Body.Close()
		projectID := proj.ID

		actReqA, _ := http.NewRequest(http.MethodGet, baseURLA+"/projects/"+projectID+"/activity", nil)
		actReqA.Header.Set("Authorization", "Bearer "+tokenA)
		actRespA, err := clientA.Do(actReqA)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, actRespA.StatusCode)
		var actA projectActivityAPIResponse
		require.NoError(t, json.NewDecoder(actRespA.Body).Decode(&actA))
		actRespA.Body.Close()

		summariesA := make([]string, len(actA.Items))
		for i, item := range actA.Items {
			summariesA[i] = item.Summary
		}
		var nextCursorA *string
		if actA.NextCursor != nil {
			s := *actA.NextCursor
			nextCursorA = &s
		}

		closeA()

		// Server B (fresh wiring, same DB)
		tsB, closeB := newTestServerForRestart(t)
		defer closeB()
		clientB := tsB.Server.Client()
		baseURLB := tsB.BaseURL()

		tokenB := loginAndGetToken(t, clientB, baseURLB, phone)

		actReqB, _ := http.NewRequest(http.MethodGet, baseURLB+"/projects/"+projectID+"/activity", nil)
		actReqB.Header.Set("Authorization", "Bearer "+tokenB)
		actRespB, err := clientB.Do(actReqB)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, actRespB.StatusCode)
		var actB projectActivityAPIResponse
		require.NoError(t, json.NewDecoder(actRespB.Body).Decode(&actB))
		actRespB.Body.Close()

		summariesB := make([]string, len(actB.Items))
		for i, item := range actB.Items {
			summariesB[i] = item.Summary
		}
		var nextCursorB *string
		if actB.NextCursor != nil {
			s := *actB.NextCursor
			nextCursorB = &s
		}

		require.Len(t, summariesB, len(summariesA), "lengths must match")
		for i := range summariesA {
			assert.Equal(t, summariesA[i], summariesB[i], "summary at index %d must be byte-identical", i)
		}
		if nextCursorA == nil {
			assert.Nil(t, nextCursorB, "next_cursor must both be nil")
		} else {
			require.NotNil(t, nextCursorB)
			assert.Equal(t, *nextCursorA, *nextCursorB, "next_cursor must match")
		}
	})

	t.Run("P32_ProjectActivity_PaginationStable", func(t *testing.T) {
		phone := "+499911111132"
		tsA, closeA := newTestServerForRestart(t)
		tsA.TruncateAuth(t)
		clientA := tsA.Server.Client()
		baseURLA := tsA.BaseURL()

		tokenA, userAID := loginAndGetTokenAndUserID(t, clientA, baseURLA, phone)
		_, userBID := loginAndGetTokenAndUserID(t, clientA, baseURLA, "+499911111133")
		_, userCID := loginAndGetTokenAndUserID(t, clientA, baseURLA, "+499111133301")
		_, userDID := loginAndGetTokenAndUserID(t, clientA, baseURLA, "+499111133302")

		// Create project
		projBody, _ := json.Marshal(map[string]string{"name": "PaginationStableTest"})
		projReq, _ := http.NewRequest(http.MethodPost, baseURLA+"/projects", bytes.NewReader(projBody))
		projReq.Header.Set("Authorization", "Bearer "+tokenA)
		projReq.Header.Set("Content-Type", "application/json")
		projResp, err := clientA.Do(projReq)
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, projResp.StatusCode)
		var proj projectAPIResponse
		require.NoError(t, json.NewDecoder(projResp.Body).Decode(&proj))
		projResp.Body.Close()
		projectID := proj.ID

		// Emit 5 events: project_created, conv1, conv2, conv3, project_archived.
		// Distinct member sets defeat the idempotency guard so each call creates a new conversation.
		for _, memberID := range []string{userBID, userCID, userDID} {
			convBody, _ := json.Marshal(map[string]interface{}{
				"member_user_ids": []string{userAID, memberID},
				"project_id":      projectID,
			})
			convReq, _ := http.NewRequest(http.MethodPost, baseURLA+"/conversations", bytes.NewReader(convBody))
			convReq.Header.Set("Authorization", "Bearer "+tokenA)
			convReq.Header.Set("Content-Type", "application/json")
			convResp, err := clientA.Do(convReq)
			require.NoError(t, err)
			convResp.Body.Close()
			require.Equal(t, http.StatusCreated, convResp.StatusCode)
		}
		archiveReq, _ := http.NewRequest(http.MethodPost, baseURLA+"/projects/"+projectID+"/archive", nil)
		archiveReq.Header.Set("Authorization", "Bearer "+tokenA)
		archiveResp, err := clientA.Do(archiveReq)
		require.NoError(t, err)
		require.Equal(t, http.StatusNoContent, archiveResp.StatusCode)

		// Page 1
		actReq1A, _ := http.NewRequest(http.MethodGet, baseURLA+"/projects/"+projectID+"/activity?limit=2", nil)
		actReq1A.Header.Set("Authorization", "Bearer "+tokenA)
		resp1A, err := clientA.Do(actReq1A)
		require.NoError(t, err)
		var page1A projectActivityAPIResponse
		require.NoError(t, json.NewDecoder(resp1A.Body).Decode(&page1A))
		resp1A.Body.Close()
		require.Len(t, page1A.Items, 2)
		require.NotNil(t, page1A.NextCursor)

		summariesA1 := make([]string, len(page1A.Items))
		for i, item := range page1A.Items {
			summariesA1[i] = item.Summary
		}
		nextCursorA1 := *page1A.NextCursor

		// Page 2
		actReq2A, _ := http.NewRequest(http.MethodGet, baseURLA+"/projects/"+projectID+"/activity?limit=2&before="+url.QueryEscape(nextCursorA1), nil)
		actReq2A.Header.Set("Authorization", "Bearer "+tokenA)
		resp2A, err := clientA.Do(actReq2A)
		require.NoError(t, err)
		var page2A projectActivityAPIResponse
		require.NoError(t, json.NewDecoder(resp2A.Body).Decode(&page2A))
		resp2A.Body.Close()
		require.Len(t, page2A.Items, 2)

		summariesA2 := make([]string, len(page2A.Items))
		for i, item := range page2A.Items {
			summariesA2[i] = item.Summary
		}
		var nextCursorA2 string
		if page2A.NextCursor != nil {
			nextCursorA2 = *page2A.NextCursor
		}

		closeA()

		// Server B
		tsB, closeB := newTestServerForRestart(t)
		defer closeB()
		clientB := tsB.Server.Client()
		baseURLB := tsB.BaseURL()

		tokenB := loginAndGetToken(t, clientB, baseURLB, phone)

		// Page 1
		actReq1B, _ := http.NewRequest(http.MethodGet, baseURLB+"/projects/"+projectID+"/activity?limit=2", nil)
		actReq1B.Header.Set("Authorization", "Bearer "+tokenB)
		resp1B, err := clientB.Do(actReq1B)
		require.NoError(t, err)
		var page1B projectActivityAPIResponse
		require.NoError(t, json.NewDecoder(resp1B.Body).Decode(&page1B))
		resp1B.Body.Close()

		summariesB1 := make([]string, len(page1B.Items))
		for i, item := range page1B.Items {
			summariesB1[i] = item.Summary
		}
		var nextCursorB1 string
		if page1B.NextCursor != nil {
			nextCursorB1 = *page1B.NextCursor
		}

		// Page 2
		actReq2B, _ := http.NewRequest(http.MethodGet, baseURLB+"/projects/"+projectID+"/activity?limit=2&before="+url.QueryEscape(nextCursorB1), nil)
		actReq2B.Header.Set("Authorization", "Bearer "+tokenB)
		resp2B, err := clientB.Do(actReq2B)
		require.NoError(t, err)
		var page2B projectActivityAPIResponse
		require.NoError(t, json.NewDecoder(resp2B.Body).Decode(&page2B))
		resp2B.Body.Close()

		summariesB2 := make([]string, len(page2B.Items))
		for i, item := range page2B.Items {
			summariesB2[i] = item.Summary
		}
		var nextCursorB2 string
		if page2B.NextCursor != nil {
			nextCursorB2 = *page2B.NextCursor
		}

		require.Len(t, summariesB1, len(summariesA1), "page1 lengths must match")
		require.Len(t, summariesB2, len(summariesA2), "page2 lengths must match")
		for i := range summariesA1 {
			assert.Equal(t, summariesA1[i], summariesB1[i], "page1 summary at index %d must match", i)
		}
		for i := range summariesA2 {
			assert.Equal(t, summariesA2[i], summariesB2[i], "page2 summary at index %d must match", i)
		}
		assert.Equal(t, nextCursorA1, nextCursorB1, "next_cursor page1 must match")
		assert.Equal(t, nextCursorA2, nextCursorB2, "next_cursor page2 must match")
	})

	t.Run("P33_ProjectActivity_StrictOrderingInvariant", func(t *testing.T) {
		ts.TruncateAuth(t)
		token, userID := loginAndGetTokenAndUserID(t, client, baseURL, "+499911111134")
		ctx := context.Background()

		// Create project
		projBody, _ := json.Marshal(map[string]string{"name": "StrictOrderTest"})
		projReq, _ := http.NewRequest(http.MethodPost, baseURL+"/projects", bytes.NewReader(projBody))
		projReq.Header.Set("Authorization", "Bearer "+token)
		projReq.Header.Set("Content-Type", "application/json")
		projResp, err := client.Do(projReq)
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, projResp.StatusCode)
		var proj projectAPIResponse
		require.NoError(t, json.NewDecoder(projResp.Body).Decode(&proj))
		projResp.Body.Close()

		// Insert 3 conversation_added events with identical created_at
		sharedTime := time.Now().UTC().Truncate(time.Second)
		convPayload := func(label string) string {
			id := uuid.New()
			p, _ := json.Marshal(project.ConversationAddedPayload{ConversationID: id, DisplayTitle: label})
			return string(p)
		}
		insertEvent := func(payload string) string {
			payloadJSON := json.RawMessage(payload)
			hash := project.ComputePayloadHash("conversation_added", project.ConversationAddedV1, payloadJSON)
			var eventID string
			err := ts.DB.QueryRowContext(ctx, `
				INSERT INTO project_events (project_id, actor_user_id, event_type, version, payload, payload_hash, created_at)
				VALUES ($1, $2, 'conversation_added', $3, $4::jsonb, $5, $6)
				RETURNING id
			`, proj.ID, userID, project.ConversationAddedV1, payload, hash, sharedTime).Scan(&eventID)
			require.NoError(t, err)
			return eventID
		}
		idA := insertEvent(convPayload("Chat A"))
		idB := insertEvent(convPayload("Chat B"))
		idC := insertEvent(convPayload("Chat C"))

		// Fetch activity
		actReq, _ := http.NewRequest(http.MethodGet, baseURL+"/projects/"+proj.ID+"/activity", nil)
		actReq.Header.Set("Authorization", "Bearer "+token)
		actResp, err := client.Do(actReq)
		require.NoError(t, err)
		defer actResp.Body.Close()
		require.Equal(t, http.StatusOK, actResp.StatusCode)
		var act projectActivityAPIResponse
		require.NoError(t, json.NewDecoder(actResp.Body).Decode(&act))

		// Collect the IDs of the 3 inserted events as they appear in the response
		var returnedIDs []string
		for _, item := range act.Items {
			if item.ID == idA || item.ID == idB || item.ID == idC {
				returnedIDs = append(returnedIDs, item.ID)
			}
		}
		require.Len(t, returnedIDs, 3, "all 3 inserted events must appear")

		// Assert strict id DESC ordering among the 3 events (same created_at)
		for i := 1; i < len(returnedIDs); i++ {
			assert.Greater(t, returnedIDs[i-1], returnedIDs[i],
				"id[%d]=%s must be > id[%d]=%s (id DESC ordering)", i-1, returnedIDs[i-1], i, returnedIDs[i])
		}
	})

	t.Run("P34_ProjectActivity_DuplicateEventDeterministic", func(t *testing.T) {
		ts.TruncateAuth(t)
		token, userID := loginAndGetTokenAndUserID(t, client, baseURL, "+499911111135")
		ctx := context.Background()

		// Create project
		projBody, _ := json.Marshal(map[string]string{"name": "DuplicateEventTest"})
		projReq, _ := http.NewRequest(http.MethodPost, baseURL+"/projects", bytes.NewReader(projBody))
		projReq.Header.Set("Authorization", "Bearer "+token)
		projReq.Header.Set("Content-Type", "application/json")
		projResp, err := client.Do(projReq)
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, projResp.StatusCode)
		var proj projectAPIResponse
		require.NoError(t, json.NewDecoder(projResp.Body).Decode(&proj))
		projResp.Body.Close()

		// Insert the original event
		convID := uuid.New()
		payload, _ := json.Marshal(project.ConversationAddedPayload{ConversationID: convID, DisplayTitle: "Dup Chat"})
		payloadStr := string(payload)
		hash := project.ComputePayloadHash("conversation_added", project.ConversationAddedV1, json.RawMessage(payload))

		var idOriginal string
		err = ts.DB.QueryRowContext(ctx, `
			INSERT INTO project_events (project_id, actor_user_id, event_type, version, payload, payload_hash)
			VALUES ($1, $2, 'conversation_added', $3, $4::jsonb, $5)
			RETURNING id
		`, proj.ID, userID, project.ConversationAddedV1, payloadStr, hash).Scan(&idOriginal)
		require.NoError(t, err)

		// Duplicate the row: identical payload/hash, new id, created_at slightly later (default NOW())
		var idDuplicate string
		err = ts.DB.QueryRowContext(ctx, `
			INSERT INTO project_events (project_id, actor_user_id, event_type, version, payload, payload_hash)
			VALUES ($1, $2, 'conversation_added', $3, $4::jsonb, $5)
			RETURNING id
		`, proj.ID, userID, project.ConversationAddedV1, payloadStr, hash).Scan(&idDuplicate)
		require.NoError(t, err)

		require.NotEqual(t, idOriginal, idDuplicate, "duplicate must get a new id")

		// Fetch activity
		actReq, _ := http.NewRequest(http.MethodGet, baseURL+"/projects/"+proj.ID+"/activity", nil)
		actReq.Header.Set("Authorization", "Bearer "+token)
		actResp, err := client.Do(actReq)
		require.NoError(t, err)
		defer actResp.Body.Close()
		require.Equal(t, http.StatusOK, actResp.StatusCode)

		var act projectActivityAPIResponse
		require.NoError(t, json.NewDecoder(actResp.Body).Decode(&act))

		// Collect the two duplicate event items in response order
		var dupItems []projectActivityItemAPIResponse
		for _, item := range act.Items {
			if item.ID == idOriginal || item.ID == idDuplicate {
				dupItems = append(dupItems, item)
			}
		}
		require.Len(t, dupItems, 2, "both duplicate events must appear in activity")

		// Summaries must be identical (same payload decodes to same summary)
		assert.Equal(t, dupItems[0].Summary, dupItems[1].Summary, "duplicate events must produce identical summaries")

		// No unknown activity entries among the two
		for _, item := range dupItems {
			assert.NotEqual(t, "Unknown activity", item.Summary, "duplicate event must not decode as unknown")
		}

		// Strict DESC(created_at, id): duplicate was inserted later so it has a greater id and >= created_at
		// The duplicate must appear before the original in the response
		assert.Equal(t, idDuplicate, dupItems[0].ID, "later-inserted duplicate must appear first (DESC order)")
		assert.Equal(t, idOriginal, dupItems[1].ID, "original must appear second")
	})

	t.Run("P35_ProjectActivity_CursorStableAgainstNewEvents", func(t *testing.T) {
		ts.TruncateAuth(t)
		// User A owns the project; users B/C/D are members of distinct conversations
		// so the idempotency guard (same project + same member set = same conv) never fires.
		token, userID := loginAndGetTokenAndUserID(t, client, baseURL, "+499911111136")
		_, userBID := loginAndGetTokenAndUserID(t, client, baseURL, "+499911111137")
		_, userCID := loginAndGetTokenAndUserID(t, client, baseURL, "+499911111138")
		_, userDID := loginAndGetTokenAndUserID(t, client, baseURL, "+499911111139")
		_, userEID := loginAndGetTokenAndUserID(t, client, baseURL, "+499911111140")

		// ── 1. Create project (event 1: project_created) ──────────────────────────
		projBody, _ := json.Marshal(map[string]string{"name": "CursorStableTest"})
		projReq, _ := http.NewRequest(http.MethodPost, baseURL+"/projects", bytes.NewReader(projBody))
		projReq.Header.Set("Authorization", "Bearer "+token)
		projReq.Header.Set("Content-Type", "application/json")
		projResp, err := client.Do(projReq)
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, projResp.StatusCode)
		var proj projectAPIResponse
		require.NoError(t, json.NewDecoder(projResp.Body).Decode(&proj))
		projResp.Body.Close()

		// ── 2. Emit 3 distinct conversation_added events (events 2-4) ─────────────
		// Each conversation has a unique member set to defeat the idempotency guard.
		for _, memberID := range []string{userBID, userCID, userDID} {
			convBody, _ := json.Marshal(map[string]interface{}{
				"member_user_ids": []string{userID, memberID},
				"project_id":      proj.ID,
			})
			convReq, _ := http.NewRequest(http.MethodPost, baseURL+"/conversations", bytes.NewReader(convBody))
			convReq.Header.Set("Authorization", "Bearer "+token)
			convReq.Header.Set("Content-Type", "application/json")
			convResp, err := client.Do(convReq)
			require.NoError(t, err)
			convResp.Body.Close()
			require.Equal(t, http.StatusCreated, convResp.StatusCode)
		}

		// ── 3. Archive project (event 5) ──────────────────────────────────────────
		archiveReq, _ := http.NewRequest(http.MethodPost, baseURL+"/projects/"+proj.ID+"/archive", nil)
		archiveReq.Header.Set("Authorization", "Bearer "+token)
		archiveResp, err := client.Do(archiveReq)
		require.NoError(t, err)
		require.Equal(t, http.StatusNoContent, archiveResp.StatusCode)

		// ── 4. Fetch page 1 (limit=2) ─────────────────────────────────────────────
		actReq1, _ := http.NewRequest(http.MethodGet, baseURL+"/projects/"+proj.ID+"/activity?limit=2", nil)
		actReq1.Header.Set("Authorization", "Bearer "+token)
		resp1, err := client.Do(actReq1)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp1.StatusCode)
		var page1 projectActivityAPIResponse
		require.NoError(t, json.NewDecoder(resp1.Body).Decode(&page1))
		resp1.Body.Close()
		require.Len(t, page1.Items, 2, "page 1 must have 2 items")
		require.NotNil(t, page1.NextCursor, "page 1 must have a next_cursor")
		assert.Contains(t, *page1.NextCursor, "|", "cursor must be composite format")

		page1IDs := make([]string, len(page1.Items))
		page1Timestamps := make([]string, len(page1.Items))
		page1Summaries := make([]string, len(page1.Items))
		for i, item := range page1.Items {
			page1IDs[i] = item.ID
			page1Timestamps[i] = item.Timestamp
			page1Summaries[i] = item.Summary
		}
		nextCursor1 := *page1.NextCursor

		// ── 5. Insert a NEW event AFTER page 1 was captured ───────────────────────
		// Use the API (distinct member set) so actor snapshot and payload_hash are
		// handled correctly by the production path.
		newConvBody, _ := json.Marshal(map[string]interface{}{
			"member_user_ids": []string{userID, userEID},
			"project_id":      proj.ID,
		})
		newConvReq, _ := http.NewRequest(http.MethodPost, baseURL+"/conversations", bytes.NewReader(newConvBody))
		newConvReq.Header.Set("Authorization", "Bearer "+token)
		newConvReq.Header.Set("Content-Type", "application/json")
		newConvResp, err := client.Do(newConvReq)
		require.NoError(t, err)
		newConvResp.Body.Close()
		require.Equal(t, http.StatusCreated, newConvResp.StatusCode)

		// Identify the new event's activity ID by fetching a fresh page-1 (limit=1).
		freshReq, _ := http.NewRequest(http.MethodGet, baseURL+"/projects/"+proj.ID+"/activity?limit=1", nil)
		freshReq.Header.Set("Authorization", "Bearer "+token)
		freshResp, err := client.Do(freshReq)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, freshResp.StatusCode)
		var freshPage projectActivityAPIResponse
		require.NoError(t, json.NewDecoder(freshResp.Body).Decode(&freshPage))
		freshResp.Body.Close()
		require.Len(t, freshPage.Items, 1, "fresh page-1 must return 1 item")
		newTopID := freshPage.Items[0].ID

		// ── 6. Fetch page 2 using the cursor captured before the new event ─────────
		actReq2, _ := http.NewRequest(http.MethodGet, baseURL+"/projects/"+proj.ID+"/activity?limit=2&before="+url.QueryEscape(nextCursor1), nil)
		actReq2.Header.Set("Authorization", "Bearer "+token)
		resp2, err := client.Do(actReq2)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp2.StatusCode)
		var page2 projectActivityAPIResponse
		require.NoError(t, json.NewDecoder(resp2.Body).Decode(&page2))
		resp2.Body.Close()
		require.NotEmpty(t, page2.Items, "page 2 must have items")

		page2IDs := make([]string, len(page2.Items))
		page2Timestamps := make([]string, len(page2.Items))
		page2Summaries := make([]string, len(page2.Items))
		for i, item := range page2.Items {
			page2IDs[i] = item.ID
			page2Timestamps[i] = item.Timestamp
			page2Summaries[i] = item.Summary
		}

		// ── Assertion A: no overlap between page 1 and page 2 ────────────────────
		page1IDSet := make(map[string]struct{}, len(page1IDs))
		for _, id := range page1IDs {
			page1IDSet[id] = struct{}{}
		}
		for _, id := range page2IDs {
			_, dup := page1IDSet[id]
			assert.False(t, dup, "page 2 item %s must not appear in page 1", id)
		}

		// ── Assertion B: new event must NOT appear in page 2 ─────────────────────
		for _, id := range page2IDs {
			assert.NotEqual(t, newTopID, id, "late-inserted event must not bleed into page 2 via cursor")
		}

		// ── Assertion C: strict DESC(created_at, id) ordering within each page ────
		assertDescOrder := func(ids, timestamps []string, label string) {
			for i := 1; i < len(ids); i++ {
				tPrev, errPrev := time.Parse(time.RFC3339Nano, timestamps[i-1])
				tCurr, errCurr := time.Parse(time.RFC3339Nano, timestamps[i])
				require.NoError(t, errPrev, "%s: parse timestamp[%d]", label, i-1)
				require.NoError(t, errCurr, "%s: parse timestamp[%d]", label, i)
				if tPrev.Equal(tCurr) {
					assert.Greater(t, ids[i-1], ids[i],
						"%s: equal created_at at [%d,%d] must fall back to id DESC", label, i-1, i)
				} else {
					assert.True(t, tPrev.After(tCurr),
						"%s: item[%d] timestamp must be after item[%d]", label, i-1, i)
				}
			}
		}
		assertDescOrder(page1IDs, page1Timestamps, "page1")
		assertDescOrder(page2IDs, page2Timestamps, "page2")

		// ── Assertion D: cursor sanity ────────────────────────────────────────────
		if page2.NextCursor != nil {
			assert.Contains(t, *page2.NextCursor, "|", "page2 next_cursor must be composite format")
		}

		// ── No decode failures on either page ─────────────────────────────────────
		for i, s := range page1Summaries {
			assert.NotEqual(t, "Unknown activity", s, "page1 item[%d] must not be unknown", i)
		}
		for i, s := range page2Summaries {
			assert.NotEqual(t, "Unknown activity", s, "page2 item[%d] must not be unknown", i)
		}
	})

	t.Run("P36_ProjectActivity_CursorStableAcrossRestartAndNewEvents", func(t *testing.T) {
		// ── helpers ───────────────────────────────────────────────────────────────
		collectPage := func(items []projectActivityItemAPIResponse) (ids, timestamps, summaries []string) {
			ids = make([]string, len(items))
			timestamps = make([]string, len(items))
			summaries = make([]string, len(items))
			for i, item := range items {
				ids[i] = item.ID
				timestamps[i] = item.Timestamp
				summaries[i] = item.Summary
			}
			return
		}
		assertDescOrder := func(ids, timestamps []string, label string) {
			for i := 1; i < len(ids); i++ {
				tPrev, errPrev := time.Parse(time.RFC3339Nano, timestamps[i-1])
				tCurr, errCurr := time.Parse(time.RFC3339Nano, timestamps[i])
				require.NoError(t, errPrev, "%s: parse timestamp[%d]", label, i-1)
				require.NoError(t, errCurr, "%s: parse timestamp[%d]", label, i)
				if tPrev.Equal(tCurr) {
					assert.Greater(t, ids[i-1], ids[i],
						"%s: equal created_at at [%d,%d] must fall back to id DESC", label, i-1, i)
				} else {
					assert.True(t, tPrev.After(tCurr),
						"%s: item[%d] timestamp must be after item[%d]", label, i-1, i)
				}
			}
		}

		// ── Server A ──────────────────────────────────────────────────────────────
		tsA, closeA := newTestServerForRestart(t)
		tsA.TruncateAuth(t)
		clientA := tsA.Server.Client()
		baseURLA := tsA.BaseURL()

		tokenA, userAID := loginAndGetTokenAndUserID(t, clientA, baseURLA, "+499911111141")
		_, userBID := loginAndGetTokenAndUserID(t, clientA, baseURLA, "+499911111142")
		_, userCID := loginAndGetTokenAndUserID(t, clientA, baseURLA, "+499911111143")
		_, userDID := loginAndGetTokenAndUserID(t, clientA, baseURLA, "+499911111144")
		_, userEID := loginAndGetTokenAndUserID(t, clientA, baseURLA, "+499911111145")

		// Create project (event 1: project_created)
		projBody, _ := json.Marshal(map[string]string{"name": "RestartCursorStableTest"})
		projReq, _ := http.NewRequest(http.MethodPost, baseURLA+"/projects", bytes.NewReader(projBody))
		projReq.Header.Set("Authorization", "Bearer "+tokenA)
		projReq.Header.Set("Content-Type", "application/json")
		projResp, err := clientA.Do(projReq)
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, projResp.StatusCode)
		var proj projectAPIResponse
		require.NoError(t, json.NewDecoder(projResp.Body).Decode(&proj))
		projResp.Body.Close()
		projectID := proj.ID

		// 3 distinct conversation_added events (events 2-4): unique member sets defeat deduplication
		for _, memberID := range []string{userBID, userCID, userDID} {
			convBody, _ := json.Marshal(map[string]interface{}{
				"member_user_ids": []string{userAID, memberID},
				"project_id":      projectID,
			})
			convReq, _ := http.NewRequest(http.MethodPost, baseURLA+"/conversations", bytes.NewReader(convBody))
			convReq.Header.Set("Authorization", "Bearer "+tokenA)
			convReq.Header.Set("Content-Type", "application/json")
			convResp, err := clientA.Do(convReq)
			require.NoError(t, err)
			convResp.Body.Close()
			require.Equal(t, http.StatusCreated, convResp.StatusCode)
		}

		// Archive project (event 5: project_archived)
		archiveReq, _ := http.NewRequest(http.MethodPost, baseURLA+"/projects/"+projectID+"/archive", nil)
		archiveReq.Header.Set("Authorization", "Bearer "+tokenA)
		archiveResp, err := clientA.Do(archiveReq)
		require.NoError(t, err)
		require.Equal(t, http.StatusNoContent, archiveResp.StatusCode)

		// Fetch page 1 on Server A (limit=2)
		req1A, _ := http.NewRequest(http.MethodGet, baseURLA+"/projects/"+projectID+"/activity?limit=2", nil)
		req1A.Header.Set("Authorization", "Bearer "+tokenA)
		resp1A, err := clientA.Do(req1A)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp1A.StatusCode)
		var page1A projectActivityAPIResponse
		require.NoError(t, json.NewDecoder(resp1A.Body).Decode(&page1A))
		resp1A.Body.Close()
		require.Len(t, page1A.Items, 2, "server A page1 must have 2 items")
		require.NotNil(t, page1A.NextCursor, "server A page1 must have next_cursor")
		assert.Contains(t, *page1A.NextCursor, "|", "cursor must be composite format")

		page1IDsA, page1TimestampsA, page1SummariesA := collectPage(page1A.Items)
		nextCursor1 := *page1A.NextCursor
		assertDescOrder(page1IDsA, page1TimestampsA, "serverA/page1")

		// Shut down Server A
		closeA()

		// ── Server B (restart, same DB) ───────────────────────────────────────────
		tsB, closeB := newTestServerForRestart(t)
		defer closeB()
		clientB := tsB.Server.Client()
		baseURLB := tsB.BaseURL()

		// Re-login the same user (credentials still in DB)
		tokenB := loginAndGetToken(t, clientB, baseURLB, "+499911111141")

		// Insert ONE NEW event on Server B AFTER page 1 was captured on Server A.
		// Use a distinct member set (userEID) so deduplication does not suppress the event.
		newConvBody, _ := json.Marshal(map[string]interface{}{
			"member_user_ids": []string{userAID, userEID},
			"project_id":      projectID,
		})
		newConvReq, _ := http.NewRequest(http.MethodPost, baseURLB+"/conversations", bytes.NewReader(newConvBody))
		newConvReq.Header.Set("Authorization", "Bearer "+tokenB)
		newConvReq.Header.Set("Content-Type", "application/json")
		newConvResp, err := clientB.Do(newConvReq)
		require.NoError(t, err)
		newConvResp.Body.Close()
		require.Equal(t, http.StatusCreated, newConvResp.StatusCode)

		// Identify the new event's activity ID via a fresh limit=1 fetch
		freshReq, _ := http.NewRequest(http.MethodGet, baseURLB+"/projects/"+projectID+"/activity?limit=1", nil)
		freshReq.Header.Set("Authorization", "Bearer "+tokenB)
		freshResp, err := clientB.Do(freshReq)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, freshResp.StatusCode)
		var freshPage projectActivityAPIResponse
		require.NoError(t, json.NewDecoder(freshResp.Body).Decode(&freshPage))
		freshResp.Body.Close()
		require.Len(t, freshPage.Items, 1, "fresh limit=1 must return 1 item")
		newEventID := freshPage.Items[0].ID

		// Sanity: new event must not already be in page1IDsA
		page1IDSetA := make(map[string]struct{}, len(page1IDsA))
		for _, id := range page1IDsA {
			page1IDSetA[id] = struct{}{}
		}
		_, alreadyInPage1 := page1IDSetA[newEventID]
		require.False(t, alreadyInPage1, "new event must not already be in page1IDsA")

		// Fetch page 2 on Server B using the cursor from Server A
		req2B, _ := http.NewRequest(http.MethodGet, baseURLB+"/projects/"+projectID+"/activity?limit=2&before="+url.QueryEscape(nextCursor1), nil)
		req2B.Header.Set("Authorization", "Bearer "+tokenB)
		resp2B, err := clientB.Do(req2B)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp2B.StatusCode)
		var page2B projectActivityAPIResponse
		require.NoError(t, json.NewDecoder(resp2B.Body).Decode(&page2B))
		resp2B.Body.Close()
		require.NotEmpty(t, page2B.Items, "server B page2 must have items")

		page2IDsB, page2TimestampsB, page2SummariesB := collectPage(page2B.Items)

		// New event must NOT appear in page 2 (it is newer than the cursor)
		for _, id := range page2IDsB {
			assert.NotEqual(t, newEventID, id, "new event must not bleed into page2 via cursor")
		}

		// No overlap between page1 (server A) and page2 (server B)
		for _, id := range page2IDsB {
			_, dup := page1IDSetA[id]
			assert.False(t, dup, "page2 item %s must not duplicate a page1 item", id)
		}

		// page2 must be strictly ordered DESC(created_at, id)
		assertDescOrder(page2IDsB, page2TimestampsB, "serverB/page2")

		// Cursor used for page2 is exactly the one captured on server A (string identity)
		assert.NotEmpty(t, nextCursor1, "cursor from server A must be non-empty")

		// If page2 has its own next_cursor it must be composite
		if page2B.NextCursor != nil {
			assert.Contains(t, *page2B.NextCursor, "|", "page2 next_cursor must be composite format")
		}

		// Verify new event appears at the top of a fresh page1 on Server B
		freshPage1Req, _ := http.NewRequest(http.MethodGet, baseURLB+"/projects/"+projectID+"/activity?limit=2", nil)
		freshPage1Req.Header.Set("Authorization", "Bearer "+tokenB)
		freshPage1Resp, err := clientB.Do(freshPage1Req)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, freshPage1Resp.StatusCode)
		var freshPage1B projectActivityAPIResponse
		require.NoError(t, json.NewDecoder(freshPage1Resp.Body).Decode(&freshPage1B))
		freshPage1Resp.Body.Close()
		require.NotEmpty(t, freshPage1B.Items, "fresh page1 on server B must have items")
		assert.Equal(t, newEventID, freshPage1B.Items[0].ID,
			"new event must be the newest item on a fresh page1 fetch")

		// No decode failures
		for i, s := range page1SummariesA {
			assert.NotEqual(t, "Unknown activity", s, "serverA page1 item[%d] must not be unknown", i)
		}
		for i, s := range page2SummariesB {
			assert.NotEqual(t, "Unknown activity", s, "serverB page2 item[%d] must not be unknown", i)
		}
	})

	t.Run("P37_ProjectActivity_ConcurrentInsertsDeterministic", func(t *testing.T) {
		// NOT parallel: shares the same DB as other integration tests in this suite.
		const N = 6 // number of concurrent conversations

		ts.TruncateAuth(t)

		// Login owner + N distinct members (phones ...146 through ...152).
		// Each conversation uses a unique (owner, memberIDs[i]) pair so the
		// idempotency guard never collapses two requests into one event.
		token, userAID := loginAndGetTokenAndUserID(t, client, baseURL, "+499911111146")
		memberIDs := make([]string, N)
		for i := 0; i < N; i++ {
			phone := fmt.Sprintf("+49991111%04d", 147+i) // ...147 through ...152
			_, memberIDs[i] = loginAndGetTokenAndUserID(t, client, baseURL, phone)
		}

		// Create project (event 1: project_created)
		projBody, _ := json.Marshal(map[string]string{"name": "ConcurrentTest"})
		projReq, _ := http.NewRequest(http.MethodPost, baseURL+"/projects", bytes.NewReader(projBody))
		projReq.Header.Set("Authorization", "Bearer "+token)
		projReq.Header.Set("Content-Type", "application/json")
		projResp, err := client.Do(projReq)
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, projResp.StatusCode)
		var proj projectAPIResponse
		require.NoError(t, json.NewDecoder(projResp.Body).Decode(&proj))
		projResp.Body.Close()

		// Concurrently POST N conversations; each goroutine writes only to its own slot.
		type result struct {
			status int
			err    error
		}
		results := make([]result, N)
		var wg sync.WaitGroup
		for i := 0; i < N; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				body, _ := json.Marshal(map[string]interface{}{
					"member_user_ids": []string{userAID, memberIDs[idx]},
					"project_id":      proj.ID,
				})
				req, _ := http.NewRequest(http.MethodPost, baseURL+"/conversations", bytes.NewReader(body))
				req.Header.Set("Authorization", "Bearer "+token)
				req.Header.Set("Content-Type", "application/json")
				resp, reqErr := client.Do(req)
				if reqErr != nil {
					results[idx] = result{err: reqErr}
					return
				}
				resp.Body.Close()
				results[idx] = result{status: resp.StatusCode}
			}(i)
		}
		wg.Wait()

		// All N concurrent requests must have succeeded
		for i, r := range results {
			require.NoError(t, r.err, "goroutine %d must not error", i)
			assert.Equal(t, http.StatusCreated, r.status, "goroutine %d must return 201", i)
		}

		// Fetch full activity (limit large enough to capture all events)
		actReq, _ := http.NewRequest(http.MethodGet, baseURL+"/projects/"+proj.ID+"/activity?limit=100", nil)
		actReq.Header.Set("Authorization", "Bearer "+token)
		actResp, err := client.Do(actReq)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, actResp.StatusCode)
		var act projectActivityAPIResponse
		require.NoError(t, json.NewDecoder(actResp.Body).Decode(&act))
		actResp.Body.Close()

		// ── Completeness: exactly N conversation_added items ──────────────────────
		var convItems []projectActivityItemAPIResponse
		for _, item := range act.Items {
			if item.Type == "conversation_added" {
				convItems = append(convItems, item)
			}
		}
		require.Len(t, convItems, N, "must have exactly %d conversation_added events", N)

		// No decode failures among conversation_added items
		for i, item := range convItems {
			assert.NotEqual(t, "Unknown activity", item.Summary,
				"conversation_added item[%d] must not be unknown", i)
		}

		// ── Uniqueness: N distinct IDs among conversation_added items ─────────────
		uniqueConvIDs := make(map[string]struct{}, N)
		for _, item := range convItems {
			uniqueConvIDs[item.ID] = struct{}{}
		}
		assert.Len(t, uniqueConvIDs, N, "all %d conversation_added items must have distinct IDs", N)

		// ── Ordering: full activity list strictly DESC(created_at, id) ───────────
		// Rule:
		//   if tPrev.After(tCurr)  => OK
		//   if tPrev.Equal(tCurr)  => require idPrev > idCurr (lexicographic)
		//   else                   => fail (tCurr is newer than tPrev)
		for i := 1; i < len(act.Items); i++ {
			idPrev := act.Items[i-1].ID
			idCurr := act.Items[i].ID
			tPrev, errPrev := time.Parse(time.RFC3339Nano, act.Items[i-1].Timestamp)
			tCurr, errCurr := time.Parse(time.RFC3339Nano, act.Items[i].Timestamp)
			require.NoError(t, errPrev, "parse timestamp[%d]", i-1)
			require.NoError(t, errCurr, "parse timestamp[%d]", i)
			if tPrev.After(tCurr) {
				// correct: strictly descending timestamp
			} else if tPrev.Equal(tCurr) {
				assert.Greater(t, idPrev, idCurr,
					"[%d,%d] equal created_at: id DESC tiebreaker violated (idPrev=%s idCurr=%s)",
					i-1, i, idPrev, idCurr)
			} else {
				assert.Fail(t,
					fmt.Sprintf("[%d,%d] ordering violated: item[%d].created_at=%s is BEFORE item[%d].created_at=%s",
						i-1, i, i-1, act.Items[i-1].Timestamp, i, act.Items[i].Timestamp))
			}
		}

		// ── Stability: two back-to-back reads must return identical sequences ─────
		actReq2, _ := http.NewRequest(http.MethodGet, baseURL+"/projects/"+proj.ID+"/activity?limit=100", nil)
		actReq2.Header.Set("Authorization", "Bearer "+token)
		actResp2, err := client.Do(actReq2)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, actResp2.StatusCode)
		var act2 projectActivityAPIResponse
		require.NoError(t, json.NewDecoder(actResp2.Body).Decode(&act2))
		actResp2.Body.Close()

		require.Len(t, act2.Items, len(act.Items), "repeated read must return same number of items")
		for i := range act.Items {
			assert.Equal(t, act.Items[i].ID, act2.Items[i].ID,
				"repeated read: ID mismatch at index %d", i)
			assert.Equal(t, act.Items[i].Summary, act2.Items[i].Summary,
				"repeated read: Summary mismatch at index %d", i)
		}
	})

	t.Run("P38_ProjectActivity_ReprojectionIdempotent", func(t *testing.T) {
		// NOT parallel: shares the same DB as other integration tests in this suite.
		ts.TruncateAuth(t)
		ctx := context.Background()

		token, userAID := loginAndGetTokenAndUserID(t, client, baseURL, "+499911111153")
		_, userBID := loginAndGetTokenAndUserID(t, client, baseURL, "+499911111154")
		_, userCID := loginAndGetTokenAndUserID(t, client, baseURL, "+499911111155")
		_, userDID := loginAndGetTokenAndUserID(t, client, baseURL, "+499911111156")

		// ── 1. Create project (event 1: project_created) ──────────────────────────
		projBody, _ := json.Marshal(map[string]string{"name": "ReprojectionTest"})
		projReq, _ := http.NewRequest(http.MethodPost, baseURL+"/projects", bytes.NewReader(projBody))
		projReq.Header.Set("Authorization", "Bearer "+token)
		projReq.Header.Set("Content-Type", "application/json")
		projResp, err := client.Do(projReq)
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, projResp.StatusCode)
		var proj projectAPIResponse
		require.NoError(t, json.NewDecoder(projResp.Body).Decode(&proj))
		projResp.Body.Close()

		// ── 2. 3 distinct conversation_added events (events 2-4) ──────────────────
		for _, memberID := range []string{userBID, userCID, userDID} {
			convBody, _ := json.Marshal(map[string]interface{}{
				"member_user_ids": []string{userAID, memberID},
				"project_id":      proj.ID,
			})
			convReq, _ := http.NewRequest(http.MethodPost, baseURL+"/conversations", bytes.NewReader(convBody))
			convReq.Header.Set("Authorization", "Bearer "+token)
			convReq.Header.Set("Content-Type", "application/json")
			convResp, err := client.Do(convReq)
			require.NoError(t, err)
			convResp.Body.Close()
			require.Equal(t, http.StatusCreated, convResp.StatusCode)
		}

		// ── 3. Archive project (event 5: project_archived) ────────────────────────
		archiveReq, _ := http.NewRequest(http.MethodPost, baseURL+"/projects/"+proj.ID+"/archive", nil)
		archiveReq.Header.Set("Authorization", "Bearer "+token)
		archiveResp, err := client.Do(archiveReq)
		require.NoError(t, err)
		require.Equal(t, http.StatusNoContent, archiveResp.StatusCode)

		// ── 4. Fetch activity via HTTP (itemsA) ───────────────────────────────────
		actReq, _ := http.NewRequest(http.MethodGet, baseURL+"/projects/"+proj.ID+"/activity?limit=100", nil)
		actReq.Header.Set("Authorization", "Bearer "+token)
		actResp, err := client.Do(actReq)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, actResp.StatusCode)
		var actPage projectActivityAPIResponse
		require.NoError(t, json.NewDecoder(actResp.Body).Decode(&actPage))
		actResp.Body.Close()
		require.Len(t, actPage.Items, 5, "must have exactly 5 activity items")

		type idSummary struct{ id, summary string }
		itemsA := make([]idSummary, len(actPage.Items))
		for i, item := range actPage.Items {
			itemsA[i] = idSummary{item.ID, item.Summary}
		}

		// ── 5. Fetch raw project_events ASC from DB ───────────────────────────────
		// Columns match the scan order used in repo.projectEventRepo.ListByProject.
		projIDParsed, err := uuid.Parse(proj.ID)
		require.NoError(t, err)

		rows, err := ts.DB.QueryContext(ctx, `
			SELECT pe.id, pe.project_id, pe.actor_user_id,
			       pe.event_type, pe.version, pe.payload, pe.payload_hash, pe.created_at,
			       pe.actor_display_name, pe.actor_phone_number
			FROM project_events pe
			WHERE pe.project_id = $1
			ORDER BY pe.created_at ASC, pe.id ASC
		`, projIDParsed)
		require.NoError(t, err)
		defer rows.Close()

		var rawEventsASC []project.EventForProjection
		for rows.Next() {
			var (
				idStr, projStr, actorStr string
				payload                  []byte
				payloadHash              string
				createdAt                time.Time
				actorDisplayName         sql.NullString
				actorPhoneNumber         sql.NullString
				eventType                string
				version                  int
			)
			err := rows.Scan(
				&idStr, &projStr, &actorStr,
				&eventType, &version, &payload, &payloadHash, &createdAt,
				&actorDisplayName, &actorPhoneNumber,
			)
			require.NoError(t, err)

			var me model.ProjectEvent
			me.ID, _ = uuid.Parse(idStr)
			me.ProjectID, _ = uuid.Parse(projStr)
			me.ActorUserID, _ = uuid.Parse(actorStr)
			me.EventType = eventType
			me.Version = version
			me.PayloadHash = payloadHash
			me.CreatedAt = createdAt
			if len(payload) > 0 {
				me.Payload = json.RawMessage(payload)
			}

			displayName := ""
			if actorDisplayName.Valid {
				displayName = actorDisplayName.String
			}
			phoneNumber := ""
			if actorPhoneNumber.Valid {
				phoneNumber = actorPhoneNumber.String
			}

			rawEventsASC = append(rawEventsASC, project.EventForProjection{
				Event:            me,
				ActorDisplayName: displayName,
				ActorPhoneNumber: phoneNumber,
			})
		}
		require.NoError(t, rows.Err())
		require.Len(t, rawEventsASC, 5, "must have 5 raw events in DB")

		// ── 6. Manually rebuild projection ────────────────────────────────────────
		// BuildProjectActivity expects DESC order; reverse the ASC slice in-place.
		rawEventsDESC := make([]project.EventForProjection, len(rawEventsASC))
		for i, ev := range rawEventsASC {
			rawEventsDESC[len(rawEventsASC)-1-i] = ev
		}

		itemsBProjected, _, err := project.BuildProjectActivity(rawEventsDESC, false)
		require.NoError(t, err)
		require.Len(t, itemsBProjected, 5, "manual reprojection must produce 5 items")

		itemsB := make([]idSummary, len(itemsBProjected))
		for i, item := range itemsBProjected {
			itemsB[i] = idSummary{item.ID.String(), item.Summary}
		}

		// ── 7. Assert byte-identical output ──────────────────────────────────────
		require.Len(t, itemsA, len(itemsB), "HTTP and reprojection must return same count")
		for i := range itemsA {
			assert.Equal(t, itemsA[i].id, itemsB[i].id,
				"ID mismatch at index %d: HTTP=%s reprojection=%s", i, itemsA[i].id, itemsB[i].id)
			assert.Equal(t, itemsA[i].summary, itemsB[i].summary,
				"Summary mismatch at index %d: HTTP=%q reprojection=%q", i, itemsA[i].summary, itemsB[i].summary)
		}

		// No "Unknown activity" in either source
		for i, item := range itemsA {
			assert.NotEqual(t, "Unknown activity", item.summary,
				"HTTP item[%d] must not be unknown", i)
		}
		for i, item := range itemsB {
			assert.NotEqual(t, "Unknown activity", item.summary,
				"reprojection item[%d] must not be unknown", i)
		}

		// ── 8. Second HTTP fetch must be identical to first ───────────────────────
		actReq2, _ := http.NewRequest(http.MethodGet, baseURL+"/projects/"+proj.ID+"/activity?limit=100", nil)
		actReq2.Header.Set("Authorization", "Bearer "+token)
		actResp2, err := client.Do(actReq2)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, actResp2.StatusCode)
		var actPage2 projectActivityAPIResponse
		require.NoError(t, json.NewDecoder(actResp2.Body).Decode(&actPage2))
		actResp2.Body.Close()

		require.Len(t, actPage2.Items, len(actPage.Items), "second HTTP fetch must return same count")
		for i := range actPage.Items {
			assert.Equal(t, actPage.Items[i].ID, actPage2.Items[i].ID,
				"second fetch: ID mismatch at index %d", i)
			assert.Equal(t, actPage.Items[i].Summary, actPage2.Items[i].Summary,
				"second fetch: Summary mismatch at index %d", i)
		}
	})
}

type projectActivityAPIResponse struct {
	Items      []projectActivityItemAPIResponse `json:"items"`
	NextCursor *string                          `json:"next_cursor,omitempty"`
	HasMore    bool                             `json:"has_more"`
}

type projectActivityItemAPIResponse struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	Timestamp  string `json:"timestamp"`
	ActorID    string `json:"actor_id"`
	ActorLabel string `json:"actor_label"`
	Summary    string `json:"summary"`
}
