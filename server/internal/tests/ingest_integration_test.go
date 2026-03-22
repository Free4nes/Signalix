package tests

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ingestAckResponse mirrors the JSON returned by POST /ingest on success
type ingestAckResponse struct {
	OK         bool      `json:"ok"`
	ProjectID  string    `json:"project_id"`
	ReceivedAt time.Time `json:"received_at"`
	Event      string    `json:"event"`
}

// eventAPIResponse mirrors GET /projects/{id}/events items
type eventAPIResponse struct {
	ID         string          `json:"id"`
	Event      string          `json:"event"`
	ReceivedAt time.Time       `json:"received_at"`
	Payload    json.RawMessage `json:"payload"`
}

func TestIngestIntegration(t *testing.T) {
	if os.Getenv("DATABASE_URL") == "" {
		t.Skip("DATABASE_URL not set; skipping integration test")
	}

	ts := newTestServer(t)
	baseURL := ts.BaseURL()
	client := ts.Server.Client()

	t.Run("I1_IngestWithValidKey_Returns200AndProjectID", func(t *testing.T) {
		ts.TruncateAuth(t)
		token := loginAndGetToken(t, client, baseURL, "+499001000001")

		// Create project
		projBody, _ := json.Marshal(map[string]string{"name": "IngestProject"})
		projReq, _ := http.NewRequest(http.MethodPost, baseURL+"/projects", bytes.NewReader(projBody))
		projReq.Header.Set("Authorization", "Bearer "+token)
		projReq.Header.Set("Content-Type", "application/json")
		projResp, err := client.Do(projReq)
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, projResp.StatusCode)
		var proj projectAPIResponse
		require.NoError(t, json.NewDecoder(projResp.Body).Decode(&proj))
		projResp.Body.Close()

		// Create API key
		keyBody, _ := json.Marshal(map[string]string{"name": "TestKey"})
		keyReq, _ := http.NewRequest(http.MethodPost, baseURL+"/projects/"+proj.ID+"/keys", bytes.NewReader(keyBody))
		keyReq.Header.Set("Authorization", "Bearer "+token)
		keyReq.Header.Set("Content-Type", "application/json")
		keyResp, err := client.Do(keyReq)
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, keyResp.StatusCode)
		var createdKey createKeyAPIResponse
		require.NoError(t, json.NewDecoder(keyResp.Body).Decode(&createdKey))
		keyResp.Body.Close()
		require.NotEmpty(t, createdKey.APIKey, "plaintext key must be returned on creation")

		// Call POST /ingest with the plaintext key
		ingestBody, _ := json.Marshal(map[string]interface{}{
			"event": "hello",
			"data":  map[string]interface{}{"x": 1},
		})
		ingestReq, _ := http.NewRequest(http.MethodPost, baseURL+"/ingest", bytes.NewReader(ingestBody))
		ingestReq.Header.Set("X-API-Key", createdKey.APIKey)
		ingestReq.Header.Set("Content-Type", "application/json")
		ingestResp, err := client.Do(ingestReq)
		require.NoError(t, err)
		defer ingestResp.Body.Close()
		assert.Equal(t, http.StatusOK, ingestResp.StatusCode, "ingest with valid key must return 200")

		var ack ingestAckResponse
		require.NoError(t, json.NewDecoder(ingestResp.Body).Decode(&ack))
		assert.True(t, ack.OK)
		assert.Equal(t, proj.ID, ack.ProjectID, "project_id in ack must match the project that owns the key")
		assert.Equal(t, "hello", ack.Event)
		assert.False(t, ack.ReceivedAt.IsZero())

		// Verify the event was persisted: GET /projects/{id}/events
		eventsReq, _ := http.NewRequest(http.MethodGet, baseURL+"/projects/"+proj.ID+"/events", nil)
		eventsReq.Header.Set("Authorization", "Bearer "+token)
		eventsResp, err := client.Do(eventsReq)
		require.NoError(t, err)
		defer eventsResp.Body.Close()
		assert.Equal(t, http.StatusOK, eventsResp.StatusCode)

		var events []eventAPIResponse
		require.NoError(t, json.NewDecoder(eventsResp.Body).Decode(&events))
		require.Len(t, events, 1, "exactly one event should be stored")
		assert.Equal(t, "hello", events[0].Event)
		assert.NotEmpty(t, events[0].ID)
	})

	t.Run("I2_IngestMissingKey_Returns401MissingApiKey", func(t *testing.T) {
		ts.TruncateAuth(t)

		ingestBody, _ := json.Marshal(map[string]interface{}{"event": "test"})
		ingestReq, _ := http.NewRequest(http.MethodPost, baseURL+"/ingest", bytes.NewReader(ingestBody))
		ingestReq.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(ingestReq)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

		var errResp errorResponse
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&errResp))
		assert.Equal(t, "missing_api_key", errResp.Error)
	})

	t.Run("I3_IngestInvalidKey_Returns401InvalidApiKey", func(t *testing.T) {
		ts.TruncateAuth(t)

		ingestBody, _ := json.Marshal(map[string]interface{}{"event": "test"})
		ingestReq, _ := http.NewRequest(http.MethodPost, baseURL+"/ingest", bytes.NewReader(ingestBody))
		ingestReq.Header.Set("X-API-Key", "sk_live_thisisnotavalidkey")
		ingestReq.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(ingestReq)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

		var errResp errorResponse
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&errResp))
		assert.Equal(t, "invalid_api_key", errResp.Error)
	})

	t.Run("I4_IngestRevokedKey_Returns401RevokedApiKey", func(t *testing.T) {
		ts.TruncateAuth(t)
		token := loginAndGetToken(t, client, baseURL, "+499001000002")

		// Create project + key
		projBody, _ := json.Marshal(map[string]string{"name": "RevokeIngestProject"})
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
		var createdKey createKeyAPIResponse
		require.NoError(t, json.NewDecoder(keyResp.Body).Decode(&createdKey))
		keyResp.Body.Close()

		// Revoke the key
		revokeReq, _ := http.NewRequest(http.MethodPost, baseURL+"/projects/"+proj.ID+"/keys/"+createdKey.ID+"/revoke", nil)
		revokeReq.Header.Set("Authorization", "Bearer "+token)
		revokeResp, err := client.Do(revokeReq)
		require.NoError(t, err)
		revokeResp.Body.Close()
		require.Equal(t, http.StatusNoContent, revokeResp.StatusCode)

		// Attempt ingest with the now-revoked key
		ingestBody, _ := json.Marshal(map[string]interface{}{"event": "after_revoke"})
		ingestReq, _ := http.NewRequest(http.MethodPost, baseURL+"/ingest", bytes.NewReader(ingestBody))
		ingestReq.Header.Set("X-API-Key", createdKey.APIKey)
		ingestReq.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(ingestReq)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

		var errResp errorResponse
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&errResp))
		assert.Equal(t, "revoked_api_key", errResp.Error)
	})

	t.Run("I6_ListEvents_ForbiddenForOtherUser", func(t *testing.T) {
		ts.TruncateAuth(t)

		// User A creates a project and ingests an event
		tokenA := loginAndGetToken(t, client, baseURL, "+499001000010")

		projBody, _ := json.Marshal(map[string]string{"name": "OwnerProject"})
		projReq, _ := http.NewRequest(http.MethodPost, baseURL+"/projects", bytes.NewReader(projBody))
		projReq.Header.Set("Authorization", "Bearer "+tokenA)
		projReq.Header.Set("Content-Type", "application/json")
		projResp, err := client.Do(projReq)
		require.NoError(t, err)
		var proj projectAPIResponse
		require.NoError(t, json.NewDecoder(projResp.Body).Decode(&proj))
		projResp.Body.Close()

		// User B tries to list events for User A's project
		tokenB := loginAndGetToken(t, client, baseURL, "+499001000011")
		eventsReq, _ := http.NewRequest(http.MethodGet, baseURL+"/projects/"+proj.ID+"/events", nil)
		eventsReq.Header.Set("Authorization", "Bearer "+tokenB)
		resp, err := client.Do(eventsReq)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("I5_IngestMissingEvent_Returns400InvalidPayload", func(t *testing.T) {
		ts.TruncateAuth(t)
		token := loginAndGetToken(t, client, baseURL, "+499001000003")

		projBody, _ := json.Marshal(map[string]string{"name": "PayloadProject"})
		projReq, _ := http.NewRequest(http.MethodPost, baseURL+"/projects", bytes.NewReader(projBody))
		projReq.Header.Set("Authorization", "Bearer "+token)
		projReq.Header.Set("Content-Type", "application/json")
		projResp, err := client.Do(projReq)
		require.NoError(t, err)
		var proj projectAPIResponse
		require.NoError(t, json.NewDecoder(projResp.Body).Decode(&proj))
		projResp.Body.Close()

		keyBody, _ := json.Marshal(map[string]string{"name": "PayloadKey"})
		keyReq, _ := http.NewRequest(http.MethodPost, baseURL+"/projects/"+proj.ID+"/keys", bytes.NewReader(keyBody))
		keyReq.Header.Set("Authorization", "Bearer "+token)
		keyReq.Header.Set("Content-Type", "application/json")
		keyResp, err := client.Do(keyReq)
		require.NoError(t, err)
		var createdKey createKeyAPIResponse
		require.NoError(t, json.NewDecoder(keyResp.Body).Decode(&createdKey))
		keyResp.Body.Close()

		// Send payload without "event" field
		ingestBody, _ := json.Marshal(map[string]interface{}{"data": map[string]int{"x": 1}})
		ingestReq, _ := http.NewRequest(http.MethodPost, baseURL+"/ingest", bytes.NewReader(ingestBody))
		ingestReq.Header.Set("X-API-Key", createdKey.APIKey)
		ingestReq.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(ingestReq)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

		var errResp errorResponse
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&errResp))
		assert.Equal(t, "invalid_payload", errResp.Error)
	})
}
