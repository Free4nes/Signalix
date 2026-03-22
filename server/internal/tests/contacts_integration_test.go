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

func TestContactsSyncIntegration(t *testing.T) {
	if os.Getenv("DATABASE_URL") == "" {
		t.Skip("DATABASE_URL not set; skipping integration test")
	}

	ts := newTestServer(t)
	baseURL := ts.BaseURL()
	client := ts.Server.Client()

	t.Run("Sync_ReturnsUsersForNormalizedMatches", func(t *testing.T) {
		ts.TruncateAuth(t)
		// Create 3 users with different input formats
		tokenA, _ := loginAndGetTokenAndUserID(t, client, baseURL, "+491111111111")
		_, _ = loginAndGetTokenAndUserID(t, client, baseURL, "0049222222222")
		_, _ = loginAndGetTokenAndUserID(t, client, baseURL, "+49 33 333 3333")

		// Sync with messy formats - should return all 3
		syncBody, _ := json.Marshal(map[string]interface{}{
			"phones": []string{
				"+49 11 1111 1111",
				"0049 222 222 222",
				"+49(33)333-3333",
			},
		})
		syncReq, _ := http.NewRequest(http.MethodPost, baseURL+"/contacts/sync", bytes.NewReader(syncBody))
		syncReq.Header.Set("Authorization", "Bearer "+tokenA)
		syncReq.Header.Set("Content-Type", "application/json")
		syncResp, err := client.Do(syncReq)
		require.NoError(t, err)
		defer syncResp.Body.Close()
		assert.Equal(t, http.StatusOK, syncResp.StatusCode)

		var syncRes struct {
			Users []struct {
				UserID      string `json:"user_id"`
				PhoneNumber string `json:"phone_number"`
				DisplayName string `json:"display_name"`
			} `json:"users"`
		}
		require.NoError(t, json.NewDecoder(syncResp.Body).Decode(&syncRes))
		assert.Len(t, syncRes.Users, 3)

		phones := make(map[string]bool)
		for _, u := range syncRes.Users {
			assert.NotEmpty(t, u.UserID)
			assert.Regexp(t, `^\+[0-9]+$`, u.PhoneNumber, "phone_number should be normalized")
			phones[u.PhoneNumber] = true
		}
		assert.True(t, phones["+491111111111"])
		assert.True(t, phones["+49222222222"])
		assert.True(t, phones["+49333333333"])
	})
}
