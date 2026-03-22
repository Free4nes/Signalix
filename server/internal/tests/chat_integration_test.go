package tests

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// chat API response types
type createConversationAPIResponse struct {
	ID           string   `json:"id"`
	IsGroup      bool     `json:"is_group"`
	Title        *string  `json:"title,omitempty"`
	DisplayTitle string   `json:"display_title"`
	Members      []string `json:"members"`
}

type conversationAPIResponse struct {
	ID                 string   `json:"id"`
	IsGroup            bool     `json:"is_group"`
	Title              *string  `json:"title,omitempty"`
	DisplayTitle       string   `json:"display_title"`
	Members            []string `json:"members"`
	LastMessagePreview string   `json:"last_message_preview"`
	LastMessageAt      *string  `json:"last_message_at,omitempty"`
}

type messageAPIResponse struct {
	ID             string `json:"id"`
	SenderUserID   string `json:"sender_user_id"`
	SentAt         string `json:"sent_at"`
	BodyCiphertext string `json:"body_ciphertext"`
	BodyPreview    string `json:"body_preview"`
}

// loginAndGetTokenAndUserID logs in and returns (accessToken, userID)
func loginAndGetTokenAndUserID(t *testing.T, client *http.Client, baseURL, phone string) (string, string) {
	t.Helper()
	token := loginAndGetToken(t, client, baseURL, phone)
	req, _ := http.NewRequest(http.MethodGet, baseURL+"/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	var me meResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&me))
	require.NotEmpty(t, me.ID)
	return token, me.ID
}

func TestChatIntegration(t *testing.T) {
	if os.Getenv("DATABASE_URL") == "" {
		t.Skip("DATABASE_URL not set; skipping integration test")
	}

	ts := newTestServer(t)
	baseURL := ts.BaseURL()
	client := ts.Server.Client()

	t.Run("C1_UserACreatesConversationWithUserB_BothCanList", func(t *testing.T) {
		ts.TruncateAuth(t)
		tokenA, userAID := loginAndGetTokenAndUserID(t, client, baseURL, "+496111111111")
		tokenB, userBID := loginAndGetTokenAndUserID(t, client, baseURL, "+496222222222")

		// User A creates conversation with User B
		body, _ := json.Marshal(map[string][]string{"member_user_ids": {userAID, userBID}})
		req, _ := http.NewRequest(http.MethodPost, baseURL+"/conversations", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tokenA)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusCreated, resp.StatusCode)
		var createRes createConversationAPIResponse
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&createRes))
		require.NotEmpty(t, createRes.ID)
		assert.False(t, createRes.IsGroup)
		assert.Equal(t, "+496222222222", createRes.DisplayTitle)

		// User A lists conversations
		listReqA, _ := http.NewRequest(http.MethodGet, baseURL+"/conversations", nil)
		listReqA.Header.Set("Authorization", "Bearer "+tokenA)
		listRespA, err := client.Do(listReqA)
		require.NoError(t, err)
		defer listRespA.Body.Close()
		assert.Equal(t, http.StatusOK, listRespA.StatusCode)
		var convsA []conversationAPIResponse
		require.NoError(t, json.NewDecoder(listRespA.Body).Decode(&convsA))
		require.Len(t, convsA, 1)
		assert.Equal(t, createRes.ID, convsA[0].ID)
		assert.Len(t, convsA[0].Members, 2)

		// User B lists conversations
		listReqB, _ := http.NewRequest(http.MethodGet, baseURL+"/conversations", nil)
		listReqB.Header.Set("Authorization", "Bearer "+tokenB)
		listRespB, err := client.Do(listReqB)
		require.NoError(t, err)
		defer listRespB.Body.Close()
		assert.Equal(t, http.StatusOK, listRespB.StatusCode)
		var convsB []conversationAPIResponse
		require.NoError(t, json.NewDecoder(listRespB.Body).Decode(&convsB))
		require.Len(t, convsB, 1)
		assert.Equal(t, createRes.ID, convsB[0].ID)
	})

	t.Run("C2_UserCCannotAccessMessages_403", func(t *testing.T) {
		ts.TruncateAuth(t)
		tokenA, userAID := loginAndGetTokenAndUserID(t, client, baseURL, "+497111111111")
		_, userBID := loginAndGetTokenAndUserID(t, client, baseURL, "+497222222222")
		tokenC := loginAndGetToken(t, client, baseURL, "+497333333333")

		// User A creates conversation with User B
		body, _ := json.Marshal(map[string][]string{"member_user_ids": {userAID, userBID}})
		req, _ := http.NewRequest(http.MethodPost, baseURL+"/conversations", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tokenA)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		require.NoError(t, err)
		var createRes createConversationAPIResponse
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&createRes))
		resp.Body.Close()

		// User C (not a member) tries to list messages -> 403
		listReq, _ := http.NewRequest(http.MethodGet, baseURL+"/conversations/"+createRes.ID+"/messages?limit=50", nil)
		listReq.Header.Set("Authorization", "Bearer "+tokenC)
		listResp, err := client.Do(listReq)
		require.NoError(t, err)
		defer listResp.Body.Close()
		assert.Equal(t, http.StatusForbidden, listResp.StatusCode)
	})

	t.Run("C3_PostMessage_ListIncludesIt", func(t *testing.T) {
		ts.TruncateAuth(t)
		tokenA, userAID := loginAndGetTokenAndUserID(t, client, baseURL, "+498111111111")
		_, userBID := loginAndGetTokenAndUserID(t, client, baseURL, "+498222222222")

		// Create conversation
		body, _ := json.Marshal(map[string][]string{"member_user_ids": {userAID, userBID}})
		req, _ := http.NewRequest(http.MethodPost, baseURL+"/conversations", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tokenA)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		require.NoError(t, err)
		var createRes createConversationAPIResponse
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&createRes))
		resp.Body.Close()
		convID := createRes.ID

		// User A posts a message
		ciphertext := []byte("opaque-encrypted-hello")
		msgBody, _ := json.Marshal(map[string]string{
			"body_ciphertext_base64": base64.StdEncoding.EncodeToString(ciphertext),
			"body_preview":           "Hello!",
		})
		postReq, _ := http.NewRequest(http.MethodPost, baseURL+"/conversations/"+convID+"/messages", bytes.NewReader(msgBody))
		postReq.Header.Set("Authorization", "Bearer "+tokenA)
		postReq.Header.Set("Content-Type", "application/json")
		postResp, err := client.Do(postReq)
		require.NoError(t, err)
		defer postResp.Body.Close()
		assert.Equal(t, http.StatusCreated, postResp.StatusCode)
		var createdMsg messageAPIResponse
		require.NoError(t, json.NewDecoder(postResp.Body).Decode(&createdMsg))
		assert.Equal(t, userAID, createdMsg.SenderUserID)
		assert.Equal(t, "Hello!", createdMsg.BodyPreview)
		assert.NotEmpty(t, createdMsg.ID)

		// List messages includes the new message
		listReq, _ := http.NewRequest(http.MethodGet, baseURL+"/conversations/"+convID+"/messages?limit=50", nil)
		listReq.Header.Set("Authorization", "Bearer "+tokenA)
		listResp, err := client.Do(listReq)
		require.NoError(t, err)
		defer listResp.Body.Close()
		assert.Equal(t, http.StatusOK, listResp.StatusCode)
		var msgs []messageAPIResponse
		require.NoError(t, json.NewDecoder(listResp.Body).Decode(&msgs))
		require.Len(t, msgs, 1)
		assert.Equal(t, createdMsg.ID, msgs[0].ID)
		assert.Equal(t, userAID, msgs[0].SenderUserID)
		assert.Equal(t, base64.StdEncoding.EncodeToString(ciphertext), msgs[0].BodyCiphertext)
		assert.Equal(t, "Hello!", msgs[0].BodyPreview)
	})

	t.Run("C4_CreateGroupWithABCTitle_AllThreeCanList", func(t *testing.T) {
		ts.TruncateAuth(t)
		tokenA, userAID := loginAndGetTokenAndUserID(t, client, baseURL, "+499111111111")
		tokenB, userBID := loginAndGetTokenAndUserID(t, client, baseURL, "+499222222222")
		tokenC, userCID := loginAndGetTokenAndUserID(t, client, baseURL, "+499333333333")

		body, _ := json.Marshal(map[string]interface{}{
			"member_user_ids": []string{userAID, userBID, userCID},
			"title":           "Team Alpha",
		})
		req, _ := http.NewRequest(http.MethodPost, baseURL+"/conversations", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tokenA)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusCreated, resp.StatusCode)
		var createRes createConversationAPIResponse
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&createRes))
		require.NotEmpty(t, createRes.ID)
		assert.True(t, createRes.IsGroup)
		require.NotNil(t, createRes.Title)
		assert.Equal(t, "Team Alpha", *createRes.Title)
		assert.Equal(t, "Team Alpha", createRes.DisplayTitle)
		assert.Len(t, createRes.Members, 3)

		for _, tok := range []string{tokenA, tokenB, tokenC} {
			listReq, _ := http.NewRequest(http.MethodGet, baseURL+"/conversations", nil)
			listReq.Header.Set("Authorization", "Bearer "+tok)
			listResp, err := client.Do(listReq)
			require.NoError(t, err)
			assert.Equal(t, http.StatusOK, listResp.StatusCode)
			var convs []conversationAPIResponse
			require.NoError(t, json.NewDecoder(listResp.Body).Decode(&convs))
			listResp.Body.Close()
			require.Len(t, convs, 1)
			assert.Equal(t, createRes.ID, convs[0].ID)
			assert.True(t, convs[0].IsGroup)
			assert.Equal(t, "Team Alpha", convs[0].DisplayTitle)
		}
	})

	t.Run("C5_NonMemberCannotReadGroupMessages_403", func(t *testing.T) {
		ts.TruncateAuth(t)
		tokenA, userAID := loginAndGetTokenAndUserID(t, client, baseURL, "+500111111111")
		_, userBID := loginAndGetTokenAndUserID(t, client, baseURL, "+500222222222")
		_, userCID := loginAndGetTokenAndUserID(t, client, baseURL, "+500333333333")
		tokenD := loginAndGetToken(t, client, baseURL, "+500444444444")

		body, _ := json.Marshal(map[string]interface{}{
			"member_user_ids": []string{userAID, userBID, userCID},
			"title":           "Secret Group",
		})
		req, _ := http.NewRequest(http.MethodPost, baseURL+"/conversations", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tokenA)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		require.NoError(t, err)
		var createRes createConversationAPIResponse
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&createRes))
		resp.Body.Close()

		listReq, _ := http.NewRequest(http.MethodGet, baseURL+"/conversations/"+createRes.ID+"/messages?limit=50", nil)
		listReq.Header.Set("Authorization", "Bearer "+tokenD)
		listResp, err := client.Do(listReq)
		require.NoError(t, err)
		defer listResp.Body.Close()
		assert.Equal(t, http.StatusForbidden, listResp.StatusCode)
	})

	t.Run("C6_SendMessageInGroup_ListShowsLastMessagePreview", func(t *testing.T) {
		ts.TruncateAuth(t)
		tokenA, userAID := loginAndGetTokenAndUserID(t, client, baseURL, "+501111111111")
		tokenB, userBID := loginAndGetTokenAndUserID(t, client, baseURL, "+501222222222")
		tokenC, userCID := loginAndGetTokenAndUserID(t, client, baseURL, "+501333333333")

		body, _ := json.Marshal(map[string]interface{}{
			"member_user_ids": []string{userAID, userBID, userCID},
			"title":           "Group Chat",
		})
		req, _ := http.NewRequest(http.MethodPost, baseURL+"/conversations", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tokenA)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		require.NoError(t, err)
		var createRes createConversationAPIResponse
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&createRes))
		resp.Body.Close()
		convID := createRes.ID

		msgBody, _ := json.Marshal(map[string]string{
			"body_ciphertext_base64": base64.StdEncoding.EncodeToString([]byte("Hi group!")),
			"body_preview":           "Hi group!",
		})
		postReq, _ := http.NewRequest(http.MethodPost, baseURL+"/conversations/"+convID+"/messages", bytes.NewReader(msgBody))
		postReq.Header.Set("Authorization", "Bearer "+tokenB)
		postReq.Header.Set("Content-Type", "application/json")
		postResp, err := client.Do(postReq)
		require.NoError(t, err)
		postResp.Body.Close()
		assert.Equal(t, http.StatusCreated, postResp.StatusCode)

		for _, tok := range []string{tokenA, tokenB, tokenC} {
			listReq, _ := http.NewRequest(http.MethodGet, baseURL+"/conversations", nil)
			listReq.Header.Set("Authorization", "Bearer "+tok)
			listResp, err := client.Do(listReq)
			require.NoError(t, err)
			var convs []conversationAPIResponse
			require.NoError(t, json.NewDecoder(listResp.Body).Decode(&convs))
			listResp.Body.Close()
			require.Len(t, convs, 1)
			assert.Equal(t, "Hi group!", convs[0].LastMessagePreview)
		}
	})

	t.Run("C7b_RateLimit_21stMessage_429", func(t *testing.T) {
		ts.TruncateAuth(t)
		tokenA, userAID := loginAndGetTokenAndUserID(t, client, baseURL, "+502111111111")
		_, userBID := loginAndGetTokenAndUserID(t, client, baseURL, "+502222222222")

		// Create conversation
		body, _ := json.Marshal(map[string][]string{"member_user_ids": {userAID, userBID}})
		req, _ := http.NewRequest(http.MethodPost, baseURL+"/conversations", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tokenA)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		require.NoError(t, err)
		var createRes createConversationAPIResponse
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&createRes))
		resp.Body.Close()
		convID := createRes.ID

		// Send 20 messages - all must succeed
		for i := 0; i < 20; i++ {
			msgBody, _ := json.Marshal(map[string]string{
				"body_ciphertext_base64": base64.StdEncoding.EncodeToString([]byte("msg")),
				"body_preview":           "msg",
			})
			postReq, _ := http.NewRequest(http.MethodPost, baseURL+"/conversations/"+convID+"/messages", bytes.NewReader(msgBody))
			postReq.Header.Set("Authorization", "Bearer "+tokenA)
			postReq.Header.Set("Content-Type", "application/json")
			postResp, err := client.Do(postReq)
			require.NoError(t, err)
			postResp.Body.Close()
			assert.Equal(t, http.StatusCreated, postResp.StatusCode, "message %d should be allowed", i+1)
		}

		// 21st message must be rejected with 429
		msgBody, _ := json.Marshal(map[string]string{
			"body_ciphertext_base64": base64.StdEncoding.EncodeToString([]byte("msg 21")),
			"body_preview":           "msg",
		})
		postReq, _ := http.NewRequest(http.MethodPost, baseURL+"/conversations/"+convID+"/messages", bytes.NewReader(msgBody))
		postReq.Header.Set("Authorization", "Bearer "+tokenA)
		postReq.Header.Set("Content-Type", "application/json")
		postResp, err := client.Do(postReq)
		require.NoError(t, err)
		defer postResp.Body.Close()
		assert.Equal(t, http.StatusTooManyRequests, postResp.StatusCode, "21st message must be rate limited")
		var errBody struct {
			Error      string `json:"error"`
			RetryAfter int    `json:"retry_after"`
		}
		require.NoError(t, json.NewDecoder(postResp.Body).Decode(&errBody))
		assert.Equal(t, "rate_limit_exceeded", errBody.Error)
		assert.GreaterOrEqual(t, errBody.RetryAfter, 1, "retry_after must be >= 1")
	})

	t.Run("C7_PhoneNormalization_LookupWithDifferentFormats", func(t *testing.T) {
		ts.TruncateAuth(t)
		// User A: create with +49 format
		tokenA, userAID := loginAndGetTokenAndUserID(t, client, baseURL, "+491111111111")
		// User B: create with 0049 format (request_otp normalizes, so DB gets +49)
		_, _ = loginAndGetTokenAndUserID(t, client, baseURL, "0049222222222")
		// User C: create with spaced format
		_, _ = loginAndGetTokenAndUserID(t, client, baseURL, "+49 33 333 3333")

		// Lookup user B with messy format - should find
		lookupBody, _ := json.Marshal(map[string]string{"phone_number": "0049 222 222 222"})
		lookupReq, _ := http.NewRequest(http.MethodPost, baseURL+"/contacts/lookup", bytes.NewReader(lookupBody))
		lookupReq.Header.Set("Authorization", "Bearer "+tokenA)
		lookupReq.Header.Set("Content-Type", "application/json")
		lookupResp, err := client.Do(lookupReq)
		require.NoError(t, err)
		defer lookupResp.Body.Close()
		assert.Equal(t, http.StatusOK, lookupResp.StatusCode)
		var lookupRes struct {
			UserID string `json:"user_id"`
		}
		require.NoError(t, json.NewDecoder(lookupResp.Body).Decode(&lookupRes))
		require.NotEmpty(t, lookupRes.UserID)

		// Create 1:1 chat via lookup - User A chats with B using messy phone format
		body, _ := json.Marshal(map[string]interface{}{
			"member_user_ids": []string{userAID, lookupRes.UserID},
		})
		convReq, _ := http.NewRequest(http.MethodPost, baseURL+"/conversations", bytes.NewReader(body))
		convReq.Header.Set("Authorization", "Bearer "+tokenA)
		convReq.Header.Set("Content-Type", "application/json")
		convResp, err := client.Do(convReq)
		require.NoError(t, err)
		defer convResp.Body.Close()
		assert.Equal(t, http.StatusCreated, convResp.StatusCode)
	})
}
