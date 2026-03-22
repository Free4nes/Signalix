package push

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

const expoPushURL = "https://exp.host/--/api/v2/push/send"

// ExpoMessage is a single push notification for Expo Push API
type ExpoMessage struct {
	To        string                 `json:"to"`
	Title     string                 `json:"title,omitempty"`
	Body      string                 `json:"body,omitempty"`
	Sound     string                 `json:"sound,omitempty"`
	Data      map[string]interface{} `json:"data,omitempty"`
	ChannelID string                 `json:"channelId,omitempty"` // Android: matches app's "default" channel
}

// expoTicket is the response format from Expo push API
type expoTicket struct {
	Status  string `json:"status"`
	ID      string `json:"id,omitempty"`
	Message string `json:"message,omitempty"`
	Details *struct {
		Error string `json:"error,omitempty"`
	} `json:"details,omitempty"`
}

// expoResponse is the full response from Expo push API
type expoResponse struct {
	Data   []expoTicket     `json:"data,omitempty"`
	Errors []expoErrDetail  `json:"errors,omitempty"`
}

type expoErrDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// OnInvalidToken is called when Expo reports DeviceNotRegistered for a token.
// Implementations should mark the token as invalid in the database.
type OnInvalidToken func(tokens []string)

// SendExpoPush sends push notifications to the given Expo tokens.
// Runs asynchronously; logs errors but does not block.
// If onInvalidToken is non-nil and Expo returns DeviceNotRegistered, it is called with those tokens.
func SendExpoPush(ctx context.Context, tokens []string, title, body string, data map[string]interface{}, onInvalidToken OnInvalidToken) {
	if len(tokens) == 0 {
		return
	}
	tokensCopy := make([]string, len(tokens))
	copy(tokensCopy, tokens)
	var dataCopy map[string]interface{}
	if data != nil {
		dataCopy = make(map[string]interface{})
		for k, v := range data {
			dataCopy[k] = v
		}
	}
	go func() {
		bgCtx := context.Background()
		const batchSize = 100
		for i := 0; i < len(tokensCopy); i += batchSize {
			end := i + batchSize
			if end > len(tokensCopy) {
				end = len(tokensCopy)
			}
			batch := tokensCopy[i:end]
			messages := make([]ExpoMessage, 0, len(batch))
			for _, t := range batch {
				msg := ExpoMessage{
					To:    t,
					Title: title,
					Body:  body,
					Sound: "default",
					Data:  dataCopy,
				}
				// Android uses "default" channel (created in app via setNotificationChannelAsync)
				msg.ChannelID = "default"
				messages = append(messages, msg)
			}
			bodyBytes, err := json.Marshal(messages)
			if err != nil {
				log.Printf("PUSH_ERROR marshal: %v", err)
				continue
			}
			req, err := http.NewRequestWithContext(bgCtx, http.MethodPost, expoPushURL, bytes.NewReader(bodyBytes))
			if err != nil {
				log.Printf("PUSH_ERROR new request: %v", err)
				continue
			}
			req.Header.Set("Accept", "application/json")
			req.Header.Set("Content-Type", "application/json")
			client := &http.Client{Timeout: 10 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				log.Printf("PUSH_ERROR send: %v", err)
				continue
			}
			respBody, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				log.Printf("PUSH_ERROR expo API status %d body=%s", resp.StatusCode, string(respBody))
				continue
			}

			var expoResp expoResponse
			if err := json.Unmarshal(respBody, &expoResp); err != nil {
				log.Printf("PUSH_ERROR parse response: %v", err)
				log.Printf("PUSH_SENT tokens=%d (receipt check skipped)", len(batch))
				continue
			}

			if len(expoResp.Errors) > 0 {
				for _, e := range expoResp.Errors {
					log.Printf("PUSH_ERROR request error: %s %s", e.Code, e.Message)
				}
				continue
			}

			var invalidTokens []string
			for j, ticket := range expoResp.Data {
				if j >= len(batch) {
					break
				}
				if ticket.Status == "error" && ticket.Details != nil && ticket.Details.Error == "DeviceNotRegistered" {
					invalidTokens = append(invalidTokens, batch[j])
					log.Printf("PUSH_ERROR DeviceNotRegistered token=%s", batch[j])
				}
			}
			if len(invalidTokens) > 0 && onInvalidToken != nil {
				onInvalidToken(invalidTokens)
			}
			log.Printf("PUSH_SENT tokens=%d ok=%d invalid=%d", len(batch), len(batch)-len(invalidTokens), len(invalidTokens))
		}
	}()
}

// SendNewMessagePush sends a push notification for a new chat message.
// recipientTokens: Expo tokens for the recipient user(s)
// senderName: display name of the sender (e.g. "Max" or phone)
// preview: message preview text
// conversationID: for deep link
func SendNewMessagePush(ctx context.Context, recipientTokens []string, senderName, preview, conversationID string, onInvalidToken OnInvalidToken) {
	title := "Neuer Chat"
	body := fmt.Sprintf("%s: %s", senderName, preview)
	if len(body) > 150 {
		body = body[:147] + "..."
	}
	data := map[string]interface{}{"conversationId": conversationID}
	SendExpoPush(ctx, recipientTokens, title, body, data, onInvalidToken)
}
