package repo

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/signalix/server/internal/model"
)

// MessageRepo defines the interface for message repository operations
type MessageRepo interface {
	CreateMessage(ctx context.Context, conversationID uuid.UUID, senderUserID uuid.UUID, ciphertext []byte, preview string, replyToID *uuid.UUID) (model.Message, error)
	CreateAudioMessage(ctx context.Context, conversationID uuid.UUID, senderUserID uuid.UUID, audioURL string, durationMs int, mime string) (model.Message, error)
	CreateImageMessage(ctx context.Context, conversationID uuid.UUID, senderUserID uuid.UUID, imageURL string, replyToID *uuid.UUID) (model.Message, error)
	// ListMessages returns messages for a conversation, newest first. Excludes messages hidden for callerUserID.
	ListMessages(ctx context.Context, conversationID uuid.UUID, callerUserID uuid.UUID, limit int, beforeSentAt *time.Time) ([]model.Message, error)
	// SearchMessages returns text messages in a conversation matching query in body_preview.
	SearchMessages(ctx context.Context, conversationID uuid.UUID, callerUserID uuid.UUID, query string) ([]model.Message, error)
	// DeleteForEveryone marks a message as deleted for everyone. Caller must be sender.
	DeleteForEveryone(ctx context.Context, messageID uuid.UUID, callerID uuid.UUID) (model.Message, error)
	// HideForMe inserts into message_hidden so the message is excluded for that user.
	HideForMe(ctx context.Context, messageID uuid.UUID, userID uuid.UUID) error
	// HideConversationForMe inserts all conversation messages into message_hidden for user.
	HideConversationForMe(ctx context.Context, conversationID uuid.UUID, userID uuid.UUID) error
	// GetMessage fetches a message by ID.
	GetMessage(ctx context.Context, messageID uuid.UUID) (model.Message, error)
	// UpdateMessage updates body of a text message. Caller must be sender; message must not be deleted.
	UpdateMessage(ctx context.Context, messageID uuid.UUID, callerID uuid.UUID, ciphertext []byte, preview string) (model.Message, error)
}

type messageRepo struct {
	db *sql.DB
}

// NewMessageRepo creates a new MessageRepo instance
func NewMessageRepo(db *sql.DB) MessageRepo {
	return &messageRepo{db: db}
}

// scanMessage scans a full message row including audio, deletion, and status columns.
func scanMessage(row interface {
	Scan(dest ...interface{}) error
}) (model.Message, error) {
	var m model.Message
	var idStr, convStr, senderStr string
	var audioURL sql.NullString
	var audioDurationMs sql.NullInt64
	var audioMime sql.NullString
	var deletedAt sql.NullTime
	var readAt sql.NullTime
	var editedAt sql.NullTime
	var replyToID sql.NullString
	var replyToPreview sql.NullString
	err := row.Scan(
		&idStr, &convStr, &senderStr, &m.SentAt,
		&m.BodyCiphertext, &m.BodyPreview,
		&m.MsgType, &audioURL, &audioDurationMs, &audioMime,
		&m.DeletedForEveryone, &deletedAt,
		&m.Status, &readAt, &editedAt,
		&replyToID, &replyToPreview,
	)
	if err != nil {
		return model.Message{}, err
	}
	m.ID, _ = uuid.Parse(idStr)
	m.ConversationID, _ = uuid.Parse(convStr)
	m.SenderUserID, _ = uuid.Parse(senderStr)
	if audioURL.Valid {
		m.AudioURL = &audioURL.String
	}
	if audioDurationMs.Valid {
		v := int(audioDurationMs.Int64)
		m.AudioDurationMs = &v
	}
	if audioMime.Valid {
		m.AudioMime = &audioMime.String
	}
	if deletedAt.Valid {
		m.DeletedAt = &deletedAt.Time
	}
	if readAt.Valid {
		m.ReadAt = &readAt.Time
	}
	if m.Status == "" {
		m.Status = "sent"
	}
	if editedAt.Valid {
		m.EditedAt = &editedAt.Time
	}
	if replyToID.Valid {
		rid, _ := uuid.Parse(replyToID.String)
		m.ReplyToID = &rid
	}
	if replyToPreview.Valid {
		m.ReplyToPreview = replyToPreview.String
	}
	return m, nil
}

const msgSelectCols = `id, conversation_id, sender_user_id, sent_at, body_ciphertext, body_preview, msg_type, audio_url, audio_duration_ms, audio_mime, deleted_for_everyone, deleted_at, status, read_at, edited_at, reply_to_id, (SELECT body_preview FROM messages r WHERE r.id = messages.reply_to_id) AS reply_to_preview`

// CreateMessage inserts a new text message and returns the created record.
func (r *messageRepo) CreateMessage(ctx context.Context, conversationID uuid.UUID, senderUserID uuid.UUID, ciphertext []byte, preview string, replyToID *uuid.UUID) (model.Message, error) {
	query := `INSERT INTO messages (conversation_id, sender_user_id, body_ciphertext, body_preview, msg_type, reply_to_id)
		VALUES ($1, $2, $3, $4, 'text', $5)
		RETURNING id, conversation_id, sender_user_id, sent_at, body_ciphertext, body_preview, msg_type, audio_url, audio_duration_ms, audio_mime, deleted_for_everyone, deleted_at, status, read_at, edited_at, reply_to_id,
		(SELECT body_preview FROM messages m2 WHERE m2.id = messages.reply_to_id)`
	var row *sql.Row
	if replyToID != nil {
		row = r.db.QueryRowContext(ctx, query, conversationID, senderUserID, ciphertext, preview, *replyToID)
	} else {
		row = r.db.QueryRowContext(ctx, query, conversationID, senderUserID, ciphertext, preview, nil)
	}
	m, err := scanMessageSimple(row)
	if err != nil {
		return model.Message{}, fmt.Errorf("create message: %w", err)
	}
	return m, nil
}

// scanMessageSimple scans msg cols for INSERT RETURNING (includes reply_to subquery).
func scanMessageSimple(row *sql.Row) (model.Message, error) {
	var m model.Message
	var idStr, convStr, senderStr string
	var audioURL sql.NullString
	var audioDurationMs sql.NullInt64
	var audioMime sql.NullString
	var deletedAt sql.NullTime
	var readAt sql.NullTime
	var editedAt sql.NullTime
	var replyToID sql.NullString
	var replyToPreview sql.NullString
	err := row.Scan(
		&idStr, &convStr, &senderStr, &m.SentAt,
		&m.BodyCiphertext, &m.BodyPreview,
		&m.MsgType, &audioURL, &audioDurationMs, &audioMime,
		&m.DeletedForEveryone, &deletedAt,
		&m.Status, &readAt, &editedAt,
		&replyToID, &replyToPreview,
	)
	if err != nil {
		return model.Message{}, err
	}
	m.ID, _ = uuid.Parse(idStr)
	m.ConversationID, _ = uuid.Parse(convStr)
	m.SenderUserID, _ = uuid.Parse(senderStr)
	if audioURL.Valid {
		m.AudioURL = &audioURL.String
	}
	if audioDurationMs.Valid {
		v := int(audioDurationMs.Int64)
		m.AudioDurationMs = &v
	}
	if audioMime.Valid {
		m.AudioMime = &audioMime.String
	}
	if deletedAt.Valid {
		m.DeletedAt = &deletedAt.Time
	}
	if readAt.Valid {
		m.ReadAt = &readAt.Time
	}
	if editedAt.Valid {
		m.EditedAt = &editedAt.Time
	}
	if replyToID.Valid {
		rid, _ := uuid.Parse(replyToID.String)
		m.ReplyToID = &rid
	}
	if replyToPreview.Valid {
		m.ReplyToPreview = replyToPreview.String
	}
	if m.Status == "" {
		m.Status = "sent"
	}
	return m, nil
}

// CreateAudioMessage inserts a new audio message and returns the created record.
// body_ciphertext is stored as an empty byte slice (audio payload lives at audio_url).
func (r *messageRepo) CreateAudioMessage(ctx context.Context, conversationID uuid.UUID, senderUserID uuid.UUID, audioURL string, durationMs int, mime string) (model.Message, error) {
	row := r.db.QueryRowContext(ctx, `
		INSERT INTO messages (conversation_id, sender_user_id, body_ciphertext, body_preview, msg_type, audio_url, audio_duration_ms, audio_mime)
		VALUES ($1, $2, $3, $4, 'audio', $5, $6, $7)
		RETURNING `+msgSelectCols,
		conversationID, senderUserID,
		[]byte{}, "Voice message", // body_ciphertext placeholder, body_preview
		audioURL, durationMs, mime,
	)
	m, err := scanMessage(row)
	if err != nil {
		return model.Message{}, fmt.Errorf("create audio message: %w", err)
	}
	return m, nil
}

// CreateImageMessage inserts an image message. body_preview = imageURL, body_ciphertext empty.
func (r *messageRepo) CreateImageMessage(ctx context.Context, conversationID uuid.UUID, senderUserID uuid.UUID, imageURL string, replyToID *uuid.UUID) (model.Message, error) {
	query := `INSERT INTO messages (conversation_id, sender_user_id, body_ciphertext, body_preview, msg_type, reply_to_id)
		VALUES ($1, $2, $3, $4, 'image', $5)
		RETURNING id, conversation_id, sender_user_id, sent_at, body_ciphertext, body_preview, msg_type, audio_url, audio_duration_ms, audio_mime, deleted_for_everyone, deleted_at, status, read_at, edited_at, reply_to_id,
		(SELECT body_preview FROM messages m2 WHERE m2.id = messages.reply_to_id)`
	var row *sql.Row
	if replyToID != nil {
		row = r.db.QueryRowContext(ctx, query, conversationID, senderUserID, []byte{}, imageURL, *replyToID)
	} else {
		row = r.db.QueryRowContext(ctx, query, conversationID, senderUserID, []byte{}, imageURL, nil)
	}
	m, err := scanMessage(row)
	if err != nil {
		return model.Message{}, fmt.Errorf("create image message: %w", err)
	}
	return m, nil
}

// MarkIncomingAsRead updates incoming messages (sender != callerUserID) with status in ('sent','delivered') to status='read'.
func (r *messageRepo) MarkIncomingAsRead(ctx context.Context, conversationID uuid.UUID, callerUserID uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE messages
		SET status = 'read', read_at = now()
		WHERE conversation_id = $1 AND sender_user_id != $2 AND status IN ('sent', 'delivered')`,
		conversationID, callerUserID,
	)
	return err
}

// ListMessages returns messages for a conversation, newest first. Excludes messages hidden for callerUserID.
// Marks incoming messages as read when recipient fetches.
func (r *messageRepo) ListMessages(ctx context.Context, conversationID uuid.UUID, callerUserID uuid.UUID, limit int, beforeSentAt *time.Time) ([]model.Message, error) {
	if limit <= 0 {
		limit = 50
	}

	if err := r.MarkIncomingAsRead(ctx, conversationID, callerUserID); err != nil {
		return nil, fmt.Errorf("mark incoming as read: %w", err)
	}

	query := `SELECT ` + msgSelectCols + ` FROM messages
		WHERE conversation_id = $1
		AND NOT EXISTS (SELECT 1 FROM message_hidden h WHERE h.message_id = messages.id AND h.user_id = $2)`
	args := []interface{}{conversationID, callerUserID}
	argIdx := 3
	if beforeSentAt != nil {
		query += fmt.Sprintf(` AND sent_at < $%d`, argIdx)
		args = append(args, *beforeSentAt)
		argIdx++
	}
	query += fmt.Sprintf(` ORDER BY sent_at DESC LIMIT $%d`, argIdx)
	args = append(args, limit)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list messages: %w", err)
	}
	defer rows.Close()

	var msgs []model.Message
	for rows.Next() {
		m, err := scanMessage(rows)
		if err != nil {
			return nil, fmt.Errorf("scan message: %w", err)
		}
		msgs = append(msgs, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list messages rows: %w", err)
	}
	return msgs, nil
}

// SearchMessages returns text messages in a conversation where body_preview matches query (case-insensitive).
func (r *messageRepo) SearchMessages(ctx context.Context, conversationID uuid.UUID, callerUserID uuid.UUID, query string) ([]model.Message, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, nil
	}
	// Escape % and _ for ILIKE to prevent pattern injection
	pattern := "%" + strings.ReplaceAll(strings.ReplaceAll(query, `\`, `\\`), "%", `\%`)
	pattern = strings.ReplaceAll(pattern, "_", `\_`)
	pattern = pattern + "%"

	rows, err := r.db.QueryContext(ctx, `
		SELECT `+msgSelectCols+` FROM messages
		WHERE conversation_id = $1
		AND (msg_type = 'text' OR msg_type = '' OR msg_type IS NULL)
		AND body_preview ILIKE $2
		AND NOT EXISTS (SELECT 1 FROM message_hidden h WHERE h.message_id = messages.id AND h.user_id = $3)
		ORDER BY sent_at DESC
		LIMIT 100
	`, conversationID, pattern, callerUserID)
	if err != nil {
		return nil, fmt.Errorf("search messages: %w", err)
	}
	defer rows.Close()

	var msgs []model.Message
	for rows.Next() {
		m, err := scanMessage(rows)
		if err != nil {
			return nil, fmt.Errorf("scan message: %w", err)
		}
		msgs = append(msgs, m)
	}
	return msgs, rows.Err()
}

// DeleteForEveryone marks a message as deleted for everyone. Caller must be sender.
func (r *messageRepo) DeleteForEveryone(ctx context.Context, messageID uuid.UUID, callerID uuid.UUID) (model.Message, error) {
	row := r.db.QueryRowContext(ctx, `
		UPDATE messages
		SET body_ciphertext = $1, body_preview = $2, deleted_for_everyone = true, deleted_at = now()
		WHERE id = $3 AND sender_user_id = $4
		RETURNING `+msgSelectCols,
		[]byte{}, "This message was deleted", messageID, callerID,
	)
	m, err := scanMessage(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return model.Message{}, fmt.Errorf("message not found or not sender")
		}
		return model.Message{}, fmt.Errorf("delete for everyone: %w", err)
	}
	return m, nil
}

// HideForMe inserts into message_hidden so the message is excluded for that user.
func (r *messageRepo) HideForMe(ctx context.Context, messageID uuid.UUID, userID uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO message_hidden (message_id, user_id) VALUES ($1, $2)
		ON CONFLICT (message_id, user_id) DO NOTHING`,
		messageID, userID,
	)
	if err != nil {
		return fmt.Errorf("hide for me: %w", err)
	}
	return nil
}

// HideConversationForMe hides all messages in a conversation for a specific user.
func (r *messageRepo) HideConversationForMe(ctx context.Context, conversationID uuid.UUID, userID uuid.UUID) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO message_hidden (message_id, user_id)
		SELECT id, $2
		FROM messages
		WHERE conversation_id = $1
		ON CONFLICT (message_id, user_id) DO NOTHING`,
		conversationID, userID,
	)
	if err != nil {
		return fmt.Errorf("hide conversation for me: %w", err)
	}
	return nil
}

// UpdateMessage updates body of a text message. Caller must be sender; message must not be deleted.
func (r *messageRepo) UpdateMessage(ctx context.Context, messageID uuid.UUID, callerID uuid.UUID, ciphertext []byte, preview string) (model.Message, error) {
	row := r.db.QueryRowContext(ctx, `
		UPDATE messages
		SET body_ciphertext = $1, body_preview = $2, edited_at = now()
		WHERE id = $3 AND sender_user_id = $4 AND deleted_for_everyone = false AND msg_type = 'text'
		RETURNING `+msgSelectCols,
		ciphertext, preview, messageID, callerID,
	)
	m, err := scanMessage(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return model.Message{}, fmt.Errorf("message not found or not editable")
		}
		return model.Message{}, fmt.Errorf("update message: %w", err)
	}
	return m, nil
}

// GetMessage fetches a message by ID.
func (r *messageRepo) GetMessage(ctx context.Context, messageID uuid.UUID) (model.Message, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+msgSelectCols+` FROM messages WHERE id = $1`, messageID)
	m, err := scanMessage(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return model.Message{}, fmt.Errorf("message not found")
		}
		return model.Message{}, err
	}
	return m, nil
}
