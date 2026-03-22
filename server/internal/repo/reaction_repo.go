package repo

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// ReactionRepo handles message reactions
type ReactionRepo interface {
	SetReaction(ctx context.Context, messageID, userID uuid.UUID, reaction string) error
	GetReactionsByMessageIDs(ctx context.Context, messageIDs []uuid.UUID, viewerUserID uuid.UUID) (map[uuid.UUID]ReactionSummary, error)
}

// ReactionSummary aggregates reactions for a message: emoji -> count, and viewer's reaction if any
type ReactionSummary struct {
	Counts     map[string]int // emoji -> count
	MyReaction string         // emoji if viewer reacted, else empty
}

type reactionRepo struct {
	db *sql.DB
}

// NewReactionRepo creates a new ReactionRepo
func NewReactionRepo(db *sql.DB) ReactionRepo {
	return &reactionRepo{db: db}
}

// SetReaction upserts a reaction. One user per message; overwrites previous.
func (r *reactionRepo) SetReaction(ctx context.Context, messageID, userID uuid.UUID, reaction string) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO message_reactions (message_id, user_id, reaction)
		VALUES ($1, $2, $3)
		ON CONFLICT (message_id, user_id) DO UPDATE SET reaction = $3, created_at = now()
	`, messageID, userID, reaction)
	if err != nil {
		return fmt.Errorf("set reaction: %w", err)
	}
	return nil
}

// GetReactionsByMessageIDs returns aggregated reactions for the given messages.
func (r *reactionRepo) GetReactionsByMessageIDs(ctx context.Context, messageIDs []uuid.UUID, viewerUserID uuid.UUID) (map[uuid.UUID]ReactionSummary, error) {
	if len(messageIDs) == 0 {
		return map[uuid.UUID]ReactionSummary{}, nil
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT message_id, user_id, reaction FROM message_reactions
		WHERE message_id = ANY($1::uuid[])
	`, pq.Array(messageIDs))
	if err != nil {
		return nil, fmt.Errorf("get reactions: %w", err)
	}
	defer rows.Close()

	type row struct {
		msgID   uuid.UUID
		userID  uuid.UUID
		reaction string
	}
	var data []row
	for rows.Next() {
		var x row
		if err := rows.Scan(&x.msgID, &x.userID, &x.reaction); err != nil {
			return nil, err
		}
		data = append(data, x)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	result := make(map[uuid.UUID]ReactionSummary)
	for _, d := range data {
		s := result[d.msgID]
		if s.Counts == nil {
			s.Counts = make(map[string]int)
		}
		s.Counts[d.reaction]++
		if d.userID == viewerUserID {
			s.MyReaction = d.reaction
		}
		result[d.msgID] = s
	}
	return result, nil
}
