package repo

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/signalix/server/internal/model"
)

// ConversationRepo defines the interface for conversation repository operations
type ConversationRepo interface {
	CreateConversation(ctx context.Context, title *string, isGroup bool, memberUserIDs []uuid.UUID, projectID *uuid.UUID) (model.Conversation, error)
	FindByProjectAndMembers(ctx context.Context, projectID uuid.UUID, memberIDs []uuid.UUID) (model.Conversation, bool, error)
	GetConversationWithPreview(ctx context.Context, convID uuid.UUID, viewerUserID uuid.UUID) (model.ConversationWithPreview, error)
	ListConversationsForUser(ctx context.Context, userID uuid.UUID) ([]model.ConversationWithPreview, error)
	ListConversationsForUserByProject(ctx context.Context, userID uuid.UUID, projectID uuid.UUID) ([]model.ProjectConversationItem, error)
	IsMember(ctx context.Context, conversationID uuid.UUID, userID uuid.UUID) (bool, error)
	ListMembers(ctx context.Context, conversationID uuid.UUID) ([]uuid.UUID, error)
	// ListUsersWhoShareConversationWith returns all user IDs that share at least one conversation with the given user.
	ListUsersWhoShareConversationWith(ctx context.Context, userID uuid.UUID) ([]uuid.UUID, error)
	UpdateTitle(ctx context.Context, convID uuid.UUID, title *string) error
	AddMember(ctx context.Context, convID uuid.UUID, userID uuid.UUID) error
	RemoveMember(ctx context.Context, convID uuid.UUID, userID uuid.UUID) error
}

type conversationRepo struct {
	conn     Querier
	userRepo UserRepo
}

// NewConversationRepo creates a new ConversationRepo instance
func NewConversationRepo(db *sql.DB, userRepo UserRepo) ConversationRepo {
	return &conversationRepo{conn: db, userRepo: userRepo}
}

// NewConversationRepoWithConn creates a ConversationRepo using the given Querier (tx or db)
func NewConversationRepoWithConn(conn Querier, userRepo UserRepo) ConversationRepo {
	return &conversationRepo{conn: conn, userRepo: userRepo}
}

// CreateConversation creates a new conversation with the given members and returns the conversation
func (r *conversationRepo) CreateConversation(ctx context.Context, title *string, isGroup bool, memberUserIDs []uuid.UUID, projectID *uuid.UUID) (model.Conversation, error) {
	if len(memberUserIDs) == 0 {
		return model.Conversation{}, fmt.Errorf("at least one member is required")
	}

	var conn Querier
	var commitTx func() error
	if db, ok := r.conn.(*sql.DB); ok {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return model.Conversation{}, fmt.Errorf("begin tx: %w", err)
		}
		defer tx.Rollback()
		conn = tx
		commitTx = func() error { return tx.Commit() }
	} else {
		conn = r.conn
		commitTx = func() error { return nil }
	}

	var conv model.Conversation
	var idStr string
	var projectIDStr sql.NullString
	err := conn.QueryRowContext(ctx, `
		INSERT INTO conversations (created_at, is_group, title, project_id)
		VALUES (now(), $1, $2, $3)
		RETURNING id, created_at, is_group, title, project_id
	`, isGroup, title, projectID).Scan(&idStr, &conv.CreatedAt, &conv.IsGroup, &conv.Title, &projectIDStr)
	if projectIDStr.Valid && projectIDStr.String != "" {
		u, _ := uuid.Parse(projectIDStr.String)
		conv.ProjectID = &u
	}
	if err != nil {
		return model.Conversation{}, fmt.Errorf("insert conversation: %w", err)
	}
	conv.ID, _ = uuid.Parse(idStr)

	for _, uid := range memberUserIDs {
		_, err = conn.ExecContext(ctx, `
			INSERT INTO conversation_members (conversation_id, user_id)
			VALUES ($1, $2)
		`, conv.ID, uid)
		if err != nil {
			return model.Conversation{}, fmt.Errorf("insert member: %w", err)
		}
	}

	return conv, commitTx()
}

// FindByProjectAndMembers finds an existing conversation in the project with exactly the same members.
// Returns (conv, true, nil) if found, (zero, false, nil) if not found.
func (r *conversationRepo) FindByProjectAndMembers(ctx context.Context, projectID uuid.UUID, memberIDs []uuid.UUID) (model.Conversation, bool, error) {
	if len(memberIDs) == 0 {
		return model.Conversation{}, false, nil
	}
	sorted := make([]uuid.UUID, len(memberIDs))
	copy(sorted, memberIDs)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].String() < sorted[j].String() })

	var conv model.Conversation
	var idStr string
	var title sql.NullString
	var projectIDStr sql.NullString
	err := r.conn.QueryRowContext(ctx, `
		SELECT c.id, c.created_at, c.is_group, c.title, c.project_id
		FROM conversations c
		WHERE c.project_id = $1
		AND (SELECT array_agg(cm.user_id ORDER BY cm.user_id) FROM conversation_members cm WHERE cm.conversation_id = c.id) = $2::uuid[]
		LIMIT 1
	`, projectID, pq.Array(sorted)).Scan(&idStr, &conv.CreatedAt, &conv.IsGroup, &title, &projectIDStr)
	if err == sql.ErrNoRows {
		return model.Conversation{}, false, nil
	}
	if err != nil {
		return model.Conversation{}, false, fmt.Errorf("find by project and members: %w", err)
	}
	conv.ID, _ = uuid.Parse(idStr)
	if projectIDStr.Valid && projectIDStr.String != "" {
		u, _ := uuid.Parse(projectIDStr.String)
		conv.ProjectID = &u
	}
	if title.Valid {
		conv.Title = &title.String
	}
	return conv, true, nil
}

// GetConversationWithPreview returns a single conversation with display_title for the viewer
func (r *conversationRepo) GetConversationWithPreview(ctx context.Context, convID uuid.UUID, viewerUserID uuid.UUID) (model.ConversationWithPreview, error) {
	ok, err := r.IsMember(ctx, convID, viewerUserID)
	if err != nil || !ok {
		return model.ConversationWithPreview{}, fmt.Errorf("conversation not found")
	}
	var c model.Conversation
	var title sql.NullString
	var projectIDStr sql.NullString
	var projectName sql.NullString
	err = r.conn.QueryRowContext(ctx, `
		SELECT c.id, c.created_at, c.is_group, c.title, c.project_id, p.name
		FROM conversations c
		LEFT JOIN projects p ON p.id = c.project_id
		WHERE c.id = $1
	`, convID).Scan(&c.ID, &c.CreatedAt, &c.IsGroup, &title, &projectIDStr, &projectName)
	if err != nil {
		if err == sql.ErrNoRows {
			return model.ConversationWithPreview{}, fmt.Errorf("conversation not found")
		}
		return model.ConversationWithPreview{}, err
	}
	if title.Valid {
		c.Title = &title.String
	}
	if projectIDStr.Valid && projectIDStr.String != "" {
		u, _ := uuid.Parse(projectIDStr.String)
		c.ProjectID = &u
	}
	out := model.ConversationWithPreview{
		ID: c.ID, CreatedAt: c.CreatedAt, IsGroup: c.IsGroup, Title: c.Title,
		ProjectID: c.ProjectID, ProjectName: projectName.String,
	}
	members, _ := r.listMembers(ctx, c.ID)
	out.Members = members
	if c.IsGroup {
		if c.Title != nil && strings.TrimSpace(*c.Title) != "" {
			out.DisplayTitle = *c.Title
		} else {
			out.DisplayTitle = "Group"
		}
	} else {
		var otherID uuid.UUID
		for _, m := range members {
			if m != viewerUserID {
				otherID = m
				break
			}
		}
		if otherID != uuid.Nil {
			otherUser, err := r.userRepo.GetByID(ctx, otherID.String())
			if err == nil {
				if strings.TrimSpace(otherUser.DisplayName) != "" {
					out.DisplayTitle = otherUser.DisplayName
				} else {
					out.DisplayTitle = otherUser.PhoneNumber
				}
			} else {
				s := otherID.String()
				if len(s) >= 12 {
					out.DisplayTitle = s[:8] + "..." + s[len(s)-4:]
				} else {
					out.DisplayTitle = s
				}
			}
		} else {
			out.DisplayTitle = "Chat"
		}
	}
	return out, nil
}

// ListConversationsForUser returns conversations for the user with last_message_preview, last_message_at, is_group, title, display_title, project_id, project_name.
// Loads members and other-user profiles in bulk to avoid N+1.
func (r *conversationRepo) ListConversationsForUser(ctx context.Context, userID uuid.UUID) ([]model.ConversationWithPreview, error) {
	rows, err := r.conn.QueryContext(ctx, `
		WITH last_msgs AS (
			SELECT DISTINCT ON (conversation_id)
				conversation_id,
				body_preview,
				sent_at
			FROM messages
			WHERE NOT EXISTS (
				SELECT 1
				FROM message_hidden h
				WHERE h.message_id = messages.id AND h.user_id = $1
			)
			ORDER BY conversation_id, sent_at DESC
		)
		SELECT c.id, c.created_at, c.is_group, c.title, c.project_id, p.name, lm.body_preview, lm.sent_at
		FROM conversations c
		JOIN conversation_members cm ON cm.conversation_id = c.id AND cm.user_id = $1
		LEFT JOIN projects p ON p.id = c.project_id
		LEFT JOIN last_msgs lm ON lm.conversation_id = c.id
		ORDER BY lm.sent_at DESC NULLS LAST, c.created_at DESC
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("list conversations: %w", err)
	}
	defer rows.Close()

	type row struct {
		c model.ConversationWithPreview
	}
	var partial []row
	var convIDs []uuid.UUID
	for rows.Next() {
		var x row
		var idStr string
		var title sql.NullString
		var projectIDStr sql.NullString
		var projectName sql.NullString
		var preview sql.NullString
		var lastAt sql.NullTime
		if err := rows.Scan(&idStr, &x.c.CreatedAt, &x.c.IsGroup, &title, &projectIDStr, &projectName, &preview, &lastAt); err != nil {
			return nil, fmt.Errorf("scan conversation: %w", err)
		}
		x.c.ID, _ = uuid.Parse(idStr)
		if title.Valid {
			x.c.Title = &title.String
		}
		if projectIDStr.Valid && projectIDStr.String != "" {
			u, _ := uuid.Parse(projectIDStr.String)
			x.c.ProjectID = &u
		}
		x.c.ProjectName = projectName.String
		x.c.LastMessagePreview = preview.String
		if lastAt.Valid {
			x.c.LastMessageAt = &lastAt.Time
		}
		partial = append(partial, x)
		convIDs = append(convIDs, x.c.ID)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list conversations rows: %w", err)
	}
	if len(convIDs) == 0 {
		return nil, nil
	}

	membersByConv, err := r.listMembersForConversationIDs(ctx, convIDs)
	if err != nil {
		return nil, err
	}

	otherIDsSet := make(map[uuid.UUID]struct{})
	for _, p := range partial {
		members := membersByConv[p.c.ID]
		if !p.c.IsGroup && len(members) == 2 {
			for _, m := range members {
				if m != userID {
					otherIDsSet[m] = struct{}{}
					break
				}
			}
		}
	}
	var otherIDs []uuid.UUID
	for id := range otherIDsSet {
		otherIDs = append(otherIDs, id)
	}
	var usersByID map[uuid.UUID]model.User
	if len(otherIDs) > 0 {
		users, err := r.userRepo.FindUsersByIDs(ctx, otherIDs)
		if err != nil {
			return nil, fmt.Errorf("find users for display: %w", err)
		}
		log.Printf("CONVERSATION_LIST_USERS_BULK count=%d", len(users))
		usersByID = make(map[uuid.UUID]model.User, len(users))
		for _, u := range users {
			usersByID[u.ID] = u
		}
	}

	result := make([]model.ConversationWithPreview, 0, len(partial))
	for _, p := range partial {
		c := p.c
		c.Members = membersByConv[c.ID]
		if c.IsGroup {
			if c.Title != nil && strings.TrimSpace(*c.Title) != "" {
				c.DisplayTitle = *c.Title
			} else {
				c.DisplayTitle = "Group"
			}
		} else {
			var otherID uuid.UUID
			for _, m := range c.Members {
				if m != userID {
					otherID = m
					break
				}
			}
			if otherID != uuid.Nil {
				if u, ok := usersByID[otherID]; ok {
					if strings.TrimSpace(u.DisplayName) != "" {
						c.DisplayTitle = u.DisplayName
					} else {
						c.DisplayTitle = u.PhoneNumber
					}
					if u.AvatarURL != "" {
						c.OtherUserAvatarURL = &u.AvatarURL
					}
				} else {
					s := otherID.String()
					if len(s) >= 12 {
						c.DisplayTitle = s[:8] + "..." + s[len(s)-4:]
					} else {
						c.DisplayTitle = s
					}
				}
			} else {
				c.DisplayTitle = "Chat"
			}
		}
		result = append(result, c)
	}
	return result, nil
}

// ListConversationsForUserByProject returns conversations for a user filtered by project_id, ordered by updated_at DESC
func (r *conversationRepo) ListConversationsForUserByProject(ctx context.Context, userID uuid.UUID, projectID uuid.UUID) ([]model.ProjectConversationItem, error) {
	rows, err := r.conn.QueryContext(ctx, `
		WITH last_msgs AS (
			SELECT DISTINCT ON (conversation_id)
				conversation_id,
				body_preview,
				sent_at
			FROM messages
			WHERE NOT EXISTS (
				SELECT 1
				FROM message_hidden h
				WHERE h.message_id = messages.id AND h.user_id = $1
			)
			ORDER BY conversation_id, sent_at DESC
		)
		SELECT c.id, c.created_at, c.is_group, c.title, lm.body_preview, lm.sent_at
		FROM conversations c
		JOIN conversation_members cm ON cm.conversation_id = c.id AND cm.user_id = $1
		LEFT JOIN last_msgs lm ON lm.conversation_id = c.id
		WHERE c.project_id = $2
		ORDER BY lm.sent_at DESC NULLS LAST, c.created_at DESC
	`, userID, projectID)
	if err != nil {
		return nil, fmt.Errorf("list conversations by project: %w", err)
	}
	defer rows.Close()

	var result []model.ProjectConversationItem
	for rows.Next() {
		var item model.ProjectConversationItem
		var idStr string
		var isGroup bool
		var title sql.NullString
		var preview sql.NullString
		var lastAt sql.NullTime
		if err := rows.Scan(&idStr, &item.UpdatedAt, &isGroup, &title, &preview, &lastAt); err != nil {
			return nil, fmt.Errorf("scan conversation: %w", err)
		}
		item.ID, _ = uuid.Parse(idStr)
		item.LastMessagePreview = preview.String
		if lastAt.Valid {
			item.UpdatedAt = lastAt.Time
		}

		members, err := r.listMembers(ctx, item.ID)
		if err != nil {
			return nil, fmt.Errorf("list members for %s: %w", item.ID, err)
		}
		if isGroup {
			if title.Valid && strings.TrimSpace(title.String) != "" {
				item.DisplayTitle = title.String
			} else {
				item.DisplayTitle = "Group"
			}
		} else {
			var otherID uuid.UUID
			for _, m := range members {
				if m != userID {
					otherID = m
					break
				}
			}
			if otherID != uuid.Nil {
				otherUser, err := r.userRepo.GetByID(ctx, otherID.String())
				if err == nil {
					if strings.TrimSpace(otherUser.DisplayName) != "" {
						item.DisplayTitle = otherUser.DisplayName
					} else {
						item.DisplayTitle = otherUser.PhoneNumber
					}
				} else {
					s := otherID.String()
					if len(s) >= 12 {
						item.DisplayTitle = s[:8] + "..." + s[len(s)-4:]
					} else {
						item.DisplayTitle = s
					}
				}
			} else {
				item.DisplayTitle = "Chat"
			}
		}
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list conversations by project rows: %w", err)
	}
	return result, nil
}

// ListMembers returns all user IDs that are members of the conversation
func (r *conversationRepo) ListMembers(ctx context.Context, convID uuid.UUID) ([]uuid.UUID, error) {
	return r.listMembers(ctx, convID)
}

func (r *conversationRepo) listMembers(ctx context.Context, convID uuid.UUID) ([]uuid.UUID, error) {
	rows, err := r.conn.QueryContext(ctx, `
		SELECT user_id FROM conversation_members WHERE conversation_id = $1
	`, convID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var members []uuid.UUID
	for rows.Next() {
		var idStr string
		if err := rows.Scan(&idStr); err != nil {
			return nil, err
		}
		u, _ := uuid.Parse(idStr)
		members = append(members, u)
	}
	return members, rows.Err()
}

// listMembersForConversationIDs returns members for each conversation in one query. Key is conversation_id.
func (r *conversationRepo) listMembersForConversationIDs(ctx context.Context, convIDs []uuid.UUID) (map[uuid.UUID][]uuid.UUID, error) {
	if len(convIDs) == 0 {
		return nil, nil
	}
	idsStr := make([]string, len(convIDs))
	for i, id := range convIDs {
		idsStr[i] = id.String()
	}
	rows, err := r.conn.QueryContext(ctx, `
		SELECT conversation_id, user_id FROM conversation_members WHERE conversation_id = ANY($1::uuid[])
	`, pq.Array(idsStr))
	if err != nil {
		return nil, fmt.Errorf("list members bulk: %w", err)
	}
	defer rows.Close()

	out := make(map[uuid.UUID][]uuid.UUID)
	var count int
	for rows.Next() {
		var convStr, userStr string
		if err := rows.Scan(&convStr, &userStr); err != nil {
			return nil, err
		}
		convID, _ := uuid.Parse(convStr)
		userID, _ := uuid.Parse(userStr)
		out[convID] = append(out[convID], userID)
		count++
	}
	log.Printf("CONVERSATION_LIST_MEMBERS_BULK count=%d", count)
	return out, rows.Err()
}

// IsMember returns true if userID is a member of conversationID
func (r *conversationRepo) IsMember(ctx context.Context, conversationID uuid.UUID, userID uuid.UUID) (bool, error) {
	var exists int
	err := r.conn.QueryRowContext(ctx, `
		SELECT 1 FROM conversation_members
		WHERE conversation_id = $1 AND user_id = $2
	`, conversationID, userID).Scan(&exists)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("check member: %w", err)
	}
	return true, nil
}

// ListUsersWhoShareConversationWith returns all user IDs that share at least one conversation with the given user.
func (r *conversationRepo) ListUsersWhoShareConversationWith(ctx context.Context, userID uuid.UUID) ([]uuid.UUID, error) {
	rows, err := r.conn.QueryContext(ctx, `
		SELECT DISTINCT cm2.user_id FROM conversation_members cm1
		JOIN conversation_members cm2 ON cm1.conversation_id = cm2.conversation_id
		WHERE cm1.user_id = $1 AND cm2.user_id != $1
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("list users who share conversation: %w", err)
	}
	defer rows.Close()
	var ids []uuid.UUID
	for rows.Next() {
		var idStr string
		if err := rows.Scan(&idStr); err != nil {
			return nil, err
		}
		u, _ := uuid.Parse(idStr)
		ids = append(ids, u)
	}
	return ids, rows.Err()
}

// UpdateTitle sets the conversation title. Used for renaming groups.
func (r *conversationRepo) UpdateTitle(ctx context.Context, convID uuid.UUID, title *string) error {
	_, err := r.conn.ExecContext(ctx, `UPDATE conversations SET title = $1 WHERE id = $2`, title, convID)
	if err != nil {
		return fmt.Errorf("update title: %w", err)
	}
	return nil
}

// AddMember adds a user to the conversation.
func (r *conversationRepo) AddMember(ctx context.Context, convID uuid.UUID, userID uuid.UUID) error {
	_, err := r.conn.ExecContext(ctx, `
		INSERT INTO conversation_members (conversation_id, user_id)
		VALUES ($1, $2)
		ON CONFLICT (conversation_id, user_id) DO NOTHING
	`, convID, userID)
	if err != nil {
		return fmt.Errorf("add member: %w", err)
	}
	return nil
}

// RemoveMember removes a user from the conversation.
func (r *conversationRepo) RemoveMember(ctx context.Context, convID uuid.UUID, userID uuid.UUID) error {
	res, err := r.conn.ExecContext(ctx, `
		DELETE FROM conversation_members
		WHERE conversation_id = $1 AND user_id = $2
	`, convID, userID)
	if err != nil {
		return fmt.Errorf("remove member: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("member not in conversation")
	}
	return nil
}
