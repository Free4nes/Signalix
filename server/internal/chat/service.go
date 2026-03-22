package chat

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/signalix/server/internal/model"
	"github.com/signalix/server/internal/project"
	"github.com/signalix/server/internal/repo"
)

// ErrNotFound is returned when a resource does not exist
var ErrNotFound = errors.New("not found")

// ErrForbidden is returned when the caller is not a member of the conversation
var ErrForbidden = errors.New("forbidden")

// ErrInvalidInput is returned for validation errors
var ErrInvalidInput = errors.New("invalid input")

// Service provides chat functionality with membership enforcement
type Service struct {
	db          *sql.DB
	userRepo    repo.UserRepo
	convs       repo.ConversationRepo
	msgs        repo.MessageRepo
	projs       repo.ProjectRepo
	projectEvts repo.ProjectEventRepo
	reactions   repo.ReactionRepo

	// CreateConversationTestHook, when non-nil, is called before AddProjectEvent in CreateConversation (when projectID set).
	// Return an error to simulate failure and trigger rollback. Used for integration tests.
	CreateConversationTestHook func() error
}

// NewService creates a new chat Service. db and userRepo are used for transactional conversation+event when projectID is set.
func NewService(db *sql.DB, userRepo repo.UserRepo, convs repo.ConversationRepo, msgs repo.MessageRepo, projs repo.ProjectRepo, projectEvts repo.ProjectEventRepo, reactions repo.ReactionRepo) *Service {
	return &Service{db: db, userRepo: userRepo, convs: convs, msgs: msgs, projs: projs, projectEvts: projectEvts, reactions: reactions}
}

// CreateConversation creates a new conversation. title and projectID are optional.
// is_group = (len(members) > 2) OR (title provided).
// Validation: if is_group then len(members) >= 3, else len(members) == 2.
// If projectID is set, the creator must own the project; otherwise returns ErrForbidden.
func (s *Service) CreateConversation(ctx context.Context, creatorUserID uuid.UUID, memberUserIDs []uuid.UUID, title *string, projectID *uuid.UUID) (model.ConversationWithPreview, error) {
	if len(memberUserIDs) == 0 {
		return model.ConversationWithPreview{}, fmt.Errorf("%w: member_user_ids is required", ErrInvalidInput)
	}

	seen := make(map[uuid.UUID]bool)
	seen[creatorUserID] = true
	members := []uuid.UUID{creatorUserID}
	for _, id := range memberUserIDs {
		if id != creatorUserID && !seen[id] {
			seen[id] = true
			members = append(members, id)
		}
	}

	hasTitle := title != nil && strings.TrimSpace(*title) != ""
	isGroup := len(members) > 2 || hasTitle

	if isGroup {
		if len(members) < 3 {
			return model.ConversationWithPreview{}, fmt.Errorf("%w: group requires at least 3 members", ErrInvalidInput)
		}
	} else {
		if len(members) != 2 {
			return model.ConversationWithPreview{}, fmt.Errorf("%w: 1:1 chat requires exactly 2 members", ErrInvalidInput)
		}
	}

	if projectID != nil && *projectID != uuid.Nil {
		proj, err := s.projs.GetProjectByID(ctx, *projectID)
		if err != nil {
			return model.ConversationWithPreview{}, ErrForbidden
		}
		if proj.HardArchived {
			return model.ConversationWithPreview{}, project.ErrProjectArchived
		}
		if proj.OwnerUserID != creatorUserID {
			return model.ConversationWithPreview{}, ErrForbidden
		}
	}

	if projectID != nil && *projectID != uuid.Nil {
		// Idempotent: if conversation already exists with same project + members, return existing
		existing, found, err := s.convs.FindByProjectAndMembers(ctx, *projectID, members)
		if err != nil {
			return model.ConversationWithPreview{}, fmt.Errorf("find existing conversation: %w", err)
		}
		if found {
			return s.convs.GetConversationWithPreview(ctx, existing.ID, creatorUserID)
		}

		// Conversation + project_event must be atomic
		var preview model.ConversationWithPreview
		err = repo.WithTxForConversation(ctx, s.db, s.userRepo, func(tx *repo.Tx) error {
			conv, err := tx.Convs.CreateConversation(ctx, title, isGroup, members, projectID)
			if err != nil {
				return err
			}
			var p model.ConversationWithPreview
			p, err = tx.Convs.GetConversationWithPreview(ctx, conv.ID, creatorUserID)
			if err != nil {
				return err
			}
			preview = p
			payload := project.ConversationAddedPayload{
				ConversationID: conv.ID,
				DisplayTitle:   preview.DisplayTitle,
			}
			if err := payload.Validate(); err != nil {
				return fmt.Errorf("event payload: %w", err)
			}
			ev := project.NewConversationAddedEvent(conv.ID, preview.DisplayTitle)
			if s.CreateConversationTestHook != nil {
				if err := s.CreateConversationTestHook(); err != nil {
					return err
				}
			}
			return tx.ProjectEvts.AddProjectEvent(ctx, *projectID, creatorUserID, string(ev.EventType), ev.Version, ev.Payload)
		})
		if err != nil {
			return model.ConversationWithPreview{}, err
		}
		return preview, nil
	}

	conv, err := s.convs.CreateConversation(ctx, title, isGroup, members, projectID)
	if err != nil {
		return model.ConversationWithPreview{}, err
	}
	return s.convs.GetConversationWithPreview(ctx, conv.ID, creatorUserID)
}

// ListConversations returns conversations for the user with last message preview
func (s *Service) ListConversations(ctx context.Context, userID uuid.UUID) ([]model.ConversationWithPreview, error) {
	return s.convs.ListConversationsForUser(ctx, userID)
}

// GetConversation returns a single conversation. Returns ErrForbidden if caller is not a member.
func (s *Service) GetConversation(ctx context.Context, callerID uuid.UUID, convID uuid.UUID) (model.ConversationWithPreview, error) {
	return s.convs.GetConversationWithPreview(ctx, convID, callerID)
}

// UpdateConversationTitle renames a group. Caller must be a member. Only groups have titles.
func (s *Service) UpdateConversationTitle(ctx context.Context, callerID uuid.UUID, convID uuid.UUID, title *string) (model.ConversationWithPreview, error) {
	ok, err := s.convs.IsMember(ctx, convID, callerID)
	if err != nil || !ok {
		return model.ConversationWithPreview{}, ErrForbidden
	}
	if err := s.convs.UpdateTitle(ctx, convID, title); err != nil {
		return model.ConversationWithPreview{}, err
	}
	return s.convs.GetConversationWithPreview(ctx, convID, callerID)
}

// AddConversationMember adds a user to the group. Caller must be a member.
func (s *Service) AddConversationMember(ctx context.Context, callerID uuid.UUID, convID uuid.UUID, userID uuid.UUID) (model.ConversationWithPreview, error) {
	ok, err := s.convs.IsMember(ctx, convID, callerID)
	if err != nil || !ok {
		return model.ConversationWithPreview{}, ErrForbidden
	}
	if err := s.convs.AddMember(ctx, convID, userID); err != nil {
		return model.ConversationWithPreview{}, err
	}
	return s.convs.GetConversationWithPreview(ctx, convID, callerID)
}

// RemoveConversationMember removes a user from the group. Caller must be a member.
func (s *Service) RemoveConversationMember(ctx context.Context, callerID uuid.UUID, convID uuid.UUID, userID uuid.UUID) (model.ConversationWithPreview, error) {
	ok, err := s.convs.IsMember(ctx, convID, callerID)
	if err != nil || !ok {
		return model.ConversationWithPreview{}, ErrForbidden
	}
	if err := s.convs.RemoveMember(ctx, convID, userID); err != nil {
		return model.ConversationWithPreview{}, err
	}
	return s.convs.GetConversationWithPreview(ctx, convID, callerID)
}

// CreateMessage creates a text message in a conversation. Returns ErrForbidden if caller is not a member.
// If replyToID is set, validates the replied-to message exists and is in the same conversation.
func (s *Service) CreateMessage(ctx context.Context, callerID uuid.UUID, conversationID uuid.UUID, ciphertext []byte, preview string, replyToID *uuid.UUID) (model.Message, error) {
	ok, err := s.convs.IsMember(ctx, conversationID, callerID)
	if err != nil {
		return model.Message{}, fmt.Errorf("check membership: %w", err)
	}
	if !ok {
		return model.Message{}, ErrForbidden
	}
	if len(ciphertext) == 0 {
		return model.Message{}, fmt.Errorf("body_ciphertext is required and must be non-empty")
	}
	if replyToID != nil && *replyToID != uuid.Nil {
		replyMsg, err := s.msgs.GetMessage(ctx, *replyToID)
		if err != nil {
			return model.Message{}, ErrNotFound
		}
		if replyMsg.ConversationID != conversationID {
			return model.Message{}, ErrInvalidInput
		}
	}
	return s.msgs.CreateMessage(ctx, conversationID, callerID, ciphertext, preview, replyToID)
}

// CreateAudioMessage creates an audio message in a conversation. Returns ErrForbidden if caller is not a member.
func (s *Service) CreateAudioMessage(ctx context.Context, callerID uuid.UUID, conversationID uuid.UUID, audioURL string, durationMs int, mime string) (model.Message, error) {
	ok, err := s.convs.IsMember(ctx, conversationID, callerID)
	if err != nil {
		return model.Message{}, fmt.Errorf("check membership: %w", err)
	}
	if !ok {
		return model.Message{}, ErrForbidden
	}
	return s.msgs.CreateAudioMessage(ctx, conversationID, callerID, audioURL, durationMs, mime)
}

// CreateImageMessage creates an image message in a conversation. Returns ErrForbidden if caller is not a member.
func (s *Service) CreateImageMessage(ctx context.Context, callerID uuid.UUID, conversationID uuid.UUID, imageURL string, replyToID *uuid.UUID) (model.Message, error) {
	ok, err := s.convs.IsMember(ctx, conversationID, callerID)
	if err != nil {
		return model.Message{}, fmt.Errorf("check membership: %w", err)
	}
	if !ok {
		return model.Message{}, ErrForbidden
	}
	if replyToID != nil && *replyToID != uuid.Nil {
		replyMsg, err := s.msgs.GetMessage(ctx, *replyToID)
		if err != nil {
			return model.Message{}, ErrNotFound
		}
		if replyMsg.ConversationID != conversationID {
			return model.Message{}, ErrInvalidInput
		}
	}
	return s.msgs.CreateImageMessage(ctx, conversationID, callerID, imageURL, replyToID)
}

// ListMessages returns messages for a conversation. Returns ErrForbidden if caller is not a member.
func (s *Service) ListMessages(ctx context.Context, callerID uuid.UUID, conversationID uuid.UUID, limit int, beforeSentAt *time.Time) ([]model.Message, error) {
	ok, err := s.convs.IsMember(ctx, conversationID, callerID)
	if err != nil {
		return nil, fmt.Errorf("check membership: %w", err)
	}
	if !ok {
		return nil, ErrForbidden
	}
	if limit <= 0 {
		limit = 50
	}
	return s.msgs.ListMessages(ctx, conversationID, callerID, limit, beforeSentAt)
}

// SearchMessages returns text messages in a conversation matching query in body_preview.
func (s *Service) SearchMessages(ctx context.Context, callerID uuid.UUID, conversationID uuid.UUID, query string) ([]model.Message, error) {
	ok, err := s.convs.IsMember(ctx, conversationID, callerID)
	if err != nil {
		return nil, fmt.Errorf("check membership: %w", err)
	}
	if !ok {
		return nil, ErrForbidden
	}
	return s.msgs.SearchMessages(ctx, conversationID, callerID, query)
}

// DeleteMessage deletes a message. mode must be "everyone" or "me".
// everyone: caller must be sender; sets deleted_for_everyone.
// me: inserts into message_hidden for caller.
func (s *Service) DeleteMessage(ctx context.Context, callerID uuid.UUID, conversationID uuid.UUID, messageID uuid.UUID, mode string) (model.Message, error) {
	ok, err := s.convs.IsMember(ctx, conversationID, callerID)
	if err != nil {
		return model.Message{}, fmt.Errorf("check membership: %w", err)
	}
	if !ok {
		return model.Message{}, ErrForbidden
	}

	msg, err := s.msgs.GetMessage(ctx, messageID)
	if err != nil {
		return model.Message{}, ErrNotFound
	}
	if msg.ConversationID != conversationID {
		return model.Message{}, ErrNotFound
	}

	switch mode {
	case "everyone":
		if msg.SenderUserID != callerID {
			return model.Message{}, ErrForbidden
		}
		return s.msgs.DeleteForEveryone(ctx, messageID, callerID)
	case "me":
		if err := s.msgs.HideForMe(ctx, messageID, callerID); err != nil {
			return model.Message{}, fmt.Errorf("hide for me: %w", err)
		}
		return msg, nil
	default:
		return model.Message{}, ErrInvalidInput
	}
}

// EditMessage updates a message body. Caller must be sender; message must not be deleted.
func (s *Service) EditMessage(ctx context.Context, callerID uuid.UUID, messageID uuid.UUID, ciphertext []byte, preview string) (model.Message, error) {
	msg, err := s.msgs.GetMessage(ctx, messageID)
	if err != nil {
		return model.Message{}, ErrNotFound
	}
	if msg.SenderUserID != callerID {
		return model.Message{}, ErrForbidden
	}
	if msg.DeletedForEveryone {
		return model.Message{}, ErrForbidden
	}
	if msg.MsgType != "text" {
		return model.Message{}, ErrInvalidInput
	}
	return s.msgs.UpdateMessage(ctx, messageID, callerID, ciphertext, preview)
}

// DeleteMessageByID deletes a message by ID only. Looks up conversation from the message.
func (s *Service) DeleteMessageByID(ctx context.Context, callerID uuid.UUID, messageID uuid.UUID, mode string) (model.Message, error) {
	msg, err := s.msgs.GetMessage(ctx, messageID)
	if err != nil {
		return model.Message{}, ErrNotFound
	}
	return s.DeleteMessage(ctx, callerID, msg.ConversationID, messageID, mode)
}

// ClearConversation hides all messages in a conversation for the caller.
func (s *Service) ClearConversation(ctx context.Context, callerID uuid.UUID, conversationID uuid.UUID) error {
	ok, err := s.convs.IsMember(ctx, conversationID, callerID)
	if err != nil {
		return fmt.Errorf("check membership: %w", err)
	}
	if !ok {
		return ErrForbidden
	}
	if err := s.msgs.HideConversationForMe(ctx, conversationID, callerID); err != nil {
		return err
	}
	return nil
}

var allowedReactions = map[string]bool{"👍": true, "❤️": true, "😂": true, "😮": true, "😢": true}

// AddReaction sets the caller's reaction on a message. One reaction per user per message; overwrites previous.
func (s *Service) AddReaction(ctx context.Context, callerID uuid.UUID, messageID uuid.UUID, reaction string) (convID uuid.UUID, err error) {
	if !allowedReactions[reaction] {
		return uuid.Nil, ErrInvalidInput
	}
	msg, err := s.msgs.GetMessage(ctx, messageID)
	if err != nil {
		return uuid.Nil, ErrNotFound
	}
	ok, err := s.convs.IsMember(ctx, msg.ConversationID, callerID)
	if err != nil || !ok {
		return uuid.Nil, ErrForbidden
	}
	if s.reactions == nil {
		return msg.ConversationID, nil
	}
	if err := s.reactions.SetReaction(ctx, messageID, callerID, reaction); err != nil {
		return uuid.Nil, fmt.Errorf("set reaction: %w", err)
	}
	return msg.ConversationID, nil
}
