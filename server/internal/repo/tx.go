package repo

import (
	"context"
	"database/sql"
	"fmt"
)

// Tx holds transaction-scoped repos for atomic domain + event writes.
type Tx struct {
	Projects    ProjectRepo
	ProjectEvts ProjectEventRepo
	Convs       ConversationRepo
}

// WithTx runs fn inside a transaction. On success, commits. On error, rollbacks.
// All repo operations inside fn use the same transaction.
func WithTx(ctx context.Context, db *sql.DB, fn func(tx *Tx) error) error {
	txx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer txx.Rollback()

	tx := &Tx{
		Projects:    NewProjectRepoWithConn(txx),
		ProjectEvts: NewProjectEventRepoWithConn(txx),
	}
	if err := fn(tx); err != nil {
		return err
	}
	return txx.Commit()
}

// WithTxForConversation runs fn inside a transaction for conversation + project event.
func WithTxForConversation(ctx context.Context, db *sql.DB, userRepo UserRepo, fn func(tx *Tx) error) error {
	txx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer txx.Rollback()

	tx := &Tx{
		Projects:    NewProjectRepoWithConn(txx),
		ProjectEvts: NewProjectEventRepoWithConn(txx),
		Convs:       NewConversationRepoWithConn(txx, userRepo),
	}
	if err := fn(tx); err != nil {
		return err
	}
	return txx.Commit()
}
