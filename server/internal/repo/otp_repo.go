package repo

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/signalix/server/internal/model"
)

// OtpRepo defines the interface for OTP session repository operations
type OtpRepo interface {
	CreateOrReplaceSession(ctx context.Context, phone, otpHashHex string, expiresAt time.Time, requestIP, userAgent *string) (uuid.UUID, error)
	GetActiveSessionByPhone(ctx context.Context, phone string) (model.OtpSession, error)
	MarkConsumed(ctx context.Context, sessionID uuid.UUID) error
	IncrementAttempt(ctx context.Context, sessionID uuid.UUID) (newAttemptCount int, err error)
	CountRecentRequests(ctx context.Context, phone string, since time.Time) (int, error)
}

type otpRepo struct {
	db *sql.DB
}

// NewOtpRepo creates a new OtpRepo instance
func NewOtpRepo(db *sql.DB) OtpRepo {
	return &otpRepo{db: db}
}

// CreateOrReplaceSession ensures only one active session per phone: atomically invalidates any existing
// session (consumed_at IS NULL) and inserts a new one. Uses advisory lock for race safety.
func (r *otpRepo) CreateOrReplaceSession(ctx context.Context, phone, otpHashHex string, expiresAt time.Time, requestIP, userAgent *string) (uuid.UUID, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return uuid.Nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Advisory lock: serialize requests per phone to avoid duplicate key on INSERT.
	// Blocks until we hold the lock; released on COMMIT/ROLLBACK.
	_, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(1, hashtext($1))`, phone)
	if err != nil {
		return uuid.Nil, fmt.Errorf("advisory lock: %w", err)
	}

	// Invalidate any existing active session (unique index: phone WHERE consumed_at IS NULL).
	// Must consume ALL such rows, including expired ones.
	_, err = tx.ExecContext(ctx, `
		UPDATE otp_sessions
		SET consumed_at = now()
		WHERE phone_number = $1 AND consumed_at IS NULL
	`, phone)
	if err != nil {
		return uuid.Nil, fmt.Errorf("consume existing sessions: %w", err)
	}

	var idStr string
	err = tx.QueryRowContext(ctx, `
		INSERT INTO otp_sessions (phone_number, otp_hash, expires_at, request_ip, user_agent)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id
	`, phone, otpHashHex, expiresAt, requestIP, userAgent).Scan(&idStr)
	if err != nil {
		return uuid.Nil, fmt.Errorf("insert session: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return uuid.Nil, fmt.Errorf("commit: %w", err)
	}

	sessionID, err := uuid.Parse(idStr)
	if err != nil {
		return uuid.Nil, fmt.Errorf("parse session ID: %w", err)
	}
	return sessionID, nil
}

// GetActiveSessionByPhone returns the latest active (unconsumed, unexpired, attempt_count < 5) session for the phone.
func (r *otpRepo) GetActiveSessionByPhone(ctx context.Context, phone string) (model.OtpSession, error) {
	query := `
		SELECT id, phone_number, otp_hash, expires_at, consumed_at, created_at,
		       attempt_count, last_attempt_at, request_ip, user_agent
		FROM otp_sessions
		WHERE phone_number = $1
		  AND consumed_at IS NULL
		  AND expires_at > now()
		  AND attempt_count < 5
		ORDER BY created_at DESC
		LIMIT 1
	`
	var session model.OtpSession
	var idStr string
	var otpHashHex string
	err := r.db.QueryRowContext(ctx, query, phone).Scan(
		&idStr,
		&session.PhoneNumber,
		&otpHashHex,
		&session.ExpiresAt,
		&session.ConsumedAt,
		&session.CreatedAt,
		&session.AttemptCount,
		&session.LastAttemptAt,
		&session.RequestIP,
		&session.UserAgent,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return model.OtpSession{}, fmt.Errorf("no active session: %w", err)
		}
		return model.OtpSession{}, fmt.Errorf("query session: %w", err)
	}

	session.ID, err = uuid.Parse(idStr)
	if err != nil {
		return model.OtpSession{}, fmt.Errorf("parse session ID: %w", err)
	}

	session.OTPHash, err = hex.DecodeString(otpHashHex)
	if err != nil {
		return model.OtpSession{}, fmt.Errorf("decode otp_hash: %w", err)
	}

	return session, nil
}

// MarkConsumed sets consumed_at = now() for the session.
func (r *otpRepo) MarkConsumed(ctx context.Context, sessionID uuid.UUID) error {
	result, err := r.db.ExecContext(ctx, `
		UPDATE otp_sessions SET consumed_at = now() WHERE id = $1
	`, sessionID)
	if err != nil {
		return fmt.Errorf("mark consumed: %w", err)
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("session not found")
	}
	return nil
}

// IncrementAttempt sets attempt_count = attempt_count + 1 and last_attempt_at = now(); returns the new attempt_count.
func (r *otpRepo) IncrementAttempt(ctx context.Context, sessionID uuid.UUID) (int, error) {
	var newCount int
	err := r.db.QueryRowContext(ctx, `
		UPDATE otp_sessions
		SET attempt_count = attempt_count + 1, last_attempt_at = now()
		WHERE id = $1
		RETURNING attempt_count
	`, sessionID).Scan(&newCount)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, fmt.Errorf("session not found")
		}
		return 0, fmt.Errorf("increment attempt: %w", err)
	}
	return newCount, nil
}

// CountRecentRequests returns the number of sessions created for the phone since the given time (for rate limiting).
func (r *otpRepo) CountRecentRequests(ctx context.Context, phone string, since time.Time) (int, error) {
	var count int
	err := r.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM otp_sessions
		WHERE phone_number = $1 AND created_at >= $2
	`, phone, since).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count recent requests: %w", err)
	}
	return count, nil
}
