package tests

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/pressly/goose/v3"
)

// Default database URL matching docker-compose.yml:
// POSTGRES_USER=postgres, POSTGRES_PASSWORD=postgres, POSTGRES_DB=messenger
const defaultDBURL = "postgres://postgres:postgres@127.0.0.1:5432/messenger?sslmode=disable"

// ResolveDatabaseURL returns DATABASE_URL from env if set; otherwise the default from docker-compose.
func ResolveDatabaseURL() string {
	if u := os.Getenv("DATABASE_URL"); u != "" {
		return strings.TrimSpace(u)
	}
	return defaultDBURL
}

// maskDSN returns a DSN with password redacted for logging.
func maskDSN(dsn string) string {
	u, err := url.Parse(dsn)
	if err != nil {
		return "(invalid)"
	}
	if u.User != nil {
		u.User = url.UserPassword(u.User.Username(), "****")
	}
	return u.String()
}

const (
	// MigrationDir is the path to migrations relative to module root (server/).
	MigrationDir = "internal/db/migrations"
	// MigrationDirFromRepoRoot is used when tests run from repo root.
	MigrationDirFromRepoRoot = "server/internal/db/migrations"
	// MigrationDirFromInternalTests is used when go test ./... runs tests from server/internal/tests.
	MigrationDirFromInternalTests = "../../internal/db/migrations"
)

// ResolveMigrationDir returns the first existing directory of:
//   - internal/db/migrations (CWD=server/)
//   - server/internal/db/migrations (CWD=repo root)
//   - ../../internal/db/migrations (CWD=server/internal/tests, e.g. go test ./...)
// Returns empty string if none exists.
func ResolveMigrationDir() string {
	for _, dir := range []string{MigrationDir, MigrationDirFromRepoRoot, MigrationDirFromInternalTests} {
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			abs, _ := filepath.Abs(dir)
			return abs
		}
	}
	return ""
}

// RunMigrations runs goose Up using the resolved migration directory.
func RunMigrations(db *sql.DB) error {
	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("set dialect: %w", err)
	}
	dir := ResolveMigrationDir()
	if dir == "" {
		return fmt.Errorf("migrations directory not found (tried %q, %q, %q); run tests from server/ or repo root", MigrationDir, MigrationDirFromRepoRoot, MigrationDirFromInternalTests)
	}
	if err := goose.Up(db, dir); err != nil {
		return fmt.Errorf("goose up: %w", err)
	}
	return nil
}

// TruncateAuthTables truncates auth-related and chat tables for a clean test state.
func TruncateAuthTables(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, "TRUNCATE TABLE project_events, messages, conversation_members, conversations, events, project_api_keys, projects, refresh_sessions, devices, otp_sessions, users RESTART IDENTITY CASCADE")
	if err != nil {
		return fmt.Errorf("truncate auth tables: %w", err)
	}
	return nil
}
