package tests

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	"github.com/pressly/goose/v3"
)

const (
	// MigrationDir is the path to migrations relative to module root (server/).
	MigrationDir = "internal/db/migrations"
	// MigrationDirFromRepoRoot is used when tests run from repo root.
	MigrationDirFromRepoRoot = "server/internal/db/migrations"
)

// ResolveMigrationDir returns the first existing directory of:
//   - internal/db/migrations
//   - server/internal/db/migrations
// Returns empty string if neither exists.
func ResolveMigrationDir() string {
	for _, dir := range []string{MigrationDir, MigrationDirFromRepoRoot} {
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
		return fmt.Errorf("migrations directory not found (tried %q and %q); run tests from server/ or repo root", MigrationDir, MigrationDirFromRepoRoot)
	}
	if err := goose.Up(db, dir); err != nil {
		return fmt.Errorf("goose up: %w", err)
	}
	return nil
}

// TruncateAuthTables truncates auth-related tables for a clean test state.
func TruncateAuthTables(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, "TRUNCATE TABLE devices, otp_sessions, users RESTART IDENTITY CASCADE")
	if err != nil {
		return fmt.Errorf("truncate auth tables: %w", err)
	}
	return nil
}
