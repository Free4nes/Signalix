package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"

	_ "github.com/lib/pq"
)

// redactDSN returns a copy of the DSN with password replaced by **** for logging.
func redactDSN(databaseURL string) string {
	u, err := url.Parse(databaseURL)
	if err != nil {
		return "(invalid DATABASE_URL)"
	}
	if u.User != nil {
		user := u.User.Username()
		u.User = url.UserPassword(user, "****")
	}
	return u.String()
}

// extractDBName returns the database name from URL path ("/messenger" -> "messenger").
func extractDBName(u *url.URL) string {
	if u == nil {
		return ""
	}
	dbName := strings.TrimPrefix(u.Path, "/")
	// u.Path never contains query; trimming here is just defensive:
	if idx := strings.Index(dbName, "?"); idx >= 0 {
		dbName = dbName[:idx]
	}
	return strings.TrimSpace(dbName)
}

func isDatabaseDoesNotExist(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())

	// Common Postgres / pq messages (EN + DE)
	return strings.Contains(msg, "does not exist") ||
		strings.Contains(msg, "database") && strings.Contains(msg, "does not exist") ||
		strings.Contains(msg, "existiert nicht") ||
		strings.Contains(msg, "datenbank") && strings.Contains(msg, "existiert nicht")
}

// Open establishes a connection to PostgreSQL and configures the connection pool.
func Open(ctx context.Context, databaseURL string) (*sql.DB, error) {
	databaseURL = strings.TrimSpace(databaseURL)
	if databaseURL == "" {
		return nil, fmt.Errorf("DATABASE_URL is empty")
	}

	// Parse once, properly
	u, err := url.Parse(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid DATABASE_URL: %w", err)
	}

	dbName := extractDBName(u)
	host := u.Hostname()
	port := u.Port()

	if host == "" {
		host = "localhost"
	}
	if port == "" {
		port = "5432"
	}

	// Log what the app *will* use (masked)
	log.Printf("DB connect target: host=%s port=%s db=%q user=%q", host, port, dbName, func() string {
		if u.User == nil {
			return ""
		}
		return u.User.Username()
	}())
	log.Printf("DB DSN (masked): %s", redactDSN(databaseURL))

	// Optional safety check: verify DB exists on this instance by connecting to maintenance DB "postgres"
	if dbName != "" {
		maintenanceURL := *u
		maintenanceURL.Path = "/postgres"
		maintenanceURL.RawPath = ""
		// keep query (sslmode etc.) as-is

		maintDB, err := sql.Open("postgres", maintenanceURL.String())
		if err == nil {
			defer maintDB.Close()

			checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()

			var found string
			rowErr := maintDB.QueryRowContext(checkCtx,
				"SELECT datname FROM pg_database WHERE datname = $1",
				dbName,
			).Scan(&found)

			if rowErr == nil {
				log.Printf("DB precheck: database %q exists on this Postgres instance.", found)
			} else if errors.Is(rowErr, sql.ErrNoRows) {
				log.Printf("DB precheck: database %q NOT found on this Postgres instance.", dbName)
			} else {
				log.Printf("DB precheck: could not query pg_database: %v", rowErr)
			}
		} else {
			log.Printf("DB precheck: could not open maintenance connection: %v", err)
		}
	}

	// Open connection using exact DATABASE_URL string
	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to open database connection: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)
	db.SetConnMaxIdleTime(10 * time.Minute)

	// Ping to verify connection
	connectCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := db.PingContext(connectCtx); err != nil {
		_ = db.Close()

		if isDatabaseDoesNotExist(err) {
			return nil, fmt.Errorf(
				"database %q not found on host=%s port=%s; verify you connect to the same Postgres instance as pgAdmin/psql: %w",
				dbName, host, port, err,
			)
		}

		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return db, nil
}
