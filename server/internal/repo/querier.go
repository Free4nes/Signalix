package repo

import (
	"context"
	"database/sql"
)

// Querier is implemented by both *sql.DB and *sql.Tx for use in transactions.
type Querier interface {
	ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row
}
