# Signalix Server Makefile

.PHONY: test test-integration build run

# Run all tests (unit + integration). Set DATABASE_URL for integration tests.
test:
	go test ./... -v

# Run integration and E2E tests. Requires PostgreSQL and DATABASE_URL.
# Create DB: createdb messenger_test
# Example: make test-integration DATABASE_URL="postgres://postgres:Ricardo-Leticia100@127.0.0.1:5432/messenger_test?sslmode=disable"
test-integration:
	go test ./internal/tests/... -v

build:
	go build -o bin/api ./cmd/api

run: build
	./bin/api
