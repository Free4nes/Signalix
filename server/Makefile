# Signalix Server Makefile

.PHONY: test test-integration build run

# Run all tests (unit + integration). Set DATABASE_URL for integration tests.
test:
	go test ./... -v

# Run only integration tests. Requires a running PostgreSQL and DATABASE_URL.
# Example: make test-integration DATABASE_URL="postgres://postgres:password@127.0.0.1:5432/signalix_test?sslmode=disable"
test-integration:
	go test ./internal/tests/... -v -run TestAuthIntegration

build:
	go build -o bin/api ./cmd/api

run: build
	./bin/api
