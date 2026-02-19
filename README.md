# Signalix

[![CI](https://github.com/Free4nes/Signalix/actions/workflows/ci.yml/badge.svg)](https://github.com/Free4nes/Signalix/actions/workflows/ci.yml)

OTP-based authentication API in Go (PostgreSQL, CI-tested, Docker-ready).

## Features

- OTP request & verification (dev mode: fixed OTP for testing)
- JWT access tokens
- Rate limiting (per-IP, per-phone)
- PostgreSQL-backed sessions
- Health check endpoint
- Protected `/me` endpoint

## Tech Stack

- Go 1.21+
- PostgreSQL 16
- Chi router
- JWT, goose migrations

## Local Development

**PowerShell (Windows):**
```powershell
cd server
$env:DATABASE_URL = "postgres://postgres:DEIN_PASSWORT@127.0.0.1:5432/messenger?sslmode=disable"
$env:JWT_SECRET = "your-secret-at-least-32-characters-long"
$env:OTP_SALT = "your-otp-salt"
$env:OTP_DEV_MODE = "true"
go run ./cmd/api
```

**Linux / macOS:**
```bash
cd server
export DATABASE_URL="postgres://postgres:DEIN_PASSWORT@127.0.0.1:5432/messenger?sslmode=disable"
export JWT_SECRET="your-secret-at-least-32-characters-long"
export OTP_SALT="your-otp-salt"
export OTP_DEV_MODE="true"
go run ./cmd/api
```

See [server/.env.example](server/.env.example). Create `messenger` (or `messenger_test` for tests) with `createdb messenger`.

## Run Tests

**PowerShell:**
```powershell
cd server
$env:DATABASE_URL = "postgres://postgres:DEIN_PASSWORT@127.0.0.1:5432/messenger_test?sslmode=disable"
go test ./... -v
```

**Linux / macOS:**
```bash
cd server
export DATABASE_URL="postgres://postgres:DEIN_PASSWORT@127.0.0.1:5432/messenger_test?sslmode=disable"
go test ./... -v
```

Create test DB: `createdb messenger_test`.

## Docker Usage

```bash
docker compose up -d
```

API: http://localhost:8080. DB: `postgres:5432` (postgres/postgres).

## CI

GitHub Actions runs on push/PR to `main`:
- `go vet ./...`
- `go test ./...` (unit + integration + E2E)
- PostgreSQL 16 service container

## API Documentation

Full API docs: [server/README.md](server/README.md)
