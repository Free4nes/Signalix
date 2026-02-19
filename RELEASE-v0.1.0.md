# Release v0.1.0

## Summary

Initial stable release of Signalix: an OTP-based authentication API in Go, production-ready with CI, Docker, and comprehensive tests.

## Features

- **OTP Auth Flow**: Request OTP, verify, receive JWT access token
- **Dev Mode**: Fixed OTP (`123456`) for local testing when `OTP_DEV_MODE=true`
- **JWT Protection**: Bearer token for `/me` and future protected endpoints
- **Rate Limiting**: Per-IP and per-phone limits (3 OTP requests per 10 min per phone)
- **PostgreSQL**: Migrations via goose, pgcrypto for OTP hashing

## Testing

- Unit tests: `internal/auth` (OTP hashing, constant-time compare)
- Integration tests: Full auth flow (health, request_otp, verify_otp, /me, invalid OTP, rate limit)
- E2E tests: Complete flow + production mode check (no dev_otp exposure)
- All tests run in CI on every push to `main`

## CI

- GitHub Actions workflow: [.github/workflows/ci.yml](.github/workflows/ci.yml)
- Triggers: push, pull_request to `main`
- PostgreSQL 16 service container
- Steps: go vet, go test (unit + integration + E2E)

## Docker Support

- `docker compose up -d` runs API + PostgreSQL
- Multi-stage Dockerfile in `server/Dockerfile`
- Default credentials: postgres/postgres (change for production)

## Notes

- Requires Go 1.21+
- Requires PostgreSQL 12+ (pgcrypto)
- Copy `server/.env.example` to `server/.env` for local config
- Use `127.0.0.1` instead of `localhost` for DATABASE_URL (recommended)
