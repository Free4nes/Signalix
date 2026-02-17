# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /build

# Copy module files first for layer cache (context is repo root when built via compose)
COPY server/go.mod server/go.sum ./
RUN go mod download

COPY server/ .

# Build static binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /app/api ./cmd/api

# Runtime stage
FROM alpine:3.19

WORKDIR /app

# Runtime deps only (ca-certificates for HTTPS if needed)
RUN apk add --no-cache ca-certificates tzdata

# Copy binary and migrations (required for goose on startup)
COPY --from=builder /app/api .
COPY --from=builder /build/internal/db/migrations /app/internal/db/migrations

EXPOSE 8080

CMD ["./api"]
