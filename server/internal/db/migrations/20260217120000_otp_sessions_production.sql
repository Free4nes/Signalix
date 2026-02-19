-- +goose Up
DROP TABLE IF EXISTS otp_sessions;

CREATE TABLE otp_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    phone_number TEXT NOT NULL,
    otp_hash TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    attempt_count INT NOT NULL DEFAULT 0,
    last_attempt_at TIMESTAMPTZ NULL,
    request_ip TEXT NULL,
    user_agent TEXT NULL
);

CREATE INDEX idx_otp_sessions_phone_created ON otp_sessions(phone_number, created_at DESC);

-- Only one unconsumed session per phone (expiration checked in application)
DROP INDEX IF EXISTS idx_otp_sessions_one_active_per_phone;
CREATE UNIQUE INDEX idx_otp_sessions_one_active_per_phone
    ON otp_sessions(phone_number)
    WHERE consumed_at IS NULL;

CREATE INDEX idx_otp_sessions_expires_at ON otp_sessions(expires_at);

-- +goose Down
DROP TABLE IF EXISTS otp_sessions;

CREATE TABLE otp_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    phone_number TEXT NOT NULL,
    otp_hash BYTEA NOT NULL,
    attempts INT NOT NULL DEFAULT 0,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_otp_sessions_phone_created ON otp_sessions(phone_number, created_at DESC);
