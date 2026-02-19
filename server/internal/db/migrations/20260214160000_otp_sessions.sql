-- +goose Up
CREATE TABLE otp_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    phone_number TEXT NOT NULL,
    otp_hash BYTEA NOT NULL,
    attempts INT NOT NULL DEFAULT 0,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_otp_sessions_phone_created ON otp_sessions(phone_number, created_at DESC);

-- +goose Down
DROP TABLE IF EXISTS otp_sessions;
