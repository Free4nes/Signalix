-- +goose Up
CREATE TABLE refresh_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ NULL,
    replaced_by UUID NULL REFERENCES refresh_sessions(id)
);

CREATE INDEX idx_refresh_sessions_user_id ON refresh_sessions(user_id);
CREATE INDEX idx_refresh_sessions_token_hash ON refresh_sessions(token_hash);
CREATE INDEX idx_refresh_sessions_expires_at ON refresh_sessions(expires_at);

-- +goose Down
DROP TABLE IF EXISTS refresh_sessions;
