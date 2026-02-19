-- +goose Up
-- Enable pgcrypto extension for gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    phone_number TEXT UNIQUE NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Devices table
CREATE TABLE devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_name TEXT NOT NULL,
    identity_key_pub BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ
);

-- Index on user_id for devices
CREATE INDEX idx_devices_user_id ON devices(user_id);

-- Prekeys table (Signed PreKey per Device)
CREATE TABLE prekeys (
    device_id UUID PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    signed_prekey_id INT NOT NULL,
    signed_prekey_pub BYTEA NOT NULL,
    signed_prekey_signature BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One-time prekeys table
CREATE TABLE one_time_prekeys (
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    prekey_id INT NOT NULL,
    prekey_pub BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, prekey_id)
);

-- Messages queue table
CREATE TABLE messages_queue (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    from_device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    to_device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    envelope BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Index on to_device_id and created_at for efficient message retrieval
CREATE INDEX idx_messages_queue_to_device_created ON messages_queue(to_device_id, created_at);

-- +goose Down
-- Drop tables in reverse order (respecting foreign key dependencies)
DROP TABLE IF EXISTS messages_queue;
DROP TABLE IF EXISTS one_time_prekeys;
DROP TABLE IF EXISTS prekeys;
DROP TABLE IF EXISTS devices;
DROP TABLE IF EXISTS users;

-- Optionally drop extension (commented out to avoid issues if other tables use it)
-- DROP EXTENSION IF EXISTS pgcrypto;
