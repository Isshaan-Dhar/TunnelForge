CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS users (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'user',
    is_active     BOOLEAN NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login    TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS devices (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id       UUID NOT NULL REFERENCES users(id),
    device_name   TEXT NOT NULL,
    cert_serial   TEXT UNIQUE NOT NULL,
    is_trusted    BOOLEAN NOT NULL DEFAULT FALSE,
    registered_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_devices_user_id     ON devices (user_id);
CREATE INDEX IF NOT EXISTS idx_devices_cert_serial ON devices (cert_serial);

CREATE TABLE IF NOT EXISTS policies (
    id                     UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name                   TEXT UNIQUE NOT NULL,
    user_role              TEXT NOT NULL,
    allowed_hours_start    INTEGER NOT NULL DEFAULT 0,
    allowed_hours_end      INTEGER NOT NULL DEFAULT 23,
    require_trusted_device BOOLEAN NOT NULL DEFAULT FALSE,
    allowed_resources      TEXT[] NOT NULL DEFAULT '{}',
    created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS sessions (
    id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id    UUID NOT NULL REFERENCES users(id),
    device_id  UUID REFERENCES devices(id),
    token_id   TEXT UNIQUE NOT NULL,
    client_ip  TEXT NOT NULL,
    issued_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked    BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id  ON sessions (user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_token_id ON sessions (token_id);

CREATE TABLE IF NOT EXISTS audit_log (
    id          BIGSERIAL PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    user_id     UUID,
    username    TEXT,
    action      TEXT NOT NULL,
    resource    TEXT,
    client_ip   TEXT,
    device_id   UUID,
    status      TEXT NOT NULL,
    detail      TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_log_user_id     ON audit_log (user_id,  occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_action      ON audit_log (action,   occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_occurred_at ON audit_log (occurred_at DESC);

INSERT INTO users (username, password_hash, role) VALUES
    ('admin', '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'admin'),
    ('alice', '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'user'),
    ('bob',   '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'user')
ON CONFLICT (username) DO NOTHING;

INSERT INTO policies (name, user_role, allowed_hours_start, allowed_hours_end, require_trusted_device, allowed_resources) VALUES
    ('admin-policy',    'admin', 0, 23, FALSE, ARRAY['/admin', '/api', '/metrics']),
    ('user-policy',     'user',  0, 23, FALSE, ARRAY['/api']),
    ('restricted-user', 'user',  9, 17, TRUE,  ARRAY['/api/readonly'])
ON CONFLICT (name) DO NOTHING;