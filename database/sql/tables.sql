CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- DROP TABLE IF EXISTS trusted_devices CASCADE;
-- DROP TABLE IF EXISTS otp_sessions CASCADE;
-- DROP TABLE IF EXISTS auth_logs CASCADE;
-- DROP TABLE IF EXISTS users CASCADE;

-- =========================
-- USERS
-- =========================
CREATE TABLE IF NOT EXISTS users (
    id                  SERIAL PRIMARY KEY,
    username            VARCHAR(50) UNIQUE NOT NULL,
    full_name           VARCHAR(100),
    email               VARCHAR(100) UNIQUE,
    password_hash       TEXT NOT NULL,
    role                VARCHAR(20) DEFAULT 'user',
    otp_secret          TEXT,
    biometric_template  TEXT,
    is_active           BOOLEAN DEFAULT TRUE,
    last_password_change TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login          TIMESTAMP,
    created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users (username);
CREATE INDEX IF NOT EXISTS idx_users_email    ON users (email);

-- =========================
-- AUTH LOGS
-- =========================
CREATE TABLE IF NOT EXISTS auth_logs (
    log_id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username                VARCHAR(50) REFERENCES users(username) ON DELETE SET NULL,
    event_type              VARCHAR(50),       -- e.g. login, otp_success, otp_failed, lockout
    ip_address              INET,
    auth_logs_details       TEXT,
    user_agent              TEXT,
    timestamp               TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    success                 BOOLEAN
);

CREATE INDEX IF NOT EXISTS idx_logs_username  ON auth_logs(username);
CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON auth_logs(timestamp);

-- =========================
-- OTP SESSIONS
-- =========================
CREATE TABLE IF NOT EXISTS otp_sessions (
    id          BIGSERIAL PRIMARY KEY,
    username    VARCHAR(50) REFERENCES users(username) ON DELETE CASCADE,
    otp_hash    TEXT NOT NULL,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at  TIMESTAMP NOT NULL,
    used        BOOLEAN DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_otp_username   ON otp_sessions(username);
CREATE INDEX IF NOT EXISTS idx_otp_expires    ON otp_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_otp_used       ON otp_sessions(used);

-- =========================
-- TRUSTED DEVICES
-- =========================
CREATE TABLE IF NOT EXISTS trusted_devices (
    device_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username    VARCHAR(50) REFERENCES users(username) ON DELETE CASCADE,
    device_name VARCHAR(100),
    last_used   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_trusted_username ON trusted_devices(username);


-- =========================
-- ATTACK LOGS
-- =========================
CREATE TABLE IF NOT EXISTS attack_logs (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) NOT NULL,
    attack_type VARCHAR(50) NOT NULL,
    target_host VARCHAR(100) NOT NULL,
    target_port INTEGER NOT NULL,
    duration_seconds INTEGER NOT NULL,
    rate_pps INTEGER NOT NULL,
    threads INTEGER NOT NULL,
    mfa_mode VARCHAR(64),
    attack_params JSONB,
    attack_result JSONB,
    packets_sent BIGINT,
    bytes_sent BIGINT,
    actual_rate_pps FLOAT,
    success BOOLEAN NOT NULL,
    message TEXT,
    start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    end_time TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_attack_logs_username ON attack_logs(username);
CREATE INDEX IF NOT EXISTS idx_attack_logs_timestamp ON attack_logs(created_at);


-- =========================
-- PHISHING LOGS
-- =========================
CREATE TABLE IF NOT EXISTS phishing_logs (
    id BIGSERIAL PRIMARY KEY,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    attack_type TEXT NOT NULL,
    target_host TEXT NOT NULL,
    source_ip TEXT,
    user_agent TEXT,
    region TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_phishing_logs_username ON phishing_logs(username);
CREATE INDEX IF NOT EXISTS idx_phishing_logs_created_at ON phishing_logs(created_at);
