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
    password_scheme     VARCHAR(32) NOT NULL DEFAULT 'postgres_bcrypt_legacy',
    failed_attempts     INTEGER NOT NULL DEFAULT 0,
    locked_until        TIMESTAMPTZ,
    last_failed_login   TIMESTAMPTZ,
    role                VARCHAR(20) DEFAULT 'user',
    otp_enabled         BOOLEAN NOT NULL DEFAULT FALSE,
    biometric_template  TEXT,
    biometric_mode      VARCHAR(32),
    biometric_threshold DOUBLE PRECISION,
    is_experiment_user  BOOLEAN NOT NULL DEFAULT FALSE,
    experiment_cohort   VARCHAR(64),
    password_class      VARCHAR(32),
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
    success                 BOOLEAN,
    run_id                  UUID,
    attempt_id              UUID,
    mfa_mode                VARCHAR(64)
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
    used        BOOLEAN DEFAULT FALSE,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    invalidated_reason VARCHAR(64),
    run_id      UUID,
    attempt_id  UUID
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
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    run_id UUID,
    attempt_id UUID,
    actual_mechanism VARCHAR(96),
    is_valid BOOLEAN,
    execution_status VARCHAR(32),
    security_outcome VARCHAR(32),
    error_type VARCHAR(96),
    authorized_at TIMESTAMPTZ,
    authorization_expires_at TIMESTAMPTZ,
    authorization_in_port INTEGER,
    authorization_dpid BIGINT,
    legitimate_before BOOLEAN,
    legitimate_after BOOLEAN,
    campaign_id UUID,
    task_id UUID,
    sample_id UUID,
    repetition INTEGER,
    intensity_level VARCHAR(16),
    binding_profile VARCHAR(32),
    topology_id VARCHAR(64),
    resource_metrics JSONB,
    pcap_evidence JSONB
);

CREATE INDEX IF NOT EXISTS idx_attack_logs_username ON attack_logs(username);
CREATE INDEX IF NOT EXISTS idx_attack_logs_timestamp ON attack_logs(created_at);

-- =========================
-- NON-DESTRUCTIVE V2 MIGRATION
-- The following statements also upgrade databases created by earlier builds.
-- =========================
ALTER TABLE auth_logs ADD COLUMN IF NOT EXISTS run_id UUID;
ALTER TABLE auth_logs ADD COLUMN IF NOT EXISTS attempt_id UUID;
ALTER TABLE auth_logs ADD COLUMN IF NOT EXISTS mfa_mode VARCHAR(64);
ALTER TABLE otp_sessions ADD COLUMN IF NOT EXISTS run_id UUID;
ALTER TABLE otp_sessions ADD COLUMN IF NOT EXISTS attempt_id UUID;
ALTER TABLE otp_sessions ADD COLUMN IF NOT EXISTS failed_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE otp_sessions ADD COLUMN IF NOT EXISTS invalidated_reason VARCHAR(64);

ALTER TABLE attack_logs ADD COLUMN IF NOT EXISTS run_id UUID;
ALTER TABLE attack_logs ADD COLUMN IF NOT EXISTS attempt_id UUID;
ALTER TABLE attack_logs ADD COLUMN IF NOT EXISTS actual_mechanism VARCHAR(96);
ALTER TABLE attack_logs ADD COLUMN IF NOT EXISTS is_valid BOOLEAN;
ALTER TABLE attack_logs ADD COLUMN IF NOT EXISTS execution_status VARCHAR(32);
ALTER TABLE attack_logs ADD COLUMN IF NOT EXISTS security_outcome VARCHAR(32);
ALTER TABLE attack_logs ADD COLUMN IF NOT EXISTS error_type VARCHAR(96);
ALTER TABLE attack_logs ADD COLUMN IF NOT EXISTS authorized_at TIMESTAMPTZ;
ALTER TABLE attack_logs ADD COLUMN IF NOT EXISTS authorization_expires_at TIMESTAMPTZ;
ALTER TABLE attack_logs ADD COLUMN IF NOT EXISTS authorization_in_port INTEGER;
ALTER TABLE attack_logs ADD COLUMN IF NOT EXISTS authorization_dpid BIGINT;
ALTER TABLE attack_logs ADD COLUMN IF NOT EXISTS legitimate_before BOOLEAN;
ALTER TABLE attack_logs ADD COLUMN IF NOT EXISTS legitimate_after BOOLEAN;

-- =========================
-- SCIENTIFIC CAMPAIGNS
-- =========================
ALTER TABLE users ADD COLUMN IF NOT EXISTS otp_enabled BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_scheme VARCHAR(32) NOT NULL DEFAULT 'postgres_bcrypt_legacy';
ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_failed_login TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS biometric_template TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS biometric_mode VARCHAR(32);
ALTER TABLE users ADD COLUMN IF NOT EXISTS biometric_threshold DOUBLE PRECISION;
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_experiment_user BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS experiment_cohort VARCHAR(64);
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_class VARCHAR(32);
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT TRUE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login TIMESTAMP;
ALTER TABLE users ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;

ALTER TABLE attack_logs ADD COLUMN IF NOT EXISTS campaign_id UUID;
ALTER TABLE attack_logs ADD COLUMN IF NOT EXISTS task_id UUID;
ALTER TABLE attack_logs ADD COLUMN IF NOT EXISTS sample_id UUID;
ALTER TABLE attack_logs ADD COLUMN IF NOT EXISTS repetition INTEGER;
ALTER TABLE attack_logs ADD COLUMN IF NOT EXISTS intensity_level VARCHAR(16);
ALTER TABLE attack_logs ADD COLUMN IF NOT EXISTS binding_profile VARCHAR(32);
ALTER TABLE attack_logs ADD COLUMN IF NOT EXISTS topology_id VARCHAR(64);
ALTER TABLE attack_logs ADD COLUMN IF NOT EXISTS resource_metrics JSONB;
ALTER TABLE attack_logs ADD COLUMN IF NOT EXISTS pcap_evidence JSONB;

-- =========================
-- REPRODUCIBLE THESIS STUDIES
-- =========================
CREATE TABLE IF NOT EXISTS thesis_studies (
    study_id UUID PRIMARY KEY,
    protocol_id VARCHAR(64) NOT NULL,
    implementation_revision VARCHAR(64) NOT NULL,
    base_seed BIGINT NOT NULL,
    repetitions INTEGER NOT NULL CHECK (repetitions BETWEEN 1 AND 30),
    expected_topologies JSONB NOT NULL,
    design_config JSONB NOT NULL,
    status VARCHAR(24) NOT NULL DEFAULT 'planned',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS topology_executions (
    execution_id UUID PRIMARY KEY,
    study_id UUID NOT NULL REFERENCES thesis_studies(study_id) ON DELETE CASCADE,
    topology_id VARCHAR(64) NOT NULL,
    status VARCHAR(24) NOT NULL DEFAULT 'planned',
    expected_network_runs INTEGER NOT NULL,
    completed_network_runs INTEGER NOT NULL DEFAULT 0,
    valid_network_runs INTEGER NOT NULL DEFAULT 0,
    auth_study_completed BOOLEAN NOT NULL DEFAULT FALSE,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    UNIQUE (study_id, topology_id)
);

CREATE TABLE IF NOT EXISTS experiment_campaigns (
    campaign_id UUID PRIMARY KEY,
    study_id UUID REFERENCES thesis_studies(study_id) ON DELETE CASCADE,
    protocol_id VARCHAR(64) NOT NULL,
    schema_version INTEGER NOT NULL,
    seed BIGINT NOT NULL,
    scenario VARCHAR(64) NOT NULL,
    topology_id VARCHAR(64) NOT NULL,
    binding_profile VARCHAR(32) NOT NULL,
    repetitions INTEGER NOT NULL CHECK (repetitions BETWEEN 1 AND 30),
    design VARCHAR(96) NOT NULL,
    manifest JSONB NOT NULL,
    manifest_sha256 CHAR(64) NOT NULL,
    status VARCHAR(24) NOT NULL DEFAULT 'planned',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS experiment_runs (
    task_id UUID PRIMARY KEY,
    campaign_id UUID NOT NULL REFERENCES experiment_campaigns(campaign_id) ON DELETE CASCADE,
    sample_id UUID NOT NULL,
    run_id UUID NOT NULL,
    operator_attempt_id UUID,
    task_auth_attempt_id UUID,
    experiment_username VARCHAR(50) REFERENCES users(username) ON DELETE SET NULL,
    scenario VARCHAR(64) NOT NULL,
    intensity_level VARCHAR(16) NOT NULL,
    repetition INTEGER NOT NULL,
    policy_position INTEGER NOT NULL,
    mfa_mode VARCHAR(64) NOT NULL,
    binding_profile VARCHAR(32) NOT NULL,
    topology_id VARCHAR(64) NOT NULL,
    sampled_parameters JSONB NOT NULL,
    observed_result JSONB,
    resource_metrics JSONB,
    pcap_evidence JSONB,
    execution_status VARCHAR(32) NOT NULL DEFAULT 'planned',
    is_valid BOOLEAN,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS authentication_experiment_logs (
    id BIGSERIAL PRIMARY KEY,
    campaign_id UUID REFERENCES experiment_campaigns(campaign_id) ON DELETE CASCADE,
    study_id UUID REFERENCES thesis_studies(study_id) ON DELETE CASCADE,
    run_id UUID NOT NULL,
    username VARCHAR(50) REFERENCES users(username) ON DELETE SET NULL,
    scenario VARCHAR(64) NOT NULL,
    attack_family VARCHAR(64) NOT NULL DEFAULT 'factor_availability',
    attack_variant VARCHAR(96) NOT NULL DEFAULT 'declared_factor_set',
    intensity_level VARCHAR(16) NOT NULL DEFAULT 'medium',
    mfa_mode VARCHAR(64) NOT NULL,
    repetition INTEGER NOT NULL DEFAULT 1,
    supplied_factors JSONB NOT NULL,
    authentication_succeeded BOOLEAN NOT NULL,
    expected_success BOOLEAN,
    biometric_score DOUBLE PRECISION,
    biometric_threshold DOUBLE PRECISION,
    is_valid BOOLEAN NOT NULL DEFAULT TRUE,
    latency_ms DOUBLE PRECISION NOT NULL,
    resource_metrics JSONB,
    message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS chained_experiment_runs (
    chain_id UUID PRIMARY KEY,
    study_id UUID NOT NULL REFERENCES thesis_studies(study_id) ON DELETE CASCADE,
    block_id UUID NOT NULL,
    base_task_id UUID NOT NULL,
    run_id UUID NOT NULL,
    auth_attempt_id UUID NOT NULL,
    experiment_username VARCHAR(50) REFERENCES users(username) ON DELETE SET NULL,
    auth_attack_variant VARCHAR(96) NOT NULL,
    intensity_level VARCHAR(16) NOT NULL,
    mfa_mode VARCHAR(64) NOT NULL,
    binding_profile VARCHAR(32) NOT NULL,
    network_scenario VARCHAR(64) NOT NULL,
    topology_id VARCHAR(64) NOT NULL,
    repetition INTEGER NOT NULL,
    sampled_parameters JSONB NOT NULL,
    factor_state JSONB NOT NULL,
    authentication_succeeded BOOLEAN NOT NULL,
    expected_authentication_success BOOLEAN NOT NULL,
    authentication_latency_ms DOUBLE PRECISION NOT NULL,
    authentication_metrics JSONB,
    network_stage_status VARCHAR(32) NOT NULL,
    network_result JSONB,
    resource_metrics JSONB,
    pcap_evidence JSONB,
    chain_outcome VARCHAR(48) NOT NULL,
    execution_status VARCHAR(32) NOT NULL,
    is_valid BOOLEAN NOT NULL,
    started_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMPTZ
);

ALTER TABLE authentication_experiment_logs ADD COLUMN IF NOT EXISTS repetition INTEGER NOT NULL DEFAULT 1;
ALTER TABLE authentication_experiment_logs ADD COLUMN IF NOT EXISTS resource_metrics JSONB;
ALTER TABLE authentication_experiment_logs ADD COLUMN IF NOT EXISTS study_id UUID REFERENCES thesis_studies(study_id) ON DELETE CASCADE;
ALTER TABLE authentication_experiment_logs ADD COLUMN IF NOT EXISTS attack_family VARCHAR(64) NOT NULL DEFAULT 'factor_availability';
ALTER TABLE authentication_experiment_logs ADD COLUMN IF NOT EXISTS attack_variant VARCHAR(96) NOT NULL DEFAULT 'declared_factor_set';
ALTER TABLE authentication_experiment_logs ADD COLUMN IF NOT EXISTS intensity_level VARCHAR(16) NOT NULL DEFAULT 'medium';
ALTER TABLE authentication_experiment_logs ADD COLUMN IF NOT EXISTS expected_success BOOLEAN;
ALTER TABLE authentication_experiment_logs ADD COLUMN IF NOT EXISTS biometric_score DOUBLE PRECISION;
ALTER TABLE authentication_experiment_logs ADD COLUMN IF NOT EXISTS biometric_threshold DOUBLE PRECISION;
ALTER TABLE authentication_experiment_logs ADD COLUMN IF NOT EXISTS is_valid BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE experiment_runs ADD COLUMN IF NOT EXISTS task_auth_attempt_id UUID;
ALTER TABLE experiment_runs ADD COLUMN IF NOT EXISTS experiment_username VARCHAR(50) REFERENCES users(username) ON DELETE SET NULL;
ALTER TABLE experiment_campaigns ADD COLUMN IF NOT EXISTS study_id UUID REFERENCES thesis_studies(study_id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_auth_logs_run_id ON auth_logs(run_id);
CREATE INDEX IF NOT EXISTS idx_auth_logs_attempt_id ON auth_logs(attempt_id);
CREATE INDEX IF NOT EXISTS idx_otp_sessions_run_id ON otp_sessions(run_id);
CREATE INDEX IF NOT EXISTS idx_otp_sessions_attempt_id ON otp_sessions(attempt_id);
CREATE INDEX IF NOT EXISTS idx_attack_logs_run_id ON attack_logs(run_id);
CREATE INDEX IF NOT EXISTS idx_attack_logs_validity ON attack_logs(is_valid, execution_status);
CREATE INDEX IF NOT EXISTS idx_attack_logs_campaign ON attack_logs(campaign_id, task_id);
CREATE INDEX IF NOT EXISTS idx_experiment_runs_campaign ON experiment_runs(campaign_id);
CREATE INDEX IF NOT EXISTS idx_experiment_runs_block ON experiment_runs(sample_id, mfa_mode);
CREATE INDEX IF NOT EXISTS idx_auth_experiment_campaign ON authentication_experiment_logs(campaign_id);
CREATE INDEX IF NOT EXISTS idx_auth_experiment_study
    ON authentication_experiment_logs(study_id, attack_family, scenario, mfa_mode);
CREATE INDEX IF NOT EXISTS idx_chained_study_topology
    ON chained_experiment_runs(study_id, topology_id, execution_status, is_valid);
CREATE INDEX IF NOT EXISTS idx_chained_block
    ON chained_experiment_runs(block_id, mfa_mode, binding_profile);
CREATE INDEX IF NOT EXISTS idx_users_experiment_cohort
    ON users(is_experiment_user, experiment_cohort);
DROP INDEX IF EXISTS uq_auth_experiment_cell;
CREATE UNIQUE INDEX IF NOT EXISTS uq_auth_experiment_cell_v2
    ON authentication_experiment_logs(
        study_id, username, attack_family, attack_variant, scenario,
        intensity_level, mfa_mode, repetition
    ) WHERE study_id IS NOT NULL;
