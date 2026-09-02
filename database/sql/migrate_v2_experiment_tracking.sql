BEGIN;

ALTER TABLE auth_logs ADD COLUMN IF NOT EXISTS run_id UUID;
ALTER TABLE auth_logs ADD COLUMN IF NOT EXISTS attempt_id UUID;
ALTER TABLE auth_logs ADD COLUMN IF NOT EXISTS mfa_mode VARCHAR(64);
ALTER TABLE otp_sessions ADD COLUMN IF NOT EXISTS run_id UUID;
ALTER TABLE otp_sessions ADD COLUMN IF NOT EXISTS attempt_id UUID;

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

CREATE INDEX IF NOT EXISTS idx_auth_logs_run_id ON auth_logs(run_id);
CREATE INDEX IF NOT EXISTS idx_auth_logs_attempt_id ON auth_logs(attempt_id);
CREATE INDEX IF NOT EXISTS idx_otp_sessions_run_id ON otp_sessions(run_id);
CREATE INDEX IF NOT EXISTS idx_otp_sessions_attempt_id ON otp_sessions(attempt_id);
CREATE INDEX IF NOT EXISTS idx_attack_logs_run_id ON attack_logs(run_id);
CREATE INDEX IF NOT EXISTS idx_attack_logs_validity
    ON attack_logs(is_valid, execution_status);

COMMIT;
