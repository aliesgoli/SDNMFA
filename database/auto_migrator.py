"""Apply and verify the versioned, non-destructive PostgreSQL schema."""

import os
import sys
from pathlib import Path
from typing import Dict, Set


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
while PROJECT_ROOT in sys.path:
    sys.path.remove(PROJECT_ROOT)
sys.path.insert(0, PROJECT_ROOT)

from database.db_config import get_db_connection, release_db_connection


SCHEMA_PATH = Path(__file__).resolve().parent / "sql" / "tables.sql"
REQUIRED_SCHEMA: Dict[str, Set[str]] = {
    "users": {
        "username", "password_hash", "otp_enabled", "biometric_template",
        "biometric_mode", "biometric_threshold", "is_active", "last_login",
        "updated_at", "password_scheme", "failed_attempts", "locked_until",
        "is_experiment_user", "experiment_cohort", "password_class",
    },
    "auth_logs": {
        "username", "event_type", "auth_logs_details", "timestamp", "success",
        "run_id", "attempt_id", "mfa_mode",
    },
    "otp_sessions": {
        "id", "username", "otp_hash", "created_at", "expires_at", "used",
        "run_id", "attempt_id",
        "failed_attempts", "invalidated_reason",
    },
    "attack_logs": {
        "username", "attack_type", "target_host", "target_port",
        "duration_seconds", "rate_pps", "threads", "mfa_mode",
        "attack_params", "attack_result", "success", "start_time", "end_time",
        "run_id", "attempt_id", "actual_mechanism", "is_valid",
        "execution_status", "security_outcome", "error_type", "authorized_at",
        "authorization_expires_at", "authorization_in_port",
        "authorization_dpid", "legitimate_before", "legitimate_after",
        "campaign_id", "task_id", "sample_id", "repetition",
        "intensity_level", "binding_profile", "topology_id",
        "resource_metrics", "pcap_evidence",
    },
    "experiment_campaigns": {
        "campaign_id", "study_id", "protocol_id", "schema_version", "seed", "scenario",
        "topology_id", "binding_profile", "repetitions", "manifest",
        "manifest_sha256", "status",
    },
    "experiment_runs": {
        "task_id", "campaign_id", "sample_id", "run_id",
        "task_auth_attempt_id", "experiment_username", "scenario", "intensity_level", "repetition",
        "mfa_mode", "binding_profile", "topology_id", "sampled_parameters",
        "observed_result", "execution_status", "is_valid",
    },
    "authentication_experiment_logs": {
        "campaign_id", "study_id", "run_id", "username", "scenario", "mfa_mode",
        "repetition", "supplied_factors", "authentication_succeeded",
        "latency_ms", "resource_metrics", "attack_family", "attack_variant",
        "intensity_level", "expected_success", "biometric_score",
        "biometric_threshold", "is_valid",
    },
    "thesis_studies": {
        "study_id", "protocol_id", "implementation_revision", "base_seed",
        "repetitions", "expected_topologies", "design_config", "status",
    },
    "topology_executions": {
        "execution_id", "study_id", "topology_id", "status",
        "expected_network_runs", "completed_network_runs", "valid_network_runs",
        "auth_study_completed",
    },
    "chained_experiment_runs": {
        "chain_id", "study_id", "block_id", "base_task_id", "run_id",
        "auth_attempt_id", "experiment_username", "auth_attack_variant",
        "intensity_level", "mfa_mode", "binding_profile", "network_scenario",
        "topology_id", "repetition", "sampled_parameters", "factor_state",
        "authentication_succeeded", "expected_authentication_success",
        "authentication_latency_ms", "authentication_metrics",
        "network_stage_status", "network_result", "resource_metrics",
        "pcap_evidence", "chain_outcome", "execution_status", "is_valid",
    },
}


def _schema_gaps(cursor) -> Dict[str, Set[str]]:
    table_names = tuple(REQUIRED_SCHEMA)
    placeholders = ", ".join(["%s"] * len(table_names))
    cursor.execute(
        """
        SELECT table_name, column_name
        FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name IN (%s)
        """ % placeholders,
        table_names,
    )
    observed = {table: set() for table in REQUIRED_SCHEMA}
    for table, column in cursor.fetchall():
        if table in observed:
            observed[table].add(column)
    return {
        table: required - observed[table]
        for table, required in REQUIRED_SCHEMA.items()
        if required - observed[table]
    }


def auto_migrate() -> bool:
    conn = get_db_connection()
    if not conn:
        print("Database connection failed")
        return False
    try:
        schema_sql = SCHEMA_PATH.read_text(encoding="utf-8")
        with conn.cursor() as cursor:
            cursor.execute(schema_sql)
            gaps = _schema_gaps(cursor)
            cursor.execute(
                "SELECT EXISTS(SELECT 1 FROM pg_extension WHERE extname='pgcrypto')"
            )
            pgcrypto_available = bool(cursor.fetchone()[0])
        if gaps or not pgcrypto_available:
            details = "; ".join(
                "%s=[%s]" % (table, ",".join(sorted(columns)))
                for table, columns in sorted(gaps.items())
            )
            if not pgcrypto_available:
                details = (details + "; " if details else "") + "extension=[pgcrypto]"
            raise RuntimeError("schema verification failed: %s" % details)
        conn.commit()
        print("Database schema is up to date and verified")
        return True
    except Exception as exc:
        conn.rollback()
        print("Migration failed: %s" % exc)
        return False
    finally:
        release_db_connection(conn)


if __name__ == "__main__":
    raise SystemExit(0 if auto_migrate() else 1)
